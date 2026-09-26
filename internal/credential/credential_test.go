package credential

import (
	"strings"
	"testing"
	"time"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func TestUsernameRoundTrip(t *testing.T) {
	for _, tc := range []struct{ name, ns string }{
		{"grafana", "monitoring"},
		{"argo.cd.notifications", "argocd"}, // names may contain dots, namespaces cannot
	} {
		u := Username(tc.name, tc.ns)
		ns, name, ok := ParseUsername(u)
		if !ok || ns != tc.ns || name != tc.name {
			t.Fatalf("%q -> %q %q %v", u, ns, name, ok)
		}
	}
	for _, bad := range []string{"", "nodot", ".ns", "name.", "."} {
		if _, _, ok := ParseUsername(bad); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

func TestGeneratedPassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) != 43 || a == b || strings.ContainsAny(a, "+/=") {
		t.Fatalf("want 43 url-safe chars, distinct: %q %q", a, b)
	}
	h := HashGenerated(a)
	if !strings.HasPrefix(h, "sha256:") || !VerifyGenerated(h, a) || VerifyGenerated(h, b) {
		t.Fatalf("hash %q does not verify", h)
	}
	for _, bad := range []string{"", "sha256:zz", "md5:" + strings.Repeat("0", 64), "sha256:00"} {
		if VerifyGenerated(bad, a) {
			t.Fatalf("malformed hash %q must never verify", bad)
		}
	}
}

func TestArgon2id(t *testing.T) {
	salt := []byte("0123456789abcdef")
	phc := HashArgon2id("s3cret", salt, 19*1024, 2, 1)
	ok, err := VerifyArgon2id(phc, "s3cret")
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := VerifyArgon2id(phc, "S3cret"); ok {
		t.Fatal("wrong password verified")
	}
	// Padded base64, as some tools emit it, is accepted too.
	padded := strings.Replace(phc, "$MDEyMzQ1Njc4OWFiY2RlZg$", "$MDEyMzQ1Njc4OWFiY2RlZg==$", 1)
	if ok, err := VerifyArgon2id(padded, "s3cret"); err != nil || !ok {
		t.Fatalf("padded salt: %v %v", ok, err)
	}
}

func TestParseArgon2idRejects(t *testing.T) {
	good := HashArgon2id("x", []byte("0123456789abcdef"), 19*1024, 2, 1)
	if _, err := ParseArgon2id(good); err != nil {
		t.Fatalf("good hash rejected: %v", err)
	}
	cases := map[string]string{
		"plaintext":      "hunter2",
		"bcrypt":         "$2y$10$abcdefghijklmnopqrstuuJ0Zx0Mh6LB3aNwX4gGZ6tLo5hUpdX1K",
		"argon2i":        strings.Replace(good, "argon2id", "argon2i", 1),
		"old version":    strings.Replace(good, "v=19", "v=16", 1),
		"memory too big": strings.Replace(good, "m=19456", "m=1048576", 1),
		"too weak":       strings.Replace(good, "t=2", "t=1", 1),
		"memory tiny":    strings.Replace(good, "m=19456", "m=1024", 1),
		"threads":        strings.Replace(good, "p=1", "p=0", 1),
		"unknown param":  strings.Replace(good, "p=1", "p=1,x=2", 1),
		"duplicate":      strings.Replace(good, "p=1", "p=1,p=2", 1),
		"short salt":     "$argon2id$v=19$m=19456,t=2,p=1$YWJj$" + strings.Split(good, "$")[5],
		"bad base64":     "$argon2id$v=19$m=19456,t=2,p=1$!!!$!!!",
		"missing part":   "$argon2id$v=19$m=19456,t=2,p=1$abc",
	}
	for name, phc := range cases {
		if _, err := ParseArgon2id(phc); err == nil {
			t.Errorf("%s: %q must be rejected", name, phc)
		}
	}
	if _, err := ParseArgon2id("hunter2"); !strings.Contains(err.Error(), "never the plaintext") {
		t.Errorf("plaintext-looking values get a hint, got %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":    0,
		"90d": 90 * 24 * time.Hour,
		"24h": 24 * time.Hour,
		"90m": 90 * time.Minute,
	} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"-1h", "1.5d", "d", "ninety days", "-3d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestExclusions(t *testing.T) {
	e := ParseExclusions(" kube-*, cert-manager ,,istio-*", "sigillum-system")
	for ns, want := range map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"cert-manager":    true,
		"cert-manager-x":  false,
		"istio-system":    true,
		"sigillum-system": true, // release namespace, always
		"monitoring":      false,
		"kubernetes":      false,
	} {
		if got := e.Excluded(ns); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", ns, got, want)
		}
	}
	exact, prefixes := e.split()
	if strings.Join(exact, ",") != "cert-manager" || strings.Join(prefixes, ",") != "kube-,istio-" {
		t.Fatalf("split: %v %v", exact, prefixes)
	}
}

// Review of #20: a '*' that is not a single trailing one never matches, so
// it is rejected instead of silently excluding nothing.
func TestExclusionsValidate(t *testing.T) {
	if err := ParseExclusions("kube-*, cert-manager ,istio-*", "sigillum-system").Validate(); err != nil {
		t.Fatalf("valid patterns rejected: %v", err)
	}
	for _, bad := range []string{"*-system", "kube-*-a", "**", "a**"} {
		if err := ParseExclusions(bad, "").Validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Review of #20: one rotation parser for the webhook and the controller.
func TestParseRotation(t *testing.T) {
	iv, grace, err := ParseRotation(nil)
	if err != nil || iv != 0 || grace != DefaultGracePeriod {
		t.Fatalf("nil: %v %v %v", iv, grace, err)
	}
	iv, grace, err = ParseRotation(&sigv1.CredentialRotation{Interval: "90d", GracePeriod: "0s"})
	if err != nil || iv != 90*24*time.Hour || grace != 0 {
		t.Fatalf("90d/0s: %v %v %v", iv, grace, err)
	}
	_, _, err = ParseRotation(&sigv1.CredentialRotation{Interval: "90s", GracePeriod: "soon"})
	var fields []string
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		fields = append(fields, e.(*RotationError).Field)
	}
	if strings.Join(fields, ",") != "interval,gracePeriod" || !strings.Contains(err.Error(), "spec.rotation.interval: must be at least 1h") {
		t.Fatalf("want both fields reported, got %v", err)
	}
}
