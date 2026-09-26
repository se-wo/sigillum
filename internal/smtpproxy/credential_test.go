package smtpproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/gateway"
)

const (
	credUser     = "grafana.monitoring"
	credPassword = "correct-horse-battery-staple-0123456789abcdef"
)

// readyCredential is a generated-mode MailCredential as the controller
// leaves it once the password is issued.
func readyCredential(currentPassword string) *sigv1.MailCredential {
	return &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring", Generation: 1, UID: "uid-1"},
		Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "grafana-smtp"},
		Status: sigv1.MailCredentialStatus{
			Username:           credUser,
			SecretName:         "grafana-smtp",
			Current:            &sigv1.CredentialHash{Hash: credential.HashGenerated(currentPassword), CreatedAt: metav1.Now()},
			ObservedGeneration: 1,
			Conditions: []metav1.Condition{{Type: sigv1.ConditionReady, Status: metav1.ConditionTrue,
				ObservedGeneration: 1, Reason: sigv1.ReasonReady, LastTransitionTime: metav1.Now()}},
		},
	}
}

func credentialClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := sigv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&sigv1.MailCredential{}).Build()
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sigillum"},
		DNSNames:     []string{"sigillum"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func startTLSProxy(t *testing.T, b *Backend) string {
	t.Helper()
	b.Logger = discardLogger()
	b.AuthTimeout = time.Second
	o, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(o, b, selfSignedTLS(t))
	srv.AllowInsecureAuth = true // tokens may use plaintext; credentials still need TLS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestCredential_PlainRequiresTLS(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	b := &Backend{Sender: sender, Tokens: stubTokens{},
		Credentials: credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1)}
	addr := startTLSProxy(t, b)

	c := dial(t, addr)
	if _, params := c.Extension("AUTH"); strings.Contains(params, "PLAIN") || strings.Contains(params, "LOGIN") {
		t.Fatalf("PLAIN/LOGIN must not be offered before STARTTLS: %q", params)
	}
	err := c.Auth(sasl.NewPlainClient("", credUser, credPassword))
	if smtpCode(err) != 538 {
		t.Fatalf("want 538 encryption required, got %v", err)
	}

	c, err = smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, params := c.Extension("AUTH"); !strings.Contains(params, "PLAIN") || !strings.Contains(params, "LOGIN") {
		t.Fatalf("PLAIN and LOGIN must be offered after STARTTLS: %q", params)
	}
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sender.reqs) != 1 {
		t.Fatalf("want one gateway request, got %d", len(sender.reqs))
	}
	id := sender.reqs[0].Identity
	if id.Namespace != "monitoring" || id.ServiceAccount != "grafana" || id.AuthMethod != gateway.AuthSMTPCredential ||
		id.Credential != credUser || id.CredentialPrevious {
		t.Fatalf("unexpected identity %+v", id)
	}
	if !strings.Contains(string(sender.reqs[0].Raw), "with ESMTPSA id ") {
		t.Fatalf("Received header must say ESMTPSA: %q", sender.reqs[0].Raw[:120])
	}
}

func TestCredential_LoginMechanismAndInsecureOptIn(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1)})

	conn, err := textproto.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expect := func(code int) string {
		t.Helper()
		_, msg, err := conn.ReadResponse(code)
		if err != nil {
			t.Fatalf("want %d: %v", code, err)
		}
		return msg
	}
	b64 := base64.StdEncoding.EncodeToString
	expect(220)
	_ = conn.PrintfLine("EHLO client.test")
	if ext := expect(250); !strings.Contains(ext, "AUTH PLAIN LOGIN") {
		t.Fatalf("PLAIN/LOGIN must be offered with the insecure opt-in: %q", ext)
	}
	_ = conn.PrintfLine("AUTH LOGIN")
	if ch, _ := base64.StdEncoding.DecodeString(expect(334)); string(ch) != "Username:" {
		t.Fatalf("unexpected challenge %q", ch)
	}
	_ = conn.PrintfLine("%s", b64([]byte(credUser)))
	if ch, _ := base64.StdEncoding.DecodeString(expect(334)); string(ch) != "Password:" {
		t.Fatalf("unexpected challenge %q", ch)
	}
	_ = conn.PrintfLine("%s", b64([]byte(credPassword)))
	expect(235)
	_ = conn.PrintfLine("MAIL FROM:<grafana@monitoring.example>")
	expect(250)
}

func TestCredential_FailuresAreAuditedAndThrottled(t *testing.T) {
	sender := &stubSender{}
	b := &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials:  credential.NewVerifier(credentialClient(t, readyCredential(credPassword)), 1),
		AuthFailures: &FailureLimiter{Window: time.Minute, PerUser: 2, PerIP: 100}}
	addr := startProxy(t, b)

	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		if err := c.Auth(sasl.NewPlainClient("", credUser, "wrong")); smtpCode(err) != 535 {
			t.Fatalf("attempt %d: want 535, got %v", i, err)
		}
	}
	// The limit is reached: even the right password is refused for now.
	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); smtpCode(err) != 454 {
		t.Fatalf("want 454 while throttled, got %v", err)
	}
	want := []string{"invalid_credentials", "invalid_credentials", "auth_rate_limited"}
	if strings.Join(sender.rejects, ",") != strings.Join(want, ",") {
		t.Fatalf("audit reasons %v, want %v", sender.rejects, want)
	}
	for _, ev := range sender.events {
		if ev.AuthMethod != gateway.AuthSMTPCredential || ev.Credential != credUser {
			t.Fatalf("failed login must be audited with the credential username: %+v", ev)
		}
	}

	// A different, unthrottled user with a bad authzid is refused.
	c = dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("other.monitoring", "x.monitoring", "pw")); smtpCode(err) != 535 {
		t.Fatalf("mismatched authzid: want 535, got %v", err)
	}
}

func TestCredential_PreviousPasswordAndRevocation(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential("new-password-0123456789abcdef0123456789")
	mc.Status.Previous = &sigv1.PreviousCredentialHash{Hash: credential.HashGenerated(credPassword),
		ValidUntil: metav1.NewTime(time.Now().Add(time.Hour))}
	cl := credentialClient(t, mc)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(cl, 1)})

	c := dial(t, addr)
	if err := c.Auth(sasl.NewPlainClient("", credUser, credPassword)); err != nil {
		t.Fatalf("previous password must work during the grace period: %v", err)
	}
	msg := "From: grafana@monitoring.example\r\nTo: ops@example.com\r\nSubject: alert\r\n\r\nfiring\r\n"
	if err := send(c, "grafana@monitoring.example", []string{"ops@example.com"}, msg); err != nil {
		t.Fatal(err)
	}
	if !sender.reqs[0].Identity.CredentialPrevious {
		t.Fatal("use of the previous password must be flagged for the audit record")
	}

	// Deleting the MailCredential ends the open session too.
	if err := cl.Delete(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("grafana@monitoring.example", nil); smtpCode(err) != 530 {
		t.Fatalf("want 530 after revocation, got %v", err)
	}
}

func TestCredential_BringYourOwnHash(t *testing.T) {
	sender := &stubSender{result: gateway.Result{Status: gateway.StatusAccepted}}
	mc := readyCredential("unused")
	mc.Spec.SecretName, mc.Status.Current = "", nil
	mc.Spec.PasswordHash = credential.HashArgon2id("user-chosen", []byte("0123456789abcdef"), 7*1024, 5, 1)
	addr := startProxy(t, &Backend{Sender: sender, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, mc), 1)})

	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, "wrong")); smtpCode(err) != 535 {
		t.Fatalf("want 535, got %v", err)
	}
	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, "user-chosen")); err != nil {
		t.Fatalf("argon2id credential: %v", err)
	}
}

func TestCredential_NotReadyIsRefused(t *testing.T) {
	mc := readyCredential(credPassword)
	mc.Generation = 2 // spec changed, controller has not caught up
	addr := startProxy(t, &Backend{Sender: &stubSender{}, AllowInsecureCredentialAuth: true,
		Credentials: credential.NewVerifier(credentialClient(t, mc), 1)})
	if err := dial(t, addr).Auth(sasl.NewPlainClient("", credUser, credPassword)); smtpCode(err) != 535 {
		t.Fatalf("want 535 for a credential the controller has not accepted, got %v", err)
	}
}

func TestFailureLimiterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	f := &FailureLimiter{Window: time.Minute, PerUser: 2, PerIP: 3, now: func() time.Time { return now }}
	f.Fail("a", "1.1.1.1")
	f.Fail("a", "1.1.1.1")
	if !f.Blocked("a", "2.2.2.2") {
		t.Fatal("user limit reached")
	}
	if f.Blocked("b", "2.2.2.2") {
		t.Fatal("other user and IP are not blocked")
	}
	f.Fail("b", "1.1.1.1")
	if !f.Blocked("c", "1.1.1.1") {
		t.Fatal("IP limit reached")
	}
	now = now.Add(61 * time.Second)
	if f.Blocked("a", "1.1.1.1") {
		t.Fatal("failures must expire after the window")
	}
	_ = f.Blocked("b", "1.1.1.1")
	if len(f.hits) != 0 {
		t.Fatalf("expired keys must be pruned when looked at, have %d", len(f.hits))
	}
}

func TestSMTPAuthModeCredentialFlag(t *testing.T) {
	o, err := ParseFlags([]string{"--auth-modes=oauthbearer,credential"})
	if err != nil || !o.has(ModeCredential) || o.AllowInsecureCredentialAuth {
		t.Fatalf("parse: %v %+v", err, o)
	}
	var _ smtp.Backend = &Backend{}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
