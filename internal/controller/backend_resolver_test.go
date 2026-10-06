package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func smtpSpec(ref *sigv1.SecretReference) *sigv1.BackendSpec {
	return &sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
		Endpoints:      []sigv1.SMTPEndpoint{{Host: "relay.example", Port: 587}},
		AuthType:       sigv1.SMTPAuthPlain,
		CredentialsRef: ref,
	}}
}

// A namespaced MailBackend must not read Secrets of other namespaces, even
// with the webhook disabled (security review of v0.3.0).
func TestResolveBackendConfigKeepsMailBackendInItsNamespace(t *testing.T) {
	relay := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "relay", Namespace: "sigillum-system"},
		Data: map[string][]byte{"username": []byte("u"), "password": []byte("relay-password")}}
	own := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "own", Namespace: "team"},
		Data: map[string][]byte{"username": []byte("t"), "password": []byte("team-password")}}
	c := fake.NewClientBuilder().WithObjects(relay, own).Build()
	ctx := context.Background()

	_, err := ResolveBackendConfig(ctx, c, "team/b", smtpSpec(&sigv1.SecretReference{Name: "relay", Namespace: "sigillum-system"}), "team")
	if err == nil || !strings.Contains(err.Error(), "own namespace") {
		t.Fatalf("cross-namespace credentialsRef on a MailBackend must be refused, got %v", err)
	}

	for _, ns := range []string{"", "team"} {
		cfg, err := ResolveBackendConfig(ctx, c, "team/b", smtpSpec(&sigv1.SecretReference{Name: "own", Namespace: ns}), "team")
		if err != nil || cfg.SMTP.Password != "team-password" {
			t.Fatalf("namespace %q: own Secret must resolve, got %v %+v", ns, err, cfg.SMTP)
		}
	}

	// ClusterMailBackends name the Secret's namespace explicitly.
	cfg, err := ResolveBackendConfig(ctx, c, "/b", smtpSpec(&sigv1.SecretReference{Name: "relay", Namespace: "sigillum-system"}), "")
	if err != nil || cfg.SMTP.Password != "relay-password" {
		t.Fatalf("ClusterMailBackend: %v %+v", err, cfg.SMTP)
	}
	if _, err := ResolveBackendConfig(ctx, c, "/b", smtpSpec(&sigv1.SecretReference{Name: "relay"}), ""); err == nil {
		t.Fatal("ClusterMailBackend without credentialsRef.namespace must be refused")
	}
}

func TestResolveBackendConfigMicrosoftGraph(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "m365", Namespace: "sigillum-system"},
		Data: map[string][]byte{sigv1.GraphSecretClientSecretKey: []byte("s3cret")}}
	empty := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "sigillum-system"}}
	c := fake.NewClientBuilder().WithObjects(sec, empty).Build()
	spec := func(ref sigv1.SecretReference) *sigv1.BackendSpec {
		return &sigv1.BackendSpec{Type: sigv1.BackendMicrosoftGraph, MicrosoftGraph: &sigv1.MicrosoftGraphBackendSpec{
			TenantID: "contoso.onmicrosoft.com", ClientID: "00000000-0000-0000-0000-000000000001", CredentialsRef: ref}}
	}
	cfg, err := ResolveBackendConfig(context.Background(), c, "/m365", spec(sigv1.SecretReference{Name: "m365", Namespace: "sigillum-system"}), "")
	if err != nil || cfg.Graph == nil || cfg.Graph.ClientSecret != "s3cret" || cfg.Graph.TenantID != "contoso.onmicrosoft.com" {
		t.Fatalf("got %+v %v", cfg.Graph, err)
	}
	if _, err := ResolveBackendConfig(context.Background(), c, "/m365", spec(sigv1.SecretReference{Name: "empty", Namespace: "sigillum-system"}), ""); err == nil ||
		!strings.Contains(err.Error(), "client_secret") {
		t.Fatalf("a Secret without client_secret must be refused, got %v", err)
	}
	if _, err := ResolveBackendConfig(context.Background(), c, "team/m365", spec(sigv1.SecretReference{Name: "m365", Namespace: "sigillum-system"}), "team"); err == nil ||
		!strings.Contains(err.Error(), "own namespace") {
		t.Fatalf("a MailBackend must not read another namespace's Secret, got %v", err)
	}
	if _, err := ResolveBackendConfig(context.Background(), c, "/m365", &sigv1.BackendSpec{Type: sigv1.BackendMicrosoftGraph}, ""); err == nil {
		t.Fatal("type microsoftGraph without spec.microsoftGraph must be refused")
	}
}

// #57: caSecretRef adds PEM CA certificates to the roots; it follows the
// namespace rules of credentialsRef.
func TestResolveBackendConfigCASecretRef(t *testing.T) {
	ca := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "corp-ca", Namespace: "sigillum-system"},
		Data: map[string][]byte{"ca.crt": testCAPEM(t), "bundle.pem": testCAPEM(t), "junk": []byte("not a certificate")}}
	teamCA := ca.DeepCopy()
	teamCA.Namespace = "team"
	c := fake.NewClientBuilder().WithObjects(ca, teamCA).Build()
	ctx := context.Background()
	spec := func(ref sigv1.CASecretReference) *sigv1.BackendSpec {
		s := smtpSpec(nil)
		s.SMTP.AuthType = sigv1.SMTPAuthNone
		s.SMTP.CASecretRef = &ref
		return s
	}

	for _, key := range []string{"", "bundle.pem"} {
		cfg, err := ResolveBackendConfig(ctx, c, "/b", spec(sigv1.CASecretReference{Name: "corp-ca", Namespace: "sigillum-system", Key: key}), "")
		if err != nil || cfg.SMTP.RootCAs == nil {
			t.Fatalf("key %q: want a root pool, got %v", key, err)
		}
	}
	for _, tc := range []struct {
		ref      sigv1.CASecretReference
		fallback string
		want     string
	}{
		{sigv1.CASecretReference{Name: "corp-ca", Namespace: "sigillum-system", Key: "missing"}, "", "has no key missing"},
		{sigv1.CASecretReference{Name: "corp-ca", Namespace: "sigillum-system", Key: "junk"}, "", "holds no PEM certificate"},
		{sigv1.CASecretReference{Name: "absent", Namespace: "sigillum-system"}, "", "CA secret sigillum-system/absent not found"},
		{sigv1.CASecretReference{Name: "corp-ca"}, "", "caSecretRef.namespace must be set"},
		{sigv1.CASecretReference{Name: "corp-ca", Namespace: "sigillum-system"}, "team", "own namespace"},
	} {
		if _, err := ResolveBackendConfig(ctx, c, "x", spec(tc.ref), tc.fallback); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: want %q, got %v", tc.ref, tc.want, err)
		}
	}
	if cfg, err := ResolveBackendConfig(ctx, c, "team/b", spec(sigv1.CASecretReference{Name: "corp-ca"}), "team"); err != nil || cfg.SMTP.RootCAs == nil {
		t.Fatalf("MailBackend: its own namespace's CA must resolve, got %v", err)
	}
}

// testCAPEM returns a self-signed CA certificate in PEM.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
