package controller

import (
	"context"
	"strings"
	"testing"

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
