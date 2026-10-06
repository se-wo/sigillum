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

func TestResolveBackendConfigGmail(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "workspace", Namespace: "sigillum-system"},
		Data: map[string][]byte{sigv1.GmailSecretServiceAccountKey: []byte(`{"type":"service_account"}`)}}
	empty := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "sigillum-system"}}
	c := fake.NewClientBuilder().WithObjects(sec, empty).Build()
	spec := func(name string) *sigv1.BackendSpec {
		return &sigv1.BackendSpec{Type: sigv1.BackendGmail,
			Gmail: &sigv1.GmailBackendSpec{CredentialsRef: sigv1.SecretReference{Name: name, Namespace: "sigillum-system"}}}
	}
	cfg, err := ResolveBackendConfig(context.Background(), c, "/workspace", spec("workspace"), "")
	if err != nil || string(cfg.Gmail.ServiceAccountJSON) != `{"type":"service_account"}` {
		t.Fatalf("got %+v, %v", cfg.Gmail, err)
	}
	if _, err := ResolveBackendConfig(context.Background(), c, "/workspace", spec("empty"), ""); err == nil ||
		!strings.Contains(err.Error(), "service_account.json") {
		t.Fatalf("want the missing key named, got %v", err)
	}
	if _, err := ResolveBackendConfig(context.Background(), c, "/workspace", &sigv1.BackendSpec{Type: sigv1.BackendGmail}, ""); err == nil {
		t.Fatal("a gmail backend without spec.gmail must be refused")
	}
}
