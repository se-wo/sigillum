//go:build envtest

package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func TestWebhook_RejectsEmptyEndpoints(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-1"}}
	_ = testClient.Create(context.Background(), ns)

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: nil,
				AuthType:  sigv1.SMTPAuthNone,
			},
		},
	}
	err := testClient.Create(context.Background(), mb)
	if err == nil {
		t.Fatal("expected webhook to reject empty endpoints")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("wanted endpoint error, got %v", err)
	}
}

func TestWebhook_RejectsMissingCredentialsWhenAuthPlain(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-2"}}
	_ = testClient.Create(context.Background(), ns)

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "needs-creds", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
				AuthType:  sigv1.SMTPAuthPlain,
			},
		},
	}
	err := testClient.Create(context.Background(), mb)
	if err == nil {
		t.Fatal("expected webhook to reject missing credentialsRef")
	}
	if !strings.Contains(err.Error(), "credentialsRef") {
		t.Fatalf("wanted credentialsRef error, got %v", err)
	}
}

func TestWebhook_AcceptsValidBackend(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-3"}}
	_ = testClient.Create(context.Background(), ns)

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
				AuthType:  sigv1.SMTPAuthNone,
			},
		},
	}
	if err := testClient.Create(context.Background(), mb); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
}

func TestWebhook_RejectsCrossNamespaceCredentialsRef(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-5"}}
	_ = testClient.Create(context.Background(), ns)

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-ns", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
				AuthType:  sigv1.SMTPAuthPlain,
				CredentialsRef: &sigv1.SecretReference{
					Name:      "victim-secret",
					Namespace: "kube-system", // different namespace — must be rejected
				},
			},
		},
	}
	err := testClient.Create(context.Background(), mb)
	if err == nil {
		t.Fatal("expected webhook to reject cross-namespace credentialsRef")
	}
	if !strings.Contains(err.Error(), "cross-namespace") {
		t.Fatalf("wanted cross-namespace error, got %v", err)
	}
}

func TestWebhook_RejectsInsecureSkipVerify(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-6"}}
	_ = testClient.Create(context.Background(), ns)

	mb := &sigv1.MailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "insecure-tls", Namespace: ns.Name},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{
					Host:               "mx",
					Port:               587,
					TLS:                sigv1.SMTPTLSStartTLS,
					InsecureSkipVerify: true,
				}},
				AuthType: sigv1.SMTPAuthNone,
			},
		},
	}
	err := testClient.Create(context.Background(), mb)
	if err == nil {
		t.Fatal("expected webhook to reject insecureSkipVerify=true")
	}
	if !strings.Contains(err.Error(), "insecureSkipVerify") {
		t.Fatalf("wanted insecureSkipVerify error, got %v", err)
	}
}

func TestWebhook_MailPolicyRejectsEmptySubjects(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-4"}}
	_ = testClient.Create(context.Background(), ns)

	mp := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: ns.Name},
		Spec: sigv1.MailPolicySpec{
			Priority:   1,
			Subjects:   nil,
			BackendRef: sigv1.BackendRef{Name: "x", Kind: sigv1.KindClusterMailBackend},
		},
	}
	err := testClient.Create(context.Background(), mp)
	if err == nil {
		t.Fatal("expected webhook to reject empty subjects")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("wanted subject error, got %v", err)
	}
}

// An empty allowedSenders denies every sender while an omitted one allows
// all, so the API server must keep the two apart through a typed client.
func TestBackend_AllowedSendersEmptyAndOmittedStayApart(t *testing.T) {
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sigillum-wh-senders"}}
	_ = testClient.Create(ctx, ns)

	for _, tc := range []struct {
		name    string
		senders []string
	}{
		{"omitted", nil},
		{"empty", []string{}},
		{"listed", []string{"me@example.com", "*@noreply.example.com"}},
	} {
		mb := &sigv1.MailBackend{
			ObjectMeta: metav1.ObjectMeta{Name: tc.name, Namespace: ns.Name},
			Spec: sigv1.BackendSpec{
				Type: sigv1.BackendSMTP,
				SMTP: &sigv1.SMTPBackendSpec{
					Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
					AuthType:  sigv1.SMTPAuthNone,
				},
				AllowedSenders: tc.senders,
			},
		}
		if err := testClient.Create(ctx, mb); err != nil {
			t.Fatalf("%s: create: %v", tc.name, err)
		}
		// A status update sends the whole object back, as the controller does.
		mb.Status.ObservedGeneration = mb.Generation
		if err := testClient.Status().Update(ctx, mb); err != nil {
			t.Fatalf("%s: status update: %v", tc.name, err)
		}
		var got sigv1.MailBackend
		if err := testClient.Get(ctx, client.ObjectKeyFromObject(mb), &got); err != nil {
			t.Fatalf("%s: get: %v", tc.name, err)
		}
		if (got.Spec.AllowedSenders == nil) != (tc.senders == nil) || len(got.Spec.AllowedSenders) != len(tc.senders) {
			t.Fatalf("%s: allowedSenders = %#v, want %#v", tc.name, got.Spec.AllowedSenders, tc.senders)
		}
	}
}

func TestWebhook_RejectsUnanchoredBackendSender(t *testing.T) {
	cmb := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "unanchored-sender"},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
				AuthType:  sigv1.SMTPAuthNone,
			},
			AllowedSenders: []string{"*example.com"},
		},
	}
	err := testClient.Create(context.Background(), cmb)
	if err == nil || !strings.Contains(err.Error(), "spec.allowedSenders[0]") {
		t.Fatalf("want rejection of spec.allowedSenders[0], got %v", err)
	}
}
