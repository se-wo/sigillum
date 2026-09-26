package smtpproxy

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/gateway"
)

type auditRecorder struct{ events []audit.Event }

func (a *auditRecorder) Record(e audit.Event) { a.events = append(a.events, e) }

// The SMTP path enforces allowedRecipients on the envelope recipients
// through the real gateway pipeline (issue #6).
func TestAllowedRecipientsOnSMTP(t *testing.T) {
	pol := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "alerts-only", Namespace: "billing"},
		Spec: sigv1.MailPolicySpec{
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "mailer"}}},
			BackendRef: sigv1.BackendRef{Name: "relay", Kind: sigv1.KindClusterMailBackend},
			RecipientRestrictions: &sigv1.RecipientRestrictions{
				AllowedRecipients: []string{"alerts@contoso.com", "*@oncall.contoso.com"},
			},
		},
	}
	cl := credentialClient(t, pol)
	rec := &auditRecorder{}
	gw := &gateway.Gateway{Logger: discardLogger(), Audit: rec,
		Policies: gateway.CachedPolicyStore{C: cl}, Reader: cl}
	c := authed(t, startProxy(t, &Backend{Sender: gw, Tokens: stubTokens{}}))

	msg := "From: app@billing.example\r\nTo: ceo@contoso.com\r\nSubject: x\r\n\r\nbody\r\n"
	err := send(c, "app@billing.example", []string{"alerts@contoso.com", "ceo@contoso.com"}, msg)
	if smtpCode(err) != 550 {
		t.Fatalf("mailbox outside allowedRecipients: want 550, got %v", err)
	}
	if ev := rec.events[len(rec.events)-1]; ev.Reason != "recipient_not_allowed" || ev.Policy != "alerts-only" {
		t.Fatalf("unexpected audit record %+v", ev)
	}

	// Allowed recipients pass the policy and stop at the (missing) backend.
	err = send(c, "app@billing.example", []string{"alerts@contoso.com", "pager@oncall.contoso.com"}, msg)
	if smtpCode(err) != 451 {
		t.Fatalf("allowed recipients: want to pass the policy (451 backend not ready), got %v", err)
	}
	if ev := rec.events[len(rec.events)-1]; ev.Reason != "backend_not_ready" {
		t.Fatalf("unexpected audit record %+v", ev)
	}
	if !strings.Contains(err.Error(), "id ") {
		t.Fatalf("reply must carry the message id: %v", err)
	}
}
