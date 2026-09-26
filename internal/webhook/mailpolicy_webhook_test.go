package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func validPolicy() *sigv1.MailPolicy {
	return &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: sigv1.MailPolicySpec{
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "sa"}}},
			BackendRef: sigv1.BackendRef{Name: "b", Kind: sigv1.KindClusterMailBackend},
		},
	}
}

func TestMailPolicyValidator_RecipientDomains(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		blocked []string
		wantErr string
	}{
		{name: "valid", allowed: []string{"example.com", "Customer.Example.com"}, blocked: []string{"gmail.com"}},
		{name: "address", allowed: []string{"a@example.com"}, wantErr: "bare domain"},
		{name: "glob", blocked: []string{"*.example.com"}, wantErr: "bare domain"},
		{name: "empty", allowed: []string{""}, wantErr: "allowedDomains[0]"},
		{name: "spaces", blocked: []string{"exa mple.com"}, wantErr: "blockedDomains[0]"},
	}
	v := &MailPolicyValidator{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mp := validPolicy()
			mp.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{AllowedDomains: tc.allowed, BlockedDomains: tc.blocked}
			_, err := v.ValidateCreate(context.Background(), mp)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestMailPolicyValidator_InvalidSelectorOperator(t *testing.T) {
	mp := validPolicy()
	mp.Spec.Subjects = []sigv1.PolicySubject{{ServiceAccountSelector: &sigv1.LabelSelectorSubject{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: "Bogus"}},
	}}}
	if _, err := (&MailPolicyValidator{}).ValidateCreate(context.Background(), mp); err == nil {
		t.Fatal("expected invalid selector operator to be rejected")
	}
}
