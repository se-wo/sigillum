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

func TestMailPolicyValidator_AllowedRecipients(t *testing.T) {
	cases := []struct {
		name    string
		rcpts   []string
		wantErr string
	}{
		{name: "valid", rcpts: []string{"qa@staging.example.com", "QA-Team@example.com"}},
		{name: "globs anchored on a domain", rcpts: []string{"*@oncall.example.com", "alerts-?@example.com", "team-[ab]@example.com"}},
		{name: "domain only", rcpts: []string{"example.com"}, wantErr: "allowedRecipients[0]"},
		{name: "star", rcpts: []string{"*"}, wantErr: "<local-part pattern>@<domain>"},
		{name: "star at star", rcpts: []string{"*@*"}, wantErr: "must not contain wildcards"},
		{name: "unanchored domain", rcpts: []string{"*@*.example.com"}, wantErr: "must not contain wildcards"},
		{name: "glob across the at sign", rcpts: []string{"*example.com"}, wantErr: "<local-part pattern>@<domain>"},
		{name: "two at signs", rcpts: []string{"*@x@example.com"}, wantErr: "<local-part pattern>@<domain>"},
		{name: "empty local part", rcpts: []string{"@example.com"}, wantErr: "allowedRecipients[0]"},
		{name: "routing in pattern", rcpts: []string{"*%evil.test@example.com"}, wantErr: "routing"},
		{name: "bad glob", rcpts: []string{"[a@example.com"}, wantErr: "invalid glob"},
		{name: "display name", rcpts: []string{"QA <qa@example.com>"}, wantErr: "plain address"},
		{name: "percent hack", rcpts: []string{"qa%evil.test@example.com"}, wantErr: "allowedRecipients[0]"},
		{name: "empty", rcpts: []string{""}, wantErr: "allowedRecipients[0]"},
	}
	v := &MailPolicyValidator{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mp := validPolicy()
			mp.Spec.RecipientRestrictions = &sigv1.RecipientRestrictions{AllowedRecipients: tc.rcpts}
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

// #44: a policy's allowedSenders are validated like a backend's, but only
// as a warning for now (0.x compatibility) — never a hard error.
func TestMailPolicyValidator_AllowedSendersWarn(t *testing.T) {
	v := &MailPolicyValidator{}
	for _, tc := range []struct {
		name, entry, want string
	}{
		{"wildcard all", "*", "future release"},
		{"unanchored", "*example.com", "future release"},
		{"plain ok", "noreply@example.com", ""},
		{"anchored glob ok", "*@example.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp := validPolicy()
			mp.Spec.SenderRestrictions = &sigv1.SenderRestrictions{AllowedSenders: []string{tc.entry}}
			w, err := v.ValidateCreate(context.Background(), mp)
			if err != nil {
				t.Fatalf("allowedSenders must never be a hard error, got %v", err)
			}
			joined := strings.Join(w, "\n")
			if tc.want == "" {
				if len(w) != 0 {
					t.Fatalf("%q must not warn, got %v", tc.entry, w)
				}
			} else if !strings.Contains(joined, tc.want) || !strings.Contains(joined, tc.entry) {
				t.Fatalf("want a warning naming %q and %q, got %v", tc.entry, tc.want, w)
			}
		})
	}
	// An empty entry stays a hard error.
	mp := validPolicy()
	mp.Spec.SenderRestrictions = &sigv1.SenderRestrictions{AllowedSenders: []string{""}}
	if _, err := v.ValidateCreate(context.Background(), mp); err == nil {
		t.Fatal("an empty allowedSenders entry must be an error")
	}
}
