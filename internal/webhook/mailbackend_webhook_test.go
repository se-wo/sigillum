package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	_ "github.com/se-wo/sigillum/internal/driver/smtp" // registers type smtp
)

func validClusterBackend(senders []string) *sigv1.ClusterMailBackend {
	return &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "relay"},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendSMTP,
			SMTP: &sigv1.SMTPBackendSpec{
				Endpoints: []sigv1.SMTPEndpoint{{Host: "mx", Port: 587, TLS: sigv1.SMTPTLSStartTLS}},
				AuthType:  sigv1.SMTPAuthNone,
			},
			AllowedSenders: senders,
		},
	}
}

func TestMailBackendValidator_AllowedSenders(t *testing.T) {
	cases := []struct {
		name     string
		senders  []string
		wantErr  string
		wantWarn bool
	}{
		{name: "omitted", senders: nil},
		{name: "addresses and anchored globs", senders: []string{"me@outlook.com", "*@example.com", "noreply-?@example.com"}},
		{name: "empty list warns", senders: []string{}, wantWarn: true},
		{name: "empty entry", senders: []string{""}, wantErr: "allowedSenders[0]"},
		{name: "star", senders: []string{"*"}, wantErr: "<local-part pattern>@<domain>"},
		{name: "glob across the at sign", senders: []string{"me@outlook.com", "*example.com"}, wantErr: "allowedSenders[1]"},
		{name: "wildcard domain", senders: []string{"*@*.example.com"}, wantErr: "must not contain wildcards"},
		{name: "bare domain", senders: []string{"example.com"}, wantErr: "plain address"},
		{name: "display name", senders: []string{"Me <me@example.com>"}, wantErr: "allowedSenders[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warns, err := NewClusterMailBackendValidator().ValidateCreate(context.Background(), validClusterBackend(tc.senders))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if gotWarn := len(warns) > 0; gotWarn != tc.wantWarn {
				t.Fatalf("warnings = %v, want warning: %v", warns, tc.wantWarn)
			}
			if tc.wantErr != "" && strings.Contains(err.Error(), "allowedDomains") {
				t.Fatalf("a backend has no allowedDomains to point to: %v", err)
			}
		})
	}
}
