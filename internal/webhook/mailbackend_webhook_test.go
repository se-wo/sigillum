package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	_ "github.com/se-wo/sigillum/internal/driver/gmail" // registers type gmail
	_ "github.com/se-wo/sigillum/internal/driver/graph" // registers type microsoftGraph
	_ "github.com/se-wo/sigillum/internal/driver/smtp"  // registers type smtp
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

func graphBackend(mutate func(*sigv1.BackendSpec)) *sigv1.ClusterMailBackend {
	b := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "m365"},
		Spec: sigv1.BackendSpec{
			Type: sigv1.BackendMicrosoftGraph,
			MicrosoftGraph: &sigv1.MicrosoftGraphBackendSpec{
				TenantID:       "72f988bf-86f1-41af-91ab-2d7cd011db47",
				ClientID:       "11111111-2222-3333-4444-555555555555",
				CredentialsRef: sigv1.SecretReference{Name: "m365", Namespace: "sigillum-system"},
			},
			AllowedSenders: []string{"noreply@contoso.com"},
		},
	}
	if mutate != nil {
		mutate(&b.Spec)
	}
	return b
}

func TestMailBackendValidator_MicrosoftGraph(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sigv1.BackendSpec)
		wantErr string
	}{
		{name: "valid"},
		{name: "verified domain as tenant", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph.TenantID = "contoso.onmicrosoft.com" }},
		{name: "missing block", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph = nil }, wantErr: "spec.microsoftGraph"},
		{name: "tenant with a path", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph.TenantID = "common/../x" }, wantErr: "tenantID"},
		{name: "upper-case tenant", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph.TenantID = "Contoso.com" }, wantErr: "tenantID"},
		{name: "client ID not a GUID", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph.ClientID = "my-app" }, wantErr: "clientID"},
		{name: "no namespace on a cluster backend", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph.CredentialsRef.Namespace = "" },
			wantErr: "credentialsRef.namespace"},
		{name: "allowedSenders omitted", mutate: func(s *sigv1.BackendSpec) { s.AllowedSenders = nil }, wantErr: "spec.allowedSenders"},
		{name: "allowedSenders empty", mutate: func(s *sigv1.BackendSpec) { s.AllowedSenders = []string{} }, wantErr: "spec.allowedSenders"},
		{name: "smtp block as well", mutate: func(s *sigv1.BackendSpec) { s.SMTP = &sigv1.SMTPBackendSpec{} }, wantErr: "spec.smtp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClusterMailBackendValidator().ValidateCreate(context.Background(), graphBackend(tc.mutate))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	// A namespaced MailBackend reads its own namespace only.
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "m365", Namespace: "team"}, Spec: graphBackend(nil).Spec}
	if _, err := NewMailBackendValidator().ValidateCreate(context.Background(), mb); err == nil || !strings.Contains(err.Error(), "cross-namespace") {
		t.Fatalf("want cross-namespace refusal, got %v", err)
	}

	// The graph block on an smtp backend is refused too.
	smtp := validClusterBackend(nil)
	smtp.Spec.MicrosoftGraph = graphBackend(nil).Spec.MicrosoftGraph
	if _, err := NewClusterMailBackendValidator().ValidateCreate(context.Background(), smtp); err == nil || !strings.Contains(err.Error(), "spec.microsoftGraph") {
		t.Fatalf("want spec.microsoftGraph refused on smtp, got %v", err)
	}
}

func gmailBackend(mutate func(*sigv1.BackendSpec)) *sigv1.ClusterMailBackend {
	b := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "workspace"},
		Spec: sigv1.BackendSpec{
			Type:           sigv1.BackendGmail,
			Gmail:          &sigv1.GmailBackendSpec{CredentialsRef: sigv1.SecretReference{Name: "workspace", Namespace: "sigillum-system"}},
			AllowedSenders: []string{"noreply@example.com"},
		},
	}
	if mutate != nil {
		mutate(&b.Spec)
	}
	return b
}

func TestMailBackendValidator_Gmail(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*sigv1.BackendSpec)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing block", mutate: func(s *sigv1.BackendSpec) { s.Gmail = nil }, wantErr: "spec.gmail"},
		{name: "no namespace on a cluster backend", mutate: func(s *sigv1.BackendSpec) { s.Gmail.CredentialsRef.Namespace = "" },
			wantErr: "gmail.credentialsRef.namespace"},
		{name: "allowedSenders omitted", mutate: func(s *sigv1.BackendSpec) { s.AllowedSenders = nil }, wantErr: "spec.allowedSenders"},
		{name: "allowedSenders empty", mutate: func(s *sigv1.BackendSpec) { s.AllowedSenders = []string{} }, wantErr: "spec.allowedSenders"},
		{name: "smtp block as well", mutate: func(s *sigv1.BackendSpec) { s.SMTP = &sigv1.SMTPBackendSpec{} }, wantErr: "spec.smtp"},
		{name: "graph block as well", mutate: func(s *sigv1.BackendSpec) { s.MicrosoftGraph = &sigv1.MicrosoftGraphBackendSpec{} },
			wantErr: "spec.microsoftGraph"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClusterMailBackendValidator().ValidateCreate(context.Background(), gmailBackend(tc.mutate))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	// The gmail block on other types is refused.
	smtp := validClusterBackend(nil)
	smtp.Spec.Gmail = gmailBackend(nil).Spec.Gmail
	if _, err := NewClusterMailBackendValidator().ValidateCreate(context.Background(), smtp); err == nil || !strings.Contains(err.Error(), "spec.gmail") {
		t.Fatalf("want spec.gmail refused on smtp, got %v", err)
	}
	// A namespaced MailBackend reads its own namespace only.
	mb := &sigv1.MailBackend{ObjectMeta: metav1.ObjectMeta{Name: "workspace", Namespace: "team"}, Spec: gmailBackend(nil).Spec}
	if _, err := NewMailBackendValidator().ValidateCreate(context.Background(), mb); err == nil || !strings.Contains(err.Error(), "cross-namespace") {
		t.Fatalf("want cross-namespace refusal, got %v", err)
	}
}
