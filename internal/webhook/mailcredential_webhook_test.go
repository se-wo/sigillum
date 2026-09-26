package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

func TestMailCredentialValidator(t *testing.T) {
	byo := credential.HashArgon2id("pw", []byte("0123456789abcdef"), 19*1024, 2, 1)
	cases := []struct {
		name     string
		ns       string
		spec     sigv1.MailCredentialSpec
		disabled bool
		wantErr  string
		notInErr string
	}{
		{name: "generated", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "grafana-smtp",
			Rotation: &sigv1.CredentialRotation{Interval: "90d", GracePeriod: "24h"}}},
		{name: "bring your own hash", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", PasswordHash: byo}},
		{name: "neither mode", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana"}, wantErr: "spec.secretName"},
		{name: "both modes", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "s", PasswordHash: byo},
			wantErr: "mutually exclusive"},
		{name: "rotation with own hash", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", PasswordHash: byo,
			Rotation: &sigv1.CredentialRotation{Interval: "90d"}}, wantErr: "spec.rotation"},
		{name: "plaintext password", spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", PasswordHash: "hunter2"},
			wantErr: "never the plaintext", notInErr: "hunter2"},
		{name: "missing service account", spec: sigv1.MailCredentialSpec{SecretName: "s"}, wantErr: "serviceAccountName"},
		{name: "bad interval", spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", SecretName: "s",
			Rotation: &sigv1.CredentialRotation{Interval: "90 days"}}, wantErr: "spec.rotation.interval"},
		{name: "interval too short", spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", SecretName: "s",
			Rotation: &sigv1.CredentialRotation{Interval: "90s"}}, wantErr: "at least 1h"},
		{name: "bad secret name", spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", SecretName: "Bad_Name"},
			wantErr: "spec.secretName"},
		{name: "excluded namespace", ns: "kube-system", spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", SecretName: "s"},
			wantErr: "excluded"},
		{name: "release namespace", ns: "sigillum-system", spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", PasswordHash: byo},
			wantErr: "excluded"},
		{name: "generated disabled", disabled: true, spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", SecretName: "s"},
			wantErr: "generated credentials are disabled"},
		{name: "own hash while generated disabled", disabled: true,
			spec: sigv1.MailCredentialSpec{ServiceAccountName: "a", PasswordHash: byo}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &MailCredentialValidator{
				Exclusions:       credential.ParseExclusions("kube-*", "sigillum-system"),
				GeneratedEnabled: !tc.disabled,
			}
			ns := tc.ns
			if ns == "" {
				ns = "monitoring"
			}
			mc := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: ns}, Spec: tc.spec}
			_, err := v.ValidateCreate(context.Background(), mc)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if tc.notInErr != "" && strings.Contains(err.Error(), tc.notInErr) {
				t.Fatalf("error must not echo %q: %v", tc.notInErr, err)
			}
		})
	}
}
