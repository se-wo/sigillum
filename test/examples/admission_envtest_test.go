//go:build envtest

package examples

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// TestAdmissionRecipes applies the ValidatingAdmissionPolicy recipes in
// examples/admission to a real API server and checks what they admit.
func TestAdmissionRecipes(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(examplesDir(), "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	scheme := k8sruntime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = sigv1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for _, d := range loadExamples(t) {
		if !strings.HasPrefix(d.file, "admission"+string(filepath.Separator)+"vap-") {
			continue
		}
		obj := d.obj.DeepCopy()
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("%s: %v", d.file, err)
		}
	}
	for name, labels := range map[string]map[string]string{
		"billing": {
			"environment":                          "production",
			"sigillum.dev/sender-domain":           "billing.example.com",
			"backends.sigillum.dev/corporate-smtp": "true",
		},
		"dev": nil,
	} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}); err != nil {
			t.Fatal(err)
		}
	}

	policy := func(ns string, mutate func(*sigv1.MailPolicySpec)) *sigv1.MailPolicy {
		p := &sigv1.MailPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "p-", Namespace: ns},
			Spec: sigv1.MailPolicySpec{
				Subjects:           []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "app"}}},
				BackendRef:         sigv1.BackendRef{Name: "corporate-smtp", Kind: sigv1.KindClusterMailBackend},
				SenderRestrictions: &sigv1.SenderRestrictions{AllowedSenders: []string{"*@billing.example.com"}},
			},
		}
		if mutate != nil {
			mutate(&p.Spec)
		}
		return p
	}

	cases := []struct {
		name    string
		ns      string
		mutate  func(*sigv1.MailPolicySpec)
		wantErr string
	}{
		{name: "compliant production policy", ns: "billing"},
		{name: "sender outside the namespace domain", ns: "billing",
			mutate:  func(s *sigv1.MailPolicySpec) { s.SenderRestrictions.AllowedSenders = []string{"*example.com"} },
			wantErr: "must end in @billing.example.com"},
		{name: "subdomain is not the domain", ns: "billing",
			mutate: func(s *sigv1.MailPolicySpec) {
				s.SenderRestrictions.AllowedSenders = []string{"x@evil.billing.example.com.test"}
			},
			wantErr: "must end in @billing.example.com"},
		{name: "pod-IP fallback in production", ns: "billing",
			mutate:  func(s *sigv1.MailPolicySpec) { s.LegacyAuth = &sigv1.LegacyAuthSpec{PodIPFallback: true} },
			wantErr: "podIPFallback"},
		{name: "cluster backend without namespace opt-in", ns: "billing",
			mutate:  func(s *sigv1.MailPolicySpec) { s.BackendRef.Name = "marketing-smtp" },
			wantErr: "may not use ClusterMailBackend marketing-smtp"},
		{name: "senders required everywhere", ns: "dev",
			mutate: func(s *sigv1.MailPolicySpec) {
				// Only this recipe may be violated: when several policies
				// deny, the API server reports just one of them.
				s.SenderRestrictions = nil
				s.BackendRef = sigv1.BackendRef{Name: "mailpit", Kind: sigv1.KindMailBackend}
			},
			wantErr: "allowedSenders"},
		{name: "dev namespace may not use the corporate relay", ns: "dev",
			wantErr: "may not use ClusterMailBackend corporate-smtp"},
		{name: "own MailBackend needs no opt-in", ns: "dev",
			mutate: func(s *sigv1.MailPolicySpec) {
				s.BackendRef = sigv1.BackendRef{Name: "mailpit", Kind: sigv1.KindMailBackend}
			}},
		{name: "pod-IP fallback outside production", ns: "dev",
			mutate: func(s *sigv1.MailPolicySpec) {
				s.BackendRef = sigv1.BackendRef{Name: "mailpit", Kind: sigv1.KindMailBackend}
				s.LegacyAuth = &sigv1.LegacyAuthSpec{PodIPFallback: true}
			}},
	}
	// Policies are loaded asynchronously, each on its own: poll every
	// denial until its recipe bites (each case violates exactly one recipe).
	// Admissions are checked after all denials, so every policy is loaded.
	for _, tc := range cases {
		if tc.wantErr == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			deadline := time.Now().Add(30 * time.Second)
			for {
				err := c.Create(ctx, policy(tc.ns, tc.mutate), client.DryRunAll)
				if err != nil && strings.Contains(err.Error(), tc.wantErr) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("want denial containing %q, got %v", tc.wantErr, err)
				}
				time.Sleep(200 * time.Millisecond)
			}
		})
	}
	for _, tc := range cases {
		if tc.wantErr != "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Create(ctx, policy(tc.ns, tc.mutate)); err != nil {
				t.Fatalf("unexpected denial: %v", err)
			}
		})
	}
}
