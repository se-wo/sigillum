//go:build envtest

package crdcheck

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestWaitAgainstAPIServer runs the check against the schemas a real API
// server publishes: first with a 0.2 MailPolicy CRD and no MailCredential
// CRD, then after the CRDs of this release are applied.
func TestWaitAgainstAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	crds := loadCRDs(t)
	stale := crds["MailPolicy"].DeepCopy()
	rr := stale.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["recipientRestrictions"]
	delete(rr.Properties, "allowedRecipients")
	stale.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["recipientRestrictions"] = rr

	env := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{stale}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx := context.Background()

	err = Wait(ctx, cfg, Required, 5*time.Second)
	for _, want := range []string{
		"the MailPolicy CRD has no field spec.recipientRestrictions.allowedRecipients",
		"kind MailCredential is not installed",
		"kubectl apply --server-side -f charts/sigillum/crds/",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("outdated CRDs: want %q, got %v", want, err)
		}
	}

	scheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	cur := &apiextensionsv1.CustomResourceDefinition{}
	if err := c.Get(ctx, client.ObjectKey{Name: stale.Name}, cur); err != nil {
		t.Fatal(err)
	}
	crds["MailPolicy"].ResourceVersion = cur.ResourceVersion
	if err := c.Update(ctx, crds["MailPolicy"]); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, crds["MailCredential"]); err != nil {
		t.Fatal(err)
	}
	// Published a few seconds after the update; Wait retries.
	if err := Wait(ctx, cfg, Required, 30*time.Second); err != nil {
		t.Fatalf("current CRDs: %v", err)
	}

	// A ServiceAccount without any RoleBinding can run the check.
	sa := rest.CopyConfig(cfg)
	sa.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:default:unprivileged",
		Groups:   []string{"system:serviceaccounts", "system:authenticated"},
	}
	saClient, err := client.New(sa, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saClient.List(ctx, &corev1.SecretList{}); !apierrors.IsForbidden(err) {
		t.Fatalf("RBAC not enforced (list secrets: %v)", err)
	}
	if err := Wait(ctx, sa, Required, 10*time.Second); err != nil {
		t.Fatalf("unprivileged ServiceAccount: %v", err)
	}
}
