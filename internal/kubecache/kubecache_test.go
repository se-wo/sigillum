package kubecache

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGuardSecretReads(t *testing.T) {
	ctx := context.Background()
	c := GuardSecretReads(fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "relay", Namespace: "sigillum-system"}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "team-a"}},
	).Build(), []string{"sigillum-system"})

	if err := c.Get(ctx, client.ObjectKey{Namespace: "sigillum-system", Name: "relay"}, &corev1.Secret{}); err != nil {
		t.Fatalf("allowed namespace: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "team-a", Name: "cm"}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("not a Secret: %v", err)
	}
	err := c.Get(ctx, client.ObjectKey{Namespace: "team-a", Name: "team-relay"}, &corev1.Secret{})
	var nsErr *SecretNamespaceError
	if !errors.As(err, &nsErr) || nsErr.Namespace != "team-a" || nsErr.Name != "team-relay" {
		t.Fatalf("want *SecretNamespaceError, got %v", err)
	}

	if !SecretNamespaceAllowed(nil, "any") {
		t.Fatal("no list must allow every namespace")
	}
}
