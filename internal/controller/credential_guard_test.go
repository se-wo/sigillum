package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

// After a verdict change the leader requeues every generated credential,
// however many there are (review of #20: a non-blocking send dropped
// events beyond the channel buffer, leaving SecretsManaged stale).
func TestGuardRequeuerDeliversEveryGeneratedCredential(t *testing.T) {
	s := runtime.NewScheme()
	if err := sigv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	const generated = 1500
	objs := []client.Object{&sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "own-hash", Namespace: "a"},
		Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "x", PasswordHash: "$argon2id$..."},
	}}
	for i := 0; i < generated; i++ {
		objs = append(objs, &sigv1.MailCredential{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("c%d", i), Namespace: "a"},
			Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "x", SecretName: "s"},
		})
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	g := NewGuardChecker(credential.Guard{Name: "guard"}, c, c, time.Hour, logr.Discard())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = g.Requeuer().Start(ctx) }()
	g.Check(ctx) // no guard in the fake cluster: verdict changes to "missing"

	seen := map[string]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < generated {
		select {
		case ev := <-g.Events():
			seen[ev.Object.GetName()] = true
		case <-timeout:
			t.Fatalf("only %d of %d generated credentials requeued", len(seen), generated)
		}
	}
	if seen["own-hash"] {
		t.Fatal("bring-your-own-hash credentials do not depend on the guard")
	}
	if ok, _ := g.OK(); ok {
		t.Fatal("a missing guard must not verify")
	}
}

// Review of #20: a failed lookup (timeout, API server restart) keeps the
// last verdict; only a missing, forbidden or changed guard flips it.
func TestGuardCheckKeepsVerdictOnTransientErrors(t *testing.T) {
	s := runtime.NewScheme()
	if err := admv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	guard := credential.Guard{Name: "guard", ControllerUsername: "system:serviceaccount:sigillum-system:controller",
		Exclusions: credential.ParseExclusions("kube-*", "sigillum-system")}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(guard.Policy(), guard.Binding()).Build()
	var failWith error
	c := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if failWith != nil {
				return failWith
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	g := NewGuardChecker(guard, c, c, time.Hour, logr.Discard())
	ctx := context.Background()
	if !g.Check(ctx) {
		t.Fatal("first check sets the verdict")
	}
	if ok, msg := g.OK(); !ok {
		t.Fatalf("guard must verify: %s", msg)
	}

	failWith = apierrors.NewTimeoutError("etcd leader change", 1)
	if g.Check(ctx) {
		t.Fatal("a timeout must not change the verdict")
	}
	if ok, _ := g.OK(); !ok {
		t.Fatal("a timeout must keep the guard verified")
	}

	failWith = apierrors.NewNotFound(schema.GroupResource{Group: "admissionregistration.k8s.io",
		Resource: "validatingadmissionpolicies"}, guard.Name)
	if !g.Check(ctx) {
		t.Fatal("a deleted guard changes the verdict")
	}
	if ok, _ := g.OK(); ok {
		t.Fatal("a deleted guard must not verify")
	}
}

// Review of #20: a failed List after a verdict change is retried; the
// change signal was consumed, so giving up would leave conditions stale.
func TestGuardRequeuerRetriesFailedList(t *testing.T) {
	s := runtime.NewScheme()
	if err := sigv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(&sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "a"},
		Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "x", SecretName: "s"},
	}).Build()
	failures := 1
	lister := interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if failures > 0 {
				failures--
				return apierrors.NewTimeoutError("list timed out", 1)
			}
			return cl.List(ctx, list, opts...)
		},
	})
	old := requeueRetryDelay
	requeueRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { requeueRetryDelay = old })

	g := NewGuardChecker(credential.Guard{Name: "guard"}, base, lister, time.Hour, logr.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = g.Requeuer().Start(ctx) }()
	g.Check(ctx)
	select {
	case ev := <-g.Events():
		if ev.Object.GetName() != "c" {
			t.Fatalf("unexpected requeue %s", ev.Object.GetName())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the credential was not requeued after the List failed once")
	}
}

// Review of #20: a guard that goes from missing to tampered changes the
// verdict's reason, which must requeue and log like any other change.
func TestGuardCheckDetectsReasonChange(t *testing.T) {
	s := runtime.NewScheme()
	if err := admv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	guard := credential.Guard{Name: "guard", ControllerUsername: "system:serviceaccount:sigillum-system:controller",
		Exclusions: credential.ParseExclusions("kube-*", "sigillum-system")}
	c := fake.NewClientBuilder().WithScheme(s).Build()
	g := NewGuardChecker(guard, c, c, time.Hour, logr.Discard())
	ctx := context.Background()
	g.Check(ctx) // missing
	weakened := guard.Policy()
	weakened.Spec.Validations = weakened.Spec.Validations[:1]
	if err := c.Create(ctx, weakened); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, guard.Binding()); err != nil {
		t.Fatal(err)
	}
	if !g.Check(ctx) {
		t.Fatal("missing → tampered must count as a change")
	}
	if _, msg := g.OK(); !strings.Contains(msg, "validations changed") {
		t.Fatalf("the verdict must name the current problem, got %q", msg)
	}
	if g.Check(ctx) {
		t.Fatal("the same failure again is no change")
	}
}
