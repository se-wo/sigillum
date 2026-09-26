package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
