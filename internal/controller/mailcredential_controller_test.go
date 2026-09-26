package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

var credKey = types.NamespacedName{Namespace: "monitoring", Name: "grafana"}

// issuedCredential is a generated-mode credential whose rotation was just
// requested, with a password from an earlier rotation still in its grace
// period.
func issuedCredential(grace string) *sigv1.MailCredential {
	now := metav1.Now()
	return &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: credKey.Name, Namespace: credKey.Namespace, UID: "uid-1", Generation: 1,
			Annotations: map[string]string{sigv1.RotateAnnotation: "1"}},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "grafana-smtp",
			Rotation: &sigv1.CredentialRotation{GracePeriod: grace}},
		Status: sigv1.MailCredentialStatus{
			Username:   "grafana.monitoring",
			SecretName: "grafana-smtp",
			Current:    &sigv1.CredentialHash{Hash: credential.HashGenerated("current"), CreatedAt: now},
			Previous: &sigv1.PreviousCredentialHash{Hash: credential.HashGenerated("older"),
				ValidUntil: metav1.NewTime(now.Add(time.Hour))},
		},
	}
}

func credReconciler(t *testing.T, mc *sigv1.MailCredential, funcs interceptor.Funcs) (*MailCredentialReconciler, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := sigv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: credKey.Namespace}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(mc, sa).
		WithStatusSubresource(&sigv1.MailCredential{}).WithInterceptorFuncs(funcs).Build()
	return &MailCredentialReconciler{
		Client:           c,
		Exclusions:       credential.ParseExclusions("kube-*", "sigillum-system"),
		GeneratedEnabled: true,
		Guard:            &GuardChecker{checked: true},
		GeneratePassword: func() (string, error) { return "new-password", nil },
	}, c
}

func getCredential(t *testing.T, c client.Client) *sigv1.MailCredential {
	t.Helper()
	var mc sigv1.MailCredential
	if err := c.Get(context.Background(), credKey, &mc); err != nil {
		t.Fatal(err)
	}
	return &mc
}

// With gracePeriod 0 the rotated-out password stops working at once, and an
// older previous password from an earlier rotation must not stay valid.
func TestRotationWithoutGraceClearsPrevious(t *testing.T) {
	r, c := credReconciler(t, issuedCredential("0s"), interceptor.Funcs{})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	mc := getCredential(t, c)
	if mc.Status.Previous != nil {
		t.Fatalf("previous password must not survive a zero-grace rotation: %+v", mc.Status.Previous)
	}
	if !credential.VerifyGenerated(mc.Status.Current.Hash, "new-password") {
		t.Fatal("current hash must be the new password")
	}
}

// A conflict on the status write after the Secret got a new password is
// retried, so the hash of the password in the Secret is not lost.
func TestRotationStatusWriteRetriedOnConflict(t *testing.T) {
	conflicts := 0
	r, c := credReconciler(t, issuedCredential("1h"), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if conflicts == 0 {
				conflicts++
				return apierrors.NewConflict(schema.GroupResource{Group: "sigillum.dev", Resource: "mailcredentials"},
					obj.GetName(), nil)
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	mc := getCredential(t, c)
	if conflicts != 1 || mc.Status.Current == nil || !credential.VerifyGenerated(mc.Status.Current.Hash, "new-password") {
		t.Fatalf("hash of the written password must reach status after a conflict: %+v", mc.Status)
	}
	if mc.Status.Previous == nil || !credential.VerifyGenerated(mc.Status.Previous.Hash, "current") {
		t.Fatalf("the rotated-out password keeps its grace period: %+v", mc.Status.Previous)
	}
}

// Missing RBAC is a write failure, not a foreign Secret; the issued
// password stays valid.
func TestForbiddenSecretWriteIsNotAConflict(t *testing.T) {
	r, c := credReconciler(t, issuedCredential("1h"), interceptor.Funcs{
		// The Secret exists (Create: AlreadyExists), and patching it is
		// forbidden by RBAC.
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, obj.GetName())
			}
			return cl.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), nil)
			}
			return cl.Patch(ctx, obj, p, opts...)
		},
	})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err == nil {
		t.Fatal("a failed Secret write must be retried with backoff")
	}
	mc := getCredential(t, c)
	ready := meta.FindStatusCondition(mc.Status.Conditions, sigv1.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || ready.Reason == sigv1.ReasonSecretConflict {
		t.Fatalf("issued password stays usable and the failure is not a conflict: %+v", ready)
	}
	if !credential.VerifyGenerated(mc.Status.Current.Hash, "current") {
		t.Fatal("status must keep the hash of the password still in the Secret")
	}
}
