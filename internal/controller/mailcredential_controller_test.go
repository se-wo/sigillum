package controller

import (
	"context"
	"fmt"
	"strings"
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

// Review of #20: any status write failure after the Secret got a new
// password is retried, not only a conflict. A timeout that was given up on
// dropped the hash of the password in the Secret.
func TestRotationStatusWriteRetriedOnTimeout(t *testing.T) {
	failures := 0
	r, c := credReconciler(t, issuedCredential("1h"), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if failures < 2 {
				failures++
				return apierrors.NewTimeoutError("request timed out", 1)
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	mc := getCredential(t, c)
	if failures != 2 || mc.Status.Current == nil || !credential.VerifyGenerated(mc.Status.Current.Hash, "new-password") {
		t.Fatalf("hash of the written password must reach status after a timeout: %+v", mc.Status)
	}
}

// Review of #20: pointing spec.secretName at a foreign Secret must not take
// down a credential whose password is still in the previous Secret.
func TestSecretConflictKeepsIssuedPassword(t *testing.T) {
	mc := issuedCredential("1h")
	mc.Annotations = nil
	mc.Spec.SecretName = "tls-cert"
	r, c := credReconciler(t, mc, interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, obj.GetName())
			}
			return cl.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				return apierrors.NewInvalid(schema.GroupKind{Kind: "Secret"}, obj.GetName(), nil)
			}
			return cl.Patch(ctx, obj, p, opts...)
		},
	})
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey})
	if err != nil || res.RequeueAfter == 0 {
		t.Fatalf("a conflict is retried later: %v, %+v", err, res)
	}
	got := getCredential(t, c)
	ready := meta.FindStatusCondition(got.Status.Conditions, sigv1.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || !strings.Contains(ready.Message, "not owned by this MailCredential") {
		t.Fatalf("password in grafana-smtp stays usable, the conflict is reported: %+v", ready)
	}
	if got.Status.SecretName != "grafana-smtp" || !credential.VerifyGenerated(got.Status.Current.Hash, "current") {
		t.Fatalf("status keeps the issued password: %+v", got.Status)
	}
}

// Review of #20: logins follow the state the controller accepted. A
// replaced bring-your-own hash stops working at once and the new one works
// after the reconcile; the ServiceAccount is recorded in status.
func TestBringYourOwnHashAcceptedIntoStatus(t *testing.T) {
	mc := &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: credKey.Name, Namespace: credKey.Namespace, UID: "uid-1", Generation: 1},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana",
			PasswordHash: credential.HashArgon2id("one", []byte("0123456789abcdef"), 7*1024, 5, 1)},
	}
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	got := getCredential(t, c)
	if !credential.Usable(got) || got.Status.ServiceAccountName != "grafana" || got.Status.Current.Hash != mc.Spec.PasswordHash {
		t.Fatalf("accepted bring-your-own hash must be usable: %+v", got.Status)
	}
	got.Spec.PasswordHash = credential.HashArgon2id("two", []byte("0123456789abcdef"), 7*1024, 5, 1)
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if credential.Usable(getCredential(t, c)) {
		t.Fatal("a replaced hash must not be usable before the controller accepted it")
	}
	reconcile()
	if got := getCredential(t, c); !credential.Usable(got) || got.Status.Current.Hash != got.Spec.PasswordHash {
		t.Fatalf("the new hash must be usable once accepted: %+v", got.Status)
	}
}

// Review of #20: switching from bring your own hash to generated mode must
// not advertise a grace period for the argon2id hash, which generated mode
// cannot verify.
func TestSwitchToGeneratedDropsOwnHash(t *testing.T) {
	phc := credential.HashArgon2id("one", []byte("0123456789abcdef"), 7*1024, 5, 1)
	mc := issuedCredential("1h")
	mc.Status.SecretName, mc.Status.Previous = "", nil
	mc.Status.Current = &sigv1.CredentialHash{Hash: phc, CreatedAt: metav1.Now()}
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	got := getCredential(t, c)
	if got.Status.Previous != nil {
		t.Fatalf("the own hash must not become the previous password: %+v", got.Status.Previous)
	}
	if !credential.VerifyGenerated(got.Status.Current.Hash, "new-password") {
		t.Fatalf("a generated password must be issued: %+v", got.Status.Current)
	}
}

// Review of #20: a name longer than a label value cannot be a generated
// credential (webhook disabled); it must fail once, not retry forever.
func TestGeneratedNameTooLongIsInvalid(t *testing.T) {
	mc := issuedCredential("1h")
	mc.Name = strings.Repeat("a", 64)
	mc.Status = sigv1.MailCredentialStatus{}
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	key := client.ObjectKeyFromObject(mc)
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil || res.RequeueAfter != 0 {
		t.Fatalf("an invalid name is not retried: %v, %+v", err, res)
	}
	var got sigv1.MailCredential
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(got.Status.Conditions, sigv1.ConditionReady)
	if ready == nil || ready.Reason != sigv1.ReasonInvalidConfiguration || !strings.Contains(ready.Message, "label value") {
		t.Fatalf("want InvalidConfiguration naming the label limit, got %+v", ready)
	}
}

// Review of #20: with the webhook disabled, a typo such as "90s" must not
// rotate the password every 90 seconds.
func TestShortRotationIntervalIsInvalid(t *testing.T) {
	mc := issuedCredential("1h")
	mc.Spec.Rotation.Interval = "90s"
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey})
	if err != nil || res.RequeueAfter != 0 {
		t.Fatalf("an invalid interval is not retried: %v, %+v", err, res)
	}
	got := getCredential(t, c)
	ready := meta.FindStatusCondition(got.Status.Conditions, sigv1.ConditionReady)
	if ready == nil || ready.Reason != sigv1.ReasonInvalidConfiguration || !strings.Contains(ready.Message, "at least 1h") {
		t.Fatalf("want InvalidConfiguration, got %+v", ready)
	}
	if !credential.VerifyGenerated(got.Status.Current.Hash, "current") {
		t.Fatal("no rotation may happen")
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
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey})
	if err == nil {
		t.Fatal("a failed Secret write must be retried with backoff")
	}
	// Review of #20: controller-runtime ignores (and warns about) a
	// Result that comes with an error.
	if res != (ctrl.Result{}) {
		t.Fatalf("an error must come with an empty Result, got %+v", res)
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

// Review of #20: a reconcile that starts before the informer cache holds the
// status of the previous rotation must not rotate again. Otherwise the
// Secret gets a second password while status keeps accepting only the
// first, and the controller, unable to read Secrets, never notices.
func TestRotationDecidedOnFreshObjectNotStaleCache(t *testing.T) {
	stale := issuedCredential("1h")
	var staleCache bool
	passwords := []string{"p1", "p2"}
	r, base := credReconciler(t, stale.DeepCopy(), interceptor.Funcs{})
	// The reconciler reads through a cache that can lag behind the API
	// server; the fake client itself plays the API server.
	r.Client = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if mc, ok := obj.(*sigv1.MailCredential); ok && staleCache {
				stale.DeepCopyInto(mc)
				return nil
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	r.APIReader = base
	r.GeneratePassword = func() (string, error) { p := passwords[0]; passwords = passwords[1:]; return p, nil }

	req := ctrl.Request{NamespacedName: credKey}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// The key was re-queued meanwhile; the cache still has the object from
	// before the first rotation.
	staleCache = true
	_, _ = r.Reconcile(context.Background(), req)
	if len(passwords) != 1 {
		t.Fatal("rotated a second time from a stale cache: apps that read p1 lose it without a grace period")
	}

	var sec corev1.Secret
	if err := base.Get(context.Background(), types.NamespacedName{Namespace: credKey.Namespace, Name: "grafana-smtp"}, &sec); err != nil {
		t.Fatal(err)
	}
	mc := getCredential(t, base)
	if !credential.VerifyGenerated(mc.Status.Current.Hash, string(sec.Data["password"])) {
		t.Fatalf("status must accept the password in the Secret (%q); rotated twice from a stale cache", sec.Data["password"])
	}
}

// Review of #20: reconciles with nothing to rotate read from the cache;
// only a rotation is decided on an uncached read.
func TestSteadyStateReconcileSkipsAPIReader(t *testing.T) {
	mc := issuedCredential("1h")
	mc.Annotations = nil
	r, base := credReconciler(t, mc, interceptor.Funcs{})
	uncached := 0
	r.APIReader = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			uncached++
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	if uncached != 0 {
		t.Fatalf("a credential with nothing due must not be read uncached, got %d reads", uncached)
	}
}

// Review of #20: a JSON decode into a filled object keeps fields the JSON
// omits, so the uncached read must decode into an empty object, or a
// cleared status.previous would come back from the cached copy.
func TestFreshReadUsesEmptyObject(t *testing.T) {
	r, base := credReconciler(t, issuedCredential("1h"), interceptor.Funcs{})
	var dirty bool
	r.APIReader = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if mc, ok := obj.(*sigv1.MailCredential); ok && (mc.Name != "" || mc.Status.Previous != nil) {
				dirty = true
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	if dirty {
		t.Fatal("the uncached read decoded into the cached copy")
	}
}

// Review of #20: a generated credential that fails early (here an invalid
// interval) still gets a current SecretsManaged condition.
func TestSecretsManagedOnEarlyFailure(t *testing.T) {
	mc := issuedCredential("1h")
	mc.Spec.Rotation.Interval = "90s"
	mc.Status.Conditions = []metav1.Condition{{Type: sigv1.ConditionSecretsManaged, Status: metav1.ConditionTrue,
		Reason: sigv1.ReasonReady, Message: "credential Secret guard verified", LastTransitionTime: metav1.Now()}}
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	r.Guard = &GuardChecker{checked: true, err: fmt.Errorf("ValidatingAdmissionPolicy deleted")}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	managed := meta.FindStatusCondition(getCredential(t, c).Status.Conditions, sigv1.ConditionSecretsManaged)
	if managed == nil || managed.Status != metav1.ConditionFalse || managed.Reason != sigv1.ReasonGuardMissing {
		t.Fatalf("SecretsManaged must follow the guard on every path, got %+v", managed)
	}
}

// Review of #20: only transient status write errors are retried, and none
// once the context is done; a permanent one must not block the worker for
// the whole backoff.
func TestRotationStatusWriteStopsOnPermanentErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		cancel bool
	}{
		"invalid":   {err: apierrors.NewInvalid(schema.GroupKind{Group: "sigillum.dev", Kind: "MailCredential"}, "grafana", nil)},
		"cancelled": {err: apierrors.NewTimeoutError("request timed out", 1), cancel: true},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			r, _ := credReconciler(t, issuedCredential("1h"), interceptor.Funcs{
				SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
					calls++
					return tc.err
				},
			})
			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancel {
				cancel()
			} else {
				defer cancel()
			}
			start := time.Now()
			if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: credKey}); err == nil {
				t.Fatal("the failed status write must be reported")
			}
			if calls > 2 || time.Since(start) > time.Second {
				t.Fatalf("retried a permanent failure: %d calls in %s", calls, time.Since(start))
			}
		})
	}
}

// Review of #20: an unchanged status is not written again.
func TestUnchangedStatusIsNotWritten(t *testing.T) {
	writes := 0
	mc := issuedCredential("1h")
	mc.Annotations = nil
	r, _ := credReconciler(t, mc, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			writes++
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 {
		t.Fatalf("want one status write for two identical reconciles, got %d", writes)
	}
}

func TestJSONPointerEscape(t *testing.T) {
	for in, want := range map[string]string{
		"sigillum.dev/credential": "sigillum.dev~1credential",
		"a~/b":                    "a~0~1b",
		"~1":                      "~01",
	} {
		if got := jsonPointerEscape(in); got != want {
			t.Errorf("jsonPointerEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
