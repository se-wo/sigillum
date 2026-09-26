//go:build envtest

package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

const testControllerUsername = "system:serviceaccount:" + testReleaseNamespace + ":sigillum-controller"

// controllerClient acts as the controller's ServiceAccount, so the guard's
// matchCondition applies. system:masters stands in for the chart's RBAC.
func controllerClient(t *testing.T) client.Client {
	t.Helper()
	cfg := rest.CopyConfig(testCfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: testControllerUsername, Groups: []string{"system:masters"}}
	c, err := client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ensureNamespace(t *testing.T, name string) {
	t.Helper()
	err := testClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

// installGuard creates the credential Secret guard and waits until the
// apiserver enforces it.
func installGuard(t *testing.T, g credential.Guard, cc client.Client) {
	t.Helper()
	ctx := context.Background()
	if err := testClient.Create(ctx, g.Policy()); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if err := testClient.Create(ctx, g.Binding()); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	ensureNamespace(t, "guard-probe")
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; ; i++ {
		probe := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("probe-%d", i), Namespace: "guard-probe"}}
		err := cc.Create(ctx, probe)
		if err != nil && strings.Contains(err.Error(), "sigillum.dev/credential") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard not enforced after 30s (last error %v)", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func readyCondition(mc *sigv1.MailCredential) *metav1.Condition {
	return meta.FindStatusCondition(mc.Status.Conditions, sigv1.ConditionReady)
}

func TestIntegration_MailCredentialGeneratedLifecycle(t *testing.T) {
	ctx := context.Background()
	cc := controllerClient(t)
	ensureNamespace(t, testReleaseNamespace)
	guard := credential.Guard{Name: "sigillum-credential-guard", ControllerUsername: testControllerUsername, Exclusions: testExclusions}
	installGuard(t, guard, cc)

	checker := NewGuardChecker(guard, testClient, cc, time.Minute, logr.Discard())
	checker.Check(ctx)
	if ok, msg := checker.OK(); !ok {
		t.Fatalf("guard installed from Guard.Policy must verify: %s", msg)
	}

	ns := "creds-it"
	ensureNamespace(t, ns)
	if err := testClient.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	mc := &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: ns},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "grafana-smtp",
			Rotation: &sigv1.CredentialRotation{GracePeriod: "1h"}},
	}
	if err := testClient.Create(ctx, mc); err != nil {
		t.Fatal(err)
	}

	passwords := []string{"first-password", "second-password"}
	r := &MailCredentialReconciler{Client: cc, Exclusions: testExclusions, GeneratedEnabled: true, Guard: checker,
		SMTPHost: "sigillum-smtp.sigillum-system.svc", SMTPPort: 587,
		GeneratePassword: func() (string, error) { p := passwords[0]; passwords = passwords[1:]; return p, nil }}
	reconcile := func(name string) *sigv1.MailCredential {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
		var got sigv1.MailCredential
		if err := testClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &got); err != nil {
			t.Fatal(err)
		}
		return &got
	}
	secret := func(name string) *corev1.Secret {
		t.Helper()
		var s corev1.Secret
		if err := testClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &s); err != nil {
			t.Fatal(err)
		}
		return &s
	}

	// Initial issue.
	got := reconcile("grafana")
	if c := readyCondition(got); c == nil || c.Status != metav1.ConditionTrue || !credential.Usable(got) {
		t.Fatalf("want Ready, got %+v", got.Status.Conditions)
	}
	if got.Status.Username != "grafana."+ns || got.Status.Current == nil || got.Status.Previous != nil {
		t.Fatalf("unexpected status %+v", got.Status)
	}
	s := secret("grafana-smtp")
	if string(s.Data["password"]) != "first-password" || string(s.Data["username"]) != "grafana."+ns ||
		string(s.Data["host"]) != "sigillum-smtp.sigillum-system.svc" || string(s.Data["port"]) != "587" {
		t.Fatalf("unexpected secret data %v", s.Data)
	}
	if s.Labels[sigv1.CredentialLabel] != "grafana" || len(s.OwnerReferences) != 1 || s.OwnerReferences[0].UID != got.UID {
		t.Fatalf("secret must be labelled and owned: %+v", s.ObjectMeta)
	}
	if !credential.VerifyGenerated(got.Status.Current.Hash, "first-password") {
		t.Fatal("status hash does not match the written password")
	}

	// On-demand rotation keeps the old password valid for the grace period.
	got.Annotations = map[string]string{sigv1.RotateAnnotation: "1"}
	if err := testClient.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	got = reconcile("grafana")
	if string(secret("grafana-smtp").Data["password"]) != "second-password" {
		t.Fatal("rotation must rewrite the Secret")
	}
	if !credential.VerifyGenerated(got.Status.Current.Hash, "second-password") || got.Status.Previous == nil ||
		!credential.VerifyGenerated(got.Status.Previous.Hash, "first-password") {
		t.Fatalf("rotation status wrong: %+v", got.Status)
	}
	if d := time.Until(got.Status.Previous.ValidUntil.Time); d < 50*time.Minute || d > time.Hour {
		t.Fatalf("previous must stay valid for the 1h grace period, %v left", d)
	}
	// The same annotation value does not rotate again.
	got = reconcile("grafana")
	if !credential.VerifyGenerated(got.Status.Current.Hash, "second-password") {
		t.Fatal("unchanged rotate annotation must not rotate again")
	}

	// A foreign Secret with the requested name is never touched.
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-password", Namespace: ns},
		StringData: map[string]string{"password": "do-not-touch"}}
	if err := testClient.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	thief := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "thief", Namespace: ns},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "grafana", SecretName: "db-password"}}
	if err := testClient.Create(ctx, thief); err != nil {
		t.Fatal(err)
	}
	passwords = []string{"stolen"}
	got = reconcile("thief")
	if c := readyCondition(got); c == nil || c.Reason != sigv1.ReasonSecretConflict {
		t.Fatalf("want SecretConflict, got %+v", got.Status.Conditions)
	}
	if string(secret("db-password").Data["password"]) != "do-not-touch" {
		t.Fatal("foreign Secret was overwritten")
	}

	// Missing ServiceAccount.
	orphan := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: ns},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "nobody", SecretName: "orphan-smtp"}}
	if err := testClient.Create(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if c := readyCondition(reconcile("orphan")); c == nil || c.Reason != sigv1.ReasonServiceAccountNotFound {
		t.Fatalf("want ServiceAccountNotFound, got %+v", c)
	}
}

func TestIntegration_CredentialGuardEnforcement(t *testing.T) {
	ctx := context.Background()
	cc := controllerClient(t)
	ensureNamespace(t, testReleaseNamespace)
	guard := credential.Guard{Name: "sigillum-credential-guard", ControllerUsername: testControllerUsername, Exclusions: testExclusions}
	installGuard(t, guard, cc)

	ns := "guard-it"
	ensureNamespace(t, ns)
	ensureNamespace(t, "kube-guard-it")
	owner := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "app", SecretName: "app-smtp"}}
	if err := testClient.Create(ctx, owner); err != nil {
		t.Fatal(err)
	}
	credSecret := func(name, namespace string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels:      map[string]string{sigv1.CredentialLabel: owner.Name},
			Annotations: map[string]string{sigv1.CredentialUIDAnnotation: string(owner.UID)},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: sigv1.GroupVersion.String(), Kind: "MailCredential",
				Name: owner.Name, UID: owner.UID, Controller: ptr.To(true)}},
		}}
	}

	// Allowed: a labelled Secret controlled by its MailCredential.
	if err := cc.Create(ctx, credSecret("app-smtp", ns)); err != nil {
		t.Fatalf("guard must allow a proper credential Secret: %v", err)
	}
	// Denied: no owner reference.
	s := credSecret("no-owner", ns)
	s.OwnerReferences = nil
	if err := cc.Create(ctx, s); err == nil {
		t.Fatal("guard must deny a Secret without owner reference")
	}
	// Denied: a ServiceAccount token Secret, which the token controller
	// would fill with a token of the named ServiceAccount.
	s = credSecret("sa-token", ns)
	s.Type = corev1.SecretTypeServiceAccountToken
	s.Annotations[corev1.ServiceAccountNameKey] = "default"
	if err := cc.Create(ctx, s); err == nil || !strings.Contains(err.Error(), "type Opaque") {
		t.Fatalf("guard must deny non-Opaque Secrets, got %v", err)
	}
	// Denied: keys other than the credential's.
	s = credSecret("extra-key", ns)
	s.Data = map[string][]byte{sigv1.CredentialSecretPasswordKey: []byte("x"), ".dockerconfigjson": []byte("{}")}
	if err := cc.Create(ctx, s); err == nil || !strings.Contains(err.Error(), "only write the keys") {
		t.Fatalf("guard must deny other keys, got %v", err)
	}
	// Denied: excluded namespace, even with a proper shape.
	if err := cc.Create(ctx, credSecret("app-smtp", "kube-guard-it")); err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("guard must deny excluded namespaces, got %v", err)
	}
	if err := cc.Create(ctx, credSecret("app-smtp", testReleaseNamespace)); err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("guard must deny the release namespace, got %v", err)
	}
	// Denied: taking over an existing foreign Secret by relabelling it.
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-cert", Namespace: ns}}
	if err := testClient.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	takeover := credSecret("tls-cert", ns)
	takeover.ResourceVersion = foreign.ResourceVersion
	if err := cc.Update(ctx, takeover); err == nil || !strings.Contains(err.Error(), "same MailCredential") {
		t.Fatalf("guard must deny taking over a foreign Secret, got %v", err)
	}
	// Other users are not affected by the guard.
	if err := testClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: ns}}); err != nil {
		t.Fatalf("guard must only apply to the controller: %v", err)
	}

	// Tampering with the policy is detected and stops Secret writes.
	var vap = guard.Policy()
	if err := testClient.Get(ctx, types.NamespacedName{Name: guard.Name}, vap); err != nil {
		t.Fatal(err)
	}
	orig := vap.DeepCopy()
	vap.Spec.Validations = vap.Spec.Validations[:1]
	if err := testClient.Update(ctx, vap); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var cur = guard.Policy()
		if err := testClient.Get(ctx, types.NamespacedName{Name: guard.Name}, cur); err == nil {
			cur.Spec = orig.Spec
			_ = testClient.Update(ctx, cur)
		}
	})
	checker := NewGuardChecker(guard, testClient, cc, time.Minute, logr.Discard())
	checker.Check(ctx)
	if ok, _ := checker.OK(); ok {
		t.Fatal("a weakened guard must not verify")
	}
	if err := testClient.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	r := &MailCredentialReconciler{Client: cc, Exclusions: testExclusions, GeneratedEnabled: true, Guard: checker}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	var got sigv1.MailCredential
	if err := testClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "app"}, &got); err != nil {
		t.Fatal(err)
	}
	if c := readyCondition(&got); c == nil || c.Reason != sigv1.ReasonGuardMissing || got.Status.Current != nil {
		t.Fatalf("want GuardMissing and no password, got %+v", got.Status)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, sigv1.ConditionSecretsManaged); c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("want SecretsManaged=False, got %+v", got.Status.Conditions)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("a credential waiting for the guard must be requeued")
	}
}

func TestIntegration_MailCredentialWebhookRejectsExcludedNamespace(t *testing.T) {
	ensureNamespace(t, "kube-webhook-it")
	mc := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "kube-webhook-it"},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "x", SecretName: "x"}}
	err := testClient.Create(context.Background(), mc)
	if err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("webhook must reject excluded namespaces, got %v", err)
	}
}

// Review of #20: the controller watches ServiceAccounts as metadata only.
// A credential created before its ServiceAccount becomes Ready once the
// ServiceAccount appears, through that watch and the metadata cache.
func TestIntegration_ServiceAccountWatchIsMetadataOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := ctrl.NewManager(testCfg, ctrl.Options{Scheme: testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
	if err != nil {
		t.Fatal(err)
	}
	r := &MailCredentialReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Exclusions: testExclusions}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	go func() { _ = mgr.Start(ctx) }()

	ns := "sa-watch-it"
	ensureNamespace(t, ns)
	mc := &sigv1.MailCredential{ObjectMeta: metav1.ObjectMeta{Name: "late", Namespace: ns},
		Spec: sigv1.MailCredentialSpec{ServiceAccountName: "late-sa",
			PasswordHash: credential.HashArgon2id("pw", []byte("0123456789abcdef"), 7*1024, 5, 1)}}
	if err := testClient.Create(ctx, mc); err != nil {
		t.Fatal(err)
	}
	waitReason := func(want string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			var got sigv1.MailCredential
			if err := testClient.Get(ctx, client.ObjectKeyFromObject(mc), &got); err == nil {
				if c := readyCondition(&got); c != nil && c.Reason == want {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("Ready reason %s not reached", want)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	waitReason(sigv1.ReasonServiceAccountNotFound)
	if err := testClient.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "late-sa", Namespace: ns}}); err != nil {
		t.Fatal(err)
	}
	waitReason(sigv1.ReasonBringYourOwnHash)
}
