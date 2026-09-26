package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/credential"
)

// credentialSAIndex indexes MailCredentials by spec.serviceAccountName so a
// ServiceAccount change requeues the credentials bound to it.
const credentialSAIndex = "spec.serviceAccountName"

// Requeue intervals for conditions the controller cannot watch: it has no
// read access to Secrets, and the guard verdict may change between checks.
const (
	secretConflictRequeue = 10 * time.Minute
	guardMissingRequeue   = 5 * time.Minute
)

// MailCredentialReconciler issues and rotates Sigillum SMTP credentials
// (US-3.7, SPEC §4.3.4).
//
// In generated mode it writes a random password to a Secret in the
// credential's namespace and records only its SHA-256 in status. It holds
// create and patch on Secrets but no read verbs: it cannot see whether a
// Secret exists or what it holds, so a write to a Secret it does not own
// is refused by a JSON-patch test on the owner annotation (and by the
// credential Secret guard, without which it writes nothing at all).
type MailCredentialReconciler struct {
	client.Client
	Exclusions credential.Exclusions
	// GeneratedEnabled is false when the chart runs with
	// credentials.enabled=false (bring-your-own-hash only).
	GeneratedEnabled bool
	// Guard reports whether the credential Secret guard is in place.
	// Required when GeneratedEnabled.
	Guard *GuardChecker
	// SMTPHost and SMTPPort are written into generated Secrets.
	SMTPHost string
	SMTPPort int32

	// Test hooks.
	Now              func() time.Time
	GeneratePassword func() (string, error)
}

// +kubebuilder:rbac:groups=sigillum.dev,resources=mailcredentials,verbs=get;list;watch
// +kubebuilder:rbac:groups=sigillum.dev,resources=mailcredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,verbs=get

func (r *MailCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	var mc sigv1.MailCredential
	if err := r.Get(ctx, req.NamespacedName, &mc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	now := r.now()
	st := &mc.Status
	st.Username = credential.Username(mc.Name, mc.Namespace)
	st.ObservedGeneration = mc.Generation

	var (
		result   ctrl.Result
		retErr   error
		ready    = metav1.ConditionFalse
		reason   string
		message  string
		finished bool
		// secretWritten: a new password is in the Secret, so its hash must
		// reach status even if the first status write conflicts.
		secretWritten bool
	)
	fail := func(rsn, msg string) { reason, message, finished = rsn, msg, true }

	if r.Exclusions.Excluded(mc.Namespace) {
		fail(sigv1.ReasonNamespaceExcluded, fmt.Sprintf("namespace %s may not hold mail credentials", mc.Namespace))
	}
	if !finished && !mc.Generated() {
		// Bring your own hash: the proxy verifies spec.passwordHash; nothing
		// generated may linger from an earlier generated-mode spec.
		st.SecretName, st.Current, st.Previous = "", nil, nil
		if _, err := credential.ParseArgon2id(mc.Spec.PasswordHash); err != nil {
			fail(sigv1.ReasonInvalidConfiguration, "spec.passwordHash: "+err.Error())
		} else if mc.Spec.SecretName != "" || mc.Spec.Rotation != nil {
			fail(sigv1.ReasonInvalidConfiguration, "spec.passwordHash cannot be combined with spec.secretName or spec.rotation")
		}
	}
	var interval, grace time.Duration
	if !finished && mc.Generated() {
		var err error
		if mc.Spec.SecretName == "" {
			fail(sigv1.ReasonInvalidConfiguration, "set spec.secretName (generated mode) or spec.passwordHash (bring your own hash)")
		} else if interval, grace, err = rotationSettings(mc.Spec.Rotation); err != nil {
			fail(sigv1.ReasonInvalidConfiguration, err.Error())
		}
	}
	if !finished {
		var sa corev1.ServiceAccount
		err := r.Get(ctx, types.NamespacedName{Namespace: mc.Namespace, Name: mc.Spec.ServiceAccountName}, &sa)
		switch {
		case apierrors.IsNotFound(err):
			fail(sigv1.ReasonServiceAccountNotFound, fmt.Sprintf("ServiceAccount %s/%s not found", mc.Namespace, mc.Spec.ServiceAccountName))
		case err != nil:
			return ctrl.Result{}, err
		}
	}
	if !finished && !mc.Generated() {
		ready, reason, message, finished = metav1.ConditionTrue, sigv1.ReasonBringYourOwnHash,
			"credential ready; password verified against spec.passwordHash", true
	}

	if !finished {
		// Generated mode.
		if st.Previous != nil && !now.Before(st.Previous.ValidUntil.Time) {
			st.Previous = nil
		}
		why := rotationDue(&mc, now, interval)
		// usable: a password issued earlier is still in the (unchanged)
		// Secret, so a failed rotation need not take the credential down.
		usable := st.Current != nil && st.SecretName == mc.Spec.SecretName
		keepOrFail := func(rsn, msg string) {
			if usable {
				message = "password in Secret " + st.SecretName + " still valid, but rotation failed: " + msg
				return
			}
			fail(rsn, msg)
		}
		guardOK, guardMsg := r.GeneratedEnabled, ""
		if r.GeneratedEnabled {
			guardOK, guardMsg = r.Guard.OK()
		}
		switch {
		case !r.GeneratedEnabled:
			fail(sigv1.ReasonGeneratedModeDisabled, "generated credentials are disabled (chart credentials.enabled=false); use spec.passwordHash")
		case why == "":
		case !guardOK:
			keepOrFail(sigv1.ReasonGuardMissing, guardMsg)
			result.RequeueAfter = guardMissingRequeue
		default:
			password, err := r.generatePassword()
			if err != nil {
				return ctrl.Result{}, err
			}
			conflict, err := r.writeSecret(ctx, &mc, st.Username, password)
			switch {
			case conflict:
				fail(sigv1.ReasonSecretConflict, fmt.Sprintf("Secret %s/%s exists and is not owned by this MailCredential: %v",
					mc.Namespace, mc.Spec.SecretName, err))
				result.RequeueAfter = secretConflictRequeue
			case err != nil:
				keepOrFail(sigv1.ReasonSecretWriteFailed, err.Error())
				retErr = err
			default:
				if st.Current != nil && grace > 0 {
					st.Previous = &sigv1.PreviousCredentialHash{Hash: st.Current.Hash, ValidUntil: metav1.NewTime(now.Add(grace))}
				} else {
					// No grace: an older Previous must not outlive the
					// password that was just rotated out.
					st.Previous = nil
				}
				secretWritten = true
				st.Current = &sigv1.CredentialHash{Hash: credential.HashGenerated(password), CreatedAt: metav1.NewTime(now)}
				st.SecretName = mc.Spec.SecretName
				st.LastRotateRequest = mc.Annotations[sigv1.RotateAnnotation]
				log.Info("mail credential password written", "reason", why, "secret", mc.Spec.SecretName,
					"previous_valid_until", previousUntil(st.Previous))
			}
		}
		if r.GeneratedEnabled {
			managed := metav1.Condition{Type: sigv1.ConditionSecretsManaged, Status: metav1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(now), ObservedGeneration: mc.Generation,
				Reason: sigv1.ReasonReady, Message: "credential Secret guard verified"}
			if !guardOK {
				managed.Status, managed.Reason, managed.Message = metav1.ConditionFalse, sigv1.ReasonGuardMissing, guardMsg
			}
			st.Conditions = setCondition(st.Conditions, managed)
		}
		if !finished {
			ready, reason = metav1.ConditionTrue, sigv1.ReasonReady
			if message == "" {
				message = "credential ready; password in Secret " + st.SecretName
			}
		}
		result.RequeueAfter = minPositive(result.RequeueAfter, nextCredentialEvent(st, now, interval))
	}
	if !mc.Generated() || !r.GeneratedEnabled {
		meta.RemoveStatusCondition(&st.Conditions, sigv1.ConditionSecretsManaged)
	}

	st.Conditions = setCondition(st.Conditions, metav1.Condition{
		Type:               sigv1.ConditionReady,
		Status:             ready,
		LastTransitionTime: metav1.NewTime(now),
		ObservedGeneration: mc.Generation,
		Reason:             reason,
		Message:            message,
	})
	if err := r.updateStatus(ctx, &mc, secretWritten); err != nil {
		return ctrl.Result{}, err
	}
	return result, retErr
}

// updateStatus writes mc.Status. After a new password was written to the
// Secret (secretWritten), a conflict is retried against the latest object:
// giving up would drop the hash of the password now in the Secret, and the
// next reconcile would rotate again, so apps that already read it would be
// locked out without a grace period.
func (r *MailCredentialReconciler) updateStatus(ctx context.Context, mc *sigv1.MailCredential, secretWritten bool) error {
	err := r.Status().Update(ctx, mc)
	if !secretWritten || !apierrors.IsConflict(err) {
		return err
	}
	status := *mc.Status.DeepCopy()
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var latest sigv1.MailCredential
		if err := r.Get(ctx, client.ObjectKeyFromObject(mc), &latest); err != nil {
			return client.IgnoreNotFound(err)
		}
		if latest.UID != mc.UID {
			return nil // recreated; the Secret belongs to the old object
		}
		latest.Status = status
		return r.Status().Update(ctx, &latest)
	})
}

// rotationDue returns why the generated password must be (re)written, or
// "" if it need not.
func rotationDue(mc *sigv1.MailCredential, now time.Time, interval time.Duration) string {
	st := &mc.Status
	switch {
	case st.Current == nil:
		return "initial"
	case st.SecretName != mc.Spec.SecretName:
		return "secretName changed"
	}
	if v := mc.Annotations[sigv1.RotateAnnotation]; v != "" && v != st.LastRotateRequest {
		return "rotation requested"
	}
	if interval > 0 && !now.Before(st.Current.CreatedAt.Add(interval)) {
		return "rotation interval elapsed"
	}
	return ""
}

func rotationSettings(rot *sigv1.CredentialRotation) (interval, grace time.Duration, err error) {
	grace = credential.DefaultGracePeriod
	if rot == nil {
		return 0, grace, nil
	}
	if interval, err = credential.ParseDuration(rot.Interval); err != nil {
		return 0, 0, fmt.Errorf("spec.rotation.interval: %w", err)
	}
	if rot.GracePeriod != "" {
		if grace, err = credential.ParseDuration(rot.GracePeriod); err != nil {
			return 0, 0, fmt.Errorf("spec.rotation.gracePeriod: %w", err)
		}
	}
	return interval, grace, nil
}

// nextCredentialEvent is the time until the previous password expires or
// the next scheduled rotation, whichever comes first (0: none).
func nextCredentialEvent(st *sigv1.MailCredentialStatus, now time.Time, interval time.Duration) time.Duration {
	var next time.Duration
	if st.Previous != nil {
		next = minPositive(next, st.Previous.ValidUntil.Sub(now)+time.Second)
	}
	if interval > 0 && st.Current != nil {
		next = minPositive(next, st.Current.CreatedAt.Add(interval).Sub(now)+time.Second)
	}
	return next
}

func minPositive(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0 || a < b:
		return a
	}
	return b
}

func previousUntil(p *sigv1.PreviousCredentialHash) string {
	if p == nil {
		return ""
	}
	return p.ValidUntil.UTC().Format(time.RFC3339)
}

// writeSecret creates the credential Secret or, if it exists, replaces its
// data. The replacement is a JSON patch whose test operations require the
// Secret to carry this MailCredential's label and UID annotation; without
// read access that is how a foreign Secret of the same name is detected.
// conflict reports exactly that case.
func (r *MailCredentialReconciler) writeSecret(ctx context.Context, mc *sigv1.MailCredential, username, password string) (conflict bool, err error) {
	data := map[string][]byte{
		sigv1.CredentialSecretUsernameKey: []byte(username),
		sigv1.CredentialSecretPasswordKey: []byte(password),
		sigv1.CredentialSecretHostKey:     []byte(r.SMTPHost),
		sigv1.CredentialSecretPortKey:     []byte(strconv.Itoa(int(r.SMTPPort))),
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        mc.Spec.SecretName,
			Namespace:   mc.Namespace,
			Labels:      map[string]string{sigv1.CredentialLabel: mc.Name},
			Annotations: map[string]string{sigv1.CredentialUIDAnnotation: string(mc.UID)},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: sigv1.GroupVersion.String(),
				Kind:       "MailCredential",
				Name:       mc.Name,
				UID:        mc.UID,
				Controller: ptr.To(true),
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	err = r.Create(ctx, sec)
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return false, err
	}
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/labels/" + jsonPointerEscape(sigv1.CredentialLabel), "value": mc.Name},
		{"op": "test", "path": "/metadata/annotations/" + jsonPointerEscape(sigv1.CredentialUIDAnnotation), "value": string(mc.UID)},
		{"op": "add", "path": "/data", "value": data},
	})
	if err != nil {
		return false, err
	}
	target := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: mc.Spec.SecretName, Namespace: mc.Namespace}}
	err = r.Patch(ctx, target, client.RawPatch(types.JSONPatchType, patch))
	if apierrors.IsInvalid(err) || apierrors.IsForbidden(err) {
		return true, err
	}
	return false, err
}

// jsonPointerEscape escapes a map key for use in a JSON pointer (RFC 6901).
func jsonPointerEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

func (r *MailCredentialReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *MailCredentialReconciler) generatePassword() (string, error) {
	if r.GeneratePassword != nil {
		return r.GeneratePassword()
	}
	return credential.GeneratePassword()
}

// SetupWithManager wires the reconciler. MailCredentials are requeued when
// their ServiceAccount changes and when the guard verdict changes.
func (r *MailCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &sigv1.MailCredential{}, credentialSAIndex,
		func(o client.Object) []string {
			return []string{o.(*sigv1.MailCredential).Spec.ServiceAccountName}
		}); err != nil {
		return err
	}
	b := ctrl.NewControllerManagedBy(mgr).
		For(&sigv1.MailCredential{}).
		Watches(&corev1.ServiceAccount{}, handler.EnqueueRequestsFromMapFunc(r.credentialsForServiceAccount))
	if r.Guard != nil {
		b = b.WatchesRawSource(source.Channel(r.Guard.Events(), &handler.EnqueueRequestForObject{}))
	}
	return b.Complete(r)
}

func (r *MailCredentialReconciler) credentialsForServiceAccount(ctx context.Context, o client.Object) []reconcile.Request {
	var list sigv1.MailCredentialList
	if err := r.List(ctx, &list, client.InNamespace(o.GetNamespace()),
		client.MatchingFields{credentialSAIndex: o.GetName()}); err != nil {
		return nil
	}
	out := make([]reconcile.Request, len(list.Items))
	for i, mc := range list.Items {
		out[i] = reconcile.Request{NamespacedName: types.NamespacedName{Namespace: mc.Namespace, Name: mc.Name}}
	}
	return out
}
