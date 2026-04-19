package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// MailPolicyReconciler computes Ready and UsingLegacyAuth conditions for a
// MailPolicy by resolving its backendRef. Subject-match counts are deferred
// to the api-server's hot path; the controller only validates referential
// integrity and surfaces the legacy-auth opt-in for security scans (US-3.5).
type MailPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sigillum.dev,resources=mailpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=sigillum.dev,resources=mailpolicies/status,verbs=get;update;patch

func (r *MailPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var mp sigv1.MailPolicy
	if err := r.Get(ctx, req.NamespacedName, &mp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	cond := r.evaluate(ctx, &mp)
	mp.Status.Conditions = setCondition(mp.Status.Conditions, cond)
	mp.Status.ObservedGeneration = mp.Generation

	// UsingLegacyAuth condition surfaces the policy when pod-IP fallback is on.
	legacyCond := metav1.Condition{
		Type:               sigv1.ConditionUsingLegacyAuth,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: mp.Generation,
	}
	if mp.Spec.LegacyAuth != nil && mp.Spec.LegacyAuth.PodIPFallback {
		legacyCond.Status = metav1.ConditionTrue
		legacyCond.Reason = "PodIPFallbackEnabled"
		legacyCond.Message = "spec.legacyAuth.podIPFallback is enabled"
	} else {
		legacyCond.Status = metav1.ConditionFalse
		legacyCond.Reason = "Disabled"
		legacyCond.Message = "no legacy auth modes enabled"
	}
	mp.Status.Conditions = setCondition(mp.Status.Conditions, legacyCond)

	if err := r.Status().Update(ctx, &mp); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *MailPolicyReconciler) evaluate(ctx context.Context, mp *sigv1.MailPolicy) metav1.Condition {
	gen := mp.Generation
	switch mp.Spec.BackendRef.Kind {
	case sigv1.KindClusterMailBackend, "":
		var cmb sigv1.ClusterMailBackend
		if err := r.Get(ctx, types.NamespacedName{Name: mp.Spec.BackendRef.Name}, &cmb); err != nil {
			if apierrors.IsNotFound(err) {
				return errorReadyCondition(gen, sigv1.ReasonBackendNotFound,
					fmt.Sprintf("ClusterMailBackend %q not found", mp.Spec.BackendRef.Name))
			}
			return errorReadyCondition(gen, sigv1.ReasonBackendNotFound, err.Error())
		}
		if !backendReady(cmb.Status.Conditions) {
			return errorReadyCondition(gen, sigv1.ReasonBackendNotReady,
				fmt.Sprintf("ClusterMailBackend %q is not Ready", cmb.Name))
		}
	case sigv1.KindMailBackend:
		var nb sigv1.MailBackend
		if err := r.Get(ctx, types.NamespacedName{Namespace: mp.Namespace, Name: mp.Spec.BackendRef.Name}, &nb); err != nil {
			if apierrors.IsNotFound(err) {
				return errorReadyCondition(gen, sigv1.ReasonBackendNotFound,
					fmt.Sprintf("MailBackend %s/%s not found", mp.Namespace, mp.Spec.BackendRef.Name))
			}
			return errorReadyCondition(gen, sigv1.ReasonBackendNotFound, err.Error())
		}
		if !backendReady(nb.Status.Conditions) {
			return errorReadyCondition(gen, sigv1.ReasonBackendNotReady,
				fmt.Sprintf("MailBackend %s/%s is not Ready", nb.Namespace, nb.Name))
		}
	default:
		return errorReadyCondition(gen, sigv1.ReasonInvalidConfiguration,
			fmt.Sprintf("unsupported backendRef.kind %q", mp.Spec.BackendRef.Kind))
	}

	return metav1.Condition{
		Type:               sigv1.ConditionReady,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: gen,
		Reason:             sigv1.ReasonReady,
		Message:            "policy is ready and backend is reachable",
	}
}

func backendReady(conds []metav1.Condition) bool {
	for _, c := range conds {
		if c.Type == sigv1.ConditionReady {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

func (r *MailPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sigv1.MailPolicy{}).
		Complete(r)
}
