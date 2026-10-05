package controller

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// MailBackendReconciler reconciles a namespace-scoped MailBackend.
type MailBackendReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Broker keeps the tokens of XOAUTH2 backends; nil leaves them not
	// ready.
	Broker *TokenBroker
}

// +kubebuilder:rbac:groups=sigillum.dev,resources=mailbackends,verbs=get;list;watch
// +kubebuilder:rbac:groups=sigillum.dev,resources=mailbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sigillum.dev,resources=mailbackends/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *MailBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var mb sigv1.MailBackend
	if err := r.Get(ctx, req.NamespacedName, &mb); err != nil {
		if apierrors.IsNotFound(err) {
			r.Broker.Forget(req.NamespacedName.String())
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	requeue := reconcileBackend(ctx, r.Client, r.Broker, &mb, string(sigv1.KindMailBackend), req.NamespacedName.String(),
		&mb.Spec, &mb.Status, mb.Namespace)
	if err := r.Status().Update(ctx, &mb); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *MailBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sigv1.MailBackend{}).
		Complete(r)
}

// reconcileBackend is shared between MailBackend and ClusterMailBackend.
// It mutates status in place and returns the requeue interval.
func reconcileBackend(
	ctx context.Context,
	c client.Client,
	broker *TokenBroker,
	owner client.Object,
	kind string,
	key string,
	spec *sigv1.BackendSpec,
	status *sigv1.BackendStatus,
	secretFallbackNs string,
) time.Duration {
	generation := owner.GetGeneration()
	// Default health-check cadence per SPEC §4.3.1.
	probeInterval := 60 * time.Second
	if spec.HealthCheck != nil && spec.HealthCheck.IntervalSeconds > 0 {
		probeInterval = time.Duration(spec.HealthCheck.IntervalSeconds) * time.Second
	}
	probeEnabled := spec.HealthCheck == nil || spec.HealthCheck.Enabled

	cfg, err := ResolveBackendConfig(ctx, c, key, spec, secretFallbackNs)
	if err != nil {
		status.Conditions = setCondition(status.Conditions, errorReadyCondition(generation, sigv1.ReasonInvalidConfiguration, err.Error()))
		status.ObservedGeneration = generation
		return probeInterval
	}

	// A delegated sign-in (XOAUTH2): the broker refreshes the access token
	// on every reconcile that is due, and the health check below uses it.
	if cfg.SMTP != nil && cfg.SMTP.AuthType == string(sigv1.SMTPAuthXOAUTH2) && spec.SMTP.OAuth.Delegated() {
		res, err := authorizeDelegated(ctx, c, broker, owner, kind, key, spec, secretFallbackNs)
		if err != nil {
			status.Conditions = setCondition(status.Conditions, errorReadyCondition(generation, sigv1.ReasonInvalidConfiguration, err.Error()))
			status.ObservedGeneration = generation
			return probeInterval
		}
		authz := authorizedCondition(generation, res)
		status.Conditions = setCondition(status.Conditions, authz)
		if res.RequeueAfter > 0 && res.RequeueAfter < probeInterval {
			probeInterval = res.RequeueAfter
		}
		if res.Token.AccessToken == "" {
			status.Conditions = setCondition(status.Conditions, errorReadyCondition(generation, authz.Reason,
				"no access token yet: "+authz.Message))
			status.ObservedGeneration = generation
			return probeInterval
		}
		cfg.SMTP.Tokens = staticTokens(res.Token)
	} else {
		meta.RemoveStatusCondition(&status.Conditions, sigv1.ConditionAuthorized)
		broker.Forget(key)
	}

	if !probeEnabled {
		status.Conditions = setCondition(status.Conditions, metav1.Condition{
			Type:               sigv1.ConditionReady,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: generation,
			Reason:             sigv1.ReasonReady,
			Message:            "health checks disabled; assuming ready",
		})
		status.ObservedGeneration = generation
		return probeInterval
	}

	endpoints, caps, err := probeBackend(ctx, cfg)
	if err != nil {
		status.Conditions = setCondition(status.Conditions, errorReadyCondition(generation, sigv1.ReasonProbeError, err.Error()))
		status.ObservedGeneration = generation
		now := metav1.Now()
		status.LastProbeTime = &now
		return probeInterval
	}

	anyReady := false
	for _, e := range endpoints {
		if e.Ready {
			anyReady = true
			break
		}
	}
	now := metav1.Now()
	status.EndpointStatus = endpoints
	status.Capabilities = caps
	status.LastProbeTime = &now
	status.Conditions = setCondition(status.Conditions, readyConditionFor(generation, anyReady, summarizeEndpoints(endpoints)))
	status.ObservedGeneration = generation
	return probeInterval
}

func summarizeEndpoints(eps []sigv1.EndpointStatus) string {
	ready := 0
	for _, e := range eps {
		if e.Ready {
			ready++
		}
	}
	switch ready {
	case 0:
		return "no endpoints ready"
	case len(eps):
		return "all endpoints ready"
	default:
		return "some endpoints ready"
	}
}
