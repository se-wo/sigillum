package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/webhook"
)

// ClusterMailBackendReconciler reconciles a cluster-scoped ClusterMailBackend.
type ClusterMailBackendReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sigillum.dev,resources=clustermailbackends,verbs=get;list;watch
// +kubebuilder:rbac:groups=sigillum.dev,resources=clustermailbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sigillum.dev,resources=clustermailbackends/finalizers,verbs=update

func (r *ClusterMailBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var cmb sigv1.ClusterMailBackend
	if err := r.Get(ctx, req.NamespacedName, &cmb); err != nil {
		if apierrors.IsNotFound(err) {
			forgetBackendMetrics("/" + req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	requeue := reconcileBackend(ctx, r.Client, "/"+req.Name, &cmb.Spec, &cmb.Status, cmb.Generation, "",
		webhook.ValidateBackend(&cmb))
	recordBackendMetrics("/"+req.Name, cmb.Spec.Type, &cmb.Status)
	if err := r.Status().Update(ctx, &cmb); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *ClusterMailBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sigv1.ClusterMailBackend{}).
		Complete(r)
}
