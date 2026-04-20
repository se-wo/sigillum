package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/driver"
)

// probeBackend builds a one-shot driver from cfg, runs HealthCheck, and
// translates the per-endpoint result into the API status shape. The driver is
// closed before return — controller-side probes are stateless on purpose.
func probeBackend(ctx context.Context, cfg driver.Config) ([]sigv1.EndpointStatus, []sigv1.Capability, error) {
	d, err := driver.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := d.HealthCheck(probeCtx)
	out := make([]sigv1.EndpointStatus, 0, len(results))
	for _, r := range results {
		out = append(out, sigv1.EndpointStatus{Host: r.Host, Port: r.Port, Ready: r.Ready, Message: r.Message})
	}
	caps := make([]sigv1.Capability, 0, len(d.Capabilities()))
	for _, c := range d.Capabilities() {
		caps = append(caps, sigv1.Capability(c))
	}
	return out, caps, nil
}

// readyConditionFor builds the canonical Ready condition. anyReady=true if at
// least one endpoint is healthy.
func readyConditionFor(generation int64, anyReady bool, message string) metav1.Condition {
	cond := metav1.Condition{
		Type:               sigv1.ConditionReady,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: generation,
	}
	if anyReady {
		cond.Status = metav1.ConditionTrue
		cond.Reason = sigv1.ReasonAtLeastOneEndpointReady
		cond.Message = message
	} else {
		cond.Status = metav1.ConditionFalse
		cond.Reason = sigv1.ReasonAllEndpointsDown
		cond.Message = message
	}
	return cond
}

func errorReadyCondition(generation int64, reason, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               sigv1.ConditionReady,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            msg,
	}
}
