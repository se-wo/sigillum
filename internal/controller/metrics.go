package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// Readiness gauges (#76), set on every reconcile by the leader and deleted
// with the object, so a broken backend is visible before traffic fails.
var (
	backendReadyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sigillum_backend_ready",
		Help: "1 while a MailBackend or ClusterMailBackend is Ready, 0 otherwise. " +
			"backend is <namespace>/<name>, or /<name> for a ClusterMailBackend.",
	}, []string{"backend", "type"})
	backendEndpointsReadyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sigillum_backend_endpoints_ready",
		Help: "Endpoints of a backend that passed its last health check.",
	}, []string{"backend"})
	backendEndpointsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sigillum_backend_endpoints",
		Help: "Endpoints of a backend in its last health check.",
	}, []string{"backend"})
	policyReadyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sigillum_policy_ready",
		Help: "1 while a MailPolicy is Ready, 0 otherwise; reason is the Ready condition's reason.",
	}, []string{"namespace", "policy", "reason"})
	credentialReadyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sigillum_credential_ready",
		Help: "1 while a MailCredential is Ready, 0 otherwise.",
	}, []string{"namespace", "credential"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(backendReadyGauge, backendEndpointsReadyGauge, backendEndpointsGauge,
		policyReadyGauge, credentialReadyGauge, telemetry.BuildInfo)
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// recordBackendMetrics sets the gauges of the backend key from its status.
// The series of an earlier type are removed first.
func recordBackendMetrics(key string, typ sigv1.BackendType, status *sigv1.BackendStatus) {
	backendReadyGauge.DeletePartialMatch(prometheus.Labels{"backend": key})
	backendReadyGauge.WithLabelValues(key, string(typ)).Set(boolGauge(meta.IsStatusConditionTrue(status.Conditions, sigv1.ConditionReady)))
	ready := 0
	for _, e := range status.EndpointStatus {
		if e.Ready {
			ready++
		}
	}
	backendEndpointsReadyGauge.WithLabelValues(key).Set(float64(ready))
	backendEndpointsGauge.WithLabelValues(key).Set(float64(len(status.EndpointStatus)))
}

func forgetBackendMetrics(key string) {
	backendReadyGauge.DeletePartialMatch(prometheus.Labels{"backend": key})
	backendEndpointsReadyGauge.DeleteLabelValues(key)
	backendEndpointsGauge.DeleteLabelValues(key)
}

// recordPolicyMetrics keeps one series per policy: the one of the current
// reason.
func recordPolicyMetrics(namespace, name string, conds []metav1.Condition) {
	policyReadyGauge.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "policy": name})
	reason, ready := "", false
	if c := meta.FindStatusCondition(conds, sigv1.ConditionReady); c != nil {
		reason, ready = c.Reason, c.Status == metav1.ConditionTrue
	}
	policyReadyGauge.WithLabelValues(namespace, name, reason).Set(boolGauge(ready))
}

func forgetPolicyMetrics(namespace, name string) {
	policyReadyGauge.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "policy": name})
}

func recordCredentialMetrics(namespace, name string, ready bool) {
	credentialReadyGauge.WithLabelValues(namespace, name).Set(boolGauge(ready))
}

func forgetCredentialMetrics(namespace, name string) {
	credentialReadyGauge.DeleteLabelValues(namespace, name)
}
