package controller

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/telemetry"
)

// #76: backend and policy readiness are exported by the controller, follow
// the object's status and disappear with the object.
func TestReadinessMetricsFollowStatusAndDeletion(t *testing.T) {
	cmb := &sigv1.ClusterMailBackend{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics-relay"},
		Spec: sigv1.BackendSpec{Type: sigv1.BackendSMTP, SMTP: &sigv1.SMTPBackendSpec{
			Endpoints: []sigv1.SMTPEndpoint{{Host: "relay", Port: 25}}, AuthType: sigv1.SMTPAuthNone,
		}, HealthCheck: &sigv1.HealthCheckSpec{Enabled: false}},
	}
	mp := &sigv1.MailPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "pol", Namespace: "metrics"},
		Spec: sigv1.MailPolicySpec{
			Subjects:   []sigv1.PolicySubject{{ServiceAccount: &sigv1.ServiceAccountSubject{Name: "sa"}}},
			BackendRef: sigv1.BackendRef{Name: "metrics-relay", Kind: sigv1.KindClusterMailBackend},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mp).
		WithStatusSubresource(&sigv1.MailPolicy{}, &sigv1.ClusterMailBackend{}).Build()
	ctx := context.Background()
	backends := &ClusterMailBackendReconciler{Client: c, Scheme: scheme}
	policies := &MailPolicyReconciler{Client: c, Scheme: scheme}
	backendReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: "metrics-relay"}}
	policyReq := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "metrics", Name: "pol"}}
	reconcile := func(r interface {
		Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
	}, req ctrl.Request) {
		t.Helper()
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatal(err)
		}
	}

	// No backend yet: the policy is not Ready, with the reason as a label.
	reconcile(policies, policyReq)
	if got := gaugeValue(t, policyReadyGauge.WithLabelValues("metrics", "pol", sigv1.ReasonBackendNotFound)); got != 0 {
		t.Fatalf("want policy_ready 0 for BackendNotFound, got %v", got)
	}

	if err := c.Create(ctx, cmb); err != nil {
		t.Fatal(err)
	}
	reconcile(backends, backendReq)
	if got := gaugeValue(t, backendReadyGauge.WithLabelValues("/metrics-relay", "smtp")); got != 1 {
		t.Fatalf("want backend_ready 1, got %v", got)
	}
	reconcile(policies, policyReq)
	if got := gaugeValue(t, policyReadyGauge.WithLabelValues("metrics", "pol", sigv1.ReasonReady)); got != 1 {
		t.Fatalf("want policy_ready 1, got %v", got)
	}
	// The series of the old reason is gone.
	if n := policyReadyGauge.DeletePartialMatch(prometheus.Labels{"namespace": "metrics", "policy": "pol"}); n != 1 {
		t.Fatalf("want one policy_ready series, got %d", n)
	}

	// An invalid backend (insecureSkipVerify) is not Ready.
	if err := c.Get(ctx, backendReq.NamespacedName, cmb); err != nil {
		t.Fatal(err)
	}
	cmb.Spec.SMTP.Endpoints[0].InsecureSkipVerify = true
	if err := c.Update(ctx, cmb); err != nil {
		t.Fatal(err)
	}
	reconcile(backends, backendReq)
	if got := gaugeValue(t, backendReadyGauge.WithLabelValues("/metrics-relay", "smtp")); got != 0 {
		t.Fatalf("want backend_ready 0 for an invalid backend, got %v", got)
	}

	if err := c.Delete(ctx, cmb); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, mp); err != nil {
		t.Fatal(err)
	}
	reconcile(backends, backendReq)
	reconcile(policies, policyReq)
	for name, left := range map[string]bool{
		"backend_ready":           backendReadyGauge.DeletePartialMatch(prometheus.Labels{"backend": "/metrics-relay"}) > 0,
		"backend_endpoints_ready": backendEndpointsReadyGauge.DeleteLabelValues("/metrics-relay"),
		"backend_endpoints":       backendEndpointsGauge.DeleteLabelValues("/metrics-relay"),
		"policy_ready":            policyReadyGauge.DeletePartialMatch(prometheus.Labels{"namespace": "metrics", "policy": "pol"}) > 0,
	} {
		if left {
			t.Fatalf("want no %s series after deletion", name)
		}
	}
}

func TestBackendMetricsCountEndpoints(t *testing.T) {
	t.Cleanup(func() { forgetBackendMetrics("team/relay") })
	status := &sigv1.BackendStatus{
		EndpointStatus: []sigv1.EndpointStatus{{Host: "a", Ready: true}, {Host: "b"}, {Host: "c", Ready: true}},
		Conditions:     []metav1.Condition{{Type: sigv1.ConditionReady, Status: metav1.ConditionTrue}},
	}
	recordBackendMetrics("team/relay", sigv1.BackendSMTP, status)
	if got := gaugeValue(t, backendEndpointsReadyGauge.WithLabelValues("team/relay")); got != 2 {
		t.Fatalf("want 2 ready endpoints, got %v", got)
	}
	if got := gaugeValue(t, backendEndpointsGauge.WithLabelValues("team/relay")); got != 3 {
		t.Fatalf("want 3 endpoints, got %v", got)
	}
	// A changed type replaces the series instead of adding one.
	recordBackendMetrics("team/relay", sigv1.BackendMicrosoftGraph, status)
	if n := backendReadyGauge.DeletePartialMatch(prometheus.Labels{"backend": "team/relay"}); n != 1 {
		t.Fatalf("want one backend_ready series after a type change, got %d", n)
	}
}

func TestCredentialMetricFollowsReadyAndDeletion(t *testing.T) {
	mc := &sigv1.MailCredential{
		ObjectMeta: metav1.ObjectMeta{Name: credKey.Name, Namespace: credKey.Namespace, UID: "uid-1", Generation: 1},
		Spec:       sigv1.MailCredentialSpec{ServiceAccountName: "grafana"}, // neither hash nor Secret: invalid
	}
	r, c := credReconciler(t, mc, interceptor.Funcs{})
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	if got := gaugeValue(t, credentialReadyGauge.WithLabelValues(credKey.Namespace, credKey.Name)); got != 0 {
		t.Fatalf("want credential_ready 0, got %v", got)
	}
	if err := c.Delete(context.Background(), mc); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: credKey}); err != nil {
		t.Fatal(err)
	}
	if credentialReadyGauge.DeleteLabelValues(credKey.Namespace, credKey.Name) {
		t.Fatal("want no credential_ready series after deletion")
	}
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

// #76: the controller serves sigillum_build_info from controller-runtime's
// registry.
func TestControllerRegistryServesBuildInfo(t *testing.T) {
	telemetry.BuildInfo.WithLabelValues("test", "abc").Set(1)
	t.Cleanup(func() { telemetry.BuildInfo.DeleteLabelValues("test", "abc") })
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "sigillum_build_info" {
			return
		}
	}
	t.Fatal("sigillum_build_info missing from the controller registry")
}
