package smtpproxy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func pod(name, ip string, phase corev1.PodPhase, hostNet bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "legacy", Labels: map[string]string{"app": name}},
		Spec:       corev1.PodSpec{ServiceAccountName: name + "-sa", HostNetwork: hostNet},
		Status:     corev1.PodStatus{Phase: phase, PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}}},
	}
}

func TestCachedPodResolver(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&corev1.Pod{}, PodIPIndex, IndexPodIP).
		WithObjects(
			pod("cron", "10.0.0.1", corev1.PodRunning, false),
			pod("old", "10.0.0.2", corev1.PodSucceeded, false), // IP recycled from a finished pod
			pod("a", "10.0.0.3", corev1.PodRunning, false),
			pod("b", "10.0.0.3", corev1.PodRunning, false),
			pod("node-agent", "10.0.0.4", corev1.PodRunning, true),
		).Build()
	r := CachedPodResolver{C: c}
	ctx := context.Background()

	id, err := r.ResolveIP(ctx, "10.0.0.1")
	if err != nil || id.Namespace != "legacy" || id.ServiceAccount != "cron-sa" || id.Labels["app"] != "cron" {
		t.Fatalf("running pod: got %+v, %v", id, err)
	}
	for ip, why := range map[string]string{
		"10.0.0.2": "finished pods must not lend their identity",
		"10.0.0.3": "ambiguous IPs must be refused",
		"10.0.0.4": "host-network pods share the node IP and must be refused",
		"10.9.9.9": "unknown IPs must be refused",
	} {
		if id, err := r.ResolveIP(ctx, ip); err == nil {
			t.Errorf("%s (%s): got %+v", ip, why, id)
		}
	}
}
