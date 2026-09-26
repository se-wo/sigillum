package smtpproxy

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodIPIndex is the informer field index from pod IP to pod.
const PodIPIndex = "status.podIP"

// PodIdentity is what the pod-IP fallback can establish about a caller.
type PodIdentity struct {
	Namespace      string
	Name           string
	ServiceAccount string
	Labels         map[string]string
}

// PodResolver maps a source IP to the pod that owns it.
type PodResolver interface {
	ResolveIP(ctx context.Context, ip string) (*PodIdentity, error)
}

// IndexPodIP extracts the index key for PodIPIndex. Host-network pods share
// the node IP, so they are never indexed and can never be identified.
func IndexPodIP(obj client.Object) []string {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.HostNetwork || pod.Status.PodIP == "" {
		return nil
	}
	ips := make([]string, 0, len(pod.Status.PodIPs))
	for _, ip := range pod.Status.PodIPs {
		ips = append(ips, ip.IP)
	}
	if len(ips) == 0 {
		ips = append(ips, pod.Status.PodIP)
	}
	return ips
}

// CachedPodResolver resolves IPs through an informer cache that has
// PodIPIndex registered.
type CachedPodResolver struct {
	C client.Reader
}

var errPodNotFound = errors.New("no running pod owns this IP")

// ResolveIP implements PodResolver. Anything but exactly one running pod is
// an error: pod IPs are recycled, and a terminated pod's stale IP must not
// lend its identity to whoever inherits the address.
func (r CachedPodResolver) ResolveIP(ctx context.Context, ip string) (*PodIdentity, error) {
	var pods corev1.PodList
	if err := r.C.List(ctx, &pods, client.MatchingFields{PodIPIndex: ip}); err != nil {
		return nil, fmt.Errorf("pod lookup: %w", err)
	}
	var match *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("IP %s is ambiguous (pods %s and %s)", ip, match.Name, p.Name)
		}
		match = p
	}
	if match == nil {
		return nil, errPodNotFound
	}
	sa := match.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	return &PodIdentity{
		Namespace:      match.Namespace,
		Name:           match.Name,
		ServiceAccount: sa,
		Labels:         match.Labels,
	}, nil
}
