package controller

import (
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretNamespaces parses a --secret-namespaces value (comma-separated). An
// empty value falls back to the pod's own namespace (POD_NAMESPACE).
func SecretNamespaces(list string) []string {
	var out []string
	for _, ns := range strings.Split(list, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			out = append(out, ns)
		}
	}
	if len(out) == 0 {
		if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
			out = []string{ns}
		}
	}
	return out
}

// RestrictSecretCache limits the Secret informer to namespaces. Components
// may only list and watch Secrets in the release namespace and
// rbac.allowedSecretNamespaces; a cluster-wide Secret informer would be
// refused and block every read of a backend credentials Secret. A Secret
// outside these namespaces then fails fast instead. No namespaces: leave
// the cache unrestricted (local development against a kubeconfig).
func RestrictSecretCache(o *cache.Options, namespaces []string) {
	if len(namespaces) == 0 {
		return
	}
	cfg := make(map[string]cache.Config, len(namespaces))
	for _, ns := range namespaces {
		cfg[ns] = cache.Config{}
	}
	if o.ByObject == nil {
		o.ByObject = map[client.Object]cache.ByObject{}
	}
	o.ByObject[&corev1.Secret{}] = cache.ByObject{Namespaces: cfg}
}
