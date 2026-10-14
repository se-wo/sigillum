// Package kubecache holds informer cache settings shared by all modes.
package kubecache

import (
	"context"
	"fmt"
	"os"
	"slices"
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

// SecretNamespaceError is returned for a Secret outside the namespaces the
// components may read (--secret-namespaces). It replaces the cache's
// "unknown namespace for the cache" with what the operator has to do.
type SecretNamespaceError struct {
	Namespace, Name string
	// Allowed are the namespaces whose Secrets may be read.
	Allowed []string
}

func (e *SecretNamespaceError) Error() string {
	return fmt.Sprintf("Secret %s/%s: Sigillum reads Secrets only in %s (the release namespace and rbac.allowedSecretNamespaces); "+
		"ask the platform team to add %q to the chart value rbac.allowedSecretNamespaces",
		e.Namespace, e.Name, strings.Join(e.Allowed, ", "), e.Namespace)
}

// SecretNamespaceAllowed reports whether Secrets in ns may be read. No
// namespaces: every namespace (an unrestricted cache, see
// RestrictSecretCache).
func SecretNamespaceAllowed(namespaces []string, ns string) bool {
	return len(namespaces) == 0 || slices.Contains(namespaces, ns)
}

// GuardSecretReads returns c, except that reading a Secret outside
// namespaces fails with a *SecretNamespaceError.
func GuardSecretReads(c client.Client, namespaces []string) client.Client {
	if len(namespaces) == 0 {
		return c
	}
	return secretGuard{Client: c, namespaces: namespaces}
}

type secretGuard struct {
	client.Client
	namespaces []string
}

func (g secretGuard) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Secret); ok && !SecretNamespaceAllowed(g.namespaces, key.Namespace) {
		return &SecretNamespaceError{Namespace: key.Namespace, Name: key.Name, Allowed: g.namespaces}
	}
	return g.Client.Get(ctx, key, obj, opts...)
}
