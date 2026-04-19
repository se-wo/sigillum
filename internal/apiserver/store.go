package apiserver

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/controller"
	"github.com/se-wo/sigillum/internal/driver"
)

// PolicyStore is the read-side abstraction the api-server uses to fetch
// policies on the hot path. Backed by a controller-runtime informer cache.
type PolicyStore interface {
	ListInNamespace(namespace string) []sigv1.MailPolicy
}

type cachedPolicyStore struct {
	c client.Reader
}

func newCachedPolicyStore(c client.Reader) *cachedPolicyStore {
	return &cachedPolicyStore{c: c}
}

func (s *cachedPolicyStore) ListInNamespace(namespace string) []sigv1.MailPolicy {
	var list sigv1.MailPolicyList
	if err := s.c.List(context.Background(), &list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	return list.Items
}

// backendForPolicy resolves the policy's BackendRef into a live driver.
// Refuses to send if the referenced backend has Ready=False.
func (s *Server) backendForPolicy(ctx context.Context, p *sigv1.MailPolicy) (driver.Driver, string, error) {
	switch p.Spec.BackendRef.Kind {
	case sigv1.KindMailBackend:
		var mb sigv1.MailBackend
		if err := s.k8sReader.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.BackendRef.Name}, &mb); err != nil {
			return nil, "", fmt.Errorf("MailBackend %s/%s: %w", p.Namespace, p.Spec.BackendRef.Name, err)
		}
		if !backendIsReady(&mb.Status) {
			return nil, "", fmt.Errorf("MailBackend %s/%s is not Ready", p.Namespace, p.Spec.BackendRef.Name)
		}
		cfg, err := controller.ResolveBackendConfig(ctx, s.k8sReader, p.Namespace+"/"+mb.Name, &mb.Spec, mb.Namespace)
		if err != nil {
			return nil, "", err
		}
		d, err := driver.New(cfg)
		return d, p.Namespace + "/" + mb.Name, err
	case sigv1.KindClusterMailBackend, "":
		var cmb sigv1.ClusterMailBackend
		if err := s.k8sReader.Get(ctx, types.NamespacedName{Name: p.Spec.BackendRef.Name}, &cmb); err != nil {
			return nil, "", fmt.Errorf("ClusterMailBackend %s: %w", p.Spec.BackendRef.Name, err)
		}
		if !backendIsReady(&cmb.Status) {
			return nil, "", fmt.Errorf("ClusterMailBackend %s is not Ready", p.Spec.BackendRef.Name)
		}
		cfg, err := controller.ResolveBackendConfig(ctx, s.k8sReader, "/"+cmb.Name, &cmb.Spec, "")
		if err != nil {
			return nil, "", err
		}
		d, err := driver.New(cfg)
		return d, "/" + cmb.Name, err
	default:
		return nil, "", fmt.Errorf("unsupported backendRef.kind %q", p.Spec.BackendRef.Kind)
	}
}

func backendIsReady(s *sigv1.BackendStatus) bool {
	for _, c := range s.Conditions {
		if c.Type == sigv1.ConditionReady {
			return string(c.Status) == "True"
		}
	}
	return false
}
