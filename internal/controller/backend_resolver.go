// Package controller hosts the controller-runtime manager and reconcilers.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/driver"
)

// ResolveBackendConfig assembles a driver.Config from a backend's spec and
// the credentials secret it references. The resolver is shared by the
// controller's probe loop and by the api-server's send path so both paths see
// the same view of the backend.
//
// secretFallbackNs is used when credentialsRef.namespace is empty:
//   - for ClusterMailBackend the caller passes "" and the namespace is required
//   - for MailBackend the caller passes the backend's own namespace
func ResolveBackendConfig(
	ctx context.Context,
	c client.Reader,
	backendKey string,
	spec *sigv1.BackendSpec,
	secretFallbackNs string,
) (driver.Config, error) {
	cfg := driver.Config{
		Type:       driver.Type(spec.Type),
		BackendKey: backendKey,
	}
	switch spec.Type {
	case sigv1.BackendSMTP:
		if spec.SMTP == nil {
			return cfg, fmt.Errorf("spec.smtp is required when type=smtp")
		}
		smtpCfg := &driver.SMTPConfig{
			Endpoints: make([]driver.SMTPEndpoint, 0, len(spec.SMTP.Endpoints)),
			AuthType:  string(spec.SMTP.AuthType),
			Timeout:   spec.SMTP.ConnectionTimeoutSeconds,
			Helo:      spec.SMTP.HeloDomain,
		}
		if smtpCfg.AuthType == "" {
			smtpCfg.AuthType = string(sigv1.SMTPAuthNone)
		}
		for _, ep := range spec.SMTP.Endpoints {
			tls := string(ep.TLS)
			if tls == "" {
				tls = string(sigv1.SMTPTLSStartTLS)
			}
			smtpCfg.Endpoints = append(smtpCfg.Endpoints, driver.SMTPEndpoint{
				Host: ep.Host, Port: ep.Port, TLS: tls, InsecureSkipVerify: ep.InsecureSkipVerify,
			})
		}
		if smtpCfg.AuthType != string(sigv1.SMTPAuthNone) {
			if spec.SMTP.CredentialsRef == nil {
				return cfg, fmt.Errorf("spec.smtp.credentialsRef is required when authType != NONE")
			}
			sec, err := credentialsSecret(ctx, c, "spec.smtp", *spec.SMTP.CredentialsRef, secretFallbackNs)
			if err != nil {
				return cfg, err
			}
			smtpCfg.Username = string(sec.Data[sigv1.SMTPSecretUsernameKey])
			smtpCfg.Password = string(sec.Data[sigv1.SMTPSecretPasswordKey])
		}
		cfg.SMTP = smtpCfg
	case sigv1.BackendMicrosoftGraph:
		g := spec.MicrosoftGraph
		if g == nil {
			return cfg, fmt.Errorf("spec.microsoftGraph is required when type=microsoftGraph")
		}
		sec, err := credentialsSecret(ctx, c, "spec.microsoftGraph", g.CredentialsRef, secretFallbackNs)
		if err != nil {
			return cfg, err
		}
		secret := string(sec.Data[sigv1.GraphSecretClientSecretKey])
		if secret == "" {
			return cfg, fmt.Errorf("credentials secret %s/%s has no key %s", sec.Namespace, sec.Name, sigv1.GraphSecretClientSecretKey)
		}
		cfg.Graph = &driver.GraphConfig{TenantID: g.TenantID, ClientID: g.ClientID, ClientSecret: secret}
	default:
		return cfg, fmt.Errorf("backend type %q is not implemented", spec.Type)
	}
	return cfg, nil
}

// credentialsSecret loads a backend's credentials Secret. secretFallbackNs
// is the namespace of a namespaced MailBackend, empty for a
// ClusterMailBackend; field names the spec block in errors.
func credentialsSecret(ctx context.Context, c client.Reader, field string, ref sigv1.SecretReference, secretFallbackNs string) (*corev1.Secret, error) {
	ns := ref.Namespace
	if secretFallbackNs != "" {
		// A namespaced MailBackend may only use Secrets of its own
		// namespace. The webhook enforces this too, but it can be
		// disabled; without this check a tenant could point a
		// MailBackend at the relay credentials in the release
		// namespace and send them to an endpoint of its choice.
		if ns != "" && ns != secretFallbackNs {
			return nil, fmt.Errorf("%s.credentialsRef.namespace %q must be empty or the backend's own namespace %q", field, ns, secretFallbackNs)
		}
		ns = secretFallbackNs
	}
	if ns == "" {
		return nil, fmt.Errorf("%s.credentialsRef.namespace must be set on cluster-scoped backends", field)
	}
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ns}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("credentials secret %s/%s not found", ns, ref.Name)
		}
		return nil, fmt.Errorf("failed to load credentials secret %s/%s: %w", ns, ref.Name, err)
	}
	return &sec, nil
}
