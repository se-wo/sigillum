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
	c client.Client,
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
			ns := spec.SMTP.CredentialsRef.Namespace
			if ns == "" {
				ns = secretFallbackNs
			}
			if ns == "" {
				return cfg, fmt.Errorf("spec.smtp.credentialsRef.namespace must be set on cluster-scoped backends")
			}
			var sec corev1.Secret
			if err := c.Get(ctx, types.NamespacedName{Name: spec.SMTP.CredentialsRef.Name, Namespace: ns}, &sec); err != nil {
				if apierrors.IsNotFound(err) {
					return cfg, fmt.Errorf("credentials secret %s/%s not found", ns, spec.SMTP.CredentialsRef.Name)
				}
				return cfg, fmt.Errorf("failed to load credentials secret %s/%s: %w", ns, spec.SMTP.CredentialsRef.Name, err)
			}
			smtpCfg.Username = string(sec.Data[sigv1.SMTPSecretUsernameKey])
			smtpCfg.Password = string(sec.Data[sigv1.SMTPSecretPasswordKey])
		}
		cfg.SMTP = smtpCfg
	default:
		return cfg, fmt.Errorf("backend type %q is not implemented", spec.Type)
	}
	return cfg, nil
}
