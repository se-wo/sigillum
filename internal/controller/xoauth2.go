package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/oauth"
)

// MicrosoftSMTPScopes are requested when the refresh token of an XOAUTH2
// backend is redeemed: sending over SMTP, and a new refresh token.
var MicrosoftSMTPScopes = []string{"https://outlook.office.com/SMTP.Send", "offline_access"}

// defaultMicrosoftTenant lets personal Microsoft accounts sign in.
const defaultMicrosoftTenant = "consumers"

// secretTokens is the token source of an XOAUTH2 backend on the send path
// (api-server, SMTP proxy): the access token the controller's broker stored
// in the token Secret, read through the Secret cache on every send.
type secretTokens struct {
	reader client.Reader
	key    types.NamespacedName
}

func (s *secretTokens) Token(ctx context.Context) (oauth.Token, error) {
	var sec corev1.Secret
	if err := s.reader.Get(ctx, s.key, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return oauth.Token{}, fmt.Errorf("token Secret %s not found: the controller has not stored an access token yet", s.key)
		}
		return oauth.Token{}, fmt.Errorf("read token Secret %s: %w", s.key, err)
	}
	return AccessTokenFromSecret(&sec)
}

// staticTokens hands the driver the token the broker just returned, so the
// controller's health check does not wait for the Secret cache.
type staticTokens oauth.Token

func (t staticTokens) Token(context.Context) (oauth.Token, error) { return oauth.Token(t), nil }

// backendKindName splits a backend key as the reconcilers and the gateway
// build it: "<namespace>/<name>" for a MailBackend, "/<name>" for a
// ClusterMailBackend.
func backendKindName(key string) (kind, name string) {
	ns, name, _ := strings.Cut(key, "/")
	if ns == "" {
		return string(sigv1.KindClusterMailBackend), name
	}
	return string(sigv1.KindMailBackend), name
}

// authorizeDelegated runs the token broker for an XOAUTH2 backend (SPEC
// US-6.3): the seed refresh token and an optional client secret come from
// the credentials Secret, and the token Secret is kept in its namespace.
func authorizeDelegated(ctx context.Context, c client.Reader, b *TokenBroker, owner client.Object, kind, key string,
	spec *sigv1.BackendSpec, secretFallbackNs string) (BrokerResult, error) {
	if b == nil {
		return BrokerResult{}, fmt.Errorf("this controller runs without a token broker")
	}
	o := spec.SMTP.OAuth
	sec, err := credentialsSecret(ctx, c, "spec.smtp", *spec.SMTP.CredentialsRef, secretFallbackNs)
	if err != nil {
		return BrokerResult{}, err
	}
	tenant := o.Tenant
	if tenant == "" {
		tenant = defaultMicrosoftTenant
	}
	tokenURL := oauth.MicrosoftTokenURL
	if b.TokenURL != nil {
		tokenURL = b.TokenURL
	}
	u, err := tokenURL(tenant)
	if err != nil {
		return BrokerResult{}, err
	}
	return b.Ensure(ctx, DelegatedBackend{
		Owner:     owner,
		Kind:      kind,
		Key:       key,
		Namespace: sec.Namespace,
		Seed:      string(sec.Data[sigv1.OAuthSecretRefreshTokenKey]),
		Refresher: &oauth.RefreshToken{TokenURL: u, ClientID: o.ClientID, Scopes: MicrosoftSMTPScopes,
			ClientSecret: string(sec.Data[sigv1.GraphSecretClientSecretKey]), HTTPClient: b.HTTPClient},
	}), nil
}

// authorizedCondition reports the broker's result as the Authorized
// condition of a delegated backend.
func authorizedCondition(generation int64, res BrokerResult) metav1.Condition {
	cond := metav1.Condition{
		Type:               sigv1.ConditionAuthorized,
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: generation,
		Reason:             res.Reason,
		Message:            res.Message,
	}
	if res.Authorized {
		cond.Status = metav1.ConditionTrue
	}
	if cond.Message == "" {
		cond.Message = "the controller holds a refresh token the provider accepts"
	}
	return cond
}
