package controller

import (
	"context"
	"fmt"
	"net/http"
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
// microsoftSignInScopes add an ID token naming the account, so the
// controller can check that the mailbox itself signed in.
var (
	MicrosoftSMTPScopes   = []string{"https://outlook.office.com/SMTP.Send", "offline_access"}
	microsoftSignInScopes = append([]string{"openid", "profile", "email"}, MicrosoftSMTPScopes...)
)

func microsoftEndpoints(tenant string) (string, string, error) {
	tokenURL, err := oauth.MicrosoftTokenURL(tenant)
	if err != nil {
		return "", "", err
	}
	deviceURL, err := oauth.MicrosoftDeviceCodeURL(tenant)
	return tokenURL, deviceURL, err
}

// defaultMicrosoftTenant lets personal Microsoft accounts sign in.
const defaultMicrosoftTenant = "consumers"

// MicrosoftSMTPAppScope requests the application permissions granted to an
// app for Exchange Online, SMTP.SendAsApp among them.
const MicrosoftSMTPAppScope = "https://outlook.office365.com/.default"

// appOnlyEnv reaches Microsoft's token endpoint; tests replace it.
var appOnlyEnv = struct {
	tokenURL   func(tenant string) (string, error)
	httpClient *http.Client
}{tokenURL: oauth.MicrosoftTokenURL}

// appOnlyTokens is the token source of an XOAUTH2 backend with the client
// credentials flow: the application's own tokens, from a cache shared by
// every driver of the same application, so the gateway's per-send drivers
// and the health check fetch a token once per lifetime.
func appOnlyTokens(ctx context.Context, c client.Reader, s *sigv1.SMTPBackendSpec, secretFallbackNs string) (*oauth.Cache, error) {
	sec, err := credentialsSecret(ctx, c, "spec.smtp", *s.CredentialsRef, secretFallbackNs)
	if err != nil {
		return nil, err
	}
	secret := string(sec.Data[sigv1.GraphSecretClientSecretKey])
	if secret == "" {
		return nil, fmt.Errorf("credentials secret %s/%s has no key %s", sec.Namespace, sec.Name, sigv1.GraphSecretClientSecretKey)
	}
	tokenURL, err := appOnlyEnv.tokenURL(s.OAuth.Tenant)
	if err != nil {
		return nil, err
	}
	return oauth.SharedCache(&oauth.ClientCredentials{TokenURL: tokenURL, ClientID: s.OAuth.ClientID, ClientSecret: secret,
		Scopes: []string{MicrosoftSMTPAppScope}, HTTPClient: appOnlyEnv.httpClient}), nil
}

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
// the credentials Secret, which may be missing; the token Secret is kept
// in its namespace. Without a usable refresh token, the broker runs a
// device code sign-in for the mailbox.
func authorizeDelegated(ctx context.Context, c client.Reader, b *TokenBroker, owner client.Object, kind, key string,
	spec *sigv1.BackendSpec, secretFallbackNs string) (BrokerResult, error) {
	if b == nil {
		return BrokerResult{}, fmt.Errorf("this controller runs without a token broker")
	}
	o, ref := spec.SMTP.OAuth, *spec.SMTP.CredentialsRef
	ns, err := credentialsNamespace("spec.smtp", ref, secretFallbackNs)
	if err != nil {
		return BrokerResult{}, err
	}
	var sec corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &sec); client.IgnoreNotFound(err) != nil {
		return BrokerResult{}, fmt.Errorf("failed to load credentials secret %s/%s: %w", ns, ref.Name, err)
	}
	tenant := o.Tenant
	if tenant == "" {
		tenant = defaultMicrosoftTenant
	}
	endpoints := microsoftEndpoints
	if b.Endpoints != nil {
		endpoints = b.Endpoints
	}
	tokenURL, deviceURL, err := endpoints(tenant)
	if err != nil {
		return BrokerResult{}, err
	}
	clientSecret := string(sec.Data[sigv1.GraphSecretClientSecretKey])
	return b.Ensure(ctx, DelegatedBackend{
		Owner:     owner,
		Kind:      kind,
		Key:       key,
		Namespace: ns,
		Seed:      string(sec.Data[sigv1.OAuthSecretRefreshTokenKey]),
		Refresher: &oauth.RefreshToken{TokenURL: tokenURL, ClientID: o.ClientID, Scopes: MicrosoftSMTPScopes,
			ClientSecret: clientSecret, HTTPClient: b.HTTPClient},
		Device: &oauth.DeviceCode{DeviceAuthURL: deviceURL, TokenURL: tokenURL, ClientID: o.ClientID,
			ClientSecret: clientSecret, Scopes: microsoftSignInScopes, HTTPClient: b.HTTPClient},
		Authorize: owner.GetAnnotations()[sigv1.AuthorizeAnnotation],
		Account:   o.Mailbox,
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
