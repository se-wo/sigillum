package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/oauth"
)

var backendAuthorized = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "sigillum_backend_authorized",
	Help: "1 while the controller holds a refresh token the provider accepts for a delegated backend, " +
		"0 when a person has to sign in again (SPEC US-6.3).",
}, []string{"backend"})

func init() {
	ctrlmetrics.Registry.MustRegister(backendAuthorized)
}

const (
	// brokerRetry spaces retries after a temporary failure.
	brokerRetry = 30 * time.Second
	// brokerReauthRetry spaces retries after the provider rejected the
	// refresh token; a new sign-in changes the credentials Secret and is
	// picked up by the next reconcile anyway.
	brokerReauthRetry = 10 * time.Minute
)

// Refresher redeems a refresh token; *oauth.RefreshToken implements it.
type Refresher interface {
	Refresh(ctx context.Context, refreshToken string) (oauth.Token, string, error)
}

// DelegatedBackend is what the TokenBroker needs to know about a backend
// that sends with a person's delegated sign-in (US-6.3).
type DelegatedBackend struct {
	// Owner is the MailBackend or ClusterMailBackend; it owns the token
	// Secret.
	Owner client.Object
	Kind  string
	// Key names the backend in metrics ("<ns>/<name>" or "/<name>").
	Key string
	// Namespace holds the token Secret: the backend's credentials
	// namespace, which the api-server and SMTP proxy can read.
	Namespace string
	// Seed is the refresh_token of the credentials Secret, as a sign-in
	// left it; empty if there is none.
	Seed      string
	Refresher Refresher
	// Device runs a device code sign-in when there is no usable refresh
	// token or a new one is asked for; nil leaves the sign-in to the
	// person (a refresh_token in the credentials Secret).
	Device DeviceFlow
	// Authorize is the backend's sigillum.dev/authorize annotation; a new
	// value asks for a new sign-in.
	Authorize string
	// Account is the address the sign-in must be for; empty: any.
	Account string
}

// BrokerResult is the outcome of TokenBroker.Ensure, for the backend's
// Authorized condition.
type BrokerResult struct {
	Authorized   bool
	Reason       string
	Message      string
	RequeueAfter time.Duration
	// Token is the current access token while Authorized; it may be
	// empty or expired after a temporary refresh failure.
	Token oauth.Token
}

// TokenBroker keeps the access tokens of delegated backends fresh (SPEC
// US-6.3). The controller (leader) is the only component that redeems
// refresh tokens, so replicas never race and a rotated refresh token is
// never lost: it is kept in memory as soon as the provider returns it and
// written to the token Secret, from which a restarted controller resumes.
// The api-server and SMTP proxy read only the access token from that
// Secret (AccessTokenFromSecret).
type TokenBroker struct {
	// Reader reads the token Secret (the cached client; the credentials
	// namespaces are readable). Writer creates and patches it.
	Reader client.Reader
	Writer client.Writer
	Guard  *GuardChecker
	Now    func() time.Time
	// Endpoints returns the token and device authorization endpoints of a
	// Microsoft tenant; nil uses Microsoft's. HTTPClient reaches them; nil
	// uses the default client. Tests replace both.
	Endpoints  func(tenant string) (tokenURL, deviceURL string, err error)
	HTTPClient *http.Client

	// mu serializes Ensure, token requests included: a few delegated
	// backends refresh once every half hour, so contention is negligible
	// and no two refreshes of one chain can overlap.
	mu    sync.Mutex
	state map[types.UID]*brokerState
}

// brokerState is what the broker holds for one backend.
type brokerState struct {
	key          string // DelegatedBackend.Key, for Forget
	seed         string // seedHash of the sign-in this chain descends from
	refreshToken string
	token        oauth.Token
	refreshAt    time.Time
	stored       bool // token and refreshToken are in the Secret

	// Device code sign-in (oauth_signin.go).
	authorize  *string // the sigillum.dev/authorize value handled last
	wantSignIn bool    // a new sign-in was asked for
	device     *oauth.DeviceAuthorization
	nextPoll   time.Time
	expired    string // why the last sign-in failed; until a new request
}

// Ensure refreshes the backend's access token when it is due and stores it
// in the token Secret. Callers run it on every reconcile and health check,
// so the refresh token is used, and kept alive, every half token lifetime
// even when no mail is sent.
func (b *TokenBroker) Ensure(ctx context.Context, d DelegatedBackend) (res BrokerResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	seed := seedHash(d.Seed)
	st := b.state[d.Owner.GetUID()]
	if st == nil || st.seed != seed {
		st = b.load(ctx, d, seed)
		if b.state == nil {
			b.state = map[types.UID]*brokerState{}
		}
		b.state[d.Owner.GetUID()] = st
	}
	defer func() {
		if res.Authorized {
			res.Token = st.token
		}
		// A new sign-in failed while the old one works: keep using the
		// old one, and say so until the next request.
		if res.Reason == sigv1.ReasonAuthorized && st.expired != "" {
			res.Reason, res.Message = sigv1.ReasonAuthorizationExpired, expiredMessage(st.expired)
		}
	}()
	noteAuthorize(st, d)
	if d.Device != nil && (st.refreshToken == "" || st.wantSignIn && st.expired == "") {
		return b.signIn(ctx, d, st, now)
	}
	if st.refreshToken == "" {
		backendAuthorized.WithLabelValues(d.Key).Set(0)
		return BrokerResult{Reason: sigv1.ReasonAuthorizationRequired, RequeueAfter: brokerReauthRetry,
			Message: "no refresh token yet: sign in and store the refresh_token in the credentials Secret"}
	}
	if st.stored && now.Before(st.refreshAt) {
		backendAuthorized.WithLabelValues(d.Key).Set(1)
		return authorized(st.refreshAt.Sub(now))
	}
	// A refresh may rotate the refresh token. Only redeem it while the
	// result can be stored, or a restart would lose it.
	if ok, msg := b.Guard.OK(); !ok {
		return BrokerResult{Authorized: st.stored, Reason: sigv1.ReasonGuardMissing, Message: msg, RequeueAfter: brokerRetry}
	}
	if !now.Before(st.refreshAt) {
		tok, next, err := d.Refresher.Refresh(ctx, st.refreshToken)
		if err != nil {
			if oauth.IsPermanent(err) && d.Device != nil {
				st.refreshToken, st.token, st.stored = "", oauth.Token{}, false
				return b.signIn(ctx, d, st, now)
			}
			if oauth.IsPermanent(err) {
				backendAuthorized.WithLabelValues(d.Key).Set(0)
				return BrokerResult{Reason: sigv1.ReasonAuthorizationRequired, RequeueAfter: brokerReauthRetry,
					Message: "the provider rejected the refresh token, sign in again: " + err.Error()}
			}
			return BrokerResult{Authorized: true, Reason: sigv1.ReasonTokenRefreshFailed, RequeueAfter: brokerRetry,
				Message: err.Error()}
		}
		st.refreshToken, st.token, st.stored = next, tok, false
		st.refreshAt = now.Add(tok.Expiry.Sub(now) / 2)
	}
	return b.store(ctx, d, st, now)
}

// store writes the state's tokens into the token Secret.
func (b *TokenBroker) store(ctx context.Context, d DelegatedBackend, st *brokerState, now time.Time) BrokerResult {
	if conflict, err := b.write(ctx, d, st); err != nil {
		reason := sigv1.ReasonSecretWriteFailed
		if conflict {
			reason = sigv1.ReasonSecretConflict
		}
		return BrokerResult{Authorized: true, Reason: reason, RequeueAfter: brokerRetry,
			Message: fmt.Sprintf("store tokens in Secret %s/%s: %v", d.Namespace, tokenSecretName(d), err)}
	}
	st.stored = true
	backendAuthorized.WithLabelValues(d.Key).Set(1)
	return authorized(st.refreshAt.Sub(now))
}

// Forget drops the state and metric of a backend that was deleted or no
// longer uses a delegated sign-in. key is DelegatedBackend.Key.
func (b *TokenBroker) Forget(key string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for uid, st := range b.state {
		if st.key == key {
			delete(b.state, uid)
		}
	}
	backendAuthorized.DeleteLabelValues(key)
}

func authorized(requeue time.Duration) BrokerResult {
	return BrokerResult{Authorized: true, Reason: sigv1.ReasonAuthorized, RequeueAfter: requeue}
}

// load resumes from the token Secret if it belongs to this backend and
// descends from the current sign-in; otherwise it starts from the seed. A
// Secret that cannot be read counts as missing: the seed is then redeemed,
// which fails with invalid_grant if it was rotated away, and asks for a
// new sign-in rather than guessing.
func (b *TokenBroker) load(ctx context.Context, d DelegatedBackend, seed string) *brokerState {
	st := &brokerState{key: d.Key, seed: seed, refreshToken: d.Seed}
	var sec corev1.Secret
	if err := b.Reader.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: tokenSecretName(d)}, &sec); err != nil {
		return st
	}
	if sec.Annotations[sigv1.OAuthTokenUIDAnnotation] != string(d.Owner.GetUID()) ||
		sec.Annotations[sigv1.OAuthSeedAnnotation] != seed || len(sec.Data[sigv1.OAuthSecretRefreshTokenKey]) == 0 {
		return st
	}
	st.refreshToken = string(sec.Data[sigv1.OAuthSecretRefreshTokenKey])
	if tok, err := AccessTokenFromSecret(&sec); err == nil {
		st.token = tok
		if t, err := time.Parse(time.RFC3339, sec.Annotations[sigv1.OAuthRefreshAtAnnotation]); err == nil {
			st.refreshAt, st.stored = t, true
		}
	}
	return st
}

// write creates the token Secret or replaces its data. Like the
// MailCredential Secrets, the replacement is a JSON patch whose test
// operations require this backend's label and UID: without read access
// outside the credentials namespaces, that is how a foreign Secret of the
// same name is detected (conflict).
func (b *TokenBroker) write(ctx context.Context, d DelegatedBackend, st *brokerState) (conflict bool, err error) {
	name, uid := tokenSecretName(d), string(d.Owner.GetUID())
	data := map[string][]byte{
		sigv1.OAuthSecretRefreshTokenKey: []byte(st.refreshToken),
		sigv1.OAuthSecretAccessTokenKey:  []byte(st.token.AccessToken),
		sigv1.OAuthSecretExpiresAtKey:    []byte(st.token.Expiry.UTC().Format(time.RFC3339)),
	}
	refreshAt := st.refreshAt.UTC().Format(time.RFC3339)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: d.Namespace,
			Labels:    map[string]string{sigv1.OAuthTokenLabel: d.Owner.GetName()},
			Annotations: map[string]string{
				sigv1.OAuthTokenUIDAnnotation:  uid,
				sigv1.OAuthSeedAnnotation:      st.seed,
				sigv1.OAuthRefreshAtAnnotation: refreshAt,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: sigv1.GroupVersion.String(),
				Kind:       d.Kind,
				Name:       d.Owner.GetName(),
				UID:        d.Owner.GetUID(),
				Controller: ptr.To(true),
			}},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	err = b.Writer.Create(ctx, sec)
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return false, err
	}
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/labels/" + jsonPointerEscape(sigv1.OAuthTokenLabel), "value": d.Owner.GetName()},
		{"op": "test", "path": "/metadata/annotations/" + jsonPointerEscape(sigv1.OAuthTokenUIDAnnotation), "value": uid},
		{"op": "add", "path": "/metadata/annotations/" + jsonPointerEscape(sigv1.OAuthSeedAnnotation), "value": st.seed},
		{"op": "add", "path": "/metadata/annotations/" + jsonPointerEscape(sigv1.OAuthRefreshAtAnnotation), "value": refreshAt},
		{"op": "add", "path": "/data", "value": data},
	})
	if err != nil {
		return false, err
	}
	err = b.Writer.Patch(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: d.Namespace}},
		client.RawPatch(types.JSONPatchType, patch))
	// A failed test operation and a guard denial both answer 422 Invalid.
	if apierrors.IsInvalid(err) {
		return true, err
	}
	return false, err
}

func (b *TokenBroker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// AccessTokenFromSecret reads the access token the broker stored, for the
// api-server and SMTP proxy.
func AccessTokenFromSecret(sec *corev1.Secret) (oauth.Token, error) {
	tok := string(sec.Data[sigv1.OAuthSecretAccessTokenKey])
	exp, err := time.Parse(time.RFC3339, string(sec.Data[sigv1.OAuthSecretExpiresAtKey]))
	if tok == "" || err != nil {
		return oauth.Token{}, errors.New("token Secret has no access token yet")
	}
	return oauth.Token{AccessToken: tok, Expiry: exp}, nil
}

// TokenSecretName is the name of a delegated backend's token Secret. The
// kind is part of it, since a MailBackend and a ClusterMailBackend of the
// same name may keep their credentials in the same namespace.
func TokenSecretName(kind, backend string) string {
	prefix := "sigillum-oauth-cmb-"
	if kind == "MailBackend" {
		prefix = "sigillum-oauth-mb-"
	}
	name := prefix + backend
	if len(name) <= 253 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	// Cut where the name stays a valid DNS subdomain before the "-".
	return strings.TrimRight(name[:253-17], ".-") + "-" + hex.EncodeToString(sum[:8])
}

func tokenSecretName(d DelegatedBackend) string { return TokenSecretName(d.Kind, d.Owner.GetName()) }

// seedHash identifies a refresh token without storing it twice.
func seedHash(rt string) string {
	if rt == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rt))
	return hex.EncodeToString(sum[:16])
}
