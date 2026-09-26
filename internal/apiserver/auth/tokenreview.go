// Package auth implements the Bearer-token authenticator backed by the
// Kubernetes TokenReview API with an in-process LRU cache.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Subject is the result of a successful token review.
type Subject struct {
	Namespace      string
	ServiceAccount string
	UID            string
	Audiences      []string
	Groups         []string
}

// Authenticator validates Bearer tokens via TokenReview and caches the result.
type Authenticator struct {
	client    kubernetes.Interface
	audiences []string
	cache     *lru.Cache[string, cacheEntry]
	ttl       time.Duration
	now       func() time.Time
}

type cacheEntry struct {
	subject *Subject
	expires time.Time
}

// New constructs an Authenticator. cacheSize 0 disables caching.
//
// At least one non-empty audience is required: without one, TokenReview
// validates against the kube-apiserver's own audience, and Sigillum would
// accept (and receive) tokens that are valid for the Kubernetes API.
func New(c kubernetes.Interface, audiences []string, cacheSize int, ttl time.Duration) (*Authenticator, error) {
	if c == nil {
		return nil, errors.New("kubernetes client is required")
	}
	var auds []string
	for _, aud := range audiences {
		if aud = strings.TrimSpace(aud); aud != "" {
			auds = append(auds, aud)
		}
	}
	if len(auds) == 0 {
		return nil, errors.New("at least one token audience is required")
	}
	a := &Authenticator{client: c, audiences: auds, ttl: ttl, now: time.Now}
	if cacheSize > 0 {
		ca, err := lru.New[string, cacheEntry](cacheSize)
		if err != nil {
			return nil, err
		}
		a.cache = ca
	}
	return a, nil
}

// ErrUnavailable marks a token that could not be reviewed (the TokenReview
// request failed), as opposed to one the kube-apiserver rejected.
var ErrUnavailable = errors.New("token review unavailable")

// Authenticate validates token and returns the Kubernetes identity.
func (a *Authenticator) Authenticate(ctx context.Context, token string) (*Subject, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("empty token")
	}
	key := hashToken(token)

	if a.cache != nil {
		if e, ok := a.cache.Get(key); ok && a.now().Before(e.expires) {
			if e.subject == nil {
				return nil, errors.New("token rejected")
			}
			return e.subject, nil
		}
	}

	tr := &authv1.TokenReview{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: a.audiences,
		},
	}
	resp, err := a.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !resp.Status.Authenticated {
		if a.cache != nil {
			a.cache.Add(key, cacheEntry{expires: a.now().Add(a.ttl)})
		}
		msg := resp.Status.Error
		if msg == "" {
			msg = "token rejected by kube-apiserver"
		}
		return nil, errors.New(msg)
	}

	// The TokenReview API requires clients that set spec.audiences to verify
	// status.audiences: an authenticator that is not audience-aware may
	// answer authenticated=true with no audiences, which means the token is
	// valid for the kube-apiserver. Accepting such a token would hand
	// Sigillum a credential that can act as the ServiceAccount against the
	// Kubernetes API.
	if !a.audienceMatches(resp.Status.Audiences) {
		if a.cache != nil {
			a.cache.Add(key, cacheEntry{expires: a.now().Add(a.ttl)})
		}
		return nil, fmt.Errorf("token audiences %v do not include any of %v", resp.Status.Audiences, a.audiences)
	}

	ns, sa, ok := parseServiceAccountUsername(resp.Status.User.Username)
	if !ok {
		return nil, errors.New("token does not belong to a serviceaccount: " + resp.Status.User.Username)
	}
	subj := &Subject{
		Namespace:      ns,
		ServiceAccount: sa,
		UID:            resp.Status.User.UID,
		Audiences:      resp.Status.Audiences,
		Groups:         resp.Status.User.Groups,
	}
	if a.cache != nil {
		// Never cache a token beyond its own expiry (SPEC §5.3, G-5): the
		// TokenReview said "valid now", not "valid for the whole TTL".
		expires := a.now().Add(a.ttl)
		if exp, ok := tokenExpiry(token); ok && exp.Before(expires) {
			expires = exp
		}
		if a.now().Before(expires) {
			a.cache.Add(key, cacheEntry{subject: subj, expires: expires})
		}
	}
	return subj, nil
}

// tokenExpiry reads the exp claim of a JWT without verifying it. That is
// safe here because it is only used to shorten how long a result the
// kube-apiserver already verified stays cached, never to accept a token.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	secs, err := claims.Exp.Float64()
	if err != nil || secs <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
}

func (a *Authenticator) audienceMatches(got []string) bool {
	for _, g := range got {
		for _, want := range a.audiences {
			if g == want {
				return true
			}
		}
	}
	return false
}

// parseServiceAccountUsername decodes "system:serviceaccount:<ns>:<name>".
func parseServiceAccountUsername(u string) (string, string, bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(u, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(u, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}
