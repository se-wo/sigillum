// Package auth implements the Bearer-token authenticator backed by the
// Kubernetes TokenReview API with an in-process LRU cache.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
func New(c kubernetes.Interface, audiences []string, cacheSize int, ttl time.Duration) (*Authenticator, error) {
	if c == nil {
		return nil, errors.New("kubernetes client is required")
	}
	a := &Authenticator{client: c, audiences: audiences, ttl: ttl, now: time.Now}
	if cacheSize > 0 {
		ca, err := lru.New[string, cacheEntry](cacheSize)
		if err != nil {
			return nil, err
		}
		a.cache = ca
	}
	return a, nil
}

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
		return nil, err
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
		a.cache.Add(key, cacheEntry{subject: subj, expires: a.now().Add(a.ttl)})
	}
	return subj, nil
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
