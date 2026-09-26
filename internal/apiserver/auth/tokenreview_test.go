package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestParseServiceAccountUsername(t *testing.T) {
	cases := []struct {
		in     string
		ns, sa string
		ok     bool
	}{
		{"system:serviceaccount:billing:billing-mailer", "billing", "billing-mailer", true},
		{"system:serviceaccount::missing-ns", "", "", false},
		{"system:serviceaccount:ns:", "", "", false},
		{"system:user:foo", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		ns, sa, ok := parseServiceAccountUsername(tc.in)
		if ok != tc.ok || ns != tc.ns || sa != tc.sa {
			t.Errorf("%q -> ns=%q sa=%q ok=%v; want ns=%q sa=%q ok=%v", tc.in, ns, sa, ok, tc.ns, tc.sa, tc.ok)
		}
	}
}

func TestAuthenticator_AcceptCachesResult(t *testing.T) {
	calls := 0
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, &authv1.TokenReview{
			ObjectMeta: metav1.ObjectMeta{},
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: "system:serviceaccount:billing:billing-mailer",
					UID:      "uid-1",
				},
				Audiences: []string{"sigillum"},
			},
		}, nil
	})
	a, err := New(cs, []string{"sigillum"}, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s, err := a.Authenticate(context.Background(), "tok")
		if err != nil {
			t.Fatalf("auth %d: %v", i, err)
		}
		if s.ServiceAccount != "billing-mailer" || s.Namespace != "billing" {
			t.Fatalf("wrong subject: %+v", s)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 TokenReview call, got %d", calls)
	}
}

func TestAuthenticator_RejectIsCachedNegative(t *testing.T) {
	calls := 0
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: false, Error: "bad"}}, nil
	})
	a, _ := New(cs, []string{"sigillum"}, 16, time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := a.Authenticate(context.Background(), "tok"); err == nil {
			t.Fatalf("auth %d expected error", i)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 call due to negative cache, got %d", calls)
	}
}

func reviewWithAudiences(auds []string) func(k8stesting.Action) (bool, runtime.Object, error) {
	return func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User:          authv1.UserInfo{Username: "system:serviceaccount:billing:billing-mailer"},
			Audiences:     auds,
		}}, nil
	}
}

func TestAuthenticator_RejectsTokenWithoutRequestedAudience(t *testing.T) {
	cases := map[string][]string{
		// A non-audience-aware authenticator answers with no audiences,
		// meaning the token is valid for the kube-apiserver.
		"empty":           nil,
		"apiserver token": {"https://kubernetes.default.svc.cluster.local"},
	}
	for name, auds := range cases {
		t.Run(name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			cs.PrependReactor("create", "tokenreviews", reviewWithAudiences(auds))
			a, err := New(cs, []string{"sigillum"}, 16, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if s, err := a.Authenticate(context.Background(), "tok"); err == nil {
				t.Fatalf("token without the sigillum audience must be rejected, got %+v", s)
			}
			// The rejection is cached like any other negative result.
			if _, err := a.Authenticate(context.Background(), "tok"); err == nil {
				t.Fatal("cached result must still reject")
			}
		})
	}
}

func TestAuthenticator_AcceptsAnyConfiguredAudience(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", reviewWithAudiences([]string{"other", "sigillum-smtp"}))
	a, err := New(cs, []string{"sigillum", "sigillum-smtp"}, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), "tok"); err != nil {
		t.Fatalf("intersecting audience must be accepted: %v", err)
	}
}

func TestNew_RequiresAudience(t *testing.T) {
	for _, auds := range [][]string{nil, {}, {""}, {"  "}} {
		if _, err := New(fake.NewSimpleClientset(), auds, 0, time.Minute); err == nil {
			t.Errorf("audiences %q: want error", auds)
		}
	}
}

// jwtWithExp builds an (unsigned) JWT-shaped token with the given exp.
func jwtWithExp(exp int64) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp))) + ".sig"
}

func TestAuthenticator_CacheBoundedByTokenExpiry(t *testing.T) {
	calls := 0
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User:          authv1.UserInfo{Username: "system:serviceaccount:billing:billing-mailer"},
			Audiences:     []string{"sigillum"},
		}}, nil
	})
	a, err := New(cs, []string{"sigillum"}, 16, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	a.now = func() time.Time { return now }

	// Token expiring in 30s: cached, but only until exp, not for the 5 min TTL.
	tok := jwtWithExp(now.Unix() + 30)
	for i := 0; i < 2; i++ {
		if _, err := a.Authenticate(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("want 1 TokenReview within exp, got %d", calls)
	}
	now = now.Add(31 * time.Second)
	if _, err := a.Authenticate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cache entry must end at the token's exp; TokenReview calls = %d", calls)
	}

	// Already expired according to its claim: never cached.
	expired := jwtWithExp(now.Unix() - 1)
	for i := 0; i < 2; i++ {
		_, _ = a.Authenticate(context.Background(), expired)
	}
	if calls != 4 {
		t.Fatalf("expired token must not be cached; TokenReview calls = %d", calls)
	}

	// A far-future exp does not extend the TTL.
	long := jwtWithExp(now.Unix() + 3600)
	_, _ = a.Authenticate(context.Background(), long)
	now = now.Add(5*time.Minute + time.Second)
	_, _ = a.Authenticate(context.Background(), long)
	if calls != 6 {
		t.Fatalf("TTL must still apply; TokenReview calls = %d", calls)
	}
}

func TestTokenExpiry(t *testing.T) {
	if _, ok := tokenExpiry("opaque-token"); ok {
		t.Fatal("non-JWT must have no expiry")
	}
	if _, ok := tokenExpiry("a.!!!.c"); ok {
		t.Fatal("bad base64 must have no expiry")
	}
	if exp, ok := tokenExpiry(jwtWithExp(42)); !ok || exp.Unix() != 42 {
		t.Fatalf("exp = %v %v", exp, ok)
	}
}

// Review of #20: a failed TokenReview request is ErrUnavailable, and is
// not cached as a rejection.
func TestAuthenticator_ReviewFailureIsUnavailable(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	a, err := New(cs, []string{"sigillum"}, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), "tok"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}
