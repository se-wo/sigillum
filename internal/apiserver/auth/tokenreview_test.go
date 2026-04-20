package auth

import (
	"context"
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
		in           string
		ns, sa       string
		ok           bool
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
