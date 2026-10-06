package gateway

import (
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

func TestValidityCache(t *testing.T) {
	var c validityCache
	calls := 0
	invalid := errors.New("invalid")
	validate := func() error { calls++; return invalid }

	mp := &sigv1.MailPolicy{ObjectMeta: metav1.ObjectMeta{UID: "u1", Generation: 1}}
	for i := 0; i < 3; i++ {
		if err := c.check(mp, validate); !errors.Is(err, invalid) {
			t.Fatalf("got %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("same generation: want 1 validation, got %d", calls)
	}
	mp.Generation = 2
	_ = c.check(mp, validate)
	if calls != 2 {
		t.Fatalf("new generation: want a fresh validation, got %d calls", calls)
	}
	// Objects that did not come from the API server are never cached.
	_ = c.check(&sigv1.MailPolicy{}, validate)
	_ = c.check(&sigv1.MailPolicy{}, validate)
	if calls != 4 {
		t.Fatalf("no UID: want every call validated, got %d calls", calls)
	}
}
