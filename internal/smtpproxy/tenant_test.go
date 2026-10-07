package smtpproxy

import (
	"context"
	"testing"
	"time"
)

func TestTenantLimiter(t *testing.T) {
	lim := newTenantLimiter(2)

	// Two slots for namespace "a" are available; the third waits.
	r1, ok := lim.acquire(context.Background(), "a")
	if !ok {
		t.Fatal("first acquire must succeed")
	}
	r2, ok := lim.acquire(context.Background(), "a")
	if !ok {
		t.Fatal("second acquire must succeed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := lim.acquire(ctx, "a"); ok {
		t.Fatal("third acquire for the same tenant must wait and fail on ctx")
	}

	// A different tenant is unaffected by "a" being full.
	rb, ok := lim.acquire(context.Background(), "b")
	if !ok {
		t.Fatal("another tenant must get its own slots")
	}
	rb()

	// Releasing frees a slot for "a".
	r1()
	r3, ok := lim.acquire(context.Background(), "a")
	if !ok {
		t.Fatal("a slot must be free after release")
	}
	r2()
	r3()

	// An idle namespace is removed from the map so it cannot leak.
	lim.mu.Lock()
	n := len(lim.ns)
	lim.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle namespaces must be removed, %d left", n)
	}
}

func TestTenantLimiterNilIsUnbounded(t *testing.T) {
	var lim *tenantLimiter
	for i := 0; i < 100; i++ {
		if _, ok := lim.acquire(context.Background(), "x"); !ok {
			t.Fatal("a nil limiter must never block")
		}
	}
}
