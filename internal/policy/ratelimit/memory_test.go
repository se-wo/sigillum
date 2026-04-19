package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiter_PerMinuteWindow(t *testing.T) {
	l := NewMemoryLimiter()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		ok, _ := l.Allow(context.Background(), "k", 5, 0)
		if !ok {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	ok, retry := l.Allow(context.Background(), "k", 5, 0)
	if ok {
		t.Fatal("6th hit must be rejected")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry-after out of bounds: %v", retry)
	}

	// Slide past the window — old hits drop out and we accept again.
	now = now.Add(61 * time.Second)
	ok, _ = l.Allow(context.Background(), "k", 5, 0)
	if !ok {
		t.Fatal("expected allow after window slide")
	}
}

func TestMemoryLimiter_PerHourWindow(t *testing.T) {
	l := NewMemoryLimiter()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		l.now = func() time.Time { return base.Add(time.Duration(i) * 5 * time.Minute) }
		if ok, _ := l.Allow(context.Background(), "k", 0, 3); !ok {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	l.now = func() time.Time { return base.Add(20 * time.Minute) }
	ok, retry := l.Allow(context.Background(), "k", 0, 3)
	if ok {
		t.Fatal("4th hit in same hour must be rejected")
	}
	if retry <= 0 {
		t.Fatalf("retry-after must be > 0, got %v", retry)
	}
}

func TestMemoryLimiter_NoLimitWhenZero(t *testing.T) {
	l := NewMemoryLimiter()
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow(context.Background(), "k", 0, 0); !ok {
			t.Fatalf("hit %d unexpectedly rejected", i)
		}
	}
}

func TestMemoryLimiter_KeysAreIsolated(t *testing.T) {
	l := NewMemoryLimiter()
	for i := 0; i < 5; i++ {
		l.Allow(context.Background(), "ns/policy-a", 5, 0)
	}
	if ok, _ := l.Allow(context.Background(), "ns/policy-b", 5, 0); !ok {
		t.Fatal("different keys must not share counters")
	}
}

func TestNoLimit(t *testing.T) {
	if ok, _ := NoLimit.Allow(context.Background(), "x", 1, 1); !ok {
		t.Fatal("NoLimit.Allow must always allow")
	}
}
