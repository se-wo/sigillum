package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedisLimiter(t *testing.T) (*RedisLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	mr.SetTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	c := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return NewRedisLimiter(RedisOptions{Client: c}), mr
}

func TestRedisLimiter_PerMinuteWindow(t *testing.T) {
	l, mr := newRedisLimiter(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if ok, _, err := l.Allow(ctx, "ns/p", 5, 0); !ok || err != nil {
			t.Fatalf("hit %d: ok=%v err=%v", i, ok, err)
		}
	}
	mr.SetTime(time.Date(2026, 1, 1, 12, 0, 20, 0, time.UTC))
	ok, retry, err := l.Allow(ctx, "ns/p", 5, 0)
	if ok || err != nil {
		t.Fatalf("6th hit must be rejected: ok=%v err=%v", ok, err)
	}
	if retry != 40*time.Second {
		t.Fatalf("want retry 40s, got %v", retry)
	}
	mr.SetTime(time.Date(2026, 1, 1, 12, 1, 1, 0, time.UTC))
	if ok, _, _ := l.Allow(ctx, "ns/p", 5, 0); !ok {
		t.Fatal("expected allow after window slide")
	}
}

func TestRedisLimiter_PerHourWindow(t *testing.T) {
	l, mr := newRedisLimiter(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		mr.SetTime(base.Add(time.Duration(i) * 5 * time.Minute))
		if ok, _, _ := l.Allow(ctx, "ns/p", 0, 3); !ok {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	mr.SetTime(base.Add(20 * time.Minute))
	ok, retry, _ := l.Allow(ctx, "ns/p", 0, 3)
	if ok || retry != 40*time.Minute {
		t.Fatalf("want reject with retry 40m, got ok=%v retry=%v", ok, retry)
	}
	if ttl := mr.TTL("sigillum:rl:ns/p"); ttl <= 0 || ttl > time.Hour {
		t.Fatalf("counter key must expire within an hour, ttl=%v", ttl)
	}
}

func TestRedisLimiter_SharedAcrossInstances(t *testing.T) {
	l1, mr := newRedisLimiter(t)
	c2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer c2.Close()
	l2 := NewRedisLimiter(RedisOptions{Client: c2})
	ctx := context.Background()
	l1.Allow(ctx, "ns/p", 2, 0)
	l2.Allow(ctx, "ns/p", 2, 0)
	if ok, _, _ := l1.Allow(ctx, "ns/p", 2, 0); ok {
		t.Fatal("replicas must share one budget")
	}
}

func TestRedisLimiter_FailClosedAndOpen(t *testing.T) {
	l, mr := newRedisLimiter(t)
	mr.Close()
	ctx := context.Background()
	ok, _, err := l.Allow(ctx, "ns/p", 5, 0)
	if ok || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fail-closed: want ErrUnavailable, got ok=%v err=%v", ok, err)
	}
	l.FailOpen = true
	if ok, _, err := l.Allow(ctx, "ns/p", 5, 0); !ok || err != nil {
		t.Fatalf("fail-open: want allow, got ok=%v err=%v", ok, err)
	}
}
