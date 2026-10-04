package ratelimit

import (
	"context"
	"testing"
	"time"
)

// clocked is a Limiter whose clock the test sets.
type clocked struct {
	Limiter
	set func(time.Time)
}

// limiters runs fn against every backend, so both count the same way.
func limiters(t *testing.T, fn func(t *testing.T, l clocked)) {
	t.Run("memory", func(t *testing.T) {
		m := NewMemoryLimiter()
		var now time.Time
		m.now = func() time.Time { return now }
		fn(t, clocked{m, func(t time.Time) { now = t }})
	})
	t.Run("redis", func(t *testing.T) {
		r, mr := newRedisLimiter(t)
		fn(t, clocked{r, mr.SetTime})
	})
}

var base = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func mustAllow(t *testing.T, l clocked, at time.Duration, limits Limits) {
	t.Helper()
	l.set(base.Add(at))
	if ok, _, err := l.Allow(context.Background(), "ns/p", limits); !ok || err != nil {
		t.Fatalf("hit at +%v: want allowed, got ok=%v err=%v", at, ok, err)
	}
}

func mustReject(t *testing.T, l clocked, at time.Duration, limits Limits, retry time.Duration) {
	t.Helper()
	l.set(base.Add(at))
	ok, got, err := l.Allow(context.Background(), "ns/p", limits)
	if ok || err != nil {
		t.Fatalf("hit at +%v: want rejected, got ok=%v err=%v", at, ok, err)
	}
	if got != retry {
		t.Fatalf("hit at +%v: want retry-after %v, got %v", at, retry, got)
	}
}

func TestLimiter_PerDayWindow(t *testing.T) {
	limiters(t, func(t *testing.T, l clocked) {
		daily := Limits{PerDay: 3}
		mustAllow(t, l, 0, daily)
		mustAllow(t, l, 2*time.Hour, daily)
		mustAllow(t, l, 4*time.Hour, daily)
		// Hits older than an hour still count against the day.
		mustReject(t, l, 6*time.Hour, daily, 18*time.Hour)
		// The first hit leaves the window 24 hours after it was sent.
		mustAllow(t, l, 24*time.Hour+time.Second, daily)
		mustReject(t, l, 24*time.Hour+2*time.Second, daily, 2*time.Hour-2*time.Second)
	})
}

func TestLimiter_PerDayWithShorterWindows(t *testing.T) {
	limiters(t, func(t *testing.T, l clocked) {
		limits := Limits{PerMinute: 2, PerHour: 3, PerDay: 4}
		mustAllow(t, l, 0, limits)
		mustAllow(t, l, time.Second, limits)
		mustReject(t, l, 2*time.Second, limits, 58*time.Second)
		mustAllow(t, l, time.Minute, limits)
		mustReject(t, l, 2*time.Minute, limits, 58*time.Minute)
		mustAllow(t, l, 61*time.Minute, limits)
		mustReject(t, l, 3*time.Hour, limits, 21*time.Hour)
	})
}

// A caller that retries after Retry-After must find room in every window,
// not only in the shortest one that is full.
func TestLimiter_RetryAfterCoversEveryFullWindow(t *testing.T) {
	limiters(t, func(t *testing.T, l clocked) {
		limits := Limits{PerMinute: 2, PerHour: 2}
		mustAllow(t, l, 0, limits)
		mustAllow(t, l, 10*time.Second, limits)
		// Both windows are full; the hour frees up last.
		mustReject(t, l, 20*time.Second, limits, time.Hour-20*time.Second)
		mustAllow(t, l, time.Hour, limits)
	})
}

// After a limit is lowered below the hits already in the window, the window
// has room only once enough of them have left it.
func TestLimiter_LoweredLimit(t *testing.T) {
	limiters(t, func(t *testing.T, l clocked) {
		for i := range 5 {
			mustAllow(t, l, time.Duration(i)*time.Minute, Limits{PerHour: 10})
		}
		// Hits at +0m..+4m; with 3 allowed, the one at +2m must leave.
		mustReject(t, l, 10*time.Minute, Limits{PerHour: 3}, 52*time.Minute)
		mustAllow(t, l, 62*time.Minute, Limits{PerHour: 3})
	})
}

func TestRedisLimiter_PerDayKeyExpiry(t *testing.T) {
	l, mr := newRedisLimiter(t)
	if ok, _, err := l.Allow(context.Background(), "ns/p", Limits{PerHour: 5, PerDay: 5}); !ok || err != nil {
		t.Fatalf("want allowed, got ok=%v err=%v", ok, err)
	}
	if ttl := mr.TTL("sigillum:rl:ns/p"); ttl <= time.Hour || ttl > 24*time.Hour {
		t.Fatalf("with a daily cap the counter key must live for a day, ttl=%v", ttl)
	}
}

func TestMemoryLimiter_KeepsOnlyTheLongestCappedWindow(t *testing.T) {
	l := NewMemoryLimiter()
	var now time.Time
	l.now = func() time.Time { return now }
	ctx := context.Background()
	for _, tc := range []struct {
		limits Limits
		want   int
	}{
		// Hits at +0h and +2h; at +3h an hourly cap keeps none of them,
		// a daily cap both.
		{Limits{PerHour: 10}, 0},
		{Limits{PerHour: 10, PerDay: 10}, 2},
	} {
		l.hits = map[string][]time.Time{}
		for _, at := range []time.Duration{0, 2 * time.Hour} {
			now = base.Add(at)
			l.Allow(ctx, "k", Limits{PerDay: 10})
		}
		now = base.Add(3 * time.Hour)
		l.Allow(ctx, "k", tc.limits)
		if got := len(l.hits["k"]) - 1; got != tc.want {
			t.Errorf("%+v: kept %d earlier hits, want %d", tc.limits, got, tc.want)
		}
	}
}
