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
		l.hits = map[string]history{}
		for _, at := range []time.Duration{0, 2 * time.Hour} {
			now = base.Add(at)
			l.Allow(ctx, "k", tc.limits)
		}
		now = base.Add(3 * time.Hour)
		l.Allow(ctx, "k", tc.limits)
		if got := len(l.hits["k"].hits) - 1; got != tc.want {
			t.Errorf("%+v: kept %d earlier hits, want %d", tc.limits, got, tc.want)
		}
	}
}

// A call without the daily cap (a replica that has not seen it yet, or the
// cap briefly set to 0) must not trim the history the daily cap counts.
func TestLimiter_CallWithoutDailyCapKeepsDailyHistory(t *testing.T) {
	limiters(t, func(t *testing.T, l clocked) {
		daily := Limits{PerHour: 10, PerDay: 3}
		mustAllow(t, l, 0, daily)
		mustAllow(t, l, 2*time.Hour, daily)
		mustAllow(t, l, 4*time.Hour, Limits{PerHour: 10})
		mustReject(t, l, 6*time.Hour, daily, 18*time.Hour)
	})
}

// A call without the daily cap neither shortens the day-long expiry nor
// extends it, so a removed cap stops holding history after a day.
func TestRedisLimiter_CallWithoutDailyCapKeepsExpiry(t *testing.T) {
	l, mr := newRedisLimiter(t)
	ctx := context.Background()
	if ok, _, err := l.Allow(ctx, "ns/p", Limits{PerDay: 5}); !ok || err != nil {
		t.Fatalf("want allowed, got ok=%v err=%v", ok, err)
	}
	mr.FastForward(5 * time.Hour)
	if ok, _, err := l.Allow(ctx, "ns/p", Limits{PerHour: 5}); !ok || err != nil {
		t.Fatalf("want allowed, got ok=%v err=%v", ok, err)
	}
	if ttl := mr.TTL("sigillum:rl:ns/p"); ttl != 19*time.Hour {
		t.Fatalf("want the daily expiry left as is (19h), got %v", ttl)
	}
}

func TestMemoryLimiter_SweepsIdleKeys(t *testing.T) {
	l := NewMemoryLimiter()
	var now time.Time
	l.now = func() time.Time { return now }
	ctx := context.Background()
	send := func(at time.Duration, key string, limits Limits) {
		now = base.Add(at)
		l.Allow(ctx, key, limits)
	}
	send(0, "hourly", Limits{PerHour: 10})
	send(0, "daily", Limits{PerDay: 10})
	// Any call sweeps; an hour after its last hit the hourly key is gone.
	send(time.Hour+time.Minute, "other", Limits{PerHour: 10})
	if _, ok := l.hits["hourly"]; ok {
		t.Fatal("idle hourly key still held after an hour")
	}
	if _, ok := l.hits["daily"]; !ok {
		t.Fatal("daily key dropped before its day was over")
	}
	send(24*time.Hour+time.Minute, "other", Limits{PerHour: 10})
	if _, ok := l.hits["daily"]; ok {
		t.Fatal("idle daily key still held after a day")
	}
}

// Hits that expired but are not swept yet no longer count, as with Redis.
func TestMemoryLimiter_ExpiredHitsDoNotCount(t *testing.T) {
	m := NewMemoryLimiter()
	var now time.Time
	m.now = func() time.Time { return now }
	l := clocked{m, func(t time.Time) { now = t }}
	mustAllow(t, l, 0, Limits{PerHour: 10})
	mustAllow(t, l, 10*time.Minute, Limits{PerHour: 10}) // ns/p expires at +70m
	now = base.Add(69*time.Minute + 30*time.Second)
	m.Allow(context.Background(), "other", Limits{PerHour: 10}) // sweeps, ns/p still live
	// Not swept again before +70m30s, but both hits expired at +70m.
	mustAllow(t, l, 70*time.Minute, Limits{PerDay: 2})
}

// A trim that empties the key deletes it with its expiry; the hit that
// recreates it must set an expiry again, even under a day-long one read
// before the trim.
func TestRedisLimiter_RecreatedKeyGetsExpiry(t *testing.T) {
	l, mr := newRedisLimiter(t)
	ctx := context.Background()
	for _, step := range []time.Duration{0, 20 * time.Hour} {
		mr.FastForward(step)
		mr.SetTime(base.Add(step))
		if ok, _, err := l.Allow(ctx, "ns/p", Limits{PerDay: 5}); !ok || err != nil {
			t.Fatalf("want allowed, got ok=%v err=%v", ok, err)
		}
	}
	// Refunding the newest hit leaves the one at +0h under the expiry the
	// refunded hit set (+44h).
	if err := l.Refund(ctx, "ns/p"); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(5 * time.Hour)
	mr.SetTime(base.Add(25 * time.Hour))
	if ok, _, err := l.Allow(ctx, "ns/p", Limits{PerHour: 5}); !ok || err != nil {
		t.Fatalf("want allowed, got ok=%v err=%v", ok, err)
	}
	if ttl := mr.TTL("sigillum:rl:ns/p"); ttl <= 0 || ttl > time.Hour {
		t.Fatalf("recreated key must expire within an hour, ttl=%v", ttl)
	}
}
