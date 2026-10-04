package ratelimit

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryLimiter is a simple sliding-window counter that keeps per-key
// timestamps in memory. Suitable only for single-replica deployments.
type MemoryLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

// NewMemoryLimiter constructs a MemoryLimiter. Timestamps older than the
// longest capped window (one hour, or one day with a daily cap) are dropped
// lazily on every Allow call.
func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		hits: map[string][]time.Time{},
		now:  time.Now,
	}
}

// Allow implements Limiter.Allow with sliding-window semantics. Windows
// with a limit of 0 are not capped.
func (l *MemoryLimiter) Allow(_ context.Context, key string, limits Limits) (bool, time.Duration, error) {
	if limits.None() {
		return true, 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	// hist is sorted oldest first, so every window is a suffix of it. A hit
	// leaves a window the moment it is as old as the window, so a caller
	// retrying exactly after Retry-After finds room.
	since := func(hist []time.Time, cutoff time.Time) int {
		return sort.Search(len(hist), func(i int) bool { return hist[i].After(cutoff) })
	}
	hist := l.hits[key]
	hist = hist[since(hist, now.Add(-limits.keep())):]

	full := false
	var retry time.Duration
	for _, w := range []struct {
		limit int32
		size  time.Duration
	}{
		{limits.PerMinute, time.Minute},
		{limits.PerHour, time.Hour},
		{limits.PerDay, 24 * time.Hour},
	} {
		if w.limit <= 0 {
			continue
		}
		first := since(hist, now.Add(-w.size))
		if int64(len(hist)-first) < int64(w.limit) {
			continue
		}
		// The window has room again once enough of its hits have left it
		// for the count to drop below the limit.
		leave := hist[len(hist)-int(w.limit)].Add(w.size).Sub(now)
		full, retry = true, max(retry, leave)
	}
	if full {
		l.hits[key] = hist
		return false, ceilToSecond(retry), nil
	}

	l.hits[key] = append(hist, now)
	return true, 0, nil
}

func ceilToSecond(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	if d%time.Second != 0 {
		return d.Truncate(time.Second) + time.Second
	}
	return d
}

// Refund implements Limiter.Refund by dropping the newest hit for key.
func (l *MemoryLimiter) Refund(_ context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if hist := l.hits[key]; len(hist) > 0 {
		l.hits[key] = hist[:len(hist)-1]
	}
	return nil
}
