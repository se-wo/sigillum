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
	mu    sync.Mutex
	hits  map[string]history
	now   func() time.Time
	swept time.Time
}

// history is one key's hits, sorted oldest first, and when they all stop
// counting, like the expiry of the Redis key.
type history struct {
	hits    []time.Time
	expires time.Time
}

// NewMemoryLimiter constructs a MemoryLimiter. Timestamps older than the
// longest capped window (one hour, or one day with a daily cap) are dropped
// on every Allow call for their key, and keys nobody sent on for that long
// are removed once a minute.
func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		hits: map[string]history{},
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
	l.sweep(now)
	h := l.hits[key]
	if !h.expires.After(now) {
		h = history{} // expired but not swept yet, as gone as the Redis key
	}
	hist := h.hits[since(h.hits, now.Add(-limits.retain(h.expires.Sub(now)))):]

	// Every hit in a window is younger than the window, so the wait for a
	// full window is always positive and retry > 0 means "rejected".
	var retry time.Duration
	for _, w := range limits.windows() {
		if w.limit <= 0 {
			continue
		}
		first := since(hist, now.Add(-w.size))
		if int64(len(hist)-first) < int64(w.limit) {
			continue
		}
		// The window has room again once enough of its hits have left it
		// for the count to drop below the limit.
		retry = max(retry, hist[len(hist)-int(w.limit)].Add(w.size).Sub(now))
	}
	if retry > 0 {
		l.hits[key] = history{hist, h.expires}
		return false, ceilToSecond(retry), nil
	}

	l.hits[key] = history{append(hist, now), later(h.expires, now.Add(limits.keep()))}
	return true, 0, nil
}

// sweep removes, at most once a minute, the keys whose hits no longer
// count, so idle and deleted policies do not hold memory until restart.
func (l *MemoryLimiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	for key, h := range l.hits {
		if !h.expires.After(now) {
			delete(l.hits, key)
		}
	}
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// since returns the index of the first hit in hist, sorted oldest first,
// that is younger than cutoff, so every window is a suffix of hist. A hit
// leaves a window the moment it is as old as the window, so a caller
// retrying exactly after Retry-After finds room.
func since(hist []time.Time, cutoff time.Time) int {
	return sort.Search(len(hist), func(i int) bool { return hist[i].After(cutoff) })
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
	if h := l.hits[key]; len(h.hits) > 0 {
		l.hits[key] = history{h.hits[:len(h.hits)-1], h.expires}
	}
	return nil
}
