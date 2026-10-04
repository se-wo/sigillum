// Package ratelimit defines the rate-limit interface used by the send path.
// Two backends ship: in-memory (single replica only) and Redis (shared across
// replicas, SPEC §4.7).
package ratelimit

import (
	"context"
	"errors"
	"time"
)

// ErrUnavailable is returned by Allow when the limiter cannot reach its
// backing store and is configured to fail closed. The send path maps it to
// a retryable 503 rather than a 429, because the caller did nothing wrong.
var ErrUnavailable = errors.New("rate limiter unavailable")

// Limits caps the hits per sliding window. 0 means no cap on that window.
type Limits struct {
	PerMinute int32
	PerHour   int32
	PerDay    int32
}

// None reports whether no window is capped.
func (l Limits) None() bool { return l.PerMinute <= 0 && l.PerHour <= 0 && l.PerDay <= 0 }

// window is one sliding window and its cap (0 = no cap).
type window struct {
	limit int32
	size  time.Duration
}

// windows lists every window, shortest first. The Redis script mirrors it.
func (l Limits) windows() [3]window {
	return [3]window{{l.PerMinute, time.Minute}, {l.PerHour, time.Hour}, {l.PerDay, 24 * time.Hour}}
}

// keep is how far back hits must be kept to count every capped window:
// one hour, or one day with a daily cap.
func (l Limits) keep() time.Duration {
	if l.PerDay > 0 {
		return 24 * time.Hour
	}
	return time.Hour
}

// retain is how far back a call trims the stored history, given how long
// that history has left before it expires. It is the call's own keep, or a
// full day while a call with a daily cap holds the history for longer, so a
// replica that has not seen the cap yet, or a cap briefly set to 0, does not
// wipe the daily count. Only keep extends the expiry, so after a daily cap
// is removed the history shrinks back to an hour within a day. The Redis
// script mirrors it.
func (l Limits) retain(left time.Duration) time.Duration {
	if left > l.keep() {
		return 24 * time.Hour
	}
	return l.keep()
}

// Limiter is the interface implemented by every rate-limit backend.
type Limiter interface {
	// Allow returns true if the request fits within every capped window of
	// limits for key, and records it. retryAfter is non-zero only when
	// Allow returns false without error; it is the wait until every full
	// window has room again.
	Allow(ctx context.Context, key string, limits Limits) (allowed bool, retryAfter time.Duration, err error)
	// Refund gives back one previously admitted hit for key, e.g. when the
	// send failed transiently and the caller will retry. Removing the newest
	// hit rather than a specific one is equivalent for counting purposes.
	Refund(ctx context.Context, key string) error
}

// NoLimit is a Limiter that always allows; used when a policy declares
// no rate limits.
var NoLimit Limiter = noLimit{}

type noLimit struct{}

func (noLimit) Allow(context.Context, string, Limits) (bool, time.Duration, error) {
	return true, 0, nil
}

func (noLimit) Refund(context.Context, string) error { return nil }
