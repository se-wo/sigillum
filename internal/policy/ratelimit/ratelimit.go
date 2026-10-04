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

// keep is how far back hits must be kept to count every capped window.
func (l Limits) keep() time.Duration {
	if l.PerDay > 0 {
		return 24 * time.Hour
	}
	return time.Hour
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
