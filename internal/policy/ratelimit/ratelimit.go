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

// Limiter is the interface implemented by every rate-limit backend.
type Limiter interface {
	// Allow returns true if the request fits within the configured per-minute
	// and per-hour windows for key, and records it. retryAfter is non-zero
	// only when Allow returns false without error.
	Allow(ctx context.Context, key string, perMinute, perHour int32) (allowed bool, retryAfter time.Duration, err error)
	// Refund gives back one previously admitted hit for key, e.g. when the
	// send failed transiently and the caller will retry. Removing the newest
	// hit rather than a specific one is equivalent for counting purposes.
	Refund(ctx context.Context, key string) error
}

// NoLimit is a Limiter that always allows; used when a policy declares
// no rate limits.
var NoLimit Limiter = noLimit{}

type noLimit struct{}

func (noLimit) Allow(_ context.Context, _ string, _, _ int32) (bool, time.Duration, error) {
	return true, 0, nil
}

func (noLimit) Refund(context.Context, string) error { return nil }
