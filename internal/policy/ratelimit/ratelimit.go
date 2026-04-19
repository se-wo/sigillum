// Package ratelimit defines the rate-limit interface used by the api-server.
// v1 only ships the in-memory implementation (single-replica only). v0.2 will
// add a Redis-backed implementation per SPEC §4.7.
package ratelimit

import (
	"context"
	"time"
)

// Limiter is the interface implemented by every rate-limit backend.
type Limiter interface {
	// Allow returns true if the request fits within the configured per-minute
	// and per-hour windows for key. retryAfter is non-zero only when Allow
	// returns false.
	Allow(ctx context.Context, key string, perMinute, perHour int32) (allowed bool, retryAfter time.Duration)
}

// NoLimit is a Limiter that always allows; used when a policy declares
// no rate limits.
var NoLimit Limiter = noLimit{}

type noLimit struct{}

func (noLimit) Allow(_ context.Context, _ string, _, _ int32) (bool, time.Duration) {
	return true, 0
}
