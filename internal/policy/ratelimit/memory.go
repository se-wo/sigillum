package ratelimit

import (
	"context"
	"sync"
	"time"
)

// MemoryLimiter is a simple sliding-window counter that keeps per-key
// timestamps in memory. Suitable only for single-replica deployments.
type MemoryLimiter struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	now     func() time.Time
	maxKeep time.Duration
}

// NewMemoryLimiter constructs a MemoryLimiter. Timestamps older than one hour
// are dropped lazily on every Allow call.
func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{
		hits:    map[string][]time.Time{},
		now:     time.Now,
		maxKeep: time.Hour,
	}
}

// Allow implements Limiter.Allow with sliding-window semantics. perMinute /
// perHour values of 0 mean "no cap on that window".
func (l *MemoryLimiter) Allow(_ context.Context, key string, perMinute, perHour int32) (bool, time.Duration) {
	if perMinute <= 0 && perHour <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoffHour := now.Add(-time.Hour)
	cutoffMinute := now.Add(-time.Minute)

	hist := l.hits[key]
	// Drop anything older than 1h.
	idx := 0
	for idx < len(hist) && hist[idx].Before(cutoffHour) {
		idx++
	}
	hist = hist[idx:]

	// Count entries in last minute and last hour.
	minuteCount, hourCount := int32(0), int32(len(hist))
	for _, t := range hist {
		if !t.Before(cutoffMinute) {
			minuteCount++
		}
	}

	if perMinute > 0 && minuteCount >= perMinute {
		// retry-after = oldest-in-minute + 1m - now
		oldest := hist[len(hist)-int(minuteCount)]
		retry := time.Until(oldest.Add(time.Minute))
		l.hits[key] = hist
		return false, ceilToSecond(retry)
	}
	if perHour > 0 && hourCount >= perHour {
		oldest := hist[0]
		retry := time.Until(oldest.Add(time.Hour))
		l.hits[key] = hist
		return false, ceilToSecond(retry)
	}

	hist = append(hist, now)
	l.hits[key] = hist
	return true, 0
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
