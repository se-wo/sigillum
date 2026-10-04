package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// slidingWindow atomically trims, counts and (if within limits) records one
// hit in a sorted set scored by millisecond timestamps. It reads the clock
// from Redis TIME so replicas with skewed clocks still agree on the window.
//
// KEYS[1] = counter key
// ARGV[1] = perMinute (0 = no cap)
// ARGV[2] = perHour   (0 = no cap)
// ARGV[3] = perDay    (0 = no cap)
// ARGV[4] = unique member for this hit
//
// Returns {1, 0} when allowed, {0, retryAfterMs} when rejected, where
// retryAfterMs is the wait until every full window has room again.
var slidingWindow = redis.NewScript(`
-- Redis < 5 replicates scripts verbatim and refuses writes after the
-- non-deterministic TIME; effects replication fixes that. Redis >= 5 does
-- this by default (and 7.0 turned the call into a no-op).
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local windows = {
  {tonumber(ARGV[1]), 60000},
  {tonumber(ARGV[2]), 3600000},
  {tonumber(ARGV[3]), 86400000},
}
-- Keep hits for the longest capped window: a day only with a daily cap.
local keep = 3600000
if windows[3][1] > 0 then keep = 86400000 end

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - keep)

-- A hit leaves a window the moment it is as old as the window, hence the
-- exclusive lower bound: a caller retrying exactly after Retry-After finds
-- room.
local retry = -1
for _, w in ipairs(windows) do
  local limit, size = w[1], w[2]
  if limit > 0 then
    local from = string.format('(%d', now - size)
    local n = redis.call('ZCOUNT', KEYS[1], from, '+inf')
    if n >= limit then
      -- The window has room again once its hit at rank n - limit has left.
      local hit = redis.call('ZRANGEBYSCORE', KEYS[1], from, '+inf', 'WITHSCORES', 'LIMIT', n - limit, 1)
      local wait = tonumber(hit[2]) + size - now
      if wait > retry then retry = wait end
    end
  end
end
if retry >= 0 then
  return {0, retry}
end

redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], keep)
return {1, 0}
`)

// RedisLimiter is a sliding-window limiter shared by all api-server and
// SMTP-proxy replicas.
type RedisLimiter struct {
	client redis.UniversalClient
	prefix string
	// FailOpen admits requests while Redis is unreachable. The default
	// (false) rejects them with ErrUnavailable, per SPEC §9.1.
	FailOpen bool
	logger   *slog.Logger
}

// RedisOptions configures NewRedisLimiter.
type RedisOptions struct {
	// Client is any go-redis client (single node, Sentinel or Cluster).
	Client   redis.UniversalClient
	Prefix   string
	FailOpen bool
	Logger   *slog.Logger
}

// NewRedisLimiter builds a RedisLimiter from opts.
func NewRedisLimiter(opts RedisOptions) *RedisLimiter {
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "sigillum:rl:"
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisLimiter{client: opts.Client, prefix: prefix, FailOpen: opts.FailOpen, logger: logger}
}

// Allow implements Limiter.
func (l *RedisLimiter) Allow(ctx context.Context, key string, limits Limits) (bool, time.Duration, error) {
	if limits.None() {
		return true, 0, nil
	}
	res, err := slidingWindow.Run(ctx, l.client, []string{l.prefix + key},
		limits.PerMinute, limits.PerHour, limits.PerDay, member()).Int64Slice()
	if err != nil || len(res) != 2 {
		if err == nil {
			err = fmt.Errorf("unexpected script reply %v", res)
		}
		if l.FailOpen {
			l.logger.Warn("rate limiter unavailable, failing open", "key", key, "err", err)
			return true, 0, nil
		}
		return false, 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if res[0] == 1 {
		return true, 0, nil
	}
	return false, ceilToSecond(time.Duration(res[1]) * time.Millisecond), nil
}

// Refund implements Limiter.Refund by removing the newest hit for key.
func (l *RedisLimiter) Refund(ctx context.Context, key string) error {
	return l.client.ZPopMax(ctx, l.prefix+key, 1).Err()
}

// member returns a unique sorted-set member so concurrent hits in the same
// millisecond are all counted.
func member() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
