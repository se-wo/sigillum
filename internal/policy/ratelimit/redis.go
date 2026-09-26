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
// ARGV[3] = unique member for this hit
//
// Returns {1, 0} when allowed, {0, retryAfterMs} when rejected.
var slidingWindow = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local perMinute = tonumber(ARGV[1])
local perHour = tonumber(ARGV[2])

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - 3600000)

if perMinute > 0 then
  local inMinute = redis.call('ZCOUNT', KEYS[1], now - 60000, '+inf')
  if inMinute >= perMinute then
    local oldest = redis.call('ZRANGEBYSCORE', KEYS[1], now - 60000, '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
    return {0, tonumber(oldest[2]) + 60000 - now}
  end
end
if perHour > 0 then
  local inHour = redis.call('ZCARD', KEYS[1])
  if inHour >= perHour then
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    return {0, tonumber(oldest[2]) + 3600000 - now}
  end
end

redis.call('ZADD', KEYS[1], now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], 3600000)
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
func (l *RedisLimiter) Allow(ctx context.Context, key string, perMinute, perHour int32) (bool, time.Duration, error) {
	if perMinute <= 0 && perHour <= 0 {
		return true, 0, nil
	}
	res, err := slidingWindow.Run(ctx, l.client, []string{l.prefix + key}, perMinute, perHour, member()).Int64Slice()
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

// Ping checks connectivity; used by readiness probes.
func (l *RedisLimiter) Ping(ctx context.Context) error {
	return l.client.Ping(ctx).Err()
}

// member returns a unique sorted-set member so concurrent hits in the same
// millisecond are all counted.
func member() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
