package ratelimit

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

// Config selects and configures a Limiter from command-line flags. It is
// shared by every mode that sends mail (api, smtp) so they share one budget.
type Config struct {
	Backend        string
	RedisAddrs     string
	RedisMaster    string
	RedisDB        int
	RedisTLS       bool
	RedisKeyPrefix string
	FailOpen       bool
}

// BindFlags registers the rate-limit flags on fs. The Redis password is read
// from SIGILLUM_REDIS_PASSWORD, never from a flag, so it stays out of argv.
func (c *Config) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Backend, "ratelimit-backend", "memory", "rate-limit state store: memory (single replica only) or redis")
	fs.StringVar(&c.RedisAddrs, "redis-addrs", "", "comma-separated Redis addresses (host:port); several addresses mean Cluster, or Sentinel with --redis-master")
	fs.StringVar(&c.RedisMaster, "redis-master", "", "Sentinel master name (enables Sentinel mode)")
	fs.IntVar(&c.RedisDB, "redis-db", 0, "Redis database number (ignored in Cluster mode)")
	fs.BoolVar(&c.RedisTLS, "redis-tls", false, "connect to Redis over TLS")
	fs.StringVar(&c.RedisKeyPrefix, "redis-key-prefix", "sigillum:rl:", "prefix for rate-limit keys in Redis")
	fs.BoolVar(&c.FailOpen, "ratelimit-fail-open", false, "admit requests when Redis is unreachable (default: reject with 503)")
}

// Build constructs the configured Limiter.
func (c *Config) Build(logger *slog.Logger) (Limiter, error) {
	switch c.Backend {
	case "", "memory":
		return NewMemoryLimiter(), nil
	case "redis":
		if c.RedisAddrs == "" {
			return nil, fmt.Errorf("--redis-addrs is required with --ratelimit-backend=redis")
		}
		opts := &redis.UniversalOptions{
			Addrs:      strings.Split(c.RedisAddrs, ","),
			MasterName: c.RedisMaster,
			DB:         c.RedisDB,
			Password:   os.Getenv("SIGILLUM_REDIS_PASSWORD"),
			Username:   os.Getenv("SIGILLUM_REDIS_USERNAME"),
		}
		if c.RedisTLS {
			opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return NewRedisLimiter(RedisOptions{
			Client:   redis.NewUniversalClient(opts),
			Prefix:   c.RedisKeyPrefix,
			FailOpen: c.FailOpen,
			Logger:   logger,
		}), nil
	default:
		return nil, fmt.Errorf("unknown --ratelimit-backend %q (want memory or redis)", c.Backend)
	}
}
