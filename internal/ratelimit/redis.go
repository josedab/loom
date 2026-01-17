// Package ratelimit provides distributed rate limiting using Redis.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Common errors.
var (
	ErrRateLimited    = errors.New("rate limit exceeded")
	ErrRedisUnavailable = errors.New("redis unavailable")
)

// RedisConfig configures the Redis-backed rate limiter.
type RedisConfig struct {
	// Redis client options
	Address  string // Redis server address (e.g., "localhost:6379")
	Password string // Redis password (optional)
	DB       int    // Redis database number

	// Rate limiting options
	Rate  float64 // Requests per second
	Burst int     // Maximum burst size

	// KeyPrefix for rate limit keys (default: "loom:ratelimit:")
	KeyPrefix string

	// KeyFunc extracts the rate limit key from a request
	KeyFunc func(*http.Request) string

	// Window for sliding window rate limiting (default: 1 second)
	Window time.Duration

	// FallbackOnError if true, allows requests when Redis is unavailable
	FallbackOnError bool
}

// RedisRateLimiter implements distributed rate limiting using Redis.
type RedisRateLimiter struct {
	client          *redis.Client
	rate            float64
	burst           int
	keyPrefix       string
	keyFunc         func(*http.Request) string
	window          time.Duration
	fallbackOnError bool
}

// NewRedisRateLimiter creates a new Redis-backed rate limiter.
func NewRedisRateLimiter(cfg RedisConfig) (*RedisRateLimiter, error) {
	if cfg.Address == "" {
		return nil, errors.New("redis address is required")
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 100 // Default: 100 requests per second
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.Rate)
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "loom:ratelimit:"
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultKeyFunc
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &RedisRateLimiter{
		client:          client,
		rate:            cfg.Rate,
		burst:           cfg.Burst,
		keyPrefix:       cfg.KeyPrefix,
		keyFunc:         cfg.KeyFunc,
		window:          cfg.Window,
		fallbackOnError: cfg.FallbackOnError,
	}, nil
}

// NewRedisRateLimiterWithClient creates a rate limiter with an existing Redis client.
func NewRedisRateLimiterWithClient(client *redis.Client, cfg RedisConfig) *RedisRateLimiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 100
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.Rate)
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "loom:ratelimit:"
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultKeyFunc
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Second
	}

	return &RedisRateLimiter{
		client:          client,
		rate:            cfg.Rate,
		burst:           cfg.Burst,
		keyPrefix:       cfg.KeyPrefix,
		keyFunc:         cfg.KeyFunc,
		window:          cfg.Window,
		fallbackOnError: cfg.FallbackOnError,
	}
}

// slidingWindowScript is a Lua script for atomic sliding window rate limiting.
// It implements a sliding window log algorithm.
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

-- Remove old entries outside the window
local window_start = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current requests in window
local current = redis.call('ZCARD', key)

if current < limit then
    -- Add the new request
    redis.call('ZADD', key, now, now .. ':' .. math.random())
    redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)
    return {1, limit - current - 1, 0}
else
    -- Get the oldest entry to calculate retry time
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 0
    if #oldest >= 2 then
        retry_after = math.ceil((oldest[2] + window - now) / 1000)
        if retry_after < 0 then retry_after = 0 end
    end
    return {0, 0, retry_after}
end
`)

// tokenBucketScript is a Lua script for atomic token bucket rate limiting.
var tokenBucketScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])

-- Get current bucket state
local bucket = redis.call('HMGET', key, 'tokens', 'last_update')
local tokens = tonumber(bucket[1]) or burst
local last_update = tonumber(bucket[2]) or now

-- Calculate tokens to add based on elapsed time
local elapsed = (now - last_update) / 1000000000  -- Convert nanoseconds to seconds
local new_tokens = tokens + (elapsed * rate)
if new_tokens > burst then
    new_tokens = burst
end

-- Try to consume a token
if new_tokens >= 1 then
    new_tokens = new_tokens - 1
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_update', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 10)
    return {1, math.floor(new_tokens), 0}
else
    -- Calculate time until next token
    local wait_time = (1 - new_tokens) / rate
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_update', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 10)
    return {0, 0, math.ceil(wait_time)}
end
`)

// Allow checks if a request is allowed using the token bucket algorithm.
func (rl *RedisRateLimiter) Allow(ctx context.Context, key string) (*RateLimitResult, error) {
	fullKey := rl.keyPrefix + key
	now := time.Now().UnixNano()

	result, err := tokenBucketScript.Run(ctx, rl.client, []string{fullKey},
		now, rl.rate, rl.burst).Slice()

	if err != nil {
		if rl.fallbackOnError {
			return &RateLimitResult{
				Allowed:   true,
				Remaining: rl.burst,
			}, nil
		}
		return nil, fmt.Errorf("redis error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	retryAfter := int(result[2].(int64))

	return &RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		Limit:      rl.burst,
		RetryAfter: time.Duration(retryAfter) * time.Second,
	}, nil
}

// AllowSlidingWindow checks if a request is allowed using the sliding window algorithm.
func (rl *RedisRateLimiter) AllowSlidingWindow(ctx context.Context, key string) (*RateLimitResult, error) {
	fullKey := rl.keyPrefix + "sw:" + key
	now := time.Now().UnixMilli()
	windowMs := rl.window.Milliseconds()
	limit := int64(float64(rl.burst) * rl.window.Seconds())

	result, err := slidingWindowScript.Run(ctx, rl.client, []string{fullKey},
		now, windowMs, limit).Slice()

	if err != nil {
		if rl.fallbackOnError {
			return &RateLimitResult{
				Allowed:   true,
				Remaining: int(limit),
			}, nil
		}
		return nil, fmt.Errorf("redis error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	retryAfter := int(result[2].(int64))

	return &RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		Limit:      int(limit),
		RetryAfter: time.Duration(retryAfter) * time.Second,
	}, nil
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	Limit      int
	RetryAfter time.Duration
}

// Middleware returns an HTTP middleware for rate limiting.
func (rl *RedisRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFunc(r)

			result, err := rl.Allow(r.Context(), key)
			if err != nil {
				// If fallback is disabled, this is already an error
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Close closes the Redis connection.
func (rl *RedisRateLimiter) Close() error {
	return rl.client.Close()
}

// Stats returns rate limiter statistics.
func (rl *RedisRateLimiter) Stats(ctx context.Context) (*RedisRateLimiterStats, error) {
	// Get all rate limit keys
	pattern := rl.keyPrefix + "*"
	keys, err := rl.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}

	return &RedisRateLimiterStats{
		ActiveKeys: len(keys),
		Rate:       rl.rate,
		Burst:      rl.burst,
		KeyPrefix:  rl.keyPrefix,
	}, nil
}

// RedisRateLimiterStats contains statistics about the rate limiter.
type RedisRateLimiterStats struct {
	ActiveKeys int
	Rate       float64
	Burst      int
	KeyPrefix  string
}

// DefaultKeyFunc extracts the client IP as the rate limit key.
func DefaultKeyFunc(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr (strip port if present)
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		// Check if this is an IPv6 address
		if strings.Count(addr, ":") > 1 {
			// IPv6 with port: [::1]:8080
			if strings.HasPrefix(addr, "[") {
				if bracketIdx := strings.Index(addr, "]:"); bracketIdx > 0 {
					return addr[1:bracketIdx]
				}
			}
			// IPv6 without port
			return addr
		}
		return addr[:idx]
	}
	return addr
}

// FixedWindowRateLimiter implements fixed window rate limiting with Redis.
type FixedWindowRateLimiter struct {
	client    *redis.Client
	limit     int
	window    time.Duration
	keyPrefix string
	keyFunc   func(*http.Request) string
	fallback  bool
}

// FixedWindowConfig configures the fixed window rate limiter.
type FixedWindowConfig struct {
	Address   string
	Password  string
	DB        int
	Limit     int           // Maximum requests per window
	Window    time.Duration // Window duration
	KeyPrefix string
	KeyFunc   func(*http.Request) string
	Fallback  bool
}

// NewFixedWindowRateLimiter creates a fixed window rate limiter.
func NewFixedWindowRateLimiter(cfg FixedWindowConfig) (*FixedWindowRateLimiter, error) {
	if cfg.Address == "" {
		return nil, errors.New("redis address is required")
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 100
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "loom:fixedwindow:"
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultKeyFunc
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &FixedWindowRateLimiter{
		client:    client,
		limit:     cfg.Limit,
		window:    cfg.Window,
		keyPrefix: cfg.KeyPrefix,
		keyFunc:   cfg.KeyFunc,
		fallback:  cfg.Fallback,
	}, nil
}

// fixedWindowScript is a Lua script for atomic fixed window rate limiting.
var fixedWindowScript = redis.NewScript(`
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end

if current <= limit then
    return {1, limit - current, 0}
else
    local ttl = redis.call('TTL', key)
    return {0, 0, ttl}
end
`)

// Allow checks if a request is allowed.
func (rl *FixedWindowRateLimiter) Allow(ctx context.Context, key string) (*RateLimitResult, error) {
	// Create time-based window key
	windowKey := time.Now().Truncate(rl.window).Unix()
	fullKey := fmt.Sprintf("%s%s:%d", rl.keyPrefix, key, windowKey)
	windowSecs := int(rl.window.Seconds())

	result, err := fixedWindowScript.Run(ctx, rl.client, []string{fullKey},
		rl.limit, windowSecs).Slice()

	if err != nil {
		if rl.fallback {
			return &RateLimitResult{
				Allowed:   true,
				Remaining: rl.limit,
			}, nil
		}
		return nil, fmt.Errorf("redis error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	retryAfter := int(result[2].(int64))

	return &RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		Limit:      rl.limit,
		RetryAfter: time.Duration(retryAfter) * time.Second,
	}, nil
}

// Middleware returns an HTTP middleware for rate limiting.
func (rl *FixedWindowRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFunc(r)

			result, err := rl.Allow(r.Context(), key)
			if err != nil {
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Close closes the Redis connection.
func (rl *FixedWindowRateLimiter) Close() error {
	return rl.client.Close()
}
