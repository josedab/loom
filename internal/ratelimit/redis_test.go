package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// getTestRedisClient returns a Redis client for testing.
// Returns nil if Redis is not available.
func getTestRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
		return nil
	}

	return client
}

func TestDefaultKeyFunc(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			name: "X-Forwarded-For single",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For multiple",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Real-IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "10.0.0.5")
			},
			expectedIP: "10.0.0.5",
		},
		{
			name: "RemoteAddr fallback",
			setupReq: func(r *http.Request) {
				// No headers
			},
			expectedIP: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			ip := DefaultKeyFunc(req)
			if ip != tt.expectedIP {
				t.Errorf("expected %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestRedisRateLimiter_Allow(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	// Clean up test keys
	ctx := context.Background()
	defer client.Del(ctx, "test:ratelimit:testkey")

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      10,
		Burst:     5,
		KeyPrefix: "test:ratelimit:",
	})

	// First 5 requests should be allowed (burst)
	for i := 0; i < 5; i++ {
		result, err := rl.Allow(ctx, "testkey")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be rate limited (need to wait for tokens)
	result, err := rl.Allow(ctx, "testkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("6th request should be rate limited")
	}
	if result.RetryAfter <= 0 {
		t.Error("RetryAfter should be positive")
	}
}

func TestRedisRateLimiter_DifferentKeys(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	defer client.Del(ctx, "test:ratelimit:key1", "test:ratelimit:key2")

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      1,
		Burst:     2,
		KeyPrefix: "test:ratelimit:",
	})

	// Exhaust key1
	rl.Allow(ctx, "key1")
	rl.Allow(ctx, "key1")

	// key1 should be limited
	result1, _ := rl.Allow(ctx, "key1")
	if result1.Allowed {
		t.Error("key1 should be rate limited")
	}

	// key2 should still be allowed
	result2, _ := rl.Allow(ctx, "key2")
	if !result2.Allowed {
		t.Error("key2 should be allowed")
	}
}

func TestRedisRateLimiter_TokenRefill(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	defer client.Del(ctx, "test:ratelimit:refill")

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      10, // 10 tokens per second
		Burst:     2,
		KeyPrefix: "test:ratelimit:",
	})

	// Use all tokens
	rl.Allow(ctx, "refill")
	rl.Allow(ctx, "refill")

	// Should be limited
	result, _ := rl.Allow(ctx, "refill")
	if result.Allowed {
		t.Error("should be rate limited")
	}

	// Wait for token refill (100ms = 1 token at 10/sec)
	time.Sleep(150 * time.Millisecond)

	// Should be allowed now
	result, _ = rl.Allow(ctx, "refill")
	if !result.Allowed {
		t.Error("should be allowed after token refill")
	}
}

func TestRedisRateLimiter_Middleware(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	defer client.Del(ctx, "test:middleware:192.0.2.1")

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      100,
		Burst:     2,
		KeyPrefix: "test:middleware:",
	})

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
		if rec.Header().Get("X-RateLimit-Limit") == "" {
			t.Error("missing X-RateLimit-Limit header")
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRedisRateLimiter_FallbackOnError(t *testing.T) {
	// Create a client with an invalid address
	client := redis.NewClient(&redis.Options{
		Addr: "invalid:6379",
	})
	defer client.Close()

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:            10,
		Burst:           5,
		KeyPrefix:       "test:fallback:",
		FallbackOnError: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should allow request when Redis is unavailable and fallback is enabled
	result, err := rl.Allow(ctx, "testkey")
	if err != nil {
		t.Fatalf("expected no error with fallback, got: %v", err)
	}
	if !result.Allowed {
		t.Error("expected request to be allowed with fallback")
	}
}

func TestFixedWindowRateLimiter_Allow(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	// Clean up after test
	defer func() {
		keys, _ := client.Keys(ctx, "test:fixed:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	rl := &FixedWindowRateLimiter{
		client:    client,
		limit:     3,
		window:    time.Minute,
		keyPrefix: "test:fixed:",
		keyFunc:   DefaultKeyFunc,
	}

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		result, err := rl.Allow(ctx, "testkey")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if result.Limit != 3 {
			t.Errorf("expected limit 3, got %d", result.Limit)
		}
	}

	// 4th request should be rate limited
	result, err := rl.Allow(ctx, "testkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("4th request should be rate limited")
	}
	if result.Remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", result.Remaining)
	}
}

func TestRedisRateLimiter_Stats(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	defer func() {
		keys, _ := client.Keys(ctx, "test:stats:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      10,
		Burst:     5,
		KeyPrefix: "test:stats:",
	})

	// Generate some keys
	rl.Allow(ctx, "key1")
	rl.Allow(ctx, "key2")
	rl.Allow(ctx, "key3")

	stats, err := rl.Stats(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats.ActiveKeys < 3 {
		t.Errorf("expected at least 3 active keys, got %d", stats.ActiveKeys)
	}
	if stats.Rate != 10 {
		t.Errorf("expected rate 10, got %f", stats.Rate)
	}
	if stats.Burst != 5 {
		t.Errorf("expected burst 5, got %d", stats.Burst)
	}
}

func TestRedisRateLimiter_SlidingWindow(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	defer func() {
		keys, _ := client.Keys(ctx, "test:sw:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	rl := NewRedisRateLimiterWithClient(client, RedisConfig{
		Rate:      10,
		Burst:     3, // 3 requests per window
		Window:    time.Second,
		KeyPrefix: "test:",
	})

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		result, err := rl.AllowSlidingWindow(ctx, "swkey")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 4th request should be rate limited
	result, err := rl.AllowSlidingWindow(ctx, "swkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("4th request should be rate limited")
	}
}

func TestNewRedisRateLimiter_InvalidAddress(t *testing.T) {
	_, err := NewRedisRateLimiter(RedisConfig{
		Address: "",
	})
	if err == nil {
		t.Error("expected error for empty address")
	}
}

func TestNewRedisRateLimiter_ConnectionFailed(t *testing.T) {
	_, err := NewRedisRateLimiter(RedisConfig{
		Address: "invalid-host:6379",
	})
	if err == nil {
		t.Error("expected error for invalid connection")
	}
}
