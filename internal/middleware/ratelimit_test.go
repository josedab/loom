package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  10,
		Burst: 5,
	})
	defer rl.Stop()

	key := "test-client"

	// Should allow burst
	for i := 0; i < 5; i++ {
		if !rl.Allow(key) {
			t.Errorf("request %d should be allowed within burst", i+1)
		}
	}

	// Should deny after burst exhausted
	if rl.Allow(key) {
		t.Error("request should be denied after burst exhausted")
	}
}

func TestRateLimiter_Replenish(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  100, // 100 per second = 1 per 10ms
		Burst: 1,
	})
	defer rl.Stop()

	key := "test-client"

	// Use the token
	if !rl.Allow(key) {
		t.Fatal("first request should be allowed")
	}

	// Should be denied immediately
	if rl.Allow(key) {
		t.Error("should be denied immediately after")
	}

	// Wait for replenishment
	time.Sleep(15 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow(key) {
		t.Error("should be allowed after replenishment")
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  10,
		Burst: 2,
	})
	defer rl.Stop()

	// Exhaust key1
	rl.Allow("key1")
	rl.Allow("key1")
	if rl.Allow("key1") {
		t.Error("key1 should be exhausted")
	}

	// key2 should still work
	if !rl.Allow("key2") {
		t.Error("key2 should be allowed")
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  1000,
		Burst: 100,
	})
	defer rl.Stop()

	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	// Launch concurrent requests
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- rl.Allow("concurrent-key")
		}()
	}

	wg.Wait()
	close(allowed)

	// Count allowed requests
	count := 0
	for a := range allowed {
		if a {
			count++
		}
	}

	// Should have allowed ~100 (burst size)
	if count > 110 || count < 90 {
		t.Errorf("expected ~100 allowed, got %d", count)
	}
}

func TestRateLimiter_Middleware(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  10,
		Burst: 2,
	})
	defer rl.Stop()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got status %d, want 200", i+1, rr.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("got status %d, want 429", rr.Code)
	}

	// Check rate limit headers
	if rr.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRateLimiter_XForwardedFor(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  10,
		Burst: 1,
	})
	defer rl.Stop()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request with X-Forwarded-For
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Same X-Forwarded-For should be rate limited
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.1")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Error("same X-Forwarded-For should be rate limited")
	}

	// Different X-Forwarded-For should work
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("X-Forwarded-For", "10.0.0.2")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusOK {
		t.Error("different X-Forwarded-For should be allowed")
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  50,
		Burst: 10,
	})
	defer rl.Stop()

	// Create some buckets
	rl.Allow("key1")
	rl.Allow("key2")
	rl.Allow("key3")

	stats := rl.Stats()

	if stats.ActiveBuckets != 3 {
		t.Errorf("expected 3 active buckets, got %d", stats.ActiveBuckets)
	}
	if stats.Rate != 50 {
		t.Errorf("expected rate 50, got %f", stats.Rate)
	}
	if stats.Burst != 10 {
		t.Errorf("expected burst 10, got %d", stats.Burst)
	}
}

func TestPerRouteRateLimiter(t *testing.T) {
	prl := NewPerRouteRateLimiter(RateLimiterConfig{
		Rate:  10,
		Burst: 5,
	})
	defer prl.Stop()

	// Set different limits for different routes
	prl.SetRouteLimit("api-v1", 100, 50)
	prl.SetRouteLimit("api-v2", 10, 5)

	// High limit route should allow more
	for i := 0; i < 50; i++ {
		if !prl.Allow("api-v1", "client1") {
			t.Errorf("api-v1 should allow request %d", i+1)
		}
	}

	// Low limit route should block earlier
	for i := 0; i < 5; i++ {
		if !prl.Allow("api-v2", "client1") {
			t.Errorf("api-v2 should allow request %d", i+1)
		}
	}
	if prl.Allow("api-v2", "client1") {
		t.Error("api-v2 should block after burst")
	}
}

func TestDefaultKeyFunc(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		wantKey  string
	}{
		{
			name:     "X-Forwarded-For",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteIP: "192.168.1.1:12345",
			wantKey:  "10.0.0.1",
		},
		{
			name:     "X-Real-IP",
			headers:  map[string]string{"X-Real-IP": "10.0.0.2"},
			remoteIP: "192.168.1.1:12345",
			wantKey:  "10.0.0.2",
		},
		{
			name:     "RemoteAddr fallback",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1:12345",
			wantKey:  "192.168.1.1", // Port is stripped for consistent rate limiting
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteIP
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			key := DefaultKeyFunc(req)
			if key != tt.wantKey {
				t.Errorf("got key %s, want %s", key, tt.wantKey)
			}
		})
	}
}

func BenchmarkRateLimiter_Allow(b *testing.B) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  100000,
		Burst: 10000,
	})
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("benchmark-key")
	}
}

func BenchmarkRateLimiter_AllowConcurrent(b *testing.B) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:  100000,
		Burst: 10000,
	})
	defer rl.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow("benchmark-key")
		}
	})
}
