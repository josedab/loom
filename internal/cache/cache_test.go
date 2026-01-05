package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	c := New(Config{
		MaxSize:         1024 * 1024,
		DefaultTTL:      time.Minute,
		ShardCount:      16,
		CleanupInterval: time.Hour, // Long interval for tests
	})
	defer c.Close()

	entry := &Entry{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(`{"test": true}`),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Minute),
		ETag:       "test-etag",
	}

	// Test Set and Get
	c.Set("test-key", entry)

	got, found := c.Get("test-key")
	if !found {
		t.Fatal("expected to find entry")
	}
	if got.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", got.StatusCode)
	}
	if string(got.Body) != `{"test": true}` {
		t.Errorf("unexpected body: %s", got.Body)
	}

	// Test miss
	_, found = c.Get("nonexistent")
	if found {
		t.Error("expected not to find nonexistent key")
	}

	// Test Delete
	c.Delete("test-key")
	_, found = c.Get("test-key")
	if found {
		t.Error("expected entry to be deleted")
	}
}

func TestCacheExpiration(t *testing.T) {
	c := New(Config{
		MaxSize:         1024 * 1024,
		DefaultTTL:      50 * time.Millisecond,
		ShardCount:      16,
		CleanupInterval: time.Hour,
	})
	defer c.Close()

	entry := &Entry{
		StatusCode: 200,
		Body:       []byte("test"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(50 * time.Millisecond),
	}

	c.Set("expiring-key", entry)

	// Should be found immediately
	_, found := c.Get("expiring-key")
	if !found {
		t.Fatal("expected to find entry")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should not be found after expiration
	_, found = c.Get("expiring-key")
	if found {
		t.Error("expected entry to be expired")
	}
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	c := New(Config{
		MaxSize:         1024 * 1024,
		DefaultTTL:      50 * time.Millisecond,
		ShardCount:      16,
		CleanupInterval: time.Hour,
	})
	defer c.Close()

	entry := &Entry{
		StatusCode: 200,
		Body:       []byte("test"),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(50 * time.Millisecond),
	}

	c.Set("stale-key", entry)

	// Wait for expiration but within stale window
	time.Sleep(75 * time.Millisecond)

	// Should get stale entry
	got, found, isStale := c.GetWithStale("stale-key", time.Second)
	if !found {
		t.Fatal("expected to find stale entry")
	}
	if !isStale {
		t.Error("expected entry to be marked as stale")
	}
	if string(got.Body) != "test" {
		t.Errorf("unexpected body: %s", got.Body)
	}
}

func TestCachePurge(t *testing.T) {
	c := New(Config{
		MaxSize:    1024 * 1024,
		DefaultTTL: time.Minute,
		ShardCount: 16,
	})
	defer c.Close()

	// Add entries with different prefixes
	for _, key := range []string{"/api/users/1", "/api/users/2", "/api/posts/1", "/other/data"} {
		c.Set(key, &Entry{
			Body:      []byte("test"),
			ExpiresAt: time.Now().Add(time.Minute),
		})
	}

	// Purge /api/users/* entries
	count := c.Purge("/api/users/")
	if count != 2 {
		t.Errorf("expected to purge 2 entries, got %d", count)
	}

	// Verify purged entries are gone
	_, found := c.Get("/api/users/1")
	if found {
		t.Error("expected /api/users/1 to be purged")
	}

	// Verify other entries remain
	_, found = c.Get("/api/posts/1")
	if !found {
		t.Error("expected /api/posts/1 to remain")
	}
}

func TestCacheStats(t *testing.T) {
	c := New(Config{
		MaxSize:    1024 * 1024,
		DefaultTTL: time.Minute,
		ShardCount: 16,
	})
	defer c.Close()

	entry := &Entry{
		Body:      []byte("test"),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	c.Set("stats-key", entry)

	// Generate hits and misses
	c.Get("stats-key")
	c.Get("stats-key")
	c.Get("nonexistent")

	stats := c.GetStats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestBuildCacheKey(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		host        string
		path        string
		query       string
		varyHeaders []string
		want        string
	}{
		{
			name:   "simple GET",
			method: "GET",
			host:   "example.com",
			path:   "/api/users",
			want:   "GET:example.com/api/users",
		},
		{
			name:   "with query",
			method: "GET",
			host:   "example.com",
			path:   "/api/users",
			query:  "page=1&limit=10",
			want:   "GET:example.com/api/users?page=1&limit=10",
		},
		{
			name:        "with vary headers",
			method:      "GET",
			host:        "example.com",
			path:        "/api/users",
			varyHeaders: []string{"Accept-Language"},
			want:        "GET:example.com/api/users|Accept-Language=;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://"+tt.host+tt.path+"?"+tt.query, nil)
			req.Host = tt.host

			got := BuildCacheKey(req, tt.varyHeaders)
			if got != tt.want {
				t.Errorf("BuildCacheKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		header string
		want   map[string]string
	}{
		{
			header: "max-age=3600",
			want:   map[string]string{"max-age": "3600"},
		},
		{
			header: "max-age=3600, s-maxage=7200, public",
			want:   map[string]string{"max-age": "3600", "s-maxage": "7200", "public": ""},
		},
		{
			header: "no-store, no-cache",
			want:   map[string]string{"no-store": "", "no-cache": ""},
		},
		{
			header: "private, max-age=0",
			want:   map[string]string{"private": "", "max-age": "0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := ParseCacheControl(tt.header)
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("ParseCacheControl(%q)[%q] = %q, want %q", tt.header, k, got[k], v)
				}
			}
		})
	}
}

func TestIsCacheable(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "GET 200 OK",
			method:     "GET",
			statusCode: 200,
			headers:    http.Header{},
			want:       true,
		},
		{
			name:       "POST not cacheable",
			method:     "POST",
			statusCode: 200,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "no-store",
			method:     "GET",
			statusCode: 200,
			headers:    http.Header{"Cache-Control": []string{"no-store"}},
			want:       false,
		},
		{
			name:       "private",
			method:     "GET",
			statusCode: 200,
			headers:    http.Header{"Cache-Control": []string{"private"}},
			want:       false,
		},
		{
			name:       "500 error",
			method:     "GET",
			statusCode: 500,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "404 is cacheable",
			method:     "GET",
			statusCode: 404,
			headers:    http.Header{},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			got := IsCacheable(req, tt.statusCode, tt.headers)
			if got != tt.want {
				t.Errorf("IsCacheable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTTL(t *testing.T) {
	defaultTTL := 5 * time.Minute

	tests := []struct {
		name    string
		headers http.Header
		want    time.Duration
	}{
		{
			name:    "max-age",
			headers: http.Header{"Cache-Control": []string{"max-age=3600"}},
			want:    time.Hour,
		},
		{
			name:    "s-maxage takes precedence",
			headers: http.Header{"Cache-Control": []string{"max-age=3600, s-maxage=7200"}},
			want:    2 * time.Hour,
		},
		{
			name:    "default when empty",
			headers: http.Header{},
			want:    defaultTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTTL(tt.headers, defaultTTL)
			if got != tt.want {
				t.Errorf("GetTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCacheMiddleware(t *testing.T) {
	c := New(DefaultConfig())
	defer c.Close()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "test"}`))
	})

	handler := Middleware(MiddlewareConfig{
		Cache:      c,
		DefaultTTL: time.Hour,
	})(backend)

	// First request - should hit backend
	req1 := httptest.NewRequest("GET", "/api/test", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS, got %s", rec1.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("expected 1 backend call, got %d", callCount)
	}

	// Second request - should hit cache
	req2 := httptest.NewRequest("GET", "/api/test", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT, got %s", rec2.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("expected still 1 backend call, got %d", callCount)
	}
}

func TestCacheMiddlewareBypass(t *testing.T) {
	c := New(DefaultConfig())
	defer c.Close()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Cache:        c,
		BypassHeader: "X-Cache-Bypass",
	})(backend)

	// First request with bypass header
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Cache-Bypass", "true")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Cache") != "BYPASS" {
		t.Errorf("expected X-Cache: BYPASS, got %s", rec.Header().Get("X-Cache"))
	}
}

func TestCacheMiddlewarePostNotCached(t *testing.T) {
	c := New(DefaultConfig())
	defer c.Close()

	callCount := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{Cache: c})(backend)

	// POST request should not be cached
	req := httptest.NewRequest("POST", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Second POST should still hit backend
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/test", nil))

	if callCount != 2 {
		t.Errorf("expected 2 backend calls for POST, got %d", callCount)
	}
}
