package cache

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

func TestNewRedisCache(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix:  "test:cache:",
		DefaultTTL: 5 * time.Minute,
	})

	if cache.keyPrefix != "test:cache:" {
		t.Errorf("expected key prefix 'test:cache:', got '%s'", cache.keyPrefix)
	}
	if cache.defaultTTL != 5*time.Minute {
		t.Errorf("expected default TTL 5m, got %v", cache.defaultTTL)
	}
}

func TestNewRedisCache_Defaults(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	cache := NewRedisCacheWithClient(client, RedisConfig{})

	if cache.keyPrefix != "loom:cache:" {
		t.Errorf("expected default key prefix 'loom:cache:', got '%s'", cache.keyPrefix)
	}
	if cache.defaultTTL != 5*time.Minute {
		t.Errorf("expected default TTL 5m, got %v", cache.defaultTTL)
	}
}

func TestRedisCache_SetAndGet(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix:  "test:setget:",
		DefaultTTL: time.Minute,
	})

	// Clean up after test
	defer func() {
		keys, _ := client.Keys(ctx, "test:setget:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	entry := &Entry{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:      []byte(`{"message": "hello"}`),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	// Set entry
	err := cache.Set(ctx, "testkey", entry)
	if err != nil {
		t.Fatalf("failed to set entry: %v", err)
	}

	// Get entry
	retrieved, found := cache.Get(ctx, "testkey")
	if !found {
		t.Fatal("expected to find entry")
	}

	if retrieved.StatusCode != entry.StatusCode {
		t.Errorf("expected status %d, got %d", entry.StatusCode, retrieved.StatusCode)
	}
	if string(retrieved.Body) != string(entry.Body) {
		t.Errorf("expected body %s, got %s", entry.Body, retrieved.Body)
	}
	if retrieved.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type header 'application/json', got '%s'", retrieved.Headers.Get("Content-Type"))
	}
}

func TestRedisCache_GetMiss(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:miss:",
	})

	_, found := cache.Get(ctx, "nonexistent")
	if found {
		t.Error("expected cache miss for nonexistent key")
	}

	stats := cache.GetStats()
	if stats.Misses == 0 {
		t.Error("expected misses to be incremented")
	}
}

func TestRedisCache_Expiration(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix:            "test:expire:",
		DefaultTTL:           50 * time.Millisecond,
		StaleWhileRevalidate: 50 * time.Millisecond,
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:expire:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	entry := &Entry{
		StatusCode: http.StatusOK,
		Body:       []byte("test"),
	}

	err := cache.Set(ctx, "expiring", entry)
	if err != nil {
		t.Fatalf("failed to set entry: %v", err)
	}

	// Should be found immediately
	_, found := cache.Get(ctx, "expiring")
	if !found {
		t.Error("expected to find entry immediately after set")
	}

	// Wait for logical expiration
	time.Sleep(60 * time.Millisecond)

	// Should not be found (logically expired)
	_, found = cache.Get(ctx, "expiring")
	if found {
		t.Error("expected entry to be expired")
	}
}

func TestRedisCache_StaleWhileRevalidate(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix:            "test:stale:",
		DefaultTTL:           50 * time.Millisecond,
		StaleWhileRevalidate: 100 * time.Millisecond,
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:stale:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	entry := &Entry{
		StatusCode: http.StatusOK,
		Body:       []byte("stale test"),
	}

	err := cache.Set(ctx, "stalekey", entry)
	if err != nil {
		t.Fatalf("failed to set entry: %v", err)
	}

	// Wait for logical expiration but within stale window
	time.Sleep(60 * time.Millisecond)

	// Should get stale entry
	retrieved, found, isStale := cache.GetWithStale(ctx, "stalekey")
	if !found {
		t.Error("expected to find stale entry")
	}
	if !isStale {
		t.Error("expected entry to be marked as stale")
	}
	if string(retrieved.Body) != "stale test" {
		t.Errorf("expected body 'stale test', got '%s'", retrieved.Body)
	}

	stats := cache.GetStats()
	if stats.StaleHits == 0 {
		t.Error("expected stale hits to be incremented")
	}
}

func TestRedisCache_Delete(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:delete:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:delete:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	entry := &Entry{
		StatusCode: http.StatusOK,
		Body:       []byte("to be deleted"),
	}

	cache.Set(ctx, "deletekey", entry)

	// Verify it exists
	_, found := cache.Get(ctx, "deletekey")
	if !found {
		t.Fatal("expected entry to exist before delete")
	}

	// Delete
	err := cache.Delete(ctx, "deletekey")
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Verify it's gone
	_, found = cache.Get(ctx, "deletekey")
	if found {
		t.Error("expected entry to be deleted")
	}
}

func TestRedisCache_Purge(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:purge:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:purge:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	// Set multiple entries
	for i := 0; i < 5; i++ {
		cache.Set(ctx, "api/users/"+string(rune('0'+i)), &Entry{
			StatusCode: http.StatusOK,
			Body:       []byte("user"),
		})
	}
	cache.Set(ctx, "api/products/1", &Entry{
		StatusCode: http.StatusOK,
		Body:       []byte("product"),
	})

	// Purge users
	deleted, err := cache.Purge(ctx, "api/users/")
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	if deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", deleted)
	}

	// Products should still exist
	_, found := cache.Get(ctx, "api/products/1")
	if !found {
		t.Error("expected products to still exist after purge")
	}
}

func TestRedisCache_Clear(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:clear:",
	})

	// Set entries
	for i := 0; i < 3; i++ {
		cache.Set(ctx, "key"+string(rune('0'+i)), &Entry{
			StatusCode: http.StatusOK,
			Body:       []byte("data"),
		})
	}

	// Clear all
	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("clear failed: %v", err)
	}

	// Verify all gone
	for i := 0; i < 3; i++ {
		_, found := cache.Get(ctx, "key"+string(rune('0'+i)))
		if found {
			t.Errorf("expected key%d to be cleared", i)
		}
	}
}

func TestRedisCache_Exists(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:exists:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:exists:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	// Should not exist
	exists, err := cache.Exists(ctx, "mykey")
	if err != nil {
		t.Fatalf("exists check failed: %v", err)
	}
	if exists {
		t.Error("expected key to not exist")
	}

	// Set and check again
	cache.Set(ctx, "mykey", &Entry{StatusCode: http.StatusOK, Body: []byte("test")})

	exists, err = cache.Exists(ctx, "mykey")
	if err != nil {
		t.Fatalf("exists check failed: %v", err)
	}
	if !exists {
		t.Error("expected key to exist")
	}
}

func TestRedisCache_GetMulti(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:multi:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:multi:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	// Set multiple entries
	for i := 0; i < 3; i++ {
		cache.Set(ctx, "key"+string(rune('0'+i)), &Entry{
			StatusCode: http.StatusOK,
			Body:       []byte("data" + string(rune('0'+i))),
		})
	}

	// Get multiple
	results, err := cache.GetMulti(ctx, []string{"key0", "key1", "key2", "missing"})
	if err != nil {
		t.Fatalf("getmulti failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	for i := 0; i < 3; i++ {
		key := "key" + string(rune('0'+i))
		if _, ok := results[key]; !ok {
			t.Errorf("expected %s in results", key)
		}
	}

	if _, ok := results["missing"]; ok {
		t.Error("did not expect 'missing' in results")
	}
}

func TestRedisCache_SetMulti(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:setmulti:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:setmulti:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	entries := map[string]*Entry{
		"a": {StatusCode: http.StatusOK, Body: []byte("a")},
		"b": {StatusCode: http.StatusOK, Body: []byte("b")},
		"c": {StatusCode: http.StatusOK, Body: []byte("c")},
	}

	err := cache.SetMulti(ctx, entries)
	if err != nil {
		t.Fatalf("setmulti failed: %v", err)
	}

	// Verify all exist
	for key := range entries {
		_, found := cache.Get(ctx, key)
		if !found {
			t.Errorf("expected %s to exist", key)
		}
	}
}

func TestRedisCache_DeleteMulti(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:delmulti:",
	})

	// Set entries
	for i := 0; i < 3; i++ {
		cache.Set(ctx, "key"+string(rune('0'+i)), &Entry{
			StatusCode: http.StatusOK,
			Body:       []byte("data"),
		})
	}

	// Delete multiple
	err := cache.DeleteMulti(ctx, []string{"key0", "key1"})
	if err != nil {
		t.Fatalf("deletemulti failed: %v", err)
	}

	// Verify deleted
	_, found := cache.Get(ctx, "key0")
	if found {
		t.Error("expected key0 to be deleted")
	}
	_, found = cache.Get(ctx, "key1")
	if found {
		t.Error("expected key1 to be deleted")
	}

	// key2 should still exist
	_, found = cache.Get(ctx, "key2")
	if !found {
		t.Error("expected key2 to still exist")
	}

	// Cleanup
	cache.Delete(ctx, "key2")
}

func TestRedisCache_Info(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:info:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:info:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	// Set some entries
	for i := 0; i < 5; i++ {
		cache.Set(ctx, "key"+string(rune('0'+i)), &Entry{
			StatusCode: http.StatusOK,
			Body:       []byte("data for info test"),
		})
	}

	info, err := cache.Info(ctx)
	if err != nil {
		t.Fatalf("info failed: %v", err)
	}

	if info.KeyCount != 5 {
		t.Errorf("expected 5 keys, got %d", info.KeyCount)
	}
	if info.KeyPrefix != "test:info:" {
		t.Errorf("expected key prefix 'test:info:', got '%s'", info.KeyPrefix)
	}
}

func TestRedisCache_FallbackOnError(t *testing.T) {
	// Create client with invalid address
	client := redis.NewClient(&redis.Options{
		Addr: "invalid:6379",
	})
	defer client.Close()

	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix:       "test:fallback:",
		FallbackOnError: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Get should return not found (not error)
	_, found := cache.Get(ctx, "key")
	if found {
		t.Error("expected not found with fallback")
	}

	// Set should not error
	err := cache.Set(ctx, "key", &Entry{StatusCode: http.StatusOK, Body: []byte("test")})
	if err != nil {
		t.Errorf("expected no error with fallback, got: %v", err)
	}

	// Stats should show errors
	stats := cache.GetStats()
	if stats.Errors == 0 {
		t.Error("expected errors to be counted")
	}
}

func TestRedisCacheMiddleware(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:middleware:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:middleware:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"count": ` + string(rune('0'+callCount)) + `}`))
	})

	middleware := RedisCacheMiddleware(cache, RedisCacheMiddlewareConfig{
		DefaultTTL:   time.Minute,
		BypassHeader: "X-Cache-Bypass",
	})

	wrapped := middleware(handler)

	// First request - cache miss
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)

	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS, got %s", rec1.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("expected handler called once, got %d", callCount)
	}

	// Second request - cache hit
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)

	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT, got %s", rec2.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("expected handler still called once, got %d", callCount)
	}

	// Request with bypass
	req3 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req3.Header.Set("X-Cache-Bypass", "true")
	rec3 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec3, req3)

	if callCount != 2 {
		t.Errorf("expected handler called twice after bypass, got %d", callCount)
	}
}

func TestRedisCacheMiddleware_ExcludedPaths(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:excluded:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:excluded:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
	})

	middleware := RedisCacheMiddleware(cache, RedisCacheMiddlewareConfig{
		DefaultTTL:    time.Minute,
		ExcludedPaths: []string{"/api/auth/*", "/health"},
	})

	wrapped := middleware(handler)

	// Excluded path - should not cache
	req1 := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)

	if callCount != 2 {
		t.Errorf("expected handler called twice for excluded path, got %d", callCount)
	}
}

func TestRedisCacheMiddleware_POSTNotCached(t *testing.T) {
	client := getTestRedisClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	cache := NewRedisCacheWithClient(client, RedisConfig{
		KeyPrefix: "test:post:",
	})

	defer func() {
		keys, _ := client.Keys(ctx, "test:post:*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	}()

	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	middleware := RedisCacheMiddleware(cache, RedisCacheMiddlewareConfig{
		DefaultTTL: time.Minute,
	})

	wrapped := middleware(handler)

	// POST should not be cached
	req1 := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)

	if callCount != 2 {
		t.Errorf("expected POST not cached, handler called %d times", callCount)
	}
}

func TestNewRedisCache_InvalidAddress(t *testing.T) {
	_, err := NewRedisCache(RedisConfig{
		Address: "",
	})
	if err == nil {
		t.Error("expected error for empty address")
	}
}

func TestNewRedisCache_ConnectionFailed(t *testing.T) {
	_, err := NewRedisCache(RedisConfig{
		Address: "invalid-host:6379",
	})
	if err == nil {
		t.Error("expected error for invalid connection")
	}
}
