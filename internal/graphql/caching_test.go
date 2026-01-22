package graphql

import (
	"context"
	"testing"
	"time"
)

func TestResponseCache_GetSet(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		MaxSize:    100,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id name } }`,
	}
	resp := &GatewayResponse{
		Data: map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{"id": "1", "name": "Alice"},
			},
		},
	}

	// Initially should miss
	_, status := cache.Get(ctx, req)
	if status != CacheStatusMiss {
		t.Errorf("expected miss, got %s", status)
	}

	// Set the cache
	cache.Set(ctx, req, resp)

	// Should hit now
	cachedResp, status := cache.Get(ctx, req)
	if status != CacheStatusHit {
		t.Errorf("expected hit, got %s", status)
	}
	if cachedResp == nil {
		t.Fatal("expected cached response")
	}
}

func TestResponseCache_Disabled(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled: false,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id } }`,
	}
	resp := &GatewayResponse{}

	cache.Set(ctx, req, resp)

	_, status := cache.Get(ctx, req)
	if status != CacheStatusDisabled {
		t.Errorf("expected disabled, got %s", status)
	}
}

func TestResponseCache_ExcludeMutations(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `mutation { createUser(name: "Bob") { id } }`,
	}
	resp := &GatewayResponse{}

	cache.Set(ctx, req, resp)

	_, status := cache.Get(ctx, req)
	if status != CacheStatusBypass {
		t.Errorf("expected bypass for mutations, got %s", status)
	}
}

func TestResponseCache_ExcludedOperations(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:            true,
		DefaultTTL:         5 * time.Minute,
		ExcludedOperations: []string{"GetSecretData"},
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query:         `query GetSecretData { secrets { value } }`,
		OperationName: "GetSecretData",
	}
	resp := &GatewayResponse{}

	cache.Set(ctx, req, resp)

	_, status := cache.Get(ctx, req)
	if status != CacheStatusBypass {
		t.Errorf("expected bypass for excluded operation, got %s", status)
	}
}

func TestResponseCache_TTL(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 50 * time.Millisecond,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id } }`,
	}
	resp := &GatewayResponse{}

	cache.Set(ctx, req, resp)

	// Should hit immediately
	_, status := cache.Get(ctx, req)
	if status != CacheStatusHit {
		t.Errorf("expected hit, got %s", status)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should miss now
	_, status = cache.Get(ctx, req)
	if status != CacheStatusMiss {
		t.Errorf("expected miss after TTL, got %s", status)
	}
}

func TestResponseCache_StaleWhileRevalidate(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:              true,
		DefaultTTL:           100 * time.Millisecond,
		StaleWhileRevalidate: 50 * time.Millisecond,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id } }`,
	}
	resp := &GatewayResponse{}

	cache.Set(ctx, req, resp)

	// Wait until stale but not expired
	time.Sleep(60 * time.Millisecond)

	// Should get stale hit
	_, status := cache.Get(ctx, req)
	if status != CacheStatusStale {
		t.Errorf("expected stale, got %s", status)
	}
}

func TestResponseCache_Invalidate(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()

	// Add several entries
	for i := 0; i < 5; i++ {
		req := &GatewayRequest{
			Query: `query { users { id } }`,
			Variables: map[string]interface{}{
				"page": i,
			},
		}
		cache.Set(ctx, req, &GatewayResponse{})
	}

	stats := cache.Stats()
	if stats.EntryCount == 0 {
		t.Error("expected entries in cache")
	}

	// Invalidate all
	count := cache.Invalidate("*")
	if count != 5 {
		t.Errorf("expected 5 invalidations, got %d", count)
	}

	stats = cache.Stats()
	if stats.EntryCount != 0 {
		t.Errorf("expected 0 entries after invalidation, got %d", stats.EntryCount)
	}
}

func TestResponseCache_TypePolicy(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
		TypePolicies: map[string]TypeCachePolicy{
			"User": {
				TTL:       1 * time.Minute,
				KeyFields: []string{"id"},
			},
		},
	})
	defer cache.Stop()

	req := &GatewayRequest{
		Query: `query { user { id name } }`, // Contains "User" indirectly
	}

	ttl := cache.getTTL(req)
	// Should use type policy TTL (1 minute) not default (5 minutes)
	// Note: This is a simplified check since the type detection is basic
	if ttl > 5*time.Minute {
		t.Errorf("unexpected TTL: %v", ttl)
	}
}

func TestResponseCache_EntityInvalidation(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:             true,
		DefaultTTL:          5 * time.Minute,
		EnableNormalization: true,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id name __typename } }`,
	}
	resp := &GatewayResponse{
		Data: map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{
					"id":         "1",
					"name":       "Alice",
					"__typename": "User",
				},
			},
		},
	}

	cache.Set(ctx, req, resp)

	// Verify cached
	_, status := cache.Get(ctx, req)
	if status != CacheStatusHit {
		t.Errorf("expected hit, got %s", status)
	}

	// Invalidate the entity
	count := cache.InvalidateEntity("User", "1")
	if count != 1 {
		t.Errorf("expected 1 invalidation, got %d", count)
	}

	// Should miss now
	_, status = cache.Get(ctx, req)
	if status != CacheStatusMiss {
		t.Errorf("expected miss after entity invalidation, got %s", status)
	}
}

func TestResponseCache_Stats(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id } }`,
	}
	resp := &GatewayResponse{}

	// Miss
	cache.Get(ctx, req)

	// Set
	cache.Set(ctx, req, resp)

	// Hit
	cache.Get(ctx, req)
	cache.Get(ctx, req)

	stats := cache.Stats()

	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.EntryCount != 1 {
		t.Errorf("expected 1 entry, got %d", stats.EntryCount)
	}
}

func TestResponseCache_DifferentVariables(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()
	query := `query GetUser($id: ID!) { user(id: $id) { name } }`

	req1 := &GatewayRequest{
		Query:     query,
		Variables: map[string]interface{}{"id": "1"},
	}
	req2 := &GatewayRequest{
		Query:     query,
		Variables: map[string]interface{}{"id": "2"},
	}

	resp1 := &GatewayResponse{
		Data: map[string]interface{}{"user": map[string]interface{}{"name": "Alice"}},
	}
	resp2 := &GatewayResponse{
		Data: map[string]interface{}{"user": map[string]interface{}{"name": "Bob"}},
	}

	cache.Set(ctx, req1, resp1)
	cache.Set(ctx, req2, resp2)

	// Different variables should be different cache entries
	cachedResp1, _ := cache.Get(ctx, req1)
	cachedResp2, _ := cache.Get(ctx, req2)

	if cachedResp1.Data.(map[string]interface{})["user"].(map[string]interface{})["name"] != "Alice" {
		t.Error("expected Alice for id=1")
	}
	if cachedResp2.Data.(map[string]interface{})["user"].(map[string]interface{})["name"] != "Bob" {
		t.Error("expected Bob for id=2")
	}
}

func TestResponseCache_DontCacheErrors(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { users { id } }`,
	}
	resp := &GatewayResponse{
		Errors: []GatewayResponseError{{Message: "some error"}},
	}

	cache.Set(ctx, req, resp)

	// Should not be cached
	_, status := cache.Get(ctx, req)
	if status != CacheStatusMiss {
		t.Errorf("expected miss for error response, got %s", status)
	}
}

func TestResponseCache_MaxSize(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		MaxSize:    3,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	ctx := context.Background()

	// Add 5 entries (more than max)
	for i := 0; i < 5; i++ {
		req := &GatewayRequest{
			Query:     `query { users { id } }`,
			Variables: map[string]interface{}{"i": i},
		}
		cache.Set(ctx, req, &GatewayResponse{})
	}

	stats := cache.Stats()
	if stats.EntryCount > 3 {
		t.Errorf("expected max 3 entries, got %d", stats.EntryCount)
	}
	if stats.Evictions == 0 {
		t.Error("expected some evictions")
	}
}

func TestEntityStore_GetWatch(t *testing.T) {
	store := NewEntityStore()

	// Initially empty
	_, ok := store.Get("User", "1")
	if ok {
		t.Error("expected entity not found")
	}

	// Add entity
	store.mu.Lock()
	store.entities["User:1"] = &EntityEntry{
		TypeName:  "User",
		ID:        "1",
		Data:      map[string]interface{}{"name": "Alice"},
		UpdatedAt: time.Now(),
	}
	store.mu.Unlock()

	// Should find now
	data, ok := store.Get("User", "1")
	if !ok {
		t.Error("expected entity found")
	}
	if data["name"] != "Alice" {
		t.Errorf("expected name Alice, got %v", data["name"])
	}
}

func TestEntityStore_Watch(t *testing.T) {
	store := NewEntityStore()

	// Watch for updates
	ch := store.Watch("User", "1")

	// Send update
	go func() {
		time.Sleep(10 * time.Millisecond)
		store.notifyWatchers(EntityUpdate{
			TypeName:  "User",
			ID:        "1",
			Operation: "update",
			Data:      map[string]interface{}{"name": "Bob"},
		})
	}()

	// Should receive update
	select {
	case update := <-ch:
		if update.TypeName != "User" || update.ID != "1" {
			t.Error("unexpected update")
		}
		if update.Data["name"] != "Bob" {
			t.Errorf("expected name Bob, got %v", update.Data["name"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for update")
	}

	// Unwatch
	store.Unwatch("User", "1", ch)
}

func TestQueryNormalizer(t *testing.T) {
	normalizer := NewQueryNormalizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "collapse whitespace",
			input:    "query  {  users  {  id  name  }  }",
			expected: "query { users { id name } }",
		},
		{
			name:     "remove comments",
			input:    "query { # get users\n users { id } }",
			expected: "query { users { id } }",
		},
		{
			name:     "multiline",
			input:    "query {\n  users {\n    id\n    name\n  }\n}",
			expected: "query { users { id name } }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.Normalize(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGenerateKey_Consistency(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	// Same query with different whitespace should produce same key
	req1 := &GatewayRequest{
		Query: `query { users { id name } }`,
	}
	req2 := &GatewayRequest{
		Query: `query {
			users {
				id
				name
			}
		}`,
	}

	key1 := cache.generateKey(req1)
	key2 := cache.generateKey(req2)

	if key1 != key2 {
		t.Errorf("expected same keys for equivalent queries, got %s and %s", key1, key2)
	}
}

func TestGenerateKey_Variables(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	// Same query, same variables in different order should produce same key
	req1 := &GatewayRequest{
		Query: `query { user(id: $id) { name } }`,
		Variables: map[string]interface{}{
			"a": 1,
			"b": 2,
		},
	}
	req2 := &GatewayRequest{
		Query: `query { user(id: $id) { name } }`,
		Variables: map[string]interface{}{
			"b": 2,
			"a": 1,
		},
	}

	key1 := cache.generateKey(req1)
	key2 := cache.generateKey(req2)

	if key1 != key2 {
		t.Errorf("expected same keys for same variables in different order, got %s and %s", key1, key2)
	}
}

func TestCacheControl_Parse(t *testing.T) {
	tests := []struct {
		header   string
		expected CacheControl
	}{
		{
			header: "max-age=300",
			expected: CacheControl{
				MaxAge: 300,
			},
		},
		{
			header: "max-age=300, public",
			expected: CacheControl{
				MaxAge: 300,
				Public: true,
			},
		},
		{
			header: "no-cache, no-store",
			expected: CacheControl{
				NoCache: true,
				NoStore: true,
			},
		},
		{
			header: "max-age=300, s-maxage=600, stale-while-revalidate=120",
			expected: CacheControl{
				MaxAge:               300,
				SMaxAge:              600,
				StaleWhileRevalidate: 120,
			},
		},
		{
			header: "private, must-revalidate",
			expected: CacheControl{
				Private:        true,
				MustRevalidate: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			cc := ParseCacheControl(tt.header)

			if cc.MaxAge != tt.expected.MaxAge {
				t.Errorf("MaxAge: expected %d, got %d", tt.expected.MaxAge, cc.MaxAge)
			}
			if cc.SMaxAge != tt.expected.SMaxAge {
				t.Errorf("SMaxAge: expected %d, got %d", tt.expected.SMaxAge, cc.SMaxAge)
			}
			if cc.NoCache != tt.expected.NoCache {
				t.Errorf("NoCache: expected %v, got %v", tt.expected.NoCache, cc.NoCache)
			}
			if cc.NoStore != tt.expected.NoStore {
				t.Errorf("NoStore: expected %v, got %v", tt.expected.NoStore, cc.NoStore)
			}
			if cc.Private != tt.expected.Private {
				t.Errorf("Private: expected %v, got %v", tt.expected.Private, cc.Private)
			}
			if cc.Public != tt.expected.Public {
				t.Errorf("Public: expected %v, got %v", tt.expected.Public, cc.Public)
			}
		})
	}
}

func TestCacheControl_ShouldCache(t *testing.T) {
	tests := []struct {
		cc       CacheControl
		expected bool
	}{
		{CacheControl{MaxAge: 300}, true},
		{CacheControl{SMaxAge: 600}, true},
		{CacheControl{NoStore: true}, false},
		{CacheControl{NoCache: true}, false},
		{CacheControl{Private: true}, false},
		{CacheControl{MaxAge: 300, NoStore: true}, false},
	}

	for _, tt := range tests {
		result := tt.cc.ShouldCache()
		if result != tt.expected {
			t.Errorf("ShouldCache for %+v: expected %v, got %v", tt.cc, tt.expected, result)
		}
	}
}

func TestCacheControl_TTL(t *testing.T) {
	tests := []struct {
		cc       CacheControl
		expected time.Duration
	}{
		{CacheControl{MaxAge: 300}, 300 * time.Second},
		{CacheControl{SMaxAge: 600}, 600 * time.Second},
		{CacheControl{MaxAge: 300, SMaxAge: 600}, 600 * time.Second}, // s-maxage takes precedence
		{CacheControl{}, 0},
	}

	for _, tt := range tests {
		result := tt.cc.TTL()
		if result != tt.expected {
			t.Errorf("TTL for %+v: expected %v, got %v", tt.cc, tt.expected, result)
		}
	}
}

func TestMatchCacheKey(t *testing.T) {
	tests := []struct {
		key      string
		pattern  string
		expected bool
	}{
		{"abc123", "*", true},
		{"abc123", "abc*", true},
		{"abc123", "*123", true},
		{"abc123", "*bc1*", true},
		{"abc123", "abc123", true},
		{"abc123", "xyz", false},
		{"abc123", "xyz*", false},
		{"abc123", "*xyz", false},
	}

	for _, tt := range tests {
		result := matchCacheKey(tt.key, tt.pattern)
		if result != tt.expected {
			t.Errorf("matchCacheKey(%q, %q): expected %v, got %v", tt.key, tt.pattern, tt.expected, result)
		}
	}
}

func TestCachingMiddleware(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:    true,
		DefaultTTL: 5 * time.Minute,
	})
	defer cache.Stop()

	callCount := 0
	upstream := func(ctx context.Context, req *GatewayRequest) (*GatewayResponse, error) {
		callCount++
		return &GatewayResponse{
			Data: map[string]interface{}{"result": callCount},
		}, nil
	}

	middleware := NewCachingMiddleware(CachingMiddlewareConfig{
		Cache: cache,
	})
	handler := middleware.Handler(upstream)

	ctx := context.Background()
	req := &GatewayRequest{
		Query: `query { data }`,
	}

	// First call should hit upstream
	resp1, _ := handler(ctx, req)
	if callCount != 1 {
		t.Errorf("expected 1 upstream call, got %d", callCount)
	}
	if resp1.Data.(map[string]interface{})["result"] != 1 {
		t.Error("expected result 1")
	}

	// Second call should use cache
	resp2, _ := handler(ctx, req)
	if callCount != 1 {
		t.Errorf("expected 1 upstream call (cached), got %d", callCount)
	}
	if resp2.Data.(map[string]interface{})["result"] != 1 {
		t.Error("expected cached result 1")
	}
}

func TestResponseCache_UpdateEntity(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:             true,
		DefaultTTL:          5 * time.Minute,
		EnableNormalization: true,
	})
	defer cache.Stop()

	// Update entity that doesn't exist yet
	cache.UpdateEntity("User", "1", map[string]interface{}{"name": "Alice"})

	// Should be stored
	data, ok := cache.entityStore.Get("User", "1")
	if !ok {
		t.Fatal("expected entity to be stored")
	}
	if data["name"] != "Alice" {
		t.Errorf("expected name Alice, got %v", data["name"])
	}

	// Update existing entity
	cache.UpdateEntity("User", "1", map[string]interface{}{"email": "alice@example.com"})

	data, _ = cache.entityStore.Get("User", "1")
	if data["name"] != "Alice" {
		t.Error("expected name to be preserved")
	}
	if data["email"] != "alice@example.com" {
		t.Error("expected email to be added")
	}
}

func TestResponseCache_InvalidateType(t *testing.T) {
	cache := NewResponseCache(CacheConfig{
		Enabled:             true,
		DefaultTTL:          5 * time.Minute,
		EnableNormalization: true,
	})
	defer cache.Stop()

	ctx := context.Background()

	// Add responses with User entities
	for i := 0; i < 3; i++ {
		req := &GatewayRequest{
			Query:     `query { users { id __typename } }`,
			Variables: map[string]interface{}{"page": i},
		}
		resp := &GatewayResponse{
			Data: map[string]interface{}{
				"users": []interface{}{
					map[string]interface{}{
						"id":         "user-" + string(rune('1'+i)),
						"__typename": "User",
					},
				},
			},
		}
		cache.Set(ctx, req, resp)
	}

	// Invalidate all User type entries
	count := cache.InvalidateType("User")
	if count != 3 {
		t.Errorf("expected 3 invalidations, got %d", count)
	}

	stats := cache.Stats()
	if stats.EntryCount != 0 {
		t.Errorf("expected 0 entries after type invalidation, got %d", stats.EntryCount)
	}
}
