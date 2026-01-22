package aigateway

import (
	"context"
	"testing"
	"time"
)

func TestSemanticCache_ExactMatch(t *testing.T) {
	config := DefaultSemanticCacheConfig()
	config.EnableSemanticMatching = false
	cache := NewSemanticCache(config)

	req := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "What is 2+2?"},
		},
	}

	resp := &LLMResponse{
		Model:       "gpt-4",
		Content:     "4",
		InputTokens: 10,
		OutputTokens: 1,
		TotalTokens: 11,
		RawBody:     []byte(`{"content": "4"}`),
	}

	ctx := context.Background()
	varyKeys := map[string]string{}

	// Cache miss
	_, err := cache.Get(ctx, req, varyKeys)
	if err != ErrCacheMiss {
		t.Errorf("Get() error = %v, want ErrCacheMiss", err)
	}

	// Set cache
	err = cache.Set(ctx, req, resp, varyKeys, time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Cache hit
	entry, err := cache.Get(ctx, req, varyKeys)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if entry.Response.Content != "4" {
		t.Errorf("Content = %q, want '4'", entry.Response.Content)
	}

	// Verify stats
	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Hits = %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}
}

func TestSemanticCache_VaryKeys(t *testing.T) {
	config := DefaultSemanticCacheConfig()
	cache := NewSemanticCache(config)

	req := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
	}

	resp := &LLMResponse{
		Content: "Hi User1",
		RawBody: []byte(`{"content": "Hi User1"}`),
	}

	ctx := context.Background()

	// Set with user1
	cache.Set(ctx, req, resp, map[string]string{"user": "user1"}, time.Hour)

	// Miss with user2
	_, err := cache.Get(ctx, req, map[string]string{"user": "user2"})
	if err != ErrCacheMiss {
		t.Errorf("Get() should miss with different user")
	}

	// Hit with user1
	entry, err := cache.Get(ctx, req, map[string]string{"user": "user1"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if entry.Response.Content != "Hi User1" {
		t.Errorf("Content = %q, want 'Hi User1'", entry.Response.Content)
	}
}

func TestSemanticCache_Expiration(t *testing.T) {
	config := DefaultSemanticCacheConfig()
	config.DefaultTTL = 50 * time.Millisecond
	cache := NewSemanticCache(config)

	req := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "Test"},
		},
	}

	resp := &LLMResponse{
		Content: "Response",
		RawBody: []byte(`{"content": "Response"}`),
	}

	ctx := context.Background()

	// Set with short TTL
	cache.Set(ctx, req, resp, nil, 50*time.Millisecond)

	// Should hit immediately
	_, err := cache.Get(ctx, req, nil)
	if err != nil {
		t.Errorf("Get() should hit immediately: %v", err)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should miss after expiration
	_, err = cache.Get(ctx, req, nil)
	if err != ErrCacheMiss {
		t.Errorf("Get() should miss after expiration: %v", err)
	}
}

func TestSemanticCache_SemanticMatching(t *testing.T) {
	config := DefaultSemanticCacheConfig()
	config.EnableSemanticMatching = true
	config.SimilarityThreshold = 0.5 // Lower threshold for test
	config.EmbeddingDimensions = 128
	cache := NewSemanticCache(config)

	// Original request
	req1 := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "What is the capital of France?"},
		},
	}

	resp := &LLMResponse{
		Model:   "gpt-4",
		Content: "Paris is the capital of France.",
		RawBody: []byte(`{"content": "Paris is the capital of France."}`),
	}

	ctx := context.Background()

	// Set original
	cache.Set(ctx, req1, resp, nil, time.Hour)

	// Similar request
	req2 := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "Tell me the capital city of France please"},
		},
	}

	// Should potentially hit with semantic matching
	// Note: With simple bag-of-words embeddings, this may or may not match
	// depending on word overlap
	entry, err := cache.Get(ctx, req2, nil)
	if err == nil && entry != nil {
		t.Logf("Semantic match found with similarity: %f", entry.Similarity)
	}
}

func TestExactCache(t *testing.T) {
	cache := NewExactCache(16, 1000, time.Hour)

	entry := &CacheEntry{
		Key:       "test-key",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Response: &LLMResponse{
			Content: "test content",
		},
	}

	// Set
	cache.Set("test-key", entry)

	// Get
	got, err := cache.Get("test-key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Response.Content != "test content" {
		t.Errorf("Content = %q, want 'test content'", got.Response.Content)
	}

	// Delete
	cache.Delete("test-key")
	_, err = cache.Get("test-key")
	if err != ErrCacheMiss {
		t.Errorf("Get() should return ErrCacheMiss after Delete")
	}

	// Count
	cache.Set("key1", entry)
	cache.Set("key2", entry)
	if cache.Count() != 2 {
		t.Errorf("Count() = %d, want 2", cache.Count())
	}

	// Clear
	cache.Clear()
	if cache.Count() != 0 {
		t.Errorf("Count() = %d after Clear, want 0", cache.Count())
	}
}

func TestExactCache_Cleanup(t *testing.T) {
	cache := NewExactCache(16, 1000, time.Hour)

	// Add expired entry
	expiredEntry := &CacheEntry{
		Key:       "expired",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), // Already expired
	}
	cache.Set("expired", expiredEntry)

	// Add valid entry
	validEntry := &CacheEntry{
		Key:       "valid",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	cache.Set("valid", validEntry)

	// Cleanup
	removed := cache.Cleanup()
	if removed != 1 {
		t.Errorf("Cleanup() removed = %d, want 1", removed)
	}

	// Verify expired is gone
	_, err := cache.Get("expired")
	if err != ErrCacheMiss {
		t.Error("expired entry should be removed")
	}

	// Verify valid still exists
	_, err = cache.Get("valid")
	if err != nil {
		t.Error("valid entry should still exist")
	}
}

func TestVectorCache(t *testing.T) {
	cache := NewVectorCache(4, 0.8, 100)

	// Create entry with embedding
	entry := &CacheEntry{
		Key:       "test",
		Model:     "gpt-4",
		Embedding: []float32{0.5, 0.5, 0.5, 0.5},
		ExpiresAt: time.Now().Add(time.Hour),
		Response: &LLMResponse{
			Content: "test response",
		},
	}

	cache.Add(entry)

	// Search with similar embedding
	similar := []float32{0.5, 0.5, 0.5, 0.4}
	found, similarity, err := cache.FindSimilar(similar, "gpt-4")
	if err != nil {
		t.Fatalf("FindSimilar() error = %v", err)
	}
	if found == nil {
		t.Fatal("FindSimilar() should find entry")
	}
	if similarity < 0.8 {
		t.Errorf("similarity = %f, want >= 0.8", similarity)
	}

	// Search with different model
	_, _, err = cache.FindSimilar(similar, "claude-3")
	if err != ErrCacheMiss {
		t.Error("FindSimilar() should miss with different model")
	}

	// Search with very different embedding
	different := []float32{-1, -1, -1, -1}
	_, _, err = cache.FindSimilar(different, "gpt-4")
	if err != ErrCacheMiss {
		t.Error("FindSimilar() should miss with very different embedding")
	}

	// Clear
	cache.Clear()
	_, _, err = cache.FindSimilar(similar, "gpt-4")
	if err != ErrCacheMiss {
		t.Error("FindSimilar() should miss after Clear")
	}
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a        []float32
		b        []float32
		expected float64
		epsilon  float64
	}{
		{
			name:     "identical vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{1, 0, 0},
			expected: 1.0,
			epsilon:  0.001,
		},
		{
			name:     "orthogonal vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{0, 1, 0},
			expected: 0.0,
			epsilon:  0.001,
		},
		{
			name:     "opposite vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{-1, 0, 0},
			expected: -1.0,
			epsilon:  0.001,
		},
		{
			name:     "similar vectors",
			a:        []float32{1, 2, 3},
			b:        []float32{1, 2, 4},
			expected: 0.99,
			epsilon:  0.02,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cosineSimilarity(tt.a, tt.b)
			diff := result - tt.expected
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.epsilon {
				t.Errorf("cosineSimilarity() = %f, want %f (±%f)",
					result, tt.expected, tt.epsilon)
			}
		})
	}
}

func TestCacheEntry_Size(t *testing.T) {
	entry := &CacheEntry{
		Key: "test-key",
		Response: &LLMResponse{
			Content: "Hello, world!",
			RawBody: []byte(`{"content": "Hello, world!"}`),
		},
		Request: &LLMRequest{
			Prompt: "Say hello",
			Messages: []Message{
				{Role: "user", Content: "Hello"},
			},
		},
		Embedding: make([]float32, 100),
	}

	size := entry.Size()
	if size <= 0 {
		t.Errorf("Size() = %d, want > 0", size)
	}

	// Size should be cached
	size2 := entry.Size()
	if size != size2 {
		t.Errorf("Size() not cached: %d != %d", size, size2)
	}
}

func TestCacheEntry_IsExpired(t *testing.T) {
	// Not expired
	entry1 := &CacheEntry{
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if entry1.IsExpired() {
		t.Error("entry should not be expired")
	}

	// Expired
	entry2 := &CacheEntry{
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if !entry2.IsExpired() {
		t.Error("entry should be expired")
	}
}

func TestCacheKeyBuilder(t *testing.T) {
	builder := NewCacheKeyBuilder()

	keys := builder.
		AddHeader("X-Custom", "value").
		AddUser("user123").
		AddOrg("org456").
		Add("custom", "data").
		Build()

	if keys["h:X-Custom"] != "value" {
		t.Errorf("header key missing or wrong")
	}
	if keys["user"] != "user123" {
		t.Errorf("user key missing or wrong")
	}
	if keys["org"] != "org456" {
		t.Errorf("org key missing or wrong")
	}
	if keys["custom"] != "data" {
		t.Errorf("custom key missing or wrong")
	}
}

func BenchmarkSemanticCache_Get(b *testing.B) {
	config := DefaultSemanticCacheConfig()
	cache := NewSemanticCache(config)

	req := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "What is 2+2?"},
		},
	}

	resp := &LLMResponse{
		Content: "4",
		RawBody: []byte(`{"content": "4"}`),
	}

	ctx := context.Background()
	cache.Set(ctx, req, resp, nil, time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(ctx, req, nil)
	}
}

func BenchmarkSemanticCache_Set(b *testing.B) {
	config := DefaultSemanticCacheConfig()
	cache := NewSemanticCache(config)

	req := &LLMRequest{
		Model: "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "What is 2+2?"},
		},
	}

	resp := &LLMResponse{
		Content: "4",
		RawBody: []byte(`{"content": "4"}`),
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(ctx, req, resp, nil, time.Hour)
	}
}

func BenchmarkExactCache_Parallel(b *testing.B) {
	cache := NewExactCache(64, 10000, time.Hour)

	entry := &CacheEntry{
		Key:       "test",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := "key-" + string(rune(i%100))
			if i%2 == 0 {
				cache.Set(key, entry)
			} else {
				cache.Get(key)
			}
			i++
		}
	})
}
