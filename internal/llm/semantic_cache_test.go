package llm

import (
	"context"
	"testing"
	"time"
)

func TestNewSemanticCache(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.9,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	if cache == nil {
		t.Fatal("expected cache to be created")
	}

	if cache.Size() != 0 {
		t.Errorf("expected empty cache, got %d entries", cache.Size())
	}
}

func TestSemanticCacheSetGet(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	ctx := context.Background()
	prompt := "What is the capital of France?"
	model := "gpt-4"
	response := []byte(`{"choices":[{"message":{"content":"Paris"}}]}`)

	// Set a cache entry
	err := cache.Set(ctx, prompt, model, response, 10)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if cache.Size() != 1 {
		t.Errorf("expected 1 entry, got %d", cache.Size())
	}

	// Get the same prompt (exact match)
	entry, found, err := cache.Get(ctx, prompt, model)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !found {
		t.Fatal("expected to find cached entry")
	}
	if string(entry.Response) != string(response) {
		t.Errorf("expected response %s, got %s", response, entry.Response)
	}
}

func TestSemanticCacheSimilarPrompts(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.8, // Lower threshold for testing
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	ctx := context.Background()
	model := "gpt-4"

	// Cache a response
	prompt1 := "What is the capital of France?"
	response1 := []byte(`{"choices":[{"message":{"content":"Paris"}}]}`)
	cache.Set(ctx, prompt1, model, response1, 10)

	// Query with a similar prompt
	prompt2 := "What is the capital of France"
	entry, found, err := cache.Get(ctx, prompt2, model)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// With high similarity prompts, should find match
	if found {
		if string(entry.Response) != string(response1) {
			t.Errorf("expected original response for similar prompt")
		}
	}
}

func TestSemanticCacheDifferentModels(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	ctx := context.Background()
	prompt := "What is 2+2?"

	// Cache for gpt-4
	cache.Set(ctx, prompt, "gpt-4", []byte(`{"model":"gpt-4"}`), 5)

	// Cache for gpt-3.5
	cache.Set(ctx, prompt, "gpt-3.5-turbo", []byte(`{"model":"gpt-3.5"}`), 5)

	// Get for gpt-4
	entry, found, _ := cache.Get(ctx, prompt, "gpt-4")
	if !found {
		t.Fatal("expected to find gpt-4 entry")
	}
	if string(entry.Response) != `{"model":"gpt-4"}` {
		t.Errorf("wrong response for gpt-4")
	}

	// Get for gpt-3.5
	entry, found, _ = cache.Get(ctx, prompt, "gpt-3.5-turbo")
	if !found {
		t.Fatal("expected to find gpt-3.5 entry")
	}
	if string(entry.Response) != `{"model":"gpt-3.5"}` {
		t.Errorf("wrong response for gpt-3.5")
	}
}

func TestSemanticCacheTTL(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 50 * time.Millisecond,
	})

	ctx := context.Background()
	prompt := "Test prompt"
	model := "gpt-4"

	cache.Set(ctx, prompt, model, []byte("response"), 5)

	// Should find immediately
	_, found, _ := cache.Get(ctx, prompt, model)
	if !found {
		t.Fatal("expected to find entry before TTL")
	}

	// Wait for TTL
	time.Sleep(100 * time.Millisecond)

	// Should not find after TTL
	_, found, _ = cache.Get(ctx, prompt, model)
	if found {
		t.Error("expected entry to expire after TTL")
	}
}

func TestSemanticCacheEviction(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          3,
		TTL:                 time.Hour,
	})

	ctx := context.Background()
	model := "gpt-4"

	// Add 4 entries (max is 3)
	for i := 0; i < 4; i++ {
		prompt := "Prompt " + string(rune('A'+i))
		cache.Set(ctx, prompt, model, []byte("response"), 5)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// Should have max entries
	if cache.Size() != 3 {
		t.Errorf("expected 3 entries after eviction, got %d", cache.Size())
	}

	// First entry should be evicted (oldest)
	_, found, _ := cache.Get(ctx, "Prompt A", model)
	if found {
		t.Error("expected oldest entry to be evicted")
	}
}

func TestSemanticCacheClear(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient: embedding,
		MaxEntries:      100,
		TTL:             time.Hour,
	})

	ctx := context.Background()

	cache.Set(ctx, "prompt1", "gpt-4", []byte("r1"), 5)
	cache.Set(ctx, "prompt2", "gpt-4", []byte("r2"), 5)

	if cache.Size() != 2 {
		t.Fatalf("expected 2 entries, got %d", cache.Size())
	}

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("expected 0 entries after clear, got %d", cache.Size())
	}
}

func TestSemanticCacheStats(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	ctx := context.Background()
	prompt := "Test prompt"
	model := "gpt-4"

	// Miss
	cache.Get(ctx, prompt, model)

	// Set
	cache.Set(ctx, prompt, model, []byte("response"), 10)

	// Hit
	cache.Get(ctx, prompt, model)
	cache.Get(ctx, prompt, model)

	stats := cache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.TokensSaved != 20 { // 10 tokens * 2 hits
		t.Errorf("expected 20 tokens saved, got %d", stats.TokensSaved)
	}
}

func TestLocalEmbedding(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	ctx := context.Background()

	vec1, err := embedding.Embed(ctx, "Hello world")
	if err != nil {
		t.Fatalf("Embed failed: %v", err)
	}
	if len(vec1) != 100 {
		t.Errorf("expected 100-dim vector, got %d", len(vec1))
	}

	// Same text should give same embedding
	vec2, _ := embedding.Embed(ctx, "Hello world")
	if !vectorsEqual(vec1, vec2) {
		t.Error("same text should produce same embedding")
	}

	// Different text should give different embedding
	vec3, _ := embedding.Embed(ctx, "Goodbye world")
	if vectorsEqual(vec1, vec3) {
		t.Error("different text should produce different embedding")
	}
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []float32
		expected float64
	}{
		{
			name:     "identical vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{1, 0, 0},
			expected: 1.0,
		},
		{
			name:     "orthogonal vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{0, 1, 0},
			expected: 0.0,
		},
		{
			name:     "opposite vectors",
			a:        []float32{1, 0, 0},
			b:        []float32{-1, 0, 0},
			expected: -1.0,
		},
		{
			name:     "different lengths",
			a:        []float32{1, 0},
			b:        []float32{1, 0, 0},
			expected: 0.0,
		},
		{
			name:     "zero vector",
			a:        []float32{0, 0, 0},
			b:        []float32{1, 0, 0},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cosineSimilarity(tt.a, tt.b)
			if abs(result-tt.expected) > 0.0001 {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestHashPrompt(t *testing.T) {
	hash1 := hashPrompt("Hello", "gpt-4")
	hash2 := hashPrompt("Hello", "gpt-4")
	hash3 := hashPrompt("Hello", "gpt-3.5")
	hash4 := hashPrompt("World", "gpt-4")

	if hash1 != hash2 {
		t.Error("same prompt+model should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("different model should produce different hash")
	}
	if hash1 == hash4 {
		t.Error("different prompt should produce different hash")
	}
	if len(hash1) != 16 {
		t.Errorf("expected 16-char hash, got %d", len(hash1))
	}
}

func TestParseOpenAIRequest(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantModel   string
		wantStream  bool
		wantErr     bool
	}{
		{
			name: "simple request",
			body: `{
				"model": "gpt-4",
				"messages": [
					{"role": "user", "content": "Hello"}
				]
			}`,
			wantModel: "gpt-4",
		},
		{
			name: "streaming request",
			body: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "Hi"}],
				"stream": true
			}`,
			wantModel:  "gpt-3.5-turbo",
			wantStream: true,
		},
		{
			name:    "invalid json",
			body:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, prompt, err := ParseOpenAIRequest([]byte(tt.body))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Model != tt.wantModel {
				t.Errorf("expected model %s, got %s", tt.wantModel, req.Model)
			}
			if req.Stream != tt.wantStream {
				t.Errorf("expected stream %v, got %v", tt.wantStream, req.Stream)
			}
			if prompt == "" {
				t.Error("expected non-empty prompt")
			}
		})
	}
}

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		text     string
		expected int
	}{
		{"", 0},
		{"hi", 0}, // 2/4 = 0
		{"hello", 1},
		{"Hello, world!", 3},
	}

	for _, tt := range tests {
		got := EstimateTokens(tt.text)
		if got != tt.expected {
			t.Errorf("EstimateTokens(%q) = %d, want %d", tt.text, got, tt.expected)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
		}
	}
}

// Helper functions

func vectorsEqual(a, b []float32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if abs(float64(a[i]-b[i])) > 0.0001 {
			return false
		}
	}
	return true
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
