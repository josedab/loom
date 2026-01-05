package llm

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddleware(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"Hello!"}}]}`))
	})

	handler := Middleware(MiddlewareConfig{
		Cache: cache,
		PathPatterns: []string{"/v1/chat/completions"},
	})(backend)

	// First request - cache miss
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS, got %s", rec.Header().Get("X-Cache"))
	}

	// Second request with same prompt - cache hit
	req2 := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT, got %s", rec2.Header().Get("X-Cache"))
	}
	if rec2.Header().Get("X-Cache-Type") != "semantic" {
		t.Errorf("expected X-Cache-Type: semantic, got %s", rec2.Header().Get("X-Cache-Type"))
	}
}

func TestMiddlewareNonMatchingPath(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient: embedding,
		MaxEntries:      100,
		TTL:             time.Hour,
	})

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Cache:        cache,
		PathPatterns: []string{"/v1/chat/completions"},
	})(backend)

	req := httptest.NewRequest("POST", "/other/path", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected backend to be called for non-matching path")
	}
	if rec.Header().Get("X-Cache") != "" {
		t.Error("should not set cache headers for non-matching path")
	}
}

func TestMiddlewareSkipStreaming(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient: embedding,
		MaxEntries:      100,
		TTL:             time.Hour,
	})

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Cache:         cache,
		PathPatterns:  []string{"/v1/chat/completions"},
		SkipStreaming: true,
	})(backend)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected backend to be called for streaming request")
	}
}

func TestMiddlewareGetRequest(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient: embedding,
		MaxEntries:      100,
		TTL:             time.Hour,
	})

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Cache:        cache,
		PathPatterns: []string{"/v1/chat/completions"},
	})(backend)

	// GET requests should pass through (LLM APIs use POST)
	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected backend to be called for GET request")
	}
}

func TestMatchesPatterns(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		expected bool
	}{
		{"/v1/chat/completions", []string{"/v1/chat/completions"}, true},
		{"/v1/chat/completions", []string{"/v1/*"}, true},
		{"/v1/completions", []string{"/v1/*"}, true},
		{"/other/path", []string{"/v1/*"}, false},
		{"/api/v1/chat", []string{"/api/*", "/v1/*"}, true},
		{"/unknown", []string{"/v1/*", "/api/*"}, false},
	}

	for _, tt := range tests {
		got := matchesPatterns(tt.path, tt.patterns)
		if got != tt.expected {
			t.Errorf("matchesPatterns(%q, %v) = %v, want %v",
				tt.path, tt.patterns, got, tt.expected)
		}
	}
}

func TestPromptNormalizer(t *testing.T) {
	tests := []struct {
		name       string
		normalizer PromptNormalizer
		input      string
		expected   string
	}{
		{
			name:       "lowercase",
			normalizer: PromptNormalizer{LowerCase: true},
			input:      "Hello World",
			expected:   "hello world",
		},
		{
			name:       "whitespace",
			normalizer: PromptNormalizer{RemoveWhitespace: true},
			input:      "Hello   World",
			expected:   "Hello World",
		},
		{
			name:       "punctuation",
			normalizer: PromptNormalizer{RemovePunctuation: true},
			input:      "Hello, World!",
			expected:   "Hello World",
		},
		{
			name:       "stopwords",
			normalizer: PromptNormalizer{StopWords: []string{"the", "a", "an"}},
			input:      "the quick brown fox",
			expected:   "quick brown fox",
		},
		{
			name: "combined",
			normalizer: PromptNormalizer{
				LowerCase:        true,
				RemoveWhitespace: true,
				StopWords:        []string{"the"},
			},
			input:    "The   Quick Brown FOX",
			expected: "quick brown fox",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.normalizer.Normalize(tt.input)
			if got != tt.expected {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResponseRecorder(t *testing.T) {
	rec := &responseRecorder{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}

	rec.WriteHeader(http.StatusCreated)
	if rec.statusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec.statusCode)
	}

	n, err := rec.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if rec.body.String() != "hello" {
		t.Errorf("expected body 'hello', got %q", rec.body.String())
	}
}

func TestCombineSSEChunks(t *testing.T) {
	chunks := [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"),
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\" World\"}}]}\n\n"),
		[]byte("data: [DONE]\n\n"),
	}

	result := combineSSEChunks(chunks)

	// Should combine into a JSON response
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
	if !bytes.Contains(result, []byte("choices")) {
		t.Error("expected result to contain 'choices'")
	}
}

func TestDefaultMiddlewareConfig(t *testing.T) {
	cfg := DefaultMiddlewareConfig()

	if len(cfg.PathPatterns) != 3 {
		t.Errorf("expected 3 default patterns, got %d", len(cfg.PathPatterns))
	}
	if !cfg.SkipStreaming {
		t.Error("expected SkipStreaming to be true by default")
	}
	if cfg.MaxBodySize != 1024*1024 {
		t.Errorf("expected 1MB max body size, got %d", cfg.MaxBodySize)
	}
}

func TestStreamRecorder(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &streamRecorder{
		ResponseWriter: underlying,
		chunks:         make([][]byte, 0),
	}

	rec.Write([]byte("chunk1"))
	rec.Write([]byte("chunk2"))

	if len(rec.chunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(rec.chunks))
	}
	if string(rec.chunks[0]) != "chunk1" {
		t.Errorf("expected 'chunk1', got %q", rec.chunks[0])
	}

	// Verify underlying writer also got the data
	if underlying.Body.String() != "chunk1chunk2" {
		t.Errorf("expected underlying to have 'chunk1chunk2', got %q", underlying.Body.String())
	}
}

func TestMiddlewareInvalidJSON(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient: embedding,
		MaxEntries:      100,
		TTL:             time.Hour,
	})

	called := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Verify body is still readable
		body, _ := io.ReadAll(r.Body)
		if string(body) != "{invalid json}" {
			t.Errorf("expected body to be preserved, got %q", body)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Cache:        cache,
		PathPatterns: []string{"/v1/chat/completions"},
	})(backend)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString("{invalid json}"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected backend to be called for invalid JSON")
	}
}

func TestStreamingMiddleware(t *testing.T) {
	embedding := NewLocalEmbedding(100)
	cache := NewSemanticCache(Config{
		EmbeddingClient:     embedding,
		SimilarityThreshold: 0.95,
		MaxEntries:          100,
		TTL:                 time.Hour,
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	})

	handler := StreamingMiddleware(StreamingMiddlewareConfig{
		Cache:        cache,
		PathPatterns: []string{"/v1/chat/completions"},
	})(backend)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Second request should hit cache
	req2 := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)

	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected cache hit on second request, got %s", rec2.Header().Get("X-Cache"))
	}
}
