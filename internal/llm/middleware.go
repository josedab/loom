package llm

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// MiddlewareConfig configures the LLM caching middleware.
type MiddlewareConfig struct {
	// Cache is the semantic cache instance
	Cache *SemanticCache
	// PathPatterns are URL patterns to apply caching to (e.g., "/v1/chat/completions")
	PathPatterns []string
	// SkipStreaming skips caching for streaming requests (default: true)
	SkipStreaming bool
	// MaxBodySize is the max request body size to cache (default: 1MB)
	MaxBodySize int64
	// Logger for middleware events
	Logger *slog.Logger
}

// DefaultMiddlewareConfig returns sensible defaults for LLM caching.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		PathPatterns: []string{
			"/v1/chat/completions",
			"/v1/completions",
			"/chat/completions",
		},
		SkipStreaming: true,
		MaxBodySize:   1024 * 1024, // 1MB
	}
}

// Middleware returns HTTP middleware that caches LLM responses semantically.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1024 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.PathPatterns) == 0 {
		cfg.PathPatterns = DefaultMiddlewareConfig().PathPatterns
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this path should be cached
			if !matchesPatterns(r.URL.Path, cfg.PathPatterns) {
				next.ServeHTTP(w, r)
				return
			}

			// Only cache POST requests (LLM APIs use POST)
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			// Read and restore body
			body, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxBodySize))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Parse the LLM request
			llmReq, prompt, err := ParseOpenAIRequest(body)
			if err != nil {
				cfg.Logger.Debug("failed to parse LLM request", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			// Skip streaming requests if configured
			if cfg.SkipStreaming && llmReq.Stream {
				next.ServeHTTP(w, r)
				return
			}

			// Check cache
			entry, found, err := cfg.Cache.Get(r.Context(), prompt, llmReq.Model)
			if err != nil {
				cfg.Logger.Debug("cache lookup failed", "error", err)
			}

			if found {
				// Cache hit - return cached response
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.Header().Set("X-Cache-Type", "semantic")
				w.WriteHeader(http.StatusOK)
				w.Write(entry.Response)
				return
			}

			// Cache miss - call backend and cache response
			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
			}

			next.ServeHTTP(rec, r)

			// Only cache successful responses
			if rec.statusCode == http.StatusOK {
				responseBody := rec.body.Bytes()
				tokenCount := EstimateTokens(prompt) + EstimateTokens(string(responseBody))

				if err := cfg.Cache.Set(r.Context(), prompt, llmReq.Model, responseBody, tokenCount); err != nil {
					cfg.Logger.Debug("failed to cache response", "error", err)
				}
			}

			w.Header().Set("X-Cache", "MISS")
		})
	}
}

// responseRecorder captures the response for caching.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// matchesPatterns checks if a path matches any of the patterns.
func matchesPatterns(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(path, pattern[:len(pattern)-1]) {
				return true
			}
		} else if path == pattern {
			return true
		}
	}
	return false
}

// StreamingMiddleware handles streaming LLM responses with caching.
// It buffers the stream and caches the complete response.
type StreamingMiddlewareConfig struct {
	Cache        *SemanticCache
	PathPatterns []string
	Logger       *slog.Logger
}

// StreamingMiddleware returns middleware that handles streaming LLM responses.
func StreamingMiddleware(cfg StreamingMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !matchesPatterns(r.URL.Path, cfg.PathPatterns) {
				next.ServeHTTP(w, r)
				return
			}

			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}

			// Read body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			llmReq, prompt, err := ParseOpenAIRequest(body)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Check cache for streaming requests too
			entry, found, _ := cfg.Cache.Get(r.Context(), prompt, llmReq.Model)
			if found {
				// For cached streaming responses, we return them as non-streaming
				// The client should handle this gracefully
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.Header().Set("X-Cache-Type", "semantic-stream")
				w.WriteHeader(http.StatusOK)
				w.Write(entry.Response)
				return
			}

			// For streaming, we need to buffer the response
			if llmReq.Stream {
				streamRec := &streamRecorder{
					ResponseWriter: w,
					chunks:         make([][]byte, 0),
				}

				next.ServeHTTP(streamRec, r)

				// Combine chunks and cache
				if len(streamRec.chunks) > 0 {
					combined := combineSSEChunks(streamRec.chunks)
					tokenCount := EstimateTokens(prompt) + EstimateTokens(string(combined))
					cfg.Cache.Set(r.Context(), prompt, llmReq.Model, combined, tokenCount)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// streamRecorder captures streaming responses.
type streamRecorder struct {
	http.ResponseWriter
	chunks [][]byte
}

func (r *streamRecorder) Write(b []byte) (int, error) {
	r.chunks = append(r.chunks, append([]byte{}, b...))
	return r.ResponseWriter.Write(b)
}

// combineSSEChunks combines Server-Sent Events chunks into a single response.
func combineSSEChunks(chunks [][]byte) []byte {
	// For OpenAI-style streaming, extract content from each chunk
	// and combine into a single response
	var content strings.Builder

	for _, chunk := range chunks {
		// Parse SSE data lines
		lines := strings.Split(string(chunk), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "data: ") {
				data := strings.TrimPrefix(line, "data: ")
				if data == "[DONE]" {
					continue
				}
				// Extract content delta (simplified)
				content.WriteString(data)
			}
		}
	}

	// Return as a simple JSON response
	return []byte(`{"choices":[{"message":{"content":"` + content.String() + `"}}]}`)
}

// PromptNormalizer helps normalize prompts for better cache hits.
type PromptNormalizer struct {
	// RemoveWhitespace removes extra whitespace
	RemoveWhitespace bool
	// LowerCase converts to lowercase
	LowerCase bool
	// RemovePunctuation removes punctuation
	RemovePunctuation bool
	// StopWords to remove
	StopWords []string
}

// Normalize applies normalization to a prompt.
func (n *PromptNormalizer) Normalize(prompt string) string {
	if n.LowerCase {
		prompt = strings.ToLower(prompt)
	}

	if n.RemoveWhitespace {
		// Collapse multiple spaces
		fields := strings.Fields(prompt)
		prompt = strings.Join(fields, " ")
	}

	if n.RemovePunctuation {
		var result strings.Builder
		for _, r := range prompt {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
				r >= '0' && r <= '9' || r == ' ' {
				result.WriteRune(r)
			}
		}
		prompt = result.String()
	}

	if len(n.StopWords) > 0 {
		words := strings.Fields(prompt)
		filtered := make([]string, 0, len(words))
		stopSet := make(map[string]bool)
		for _, sw := range n.StopWords {
			stopSet[strings.ToLower(sw)] = true
		}
		for _, word := range words {
			if !stopSet[strings.ToLower(word)] {
				filtered = append(filtered, word)
			}
		}
		prompt = strings.Join(filtered, " ")
	}

	return prompt
}
