// Package aigateway provides AI/LLM gateway capabilities.
package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Middleware provides AI gateway functionality as HTTP middleware.
type Middleware struct {
	router            *ProviderRouter
	cache             *SemanticCache
	tokenCounter      *TokenCounter
	injectionDetector *PromptInjectionDetector
	config            MiddlewareConfig
	logger            *slog.Logger
}

// MiddlewareConfig configures the AI gateway middleware.
type MiddlewareConfig struct {
	// EnableCaching enables response caching
	EnableCaching bool
	// EnableTokenCounting enables token counting in headers
	EnableTokenCounting bool
	// EnablePromptGuard enables prompt injection detection
	EnablePromptGuard bool
	// EnableRateLimiting enables per-user rate limiting
	EnableRateLimiting bool
	// MaxTokensPerRequest limits tokens per request
	MaxTokensPerRequest int
	// MaxRequestBodySize limits request body size
	MaxRequestBodySize int64
	// CacheConfig configures caching
	CacheConfig SemanticCacheConfig
	// RouterConfig configures provider routing
	RouterConfig RouterConfig
	// VaryByHeaders are headers that create cache variance
	VaryByHeaders []string
	// UserIDHeader is the header containing user ID
	UserIDHeader string
	// OrgIDHeader is the header containing organization ID
	OrgIDHeader string
	// BlockOnInjection blocks requests with detected prompt injection
	BlockOnInjection bool
}

// DefaultMiddlewareConfig returns default middleware configuration.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		EnableCaching:       true,
		EnableTokenCounting: true,
		EnablePromptGuard:   true,
		EnableRateLimiting:  false,
		MaxTokensPerRequest: 100000,
		MaxRequestBodySize:  10 * 1024 * 1024, // 10MB
		CacheConfig:         DefaultSemanticCacheConfig(),
		VaryByHeaders:       []string{"X-User-ID", "X-Org-ID"},
		UserIDHeader:        "X-User-ID",
		OrgIDHeader:         "X-Org-ID",
		BlockOnInjection:    false,
	}
}

// NewMiddleware creates a new AI gateway middleware.
func NewMiddleware(config MiddlewareConfig, logger *slog.Logger) *Middleware {
	if logger == nil {
		logger = slog.Default()
	}

	m := &Middleware{
		config:       config,
		tokenCounter: NewTokenCounter(),
		logger:       logger,
	}

	// Initialize router if providers configured
	if len(config.RouterConfig.Providers) > 0 {
		m.router = NewProviderRouter(config.RouterConfig)
	}

	// Initialize cache if enabled
	if config.EnableCaching {
		m.cache = NewSemanticCache(config.CacheConfig)
	}

	// Initialize prompt guard if enabled
	if config.EnablePromptGuard {
		m.injectionDetector = NewPromptInjectionDetector()
	}

	return m
}

// Handler returns the middleware handler.
func (m *Middleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is an LLM request
			if !isLLMRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Create request context
			ctx := NewRequestContext()
			r = r.WithContext(context.WithValue(r.Context(), llmRequestContextKey, ctx))

			// Handle LLM request
			m.handleLLMRequest(w, r, ctx)
		})
	}
}

// handleLLMRequest handles an LLM API request.
func (m *Middleware) handleLLMRequest(w http.ResponseWriter, r *http.Request, reqCtx *RequestContext) {
	start := time.Now()

	// Read and parse request body
	body, err := io.ReadAll(io.LimitReader(r.Body, m.config.MaxRequestBodySize))
	if err != nil {
		m.errorResponse(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Parse LLM request
	llmReq, err := ParseRequest(r)
	if err != nil {
		// Not a valid LLM request, pass through
		r.Body = io.NopCloser(bytes.NewReader(body))
		m.forwardRequest(w, r)
		return
	}

	reqCtx.Provider = llmReq.Provider
	reqCtx.Model = llmReq.Model

	// Count input tokens
	if m.config.EnableTokenCounting {
		tokenCount := m.tokenCounter.CountRequest(llmReq)
		reqCtx.InputTokens = tokenCount.PromptTokens

		// Check token limit
		if m.config.MaxTokensPerRequest > 0 && tokenCount.PromptTokens > m.config.MaxTokensPerRequest {
			m.errorResponse(w, http.StatusRequestEntityTooLarge, "request exceeds token limit")
			return
		}

		// Add token count headers
		w.Header().Set("X-Input-Tokens", strconv.Itoa(tokenCount.PromptTokens))
		w.Header().Set("X-Tokenizer", tokenCount.Tokenizer)
	}

	// Check for prompt injection
	if m.config.EnablePromptGuard && m.injectionDetector != nil {
		if detected, match := m.injectionDetector.DetectRequest(llmReq); detected {
			m.logger.Warn("prompt injection detected",
				"request_id", reqCtx.ID,
				"match", match,
			)
			w.Header().Set("X-Prompt-Guard", "detected")
			w.Header().Set("X-Prompt-Guard-Match", match)

			if m.config.BlockOnInjection {
				m.errorResponse(w, http.StatusBadRequest, "potential prompt injection detected")
				return
			}
		}
	}

	// Build cache vary keys
	varyKeys := m.buildVaryKeys(r)

	// Check cache
	if m.config.EnableCaching && m.cache != nil && !llmReq.Stream {
		if entry, err := m.cache.Get(r.Context(), llmReq, varyKeys); err == nil {
			reqCtx.Cached = true
			m.serveCachedResponse(w, entry, reqCtx)
			return
		}
	}

	// Route to provider or forward
	if m.router != nil {
		m.routeToProvider(w, r, llmReq, varyKeys, reqCtx)
	} else {
		// Forward to upstream (let proxy handler deal with it)
		r.Body = io.NopCloser(bytes.NewReader(body))
		m.forwardRequest(w, r)
	}

	// Record latency
	latency := time.Since(start)
	w.Header().Set("X-LLM-Latency-Ms", strconv.FormatInt(latency.Milliseconds(), 10))
}

// routeToProvider routes the request to an LLM provider.
func (m *Middleware) routeToProvider(w http.ResponseWriter, r *http.Request, llmReq *LLMRequest, varyKeys map[string]string, reqCtx *RequestContext) {
	// Handle streaming requests
	if llmReq.Stream {
		m.handleStreamingRequest(w, r, llmReq, reqCtx)
		return
	}

	// Execute request through router
	resp, err := m.router.Execute(r.Context(), llmReq)
	if err != nil {
		m.logger.Error("provider request failed",
			"request_id", reqCtx.ID,
			"error", err,
		)
		m.errorResponse(w, http.StatusBadGateway, "provider request failed")
		return
	}

	// Count output tokens
	if m.config.EnableTokenCounting {
		tokenCount := m.tokenCounter.CountResponse(resp)
		reqCtx.OutputTokens = tokenCount.CompletionTokens
		w.Header().Set("X-Output-Tokens", strconv.Itoa(tokenCount.CompletionTokens))
		w.Header().Set("X-Total-Tokens", strconv.Itoa(tokenCount.TotalPromptTokens))
	}

	// Cache response
	if m.config.EnableCaching && m.cache != nil {
		m.cache.Set(r.Context(), llmReq, resp, varyKeys, m.config.CacheConfig.DefaultTTL)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cache-Status", "miss")
	w.WriteHeader(http.StatusOK)
	w.Write(resp.RawBody)
}

// handleStreamingRequest handles streaming LLM requests.
func (m *Middleware) handleStreamingRequest(w http.ResponseWriter, r *http.Request, llmReq *LLMRequest, reqCtx *RequestContext) {
	// Get provider
	provider, err := m.router.Route(llmReq)
	if err != nil {
		m.errorResponse(w, http.StatusBadGateway, "no providers available")
		return
	}

	// Create proxy request
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, provider.Config.Endpoint, bytes.NewReader(llmReq.RawBody))
	if err != nil {
		m.errorResponse(w, http.StatusInternalServerError, "failed to create request")
		return
	}

	// Copy headers
	proxyReq.Header.Set("Content-Type", "application/json")
	for k, v := range provider.Config.Headers {
		proxyReq.Header.Set(k, v)
	}

	// Set auth
	if provider.Config.APIKey != "" {
		switch provider.Config.Provider {
		case ProviderAnthropic:
			proxyReq.Header.Set("x-api-key", provider.Config.APIKey)
			proxyReq.Header.Set("anthropic-version", "2024-01-01")
		default:
			proxyReq.Header.Set("Authorization", "Bearer "+provider.Config.APIKey)
		}
	}

	// Execute request
	client := &http.Client{
		Timeout: 5 * time.Minute, // Streaming can take longer
	}
	resp, err := client.Do(proxyReq)
	if err != nil {
		m.errorResponse(w, http.StatusBadGateway, "provider request failed")
		return
	}
	defer resp.Body.Close()

	// Setup streaming response
	sw, err := NewStreamResponseWriter(w)
	if err != nil {
		m.errorResponse(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Stream events
	parser := NewStreamParser(resp.Body, provider.Config.Provider)
	var totalContent strings.Builder
	outputTokens := 0

	for {
		event, err := parser.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// Extract and count content
		content, done := ExtractStreamContent(event, provider.Config.Provider)
		if content != "" {
			totalContent.WriteString(content)
			outputTokens += m.tokenCounter.CountText(content, llmReq.Model)
		}

		// Forward event
		sw.WriteEvent(event)

		if done {
			break
		}
	}

	// Send final event
	sw.Close()

	// Record stats
	reqCtx.OutputTokens = outputTokens
	provider.RecordRequest(reqCtx.InputTokens + outputTokens)
}

// serveCachedResponse serves a cached response.
func (m *Middleware) serveCachedResponse(w http.ResponseWriter, entry *CacheEntry, reqCtx *RequestContext) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cache-Status", "hit")
	w.Header().Set("X-Cache-Key", entry.Key[:16]+"...")

	if entry.Similarity > 0 {
		w.Header().Set("X-Cache-Similarity", strconv.FormatFloat(entry.Similarity, 'f', 4, 64))
	}

	if m.config.EnableTokenCounting && entry.Response != nil {
		w.Header().Set("X-Output-Tokens", strconv.Itoa(entry.Response.OutputTokens))
		w.Header().Set("X-Total-Tokens", strconv.Itoa(entry.Response.TotalTokens))
	}

	w.WriteHeader(http.StatusOK)
	if entry.Response != nil && entry.Response.RawBody != nil {
		w.Write(entry.Response.RawBody)
	}
}

// buildVaryKeys builds cache variance keys from the request.
func (m *Middleware) buildVaryKeys(r *http.Request) map[string]string {
	keys := make(map[string]string)

	for _, header := range m.config.VaryByHeaders {
		if value := r.Header.Get(header); value != "" {
			keys["h:"+header] = value
		}
	}

	if m.config.UserIDHeader != "" {
		if userID := r.Header.Get(m.config.UserIDHeader); userID != "" {
			keys["user"] = userID
		}
	}

	if m.config.OrgIDHeader != "" {
		if orgID := r.Header.Get(m.config.OrgIDHeader); orgID != "" {
			keys["org"] = orgID
		}
	}

	return keys
}

// forwardRequest forwards the request to the next handler.
func (m *Middleware) forwardRequest(w http.ResponseWriter, r *http.Request) {
	// This would normally call the upstream proxy
	// For now, return a 502 indicating no handler
	m.errorResponse(w, http.StatusBadGateway, "no upstream configured")
}

// errorResponse sends an error response.
func (m *Middleware) errorResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    "gateway_error",
			"code":    status,
		},
	})
}

// isLLMRequest checks if this looks like an LLM API request.
func isLLMRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	path := r.URL.Path
	llmPaths := []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",
		"/v1/embeddings",
		"/chat/completions",
		"/completions",
		"/messages",
	}

	for _, p := range llmPaths {
		if path == p || (len(path) > len(p) && path[:len(p)] == p) {
			return true
		}
	}

	return false
}

// llmRequestContextKey is the context key for LLM request context.
type llmRequestContextKeyType struct{}

var llmRequestContextKey = llmRequestContextKeyType{}

// GetRequestContext retrieves the LLM request context from the request.
func GetRequestContext(r *http.Request) *RequestContext {
	if ctx, ok := r.Context().Value(llmRequestContextKey).(*RequestContext); ok {
		return ctx
	}
	return nil
}

// AIGateway is the main AI gateway handler.
type AIGateway struct {
	middleware   *Middleware
	router       *ProviderRouter
	cache        *SemanticCache
	tokenCounter *TokenCounter
	logger       *slog.Logger
	mu           sync.RWMutex
}

// AIGatewayConfig configures the AI gateway.
type AIGatewayConfig struct {
	Providers       []ProviderConfig
	RoutingStrategy RoutingStrategy
	CacheConfig     SemanticCacheConfig
	EnableCache     bool
	EnableGuard     bool
	MaxTokens       int
}

// NewAIGateway creates a new AI gateway.
func NewAIGateway(config AIGatewayConfig, logger *slog.Logger) *AIGateway {
	if logger == nil {
		logger = slog.Default()
	}

	gw := &AIGateway{
		tokenCounter: NewTokenCounter(),
		logger:       logger,
	}

	if len(config.Providers) > 0 {
		gw.router = NewProviderRouter(RouterConfig{
			Strategy:  config.RoutingStrategy,
			Providers: config.Providers,
		})
	}

	if config.EnableCache {
		gw.cache = NewSemanticCache(config.CacheConfig)
	}

	// Create middleware
	gw.middleware = NewMiddleware(MiddlewareConfig{
		EnableCaching:       config.EnableCache,
		EnableTokenCounting: true,
		EnablePromptGuard:   config.EnableGuard,
		MaxTokensPerRequest: config.MaxTokens,
		CacheConfig:         config.CacheConfig,
		RouterConfig: RouterConfig{
			Strategy:  config.RoutingStrategy,
			Providers: config.Providers,
		},
	}, logger)

	return gw
}

// Handler returns the HTTP handler for the AI gateway.
func (gw *AIGateway) Handler() http.Handler {
	return gw.middleware.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Default handler for non-LLM requests
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
}

// Stats returns gateway statistics.
func (gw *AIGateway) Stats() map[string]interface{} {
	stats := make(map[string]interface{})

	if gw.router != nil {
		stats["router"] = gw.router.Stats()
	}

	if gw.cache != nil {
		cacheStats := gw.cache.Stats()
		stats["cache"] = map[string]interface{}{
			"hits":          cacheStats.Hits,
			"misses":        cacheStats.Misses,
			"semantic_hits": cacheStats.SemanticHits,
			"entries":       cacheStats.Entries,
			"size_bytes":    cacheStats.Size,
		}
	}

	return stats
}

// AddProvider adds a provider to the gateway.
func (gw *AIGateway) AddProvider(config ProviderConfig) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.router != nil {
		gw.router.AddProvider(config)
	}
}

// RemoveProvider removes a provider from the gateway.
func (gw *AIGateway) RemoveProvider(name string) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.router != nil {
		return gw.router.RemoveProvider(name)
	}
	return nil
}

// Close shuts down the gateway.
func (gw *AIGateway) Close() {
	if gw.router != nil {
		gw.router.Close()
	}
}
