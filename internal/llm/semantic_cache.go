// Package llm provides LLM-specific gateway features including semantic caching.
package llm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// SemanticCache provides semantic similarity-based caching for LLM APIs.
// Instead of exact prompt matching, it finds cached responses for semantically
// similar prompts using vector embeddings and cosine similarity.
type SemanticCache struct {
	entries         map[string]*SemanticEntry // hash -> entry
	vectors         []vectorEntry             // for similarity search
	embeddingClient EmbeddingClient
	similarity      float64 // minimum similarity threshold (0.0-1.0)
	maxEntries      int
	ttl             time.Duration
	mu              sync.RWMutex
	logger          *slog.Logger
	stats           *SemanticStats
}

// SemanticEntry represents a cached LLM response with its embedding.
type SemanticEntry struct {
	Hash       string
	Prompt     string
	Response   []byte
	Embedding  []float32
	Model      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	HitCount   int
	TokensSaved int // Estimated tokens saved by cache hit
}

// vectorEntry is used for efficient similarity search.
type vectorEntry struct {
	hash      string
	embedding []float32
	expiresAt time.Time
}

// SemanticStats tracks cache performance.
type SemanticStats struct {
	Hits            int64
	Misses          int64
	SemanticHits    int64 // Hits from similar (not exact) prompts
	TokensSaved     int64
	AvgSimilarity   float64
	mu              sync.Mutex
}

// EmbeddingClient generates embeddings for text.
type EmbeddingClient interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// Config configures the semantic cache.
type Config struct {
	// SimilarityThreshold is the minimum cosine similarity for a cache hit (default: 0.95)
	SimilarityThreshold float64
	// MaxEntries is the maximum number of cached entries (default: 10000)
	MaxEntries int
	// TTL is the default time-to-live for entries (default: 1 hour)
	TTL time.Duration
	// EmbeddingClient generates embeddings (required)
	EmbeddingClient EmbeddingClient
	// Logger for cache events
	Logger *slog.Logger
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SimilarityThreshold: 0.95,
		MaxEntries:          10000,
		TTL:                 time.Hour,
	}
}

// NewSemanticCache creates a new semantic cache.
func NewSemanticCache(cfg Config) *SemanticCache {
	if cfg.SimilarityThreshold == 0 {
		cfg.SimilarityThreshold = 0.95
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	sc := &SemanticCache{
		entries:         make(map[string]*SemanticEntry),
		vectors:         make([]vectorEntry, 0),
		embeddingClient: cfg.EmbeddingClient,
		similarity:      cfg.SimilarityThreshold,
		maxEntries:      cfg.MaxEntries,
		ttl:             cfg.TTL,
		logger:          cfg.Logger,
		stats:           &SemanticStats{},
	}

	// Start cleanup goroutine
	go sc.cleanupLoop()

	return sc
}

// Get retrieves a cached response for a semantically similar prompt.
func (sc *SemanticCache) Get(ctx context.Context, prompt, model string) (*SemanticEntry, bool, error) {
	// Generate embedding for the prompt
	embedding, err := sc.embeddingClient.Embed(ctx, prompt)
	if err != nil {
		return nil, false, fmt.Errorf("generating embedding: %w", err)
	}

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	// Check for exact match first (fastest path)
	hash := hashPrompt(prompt, model)
	if entry, ok := sc.entries[hash]; ok && time.Now().Before(entry.ExpiresAt) {
		entry.HitCount++
		sc.recordHit(false, 1.0, entry.TokensSaved)
		return entry, true, nil
	}

	// Find most similar cached prompt
	bestMatch, bestSimilarity := sc.findMostSimilar(embedding, model)

	if bestMatch != nil && bestSimilarity >= sc.similarity {
		bestMatch.HitCount++
		sc.recordHit(true, bestSimilarity, bestMatch.TokensSaved)
		sc.logger.Debug("semantic cache hit",
			"similarity", bestSimilarity,
			"original_prompt", truncate(bestMatch.Prompt, 50),
			"query_prompt", truncate(prompt, 50))
		return bestMatch, true, nil
	}

	sc.recordMiss()
	return nil, false, nil
}

// Set stores a response with its embedding.
func (sc *SemanticCache) Set(ctx context.Context, prompt, model string, response []byte, tokenCount int) error {
	embedding, err := sc.embeddingClient.Embed(ctx, prompt)
	if err != nil {
		return fmt.Errorf("generating embedding: %w", err)
	}

	hash := hashPrompt(prompt, model)
	now := time.Now()

	entry := &SemanticEntry{
		Hash:        hash,
		Prompt:      prompt,
		Response:    response,
		Embedding:   embedding,
		Model:       model,
		CreatedAt:   now,
		ExpiresAt:   now.Add(sc.ttl),
		TokensSaved: tokenCount,
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Evict if at capacity
	if len(sc.entries) >= sc.maxEntries {
		sc.evictOldest()
	}

	sc.entries[hash] = entry
	sc.vectors = append(sc.vectors, vectorEntry{
		hash:      hash,
		embedding: embedding,
		expiresAt: entry.ExpiresAt,
	})

	sc.logger.Debug("cached LLM response",
		"prompt", truncate(prompt, 50),
		"model", model,
		"tokens", tokenCount)

	return nil
}

// findMostSimilar finds the most similar cached entry.
func (sc *SemanticCache) findMostSimilar(embedding []float32, model string) (*SemanticEntry, float64) {
	var bestEntry *SemanticEntry
	bestSimilarity := float64(0)
	now := time.Now()

	for _, v := range sc.vectors {
		if now.After(v.expiresAt) {
			continue
		}

		entry, ok := sc.entries[v.hash]
		if !ok || entry.Model != model {
			continue
		}

		similarity := cosineSimilarity(embedding, v.embedding)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestEntry = entry
		}
	}

	return bestEntry, bestSimilarity
}

// cosineSimilarity calculates the cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// hashPrompt creates a unique hash for a prompt+model combination.
func hashPrompt(prompt, model string) string {
	h := sha256.New()
	h.Write([]byte(model))
	h.Write([]byte(prompt))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// evictOldest removes the oldest entry.
func (sc *SemanticCache) evictOldest() {
	var oldestHash string
	var oldestTime time.Time

	for hash, entry := range sc.entries {
		if oldestHash == "" || entry.CreatedAt.Before(oldestTime) {
			oldestHash = hash
			oldestTime = entry.CreatedAt
		}
	}

	if oldestHash != "" {
		delete(sc.entries, oldestHash)
		// Remove from vectors (expensive but infrequent)
		newVectors := make([]vectorEntry, 0, len(sc.vectors)-1)
		for _, v := range sc.vectors {
			if v.hash != oldestHash {
				newVectors = append(newVectors, v)
			}
		}
		sc.vectors = newVectors
	}
}

// cleanupLoop periodically removes expired entries.
func (sc *SemanticCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sc.cleanup()
	}
}

// cleanup removes expired entries.
func (sc *SemanticCache) cleanup() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	now := time.Now()

	// Remove expired entries
	for hash, entry := range sc.entries {
		if now.After(entry.ExpiresAt) {
			delete(sc.entries, hash)
		}
	}

	// Rebuild vectors slice
	newVectors := make([]vectorEntry, 0, len(sc.vectors))
	for _, v := range sc.vectors {
		if _, ok := sc.entries[v.hash]; ok {
			newVectors = append(newVectors, v)
		}
	}
	sc.vectors = newVectors
}

// Stats recording
func (sc *SemanticCache) recordHit(semantic bool, similarity float64, tokens int) {
	sc.stats.mu.Lock()
	defer sc.stats.mu.Unlock()
	sc.stats.Hits++
	if semantic {
		sc.stats.SemanticHits++
	}
	sc.stats.TokensSaved += int64(tokens)
	// Running average of similarity
	sc.stats.AvgSimilarity = (sc.stats.AvgSimilarity*float64(sc.stats.Hits-1) + similarity) / float64(sc.stats.Hits)
}

func (sc *SemanticCache) recordMiss() {
	sc.stats.mu.Lock()
	defer sc.stats.mu.Unlock()
	sc.stats.Misses++
}

// GetStats returns cache statistics.
func (sc *SemanticCache) GetStats() SemanticStats {
	sc.stats.mu.Lock()
	defer sc.stats.mu.Unlock()
	return SemanticStats{
		Hits:          sc.stats.Hits,
		Misses:        sc.stats.Misses,
		SemanticHits:  sc.stats.SemanticHits,
		TokensSaved:   sc.stats.TokensSaved,
		AvgSimilarity: sc.stats.AvgSimilarity,
	}
}

// Size returns the number of cached entries.
func (sc *SemanticCache) Size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.entries)
}

// Clear removes all entries.
func (sc *SemanticCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.entries = make(map[string]*SemanticEntry)
	sc.vectors = make([]vectorEntry, 0)
}

// truncate shortens a string for logging.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ============================================================================
// Built-in Embedding Clients
// ============================================================================

// LocalEmbedding provides a simple local embedding using term frequency.
// This is a fallback when no external embedding service is available.
// For production, use OpenAIEmbedding or a similar service.
type LocalEmbedding struct {
	vocab     map[string]int
	vocabSize int
	mu        sync.RWMutex
}

// NewLocalEmbedding creates a local embedding client.
func NewLocalEmbedding(vocabSize int) *LocalEmbedding {
	if vocabSize == 0 {
		vocabSize = 1000
	}
	return &LocalEmbedding{
		vocab:     make(map[string]int),
		vocabSize: vocabSize,
	}
}

// Embed generates a simple TF embedding vector.
func (e *LocalEmbedding) Embed(ctx context.Context, text string) ([]float32, error) {
	tokens := tokenize(text)

	e.mu.Lock()
	// Build vocabulary
	for _, token := range tokens {
		if _, ok := e.vocab[token]; !ok && len(e.vocab) < e.vocabSize {
			e.vocab[token] = len(e.vocab)
		}
	}
	e.mu.Unlock()

	// Create TF vector
	e.mu.RLock()
	defer e.mu.RUnlock()

	vector := make([]float32, e.vocabSize)
	for _, token := range tokens {
		if idx, ok := e.vocab[token]; ok {
			vector[idx]++
		}
	}

	// Normalize
	var norm float32
	for _, v := range vector {
		norm += v * v
	}
	if norm > 0 {
		norm = float32(math.Sqrt(float64(norm)))
		for i := range vector {
			vector[i] /= norm
		}
	}

	return vector, nil
}

// tokenize splits text into tokens.
func tokenize(text string) []string {
	text = strings.ToLower(text)
	// Simple word tokenization
	var tokens []string
	var current strings.Builder

	for _, r := range text {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			current.WriteRune(r)
		} else if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// OpenAIEmbedding uses OpenAI's embedding API.
type OpenAIEmbedding struct {
	apiKey     string
	model      string
	endpoint   string
	httpClient *http.Client
}

// NewOpenAIEmbedding creates an OpenAI embedding client.
func NewOpenAIEmbedding(apiKey string) *OpenAIEmbedding {
	return &OpenAIEmbedding{
		apiKey:   apiKey,
		model:    "text-embedding-3-small",
		endpoint: "https://api.openai.com/v1/embeddings",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Embed generates an embedding using OpenAI API.
func (e *OpenAIEmbedding) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody := map[string]interface{}{
		"input": text,
		"model": e.model,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OpenAI API error: %s", body)
	}

	var result struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}

	return result.Data[0].Embedding, nil
}

// ============================================================================
// LLM Request/Response Parsing
// ============================================================================

// OpenAIRequest represents an OpenAI API request.
type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ParseOpenAIRequest extracts the prompt from an OpenAI-compatible request.
func ParseOpenAIRequest(body []byte) (*OpenAIRequest, string, error) {
	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}

	// Extract prompt from messages
	var prompts []string
	for _, msg := range req.Messages {
		prompts = append(prompts, msg.Role+": "+msg.Content)
	}

	// Sort for consistent hashing
	sort.Strings(prompts)
	prompt := strings.Join(prompts, "\n")

	return &req, prompt, nil
}

// EstimateTokens provides a rough token count estimate.
func EstimateTokens(text string) int {
	// Rough estimate: ~4 characters per token for English
	return len(text) / 4
}
