// Package aigateway provides AI/LLM gateway capabilities.
package aigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrCacheMiss      = errors.New("cache miss")
	ErrCacheDisabled  = errors.New("cache disabled")
	ErrCacheCorrupted = errors.New("cache entry corrupted")
)

// SemanticCache provides caching for LLM responses with semantic similarity matching.
type SemanticCache struct {
	config      SemanticCacheConfig
	exactCache  *ExactCache              // Fast exact-match cache
	vectorCache *VectorCache             // Semantic similarity cache
	stats       CacheStats
	mu          sync.RWMutex
}

// SemanticCacheConfig configures the semantic cache.
type SemanticCacheConfig struct {
	// MaxSize is the maximum cache size in bytes
	MaxSize int64
	// DefaultTTL is the default time-to-live for cache entries
	DefaultTTL time.Duration
	// SimilarityThreshold is the minimum cosine similarity for semantic matches (0.0-1.0)
	SimilarityThreshold float64
	// EnableSemanticMatching enables vector-based semantic matching
	EnableSemanticMatching bool
	// EmbeddingDimensions is the size of embedding vectors
	EmbeddingDimensions int
	// MaxEntries is the maximum number of cache entries
	MaxEntries int
	// ShardCount is the number of cache shards for concurrency
	ShardCount int
	// CleanupInterval is how often to run cache cleanup
	CleanupInterval time.Duration
	// VaryByHeaders are headers that create cache variance
	VaryByHeaders []string
	// VaryByUser enables per-user caching
	VaryByUser bool
}

// DefaultSemanticCacheConfig returns default cache configuration.
func DefaultSemanticCacheConfig() SemanticCacheConfig {
	return SemanticCacheConfig{
		MaxSize:                100 * 1024 * 1024, // 100MB
		DefaultTTL:             1 * time.Hour,
		SimilarityThreshold:    0.95,
		EnableSemanticMatching: false, // Disabled by default (requires embedding model)
		EmbeddingDimensions:    1536,  // OpenAI ada-002 dimensions
		MaxEntries:             10000,
		ShardCount:             64,
		CleanupInterval:        5 * time.Minute,
		VaryByHeaders:          []string{"X-User-ID", "X-Org-ID"},
		VaryByUser:             false,
	}
}

// NewSemanticCache creates a new semantic cache.
func NewSemanticCache(config SemanticCacheConfig) *SemanticCache {
	if config.ShardCount <= 0 {
		config.ShardCount = 64
	}
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 1 * time.Hour
	}
	if config.SimilarityThreshold <= 0 {
		config.SimilarityThreshold = 0.95
	}
	if config.EmbeddingDimensions <= 0 {
		config.EmbeddingDimensions = 1536
	}

	cache := &SemanticCache{
		config:     config,
		exactCache: NewExactCache(config.ShardCount, config.MaxEntries, config.DefaultTTL),
	}

	if config.EnableSemanticMatching {
		cache.vectorCache = NewVectorCache(config.EmbeddingDimensions, config.SimilarityThreshold, config.MaxEntries)
	}

	// Start cleanup goroutine
	if config.CleanupInterval > 0 {
		go cache.cleanupLoop()
	}

	return cache
}

// Get retrieves a cached response for the request.
func (sc *SemanticCache) Get(ctx context.Context, req *LLMRequest, varyKeys map[string]string) (*CacheEntry, error) {
	// Generate cache key
	key := sc.generateKey(req, varyKeys)

	// Try exact match first (fast path)
	if entry, err := sc.exactCache.Get(key); err == nil {
		sc.stats.Hits.Add(1)
		return entry, nil
	}

	// Try semantic match if enabled
	if sc.vectorCache != nil && len(req.Messages) > 0 {
		// Generate embedding for the request
		embedding := sc.generateSimpleEmbedding(req)

		if entry, similarity, err := sc.vectorCache.FindSimilar(embedding, req.Model); err == nil {
			sc.stats.SemanticHits.Add(1)
			entry.Similarity = similarity
			return entry, nil
		}
	}

	sc.stats.Misses.Add(1)
	return nil, ErrCacheMiss
}

// Set stores a response in the cache.
func (sc *SemanticCache) Set(ctx context.Context, req *LLMRequest, resp *LLMResponse, varyKeys map[string]string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = sc.config.DefaultTTL
	}

	// Generate cache key
	key := sc.generateKey(req, varyKeys)

	entry := &CacheEntry{
		Key:         key,
		Request:     req,
		Response:    resp,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
		TokensUsed:  resp.TotalTokens,
		Model:       resp.Model,
	}

	// Store in exact cache
	sc.exactCache.Set(key, entry)

	// Store in vector cache if enabled
	if sc.vectorCache != nil && len(req.Messages) > 0 {
		embedding := sc.generateSimpleEmbedding(req)
		entry.Embedding = embedding
		sc.vectorCache.Add(entry)
	}

	sc.stats.Sets.Add(1)
	return nil
}

// Delete removes an entry from the cache.
func (sc *SemanticCache) Delete(key string) {
	sc.exactCache.Delete(key)
	// Note: Vector cache doesn't support individual deletes efficiently
}

// Clear removes all entries from the cache.
func (sc *SemanticCache) Clear() {
	sc.exactCache.Clear()
	if sc.vectorCache != nil {
		sc.vectorCache.Clear()
	}
	sc.stats = CacheStats{} // Reset stats
}

// Stats returns cache statistics.
func (sc *SemanticCache) Stats() CacheStatsSnapshot {
	return CacheStatsSnapshot{
		Hits:         sc.stats.Hits.Load(),
		Misses:       sc.stats.Misses.Load(),
		SemanticHits: sc.stats.SemanticHits.Load(),
		Sets:         sc.stats.Sets.Load(),
		Evictions:    sc.stats.Evictions.Load(),
		Size:         sc.exactCache.Size(),
		Entries:      sc.exactCache.Count(),
	}
}

// generateKey generates a cache key for a request.
func (sc *SemanticCache) generateKey(req *LLMRequest, varyKeys map[string]string) string {
	h := sha256.New()

	// Include model
	h.Write([]byte(req.Model))
	h.Write([]byte{0})

	// Include system prompt
	h.Write([]byte(req.SystemPrompt))
	h.Write([]byte{0})

	// Include messages
	for _, msg := range req.Messages {
		h.Write([]byte(msg.Role))
		h.Write([]byte{0})
		h.Write([]byte(msg.Content))
		h.Write([]byte{0})
	}

	// Include prompt
	h.Write([]byte(req.Prompt))
	h.Write([]byte{0})

	// Include vary keys (sorted for consistency)
	if len(varyKeys) > 0 {
		keys := make([]string, 0, len(varyKeys))
		for k := range varyKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte{0})
			h.Write([]byte(varyKeys[k]))
			h.Write([]byte{0})
		}
	}

	// Include temperature (affects output)
	if req.Temperature > 0 {
		h.Write([]byte{byte(int(req.Temperature * 100))})
	}

	return hex.EncodeToString(h.Sum(nil))
}

// generateSimpleEmbedding creates a simple embedding without external models.
// This is a simplified approach using TF-IDF-like vectors.
// For production, integrate with actual embedding models.
func (sc *SemanticCache) generateSimpleEmbedding(req *LLMRequest) []float32 {
	// Combine all text content
	var text strings.Builder
	text.WriteString(req.SystemPrompt)
	text.WriteString(" ")
	for _, msg := range req.Messages {
		text.WriteString(msg.Content)
		text.WriteString(" ")
	}
	text.WriteString(req.Prompt)

	// Simple bag-of-words embedding
	words := tokenizeText(text.String())
	embedding := make([]float32, sc.config.EmbeddingDimensions)

	for _, word := range words {
		// Hash word to embedding dimension
		h := fnv.New32a()
		h.Write([]byte(word))
		idx := int(h.Sum32()) % sc.config.EmbeddingDimensions
		embedding[idx] += 1.0
	}

	// Normalize
	normalizeVector(embedding)

	return embedding
}

// tokenizeText splits text into words.
func tokenizeText(text string) []string {
	text = strings.ToLower(text)
	// Simple word splitting
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})

	// Remove common stop words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"to": true, "of": true, "in": true, "for": true, "on": true,
		"with": true, "at": true, "by": true, "from": true, "as": true,
		"it": true, "this": true, "that": true, "which": true, "what": true,
	}

	filtered := make([]string, 0, len(words))
	for _, w := range words {
		if len(w) > 2 && !stopWords[w] {
			filtered = append(filtered, w)
		}
	}

	return filtered
}

// normalizeVector normalizes a vector to unit length.
func normalizeVector(v []float32) {
	var sum float64
	for _, x := range v {
		sum += float64(x * x)
	}
	if sum == 0 {
		return
	}
	norm := float32(1.0 / sqrt64(sum))
	for i := range v {
		v[i] *= norm
	}
}

// sqrt64 computes square root using Newton's method.
func sqrt64(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

// cleanupLoop periodically removes expired entries.
func (sc *SemanticCache) cleanupLoop() {
	ticker := time.NewTicker(sc.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		evicted := sc.exactCache.Cleanup()
		sc.stats.Evictions.Add(int64(evicted))
	}
}

// CacheEntry represents a cached LLM response.
type CacheEntry struct {
	Key        string       `json:"key"`
	Request    *LLMRequest  `json:"request"`
	Response   *LLMResponse `json:"response"`
	CreatedAt  time.Time    `json:"created_at"`
	ExpiresAt  time.Time    `json:"expires_at"`
	TokensUsed int          `json:"tokens_used"`
	Model      string       `json:"model"`
	Similarity float64      `json:"similarity,omitempty"` // For semantic matches
	Embedding  []float32    `json:"-"`                    // Not serialized
	size       int64        // Computed size in bytes
}

// IsExpired checks if the entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Size returns the approximate size of the entry in bytes.
func (e *CacheEntry) Size() int64 {
	if e.size > 0 {
		return e.size
	}

	// Estimate size
	size := int64(len(e.Key))
	if e.Response != nil {
		size += int64(len(e.Response.Content))
		size += int64(len(e.Response.RawBody))
	}
	if e.Request != nil {
		for _, msg := range e.Request.Messages {
			size += int64(len(msg.Content))
		}
		size += int64(len(e.Request.Prompt))
	}
	size += int64(len(e.Embedding) * 4) // float32 = 4 bytes

	e.size = size
	return size
}

// CacheStats holds cache statistics with atomic counters.
type CacheStats struct {
	Hits         atomic.Int64
	Misses       atomic.Int64
	SemanticHits atomic.Int64
	Sets         atomic.Int64
	Evictions    atomic.Int64
}

// CacheStatsSnapshot is a point-in-time snapshot of cache statistics.
type CacheStatsSnapshot struct {
	Hits         int64 `json:"hits"`
	Misses       int64 `json:"misses"`
	SemanticHits int64 `json:"semantic_hits"`
	Sets         int64 `json:"sets"`
	Evictions    int64 `json:"evictions"`
	Size         int64 `json:"size_bytes"`
	Entries      int   `json:"entries"`
}

// ExactCache provides fast exact-match caching using sharding.
type ExactCache struct {
	shards     []*cacheShard
	shardCount int
	maxEntries int
	defaultTTL time.Duration
}

type cacheShard struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	size    int64
}

// NewExactCache creates a new exact-match cache.
func NewExactCache(shardCount, maxEntries int, defaultTTL time.Duration) *ExactCache {
	if shardCount <= 0 {
		shardCount = 64
	}

	cache := &ExactCache{
		shards:     make([]*cacheShard, shardCount),
		shardCount: shardCount,
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}

	for i := 0; i < shardCount; i++ {
		cache.shards[i] = &cacheShard{
			entries: make(map[string]*CacheEntry),
		}
	}

	return cache
}

// getShard returns the shard for a key.
func (c *ExactCache) getShard(key string) *cacheShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%uint32(c.shardCount)]
}

// Get retrieves an entry from the cache.
func (c *ExactCache) Get(key string) (*CacheEntry, error) {
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, ok := shard.entries[key]
	shard.mu.RUnlock()

	if !ok {
		return nil, ErrCacheMiss
	}

	if entry.IsExpired() {
		c.Delete(key)
		return nil, ErrCacheMiss
	}

	return entry, nil
}

// Set stores an entry in the cache.
func (c *ExactCache) Set(key string, entry *CacheEntry) {
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Remove old entry size
	if old, ok := shard.entries[key]; ok {
		shard.size -= old.Size()
	}

	shard.entries[key] = entry
	shard.size += entry.Size()
}

// Delete removes an entry from the cache.
func (c *ExactCache) Delete(key string) {
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, ok := shard.entries[key]; ok {
		shard.size -= entry.Size()
		delete(shard.entries, key)
	}
}

// Clear removes all entries from the cache.
func (c *ExactCache) Clear() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.entries = make(map[string]*CacheEntry)
		shard.size = 0
		shard.mu.Unlock()
	}
}

// Size returns the total size of all entries in bytes.
func (c *ExactCache) Size() int64 {
	var total int64
	for _, shard := range c.shards {
		shard.mu.RLock()
		total += shard.size
		shard.mu.RUnlock()
	}
	return total
}

// Count returns the total number of entries.
func (c *ExactCache) Count() int {
	var total int
	for _, shard := range c.shards {
		shard.mu.RLock()
		total += len(shard.entries)
		shard.mu.RUnlock()
	}
	return total
}

// Cleanup removes expired entries and returns the count removed.
func (c *ExactCache) Cleanup() int {
	var removed int
	now := time.Now()

	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if now.After(entry.ExpiresAt) {
				shard.size -= entry.Size()
				delete(shard.entries, key)
				removed++
			}
		}
		shard.mu.Unlock()
	}

	return removed
}

// VectorCache provides semantic similarity-based caching.
type VectorCache struct {
	entries    []*CacheEntry
	mu         sync.RWMutex
	dimensions int
	threshold  float64
	maxEntries int
}

// NewVectorCache creates a new vector cache.
func NewVectorCache(dimensions int, threshold float64, maxEntries int) *VectorCache {
	return &VectorCache{
		entries:    make([]*CacheEntry, 0, maxEntries),
		dimensions: dimensions,
		threshold:  threshold,
		maxEntries: maxEntries,
	}
}

// Add adds an entry to the vector cache.
func (vc *VectorCache) Add(entry *CacheEntry) {
	if len(entry.Embedding) != vc.dimensions {
		return // Invalid embedding dimensions
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Remove oldest entries if at capacity
	if len(vc.entries) >= vc.maxEntries {
		vc.entries = vc.entries[1:]
	}

	vc.entries = append(vc.entries, entry)
}

// FindSimilar finds the most similar entry above the threshold.
func (vc *VectorCache) FindSimilar(embedding []float32, model string) (*CacheEntry, float64, error) {
	if len(embedding) != vc.dimensions {
		return nil, 0, errors.New("invalid embedding dimensions")
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()

	var bestEntry *CacheEntry
	bestSimilarity := float64(0)
	now := time.Now()

	for _, entry := range vc.entries {
		// Skip expired entries
		if now.After(entry.ExpiresAt) {
			continue
		}

		// Skip if model doesn't match
		if model != "" && entry.Model != model {
			continue
		}

		// Compute cosine similarity
		similarity := cosineSimilarity(embedding, entry.Embedding)
		if similarity >= vc.threshold && similarity > bestSimilarity {
			bestSimilarity = similarity
			bestEntry = entry
		}
	}

	if bestEntry == nil {
		return nil, 0, ErrCacheMiss
	}

	return bestEntry, bestSimilarity, nil
}

// Clear removes all entries.
func (vc *VectorCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.entries = vc.entries[:0]
}

// cosineSimilarity computes the cosine similarity between two vectors.
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

	return dotProduct / (sqrt64(normA) * sqrt64(normB))
}

// CacheKeyBuilder helps build cache keys with variance.
type CacheKeyBuilder struct {
	varyKeys map[string]string
}

// NewCacheKeyBuilder creates a new cache key builder.
func NewCacheKeyBuilder() *CacheKeyBuilder {
	return &CacheKeyBuilder{
		varyKeys: make(map[string]string),
	}
}

// AddHeader adds a header value to the cache key.
func (b *CacheKeyBuilder) AddHeader(name, value string) *CacheKeyBuilder {
	b.varyKeys["h:"+name] = value
	return b
}

// AddUser adds a user identifier to the cache key.
func (b *CacheKeyBuilder) AddUser(userID string) *CacheKeyBuilder {
	b.varyKeys["user"] = userID
	return b
}

// AddOrg adds an organization identifier to the cache key.
func (b *CacheKeyBuilder) AddOrg(orgID string) *CacheKeyBuilder {
	b.varyKeys["org"] = orgID
	return b
}

// Add adds a custom key-value pair.
func (b *CacheKeyBuilder) Add(key, value string) *CacheKeyBuilder {
	b.varyKeys[key] = value
	return b
}

// Build returns the vary keys map.
func (b *CacheKeyBuilder) Build() map[string]string {
	return b.varyKeys
}

// CacheEntryJSON is used for JSON serialization of cache entries.
type CacheEntryJSON struct {
	Key        string          `json:"key"`
	Request    json.RawMessage `json:"request"`
	Response   json.RawMessage `json:"response"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	TokensUsed int             `json:"tokens_used"`
	Model      string          `json:"model"`
}

// MarshalJSON implements json.Marshaler for CacheEntry.
func (e *CacheEntry) MarshalJSON() ([]byte, error) {
	reqJSON, _ := json.Marshal(e.Request)
	respJSON, _ := json.Marshal(e.Response)

	return json.Marshal(CacheEntryJSON{
		Key:        e.Key,
		Request:    reqJSON,
		Response:   respJSON,
		CreatedAt:  e.CreatedAt,
		ExpiresAt:  e.ExpiresAt,
		TokensUsed: e.TokensUsed,
		Model:      e.Model,
	})
}
