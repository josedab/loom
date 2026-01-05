// Package cache provides high-performance response caching for the gateway.
package cache

import (
	"bytes"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry represents a cached response.
type Entry struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ETag       string
	VaryKeys   []string // Headers to vary cache key on
}

// IsExpired returns true if the cache entry has expired.
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale returns true if the entry is past its freshness but within stale-while-revalidate window.
func (e *Entry) IsStale(staleWindow time.Duration) bool {
	return time.Now().After(e.ExpiresAt) && time.Now().Before(e.ExpiresAt.Add(staleWindow))
}

// Cache provides high-performance in-memory response caching.
type Cache struct {
	shards       []*shard
	shardCount   uint64
	maxSize      int64
	currentSize  int64
	ttl          time.Duration
	cleanupTick  *time.Ticker
	stopCh       chan struct{}
	stats        *Stats
}

// Stats tracks cache performance metrics.
type Stats struct {
	Hits        uint64
	Misses      uint64
	Evictions   uint64
	Expirations uint64
	StaleHits   uint64
}

// GetStats returns current cache statistics.
func (c *Cache) GetStats() Stats {
	return Stats{
		Hits:        atomic.LoadUint64(&c.stats.Hits),
		Misses:      atomic.LoadUint64(&c.stats.Misses),
		Evictions:   atomic.LoadUint64(&c.stats.Evictions),
		Expirations: atomic.LoadUint64(&c.stats.Expirations),
		StaleHits:   atomic.LoadUint64(&c.stats.StaleHits),
	}
}

// shard is a single cache partition with its own lock.
type shard struct {
	entries map[string]*Entry
	mu      sync.RWMutex
}

// Config configures the cache behavior.
type Config struct {
	// MaxSize is the maximum cache size in bytes (default: 100MB)
	MaxSize int64
	// DefaultTTL is the default time-to-live for entries (default: 5 minutes)
	DefaultTTL time.Duration
	// ShardCount is the number of shards for concurrency (default: 256)
	ShardCount int
	// CleanupInterval is how often to clean expired entries (default: 1 minute)
	CleanupInterval time.Duration
	// StaleWhileRevalidate allows serving stale content while revalidating (default: 30s)
	StaleWhileRevalidate time.Duration
}

// DefaultConfig returns sensible cache defaults.
func DefaultConfig() Config {
	return Config{
		MaxSize:              100 * 1024 * 1024, // 100MB
		DefaultTTL:           5 * time.Minute,
		ShardCount:           256,
		CleanupInterval:      time.Minute,
		StaleWhileRevalidate: 30 * time.Second,
	}
}

// New creates a new cache with the given configuration.
func New(cfg Config) *Cache {
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100 * 1024 * 1024
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.ShardCount == 0 {
		cfg.ShardCount = 256
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	shards := make([]*shard, cfg.ShardCount)
	for i := range shards {
		shards[i] = &shard{
			entries: make(map[string]*Entry),
		}
	}

	c := &Cache{
		shards:      shards,
		shardCount:  uint64(cfg.ShardCount),
		maxSize:     cfg.MaxSize,
		ttl:         cfg.DefaultTTL,
		cleanupTick: time.NewTicker(cfg.CleanupInterval),
		stopCh:      make(chan struct{}),
		stats:       &Stats{},
	}

	go c.cleanupLoop()

	return c
}

// getShard returns the shard for a given key.
func (c *Cache) getShard(key string) *shard {
	h := fnv.New64a()
	h.Write([]byte(key))
	return c.shards[h.Sum64()%c.shardCount]
}

// Get retrieves an entry from the cache.
func (c *Cache) Get(key string) (*Entry, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	entry, ok := shard.entries[key]
	shard.mu.RUnlock()

	if !ok {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false
	}

	if entry.IsExpired() {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false
	}

	atomic.AddUint64(&c.stats.Hits, 1)
	return entry, true
}

// GetWithStale retrieves an entry, allowing stale content within the stale window.
func (c *Cache) GetWithStale(key string, staleWindow time.Duration) (*Entry, bool, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	entry, ok := shard.entries[key]
	shard.mu.RUnlock()

	if !ok {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false, false
	}

	if entry.IsExpired() {
		if entry.IsStale(staleWindow) {
			atomic.AddUint64(&c.stats.StaleHits, 1)
			return entry, true, true // entry, found, isStale
		}
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false, false
	}

	atomic.AddUint64(&c.stats.Hits, 1)
	return entry, true, false
}

// Set stores an entry in the cache.
func (c *Cache) Set(key string, entry *Entry) {
	entrySize := int64(len(entry.Body))

	// Don't cache if entry is larger than max size
	if entrySize > c.maxSize {
		return
	}

	// Evict if needed to make room
	for atomic.LoadInt64(&c.currentSize)+entrySize > c.maxSize {
		c.evictOne()
	}

	shard := c.getShard(key)
	shard.mu.Lock()

	// Update size tracking
	if existing, ok := shard.entries[key]; ok {
		atomic.AddInt64(&c.currentSize, -int64(len(existing.Body)))
	}

	shard.entries[key] = entry
	atomic.AddInt64(&c.currentSize, entrySize)
	shard.mu.Unlock()
}

// SetWithTTL stores an entry with a specific TTL.
func (c *Cache) SetWithTTL(key string, entry *Entry, ttl time.Duration) {
	entry.ExpiresAt = time.Now().Add(ttl)
	c.Set(key, entry)
}

// Delete removes an entry from the cache.
func (c *Cache) Delete(key string) {
	shard := c.getShard(key)
	shard.mu.Lock()
	if entry, ok := shard.entries[key]; ok {
		atomic.AddInt64(&c.currentSize, -int64(len(entry.Body)))
		delete(shard.entries, key)
	}
	shard.mu.Unlock()
}

// Purge removes all entries matching a prefix.
func (c *Cache) Purge(prefix string) int {
	count := 0
	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if strings.HasPrefix(key, prefix) {
				atomic.AddInt64(&c.currentSize, -int64(len(entry.Body)))
				delete(shard.entries, key)
				count++
			}
		}
		shard.mu.Unlock()
	}
	return count
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.entries = make(map[string]*Entry)
		shard.mu.Unlock()
	}
	atomic.StoreInt64(&c.currentSize, 0)
}

// evictOne removes one entry (LRU-ish based on expiration).
func (c *Cache) evictOne() {
	var oldestKey string
	var oldestTime time.Time
	var oldestShard *shard

	// Find oldest entry across shards (sampling approach for performance)
	for i, shard := range c.shards {
		if i > 16 { // Sample first 16 shards for performance
			break
		}
		shard.mu.RLock()
		for key, entry := range shard.entries {
			if oldestShard == nil || entry.CreatedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.CreatedAt
				oldestShard = shard
			}
		}
		shard.mu.RUnlock()
	}

	if oldestShard != nil && oldestKey != "" {
		oldestShard.mu.Lock()
		if entry, ok := oldestShard.entries[oldestKey]; ok {
			atomic.AddInt64(&c.currentSize, -int64(len(entry.Body)))
			delete(oldestShard.entries, oldestKey)
			atomic.AddUint64(&c.stats.Evictions, 1)
		}
		oldestShard.mu.Unlock()
	}
}

// cleanupLoop periodically removes expired entries.
func (c *Cache) cleanupLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.cleanupTick.C:
			c.cleanup()
		}
	}
}

// cleanup removes all expired entries.
func (c *Cache) cleanup() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if entry.IsExpired() {
				atomic.AddInt64(&c.currentSize, -int64(len(entry.Body)))
				delete(shard.entries, key)
				atomic.AddUint64(&c.stats.Expirations, 1)
			}
		}
		shard.mu.Unlock()
	}
}

// Close stops the cache cleanup routine.
func (c *Cache) Close() {
	close(c.stopCh)
	c.cleanupTick.Stop()
}

// Size returns the current cache size in bytes.
func (c *Cache) Size() int64 {
	return atomic.LoadInt64(&c.currentSize)
}

// BuildCacheKey creates a cache key from HTTP request.
func BuildCacheKey(r *http.Request, varyHeaders []string) string {
	var b bytes.Buffer

	// Method + Host + Path + Query
	b.WriteString(r.Method)
	b.WriteByte(':')
	b.WriteString(r.Host)
	b.WriteString(r.URL.Path)
	if r.URL.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(r.URL.RawQuery)
	}

	// Add Vary headers to key
	if len(varyHeaders) > 0 {
		sort.Strings(varyHeaders)
		b.WriteByte('|')
		for _, h := range varyHeaders {
			b.WriteString(h)
			b.WriteByte('=')
			b.WriteString(r.Header.Get(h))
			b.WriteByte(';')
		}
	}

	return b.String()
}

// ParseCacheControl parses Cache-Control header directives.
func ParseCacheControl(header string) map[string]string {
	directives := make(map[string]string)
	parts := strings.Split(header, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.Index(part, "="); idx != -1 {
			key := strings.ToLower(strings.TrimSpace(part[:idx]))
			value := strings.TrimSpace(part[idx+1:])
			value = strings.Trim(value, "\"")
			directives[key] = value
		} else {
			directives[strings.ToLower(part)] = ""
		}
	}

	return directives
}

// IsCacheable determines if a response can be cached based on HTTP semantics.
func IsCacheable(r *http.Request, statusCode int, respHeaders http.Header) bool {
	// Only cache safe methods
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	// Only cache success responses
	switch statusCode {
	case http.StatusOK, http.StatusNonAuthoritativeInfo, http.StatusNoContent,
		http.StatusPartialContent, http.StatusMultipleChoices, http.StatusMovedPermanently,
		http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone:
		// Cacheable status codes per RFC 7231
	default:
		return false
	}

	// Check Cache-Control directives
	cc := ParseCacheControl(respHeaders.Get("Cache-Control"))

	// Don't cache if explicitly forbidden
	if _, ok := cc["no-store"]; ok {
		return false
	}
	if _, ok := cc["private"]; ok {
		return false
	}

	// Don't cache if request had authorization without explicit cache permission
	if r.Header.Get("Authorization") != "" {
		if _, ok := cc["public"]; !ok {
			if _, ok := cc["s-maxage"]; !ok {
				return false
			}
		}
	}

	return true
}

// GetTTL extracts TTL from response headers.
func GetTTL(respHeaders http.Header, defaultTTL time.Duration) time.Duration {
	cc := ParseCacheControl(respHeaders.Get("Cache-Control"))

	// s-maxage takes precedence for shared caches
	if sMaxAge, ok := cc["s-maxage"]; ok {
		if seconds, err := strconv.ParseInt(sMaxAge, 10, 64); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}

	// Fall back to max-age
	if maxAge, ok := cc["max-age"]; ok {
		if seconds, err := strconv.ParseInt(maxAge, 10, 64); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}

	// Check Expires header as last resort
	if expires := respHeaders.Get("Expires"); expires != "" {
		if t, err := http.ParseTime(expires); err == nil {
			ttl := time.Until(t)
			if ttl > 0 {
				return ttl
			}
		}
	}

	return defaultTTL
}

// GetVaryHeaders extracts headers to vary on from the Vary header.
func GetVaryHeaders(respHeaders http.Header) []string {
	vary := respHeaders.Get("Vary")
	if vary == "" || vary == "*" {
		return nil
	}

	headers := strings.Split(vary, ",")
	result := make([]string, 0, len(headers))
	for _, h := range headers {
		h = strings.TrimSpace(h)
		if h != "" {
			result = append(result, h)
		}
	}
	return result
}
