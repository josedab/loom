package cache

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Common errors.
var (
	ErrCacheMiss        = errors.New("cache miss")
	ErrRedisUnavailable = errors.New("redis unavailable")
)

// RedisConfig configures the Redis-backed cache.
type RedisConfig struct {
	// Redis client options
	Address  string // Redis server address (e.g., "localhost:6379")
	Password string // Redis password (optional)
	DB       int    // Redis database number

	// Cache options
	DefaultTTL           time.Duration // Default TTL for entries (default: 5 minutes)
	KeyPrefix            string        // Prefix for cache keys (default: "loom:cache:")
	StaleWhileRevalidate time.Duration // Stale window for serving stale content (default: 30s)

	// Behavior options
	FallbackOnError bool // If true, treat Redis errors as cache misses
	Compression     bool // If true, compress cached entries (future enhancement)
}

// RedisCache provides distributed caching using Redis.
type RedisCache struct {
	client               *redis.Client
	keyPrefix            string
	defaultTTL           time.Duration
	staleWindow          time.Duration
	fallbackOnError      bool
	stats                *RedisStats
	statsKeyPrefix       string
	localStatsEnabled    bool
}

// RedisStats tracks cache statistics.
type RedisStats struct {
	Hits        uint64
	Misses      uint64
	Errors      uint64
	StaleHits   uint64
}

// NewRedisCache creates a new Redis-backed cache.
func NewRedisCache(cfg RedisConfig) (*RedisCache, error) {
	if cfg.Address == "" {
		return nil, errors.New("redis address is required")
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "loom:cache:"
	}
	if cfg.StaleWhileRevalidate <= 0 {
		cfg.StaleWhileRevalidate = 30 * time.Second
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &RedisCache{
		client:            client,
		keyPrefix:         cfg.KeyPrefix,
		defaultTTL:        cfg.DefaultTTL,
		staleWindow:       cfg.StaleWhileRevalidate,
		fallbackOnError:   cfg.FallbackOnError,
		stats:             &RedisStats{},
		statsKeyPrefix:    cfg.KeyPrefix + "stats:",
		localStatsEnabled: true,
	}, nil
}

// NewRedisCacheWithClient creates a cache with an existing Redis client.
func NewRedisCacheWithClient(client *redis.Client, cfg RedisConfig) *RedisCache {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "loom:cache:"
	}
	if cfg.StaleWhileRevalidate <= 0 {
		cfg.StaleWhileRevalidate = 30 * time.Second
	}

	return &RedisCache{
		client:            client,
		keyPrefix:         cfg.KeyPrefix,
		defaultTTL:        cfg.DefaultTTL,
		staleWindow:       cfg.StaleWhileRevalidate,
		fallbackOnError:   cfg.FallbackOnError,
		stats:             &RedisStats{},
		statsKeyPrefix:    cfg.KeyPrefix + "stats:",
		localStatsEnabled: true,
	}
}

// redisEntry is the serializable form of a cache entry.
type redisEntry struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	CreatedAt  int64 // Unix timestamp
	ExpiresAt  int64 // Unix timestamp
	ETag       string
	VaryKeys   []string
}

// toRedisEntry converts an Entry to a serializable form.
func toRedisEntry(e *Entry) *redisEntry {
	return &redisEntry{
		StatusCode: e.StatusCode,
		Headers:    e.Headers,
		Body:       e.Body,
		CreatedAt:  e.CreatedAt.UnixNano(),
		ExpiresAt:  e.ExpiresAt.UnixNano(),
		ETag:       e.ETag,
		VaryKeys:   e.VaryKeys,
	}
}

// toEntry converts a redisEntry back to an Entry.
func (re *redisEntry) toEntry() *Entry {
	return &Entry{
		StatusCode: re.StatusCode,
		Headers:    re.Headers,
		Body:       re.Body,
		CreatedAt:  time.Unix(0, re.CreatedAt),
		ExpiresAt:  time.Unix(0, re.ExpiresAt),
		ETag:       re.ETag,
		VaryKeys:   re.VaryKeys,
	}
}

// encode serializes an entry to bytes using gob.
func (rc *RedisCache) encode(entry *Entry) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(toRedisEntry(entry)); err != nil {
		return nil, fmt.Errorf("failed to encode entry: %w", err)
	}
	return buf.Bytes(), nil
}

// decode deserializes bytes to an entry using gob.
func (rc *RedisCache) decode(data []byte) (*Entry, error) {
	var re redisEntry
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&re); err != nil {
		return nil, fmt.Errorf("failed to decode entry: %w", err)
	}
	return re.toEntry(), nil
}

// fullKey returns the full Redis key with prefix.
func (rc *RedisCache) fullKey(key string) string {
	return rc.keyPrefix + key
}

// Get retrieves an entry from the cache.
func (rc *RedisCache) Get(ctx context.Context, key string) (*Entry, bool) {
	fullKey := rc.fullKey(key)

	data, err := rc.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			atomic.AddUint64(&rc.stats.Misses, 1)
			return nil, false
		}
		atomic.AddUint64(&rc.stats.Errors, 1)
		if rc.fallbackOnError {
			return nil, false
		}
		return nil, false
	}

	entry, err := rc.decode(data)
	if err != nil {
		atomic.AddUint64(&rc.stats.Errors, 1)
		return nil, false
	}

	// Check logical expiration (even though Redis TTL may still be valid for stale serving)
	if entry.IsExpired() {
		atomic.AddUint64(&rc.stats.Misses, 1)
		return nil, false
	}

	atomic.AddUint64(&rc.stats.Hits, 1)
	return entry, true
}

// GetWithStale retrieves an entry, allowing stale content within the stale window.
func (rc *RedisCache) GetWithStale(ctx context.Context, key string) (*Entry, bool, bool) {
	fullKey := rc.fullKey(key)

	data, err := rc.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			atomic.AddUint64(&rc.stats.Misses, 1)
			return nil, false, false
		}
		atomic.AddUint64(&rc.stats.Errors, 1)
		return nil, false, false
	}

	entry, err := rc.decode(data)
	if err != nil {
		atomic.AddUint64(&rc.stats.Errors, 1)
		return nil, false, false
	}

	if entry.IsExpired() {
		if entry.IsStale(rc.staleWindow) {
			atomic.AddUint64(&rc.stats.StaleHits, 1)
			return entry, true, true // entry, found, isStale
		}
		atomic.AddUint64(&rc.stats.Misses, 1)
		return nil, false, false
	}

	atomic.AddUint64(&rc.stats.Hits, 1)
	return entry, true, false
}

// Set stores an entry in the cache with the default TTL.
func (rc *RedisCache) Set(ctx context.Context, key string, entry *Entry) error {
	return rc.SetWithTTL(ctx, key, entry, rc.defaultTTL)
}

// SetWithTTL stores an entry with a specific TTL.
func (rc *RedisCache) SetWithTTL(ctx context.Context, key string, entry *Entry, ttl time.Duration) error {
	// Set logical expiration
	entry.ExpiresAt = time.Now().Add(ttl)
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	data, err := rc.encode(entry)
	if err != nil {
		return err
	}

	fullKey := rc.fullKey(key)

	// Store with extended TTL to allow stale serving
	redisTTL := ttl + rc.staleWindow

	if err := rc.client.Set(ctx, fullKey, data, redisTTL).Err(); err != nil {
		atomic.AddUint64(&rc.stats.Errors, 1)
		if rc.fallbackOnError {
			return nil
		}
		return fmt.Errorf("redis set failed: %w", err)
	}

	return nil
}

// Delete removes an entry from the cache.
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	fullKey := rc.fullKey(key)
	if err := rc.client.Del(ctx, fullKey).Err(); err != nil {
		if rc.fallbackOnError {
			return nil
		}
		return fmt.Errorf("redis delete failed: %w", err)
	}
	return nil
}

// Purge removes all entries matching a prefix.
func (rc *RedisCache) Purge(ctx context.Context, prefix string) (int64, error) {
	pattern := rc.fullKey(prefix) + "*"

	var cursor uint64
	var totalDeleted int64

	for {
		keys, nextCursor, err := rc.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			if rc.fallbackOnError {
				return totalDeleted, nil
			}
			return totalDeleted, fmt.Errorf("redis scan failed: %w", err)
		}

		if len(keys) > 0 {
			deleted, err := rc.client.Del(ctx, keys...).Result()
			if err != nil {
				if rc.fallbackOnError {
					return totalDeleted, nil
				}
				return totalDeleted, fmt.Errorf("redis delete failed: %w", err)
			}
			totalDeleted += deleted
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return totalDeleted, nil
}

// Clear removes all entries with the cache key prefix.
func (rc *RedisCache) Clear(ctx context.Context) error {
	_, err := rc.Purge(ctx, "")
	return err
}

// Close closes the Redis connection.
func (rc *RedisCache) Close() error {
	return rc.client.Close()
}

// GetStats returns current cache statistics.
func (rc *RedisCache) GetStats() RedisStats {
	return RedisStats{
		Hits:      atomic.LoadUint64(&rc.stats.Hits),
		Misses:    atomic.LoadUint64(&rc.stats.Misses),
		Errors:    atomic.LoadUint64(&rc.stats.Errors),
		StaleHits: atomic.LoadUint64(&rc.stats.StaleHits),
	}
}

// Info returns information about the cache from Redis.
func (rc *RedisCache) Info(ctx context.Context) (*RedisCacheInfo, error) {
	pattern := rc.fullKey("*")

	// Count keys
	var keyCount int64
	var cursor uint64
	for {
		keys, nextCursor, err := rc.client.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return nil, fmt.Errorf("redis scan failed: %w", err)
		}
		keyCount += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	// Get memory info for a sample of keys
	var totalMemory int64
	if keyCount > 0 {
		sampleKeys, _, _ := rc.client.Scan(ctx, 0, pattern, 100).Result()
		for _, key := range sampleKeys {
			mem, err := rc.client.MemoryUsage(ctx, key).Result()
			if err == nil {
				totalMemory += mem
			}
		}
		// Extrapolate if we sampled
		if len(sampleKeys) > 0 && keyCount > int64(len(sampleKeys)) {
			avgMem := totalMemory / int64(len(sampleKeys))
			totalMemory = avgMem * keyCount
		}
	}

	return &RedisCacheInfo{
		KeyCount:        keyCount,
		EstimatedMemory: totalMemory,
		KeyPrefix:       rc.keyPrefix,
		DefaultTTL:      rc.defaultTTL,
		StaleWindow:     rc.staleWindow,
	}, nil
}

// RedisCacheInfo contains information about the Redis cache.
type RedisCacheInfo struct {
	KeyCount        int64
	EstimatedMemory int64
	KeyPrefix       string
	DefaultTTL      time.Duration
	StaleWindow     time.Duration
}

// Exists checks if a key exists in the cache.
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := rc.fullKey(key)
	count, err := rc.client.Exists(ctx, fullKey).Result()
	if err != nil {
		if rc.fallbackOnError {
			return false, nil
		}
		return false, fmt.Errorf("redis exists failed: %w", err)
	}
	return count > 0, nil
}

// Touch updates the TTL of an existing entry without modifying its content.
func (rc *RedisCache) Touch(ctx context.Context, key string, ttl time.Duration) error {
	fullKey := rc.fullKey(key)

	// Get existing entry
	data, err := rc.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrCacheMiss
		}
		return fmt.Errorf("redis get failed: %w", err)
	}

	entry, err := rc.decode(data)
	if err != nil {
		return err
	}

	// Update expiration and re-store
	entry.ExpiresAt = time.Now().Add(ttl)
	return rc.SetWithTTL(ctx, key, entry, ttl)
}

// GetMulti retrieves multiple entries from the cache.
func (rc *RedisCache) GetMulti(ctx context.Context, keys []string) (map[string]*Entry, error) {
	if len(keys) == 0 {
		return make(map[string]*Entry), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = rc.fullKey(key)
	}

	values, err := rc.client.MGet(ctx, fullKeys...).Result()
	if err != nil {
		atomic.AddUint64(&rc.stats.Errors, 1)
		if rc.fallbackOnError {
			return make(map[string]*Entry), nil
		}
		return nil, fmt.Errorf("redis mget failed: %w", err)
	}

	result := make(map[string]*Entry)
	for i, val := range values {
		if val == nil {
			atomic.AddUint64(&rc.stats.Misses, 1)
			continue
		}

		data, ok := val.(string)
		if !ok {
			continue
		}

		entry, err := rc.decode([]byte(data))
		if err != nil {
			atomic.AddUint64(&rc.stats.Errors, 1)
			continue
		}

		if entry.IsExpired() {
			atomic.AddUint64(&rc.stats.Misses, 1)
			continue
		}

		atomic.AddUint64(&rc.stats.Hits, 1)
		result[keys[i]] = entry
	}

	return result, nil
}

// SetMulti stores multiple entries in the cache.
func (rc *RedisCache) SetMulti(ctx context.Context, entries map[string]*Entry) error {
	return rc.SetMultiWithTTL(ctx, entries, rc.defaultTTL)
}

// SetMultiWithTTL stores multiple entries with a specific TTL.
func (rc *RedisCache) SetMultiWithTTL(ctx context.Context, entries map[string]*Entry, ttl time.Duration) error {
	if len(entries) == 0 {
		return nil
	}

	pipe := rc.client.Pipeline()
	redisTTL := ttl + rc.staleWindow

	for key, entry := range entries {
		entry.ExpiresAt = time.Now().Add(ttl)
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now()
		}

		data, err := rc.encode(entry)
		if err != nil {
			continue
		}

		fullKey := rc.fullKey(key)
		pipe.Set(ctx, fullKey, data, redisTTL)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		atomic.AddUint64(&rc.stats.Errors, 1)
		if rc.fallbackOnError {
			return nil
		}
		return fmt.Errorf("redis pipeline exec failed: %w", err)
	}

	return nil
}

// DeleteMulti removes multiple entries from the cache.
func (rc *RedisCache) DeleteMulti(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = rc.fullKey(key)
	}

	if err := rc.client.Del(ctx, fullKeys...).Err(); err != nil {
		if rc.fallbackOnError {
			return nil
		}
		return fmt.Errorf("redis delete failed: %w", err)
	}
	return nil
}

// RedisCacheMiddlewareConfig configures the Redis caching middleware.
type RedisCacheMiddlewareConfig struct {
	// DefaultTTL is the default TTL for cached responses
	DefaultTTL time.Duration
	// BypassHeader is the header that bypasses cache when present
	BypassHeader string
	// StaleWhileRevalidate allows serving stale content while updating
	StaleWhileRevalidate time.Duration
	// ExcludedPaths are paths that should never be cached
	ExcludedPaths []string
}

// RedisCacheMiddleware returns HTTP middleware for Redis-backed caching.
func RedisCacheMiddleware(cache *RedisCache, cfg RedisCacheMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.BypassHeader == "" {
		cfg.BypassHeader = "X-Cache-Bypass"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Only cache GET and HEAD
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Check bypass header
			if cfg.BypassHeader != "" && r.Header.Get(cfg.BypassHeader) != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if matchRedisExcludedPath(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Build cache key
			cacheKey := BuildCacheKey(r, nil)

			// Try to get from cache
			entry, found, isStale := cache.GetWithStale(ctx, cacheKey)
			if found {
				// Serve cached response
				for key, values := range entry.Headers {
					for _, v := range values {
						w.Header().Add(key, v)
					}
				}
				if isStale {
					w.Header().Set("X-Cache", "STALE")
				} else {
					w.Header().Set("X-Cache", "HIT")
				}
				w.WriteHeader(entry.StatusCode)
				w.Write(entry.Body)

				// If stale, trigger background revalidation
				if isStale && cfg.StaleWhileRevalidate > 0 {
					go func() {
						// Create a new context for background revalidation
						bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()

						// Create a new request for revalidation
						bgReq := r.Clone(bgCtx)
						bgReq.Header.Set(cfg.BypassHeader, "revalidate")

						rec := &redisBgRecorder{
							headers: make(http.Header),
						}
						next.ServeHTTP(rec, bgReq)

						if IsCacheable(bgReq, rec.statusCode, rec.headers) {
							ttl := GetTTL(rec.headers, cfg.DefaultTTL)
							newEntry := &Entry{
								StatusCode: rec.statusCode,
								Headers:    rec.headers,
								Body:       rec.body.Bytes(),
								CreatedAt:  time.Now(),
								ExpiresAt:  time.Now().Add(ttl),
								VaryKeys:   GetVaryHeaders(rec.headers),
							}
							cache.SetWithTTL(bgCtx, cacheKey, newEntry, ttl)
						}
					}()
				}
				return
			}

			// Cache miss - execute handler and capture response
			rec := newResponseRecorder(w)
			next.ServeHTTP(rec, r)

			w.Header().Set("X-Cache", "MISS")

			// Cache if cacheable
			if IsCacheable(r, rec.statusCode, rec.headers) {
				ttl := GetTTL(rec.headers, cfg.DefaultTTL)
				newEntry := &Entry{
					StatusCode: rec.statusCode,
					Headers:    cloneHeaders(rec.headers),
					Body:       rec.body.Bytes(),
					CreatedAt:  time.Now(),
					ExpiresAt:  time.Now().Add(ttl),
					VaryKeys:   GetVaryHeaders(rec.headers),
				}
				cache.SetWithTTL(ctx, cacheKey, newEntry, ttl)
			}
		})
	}
}

// redisBgRecorder captures responses during background revalidation for Redis cache.
type redisBgRecorder struct {
	statusCode int
	headers    http.Header
	body       bytes.Buffer
}

func (r *redisBgRecorder) Header() http.Header {
	return r.headers
}

func (r *redisBgRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *redisBgRecorder) WriteHeader(code int) {
	r.statusCode = code
}

// matchRedisExcludedPath checks if a path matches an excluded pattern.
func matchRedisExcludedPath(path, pattern string) bool {
	if pattern == path {
		return true
	}
	// Handle wildcard suffix
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}
