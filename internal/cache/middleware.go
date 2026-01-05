package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// MiddlewareConfig configures the caching middleware.
type MiddlewareConfig struct {
	// Cache is the cache instance to use
	Cache *Cache
	// DefaultTTL is the default TTL for cached responses
	DefaultTTL time.Duration
	// KeyPrefix is prepended to all cache keys
	KeyPrefix string
	// BypassHeader is the header that bypasses cache when present
	BypassHeader string
	// StaleWhileRevalidate allows serving stale content while updating
	StaleWhileRevalidate time.Duration
	// ExcludedPaths are paths that should never be cached
	ExcludedPaths []string
	// IncludedPaths are paths that should be cached (if set, only these are cached)
	IncludedPaths []string
	// Logger for cache events
	Logger *slog.Logger
}

// DefaultMiddlewareConfig returns sensible middleware defaults.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		DefaultTTL:           5 * time.Minute,
		BypassHeader:         "X-Cache-Bypass",
		StaleWhileRevalidate: 30 * time.Second,
	}
}

// responseRecorder captures the response for caching.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
	headers    http.Header
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		headers:        make(http.Header),
	}
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	// Copy headers before WriteHeader is called
	for k, v := range r.ResponseWriter.Header() {
		r.headers[k] = v
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// Middleware returns HTTP middleware that caches responses.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Cache == nil {
		cfg.Cache = New(DefaultConfig())
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.BypassHeader == "" {
		cfg.BypassHeader = "X-Cache-Bypass"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip non-cacheable methods
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			// Check bypass header
			if r.Header.Get(cfg.BypassHeader) != "" {
				w.Header().Set("X-Cache", "BYPASS")
				next.ServeHTTP(w, r)
				return
			}

			// Check excluded paths
			if isExcluded(r.URL.Path, cfg.ExcludedPaths, cfg.IncludedPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Build cache key
			cacheKey := cfg.KeyPrefix + BuildCacheKey(r, nil)

			// Try to get from cache with stale support
			if entry, found, isStale := cfg.Cache.GetWithStale(cacheKey, cfg.StaleWhileRevalidate); found {
				// Validate conditional requests
				if handled := handleConditional(w, r, entry); handled {
					w.Header().Set("X-Cache", "HIT")
					return
				}

				// Serve from cache
				serveCached(w, entry, isStale)

				// If stale, trigger background revalidation
				if isStale {
					go func() {
						revalidate(next, r.Clone(r.Context()), cfg, cacheKey)
					}()
				}
				return
			}

			// Cache miss - call handler and potentially cache
			rec := newResponseRecorder(w)
			next.ServeHTTP(rec, r)

			// Check if response is cacheable
			if !IsCacheable(r, rec.statusCode, rec.headers) {
				return
			}

			// Get TTL from response headers
			ttl := GetTTL(rec.headers, cfg.DefaultTTL)
			if ttl <= 0 {
				return
			}

			// Get Vary headers
			varyHeaders := GetVaryHeaders(rec.headers)

			// Rebuild key with Vary headers if needed
			if len(varyHeaders) > 0 {
				cacheKey = cfg.KeyPrefix + BuildCacheKey(r, varyHeaders)
			}

			// Create cache entry
			body := rec.body.Bytes()
			etag := generateETag(body)

			entry := &Entry{
				StatusCode: rec.statusCode,
				Headers:    cloneHeaders(rec.headers),
				Body:       body,
				CreatedAt:  time.Now(),
				ExpiresAt:  time.Now().Add(ttl),
				ETag:       etag,
				VaryKeys:   varyHeaders,
			}

			// Store in cache
			cfg.Cache.Set(cacheKey, entry)
			w.Header().Set("X-Cache", "MISS")

			cfg.Logger.Debug("cached response",
				"key", cacheKey,
				"ttl", ttl,
				"size", len(body))
		})
	}
}

// serveCached writes a cached response to the client.
func serveCached(w http.ResponseWriter, entry *Entry, isStale bool) {
	// Copy headers
	for k, v := range entry.Headers {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}

	// Set cache status header
	if isStale {
		w.Header().Set("X-Cache", "STALE")
	} else {
		w.Header().Set("X-Cache", "HIT")
	}

	// Set Age header
	age := int(time.Since(entry.CreatedAt).Seconds())
	w.Header().Set("Age", string(rune(age)))

	w.WriteHeader(entry.StatusCode)
	w.Write(entry.Body)
}

// handleConditional handles If-None-Match and If-Modified-Since.
func handleConditional(w http.ResponseWriter, r *http.Request, entry *Entry) bool {
	// Check If-None-Match
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if matchETag(inm, entry.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	// Check If-Modified-Since
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			if !entry.CreatedAt.After(t) {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
}

// revalidate fetches fresh content in the background.
func revalidate(handler http.Handler, r *http.Request, cfg MiddlewareConfig, cacheKey string) {
	// Create a response recorder for background fetch
	rec := &backgroundRecorder{
		headers: make(http.Header),
	}

	handler.ServeHTTP(rec, r)

	// Only cache successful responses
	if !IsCacheable(r, rec.statusCode, rec.headers) {
		return
	}

	ttl := GetTTL(rec.headers, cfg.DefaultTTL)
	if ttl <= 0 {
		return
	}

	entry := &Entry{
		StatusCode: rec.statusCode,
		Headers:    cloneHeaders(rec.headers),
		Body:       rec.body.Bytes(),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
		ETag:       generateETag(rec.body.Bytes()),
		VaryKeys:   GetVaryHeaders(rec.headers),
	}

	cfg.Cache.Set(cacheKey, entry)
	cfg.Logger.Debug("revalidated cached response", "key", cacheKey)
}

// backgroundRecorder captures responses during background revalidation.
type backgroundRecorder struct {
	statusCode int
	headers    http.Header
	body       bytes.Buffer
}

func (r *backgroundRecorder) Header() http.Header {
	return r.headers
}

func (r *backgroundRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *backgroundRecorder) WriteHeader(code int) {
	r.statusCode = code
}

// isExcluded checks if a path should be excluded from caching.
func isExcluded(path string, excluded, included []string) bool {
	// If included paths are specified, check those first
	if len(included) > 0 {
		for _, p := range included {
			if matchPath(path, p) {
				return false
			}
		}
		return true // Not in included list
	}

	// Check excluded paths
	for _, p := range excluded {
		if matchPath(path, p) {
			return true
		}
	}
	return false
}

// matchPath checks if a path matches a pattern (supports * wildcard).
func matchPath(path, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	return path == pattern
}

// matchETag checks if an ETag matches an If-None-Match header value.
func matchETag(header, etag string) bool {
	if header == "*" {
		return true
	}
	// Handle multiple ETags
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimSpace(v)
		// Handle weak ETags
		v = strings.TrimPrefix(v, "W/")
		if v == etag || v == `"`+etag+`"` {
			return true
		}
	}
	return false
}

// generateETag creates an ETag from response body.
func generateETag(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:8]) // First 8 bytes for shorter ETag
}

// cloneHeaders creates a copy of HTTP headers.
func cloneHeaders(h http.Header) http.Header {
	clone := make(http.Header, len(h))
	for k, v := range h {
		clone[k] = append([]string{}, v...)
	}
	return clone
}

// PurgeHandler returns an HTTP handler for cache purging.
func PurgeHandler(cache *Cache) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get the path/prefix to purge from request body or query
		prefix := r.URL.Query().Get("prefix")
		if prefix == "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
			prefix = string(bytes.TrimSpace(body))
		}

		if prefix == "" {
			// Clear entire cache
			cache.Clear()
			w.Write([]byte(`{"purged": "all"}`))
			return
		}

		// Purge by prefix
		count := cache.Purge(prefix)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"purged": ` + string(rune(count)) + `}`))
	})
}
