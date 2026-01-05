// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIKeyConfig configures API key authentication.
type APIKeyConfig struct {
	// Keys maps API key values to their metadata
	Keys map[string]APIKeyInfo

	// Header to check for API key (default: X-API-Key)
	Header string

	// QueryParam to check for API key (optional, e.g., "api_key")
	QueryParam string

	// ExcludedPaths are paths that don't require authentication
	ExcludedPaths []string

	// Realm for WWW-Authenticate header
	Realm string
}

// APIKeyInfo contains metadata about an API key.
type APIKeyInfo struct {
	Name        string            // Human-readable name
	Roles       []string          // Roles/permissions
	RateLimit   float64           // Per-key rate limit (0 = use default)
	Metadata    map[string]string // Additional metadata
	ExpiresAt   time.Time         // Expiration time (zero = never)
	AllowedIPs  []string          // Allowed IP addresses (empty = all)
}

// APIKeyContextKey is the context key for API key info.
type APIKeyContextKey struct{}

// DefaultAPIKeyConfig returns default API key configuration.
func DefaultAPIKeyConfig() APIKeyConfig {
	return APIKeyConfig{
		Header:        "X-API-Key",
		Realm:         "API",
		Keys:          make(map[string]APIKeyInfo),
		ExcludedPaths: []string{"/health", "/healthz", "/ready"},
	}
}

// APIKeyMiddleware provides API key authentication.
func APIKeyMiddleware(cfg APIKeyConfig) func(http.Handler) http.Handler {
	if cfg.Header == "" {
		cfg.Header = "X-API-Key"
	}
	if cfg.Realm == "" {
		cfg.Realm = "API"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/") {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract API key
			apiKey := r.Header.Get(cfg.Header)
			if apiKey == "" && cfg.QueryParam != "" {
				apiKey = r.URL.Query().Get(cfg.QueryParam)
			}

			if apiKey == "" {
				w.Header().Set("WWW-Authenticate", `API-Key realm="`+cfg.Realm+`"`)
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			// Validate API key using constant-time comparison
			var keyInfo *APIKeyInfo
			for key, info := range cfg.Keys {
				if subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1 {
					keyInfo = &info
					break
				}
			}

			if keyInfo == nil {
				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			// Check expiration
			if !keyInfo.ExpiresAt.IsZero() && time.Now().After(keyInfo.ExpiresAt) {
				http.Error(w, "API key expired", http.StatusUnauthorized)
				return
			}

			// Check IP allowlist
			if len(keyInfo.AllowedIPs) > 0 {
				clientIP := getClientIP(r)
				allowed := false
				for _, ip := range keyInfo.AllowedIPs {
					if ip == clientIP || strings.HasPrefix(clientIP, ip) {
						allowed = true
						break
					}
				}
				if !allowed {
					http.Error(w, "IP not allowed for this API key", http.StatusForbidden)
					return
				}
			}

			// Add key info to context
			ctx := context.WithValue(r.Context(), APIKeyContextKey{}, keyInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAPIKeyInfo extracts API key info from context.
func GetAPIKeyInfo(ctx context.Context) *APIKeyInfo {
	if info, ok := ctx.Value(APIKeyContextKey{}).(*APIKeyInfo); ok {
		return info
	}
	return nil
}

// BasicAuthConfig configures HTTP Basic authentication.
type BasicAuthConfig struct {
	// Users maps username to password hash
	Users map[string]string

	// Realm for WWW-Authenticate header
	Realm string

	// ExcludedPaths are paths that don't require authentication
	ExcludedPaths []string

	// HashFunc optional function to hash passwords for comparison
	// If nil, plain text comparison is used (not recommended for production)
	HashFunc func(password string) string
}

// BasicAuthMiddleware provides HTTP Basic authentication.
func BasicAuthMiddleware(cfg BasicAuthConfig) func(http.Handler) http.Handler {
	if cfg.Realm == "" {
		cfg.Realm = "Restricted"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/") {
					next.ServeHTTP(w, r)
					return
				}
			}

			username, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+cfg.Realm+`"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			expectedHash, exists := cfg.Users[username]
			if !exists {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+cfg.Realm+`"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Hash password if hash function provided
			passwordToCompare := password
			if cfg.HashFunc != nil {
				passwordToCompare = cfg.HashFunc(password)
			}

			// Constant time comparison
			if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(passwordToCompare)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+cfg.Realm+`"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// JWTConfig configures JWT authentication.
type JWTConfig struct {
	// Secret for HMAC algorithms
	Secret []byte

	// PublicKey for RSA/ECDSA algorithms (PEM encoded)
	PublicKey []byte

	// Algorithm: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
	Algorithm string

	// Header to extract token from (default: Authorization with Bearer prefix)
	Header string

	// TokenPrefix (default: "Bearer ")
	TokenPrefix string

	// ExcludedPaths are paths that don't require authentication
	ExcludedPaths []string

	// ClaimsContextKey is the context key for claims (default: "claims")
	ClaimsContextKey string
}

// Note: JWT implementation would require a JWT library like github.com/golang-jwt/jwt/v5
// This is a placeholder showing the interface pattern

// TokenBucket implements per-key rate limiting with API key integration.
type TokenBucketPerKey struct {
	buckets map[string]*bucket
	mu      sync.RWMutex
	defaults RateLimiterConfig
}

// NewTokenBucketPerKey creates a token bucket rate limiter per API key.
func NewTokenBucketPerKey(defaults RateLimiterConfig) *TokenBucketPerKey {
	return &TokenBucketPerKey{
		buckets:  make(map[string]*bucket),
		defaults: defaults,
	}
}

// Allow checks if a request is allowed based on API key rate limit.
func (tb *TokenBucketPerKey) Allow(keyInfo *APIKeyInfo, clientKey string) bool {
	rate := tb.defaults.Rate
	burst := tb.defaults.Burst

	// Use key-specific rate limit if set
	if keyInfo != nil && keyInfo.RateLimit > 0 {
		rate = keyInfo.RateLimit
		burst = int(keyInfo.RateLimit)
	}

	tb.mu.RLock()
	b, exists := tb.buckets[clientKey]
	tb.mu.RUnlock()

	if !exists {
		tb.mu.Lock()
		if b, exists = tb.buckets[clientKey]; !exists {
			b = &bucket{
				tokens:     float64(burst),
				lastUpdate: time.Now(),
			}
			tb.buckets[clientKey] = b
		}
		tb.mu.Unlock()
	}

	return b.take(rate, burst)
}
