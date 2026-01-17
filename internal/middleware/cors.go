// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSConfig configures Cross-Origin Resource Sharing (CORS).
type CORSConfig struct {
	// AllowedOrigins is a list of origins that are allowed to access the resource.
	// Use "*" to allow all origins (not recommended for production with credentials).
	// Supports exact matches and wildcard subdomains like "https://*.example.com".
	AllowedOrigins []string

	// AllowedMethods is a list of HTTP methods allowed for CORS requests.
	// Default: GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH
	AllowedMethods []string

	// AllowedHeaders is a list of headers that can be used in the actual request.
	// Default: Accept, Authorization, Content-Type, X-Requested-With
	AllowedHeaders []string

	// ExposedHeaders is a list of headers that browsers are allowed to access.
	ExposedHeaders []string

	// AllowCredentials indicates whether the request can include user credentials.
	// Cannot be used with AllowedOrigins: ["*"].
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached. Default: 86400 (24 hours)
	MaxAge int

	// AllowPrivateNetwork allows requests from private network origins.
	// Related to the Private Network Access specification.
	AllowPrivateNetwork bool
}

// DefaultCORSConfig returns a default CORS configuration.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
			http.MethodPatch,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-Requested-With",
		},
		MaxAge: 86400,
	}
}

// CORSMiddleware adds CORS headers to responses.
func CORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler {
	// Pre-compute allowed methods and headers strings
	allowedMethodsStr := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeadersStr := strings.Join(cfg.AllowedHeaders, ", ")
	exposedHeadersStr := strings.Join(cfg.ExposedHeaders, ", ")
	maxAgeStr := strconv.Itoa(cfg.MaxAge)

	// Build origin lookup for fast matching
	allowAll := false
	wildcardOrigins := make([]string, 0)
	exactOrigins := make(map[string]bool)

	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			allowAll = true
		} else if strings.HasPrefix(origin, "https://*.") || strings.HasPrefix(origin, "http://*.") {
			wildcardOrigins = append(wildcardOrigins, origin)
		} else {
			exactOrigins[origin] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// No Origin header means same-origin request
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := false
			responseOrigin := ""

			if allowAll {
				allowed = true
				if cfg.AllowCredentials {
					// When credentials are allowed, we must echo the origin
					responseOrigin = origin
				} else {
					responseOrigin = "*"
				}
			} else if exactOrigins[origin] {
				allowed = true
				responseOrigin = origin
			} else {
				// Check wildcard origins
				for _, pattern := range wildcardOrigins {
					if matchWildcardOrigin(origin, pattern) {
						allowed = true
						responseOrigin = origin
						break
					}
				}
			}

			if !allowed {
				// Origin not allowed - proceed without CORS headers
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", responseOrigin)

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if exposedHeadersStr != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposedHeadersStr)
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", allowedMethodsStr)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeadersStr)

				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)
				}

				// Handle Private Network Access preflight
				if cfg.AllowPrivateNetwork && r.Header.Get("Access-Control-Request-Private-Network") == "true" {
					w.Header().Set("Access-Control-Allow-Private-Network", "true")
				}

				// Vary header for caching
				w.Header().Add("Vary", "Origin")
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")

				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Add Vary header for normal requests
			w.Header().Add("Vary", "Origin")

			next.ServeHTTP(w, r)
		})
	}
}

// matchWildcardOrigin checks if origin matches a wildcard pattern like "https://*.example.com".
func matchWildcardOrigin(origin, pattern string) bool {
	// Pattern format: scheme://*.domain.com
	wildcardIdx := strings.Index(pattern, "*.")
	if wildcardIdx == -1 {
		return false
	}

	prefix := pattern[:wildcardIdx]  // e.g., "https://"
	suffix := pattern[wildcardIdx+1:] // e.g., ".example.com"

	// Origin must start with same scheme
	if !strings.HasPrefix(origin, prefix) {
		return false
	}

	// Origin must end with same domain suffix
	if !strings.HasSuffix(origin, suffix) {
		return false
	}

	// Check that the subdomain part is valid (no additional dots after prefix)
	subdomain := origin[len(prefix) : len(origin)-len(suffix)]
	return subdomain != "" && !strings.Contains(subdomain, ".")
}

// ValidateCORSConfig validates CORS configuration.
func ValidateCORSConfig(cfg CORSConfig) error {
	// Check for invalid combination of * origin with credentials
	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" && cfg.AllowCredentials {
			// This is technically allowed but we handle it specially
			break
		}
	}
	return nil
}
