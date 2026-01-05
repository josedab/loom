// Package middleware provides HTTP middleware components.
package middleware

import (
	"fmt"
	"net/http"
	"strings"
)

// HTTP3Config configures HTTP/3 advertisement.
type HTTP3Config struct {
	// Port is the UDP port where HTTP/3 is listening
	Port int
	// MaxAge is how long (in seconds) the Alt-Svc header is valid
	MaxAge int
}

// DefaultHTTP3Config returns sensible defaults for HTTP/3 advertisement.
func DefaultHTTP3Config() HTTP3Config {
	return HTTP3Config{
		Port:   443,
		MaxAge: 86400, // 24 hours
	}
}

// HTTP3Advertise returns middleware that advertises HTTP/3 availability via Alt-Svc header.
// This enables browsers and HTTP/2 clients to discover that HTTP/3 (QUIC) is available.
// The Alt-Svc header tells clients they can upgrade to HTTP/3 for subsequent requests.
//
// Example Alt-Svc header: h3=":443"; ma=86400, h3-29=":443"; ma=86400
func HTTP3Advertise(cfg HTTP3Config) func(http.Handler) http.Handler {
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 86400
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}

	// Build Alt-Svc header value with h3 and h3-29 for broader compatibility
	altSvc := fmt.Sprintf(`h3=":%d"; ma=%d, h3-29=":%d"; ma=%d`,
		cfg.Port, cfg.MaxAge, cfg.Port, cfg.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only advertise HTTP/3 for HTTPS connections
			if r.TLS != nil || strings.HasPrefix(r.Header.Get("X-Forwarded-Proto"), "https") {
				w.Header().Set("Alt-Svc", altSvc)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// QUIC0RTTMiddleware handles HTTP/3 0-RTT early data requests.
// 0-RTT allows clients to send data before the TLS handshake completes,
// reducing latency by one round-trip time.
//
// SECURITY NOTE: 0-RTT requests can be replayed by attackers.
// Only allow 0-RTT for safe, idempotent operations (GET, HEAD).
func QUIC0RTTMiddleware(allowUnsafe bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is an early data (0-RTT) request
			if r.TLS != nil && r.TLS.DidResume {
				// For 0-RTT, only allow safe methods unless explicitly configured
				if !allowUnsafe && !isSafeMethod(r.Method) {
					// Return 425 Too Early - client should retry after handshake
					w.Header().Set("Retry-After", "0")
					http.Error(w, "Too Early", http.StatusTooEarly)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isSafeMethod returns true for HTTP methods that are safe for 0-RTT replay.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
