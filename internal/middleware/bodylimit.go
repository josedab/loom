// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"errors"
	"io"
	"net/http"
	"sync"
)

// BodyLimitConfig configures body size limiting.
type BodyLimitConfig struct {
	MaxSize       int64    // Maximum body size in bytes (default: 1MB)
	ExcludedPaths []string // Paths to exclude from limit
}

// DefaultBodyLimitConfig returns default body limit configuration.
func DefaultBodyLimitConfig() BodyLimitConfig {
	return BodyLimitConfig{
		MaxSize: 1 << 20, // 1MB
	}
}

// ErrBodyTooLarge is returned when the request body exceeds the limit.
var ErrBodyTooLarge = errors.New("request body too large")

// limitedReader wraps an io.ReadCloser with a size limit.
type limitedReader struct {
	reader    io.ReadCloser
	remaining int64
	mu        sync.Mutex
}

// Read reads from the underlying reader up to the limit.
func (lr *limitedReader) Read(p []byte) (int, error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	if lr.remaining <= 0 {
		return 0, ErrBodyTooLarge
	}

	if int64(len(p)) > lr.remaining {
		p = p[:lr.remaining]
	}

	n, err := lr.reader.Read(p)
	lr.remaining -= int64(n)

	return n, err
}

// Close closes the underlying reader.
func (lr *limitedReader) Close() error {
	return lr.reader.Close()
}

// BodyLimitMiddleware limits request body size.
func BodyLimitMiddleware(cfg BodyLimitConfig) func(http.Handler) http.Handler {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1 << 20 // 1MB default
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if r.URL.Path == path {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Skip for requests without body
			if r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}

			// Check Content-Length header first for early rejection
			if r.ContentLength > cfg.MaxSize {
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}

			// Wrap the body with a limited reader
			r.Body = &limitedReader{
				reader:    r.Body,
				remaining: cfg.MaxSize,
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MaxBytesHandler is an alternative using http.MaxBytesReader.
// This provides slightly different behavior - it closes the connection
// on exceeding the limit rather than returning an error on read.
func MaxBytesMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
