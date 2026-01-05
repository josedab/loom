// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// CompressionConfig configures response compression.
type CompressionConfig struct {
	Level           int      // gzip compression level (1-9, -1 for default)
	MinSize         int      // minimum response size to compress (default: 1024)
	ContentTypes    []string // content types to compress (default: text/*, application/json, application/javascript)
	ExcludedPaths   []string // paths to exclude from compression
}

// DefaultCompressionConfig returns default compression configuration.
func DefaultCompressionConfig() CompressionConfig {
	return CompressionConfig{
		Level:   gzip.DefaultCompression,
		MinSize: 1024,
		ContentTypes: []string{
			"text/html",
			"text/css",
			"text/plain",
			"text/javascript",
			"text/xml",
			"application/json",
			"application/javascript",
			"application/xml",
			"application/xhtml+xml",
		},
	}
}

// gzipWriterPool pools gzip writers for reuse.
var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

// gzipResponseWriter wraps http.ResponseWriter with gzip compression.
type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	config      CompressionConfig
	wroteHeader bool
	compressed  bool
	statusCode  int
	size        int
}

// WriteHeader captures the status code and decides on compression.
func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = statusCode

	// Check if we should compress
	if w.shouldCompress() {
		w.ResponseWriter.Header().Del("Content-Length") // Will change with compression
		w.ResponseWriter.Header().Set("Content-Encoding", "gzip")
		w.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
		w.compressed = true

		// Get writer from pool
		w.writer = gzipWriterPool.Get().(*gzip.Writer)
		w.writer.Reset(w.ResponseWriter)
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

// Write compresses and writes data.
func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	w.size += len(b)

	if w.compressed && w.writer != nil {
		return w.writer.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Close closes the gzip writer and returns it to the pool.
func (w *gzipResponseWriter) Close() error {
	if w.writer != nil {
		err := w.writer.Close()
		gzipWriterPool.Put(w.writer)
		w.writer = nil
		return err
	}
	return nil
}

// shouldCompress determines if the response should be compressed.
func (w *gzipResponseWriter) shouldCompress() bool {
	// Don't compress if already encoded
	if w.ResponseWriter.Header().Get("Content-Encoding") != "" {
		return false
	}

	// Check content type
	contentType := w.ResponseWriter.Header().Get("Content-Type")
	if contentType == "" {
		return false
	}

	// Extract base content type (without charset, etc.)
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	for _, ct := range w.config.ContentTypes {
		if strings.HasPrefix(ct, "text/") && strings.HasPrefix(contentType, "text/") {
			return true
		}
		if ct == contentType {
			return true
		}
	}

	return false
}

// Flush implements http.Flusher.
func (w *gzipResponseWriter) Flush() {
	if w.writer != nil {
		w.writer.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// CompressionMiddleware adds gzip compression to responses.
func CompressionMiddleware(cfg CompressionConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Wrap response writer
			gzw := &gzipResponseWriter{
				ResponseWriter: w,
				config:         cfg,
			}
			defer gzw.Close()

			next.ServeHTTP(gzw, r)
		})
	}
}
