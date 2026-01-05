// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// AccessLogConfig configures access logging.
type AccessLogConfig struct {
	Logger          *slog.Logger
	SkipPaths       []string          // paths to skip logging
	SkipHealthCheck bool              // skip health check endpoints
	LogHeaders      []string          // headers to include in logs
	MaskHeaders     []string          // headers to mask (e.g., Authorization)
	IncludeQuery    bool              // include query parameters
}

// DefaultAccessLogConfig returns default access log configuration.
func DefaultAccessLogConfig() AccessLogConfig {
	return AccessLogConfig{
		Logger:          slog.Default(),
		SkipHealthCheck: true,
		LogHeaders:      []string{"User-Agent", "X-Request-ID"},
		MaskHeaders:     []string{"Authorization", "Cookie", "X-API-Key"},
		IncludeQuery:    false,
	}
}

// accessLogResponseWriter wraps http.ResponseWriter to capture response info.
type accessLogResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

// WriteHeader captures the status code.
func (w *accessLogResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the response size.
func (w *accessLogResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

// Flush implements http.Flusher.
func (w *accessLogResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// AccessLogMiddleware logs HTTP requests.
func AccessLogMiddleware(cfg AccessLogConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check skip paths
			for _, path := range cfg.SkipPaths {
				if r.URL.Path == path {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Skip health check if configured
			if cfg.SkipHealthCheck && (r.URL.Path == "/health" || r.URL.Path == "/healthz" || r.URL.Path == "/ready") {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Wrap response writer
			lrw := &accessLogResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Process request
			next.ServeHTTP(lrw, r)

			// Calculate duration
			duration := time.Since(start)

			// Build log attributes
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", lrw.statusCode),
				slog.Duration("duration", duration),
				slog.Int("size", lrw.size),
				slog.String("remote_addr", getClientIP(r)),
				slog.String("protocol", r.Proto),
			}

			// Include query if configured
			if cfg.IncludeQuery && r.URL.RawQuery != "" {
				attrs = append(attrs, slog.String("query", r.URL.RawQuery))
			}

			// Include specified headers
			for _, header := range cfg.LogHeaders {
				if val := r.Header.Get(header); val != "" {
					attrs = append(attrs, slog.String("header_"+header, val))
				}
			}

			// Include masked headers
			for _, header := range cfg.MaskHeaders {
				if r.Header.Get(header) != "" {
					attrs = append(attrs, slog.String("header_"+header, "[MASKED]"))
				}
			}

			// Log based on status code
			if lrw.statusCode >= 500 {
				cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "request completed", attrs...)
			} else if lrw.statusCode >= 400 {
				cfg.Logger.LogAttrs(r.Context(), slog.LevelWarn, "request completed", attrs...)
			} else {
				cfg.Logger.LogAttrs(r.Context(), slog.LevelInfo, "request completed", attrs...)
			}
		})
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
