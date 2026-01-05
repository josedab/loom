package shadow

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
)

// MiddlewareConfig configures the shadow middleware.
type MiddlewareConfig struct {
	// Manager is the shadow traffic manager
	Manager *Manager
	// RouteIDFunc extracts the route ID from the request
	RouteIDFunc func(*http.Request) string
	// MaxBodySize is the maximum body size to buffer for shadowing
	MaxBodySize int64
	// Logger for shadow events
	Logger *slog.Logger
}

// DefaultMiddlewareConfig returns sensible defaults.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		MaxBodySize: 1024 * 1024, // 1MB
	}
}

// Middleware returns HTTP middleware that shadows requests to configured targets.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1024 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get route ID
			routeID := ""
			if cfg.RouteIDFunc != nil {
				routeID = cfg.RouteIDFunc(r)
			}

			if routeID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if there's shadow config for this route
			shadowCfg, ok := cfg.Manager.GetConfig(routeID)
			if !ok || len(shadowCfg.Targets) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Buffer the body for shadowing (if present)
			var body []byte
			if r.Body != nil && r.ContentLength > 0 && r.ContentLength <= cfg.MaxBodySize {
				var err error
				body, err = io.ReadAll(io.LimitReader(r.Body, cfg.MaxBodySize))
				if err != nil {
					cfg.Logger.Debug("failed to read body for shadow",
						"route", routeID,
						"error", err)
				}
				// Restore body for the main handler
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			// Send shadow requests (non-blocking)
			cfg.Manager.Shadow(routeID, r, body)

			// Continue with main request
			next.ServeHTTP(w, r)
		})
	}
}

// CompareMiddleware returns middleware that compares responses between
// the primary service and shadow targets. This is useful for validating
// that a new service version returns correct responses.
type CompareConfig struct {
	// Manager is the shadow traffic manager
	Manager *Manager
	// RouteIDFunc extracts the route ID from the request
	RouteIDFunc func(*http.Request) string
	// CompareFunc compares primary and shadow responses
	CompareFunc func(primary, shadow *Response) bool
	// OnMismatch is called when responses don't match
	OnMismatch func(r *http.Request, primary, shadow *Response)
	// Logger for comparison events
	Logger *slog.Logger
}

// Response holds captured response data for comparison.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// responseRecorder captures the response for comparison.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}
