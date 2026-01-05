// Package proxy provides the main HTTP proxy handler.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/upstream"
	"github.com/google/uuid"
)

// DefaultMaxResponseBodySize is the default maximum response body size (100MB).
const DefaultMaxResponseBodySize = 100 * 1024 * 1024

// Handler is the main HTTP proxy handler.
type Handler struct {
	router              *router.Router
	upstreams           *upstream.Manager
	pipeline            *plugin.Pipeline
	metrics             *metrics.Metrics
	maxResponseBodySize int64       // Maximum response body size (0 = unlimited)
	logWorkerPool       *WorkerPool // Bounded worker pool for async log phase execution
}

// HandlerOption is a functional option for configuring the Handler.
type HandlerOption func(*Handler)

// WithMaxResponseBodySize sets the maximum response body size.
func WithMaxResponseBodySize(size int64) HandlerOption {
	return func(h *Handler) {
		h.maxResponseBodySize = size
	}
}

// WithLogWorkerPool sets a custom worker pool for async log phase execution.
func WithLogWorkerPool(pool *WorkerPool) HandlerOption {
	return func(h *Handler) {
		h.logWorkerPool = pool
	}
}

// NewHandler creates a new proxy handler.
func NewHandler(
	r *router.Router,
	u *upstream.Manager,
	p *plugin.Pipeline,
	m *metrics.Metrics,
	opts ...HandlerOption,
) *Handler {
	h := &Handler{
		router:              r,
		upstreams:           u,
		pipeline:            p,
		metrics:             m,
		maxResponseBodySize: DefaultMaxResponseBodySize,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Create default worker pool if not provided
	if h.logWorkerPool == nil {
		h.logWorkerPool = NewWorkerPool(DefaultWorkerPoolConfig())
	}
	return h
}

// ServeHTTP handles incoming HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Match route
	match := h.router.Match(r)
	if match == nil {
		h.router.NotFoundHandler().ServeHTTP(w, r)
		return
	}

	route := match.Route

	// Acquire request context from pool for plugins
	reqCtx := plugin.AcquireRequestContext()
	for k, v := range r.Header {
		if len(v) > 0 {
			reqCtx.RequestHeaders[k] = v[0]
		}
	}

	// Add path parameters to properties
	for k, v := range match.Params {
		reqCtx.Properties["path."+k] = []byte(v)
	}

	// Execute request headers phase
	result, err := h.pipeline.ExecuteRequestPhase(
		r.Context(),
		route.ID,
		plugin.PhaseOnRequestHeaders,
		reqCtx,
	)
	if err != nil {
		plugin.ReleaseRequestContext(reqCtx)
		h.handleError(w, err, http.StatusInternalServerError)
		return
	}

	if !result.Continue {
		plugin.ReleaseRequestContext(reqCtx)
		if result.ImmediateResponse != nil {
			h.writeImmediateResponse(w, result.ImmediateResponse)
		}
		return
	}

	// Apply modified headers
	for k, v := range reqCtx.RequestHeaders {
		r.Header.Set(k, v)
	}

	// Strip prefix if configured
	if route.StripPrefix && strings.HasPrefix(r.URL.Path, route.Path) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(route.Path, "/*"))
		if !strings.HasPrefix(r.URL.Path, "/") {
			r.URL.Path = "/" + r.URL.Path
		}
	}

	// Set timeout
	ctx := r.Context()
	if route.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, route.Timeout)
		defer cancel()
	}

	// Proxy to upstream
	resp, err := h.upstreams.ProxyRequest(ctx, route.Upstream, r)
	if err != nil {
		plugin.ReleaseRequestContext(reqCtx)
		h.handleProxyError(w, err)
		return
	}
	defer resp.Body.Close()

	// Capture response headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			reqCtx.ResponseHeaders[k] = v[0]
		}
	}

	// Execute response headers phase
	result, err = h.pipeline.ExecuteResponsePhase(
		ctx,
		route.ID,
		plugin.PhaseOnResponseHeaders,
		reqCtx,
	)
	if err != nil {
		plugin.ReleaseRequestContext(reqCtx)
		h.handleError(w, err, http.StatusInternalServerError)
		return
	}

	if !result.Continue {
		plugin.ReleaseRequestContext(reqCtx)
		if result.ImmediateResponse != nil {
			h.writeImmediateResponse(w, result.ImmediateResponse)
		}
		return
	}

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// Apply modified headers
	for k, v := range reqCtx.ResponseHeaders {
		w.Header().Set(k, v)
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body with optional size limit
	var bodyReader io.Reader = resp.Body
	if h.maxResponseBodySize > 0 {
		bodyReader = io.LimitReader(resp.Body, h.maxResponseBodySize)
	}

	written, err := io.Copy(w, bodyReader)
	if err != nil {
		// Log the error but don't try to write an HTTP error since headers are already sent
		slog.Error("error copying response body",
			"error", err,
			"route", route.ID,
			"method", r.Method,
			"path", r.URL.Path,
			"bytes_written", written,
		)
	}

	// Warn if response was truncated due to size limit
	if h.maxResponseBodySize > 0 && written >= h.maxResponseBodySize {
		slog.Warn("response body truncated due to size limit",
			"route", route.ID,
			"limit", h.maxResponseBodySize,
			"written", written,
		)
	}

	// Record metrics
	duration := time.Since(start)
	h.metrics.RecordRequest(r.Method, route.ID, resp.StatusCode, duration, r.ContentLength, written)

	// Execute log phase (async) - use bounded worker pool to prevent goroutine explosion
	routeID := route.ID // capture for closure
	h.logWorkerPool.Submit(func() {
		defer plugin.ReleaseRequestContext(reqCtx)
		h.pipeline.ExecuteRequestPhase(
			context.Background(),
			routeID,
			plugin.PhaseOnLog,
			reqCtx,
		)
	})
}

// handleError handles internal errors.
func (h *Handler) handleError(w http.ResponseWriter, err error, statusCode int) {
	http.Error(w, err.Error(), statusCode)
}

// handleProxyError handles proxy errors.
func (h *Handler) handleProxyError(w http.ResponseWriter, err error) {
	switch err {
	case upstream.ErrNoHealthyEndpoints:
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	case upstream.ErrCircuitOpen:
		http.Error(w, "Service Unavailable (Circuit Open)", http.StatusServiceUnavailable)
	case upstream.ErrUpstreamNotFound:
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	default:
		if err == context.DeadlineExceeded {
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
	}
}

// writeImmediateResponse writes a plugin's immediate response.
func (h *Handler) writeImmediateResponse(w http.ResponseWriter, resp *plugin.ImmediateResponse) {
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		w.Write(resp.Body)
	}
}

// MiddlewareChain chains multiple middlewares together.
func MiddlewareChain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// RecoveryMiddleware recovers from panics.
func RecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic with stack trace
					slog.Error("panic recovered",
						"error", err,
						"method", r.Method,
						"path", r.URL.Path,
						"remote_addr", r.RemoteAddr,
						"stack", string(debug.Stack()),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDMiddleware adds a request ID to each request.
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
			}
			w.Header().Set("X-Request-ID", requestID)
			next.ServeHTTP(w, r)
		})
	}
}

// generateRequestID generates a unique request ID using UUID.
func generateRequestID() string {
	return uuid.New().String()
}

// CORSMiddleware adds CORS headers.
func CORSMiddleware(allowOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if allowOrigin == "*" || allowOrigin == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
					w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
					w.Header().Set("Access-Control-Max-Age", "86400")
				}
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Close gracefully shuts down the handler's resources.
func (h *Handler) Close() {
	if h.logWorkerPool != nil {
		h.logWorkerPool.Stop()
	}
}
