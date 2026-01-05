package openapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// MiddlewareConfig configures the OpenAPI middleware.
type MiddlewareConfig struct {
	// Validator for request validation
	Validator *Validator
	// ValidateRequest enables request validation
	ValidateRequest bool
	// ValidateBody enables request body validation
	ValidateBody bool
	// OnValidationError handles validation errors (optional)
	OnValidationError func(w http.ResponseWriter, r *http.Request, result *ValidationResult)
	// Logger for middleware events
	Logger *slog.Logger
}

// ValidationMiddleware returns HTTP middleware that validates requests against OpenAPI spec.
func ValidationMiddleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.ValidateRequest {
				next.ServeHTTP(w, r)
				return
			}

			result := cfg.Validator.ValidateRequest(r)

			// Validate body if enabled and there's a request body
			if cfg.ValidateBody && result.Valid && result.Route != nil {
				if result.Route.RequestBody != nil && r.Body != nil && r.ContentLength > 0 {
					bodyBytes, err := io.ReadAll(r.Body)
					if err != nil {
						result.Valid = false
						result.Errors = append(result.Errors, ValidationError{
							Field:   "body",
							Message: "failed to read body: " + err.Error(),
						})
					} else {
						// Restore body for downstream handlers
						r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

						// Find schema for content type
						contentType := r.Header.Get("Content-Type")
						if schema := findBodySchema(result.Route.RequestBody, contentType); schema != nil {
							errors := cfg.Validator.ValidateJSON(bodyBytes, schema)
							if len(errors) > 0 {
								result.Valid = false
								result.Errors = append(result.Errors, errors...)
							}
						}
					}
				}
			}

			if !result.Valid {
				cfg.Logger.Debug("request validation failed",
					"path", r.URL.Path,
					"method", r.Method,
					"errors", len(result.Errors),
				)

				if cfg.OnValidationError != nil {
					cfg.OnValidationError(w, r, result)
					return
				}

				// Default error response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":  "validation failed",
					"errors": result.Errors,
				})
				return
			}

			// Store validation result in request context if needed
			next.ServeHTTP(w, r)
		})
	}
}

// findBodySchema finds the schema for a content type.
func findBodySchema(body *RequestBody, contentType string) *Schema {
	if body == nil || body.Content == nil {
		return nil
	}

	// Try exact match
	if media, ok := body.Content[contentType]; ok {
		return media.Schema
	}

	// Try matching base content type (without charset etc.)
	baseType := strings.Split(contentType, ";")[0]
	baseType = strings.TrimSpace(baseType)
	if media, ok := body.Content[baseType]; ok {
		return media.Schema
	}

	// Try application/json as fallback
	if media, ok := body.Content["application/json"]; ok {
		return media.Schema
	}

	return nil
}

// MockMiddlewareConfig configures the mock middleware.
type MockMiddlewareConfig struct {
	// Generator for mock responses
	Generator *MockGenerator
	// Enabled routes to mock (empty means all)
	EnabledRoutes map[string]bool
	// MockHeader enables mocking only when this header is present
	MockHeader string
	// Logger for middleware events
	Logger *slog.Logger
}

// MockMiddleware returns HTTP middleware that returns mock responses.
func MockMiddleware(cfg MockMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if mocking is enabled for this request
			shouldMock := true
			if cfg.MockHeader != "" && r.Header.Get(cfg.MockHeader) == "" {
				shouldMock = false
			}
			if len(cfg.EnabledRoutes) > 0 {
				if !cfg.EnabledRoutes[r.URL.Path] {
					shouldMock = false
				}
			}

			if !shouldMock {
				next.ServeHTTP(w, r)
				return
			}

			// Generate mock response
			status, headers, body, err := cfg.Generator.GenerateMock(r.URL.Path, r.Method)
			if err != nil {
				// No mock available, pass through
				next.ServeHTTP(w, r)
				return
			}

			// Write mock response
			for k, v := range headers {
				w.Header().Set(k, v)
			}
			w.Header().Set("X-Mock-Response", "true")
			w.WriteHeader(status)
			w.Write(body)

			cfg.Logger.Debug("mock response generated",
				"path", r.URL.Path,
				"method", r.Method,
				"status", status,
			)
		})
	}
}

// Router generates routes from an OpenAPI spec and registers handlers.
type Router struct {
	spec     *Spec
	handlers map[string]map[string]http.Handler // path -> method -> handler
	mu       sync.RWMutex
}

// NewRouter creates a new router from an OpenAPI spec.
func NewRouter(spec *Spec) *Router {
	return &Router{
		spec:     spec,
		handlers: make(map[string]map[string]http.Handler),
	}
}

// RegisterHandler registers a handler for an operation.
func (r *Router) RegisterHandler(path, method string, handler http.Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.handlers[path] == nil {
		r.handlers[path] = make(map[string]http.Handler)
	}
	r.handlers[path][method] = handler
}

// RegisterHandlerFunc registers a handler function for an operation.
func (r *Router) RegisterHandlerFunc(path, method string, handler http.HandlerFunc) {
	r.RegisterHandler(path, method, handler)
}

// RegisterByOperationID registers a handler by operation ID.
func (r *Router) RegisterByOperationID(operationID string, handler http.Handler) bool {
	routes := r.spec.GenerateRoutes()
	for _, route := range routes {
		if route.OperationID == operationID {
			r.RegisterHandler(route.Path, route.Method, handler)
			return true
		}
	}
	return false
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Try exact path match first
	if methods, ok := r.handlers[req.URL.Path]; ok {
		if handler, ok := methods[req.Method]; ok {
			handler.ServeHTTP(w, req)
			return
		}
	}

	// Try pattern matching
	for path, methods := range r.handlers {
		if matchPath(path, req.URL.Path) {
			if handler, ok := methods[req.Method]; ok {
				handler.ServeHTTP(w, req)
				return
			}
		}
	}

	// No handler found
	http.NotFound(w, req)
}

// matchPath checks if a path matches a pattern.
func matchPath(pattern, path string) bool {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i, part := range patternParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			// Parameter - matches anything
			continue
		}
		if part != pathParts[i] {
			return false
		}
	}

	return true
}

// GetRoutes returns all routes from the spec.
func (r *Router) GetRoutes() []Route {
	return r.spec.GenerateRoutes()
}

// SpecLoader handles loading and reloading OpenAPI specs.
type SpecLoader struct {
	specPath     string
	spec         *Spec
	validator    *Validator
	mock         *MockGenerator
	mu           sync.RWMutex
	lastModified time.Time
	logger       *slog.Logger
}

// NewSpecLoader creates a new spec loader.
func NewSpecLoader(specPath string, logger *slog.Logger) (*SpecLoader, error) {
	if logger == nil {
		logger = slog.Default()
	}

	loader := &SpecLoader{
		specPath: specPath,
		logger:   logger,
	}

	if err := loader.Load(); err != nil {
		return nil, err
	}

	return loader, nil
}

// Load loads or reloads the spec from file.
func (l *SpecLoader) Load() error {
	data, err := os.ReadFile(l.specPath)
	if err != nil {
		return err
	}

	spec, err := Parse(data)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.spec = spec
	l.validator = NewValidator(spec)
	l.mock = NewMockGenerator(spec)
	l.lastModified = time.Now()
	l.mu.Unlock()

	l.logger.Info("OpenAPI spec loaded",
		"path", l.specPath,
		"title", spec.Info.Title,
		"version", spec.Info.Version,
	)

	return nil
}

// Spec returns the current spec.
func (l *SpecLoader) Spec() *Spec {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.spec
}

// Validator returns the current validator.
func (l *SpecLoader) Validator() *Validator {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.validator
}

// MockGenerator returns the current mock generator.
func (l *SpecLoader) MockGenerator() *MockGenerator {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.mock
}

// WatchAndReload watches the spec file and reloads on changes.
func (l *SpecLoader) WatchAndReload(done <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			info, err := os.Stat(l.specPath)
			if err != nil {
				l.logger.Error("failed to stat spec file", "error", err)
				continue
			}

			l.mu.RLock()
			lastMod := l.lastModified
			l.mu.RUnlock()

			if info.ModTime().After(lastMod) {
				if err := l.Load(); err != nil {
					l.logger.Error("failed to reload spec", "error", err)
				}
			}
		}
	}
}

// Handler provides an HTTP API for OpenAPI operations.
type Handler struct {
	validator *Validator
	mock      *MockGenerator
	spec      *Spec
	logger    *slog.Logger
}

// NewHandler creates a new OpenAPI handler.
func NewHandler(spec *Spec, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		validator: NewValidator(spec),
		mock:      NewMockGenerator(spec),
		spec:      spec,
		logger:    logger,
	}
}

// ServeHTTP handles OpenAPI management requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/openapi")

	switch {
	case path == "" || path == "/":
		h.handleSpec(w, r)
	case path == "/routes":
		h.handleRoutes(w, r)
	case path == "/validate" && r.Method == http.MethodPost:
		h.handleValidate(w, r)
	case strings.HasPrefix(path, "/mock"):
		h.handleMock(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleSpec returns the OpenAPI spec.
func (h *Handler) handleSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.spec)
}

// handleRoutes returns all routes.
func (h *Handler) handleRoutes(w http.ResponseWriter, r *http.Request) {
	routes := h.spec.GenerateRoutes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

// handleValidate validates a request body against a schema.
func (h *Handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	schemaRef := r.URL.Query().Get("schema")
	if schemaRef == "" {
		http.Error(w, "schema parameter required", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Find schema
	schema := h.validator.resolveRef("#/components/schemas/" + schemaRef)
	if schema == nil {
		http.Error(w, "schema not found", http.StatusNotFound)
		return
	}

	errors := h.validator.ValidateJSON(body, schema)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":  len(errors) == 0,
		"errors": errors,
	})
}

// handleMock generates a mock response.
func (h *Handler) handleMock(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	method := r.URL.Query().Get("method")
	if path == "" || method == "" {
		http.Error(w, "path and method parameters required", http.StatusBadRequest)
		return
	}

	status, headers, body, err := h.mock.GenerateMock(path, method)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	w.Write(body)
}
