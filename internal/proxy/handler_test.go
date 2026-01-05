package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/upstream"
)

// getHostPort extracts the host:port from a httptest server URL.
func getHostPort(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}
	return u.Host
}

// testBackend creates a test HTTP server that returns the given status and body.
func testBackend(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

// testBackendWithHandler creates a test HTTP server with a custom handler.
func testBackendWithHandler(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// setupTestHandler creates a handler with a single route and upstream.
func setupTestHandler(t *testing.T, backendURL, path, upstreamName string, routeCfg *config.RouteConfig) *Handler {
	t.Helper()

	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil) // nil runtime for tests without plugins
	m := metrics.New()

	// Configure upstream (extract host:port from URL)
	err := u.Configure([]config.UpstreamConfig{
		{
			Name:      upstreamName,
			Endpoints: []string{getHostPort(backendURL)},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure upstream: %v", err)
	}

	// Configure route
	if routeCfg == nil {
		routeCfg = &config.RouteConfig{
			ID:       "test-route",
			Path:     path,
			Upstream: upstreamName,
		}
	}
	err = r.Configure([]config.RouteConfig{*routeCfg})
	if err != nil {
		t.Fatalf("failed to configure route: %v", err)
	}

	return NewHandler(r, u, p, m)
}

func TestHandler_BasicProxy(t *testing.T) {
	backend := testBackend(t, http.StatusOK, "Hello from backend")
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if body != "Hello from backend" {
		t.Errorf("expected body 'Hello from backend', got '%s'", body)
	}
}

func TestHandler_NotFound(t *testing.T) {
	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil)
	m := metrics.New()

	handler := NewHandler(r, u, p, m)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func TestHandler_UpstreamNotFound(t *testing.T) {
	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil)
	m := metrics.New()

	// Configure route pointing to non-existent upstream
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "test-route",
			Path:     "/api/*",
			Upstream: "nonexistent-backend",
		},
	})
	if err != nil {
		t.Fatalf("failed to configure route: %v", err)
	}

	handler := NewHandler(r, u, p, m)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d", http.StatusBadGateway, rec.Code)
	}
}

func TestHandler_StripPrefix(t *testing.T) {
	// Create a backend that echoes the request path
	backend := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("path: " + r.URL.Path))
	})
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", &config.RouteConfig{
		ID:          "test-route",
		Path:        "/api/*",
		Upstream:    "test-backend",
		StripPrefix: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users/123", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "/users/123") {
		t.Errorf("expected path to contain '/users/123', got '%s'", body)
	}
}

func TestHandler_HeaderForwarding(t *testing.T) {
	var receivedHeader string

	backend := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusOK)
	})
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Custom-Header", "custom-value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if receivedHeader != "custom-value" {
		t.Errorf("expected header 'custom-value', got '%s'", receivedHeader)
	}
}

func TestHandler_POSTWithBody(t *testing.T) {
	var receivedBody string

	backend := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("received: " + string(body)))
	})
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", nil)

	body := `{"name": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if receivedBody != body {
		t.Errorf("expected body '%s', got '%s'", body, receivedBody)
	}
}

func TestHandler_Timeout(t *testing.T) {
	backend := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", &config.RouteConfig{
		ID:       "test-route",
		Path:     "/api/*",
		Upstream: "test-backend",
		Timeout:  "100ms",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("expected status %d, got %d", http.StatusGatewayTimeout, rec.Code)
	}
}

func TestMiddlewareChain(t *testing.T) {
	var order []string

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusOK)
	})

	handler := MiddlewareChain(finalHandler, middleware1, middleware2)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Fatalf("expected %d items, got %d", len(expected), len(order))
	}

	for i, v := range expected {
		if order[i] != v {
			t.Errorf("at position %d: expected '%s', got '%s'", i, v, order[i])
		}
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := RecoveryMiddleware()(panicHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestIDMiddleware()(innerHandler)

	// Test without existing request ID
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	requestID := rec.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("expected X-Request-ID header to be set")
	}

	// Test with existing request ID
	existingID := "existing-request-id"
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	requestID = rec.Header().Get("X-Request-ID")
	if requestID != existingID {
		t.Errorf("expected X-Request-ID '%s', got '%s'", existingID, requestID)
	}
}

func TestCORSMiddleware(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware("*")(innerHandler)

	// Test preflight request
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected Access-Control-Allow-Origin header")
	}

	// Test regular request with Origin
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected Access-Control-Allow-Origin header")
	}
}

func TestCORSMiddleware_SpecificOrigin(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware("http://allowed.com")(innerHandler)

	// Test allowed origin
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://allowed.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://allowed.com" {
		t.Error("expected Access-Control-Allow-Origin header for allowed origin")
	}

	// Test disallowed origin
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://notallowed.com")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no Access-Control-Allow-Origin header for disallowed origin")
	}
}

func TestHandler_MultipleEndpoints(t *testing.T) {
	requestCount := 0

	// Create two backends
	backend1 := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend1"))
	})
	defer backend1.Close()

	backend2 := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend2"))
	})
	defer backend2.Close()

	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil)
	m := metrics.New()

	// Configure upstream with two endpoints (extract host:port from URLs)
	err := u.Configure([]config.UpstreamConfig{
		{
			Name:      "test-backend",
			Endpoints: []string{getHostPort(backend1.URL), getHostPort(backend2.URL)},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure upstream: %v", err)
	}

	// Configure route
	err = r.Configure([]config.RouteConfig{
		{
			ID:       "test-route",
			Path:     "/api/*",
			Upstream: "test-backend",
		},
	})
	if err != nil {
		t.Fatalf("failed to configure route: %v", err)
	}

	handler := NewHandler(r, u, p, m)

	// Make multiple requests
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status %d, got %d", i, http.StatusOK, rec.Code)
		}
	}

	if requestCount != 10 {
		t.Errorf("expected 10 requests to backends, got %d", requestCount)
	}
}

func TestHandler_MethodMatching(t *testing.T) {
	backend := testBackend(t, http.StatusOK, "success")
	defer backend.Close()

	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil)
	m := metrics.New()

	// Configure upstream (extract host:port from URL)
	err := u.Configure([]config.UpstreamConfig{
		{
			Name:      "test-backend",
			Endpoints: []string{getHostPort(backend.URL)},
		},
	})
	if err != nil {
		t.Fatalf("failed to configure upstream: %v", err)
	}

	// Configure route with specific methods
	err = r.Configure([]config.RouteConfig{
		{
			ID:       "test-route",
			Path:     "/api/*",
			Methods:  []string{http.MethodGet, http.MethodPost},
			Upstream: "test-backend",
		},
	})
	if err != nil {
		t.Fatalf("failed to configure route: %v", err)
	}

	handler := NewHandler(r, u, p, m)

	tests := []struct {
		method   string
		wantCode int
	}{
		{http.MethodGet, http.StatusOK},
		{http.MethodPost, http.StatusOK},
		{http.MethodPut, http.StatusNotFound},
		{http.MethodDelete, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("method %s: expected status %d, got %d", tt.method, tt.wantCode, rec.Code)
			}
		})
	}
}

func TestHandler_BackendError(t *testing.T) {
	// Create a backend that returns 500
	backend := testBackend(t, http.StatusInternalServerError, "Internal Error")
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Proxy should forward the 500 status
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestHandler_ResponseHeaders(t *testing.T) {
	backend := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Response", "response-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	defer backend.Close()

	handler := setupTestHandler(t, backend.URL, "/api/*", "test-backend", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Custom-Response") != "response-value" {
		t.Error("expected X-Custom-Response header to be forwarded")
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type header to be forwarded")
	}
}

func BenchmarkHandler_SimpleProxy(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	r := router.New()
	u := upstream.NewManager()
	p := plugin.NewPipeline(nil)
	m := metrics.New()

	u.Configure([]config.UpstreamConfig{
		{
			Name:      "test-backend",
			Endpoints: []string{getHostPort(backend.URL)},
		},
	})

	r.Configure([]config.RouteConfig{
		{
			ID:       "test-route",
			Path:     "/api/*",
			Upstream: "test-backend",
		},
	})

	handler := NewHandler(r, u, p, m)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	})
}

func BenchmarkMiddlewareChain(b *testing.B) {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := MiddlewareChain(finalHandler, middleware, middleware, middleware, middleware, middleware)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	})
}
