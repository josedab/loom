package tracing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}

	if cfg.Endpoint != "localhost:4317" {
		t.Errorf("expected Endpoint 'localhost:4317', got %s", cfg.Endpoint)
	}

	if cfg.ServiceName != "gateway" {
		t.Errorf("expected ServiceName 'gateway', got %s", cfg.ServiceName)
	}

	if cfg.SampleRate != 1.0 {
		t.Errorf("expected SampleRate 1.0, got %f", cfg.SampleRate)
	}

	if cfg.BatchTimeout != 5*time.Second {
		t.Errorf("expected BatchTimeout 5s, got %v", cfg.BatchTimeout)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		Endpoint:     "otel-collector:4317",
		ServiceName:  "my-gateway",
		SampleRate:   0.5,
		BatchTimeout: 10 * time.Second,
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}

	if cfg.Endpoint != "otel-collector:4317" {
		t.Errorf("expected Endpoint 'otel-collector:4317', got %s", cfg.Endpoint)
	}

	if cfg.ServiceName != "my-gateway" {
		t.Errorf("expected ServiceName 'my-gateway', got %s", cfg.ServiceName)
	}

	if cfg.SampleRate != 0.5 {
		t.Errorf("expected SampleRate 0.5, got %f", cfg.SampleRate)
	}

	if cfg.BatchTimeout != 10*time.Second {
		t.Errorf("expected BatchTimeout 10s, got %v", cfg.BatchTimeout)
	}
}

func TestNewProviderDisabled(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}

	// Provider should not be nil even when disabled
	if provider.tracer == nil {
		t.Error("expected non-nil tracer")
	}

	// Shutdown should work without error
	err = provider.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestProviderTracer(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	tracer := provider.Tracer()
	if tracer == nil {
		t.Error("expected non-nil tracer")
	}
}

func TestProviderMiddleware(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := provider.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestProviderMiddlewareWithDifferentStatusCodes(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"Created", http.StatusCreated},
		{"BadRequest", http.StatusBadRequest},
		{"NotFound", http.StatusNotFound},
		{"InternalServerError", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			handler := provider.Middleware()(next)

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, rec.Code)
			}
		})
	}
}

func TestProviderShutdownNilProvider(t *testing.T) {
	// Create a provider with disabled tracing (no sdktrace.TracerProvider)
	provider := &Provider{
		provider: nil,
	}

	err := provider.Shutdown(context.Background())
	if err != nil {
		t.Errorf("expected nil error for nil provider shutdown, got %v", err)
	}
}

func TestProviderStartSpan(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	if spanCtx == nil {
		t.Error("expected non-nil context")
	}

	if span == nil {
		t.Error("expected non-nil span")
	}
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	// Get span from context
	retrievedSpan := SpanFromContext(spanCtx)
	if retrievedSpan == nil {
		t.Error("expected non-nil span from context")
	}
}

func TestAddEvent(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	// Add event - should not panic
	AddEvent(spanCtx, "test-event",
		attribute.String("key", "value"),
		attribute.Int("count", 42),
	)
}

func TestRecordError(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	// Record error - should not panic
	testErr := errors.New("test error")
	RecordError(spanCtx, testErr)
}

func TestSetAttributes(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	// Set attributes - should not panic
	SetAttributes(spanCtx,
		attribute.String("key", "value"),
		attribute.Int("count", 42),
		attribute.Bool("enabled", true),
	)
}

func TestInjectContext(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	// Start a span
	spanCtx, span := provider.StartSpan(ctx, "test-operation")
	defer span.End()

	// Inject context into headers - should not panic
	headers := http.Header{}
	InjectContext(spanCtx, headers)
	// Headers may or may not be populated depending on global propagator
}

func TestTracingResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()

	rw := &tracingResponseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)

	if rw.statusCode != http.StatusCreated {
		t.Errorf("expected status code 201, got %d", rw.statusCode)
	}

	// Verify it was written to underlying response writer
	if rec.Code != http.StatusCreated {
		t.Errorf("expected underlying status code 201, got %d", rec.Code)
	}
}

func TestTracingResponseWriterDefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()

	rw := &tracingResponseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Status code should default to 200
	if rw.statusCode != http.StatusOK {
		t.Errorf("expected default status code 200, got %d", rw.statusCode)
	}
}

func TestMiddlewareWithTracingHeaders(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := provider.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	// Add trace context headers
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMiddlewareWithDifferentHTTPMethods(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodOptions,
		http.MethodHead,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := provider.Middleware()(next)

			req := httptest.NewRequest(method, "/api/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
		})
	}
}

func TestMiddlewareError4xx(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	handler := provider.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestMiddlewareError5xx(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Enabled:     false,
		ServiceName: "test-service",
	}

	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := provider.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}
