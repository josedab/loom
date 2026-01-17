package metrics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}

	if m.registry == nil {
		t.Error("expected non-nil registry")
	}

	if m.requestsTotal == nil {
		t.Error("expected non-nil requestsTotal")
	}

	if m.requestDuration == nil {
		t.Error("expected non-nil requestDuration")
	}

	if m.upstreamDuration == nil {
		t.Error("expected non-nil upstreamDuration")
	}

	if m.circuitState == nil {
		t.Error("expected non-nil circuitState")
	}

	if m.pluginDuration == nil {
		t.Error("expected non-nil pluginDuration")
	}
}

func TestHandler(t *testing.T) {
	m := New()

	handler := m.Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	// Record some metrics to ensure output
	m.RecordRequest("GET", "/test", 200, time.Millisecond, 100, 100)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body == "" {
		t.Error("expected non-empty response body")
	}
}

func TestRecordRequest(t *testing.T) {
	m := New()

	// Record a request
	m.RecordRequest("GET", "/api/users", 200, 100*time.Millisecond, 1024, 2048)

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_requests_total") {
		t.Error("expected loom_requests_total in metrics")
	}

	if !strings.Contains(body, "loom_request_duration_seconds") {
		t.Error("expected loom_request_duration_seconds in metrics")
	}

	if !strings.Contains(body, "loom_request_size_bytes") {
		t.Error("expected loom_request_size_bytes in metrics")
	}

	if !strings.Contains(body, "loom_response_size_bytes") {
		t.Error("expected loom_response_size_bytes in metrics")
	}
}

func TestRecordUpstreamRequest(t *testing.T) {
	m := New()

	// Record an upstream request
	m.RecordUpstreamRequest("backend", "localhost:8080", 200, 50*time.Millisecond)

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_upstream_requests_total") {
		t.Error("expected loom_upstream_requests_total in metrics")
	}

	if !strings.Contains(body, "loom_upstream_duration_seconds") {
		t.Error("expected loom_upstream_duration_seconds in metrics")
	}
}

func TestRecordUpstreamError(t *testing.T) {
	m := New()

	// Record an upstream error
	m.RecordUpstreamError("backend", "localhost:8080", "connection_refused")

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_upstream_errors_total") {
		t.Error("expected loom_upstream_errors_total in metrics")
	}
}

func TestSetActiveConnections(t *testing.T) {
	m := New()

	// Set active connections
	m.SetActiveConnections("http", 100)
	m.SetActiveConnections("https", 50)

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_active_connections") {
		t.Error("expected loom_active_connections in metrics")
	}

	// Verify we can update the value
	m.SetActiveConnections("http", 200)
}

func TestSetCircuitState(t *testing.T) {
	m := New()

	// Set circuit states
	m.SetCircuitState("backend1", 0) // closed
	m.SetCircuitState("backend2", 1) // open
	m.SetCircuitState("backend3", 2) // half-open

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_circuit_breaker_state") {
		t.Error("expected loom_circuit_breaker_state in metrics")
	}
}

func TestRecordPluginExecution(t *testing.T) {
	m := New()

	// Record plugin execution without error
	m.RecordPluginExecution("auth", "on_request_headers", 5*time.Millisecond, nil)

	// Record plugin execution with error
	m.RecordPluginExecution("auth", "on_request_body", 10*time.Millisecond, errors.New("plugin error"))

	// Check metrics are exposed
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_plugin_duration_seconds") {
		t.Error("expected loom_plugin_duration_seconds in metrics")
	}

	if !strings.Contains(body, "loom_plugin_errors_total") {
		t.Error("expected loom_plugin_errors_total in metrics")
	}
}

func TestMiddleware(t *testing.T) {
	m := New()

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	// Wrap with middleware
	handler := m.Middleware()(testHandler)

	// Make a request
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Check metrics are exposed
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	m.Handler().ServeHTTP(metricsRec, metricsReq)

	body := metricsRec.Body.String()

	if !strings.Contains(body, "loom_requests_total") {
		t.Error("expected loom_requests_total in metrics after middleware")
	}
}

func TestMiddlewareWithDifferentStatusCodes(t *testing.T) {
	m := New()

	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"NotFound", http.StatusNotFound},
		{"InternalServerError", http.StatusInternalServerError},
		{"BadRequest", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			handler := m.Middleware()(testHandler)

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.statusCode {
				t.Errorf("expected %d, got %d", tt.statusCode, rec.Code)
			}
		})
	}
}

func TestMetricsResponseWriter(t *testing.T) {
	// Test the metricsResponseWriter directly
	rec := httptest.NewRecorder()
	mrw := &metricsResponseWriter{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader
	mrw.WriteHeader(http.StatusCreated)
	if mrw.statusCode != http.StatusCreated {
		t.Errorf("expected status code 201, got %d", mrw.statusCode)
	}

	// Test Write
	data := []byte("test data")
	n, err := mrw.Write(data)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if mrw.bytesWritten != int64(len(data)) {
		t.Errorf("expected bytesWritten %d, got %d", len(data), mrw.bytesWritten)
	}

	// Write more data
	moreData := []byte("more")
	n, err = mrw.Write(moreData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	expectedTotal := int64(len(data) + len(moreData))
	if mrw.bytesWritten != expectedTotal {
		t.Errorf("expected bytesWritten %d, got %d", expectedTotal, mrw.bytesWritten)
	}
}

func TestMultipleMetricRecordings(t *testing.T) {
	m := New()

	// Record multiple requests
	for i := 0; i < 10; i++ {
		m.RecordRequest("GET", "/api/users", 200, time.Duration(i)*time.Millisecond, 100, 200)
		m.RecordRequest("POST", "/api/users", 201, time.Duration(i+1)*time.Millisecond, 200, 100)
	}

	// Record multiple upstream requests
	for i := 0; i < 5; i++ {
		m.RecordUpstreamRequest("backend", "localhost:8080", 200, time.Duration(i)*time.Millisecond)
	}

	// Record multiple errors
	m.RecordUpstreamError("backend", "localhost:8080", "timeout")
	m.RecordUpstreamError("backend", "localhost:8080", "connection_refused")

	// Verify metrics are exposed correctly
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body == "" {
		t.Error("expected non-empty metrics output")
	}
}

func TestMetricsHandler_OutputFormat(t *testing.T) {
	m := New()

	// Record some data
	m.RecordRequest("GET", "/api", 200, 10*time.Millisecond, 100, 200)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	// Check for Prometheus format markers
	if !strings.Contains(body, "# HELP") {
		t.Error("expected # HELP comments in Prometheus format")
	}

	if !strings.Contains(body, "# TYPE") {
		t.Error("expected # TYPE comments in Prometheus format")
	}
}

func TestMetricsContentType(t *testing.T) {
	m := New()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	contentType := rec.Header().Get("Content-Type")
	if contentType == "" {
		t.Error("expected Content-Type header")
	}

	// Should be text/plain with possible charset or openmetrics format
	if !strings.Contains(contentType, "text/plain") && !strings.Contains(contentType, "openmetrics") {
		t.Errorf("unexpected Content-Type: %s", contentType)
	}
}

func TestMetricsWithZeroValues(t *testing.T) {
	m := New()

	// Record with zero values
	m.RecordRequest("GET", "/", 200, 0, 0, 0)
	m.RecordUpstreamRequest("backend", "localhost:8080", 200, 0)
	m.SetActiveConnections("http", 0)
	m.SetCircuitState("backend", 0)

	// Should not panic
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func BenchmarkRecordRequest(b *testing.B) {
	m := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordRequest("GET", "/api/users", 200, 10*time.Millisecond, 1024, 2048)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	m := New()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK")
	})

	handler := m.Middleware()(testHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func TestRecordCacheHit(t *testing.T) {
	m := New()

	m.RecordCacheHit("response")
	m.RecordCacheHit("response")
	m.RecordCacheHit("llm")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_cache_hits_total") {
		t.Error("expected loom_cache_hits_total in metrics")
	}
}

func TestRecordCacheMiss(t *testing.T) {
	m := New()

	m.RecordCacheMiss("response")
	m.RecordCacheMiss("llm")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_cache_misses_total") {
		t.Error("expected loom_cache_misses_total in metrics")
	}
}

func TestRecordRateLimitRejection(t *testing.T) {
	m := New()

	m.RecordRateLimitRejection("/api/users", "192.168.1.1")
	m.RecordRateLimitRejection("/api/orders", "192.168.1.2")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_ratelimit_rejections_total") {
		t.Error("expected loom_ratelimit_rejections_total in metrics")
	}
}

func TestRecordAuthFailure(t *testing.T) {
	m := New()

	m.RecordAuthFailure("api_key", "invalid_key")
	m.RecordAuthFailure("basic", "wrong_password")
	m.RecordAuthFailure("jwt", "expired_token")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_auth_failures_total") {
		t.Error("expected loom_auth_failures_total in metrics")
	}
}

func TestSetUpstreamHealthStatus(t *testing.T) {
	m := New()

	m.SetUpstreamHealthStatus("backend", "localhost:8080", true)
	m.SetUpstreamHealthStatus("backend", "localhost:8081", false)
	m.SetUpstreamHealthStatus("api", "api.example.com:443", true)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_upstream_health_status") {
		t.Error("expected loom_upstream_health_status in metrics")
	}
}

func TestRecordPluginCacheHit(t *testing.T) {
	m := New()

	m.RecordPluginCacheHit()
	m.RecordPluginCacheHit()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_plugin_cache_hits_total") {
		t.Error("expected loom_plugin_cache_hits_total in metrics")
	}
}

func TestRecordPluginCacheMiss(t *testing.T) {
	m := New()

	m.RecordPluginCacheMiss()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "loom_plugin_cache_misses_total") {
		t.Error("expected loom_plugin_cache_misses_total in metrics")
	}
}
