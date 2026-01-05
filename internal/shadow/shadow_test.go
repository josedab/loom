package shadow

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerConfigure(t *testing.T) {
	m := NewManager()
	defer m.Close()

	err := m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "shadow-1", Address: "localhost:8081", Percentage: 50},
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	cfg, ok := m.GetConfig("route-1")
	if !ok {
		t.Fatal("expected to find config")
	}
	if len(cfg.Targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(cfg.Targets))
	}
}

func TestManagerRemove(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{{Name: "shadow", Address: "localhost:8081", Percentage: 100}},
	})

	m.Remove("route-1")

	_, ok := m.GetConfig("route-1")
	if ok {
		t.Error("expected config to be removed")
	}
}

func TestShadowRequest(t *testing.T) {
	// Create a shadow target server
	var receivedCount int64
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&receivedCount, 1)

		// Verify shadow headers are present
		if r.Header.Get("X-Shadow-Request") != "true" {
			t.Error("expected X-Shadow-Request header")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	m := NewManager()
	defer m.Close()

	// Extract host:port from test server URL
	addr := shadowServer.URL[7:] // Remove "http://"

	m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "test", Address: addr, Percentage: 100, Timeout: time.Second},
		},
	})

	// Create a test request
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Host = "example.com"

	// Shadow the request
	m.Shadow("route-1", req, nil)

	// Wait for shadow request to complete
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt64(&receivedCount) != 1 {
		t.Errorf("expected 1 shadow request, got %d", receivedCount)
	}
}

func TestShadowPercentage(t *testing.T) {
	var receivedCount int64
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&receivedCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	m := NewManager()
	defer m.Close()

	addr := shadowServer.URL[7:]

	m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "test", Address: addr, Percentage: 50, Timeout: time.Second},
		},
	})

	// Send 100 requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		m.Shadow("route-1", req, nil)
	}

	// Wait for shadow requests to complete
	time.Sleep(200 * time.Millisecond)

	// Should be roughly 50% (with some variance)
	count := atomic.LoadInt64(&receivedCount)
	if count < 30 || count > 70 {
		t.Errorf("expected ~50%% of requests to be shadowed, got %d%%", count)
	}
}

func TestShadowWithBody(t *testing.T) {
	var receivedBody string
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	m := NewManager()
	defer m.Close()

	addr := shadowServer.URL[7:]

	m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "test", Address: addr, Percentage: 100, Timeout: time.Second},
		},
	})

	req := httptest.NewRequest("POST", "/api/test", nil)
	body := []byte(`{"test": "data"}`)
	m.Shadow("route-1", req, body)

	time.Sleep(100 * time.Millisecond)

	if receivedBody != `{"test": "data"}` {
		t.Errorf("expected body %q, got %q", `{"test": "data"}`, receivedBody)
	}
}

func TestShadowMetrics(t *testing.T) {
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	m := NewManager()
	defer m.Close()

	addr := shadowServer.URL[7:]

	m.Configure(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "test", Address: addr, Percentage: 100, Timeout: time.Second},
		},
	})

	// Send some requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		m.Shadow("route-1", req, nil)
	}

	time.Sleep(200 * time.Millisecond)

	metrics := m.GetMetrics()
	if metrics["test"].RequestsSent != 5 {
		t.Errorf("expected 5 requests sent, got %d", metrics["test"].RequestsSent)
	}
}

func TestShouldShadow(t *testing.T) {
	// 100% should always shadow
	for i := 0; i < 100; i++ {
		if !shouldShadow(100) {
			t.Error("100% should always shadow")
		}
	}

	// 0% should never shadow
	for i := 0; i < 100; i++ {
		if shouldShadow(0) {
			t.Error("0% should never shadow")
		}
	}
}

func TestMiddleware(t *testing.T) {
	var shadowReceived int64
	shadowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&shadowReceived, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowServer.Close()

	m := NewManager()
	defer m.Close()

	addr := shadowServer.URL[7:]
	m.Configure(Config{
		RouteID: "test-route",
		Targets: []Target{
			{Name: "test", Address: addr, Percentage: 100, Timeout: time.Second},
		},
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("primary response"))
	})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		RouteIDFunc: func(r *http.Request) string {
			return "test-route"
		},
	})(backend)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check primary response
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if rec.Body.String() != "primary response" {
		t.Error("expected primary response body")
	}

	// Wait for shadow request
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt64(&shadowReceived) != 1 {
		t.Error("expected shadow server to receive request")
	}
}

func TestCloneRequest(t *testing.T) {
	original := httptest.NewRequest("POST", "/api/users?page=1", nil)
	original.Header.Set("Content-Type", "application/json")
	original.Header.Set("Authorization", "Bearer token")
	original.Host = "original.example.com"

	target := Target{
		Address: "shadow.example.com:8080",
		Headers: Headers{
			"X-Custom": "value",
		},
	}

	body := []byte(`{"name": "test"}`)
	clone := cloneRequest(original, body, target)

	if clone == nil {
		t.Fatal("expected cloned request")
	}

	// Check URL
	if clone.URL.Host != "shadow.example.com:8080" {
		t.Errorf("expected shadow host, got %s", clone.URL.Host)
	}
	if clone.URL.Path != "/api/users" {
		t.Errorf("expected path /api/users, got %s", clone.URL.Path)
	}
	if clone.URL.RawQuery != "page=1" {
		t.Errorf("expected query page=1, got %s", clone.URL.RawQuery)
	}

	// Check headers are copied
	if clone.Header.Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type header to be copied")
	}
	if clone.Header.Get("Authorization") != "Bearer token" {
		t.Error("expected Authorization header to be copied")
	}

	// Check shadow headers
	if clone.Header.Get("X-Shadow-Request") != "true" {
		t.Error("expected X-Shadow-Request header")
	}
	if clone.Header.Get("X-Original-Host") != "original.example.com" {
		t.Error("expected X-Original-Host header")
	}

	// Check target headers
	if clone.Header.Get("X-Custom") != "value" {
		t.Error("expected X-Custom header from target")
	}
}
