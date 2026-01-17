package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/upstream"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if hash == "password123" {
		t.Error("hash should differ from original password")
	}

	// Bcrypt produces different hashes for same password (due to random salt)
	hash2, err := HashPassword("password123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == hash2 {
		t.Error("bcrypt should produce different hashes due to random salt")
	}

	// Both hashes should verify against the same password
	if err := VerifyPassword(hash, "password123"); err != nil {
		t.Error("hash should verify against original password")
	}
	if err := VerifyPassword(hash2, "password123"); err != nil {
		t.Error("hash2 should verify against original password")
	}

	// Different password should not verify
	if err := VerifyPassword(hash, "different"); err == nil {
		t.Error("different password should not verify")
	}
}

func TestNewServer(t *testing.T) {
	r := router.New()
	u := upstream.NewManager()
	p, _ := plugin.NewRuntime(context.Background(), plugin.RuntimeConfig{})
	h := upstream.NewHealthChecker(u)
	m := metrics.New()
	c, _ := config.NewManager("")

	passwordHash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	auth := AuthConfig{
		Enabled: true,
		Users:   map[string]string{"admin": passwordHash},
	}

	s := NewServer(r, u, p, h, m, c, auth)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.auth.Realm != "Gateway Admin" {
		t.Errorf("expected default realm, got %s", s.auth.Realm)
	}

	// Test with custom realm
	auth.Realm = "Custom Realm"
	s = NewServer(r, u, p, h, m, c, auth)
	if s.auth.Realm != "Custom Realm" {
		t.Errorf("expected custom realm, got %s", s.auth.Realm)
	}
}

func createTempConfig(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "gateway.yaml")
	configContent := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: test-route
    path: /api/*
    upstream: test-upstream

upstreams:
  - name: test-upstream
    endpoints:
      - localhost:8080
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return configPath
}

func createTestServer(t *testing.T, auth AuthConfig) (*Server, *http.ServeMux) {
	r := router.New()
	u := upstream.NewManager()
	p, _ := plugin.NewRuntime(context.Background(), plugin.RuntimeConfig{})
	h := upstream.NewHealthChecker(u)
	m := metrics.New()
	configPath := createTempConfig(t)
	c, err := config.NewManager(configPath)
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}

	// Add test data
	r.Configure([]config.RouteConfig{
		{ID: "test-route", Path: "/api/*", Upstream: "test-upstream"},
	})
	u.Configure([]config.UpstreamConfig{
		{Name: "test-upstream", Endpoints: []string{"localhost:8080"}},
	})

	s := NewServer(r, u, p, h, m, c, auth)

	// Create a test mux with handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/info", s.handleInfo)
	mux.HandleFunc("/routes", s.handleRoutes)
	mux.HandleFunc("/routes/", s.handleRoute)
	mux.HandleFunc("/upstreams", s.handleUpstreams)
	mux.HandleFunc("/upstreams/", s.handleUpstream)
	mux.HandleFunc("/plugins", s.handlePlugins)
	mux.HandleFunc("/plugins/", s.handlePlugin)
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/cache/stats", s.handleCacheStats)
	mux.HandleFunc("/ratelimit/stats", s.handleRateLimitStats)

	return s, mux
}

func TestHandleHealth(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %s", resp["status"])
	}
}

func TestHandleReady(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "ready" {
		t.Errorf("expected status 'ready', got %s", resp["status"])
	}
}

func TestHandleInfo(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["version"] == nil {
		t.Error("expected version in response")
	}
	if resp["uptime"] == nil {
		t.Error("expected uptime in response")
	}
}

func TestHandleRoutes(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var routes []RouteInfo
	if err := json.NewDecoder(rec.Body).Decode(&routes); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}
	if len(routes) > 0 && routes[0].ID != "test-route" {
		t.Errorf("expected route ID 'test-route', got %s", routes[0].ID)
	}
}

func TestHandleRoutesMethodNotAllowed(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	// DELETE is not allowed on the /routes collection endpoint
	req := httptest.NewRequest(http.MethodDelete, "/routes", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleRoute(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	// Get existing route
	req := httptest.NewRequest(http.MethodGet, "/routes/test-route", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var route RouteInfo
	if err := json.NewDecoder(rec.Body).Decode(&route); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if route.ID != "test-route" {
		t.Errorf("expected route ID 'test-route', got %s", route.ID)
	}
}

func TestHandleRouteNotFound(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/routes/nonexistent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleRouteNoID(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/routes/", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleUpstreams(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/upstreams", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var upstreams []UpstreamInfo
	if err := json.NewDecoder(rec.Body).Decode(&upstreams); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(upstreams))
	}
	if len(upstreams) > 0 && upstreams[0].Name != "test-upstream" {
		t.Errorf("expected upstream name 'test-upstream', got %s", upstreams[0].Name)
	}
}

func TestHandleUpstream(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/upstreams/test-upstream", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var upstream UpstreamInfo
	if err := json.NewDecoder(rec.Body).Decode(&upstream); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if upstream.Name != "test-upstream" {
		t.Errorf("expected upstream name 'test-upstream', got %s", upstream.Name)
	}
}

func TestHandleUpstreamNotFound(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/upstreams/nonexistent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandlePlugins(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/plugins", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var plugins []*plugin.PluginInfo
	if err := json.NewDecoder(rec.Body).Decode(&plugins); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestHandlePluginNotFound(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/plugins/nonexistent", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleConfig(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleConfigMethodNotAllowed(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodPost, "/config", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestBasicAuthMiddleware(t *testing.T) {
	passwordHash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	auth := AuthConfig{
		Enabled: true,
		Users:   map[string]string{"admin": passwordHash},
		Realm:   "Test Realm",
	}

	s, _ := createTestServer(t, auth)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	handler := s.basicAuthMiddleware(next)

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{
			name:       "valid credentials",
			username:   "admin",
			password:   "secret",
			wantStatus: http.StatusOK,
		},
		{
			name:       "wrong password",
			username:   "admin",
			password:   "wrong",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unknown user",
			username:   "unknown",
			password:   "secret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "no credentials",
			username:   "",
			password:   "",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.username != "" || tt.password != "" {
				auth := base64.StdEncoding.EncodeToString([]byte(tt.username + ":" + tt.password))
				req.Header.Set("Authorization", "Basic "+auth)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected %d, got %d", tt.wantStatus, rec.Code)
			}

			if tt.wantStatus == http.StatusUnauthorized {
				wwwAuth := rec.Header().Get("WWW-Authenticate")
				if wwwAuth == "" {
					t.Error("expected WWW-Authenticate header")
				}
			}
		})
	}
}

func TestShutdown(t *testing.T) {
	s, _ := createTestServer(t, AuthConfig{})

	// Shutdown without starting should not error
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRouteInfo(t *testing.T) {
	info := RouteInfo{
		ID:       "test",
		Host:     "example.com",
		Path:     "/api/*",
		Methods:  []string{"GET", "POST"},
		Upstream: "backend",
		Plugins:  []string{"auth"},
		Priority: 100,
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded RouteInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != info.ID {
		t.Errorf("expected ID %s, got %s", info.ID, decoded.ID)
	}
}

func TestUpstreamInfo(t *testing.T) {
	info := UpstreamInfo{
		Name: "backend",
		Endpoints: []EndpointInfo{
			{Address: "localhost:8080", Weight: 1, Healthy: true, ActiveConns: 5},
		},
		CircuitState: "closed",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded UpstreamInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Name != info.Name {
		t.Errorf("expected name %s, got %s", info.Name, decoded.Name)
	}
}

func TestPluginInfo(t *testing.T) {
	info := plugin.PluginInfo{
		Name:     "auth",
		Phase:    "request",
		Priority: 100,
		Path:     "/plugins/auth.wasm",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded plugin.PluginInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Name != info.Name {
		t.Errorf("expected name %s, got %s", info.Name, decoded.Name)
	}
}

// mockCacheStatsProvider implements CacheStatsProvider for testing.
type mockCacheStatsProvider struct {
	stats CacheStats
}

func (m *mockCacheStatsProvider) GetStats() CacheStats {
	return m.stats
}

// mockRateLimitStatsProvider implements RateLimitStatsProvider for testing.
type mockRateLimitStatsProvider struct {
	stats RateLimitStats
}

func (m *mockRateLimitStatsProvider) GetRateLimitStats() RateLimitStats {
	return m.stats
}

func TestHandleCacheStats(t *testing.T) {
	server, mux := createTestServer(t, AuthConfig{})

	// Set up mock cache stats provider
	server.SetCacheStatsProvider(&mockCacheStatsProvider{
		stats: CacheStats{
			Hits:        100,
			Misses:      20,
			Evictions:   5,
			Expirations: 10,
			StaleHits:   3,
			Errors:      1,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/cache/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result["hits"].(float64) != 100 {
		t.Errorf("expected 100 hits, got %v", result["hits"])
	}
	if result["misses"].(float64) != 20 {
		t.Errorf("expected 20 misses, got %v", result["misses"])
	}
	// Hit rate should be 100/(100+20) * 100 = 83.33...
	hitRate := result["hit_rate"].(float64)
	if hitRate < 83 || hitRate > 84 {
		t.Errorf("expected hit_rate around 83.33, got %v", hitRate)
	}
}

func TestHandleCacheStats_NotConfigured(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/cache/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rec.Code)
	}
}

func TestHandleCacheStats_MethodNotAllowed(t *testing.T) {
	server, mux := createTestServer(t, AuthConfig{})
	server.SetCacheStatsProvider(&mockCacheStatsProvider{})

	req := httptest.NewRequest(http.MethodPost, "/cache/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleRateLimitStats(t *testing.T) {
	server, mux := createTestServer(t, AuthConfig{})

	// Set up mock rate limit stats provider
	server.SetRateLimitStatsProvider(&mockRateLimitStatsProvider{
		stats: RateLimitStats{
			ActiveKeys:   50,
			TotalAllowed: 1000,
			TotalDenied:  25,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/ratelimit/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result["active_keys"].(float64) != 50 {
		t.Errorf("expected 50 active_keys, got %v", result["active_keys"])
	}
	if result["total_allowed"].(float64) != 1000 {
		t.Errorf("expected 1000 total_allowed, got %v", result["total_allowed"])
	}
	if result["total_denied"].(float64) != 25 {
		t.Errorf("expected 25 total_denied, got %v", result["total_denied"])
	}
}

func TestHandleRateLimitStats_NotConfigured(t *testing.T) {
	_, mux := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/ratelimit/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rec.Code)
	}
}

func TestHandleRateLimitStats_MethodNotAllowed(t *testing.T) {
	server, mux := createTestServer(t, AuthConfig{})
	server.SetRateLimitStatsProvider(&mockRateLimitStatsProvider{})

	req := httptest.NewRequest(http.MethodDelete, "/ratelimit/stats", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}
