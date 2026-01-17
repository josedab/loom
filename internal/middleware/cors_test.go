package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultCORSConfig(t *testing.T) {
	cfg := DefaultCORSConfig()

	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "*" {
		t.Error("expected default AllowedOrigins to be [*]")
	}

	if len(cfg.AllowedMethods) == 0 {
		t.Error("expected default AllowedMethods")
	}

	if len(cfg.AllowedHeaders) == 0 {
		t.Error("expected default AllowedHeaders")
	}

	if cfg.MaxAge != 86400 {
		t.Errorf("expected MaxAge 86400, got %d", cfg.MaxAge)
	}
}

func TestCORSMiddleware_NoOrigin(t *testing.T) {
	cfg := DefaultCORSConfig()
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// No CORS headers should be set without Origin
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set CORS headers without Origin")
	}
}

func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	cfg := DefaultCORSConfig()
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected *, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_ExactOrigin(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{http.MethodGet},
		MaxAge:         3600,
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed origin
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected https://example.com, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	// Disallowed origin
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Origin", "https://malicious.com")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)

	if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set CORS header for disallowed origin")
	}
}

func TestCORSMiddleware_WildcardSubdomain(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://*.example.com"},
		AllowedMethods: []string{http.MethodGet},
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		origin  string
		allowed bool
	}{
		{"https://api.example.com", true},
		{"https://app.example.com", true},
		{"https://example.com", false},          // no subdomain
		{"https://sub.api.example.com", false},  // nested subdomain
		{"https://api.other.com", false},        // different domain
		{"http://api.example.com", false},       // different scheme
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			hasHeader := rec.Header().Get("Access-Control-Allow-Origin") != ""
			if hasHeader != tt.allowed {
				t.Errorf("origin %s: expected allowed=%v, got %v", tt.origin, tt.allowed, hasHeader)
			}
		})
	}
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{http.MethodGet, http.MethodPost},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         3600,
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", rec.Code)
	}

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("missing Access-Control-Allow-Origin")
	}

	if rec.Header().Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Errorf("expected 'GET, POST', got %s", rec.Header().Get("Access-Control-Allow-Methods"))
	}

	if rec.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization" {
		t.Error("missing Access-Control-Allow-Headers")
	}

	if rec.Header().Get("Access-Control-Max-Age") != "3600" {
		t.Error("missing Access-Control-Max-Age")
	}
}

func TestCORSMiddleware_Credentials(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{http.MethodGet},
		AllowCredentials: true,
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestCORSMiddleware_CredentialsWithWildcard(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet},
		AllowCredentials: true,
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// When credentials are allowed with *, we must echo the origin
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected origin echo, got %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestCORSMiddleware_ExposedHeaders(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodGet},
		ExposedHeaders: []string{"X-Custom-Header", "X-Another-Header"},
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	exposed := rec.Header().Get("Access-Control-Expose-Headers")
	if exposed != "X-Custom-Header, X-Another-Header" {
		t.Errorf("expected exposed headers, got %s", exposed)
	}
}

func TestCORSMiddleware_PrivateNetwork(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:      []string{"https://example.com"},
		AllowedMethods:      []string{http.MethodGet},
		AllowPrivateNetwork: true,
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Private-Network", "true")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Error("expected Access-Control-Allow-Private-Network: true")
	}
}

func TestCORSMiddleware_VaryHeader(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{http.MethodGet},
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Regular request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	vary := rec.Header().Get("Vary")
	if vary != "Origin" {
		t.Errorf("expected Vary: Origin, got %s", vary)
	}

	// Preflight request
	req2 := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req2.Header.Set("Origin", "https://example.com")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)

	varyValues := rec2.Header().Values("Vary")
	if len(varyValues) < 3 {
		t.Error("expected multiple Vary headers for preflight")
	}
}

func TestCORSMiddleware_MultipleOrigins(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins: []string{"https://example.com", "https://other.com"},
		AllowedMethods: []string{http.MethodGet},
	}
	handler := CORSMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		origin   string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"https://other.com", "https://other.com"},
		{"https://unknown.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			actual := rec.Header().Get("Access-Control-Allow-Origin")
			if actual != tt.expected {
				t.Errorf("origin %s: expected %s, got %s", tt.origin, tt.expected, actual)
			}
		})
	}
}

func TestMatchWildcardOrigin(t *testing.T) {
	tests := []struct {
		origin  string
		pattern string
		match   bool
	}{
		{"https://api.example.com", "https://*.example.com", true},
		{"https://app.example.com", "https://*.example.com", true},
		{"https://example.com", "https://*.example.com", false},
		{"https://sub.api.example.com", "https://*.example.com", false},
		{"http://api.example.com", "https://*.example.com", false},
		{"https://api.other.com", "https://*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			result := matchWildcardOrigin(tt.origin, tt.pattern)
			if result != tt.match {
				t.Errorf("matchWildcardOrigin(%s, %s): expected %v, got %v",
					tt.origin, tt.pattern, tt.match, result)
			}
		})
	}
}

func TestValidateCORSConfig(t *testing.T) {
	cfg := CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}

	// Should not return error (we handle this case specially)
	if err := ValidateCORSConfig(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
