package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultAPIKeyConfig(t *testing.T) {
	cfg := DefaultAPIKeyConfig()

	if cfg.Header != "X-API-Key" {
		t.Errorf("expected header X-API-Key, got %s", cfg.Header)
	}
	if cfg.Realm != "API" {
		t.Errorf("expected realm API, got %s", cfg.Realm)
	}
	if len(cfg.ExcludedPaths) != 3 {
		t.Errorf("expected 3 excluded paths, got %d", len(cfg.ExcludedPaths))
	}
}

func TestAPIKeyMiddleware(t *testing.T) {
	cfg := APIKeyConfig{
		Keys: map[string]APIKeyInfo{
			"valid-key": {Name: "test-key", Roles: []string{"admin"}},
		},
		Header: "X-API-Key",
		Realm:  "Test",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyMiddleware(cfg)(next)

	tests := []struct {
		name       string
		apiKey     string
		wantStatus int
	}{
		{
			name:       "valid key",
			apiKey:     "valid-key",
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid key",
			apiKey:     "invalid-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing key",
			apiKey:     "",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			if tt.apiKey != "" {
				req.Header.Set("X-API-Key", tt.apiKey)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestAPIKeyMiddleware_ExcludedPaths(t *testing.T) {
	cfg := APIKeyConfig{
		Keys:          map[string]APIKeyInfo{},
		ExcludedPaths: []string{"/health", "/public"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyMiddleware(cfg)(next)

	tests := []struct {
		path       string
		wantStatus int
	}{
		{"/health", http.StatusOK},
		{"/health/check", http.StatusOK},
		{"/public", http.StatusOK},
		{"/api/test", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestAPIKeyMiddleware_QueryParam(t *testing.T) {
	cfg := APIKeyConfig{
		Keys: map[string]APIKeyInfo{
			"query-key": {Name: "query-test"},
		},
		QueryParam: "api_key",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test?api_key=query-key", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAPIKeyMiddleware_Expiration(t *testing.T) {
	cfg := APIKeyConfig{
		Keys: map[string]APIKeyInfo{
			"expired-key": {
				Name:      "expired",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			"valid-key": {
				Name:      "valid",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyMiddleware(cfg)(next)

	// Expired key
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Key", "expired-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expired key: expected 401, got %d", rec.Code)
	}

	// Valid key
	req = httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Key", "valid-key")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("valid key: expected 200, got %d", rec.Code)
	}
}

func TestAPIKeyMiddleware_IPAllowlist(t *testing.T) {
	cfg := APIKeyConfig{
		Keys: map[string]APIKeyInfo{
			"ip-restricted": {
				Name:       "restricted",
				AllowedIPs: []string{"10.0.0.1", "192.168.1."},
			},
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := APIKeyMiddleware(cfg)(next)

	tests := []struct {
		name       string
		clientIP   string
		wantStatus int
	}{
		{"exact match", "10.0.0.1", http.StatusOK},
		{"prefix match", "192.168.1.100", http.StatusOK},
		{"not allowed", "172.16.0.1", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Header.Set("X-API-Key", "ip-restricted")
			req.Header.Set("X-Forwarded-For", tt.clientIP)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestGetAPIKeyInfo(t *testing.T) {
	// Test with no key in context
	ctx := context.Background()
	if info := GetAPIKeyInfo(ctx); info != nil {
		t.Error("expected nil for empty context")
	}

	// Test with key in context
	keyInfo := &APIKeyInfo{Name: "test", Roles: []string{"admin"}}
	ctx = context.WithValue(ctx, APIKeyContextKey{}, keyInfo)
	if info := GetAPIKeyInfo(ctx); info == nil {
		t.Error("expected key info from context")
	} else if info.Name != "test" {
		t.Errorf("expected name 'test', got %s", info.Name)
	}
}

func TestBasicAuthMiddleware(t *testing.T) {
	cfg := BasicAuthConfig{
		Users: map[string]string{
			"admin": "secret",
		},
		Realm: "Test",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BasicAuthMiddleware(cfg)(next)

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{"valid credentials", "admin", "secret", http.StatusOK},
		{"wrong password", "admin", "wrong", http.StatusUnauthorized},
		{"unknown user", "unknown", "secret", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.SetBasicAuth(tt.username, tt.password)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestBasicAuthMiddleware_NoAuth(t *testing.T) {
	cfg := BasicAuthConfig{
		Users: map[string]string{"admin": "secret"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BasicAuthMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestBasicAuthMiddleware_ExcludedPaths(t *testing.T) {
	cfg := BasicAuthConfig{
		Users:         map[string]string{"admin": "secret"},
		ExcludedPaths: []string{"/health"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BasicAuthMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for excluded path, got %d", rec.Code)
	}
}

func TestBasicAuthMiddleware_HashFunc(t *testing.T) {
	hashFunc := func(password string) string {
		return "hashed_" + password
	}

	cfg := BasicAuthConfig{
		Users:    map[string]string{"admin": "hashed_secret"},
		HashFunc: hashFunc,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BasicAuthMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestTokenBucketPerKey(t *testing.T) {
	tb := NewTokenBucketPerKey(RateLimiterConfig{
		Rate:  10,
		Burst: 5,
	})

	// Test with nil keyInfo (uses defaults)
	key := "test-client"
	for i := 0; i < 5; i++ {
		if !tb.Allow(nil, key) {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	if tb.Allow(nil, key) {
		t.Error("should be denied after burst")
	}
}

func TestTokenBucketPerKey_CustomRate(t *testing.T) {
	tb := NewTokenBucketPerKey(RateLimiterConfig{
		Rate:  10,
		Burst: 5,
	})

	keyInfo := &APIKeyInfo{
		RateLimit: 20,
	}

	key := "custom-client"
	// Custom rate limit of 20 means burst of 20
	for i := 0; i < 20; i++ {
		if !tb.Allow(keyInfo, key) {
			t.Errorf("request %d should be allowed with custom rate", i+1)
		}
	}

	if tb.Allow(keyInfo, key) {
		t.Error("should be denied after custom burst")
	}
}
