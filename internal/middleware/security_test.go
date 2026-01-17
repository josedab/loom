package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultSecurityHeadersConfig(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	if !cfg.HSTSEnabled {
		t.Error("expected HSTS to be enabled")
	}
	if cfg.HSTSMaxAge != 31536000 {
		t.Errorf("expected HSTS max age 31536000, got %d", cfg.HSTSMaxAge)
	}
	if !cfg.HSTSIncludeSubDomains {
		t.Error("expected HSTS include subdomains")
	}
	if cfg.XContentTypeOptions != "nosniff" {
		t.Errorf("expected X-Content-Type-Options nosniff, got %s", cfg.XContentTypeOptions)
	}
	if cfg.XFrameOptions != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %s", cfg.XFrameOptions)
	}
	if cfg.XXSSProtection != "1; mode=block" {
		t.Errorf("expected X-XSS-Protection '1; mode=block', got %s", cfg.XXSSProtection)
	}
	if cfg.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("expected Referrer-Policy strict-origin-when-cross-origin, got %s", cfg.ReferrerPolicy)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options header")
	}
	if rec.Header().Get("X-XSS-Protection") != "1; mode=block" {
		t.Error("expected X-XSS-Protection header")
	}
	if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("expected Referrer-Policy header")
	}
}

func TestSecurityHeadersMiddleware_HSTS(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	// Without TLS - no HSTS
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("should not set HSTS for non-TLS connection")
	}

	// With TLS - HSTS should be set
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected HSTS header for TLS connection")
	}
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Error("expected max-age in HSTS header")
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Error("expected includeSubDomains in HSTS header")
	}
}

func TestSecurityHeadersMiddleware_HSTSPreload(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.HSTSPreload = true

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "preload") {
		t.Error("expected preload in HSTS header")
	}
}

func TestSecurityHeadersMiddleware_ContentSecurityPolicy(t *testing.T) {
	cfg := SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp != "default-src 'self'; script-src 'self'" {
		t.Errorf("expected CSP header, got %s", csp)
	}
}

func TestSecurityHeadersMiddleware_PermissionsPolicy(t *testing.T) {
	cfg := SecurityHeadersConfig{
		PermissionsPolicy: "geolocation=(), microphone=()",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	pp := rec.Header().Get("Permissions-Policy")
	if pp != "geolocation=(), microphone=()" {
		t.Errorf("expected Permissions-Policy header, got %s", pp)
	}
}

func TestSecurityHeadersMiddleware_CustomHeaders(t *testing.T) {
	cfg := SecurityHeadersConfig{
		CustomHeaders: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Another":       "another-value",
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Custom-Header") != "custom-value" {
		t.Error("expected X-Custom-Header")
	}
	if rec.Header().Get("X-Another") != "another-value" {
		t.Error("expected X-Another header")
	}
}

func TestSecurityHeadersMiddleware_EmptyConfig(t *testing.T) {
	cfg := SecurityHeadersConfig{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should not set any security headers with empty config
	if rec.Header().Get("X-Content-Type-Options") != "" {
		t.Error("should not set X-Content-Type-Options with empty config")
	}
	if rec.Header().Get("X-Frame-Options") != "" {
		t.Error("should not set X-Frame-Options with empty config")
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{31536000, "31536000"},
		{-1, "-1"},
		{-123, "-123"},
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}
