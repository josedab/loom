package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultHTTP3Config(t *testing.T) {
	cfg := DefaultHTTP3Config()

	if cfg.Port != 443 {
		t.Errorf("expected port 443, got %d", cfg.Port)
	}
	if cfg.MaxAge != 86400 {
		t.Errorf("expected max age 86400, got %d", cfg.MaxAge)
	}
}

func TestHTTP3Advertise(t *testing.T) {
	cfg := HTTP3Config{
		Port:   443,
		MaxAge: 86400,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTP3Advertise(cfg)(next)

	// With TLS
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	altSvc := rec.Header().Get("Alt-Svc")
	if altSvc == "" {
		t.Error("expected Alt-Svc header for TLS connection")
	}
	if !strings.Contains(altSvc, `h3=":443"`) {
		t.Error("expected h3 in Alt-Svc header")
	}
	if !strings.Contains(altSvc, "ma=86400") {
		t.Error("expected max-age in Alt-Svc header")
	}
}

func TestHTTP3Advertise_NoTLS(t *testing.T) {
	cfg := DefaultHTTP3Config()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTP3Advertise(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No TLS
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Alt-Svc") != "" {
		t.Error("should not set Alt-Svc for non-TLS connection")
	}
}

func TestHTTP3Advertise_XForwardedProto(t *testing.T) {
	cfg := DefaultHTTP3Config()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTP3Advertise(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Alt-Svc") == "" {
		t.Error("expected Alt-Svc header with X-Forwarded-Proto: https")
	}
}

func TestHTTP3Advertise_CustomPort(t *testing.T) {
	cfg := HTTP3Config{
		Port:   8443,
		MaxAge: 3600,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTP3Advertise(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	altSvc := rec.Header().Get("Alt-Svc")
	if !strings.Contains(altSvc, `h3=":8443"`) {
		t.Errorf("expected h3=\":8443\" in Alt-Svc, got %s", altSvc)
	}
	if !strings.Contains(altSvc, "ma=3600") {
		t.Errorf("expected ma=3600 in Alt-Svc, got %s", altSvc)
	}
}

func TestHTTP3Advertise_DefaultValues(t *testing.T) {
	cfg := HTTP3Config{
		Port:   0, // Should default to 443
		MaxAge: 0, // Should default to 86400
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTP3Advertise(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	altSvc := rec.Header().Get("Alt-Svc")
	if !strings.Contains(altSvc, `h3=":443"`) {
		t.Errorf("expected default port 443, got %s", altSvc)
	}
	if !strings.Contains(altSvc, "ma=86400") {
		t.Errorf("expected default max-age 86400, got %s", altSvc)
	}
}

func TestQUIC0RTTMiddleware_SafeMethods(t *testing.T) {
	handler := QUIC0RTTMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	safeMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}

	for _, method := range safeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			req.TLS = &tls.ConnectionState{DidResume: true}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", method, rec.Code)
			}
		})
	}
}

func TestQUIC0RTTMiddleware_UnsafeMethods(t *testing.T) {
	handler := QUIC0RTTMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	unsafeMethods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range unsafeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			req.TLS = &tls.ConnectionState{DidResume: true}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusTooEarly {
				t.Errorf("expected 425 for %s with 0-RTT, got %d", method, rec.Code)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header")
			}
		})
	}
}

func TestQUIC0RTTMiddleware_AllowUnsafe(t *testing.T) {
	handler := QUIC0RTTMiddleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{DidResume: true}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when allowUnsafe=true, got %d", rec.Code)
	}
}

func TestQUIC0RTTMiddleware_NonResumedSession(t *testing.T) {
	handler := QUIC0RTTMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{DidResume: false}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for non-resumed session, got %d", rec.Code)
	}
}

func TestQUIC0RTTMiddleware_NoTLS(t *testing.T) {
	handler := QUIC0RTTMiddleware(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// No TLS
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for non-TLS request, got %d", rec.Code)
	}
}

func TestIsSafeMethod(t *testing.T) {
	tests := []struct {
		method string
		safe   bool
	}{
		{http.MethodGet, true},
		{http.MethodHead, true},
		{http.MethodOptions, true},
		{http.MethodPost, false},
		{http.MethodPut, false},
		{http.MethodPatch, false},
		{http.MethodDelete, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if isSafeMethod(tt.method) != tt.safe {
				t.Errorf("isSafeMethod(%s) = %v, want %v", tt.method, !tt.safe, tt.safe)
			}
		})
	}
}
