package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultAccessLogConfig(t *testing.T) {
	cfg := DefaultAccessLogConfig()

	if cfg.Logger == nil {
		t.Error("expected default logger")
	}
	if !cfg.SkipHealthCheck {
		t.Error("expected SkipHealthCheck to be true")
	}
	if len(cfg.LogHeaders) == 0 {
		t.Error("expected log headers to be set")
	}
	if len(cfg.MaskHeaders) == 0 {
		t.Error("expected mask headers to be set")
	}
}

func TestAccessLogMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger: logger,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "/api/test") {
		t.Error("log should contain request path")
	}
	if !strings.Contains(logOutput, "GET") {
		t.Error("log should contain request method")
	}
}

func TestAccessLogMiddleware_SkipHealthCheck(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger:          logger,
		SkipHealthCheck: true,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	healthPaths := []string{"/health", "/healthz", "/ready"}
	for _, path := range healthPaths {
		buf.Reset()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if buf.Len() > 0 {
			t.Errorf("should not log health check path: %s", path)
		}
	}
}

func TestAccessLogMiddleware_SkipPaths(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger:    logger,
		SkipPaths: []string{"/metrics"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if buf.Len() > 0 {
		t.Error("should not log skipped path")
	}
}

func TestAccessLogMiddleware_IncludeQuery(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger:       logger,
		IncludeQuery: true,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test?foo=bar", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "foo=bar") {
		t.Error("log should contain query parameters")
	}
}

func TestAccessLogMiddleware_LogHeaders(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger:     logger,
		LogHeaders: []string{"X-Request-ID"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Request-ID", "test-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "test-123") {
		t.Error("log should contain X-Request-ID header value")
	}
}

func TestAccessLogMiddleware_MaskHeaders(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{
		Logger:      logger,
		MaskHeaders: []string{"Authorization"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if strings.Contains(logOutput, "secret-token") {
		t.Error("log should not contain actual Authorization header value")
	}
	if !strings.Contains(logOutput, "[MASKED]") {
		t.Error("log should contain [MASKED] for Authorization header")
	}
}

func TestAccessLogMiddleware_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantLevel  string
	}{
		{"success", http.StatusOK, "INFO"},
		{"client error", http.StatusBadRequest, "WARN"},
		{"server error", http.StatusInternalServerError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))

			cfg := AccessLogConfig{Logger: logger}

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			handler := AccessLogMiddleware(cfg)(next)

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			logOutput := buf.String()
			if !strings.Contains(logOutput, tt.wantLevel) {
				t.Errorf("expected log level %s, got: %s", tt.wantLevel, logOutput)
			}
		})
	}
}

func TestAccessLogMiddleware_ResponseSize(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{Logger: logger}

	responseBody := "hello world"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody))
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "size") {
		t.Error("log should contain response size")
	}
}

func TestAccessLogMiddleware_NilLogger(t *testing.T) {
	cfg := AccessLogConfig{
		Logger: nil, // Should use default
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAccessLogResponseWriter_Flush(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	cfg := AccessLogConfig{Logger: logger}

	flushed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
			flushed = true
		}
	})

	handler := AccessLogMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !flushed {
		t.Error("expected Flush to be called")
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		remoteIP  string
		wantIP    string
	}{
		{
			name:     "X-Forwarded-For single",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteIP: "192.168.1.1:12345",
			wantIP:   "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For multiple",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"},
			remoteIP: "192.168.1.1:12345",
			wantIP:   "10.0.0.1",
		},
		{
			name:     "X-Real-IP",
			headers:  map[string]string{"X-Real-IP": "10.0.0.2"},
			remoteIP: "192.168.1.1:12345",
			wantIP:   "10.0.0.2",
		},
		{
			name:     "RemoteAddr fallback",
			headers:  map[string]string{},
			remoteIP: "192.168.1.1:12345",
			wantIP:   "192.168.1.1:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteIP
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.wantIP {
				t.Errorf("expected %s, got %s", tt.wantIP, ip)
			}
		})
	}
}
