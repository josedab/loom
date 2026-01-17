package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultBodyLimitConfig(t *testing.T) {
	cfg := DefaultBodyLimitConfig()

	if cfg.MaxSize != 1<<20 {
		t.Errorf("expected max size 1MB, got %d", cfg.MaxSize)
	}
}

func TestBodyLimitMiddleware_UnderLimit(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize: 1024,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.Write(body)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	body := strings.Repeat("a", 512)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != body {
		t.Error("body mismatch")
	}
}

func TestBodyLimitMiddleware_OverLimit(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize: 100,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			if err == ErrBodyTooLarge {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	body := strings.Repeat("a", 200)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestBodyLimitMiddleware_ContentLengthCheck(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize: 100,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	body := strings.Repeat("a", 200)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.ContentLength = 200
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for Content-Length exceeding limit, got %d", rec.Code)
	}
}

func TestBodyLimitMiddleware_ExcludedPaths(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize:       100,
		ExcludedPaths: []string{"/upload"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	body := strings.Repeat("a", 200)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for excluded path, got %d", rec.Code)
	}
}

func TestBodyLimitMiddleware_NoBody(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize: 100,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestBodyLimitMiddleware_DefaultSize(t *testing.T) {
	cfg := BodyLimitConfig{
		MaxSize: 0, // Should default to 1MB
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyLimitMiddleware(cfg)(next)

	// Should allow body under 1MB
	body := strings.Repeat("a", 1024)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestLimitedReader(t *testing.T) {
	data := []byte("hello world")
	reader := &limitedReader{
		reader:    io.NopCloser(bytes.NewReader(data)),
		remaining: 5,
	}

	buf := make([]byte, 10)
	n, err := reader.Read(buf)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected to read 5 bytes, got %d", n)
	}

	// Next read should return error
	_, err = reader.Read(buf)
	if err != ErrBodyTooLarge {
		t.Errorf("expected ErrBodyTooLarge, got %v", err)
	}
}

func TestLimitedReader_Close(t *testing.T) {
	reader := &limitedReader{
		reader:    io.NopCloser(strings.NewReader("test")),
		remaining: 100,
	}

	if err := reader.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMaxBytesMiddleware(t *testing.T) {
	handler := MaxBytesMiddleware(100)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Under limit
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small body"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for small body, got %d", rec.Code)
	}

	// Over limit
	body := strings.Repeat("a", 200)
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for large body, got %d", rec.Code)
	}
}
