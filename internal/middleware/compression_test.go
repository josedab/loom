package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultCompressionConfig(t *testing.T) {
	cfg := DefaultCompressionConfig()

	if cfg.Level != gzip.DefaultCompression {
		t.Errorf("expected default compression level, got %d", cfg.Level)
	}
	if cfg.MinSize != 1024 {
		t.Errorf("expected min size 1024, got %d", cfg.MinSize)
	}
	if len(cfg.ContentTypes) == 0 {
		t.Error("expected content types to be set")
	}
}

func TestCompressionMiddleware_Compressed(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "hello world"}`))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Error("expected gzip content encoding")
	}
	if rec.Header().Get("Vary") == "" {
		t.Error("expected Vary header")
	}

	// Verify response is gzip compressed
	reader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read compressed body: %v", err)
	}

	if !strings.Contains(string(body), "hello world") {
		t.Error("decompressed body mismatch")
	}
}

func TestCompressionMiddleware_NoAcceptEncoding(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello world"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Accept-Encoding header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("should not compress without Accept-Encoding")
	}
	if rec.Body.String() != "hello world" {
		t.Error("body mismatch")
	}
}

func TestCompressionMiddleware_ExcludedPaths(t *testing.T) {
	cfg := CompressionConfig{
		ExcludedPaths: []string{"/static/"},
		ContentTypes:  []string{"text/plain"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello world"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/static/file.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("should not compress excluded paths")
	}
}

func TestCompressionMiddleware_UnsupportedContentType(t *testing.T) {
	cfg := CompressionConfig{
		ContentTypes: []string{"text/html"},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("binary data"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("should not compress unsupported content type")
	}
}

func TestCompressionMiddleware_AlreadyEncoded(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br") // Already Brotli encoded
		w.Write([]byte("pre-compressed data"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("should not re-compress already encoded content")
	}
}

func TestCompressionMiddleware_TextContentTypes(t *testing.T) {
	cfg := DefaultCompressionConfig()

	textTypes := []string{
		"text/html",
		"text/plain",
		"text/css",
		"text/javascript",
	}

	for _, contentType := range textTypes {
		t.Run(contentType, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				w.Write([]byte("content"))
			})

			handler := CompressionMiddleware(cfg)(next)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Header().Get("Content-Encoding") != "gzip" {
				t.Errorf("expected gzip for content type %s", contentType)
			}
		})
	}
}

func TestCompressionMiddleware_ContentTypeWithCharset(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"test": true}`))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Error("should compress content type with charset")
	}
}

func TestGzipResponseWriter_Flush(t *testing.T) {
	cfg := DefaultCompressionConfig()

	flushed := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("first chunk"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
			flushed = true
		}
		w.Write([]byte("second chunk"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !flushed {
		t.Error("expected Flush to be called")
	}
}

func TestGzipResponseWriter_MultipleWrites(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("first "))
		w.Write([]byte("second "))
		w.Write([]byte("third"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	reader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer reader.Close()

	body, _ := io.ReadAll(reader)
	if string(body) != "first second third" {
		t.Errorf("expected 'first second third', got %s", string(body))
	}
}

func TestGzipResponseWriter_WriteHeader(t *testing.T) {
	cfg := DefaultCompressionConfig()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	})

	handler := CompressionMiddleware(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rec.Code)
	}
}
