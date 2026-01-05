package coalesce

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultKeyExtractor(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/users?page=1", nil)
	key := DefaultKeyExtractor(req)

	expected := "GET:/api/users?page=1"
	if key != expected {
		t.Errorf("key = %v, want %v", key, expected)
	}
}

func TestKeyWithHeaders(t *testing.T) {
	extractor := KeyWithHeaders([]string{"Authorization", "X-Tenant"})

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("X-Tenant", "tenant1")

	key := extractor(req)

	if key == "GET:/api/users?" {
		t.Error("expected headers to be included in key")
	}
}

func TestNew(t *testing.T) {
	c := New(Config{})

	if c.config.MaxWaiters != 100 {
		t.Errorf("default MaxWaiters = %d, want 100", c.config.MaxWaiters)
	}
	if c.config.Timeout != 30*time.Second {
		t.Errorf("default Timeout = %v, want 30s", c.config.Timeout)
	}
}

func TestCoalescerDo(t *testing.T) {
	c := New(Config{})

	var execCount int32

	// Execute first request
	result1, coalesced1, err := c.Do(context.Background(), "test-key", func() (*Result, error) {
		atomic.AddInt32(&execCount, 1)
		time.Sleep(50 * time.Millisecond)
		return &Result{StatusCode: 200, Body: []byte("ok")}, nil
	})

	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if coalesced1 {
		t.Error("first request should not be coalesced")
	}
	if result1.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result1.StatusCode)
	}

	if atomic.LoadInt32(&execCount) != 1 {
		t.Errorf("execCount = %d, want 1", execCount)
	}
}

func TestCoalescerCoalescing(t *testing.T) {
	c := New(Config{})

	var execCount int32
	var wg sync.WaitGroup

	// Start multiple requests simultaneously
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			result, _, err := c.Do(context.Background(), "same-key", func() (*Result, error) {
				atomic.AddInt32(&execCount, 1)
				time.Sleep(100 * time.Millisecond)
				return &Result{StatusCode: 200, Body: []byte("shared")}, nil
			})

			if err != nil {
				t.Errorf("Do() error = %v", err)
			}
			if result == nil {
				t.Error("result should not be nil")
			}
		}()
	}

	wg.Wait()

	// Function should only be executed once
	if count := atomic.LoadInt32(&execCount); count != 1 {
		t.Errorf("execCount = %d, want 1", count)
	}
}

func TestCoalescerMetrics(t *testing.T) {
	c := New(Config{})

	// Execute some requests
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Do(context.Background(), "metrics-key", func() (*Result, error) {
				time.Sleep(50 * time.Millisecond)
				return &Result{StatusCode: 200}, nil
			})
		}()
	}

	wg.Wait()

	metrics := c.GetMetrics()
	if metrics.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3", metrics.TotalRequests)
	}
	if metrics.CoalescedRequests != 2 {
		t.Errorf("CoalescedRequests = %d, want 2", metrics.CoalescedRequests)
	}
}

func TestCoalescerMaxWaiters(t *testing.T) {
	c := New(Config{MaxWaiters: 2})

	var started int32
	var wg sync.WaitGroup

	// Start blocking request
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Do(context.Background(), "max-waiters-key", func() (*Result, error) {
			atomic.AddInt32(&started, 1)
			time.Sleep(200 * time.Millisecond)
			return &Result{StatusCode: 200}, nil
		})
	}()

	// Wait for first request to start
	time.Sleep(20 * time.Millisecond)

	// Add waiters up to max
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, err := c.Do(context.Background(), "max-waiters-key", func() (*Result, error) {
				return &Result{StatusCode: 200}, nil
			})
			if idx >= 2 && err == nil {
				t.Error("expected error for exceeded max waiters")
			}
		}(i)
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
}

func TestCoalescerTimeout(t *testing.T) {
	c := New(Config{Timeout: 50 * time.Millisecond})

	var wg sync.WaitGroup

	// Start slow request
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Do(context.Background(), "timeout-key", func() (*Result, error) {
			time.Sleep(200 * time.Millisecond)
			return &Result{StatusCode: 200}, nil
		})
	}()

	// Wait for first request to start
	time.Sleep(10 * time.Millisecond)

	// Add waiter that will timeout
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, err := c.Do(context.Background(), "timeout-key", func() (*Result, error) {
			return &Result{StatusCode: 200}, nil
		})
		if err == nil {
			t.Error("expected timeout error")
		}
	}()

	wg.Wait()
}

func TestCoalescerContextCancellation(t *testing.T) {
	c := New(Config{})

	var wg sync.WaitGroup

	// Start slow request
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.Do(context.Background(), "cancel-key", func() (*Result, error) {
			time.Sleep(200 * time.Millisecond)
			return &Result{StatusCode: 200}, nil
		})
	}()

	// Wait for first request to start
	time.Sleep(10 * time.Millisecond)

	// Add waiter with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, err := c.Do(ctx, "cancel-key", func() (*Result, error) {
			return &Result{StatusCode: 200}, nil
		})
		if err == nil {
			t.Error("expected context cancellation error")
		}
	}()

	wg.Wait()
}

func TestMiddleware(t *testing.T) {
	c := New(Config{})

	var execCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&execCount, 1)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	})

	middleware := Middleware(MiddlewareConfig{
		Coalescer: c,
	})

	wrapped := middleware(handler)

	// Send multiple concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)
		}()
	}

	wg.Wait()

	// Handler should only be called once for identical requests
	if count := atomic.LoadInt32(&execCount); count != 1 {
		t.Errorf("handler called %d times, want 1", count)
	}
}

func TestMiddlewareNonCoalesceable(t *testing.T) {
	c := New(Config{})

	var execCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&execCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(MiddlewareConfig{
		Coalescer: c,
	})

	wrapped := middleware(handler)

	// POST requests should not be coalesced by default
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}

	if count := atomic.LoadInt32(&execCount); count != 3 {
		t.Errorf("handler called %d times, want 3 (no coalescing)", count)
	}
}

func TestMiddlewareCoalescedHeader(t *testing.T) {
	c := New(Config{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(MiddlewareConfig{
		Coalescer: c,
	})

	wrapped := middleware(handler)

	var wg sync.WaitGroup
	var coalescedCount int32

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Header().Get("X-Coalesced") == "true" {
				atomic.AddInt32(&coalescedCount, 1)
			}
		}()
	}

	wg.Wait()

	// At least some should be marked as coalesced
	if atomic.LoadInt32(&coalescedCount) < 2 {
		t.Error("expected at least 2 coalesced responses")
	}
}

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator(100*time.Millisecond, nil)

	// First check should not find entry
	_, found := d.Check("key1")
	if found {
		t.Error("expected not found on first check")
	}

	// Store result
	d.Store("key1", &Result{StatusCode: 200, Body: []byte("cached")})

	// Second check should find entry
	result, found := d.Check("key1")
	if !found {
		t.Error("expected found after store")
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, found = d.Check("key1")
	if found {
		t.Error("expected not found after expiry")
	}
}

func TestIdempotencyMiddleware(t *testing.T) {
	d := NewDeduplicator(time.Minute, nil)

	var execCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&execCount, 1)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": "123"}`))
	})

	middleware := IdempotencyMiddleware(IdempotencyMiddlewareConfig{
		Deduplicator: d,
	})

	wrapped := middleware(handler)

	// First request with idempotency key
	req1 := httptest.NewRequest("POST", "/orders", nil)
	req1.Header.Set("Idempotency-Key", "order-abc")
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusCreated {
		t.Errorf("first request status = %d, want 201", rec1.Code)
	}

	// Second request with same key
	req2 := httptest.NewRequest("POST", "/orders", nil)
	req2.Header.Set("Idempotency-Key", "order-abc")
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Errorf("second request status = %d, want 201", rec2.Code)
	}
	if rec2.Header().Get("X-Idempotent-Replayed") != "true" {
		t.Error("expected X-Idempotent-Replayed header")
	}

	// Handler should only be called once
	if count := atomic.LoadInt32(&execCount); count != 1 {
		t.Errorf("handler called %d times, want 1", count)
	}
}

func TestIdempotencyMiddlewareNoKey(t *testing.T) {
	d := NewDeduplicator(time.Minute, nil)

	var execCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&execCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	middleware := IdempotencyMiddleware(IdempotencyMiddlewareConfig{
		Deduplicator: d,
	})

	wrapped := middleware(handler)

	// Requests without idempotency key should not be deduplicated
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}

	if count := atomic.LoadInt32(&execCount); count != 3 {
		t.Errorf("handler called %d times, want 3", count)
	}
}

func TestIdempotencyMiddlewareGetMethod(t *testing.T) {
	d := NewDeduplicator(time.Minute, nil)

	var execCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&execCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	middleware := IdempotencyMiddleware(IdempotencyMiddlewareConfig{
		Deduplicator: d,
	})

	wrapped := middleware(handler)

	// GET requests should pass through
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Idempotency-Key", "same-key")
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
	}

	if count := atomic.LoadInt32(&execCount); count != 3 {
		t.Errorf("handler called %d times, want 3 (GET not checked)", count)
	}
}

func TestBatcher(t *testing.T) {
	batcher := NewBatcher(BatcherConfig{
		MaxSize: 5,
		Window:  50 * time.Millisecond,
		Execute: func(reqs []BatchRequest) []BatchResult {
			results := make([]BatchResult, len(reqs))
			for i, req := range reqs {
				results[i] = BatchResult{
					ID:     req.ID,
					Result: &Result{StatusCode: 200, Body: []byte("batched")},
				}
			}
			return results
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result, err := batcher.Add(context.Background(), BatchRequest{
				ID:  "req-" + string(rune('A'+idx)),
				Key: "key",
			})
			if err != nil {
				t.Errorf("Add() error = %v", err)
			}
			if result.Result == nil {
				t.Error("expected result")
			}
		}(i)
	}

	wg.Wait()
}

func TestBatcherMaxSize(t *testing.T) {
	var batchSizes []int
	var mu sync.Mutex

	batcher := NewBatcher(BatcherConfig{
		MaxSize: 2,
		Window:  1 * time.Second, // Long window
		Execute: func(reqs []BatchRequest) []BatchResult {
			mu.Lock()
			batchSizes = append(batchSizes, len(reqs))
			mu.Unlock()

			results := make([]BatchResult, len(reqs))
			for i, req := range reqs {
				results[i] = BatchResult{ID: req.ID, Result: &Result{StatusCode: 200}}
			}
			return results
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			batcher.Add(context.Background(), BatchRequest{ID: string(rune('A' + idx))})
		}(i)
		time.Sleep(5 * time.Millisecond)
	}

	wg.Wait()

	// Should have batched at max size
	mu.Lock()
	for _, size := range batchSizes {
		if size > 2 {
			t.Errorf("batch size = %d, want <= 2", size)
		}
	}
	mu.Unlock()
}

func TestHandler(t *testing.T) {
	c := New(Config{})

	// Generate some metrics
	c.Do(context.Background(), "test", func() (*Result, error) {
		return &Result{StatusCode: 200}, nil
	})

	handler := NewHandler(c, nil)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Error("expected application/json content type")
	}
}

func TestResponseCapture(t *testing.T) {
	capture := &responseCapture{
		headers: make(http.Header),
		body:    &bytes.Buffer{},
	}

	capture.Header().Set("X-Test", "value")
	capture.WriteHeader(http.StatusCreated)
	capture.Write([]byte("test body"))

	if capture.statusCode != http.StatusCreated {
		t.Errorf("statusCode = %d, want 201", capture.statusCode)
	}
	if capture.Header().Get("X-Test") != "value" {
		t.Error("expected header to be set")
	}
	if capture.body.String() != "test body" {
		t.Errorf("body = %v, want 'test body'", capture.body.String())
	}
}

func TestResponseCaptureImplicitStatus(t *testing.T) {
	capture := &responseCapture{
		headers: make(http.Header),
		body:    &bytes.Buffer{},
	}

	// Write without explicit WriteHeader
	capture.Write([]byte("test"))

	if capture.statusCode != http.StatusOK {
		t.Errorf("implicit statusCode = %d, want 200", capture.statusCode)
	}
}

func TestDifferentKeys(t *testing.T) {
	c := New(Config{})

	var execCount int32
	var wg sync.WaitGroup

	// Requests with different keys should not coalesce
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := string(rune('A' + idx))
			c.Do(context.Background(), key, func() (*Result, error) {
				atomic.AddInt32(&execCount, 1)
				time.Sleep(20 * time.Millisecond)
				return &Result{StatusCode: 200}, nil
			})
		}(i)
	}

	wg.Wait()

	// Each unique key should execute
	if count := atomic.LoadInt32(&execCount); count != 3 {
		t.Errorf("execCount = %d, want 3", count)
	}
}

func TestMiddlewareOnCoalescedCallback(t *testing.T) {
	c := New(Config{})

	var coalescedCount int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(MiddlewareConfig{
		Coalescer: c,
		OnCoalesced: func(r *http.Request, result *Result) {
			atomic.AddInt32(&coalescedCount, 1)
		},
	})

	wrapped := middleware(handler)

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)
		}()
	}

	wg.Wait()

	if count := atomic.LoadInt32(&coalescedCount); count < 2 {
		t.Errorf("coalescedCount = %d, want at least 2", count)
	}
}
