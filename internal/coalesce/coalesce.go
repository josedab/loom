// Package coalesce provides request coalescing to deduplicate concurrent identical requests.
package coalesce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Result represents the result of a coalesced request.
type Result struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Error      error
}

// Flight represents an in-flight request.
type Flight struct {
	key       string
	done      chan struct{}
	result    *Result
	waiters   int
	mu        sync.Mutex
	startTime time.Time
}

// Coalescer manages request coalescing.
type Coalescer struct {
	flights  map[string]*Flight
	mu       sync.Mutex
	config   Config
	logger   *slog.Logger
	metrics  *Metrics
}

// Config configures the coalescer.
type Config struct {
	// KeyExtractor generates a key for a request.
	KeyExtractor func(*http.Request) string
	// MaxWaiters is the maximum number of requests waiting for a single flight.
	MaxWaiters int
	// Timeout is the maximum time to wait for a flight to complete.
	Timeout time.Duration
	// EnableBody includes request body in the key.
	EnableBody bool
	// MaxBodySize is the maximum body size to include in the key.
	MaxBodySize int64
	// Logger for coalescer events.
	Logger *slog.Logger
}

// Metrics tracks coalescing statistics.
type Metrics struct {
	mu                sync.RWMutex
	TotalRequests     int64 `json:"total_requests"`
	CoalescedRequests int64 `json:"coalesced_requests"`
	ActiveFlights     int   `json:"active_flights"`
	AvgWaiters        float64 `json:"avg_waiters"`
}

// New creates a new coalescer.
func New(cfg Config) *Coalescer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxWaiters == 0 {
		cfg.MaxWaiters = 100
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1024 * 1024 // 1MB
	}
	if cfg.KeyExtractor == nil {
		cfg.KeyExtractor = DefaultKeyExtractor
	}

	return &Coalescer{
		flights: make(map[string]*Flight),
		config:  cfg,
		logger:  cfg.Logger,
		metrics: &Metrics{},
	}
}

// DefaultKeyExtractor generates a key from method, path, and query.
func DefaultKeyExtractor(r *http.Request) string {
	return fmt.Sprintf("%s:%s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
}

// KeyWithHeaders generates a key including specified headers.
func KeyWithHeaders(headers []string) func(*http.Request) string {
	return func(r *http.Request) string {
		key := DefaultKeyExtractor(r)
		for _, h := range headers {
			if v := r.Header.Get(h); v != "" {
				key += fmt.Sprintf(":%s=%s", h, v)
			}
		}
		return key
	}
}

// KeyWithBody generates a key including the request body hash.
func KeyWithBody(maxSize int64) func(*http.Request) string {
	return func(r *http.Request) string {
		key := DefaultKeyExtractor(r)

		if r.Body == nil || r.ContentLength == 0 {
			return key
		}

		// Read body
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxSize))
		if err != nil {
			return key
		}

		// Restore body
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Hash body
		hash := sha256.Sum256(bodyBytes)
		return key + ":body=" + hex.EncodeToString(hash[:8])
	}
}

// Do executes a request with coalescing.
func (c *Coalescer) Do(ctx context.Context, key string, fn func() (*Result, error)) (*Result, bool, error) {
	c.metrics.mu.Lock()
	c.metrics.TotalRequests++
	c.metrics.mu.Unlock()

	c.mu.Lock()

	// Check for existing flight
	if flight, ok := c.flights[key]; ok {
		flight.mu.Lock()
		if flight.waiters >= c.config.MaxWaiters {
			flight.mu.Unlock()
			c.mu.Unlock()
			return nil, false, fmt.Errorf("max waiters exceeded for key: %s", key)
		}
		flight.waiters++
		flight.mu.Unlock()
		c.mu.Unlock()

		c.metrics.mu.Lock()
		c.metrics.CoalescedRequests++
		c.metrics.mu.Unlock()

		// Wait for flight to complete
		select {
		case <-flight.done:
			return flight.result, true, nil
		case <-ctx.Done():
			return nil, true, ctx.Err()
		case <-time.After(c.config.Timeout):
			return nil, true, fmt.Errorf("timeout waiting for flight: %s", key)
		}
	}

	// Create new flight
	flight := &Flight{
		key:       key,
		done:      make(chan struct{}),
		waiters:   1,
		startTime: time.Now(),
	}
	c.flights[key] = flight

	c.metrics.mu.Lock()
	c.metrics.ActiveFlights = len(c.flights)
	c.metrics.mu.Unlock()

	c.mu.Unlock()

	// Execute the function
	result, err := fn()
	if err != nil {
		flight.result = &Result{Error: err}
	} else {
		flight.result = result
	}

	// Complete the flight
	close(flight.done)

	// Remove from active flights
	c.mu.Lock()
	delete(c.flights, key)
	c.metrics.mu.Lock()
	c.metrics.ActiveFlights = len(c.flights)
	c.metrics.mu.Unlock()
	c.mu.Unlock()

	c.logger.Debug("flight completed",
		"key", key,
		"waiters", flight.waiters,
		"duration", time.Since(flight.startTime),
	)

	return flight.result, false, err
}

// DoRequest executes an HTTP request with coalescing.
func (c *Coalescer) DoRequest(ctx context.Context, r *http.Request, transport http.RoundTripper) (*Result, bool, error) {
	key := c.config.KeyExtractor(r)

	return c.Do(ctx, key, func() (*Result, error) {
		resp, err := transport.RoundTrip(r.WithContext(ctx))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return &Result{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header.Clone(),
			Body:       body,
		}, nil
	})
}

// GetMetrics returns current metrics.
func (c *Coalescer) GetMetrics() *Metrics {
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()

	return &Metrics{
		TotalRequests:     c.metrics.TotalRequests,
		CoalescedRequests: c.metrics.CoalescedRequests,
		ActiveFlights:     c.metrics.ActiveFlights,
		AvgWaiters:        c.metrics.AvgWaiters,
	}
}

// MiddlewareConfig configures the coalescing middleware.
type MiddlewareConfig struct {
	// Coalescer is the coalescer to use.
	Coalescer *Coalescer
	// ShouldCoalesce determines if a request should be coalesced.
	ShouldCoalesce func(*http.Request) bool
	// OnCoalesced is called when a request was coalesced.
	OnCoalesced func(*http.Request, *Result)
	// Logger for middleware events.
	Logger *slog.Logger
}

// Middleware returns HTTP middleware that coalesces requests.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ShouldCoalesce == nil {
		cfg.ShouldCoalesce = func(r *http.Request) bool {
			// Only coalesce safe methods by default
			return r.Method == http.MethodGet || r.Method == http.MethodHead
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.ShouldCoalesce(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := cfg.Coalescer.config.KeyExtractor(r)

			result, coalesced, err := cfg.Coalescer.Do(r.Context(), key, func() (*Result, error) {
				// Capture the response
				capture := &responseCapture{
					ResponseWriter: w,
					headers:        make(http.Header),
					body:           &bytes.Buffer{},
				}

				next.ServeHTTP(capture, r)

				return &Result{
					StatusCode: capture.statusCode,
					Headers:    capture.headers,
					Body:       capture.body.Bytes(),
				}, nil
			})

			if err != nil {
				cfg.Logger.Error("coalesce error", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			if coalesced && cfg.OnCoalesced != nil {
				cfg.OnCoalesced(r, result)
			}

			// Write result to response
			writeResult(w, result)
		})
	}
}

// responseCapture captures an HTTP response.
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	headers    http.Header
	body       *bytes.Buffer
	written    bool
}

func (c *responseCapture) Header() http.Header {
	return c.headers
}

func (c *responseCapture) WriteHeader(code int) {
	if !c.written {
		c.statusCode = code
		c.written = true
	}
}

func (c *responseCapture) Write(b []byte) (int, error) {
	if !c.written {
		c.statusCode = http.StatusOK
		c.written = true
	}
	return c.body.Write(b)
}

// writeResult writes a result to the response writer.
func writeResult(w http.ResponseWriter, result *Result) {
	for key, values := range result.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Set("X-Coalesced", "true")
	w.WriteHeader(result.StatusCode)
	w.Write(result.Body)
}

// Group manages request groups for batch coalescing.
type Group struct {
	coalescer *Coalescer
	batcher   *Batcher
	config    GroupConfig
}

// GroupConfig configures a request group.
type GroupConfig struct {
	// MaxBatchSize is the maximum number of requests in a batch.
	MaxBatchSize int
	// BatchWindow is the time to wait for more requests.
	BatchWindow time.Duration
	// Executor executes a batch of requests.
	Executor func(context.Context, []BatchRequest) []BatchResult
	// Logger for group events.
	Logger *slog.Logger
}

// BatchRequest represents a request in a batch.
type BatchRequest struct {
	ID      string
	Key     string
	Request *http.Request
	Data    interface{}
}

// BatchResult represents the result of a batch request.
type BatchResult struct {
	ID     string
	Result *Result
	Error  error
}

// Batcher batches requests for efficient processing.
type Batcher struct {
	config   BatcherConfig
	pending  []pendingRequest
	mu       sync.Mutex
	timer    *time.Timer
	logger   *slog.Logger
}

// BatcherConfig configures the batcher.
type BatcherConfig struct {
	// MaxSize is the maximum batch size.
	MaxSize int
	// Window is the batching window.
	Window time.Duration
	// Execute processes a batch.
	Execute func([]BatchRequest) []BatchResult
}

type pendingRequest struct {
	req    BatchRequest
	result chan BatchResult
}

// NewBatcher creates a new batcher.
func NewBatcher(cfg BatcherConfig) *Batcher {
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100
	}
	if cfg.Window == 0 {
		cfg.Window = 10 * time.Millisecond
	}

	return &Batcher{
		config:  cfg,
		pending: make([]pendingRequest, 0, cfg.MaxSize),
		logger:  slog.Default(),
	}
}

// Add adds a request to the batch.
func (b *Batcher) Add(ctx context.Context, req BatchRequest) (BatchResult, error) {
	resultChan := make(chan BatchResult, 1)

	b.mu.Lock()

	b.pending = append(b.pending, pendingRequest{
		req:    req,
		result: resultChan,
	})

	// Start timer on first request
	if len(b.pending) == 1 {
		b.timer = time.AfterFunc(b.config.Window, b.flush)
	}

	// Flush if at capacity
	if len(b.pending) >= b.config.MaxSize {
		if b.timer != nil {
			b.timer.Stop()
		}
		b.flushLocked()
	} else {
		b.mu.Unlock()
	}

	select {
	case result := <-resultChan:
		return result, result.Error
	case <-ctx.Done():
		return BatchResult{ID: req.ID, Error: ctx.Err()}, ctx.Err()
	}
}

// flush flushes the pending batch.
func (b *Batcher) flush() {
	b.mu.Lock()
	b.flushLocked()
}

// flushLocked flushes the pending batch (must hold lock).
func (b *Batcher) flushLocked() {
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}

	pending := b.pending
	b.pending = make([]pendingRequest, 0, b.config.MaxSize)
	b.mu.Unlock()

	// Build batch
	requests := make([]BatchRequest, len(pending))
	for i, p := range pending {
		requests[i] = p.req
	}

	// Execute batch
	results := b.config.Execute(requests)

	// Map results to pending requests
	resultMap := make(map[string]BatchResult)
	for _, r := range results {
		resultMap[r.ID] = r
	}

	// Send results
	for _, p := range pending {
		if result, ok := resultMap[p.req.ID]; ok {
			p.result <- result
		} else {
			p.result <- BatchResult{ID: p.req.ID, Error: fmt.Errorf("no result for request")}
		}
		close(p.result)
	}
}

// Handler provides an HTTP API for coalescing metrics.
type Handler struct {
	coalescer *Coalescer
	logger    *slog.Logger
}

// NewHandler creates a new handler.
func NewHandler(coalescer *Coalescer, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		coalescer: coalescer,
		logger:    logger,
	}
}

// ServeHTTP handles metrics requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics := h.coalescer.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Deduplicator provides request deduplication with TTL.
type Deduplicator struct {
	seen   map[string]*dedupeEntry
	mu     sync.RWMutex
	ttl    time.Duration
	logger *slog.Logger
}

type dedupeEntry struct {
	result    *Result
	expiresAt time.Time
}

// NewDeduplicator creates a new deduplicator.
func NewDeduplicator(ttl time.Duration, logger *slog.Logger) *Deduplicator {
	if logger == nil {
		logger = slog.Default()
	}
	if ttl == 0 {
		ttl = time.Second
	}

	d := &Deduplicator{
		seen:   make(map[string]*dedupeEntry),
		ttl:    ttl,
		logger: logger,
	}

	go d.cleanup()

	return d
}

// Check checks if a request is a duplicate.
func (d *Deduplicator) Check(key string) (*Result, bool) {
	d.mu.RLock()
	entry, ok := d.seen[key]
	d.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.result, true
	}

	return nil, false
}

// Store stores a result for deduplication.
func (d *Deduplicator) Store(key string, result *Result) {
	d.mu.Lock()
	d.seen[key] = &dedupeEntry{
		result:    result,
		expiresAt: time.Now().Add(d.ttl),
	}
	d.mu.Unlock()
}

// cleanup periodically removes expired entries.
func (d *Deduplicator) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		d.mu.Lock()
		for key, entry := range d.seen {
			if now.After(entry.expiresAt) {
				delete(d.seen, key)
			}
		}
		d.mu.Unlock()
	}
}

// IdempotencyMiddlewareConfig configures idempotency middleware.
type IdempotencyMiddlewareConfig struct {
	// Deduplicator is the deduplicator to use.
	Deduplicator *Deduplicator
	// KeyHeader is the header containing the idempotency key.
	KeyHeader string
	// Methods are the HTTP methods to check.
	Methods []string
	// Logger for middleware events.
	Logger *slog.Logger
}

// IdempotencyMiddleware returns middleware that ensures idempotent requests.
func IdempotencyMiddleware(cfg IdempotencyMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.KeyHeader == "" {
		cfg.KeyHeader = "Idempotency-Key"
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{http.MethodPost, http.MethodPut}
	}

	methodSet := make(map[string]bool)
	for _, m := range cfg.Methods {
		methodSet[m] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only check configured methods
			if !methodSet[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Header.Get(cfg.KeyHeader)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check for duplicate
			if result, isDupe := cfg.Deduplicator.Check(key); isDupe {
				cfg.Logger.Debug("idempotent request detected", "key", key)
				w.Header().Set("X-Idempotent-Replayed", "true")
				writeResult(w, result)
				return
			}

			// Capture response
			capture := &responseCapture{
				ResponseWriter: w,
				headers:        make(http.Header),
				body:           &bytes.Buffer{},
			}

			next.ServeHTTP(capture, r)

			// Store for deduplication
			result := &Result{
				StatusCode: capture.statusCode,
				Headers:    capture.headers,
				Body:       capture.body.Bytes(),
			}
			cfg.Deduplicator.Store(key, result)

			// Write response
			for k, values := range capture.headers {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(capture.statusCode)
			w.Write(capture.body.Bytes())
		})
	}
}
