// Package shadow provides request shadowing (traffic mirroring) functionality.
// Shadow requests are fire-and-forget copies of live traffic sent to test services.
package shadow

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Target represents a shadow traffic destination.
type Target struct {
	Name       string        // Target identifier
	Address    string        // Target address (host:port)
	Percentage int           // Percentage of traffic to shadow (0-100)
	Timeout    time.Duration // Request timeout
	Headers    Headers       // Additional headers to add to shadowed requests
}

// Headers are key-value pairs to add to requests.
type Headers map[string]string

// Config configures shadow traffic behavior.
type Config struct {
	// RouteID is the route this shadow config applies to
	RouteID string
	// Targets are the shadow destinations
	Targets []Target
	// MaxConcurrent limits concurrent shadow requests per target
	MaxConcurrent int
	// BufferSize is the max body size to buffer for shadowing
	BufferSize int64
	// DropOnFull determines whether to drop requests when buffer is full
	DropOnFull bool
}

// Manager manages shadow traffic routing.
type Manager struct {
	configs    map[string]*shadowConfig // routeID -> config
	client     *http.Client
	workerPool *workerPool
	mu         sync.RWMutex
	logger     *slog.Logger
	metrics    *Metrics
}

// shadowConfig is the internal representation of a shadow configuration.
type shadowConfig struct {
	Config
	mu sync.RWMutex
}

// Metrics tracks shadow traffic metrics.
type Metrics struct {
	RequestsSent    map[string]*uint64 // target -> count
	RequestsDropped map[string]*uint64 // target -> count
	Errors          map[string]*uint64 // target -> count
	LatencySum      map[string]*uint64 // target -> sum of latencies in ms
	mu              sync.RWMutex
}

// NewManager creates a new shadow traffic manager.
func NewManager() *Manager {
	return &Manager{
		configs: make(map[string]*shadowConfig),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		workerPool: newWorkerPool(100), // 100 concurrent shadow workers
		logger:     slog.Default(),
		metrics:    newMetrics(),
	}
}

// Configure sets up shadow traffic for a route.
func (m *Manager) Configure(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 10
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1024 * 1024 // 1MB default
	}

	for i := range cfg.Targets {
		if cfg.Targets[i].Timeout == 0 {
			cfg.Targets[i].Timeout = 5 * time.Second
		}
	}

	m.configs[cfg.RouteID] = &shadowConfig{Config: cfg}
	m.initMetrics(cfg.Targets)

	m.logger.Info("configured shadow traffic",
		"route", cfg.RouteID,
		"targets", len(cfg.Targets))

	return nil
}

// Remove removes shadow configuration for a route.
func (m *Manager) Remove(routeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.configs, routeID)
}

// GetConfig returns the shadow config for a route.
func (m *Manager) GetConfig(routeID string) (*Config, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[routeID]
	if !ok {
		return nil, false
	}
	return &cfg.Config, true
}

// Shadow sends a copy of the request to configured shadow targets.
// This is non-blocking and returns immediately.
func (m *Manager) Shadow(routeID string, r *http.Request, body []byte) {
	m.mu.RLock()
	cfg, ok := m.configs[routeID]
	m.mu.RUnlock()

	if !ok || len(cfg.Targets) == 0 {
		return
	}

	for _, target := range cfg.Targets {
		// Check if this request should be shadowed based on percentage
		if !shouldShadow(target.Percentage) {
			continue
		}

		// Clone request for shadow
		shadowReq := cloneRequest(r, body, target)
		if shadowReq == nil {
			continue
		}

		// Submit to worker pool (non-blocking)
		submitted := m.workerPool.Submit(func() {
			m.sendShadow(target, shadowReq)
		})

		if !submitted {
			m.recordDropped(target.Name)
			if !cfg.DropOnFull {
				m.logger.Warn("shadow request dropped: pool full",
					"target", target.Name,
					"route", routeID)
			}
		}
	}
}

// sendShadow sends a shadow request to a target.
func (m *Manager) sendShadow(target Target, req *http.Request) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(req.Context(), target.Timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := m.client.Do(req)
	if err != nil {
		m.recordError(target.Name)
		m.logger.Debug("shadow request failed",
			"target", target.Name,
			"error", err)
		return
	}
	defer resp.Body.Close()

	// Drain body to enable connection reuse
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024))

	m.recordRequest(target.Name, time.Since(start))
}

// cloneRequest creates a copy of the request for shadowing.
func cloneRequest(r *http.Request, body []byte, target Target) *http.Request {
	// Build target URL
	targetURL := "http://" + target.Address + r.URL.RequestURI()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(r.Method, targetURL, bodyReader)
	if err != nil {
		return nil
	}

	// Copy headers
	for k, v := range r.Header {
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}

	// Add shadow-specific headers
	req.Header.Set("X-Shadow-Request", "true")
	req.Header.Set("X-Original-Host", r.Host)

	// Add target-specific headers
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	// Copy content length if body is present
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}

	return req
}

// shouldShadow returns true if the request should be shadowed based on percentage.
func shouldShadow(percentage int) bool {
	if percentage >= 100 {
		return true
	}
	if percentage <= 0 {
		return false
	}
	return fastrand()%100 < uint32(percentage)
}

// fastrand is a fast random number generator for traffic sampling.
var randCounter uint64

func fastrand() uint32 {
	counter := atomic.AddUint64(&randCounter, 1)
	// Simple LCG for fast random
	return uint32(counter*6364136223846793005 + 1442695040888963407)
}

// Metrics recording
func (m *Manager) initMetrics(targets []Target) {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	for _, t := range targets {
		if _, ok := m.metrics.RequestsSent[t.Name]; !ok {
			zero := uint64(0)
			m.metrics.RequestsSent[t.Name] = &zero
			zero2 := uint64(0)
			m.metrics.RequestsDropped[t.Name] = &zero2
			zero3 := uint64(0)
			m.metrics.Errors[t.Name] = &zero3
			zero4 := uint64(0)
			m.metrics.LatencySum[t.Name] = &zero4
		}
	}
}

func (m *Manager) recordRequest(target string, latency time.Duration) {
	m.metrics.mu.RLock()
	if counter, ok := m.metrics.RequestsSent[target]; ok {
		atomic.AddUint64(counter, 1)
	}
	if latencySum, ok := m.metrics.LatencySum[target]; ok {
		atomic.AddUint64(latencySum, uint64(latency.Milliseconds()))
	}
	m.metrics.mu.RUnlock()
}

func (m *Manager) recordDropped(target string) {
	m.metrics.mu.RLock()
	if counter, ok := m.metrics.RequestsDropped[target]; ok {
		atomic.AddUint64(counter, 1)
	}
	m.metrics.mu.RUnlock()
}

func (m *Manager) recordError(target string) {
	m.metrics.mu.RLock()
	if counter, ok := m.metrics.Errors[target]; ok {
		atomic.AddUint64(counter, 1)
	}
	m.metrics.mu.RUnlock()
}

// GetMetrics returns shadow traffic metrics.
func (m *Manager) GetMetrics() map[string]TargetMetrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	result := make(map[string]TargetMetrics)
	for name, sent := range m.metrics.RequestsSent {
		sentCount := atomic.LoadUint64(sent)
		var avgLatency time.Duration
		if sentCount > 0 {
			latencySum := atomic.LoadUint64(m.metrics.LatencySum[name])
			avgLatency = time.Duration(latencySum/sentCount) * time.Millisecond
		}
		result[name] = TargetMetrics{
			RequestsSent:    sentCount,
			RequestsDropped: atomic.LoadUint64(m.metrics.RequestsDropped[name]),
			Errors:          atomic.LoadUint64(m.metrics.Errors[name]),
			AvgLatency:      avgLatency,
		}
	}
	return result
}

// TargetMetrics holds metrics for a shadow target.
type TargetMetrics struct {
	RequestsSent    uint64
	RequestsDropped uint64
	Errors          uint64
	AvgLatency      time.Duration
}

func newMetrics() *Metrics {
	return &Metrics{
		RequestsSent:    make(map[string]*uint64),
		RequestsDropped: make(map[string]*uint64),
		Errors:          make(map[string]*uint64),
		LatencySum:      make(map[string]*uint64),
	}
}

// workerPool provides a bounded pool of goroutines for shadow requests.
type workerPool struct {
	tasks   chan func()
	workers int
}

func newWorkerPool(workers int) *workerPool {
	p := &workerPool{
		tasks:   make(chan func(), workers*10), // Buffer for 10x workers
		workers: workers,
	}

	// Start workers
	for i := 0; i < workers; i++ {
		go p.worker()
	}

	return p
}

func (p *workerPool) worker() {
	for task := range p.tasks {
		task()
	}
}

// Submit submits a task to the pool. Returns false if the pool is full.
func (p *workerPool) Submit(task func()) bool {
	select {
	case p.tasks <- task:
		return true
	default:
		return false
	}
}

// Close shuts down the worker pool.
func (p *workerPool) Close() {
	close(p.tasks)
}

// Close shuts down the shadow manager.
func (m *Manager) Close() {
	m.workerPool.Close()
}
