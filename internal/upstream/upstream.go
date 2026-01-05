// Package upstream provides backend connection management with load balancing.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josedab/loom/internal/config"
)

var (
	ErrNoHealthyEndpoints = errors.New("no healthy endpoints available")
	ErrCircuitOpen        = errors.New("circuit breaker is open")
	ErrUpstreamNotFound   = errors.New("upstream not found")
)

// Endpoint is a single backend instance.
type Endpoint struct {
	Address      string
	Weight       int
	healthy      atomic.Bool
	activeConns  atomic.Int64
	failureCount atomic.Int64
	lastChecked  atomic.Value // time.Time
}

// IsHealthy returns whether the endpoint is healthy.
func (e *Endpoint) IsHealthy() bool {
	return e.healthy.Load()
}

// SetHealthy sets the endpoint health status.
func (e *Endpoint) SetHealthy(healthy bool) {
	e.healthy.Store(healthy)
	e.lastChecked.Store(time.Now())
}

// ActiveConnections returns the number of active connections.
func (e *Endpoint) ActiveConnections() int64 {
	return e.activeConns.Load()
}

// Upstream represents a backend service.
type Upstream struct {
	Name         string
	Endpoints    []*Endpoint
	LoadBalancer LoadBalancer
	Circuit      *CircuitBreaker
	RetryPolicy  *RetryPolicy
	RetryBudget  *RetryBudget // Prevents retry storms
	Bulkhead     *Bulkhead    // Limits concurrent requests
	mu           sync.RWMutex
}

// LoadBalancer interface for different strategies.
type LoadBalancer interface {
	Select(endpoints []*Endpoint) *Endpoint
}

// RoundRobinBalancer implements round-robin selection.
type RoundRobinBalancer struct {
	current atomic.Uint64
}

// Select selects an endpoint using round-robin.
func (b *RoundRobinBalancer) Select(endpoints []*Endpoint) *Endpoint {
	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return nil
	}
	idx := b.current.Add(1) % uint64(len(healthy))
	return healthy[idx]
}

// WeightedBalancer implements weighted selection.
type WeightedBalancer struct {
	rng *rand.Rand
	mu  sync.Mutex
}

// NewWeightedBalancer creates a new weighted balancer.
func NewWeightedBalancer() *WeightedBalancer {
	return &WeightedBalancer{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Select selects an endpoint based on weight.
func (b *WeightedBalancer) Select(endpoints []*Endpoint) *Endpoint {
	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return nil
	}

	totalWeight := 0
	for _, ep := range healthy {
		totalWeight += ep.Weight
	}

	b.mu.Lock()
	r := b.rng.Intn(totalWeight)
	b.mu.Unlock()

	for _, ep := range healthy {
		r -= ep.Weight
		if r < 0 {
			return ep
		}
	}

	return healthy[0]
}

// LeastConnBalancer implements least-connections selection.
type LeastConnBalancer struct{}

// Select selects the endpoint with fewest connections.
func (b *LeastConnBalancer) Select(endpoints []*Endpoint) *Endpoint {
	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return nil
	}

	var selected *Endpoint
	minConns := int64(^uint64(0) >> 1) // max int64

	for _, ep := range healthy {
		conns := ep.activeConns.Load()
		if conns < minConns {
			minConns = conns
			selected = ep
		}
	}

	return selected
}

// RandomBalancer implements random selection.
type RandomBalancer struct {
	rng *rand.Rand
	mu  sync.Mutex
}

// NewRandomBalancer creates a new random balancer.
func NewRandomBalancer() *RandomBalancer {
	return &RandomBalancer{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Select selects a random endpoint.
func (b *RandomBalancer) Select(endpoints []*Endpoint) *Endpoint {
	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return nil
	}

	b.mu.Lock()
	idx := b.rng.Intn(len(healthy))
	b.mu.Unlock()

	return healthy[idx]
}

// healthyEndpointPool pools slices for filterHealthy to reduce allocations.
var healthyEndpointPool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate with typical capacity
		return make([]*Endpoint, 0, 16)
	},
}

// filterHealthy returns only the healthy endpoints.
// The returned slice should not be held long-term as it may be pooled.
func filterHealthy(endpoints []*Endpoint) []*Endpoint {
	// For small endpoint lists, pre-allocate inline to avoid pool overhead
	if len(endpoints) <= 8 {
		healthy := make([]*Endpoint, 0, len(endpoints))
		for _, ep := range endpoints {
			if ep.IsHealthy() {
				healthy = append(healthy, ep)
			}
		}
		return healthy
	}

	// For larger lists, use pooled slice
	healthy := healthyEndpointPool.Get().([]*Endpoint)
	healthy = healthy[:0] // Reset length, keep capacity
	if cap(healthy) < len(endpoints) {
		healthy = make([]*Endpoint, 0, len(endpoints))
	}

	for _, ep := range endpoints {
		if ep.IsHealthy() {
			healthy = append(healthy, ep)
		}
	}
	return healthy
}

// releaseHealthySlice returns a slice to the pool.
// This is optional but helps reduce allocations in tight loops.
func releaseHealthySlice(slice []*Endpoint) {
	if slice == nil || cap(slice) > 64 {
		// Don't pool very large slices
		return
	}
	// Clear references to allow GC
	for i := range slice {
		slice[i] = nil
	}
	healthyEndpointPool.Put(slice[:0])
}

// ConsistentHashBalancer implements consistent hashing for session affinity.
// It distributes requests based on a hash key, ensuring the same key always
// goes to the same endpoint (when available).
type ConsistentHashBalancer struct {
	replicas int                  // Virtual nodes per endpoint
	ring     []uint32             // Sorted hash ring
	nodes    map[uint32]*Endpoint // Hash -> endpoint mapping
	mu       sync.RWMutex
	hashKey  string // Header name to use as hash key (e.g., "X-User-ID")
}

// NewConsistentHashBalancer creates a new consistent hash balancer.
// replicas: number of virtual nodes per endpoint (higher = better distribution)
// hashKey: HTTP header name to use as the hash key
func NewConsistentHashBalancer(replicas int, hashKey string) *ConsistentHashBalancer {
	if replicas <= 0 {
		replicas = 150 // Default: 150 virtual nodes per endpoint
	}
	if hashKey == "" {
		hashKey = "X-Request-ID" // Default: use request ID
	}
	return &ConsistentHashBalancer{
		replicas: replicas,
		nodes:    make(map[uint32]*Endpoint),
		hashKey:  hashKey,
	}
}

// hashKey32 computes a 32-bit hash using FNV-1a.
func hashKey32(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h
}

// buildRing builds the hash ring from endpoints.
func (b *ConsistentHashBalancer) buildRing(endpoints []*Endpoint) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear existing ring
	b.ring = b.ring[:0]
	b.nodes = make(map[uint32]*Endpoint)

	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return
	}

	// Add virtual nodes for each endpoint
	for _, ep := range healthy {
		for i := 0; i < b.replicas; i++ {
			key := fmt.Sprintf("%s-%d", ep.Address, i)
			hash := hashKey32(key)
			b.ring = append(b.ring, hash)
			b.nodes[hash] = ep
		}
	}

	// Sort the ring
	sortUint32(b.ring)
}

// sortUint32 sorts a slice of uint32.
func sortUint32(a []uint32) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// Select selects an endpoint (falls back to random for requests without the hash key).
func (b *ConsistentHashBalancer) Select(endpoints []*Endpoint) *Endpoint {
	healthy := filterHealthy(endpoints)
	if len(healthy) == 0 {
		return nil
	}
	// Without a key, fall back to random selection
	return healthy[rand.Intn(len(healthy))]
}

// SelectWithKey selects an endpoint based on a hash key for consistent routing.
func (b *ConsistentHashBalancer) SelectWithKey(endpoints []*Endpoint, key string) *Endpoint {
	if key == "" {
		return b.Select(endpoints)
	}

	// Rebuild ring if endpoints changed (simple check: length)
	b.mu.RLock()
	ringLen := len(b.ring)
	b.mu.RUnlock()

	healthy := filterHealthy(endpoints)
	expectedLen := len(healthy) * b.replicas
	if ringLen != expectedLen {
		b.buildRing(endpoints)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.ring) == 0 {
		return nil
	}

	// Hash the key and find the nearest node on the ring
	hash := hashKey32(key)
	idx := b.search(hash)
	return b.nodes[b.ring[idx]]
}

// search finds the first node in the ring with hash >= the given hash.
func (b *ConsistentHashBalancer) search(hash uint32) int {
	// Binary search for the first element >= hash
	lo, hi := 0, len(b.ring)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if b.ring[mid] < hash {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	// Wrap around if we're past the end
	if lo >= len(b.ring) {
		lo = 0
	}
	return lo
}

// GetHashKey returns the header name used for hashing.
func (b *ConsistentHashBalancer) GetHashKey() string {
	return b.hashKey
}

// KeyBasedBalancer is an interface for load balancers that support key-based selection.
type KeyBasedBalancer interface {
	LoadBalancer
	SelectWithKey(endpoints []*Endpoint, key string) *Endpoint
	GetHashKey() string
}

// JitterMode controls how jitter is applied to backoff.
type JitterMode int

const (
	// JitterNone applies no jitter (deterministic backoff).
	JitterNone JitterMode = iota
	// JitterFull applies full jitter: random value between 0 and backoff.
	JitterFull
	// JitterEqual applies equal jitter: backoff/2 + random(0, backoff/2).
	// This provides a good balance between preventing thundering herd and
	// ensuring reasonable minimum backoff.
	JitterEqual
	// JitterDecorelated applies decorrelated jitter: random(base, prev*3).
	// This provides the best distribution for many use cases.
	JitterDecorelated
)

// RetryPolicy defines retry behavior.
type RetryPolicy struct {
	MaxRetries     int
	BackoffBase    time.Duration
	BackoffMax     time.Duration
	RetryableCodes map[int]bool
	JitterMode     JitterMode    // How to apply jitter (default: JitterEqual)
	lastBackoff    time.Duration // For decorrelated jitter
	mu             sync.Mutex    // Protects lastBackoff
}

// ShouldRetry checks if a status code is retryable.
func (p *RetryPolicy) ShouldRetry(statusCode int) bool {
	if p.RetryableCodes == nil {
		// Default retryable codes: 502, 503, 504
		return statusCode == 502 || statusCode == 503 || statusCode == 504
	}
	return p.RetryableCodes[statusCode]
}

// jitterRng is a shared random source for jitter calculations.
var jitterRng = struct {
	*rand.Rand
	sync.Mutex
}{
	Rand: rand.New(rand.NewSource(time.Now().UnixNano())),
}

// BackoffDuration calculates backoff for an attempt with jitter.
func (p *RetryPolicy) BackoffDuration(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	// Calculate base exponential backoff
	backoff := p.BackoffBase
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff > p.BackoffMax {
			backoff = p.BackoffMax
			break
		}
	}

	// Apply jitter based on mode
	switch p.JitterMode {
	case JitterNone:
		return backoff

	case JitterFull:
		// Full jitter: random value between 0 and backoff
		jitterRng.Lock()
		jittered := time.Duration(jitterRng.Int63n(int64(backoff) + 1))
		jitterRng.Unlock()
		return jittered

	case JitterDecorelated:
		// Decorrelated jitter: random(base, prev*3), capped at max
		p.mu.Lock()
		if p.lastBackoff == 0 {
			p.lastBackoff = p.BackoffBase
		}
		upper := int64(p.lastBackoff) * 3
		if upper > int64(p.BackoffMax) {
			upper = int64(p.BackoffMax)
		}
		lower := int64(p.BackoffBase)
		jitterRng.Lock()
		jittered := time.Duration(lower + jitterRng.Int63n(upper-lower+1))
		jitterRng.Unlock()
		p.lastBackoff = jittered
		p.mu.Unlock()
		if jittered > p.BackoffMax {
			return p.BackoffMax
		}
		return jittered

	case JitterEqual:
		fallthrough
	default:
		// Equal jitter (default): backoff/2 + random(0, backoff/2)
		// This ensures at least half the calculated backoff while adding randomness
		half := backoff / 2
		jitterRng.Lock()
		jittered := half + time.Duration(jitterRng.Int63n(int64(half)+1))
		jitterRng.Unlock()
		return jittered
	}
}

// ResetJitter resets the jitter state (used for decorrelated jitter).
func (p *RetryPolicy) ResetJitter() {
	p.mu.Lock()
	p.lastBackoff = 0
	p.mu.Unlock()
}

// RetryBudget prevents retry storms by limiting the ratio of retries to requests.
// It uses a sliding window to track recent requests and retries.
type RetryBudget struct {
	ratio       float64       // Maximum retry ratio (e.g., 0.2 = 20% retries allowed)
	minRetries  int           // Minimum retries per second always allowed
	windowSize  time.Duration // Sliding window size for tracking
	requests    atomic.Int64  // Total requests in current window
	retries     atomic.Int64  // Total retries in current window
	lastReset   atomic.Value  // time.Time of last window reset
	mu          sync.Mutex    // Protects window reset
}

// NewRetryBudget creates a retry budget with the given parameters.
// ratio: maximum retry ratio (e.g., 0.2 means retries can be at most 20% of requests)
// minRetries: minimum retries per second always allowed (even if over budget)
// windowSize: sliding window duration for calculating the ratio
func NewRetryBudget(ratio float64, minRetries int, windowSize time.Duration) *RetryBudget {
	if ratio <= 0 {
		ratio = 0.2 // Default: 20% retry budget
	}
	if ratio > 1 {
		ratio = 1.0
	}
	if minRetries < 0 {
		minRetries = 3 // Default: allow at least 3 retries per second
	}
	if windowSize <= 0 {
		windowSize = 10 * time.Second // Default: 10 second window
	}

	rb := &RetryBudget{
		ratio:      ratio,
		minRetries: minRetries,
		windowSize: windowSize,
	}
	rb.lastReset.Store(time.Now())
	return rb
}

// maybeResetWindow resets counters if the window has expired.
func (rb *RetryBudget) maybeResetWindow() {
	lastReset := rb.lastReset.Load().(time.Time)
	if time.Since(lastReset) >= rb.windowSize {
		rb.mu.Lock()
		// Double-check after acquiring lock
		lastReset = rb.lastReset.Load().(time.Time)
		if time.Since(lastReset) >= rb.windowSize {
			rb.requests.Store(0)
			rb.retries.Store(0)
			rb.lastReset.Store(time.Now())
		}
		rb.mu.Unlock()
	}
}

// RecordRequest records an original (non-retry) request.
func (rb *RetryBudget) RecordRequest() {
	rb.maybeResetWindow()
	rb.requests.Add(1)
}

// AllowRetry checks if a retry is allowed within the budget and records it if so.
func (rb *RetryBudget) AllowRetry() bool {
	rb.maybeResetWindow()

	requests := rb.requests.Load()
	retries := rb.retries.Load()

	// Always allow minimum retries
	if retries < int64(rb.minRetries) {
		rb.retries.Add(1)
		return true
	}

	// Check if within budget
	if requests == 0 {
		// No requests yet, allow retry
		rb.retries.Add(1)
		return true
	}

	currentRatio := float64(retries) / float64(requests)
	if currentRatio < rb.ratio {
		rb.retries.Add(1)
		return true
	}

	// Over budget, deny retry
	return false
}

// Stats returns current retry budget statistics.
func (rb *RetryBudget) Stats() (requests, retries int64, ratio float64) {
	rb.maybeResetWindow()
	requests = rb.requests.Load()
	retries = rb.retries.Load()
	if requests > 0 {
		ratio = float64(retries) / float64(requests)
	}
	return
}

// Bulkhead implements the bulkhead pattern to limit concurrent requests.
// It prevents any single upstream from consuming too many resources.
type Bulkhead struct {
	maxConcurrent int64         // Maximum concurrent requests allowed
	current       atomic.Int64  // Current number of active requests
	queueSize     int64         // Maximum queue size (0 = no queueing)
	queued        atomic.Int64  // Current number of queued requests
	timeout       time.Duration // Timeout for acquiring a slot
	semaphore     chan struct{} // Semaphore for limiting concurrency
}

// BulkheadConfig configures the bulkhead.
type BulkheadConfig struct {
	MaxConcurrent int64         // Maximum concurrent requests (default: 100)
	QueueSize     int64         // Maximum queue size (default: 0 = no queueing)
	Timeout       time.Duration // Timeout for acquiring a slot (default: 0 = no timeout)
}

// NewBulkhead creates a new bulkhead with the given configuration.
func NewBulkhead(cfg BulkheadConfig) *Bulkhead {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 100 // Default: 100 concurrent requests
	}
	if cfg.QueueSize < 0 {
		cfg.QueueSize = 0
	}

	return &Bulkhead{
		maxConcurrent: cfg.MaxConcurrent,
		queueSize:     cfg.QueueSize,
		timeout:       cfg.Timeout,
		semaphore:     make(chan struct{}, cfg.MaxConcurrent),
	}
}

// ErrBulkheadFull is returned when the bulkhead is at capacity.
var ErrBulkheadFull = errors.New("bulkhead is full")

// ErrBulkheadTimeout is returned when waiting for a slot times out.
var ErrBulkheadTimeout = errors.New("bulkhead timeout waiting for slot")

// Acquire attempts to acquire a slot in the bulkhead.
// Returns a release function that must be called when the request is complete.
// Returns an error if the bulkhead is full or timeout is exceeded.
func (b *Bulkhead) Acquire(ctx context.Context) (func(), error) {
	// Fast path: try non-blocking acquire
	select {
	case b.semaphore <- struct{}{}:
		b.current.Add(1)
		return b.releaseFunc(), nil
	default:
		// Semaphore is full
	}

	// Check if queueing is allowed
	if b.queueSize > 0 {
		queued := b.queued.Add(1)
		if queued > b.queueSize {
			b.queued.Add(-1)
			return nil, ErrBulkheadFull
		}
		defer b.queued.Add(-1)
	} else {
		// No queueing allowed
		return nil, ErrBulkheadFull
	}

	// Wait for a slot with timeout
	var timeoutCh <-chan time.Time
	if b.timeout > 0 {
		timer := time.NewTimer(b.timeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	select {
	case b.semaphore <- struct{}{}:
		b.current.Add(1)
		return b.releaseFunc(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeoutCh:
		return nil, ErrBulkheadTimeout
	}
}

// releaseFunc returns a function that releases a slot in the bulkhead.
func (b *Bulkhead) releaseFunc() func() {
	return func() {
		b.current.Add(-1)
		<-b.semaphore
	}
}

// TryAcquire attempts to acquire a slot without blocking.
// Returns a release function and true if successful, nil and false otherwise.
func (b *Bulkhead) TryAcquire() (func(), bool) {
	select {
	case b.semaphore <- struct{}{}:
		b.current.Add(1)
		return b.releaseFunc(), true
	default:
		return nil, false
	}
}

// Stats returns bulkhead statistics.
func (b *Bulkhead) Stats() BulkheadStats {
	return BulkheadStats{
		MaxConcurrent:     b.maxConcurrent,
		CurrentConcurrent: b.current.Load(),
		QueueSize:         b.queueSize,
		CurrentQueued:     b.queued.Load(),
	}
}

// BulkheadStats contains bulkhead statistics.
type BulkheadStats struct {
	MaxConcurrent     int64 `json:"max_concurrent"`
	CurrentConcurrent int64 `json:"current_concurrent"`
	QueueSize         int64 `json:"queue_size"`
	CurrentQueued     int64 `json:"current_queued"`
}

// Manager manages backend connections.
type Manager struct {
	upstreams map[string]*Upstream
	transport *http.Transport
	mu        sync.RWMutex
}

// NewManager creates a new upstream manager.
func NewManager() *Manager {
	return &Manager{
		upstreams: make(map[string]*Upstream),
		transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     200,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true,
		},
	}
}

// Configure sets up upstreams from configuration.
func (m *Manager) Configure(configs []config.UpstreamConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cfg := range configs {
		endpoints := make([]*Endpoint, len(cfg.Endpoints))
		for i, addr := range cfg.Endpoints {
			ep := &Endpoint{
				Address: addr,
				Weight:  1, // Default weight
			}
			ep.SetHealthy(true) // Initially healthy
			endpoints[i] = ep
		}

		var lb LoadBalancer
		switch cfg.LoadBalancer {
		case "weighted":
			lb = NewWeightedBalancer()
		case "least_conn":
			lb = &LeastConnBalancer{}
		case "random":
			lb = NewRandomBalancer()
		case "consistent_hash":
			replicas := cfg.ConsistentHash.Replicas
			if replicas <= 0 {
				replicas = 150 // Default virtual nodes
			}
			lb = NewConsistentHashBalancer(replicas, cfg.ConsistentHash.HashKey)
		default:
			lb = &RoundRobinBalancer{}
		}

		circuit := NewCircuitBreaker(
			int64(cfg.CircuitBreaker.FailureThreshold),
			int64(cfg.CircuitBreaker.SuccessThreshold),
			config.ParseDuration(cfg.CircuitBreaker.Timeout, 30*time.Second),
		)

		retry := &RetryPolicy{
			MaxRetries:  cfg.Retry.MaxRetries,
			BackoffBase: config.ParseDuration(cfg.Retry.BackoffBase, 100*time.Millisecond),
			BackoffMax:  config.ParseDuration(cfg.Retry.BackoffMax, 10*time.Second),
		}
		if len(cfg.Retry.RetryableCodes) > 0 {
			retry.RetryableCodes = make(map[int]bool)
			for _, code := range cfg.Retry.RetryableCodes {
				retry.RetryableCodes[code] = true
			}
		}

		// Create retry budget to prevent retry storms
		// Default: 20% budget, min 3 retries, 10 second window
		retryBudget := NewRetryBudget(0.2, 3, 10*time.Second)

		// Create bulkhead if enabled
		var bulkhead *Bulkhead
		if cfg.Bulkhead.Enabled {
			bulkhead = NewBulkhead(BulkheadConfig{
				MaxConcurrent: int64(cfg.Bulkhead.MaxConcurrent),
				QueueSize:     int64(cfg.Bulkhead.QueueSize),
				Timeout:       config.ParseDuration(cfg.Bulkhead.Timeout, 0),
			})
		}

		m.upstreams[cfg.Name] = &Upstream{
			Name:         cfg.Name,
			Endpoints:    endpoints,
			LoadBalancer: lb,
			Circuit:      circuit,
			RetryPolicy:  retry,
			RetryBudget:  retryBudget,
			Bulkhead:     bulkhead,
		}
	}

	return nil
}

// GetUpstream returns an upstream by name.
func (m *Manager) GetUpstream(name string) (*Upstream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.upstreams[name]
	return u, ok
}

// ProxyRequest proxies a request to an upstream.
func (m *Manager) ProxyRequest(ctx context.Context, upstreamName string, req *http.Request) (*http.Response, error) {
	m.mu.RLock()
	upstream, ok := m.upstreams[upstreamName]
	m.mu.RUnlock()

	if !ok {
		return nil, ErrUpstreamNotFound
	}

	// Check circuit breaker
	if !upstream.Circuit.Allow() {
		return nil, ErrCircuitOpen
	}

	// Record this as an original request for retry budget tracking
	if upstream.RetryBudget != nil {
		upstream.RetryBudget.RecordRequest()
	}

	var lastErr error
	maxRetries := upstream.RetryPolicy.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Check retry budget before attempting retry
			if upstream.RetryBudget != nil && !upstream.RetryBudget.AllowRetry() {
				// Retry budget exhausted, return last error
				break
			}
			time.Sleep(upstream.RetryPolicy.BackoffDuration(attempt))
		}

		// Select endpoint
		endpoint := upstream.LoadBalancer.Select(upstream.Endpoints)
		if endpoint == nil {
			return nil, ErrNoHealthyEndpoints
		}

		resp, err := m.doRequest(ctx, endpoint, req)
		if err != nil {
			lastErr = err
			upstream.Circuit.RecordFailure()
			continue
		}

		// Check if response is retryable
		if upstream.RetryPolicy.ShouldRetry(resp.StatusCode) {
			// Drain and close body for retry
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		upstream.Circuit.RecordSuccess()
		return resp, nil
	}

	return nil, lastErr
}

// doRequest performs the actual HTTP request.
func (m *Manager) doRequest(ctx context.Context, endpoint *Endpoint, req *http.Request) (*http.Response, error) {
	// Clone request and update target
	proxyReq := req.Clone(ctx)

	// Parse endpoint address
	targetURL, err := url.Parse("http://" + endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint URL: %w", err)
	}

	proxyReq.URL.Scheme = targetURL.Scheme
	proxyReq.URL.Host = targetURL.Host
	proxyReq.Host = targetURL.Host

	// Track active connections
	endpoint.activeConns.Add(1)
	defer endpoint.activeConns.Add(-1)

	resp, err := m.transport.RoundTrip(proxyReq)
	if err != nil {
		endpoint.failureCount.Add(1)
		return nil, err
	}

	return resp, nil
}

// GetUpstreams returns all configured upstreams.
func (m *Manager) GetUpstreams() []*Upstream {
	m.mu.RLock()
	defer m.mu.RUnlock()

	upstreams := make([]*Upstream, 0, len(m.upstreams))
	for _, u := range m.upstreams {
		upstreams = append(upstreams, u)
	}
	return upstreams
}

// GetUpstreamAddress returns the address of a healthy endpoint for the upstream.
// This is used for WebSocket proxying.
func (m *Manager) GetUpstreamAddress(name string) string {
	m.mu.RLock()
	upstream, ok := m.upstreams[name]
	m.mu.RUnlock()

	if !ok {
		return ""
	}

	upstream.mu.RLock()
	defer upstream.mu.RUnlock()

	endpoint := upstream.LoadBalancer.Select(upstream.Endpoints)
	if endpoint == nil {
		return ""
	}

	return endpoint.Address
}

// Close closes the transport.
func (m *Manager) Close() {
	m.transport.CloseIdleConnections()
}
