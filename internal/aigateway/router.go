// Package aigateway provides AI/LLM gateway capabilities.
package aigateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNoHealthyProviders  = errors.New("no healthy providers available")
	ErrProviderNotFound    = errors.New("provider not found")
	ErrRateLimitExceeded   = errors.New("rate limit exceeded")
	ErrRequestTimeout      = errors.New("request timeout")
	ErrProviderUnavailable = errors.New("provider unavailable")
)

// RoutingStrategy defines how providers are selected.
type RoutingStrategy string

const (
	// StrategyPriority routes to highest priority healthy provider.
	StrategyPriority RoutingStrategy = "priority"
	// StrategyRoundRobin cycles through healthy providers.
	StrategyRoundRobin RoutingStrategy = "round_robin"
	// StrategyWeighted routes based on provider weights.
	StrategyWeighted RoutingStrategy = "weighted"
	// StrategyCostOptimized routes to cheapest available provider.
	StrategyCostOptimized RoutingStrategy = "cost_optimized"
	// StrategyLatencyOptimized routes to fastest responding provider.
	StrategyLatencyOptimized RoutingStrategy = "latency_optimized"
	// StrategyFailover uses primary with automatic failover.
	StrategyFailover RoutingStrategy = "failover"
)

// ProviderRouter routes requests to LLM providers.
type ProviderRouter struct {
	providers   []*ProviderEndpoint
	strategy    RoutingStrategy
	current     atomic.Uint64 // For round-robin
	rng         *rand.Rand
	mu          sync.RWMutex
	healthCheck *HealthChecker
	client      *http.Client
	retryConfig RetryConfig
}

// RouterConfig configures the provider router.
type RouterConfig struct {
	Strategy        RoutingStrategy
	Providers       []ProviderConfig
	RetryConfig     RetryConfig
	HealthCheckPath string
	HealthInterval  time.Duration
	RequestTimeout  time.Duration
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	MaxRetries  int
	BackoffBase time.Duration
	BackoffMax  time.Duration
	RetryOn     []int // Status codes to retry on
}

// NewProviderRouter creates a new provider router.
func NewProviderRouter(cfg RouterConfig) *ProviderRouter {
	if cfg.Strategy == "" {
		cfg.Strategy = StrategyPriority
	}
	if cfg.RetryConfig.MaxRetries == 0 {
		cfg.RetryConfig.MaxRetries = 3
	}
	if cfg.RetryConfig.BackoffBase == 0 {
		cfg.RetryConfig.BackoffBase = 100 * time.Millisecond
	}
	if cfg.RetryConfig.BackoffMax == 0 {
		cfg.RetryConfig.BackoffMax = 5 * time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 120 * time.Second
	}

	router := &ProviderRouter{
		providers:   make([]*ProviderEndpoint, 0, len(cfg.Providers)),
		strategy:    cfg.Strategy,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		retryConfig: cfg.RetryConfig,
		client: &http.Client{
			Timeout: cfg.RequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	// Create provider endpoints
	for _, provCfg := range cfg.Providers {
		router.providers = append(router.providers, NewProviderEndpoint(provCfg))
	}

	// Sort by priority (highest first)
	sort.Slice(router.providers, func(i, j int) bool {
		return router.providers[i].Config.Priority > router.providers[j].Config.Priority
	})

	// Start health checker if configured
	if cfg.HealthInterval > 0 {
		router.healthCheck = NewHealthChecker(router.providers, cfg.HealthInterval, cfg.HealthCheckPath)
		go router.healthCheck.Start()
	}

	return router
}

// Route selects a provider for the request.
func (r *ProviderRouter) Route(req *LLMRequest) (*ProviderEndpoint, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	healthy := r.healthyProviders()
	if len(healthy) == 0 {
		return nil, ErrNoHealthyProviders
	}

	switch r.strategy {
	case StrategyPriority:
		return r.selectByPriority(healthy), nil
	case StrategyRoundRobin:
		return r.selectRoundRobin(healthy), nil
	case StrategyWeighted:
		return r.selectWeighted(healthy), nil
	case StrategyCostOptimized:
		return r.selectByCost(healthy, req), nil
	case StrategyLatencyOptimized:
		return r.selectByLatency(healthy), nil
	case StrategyFailover:
		return r.selectFailover(healthy), nil
	default:
		return r.selectByPriority(healthy), nil
	}
}

// healthyProviders returns all healthy providers.
func (r *ProviderRouter) healthyProviders() []*ProviderEndpoint {
	healthy := make([]*ProviderEndpoint, 0, len(r.providers))
	for _, p := range r.providers {
		if p.IsHealthy() {
			healthy = append(healthy, p)
		}
	}
	return healthy
}

// selectByPriority returns the highest priority healthy provider.
func (r *ProviderRouter) selectByPriority(providers []*ProviderEndpoint) *ProviderEndpoint {
	// Providers are already sorted by priority
	return providers[0]
}

// selectRoundRobin cycles through providers.
func (r *ProviderRouter) selectRoundRobin(providers []*ProviderEndpoint) *ProviderEndpoint {
	idx := r.current.Add(1) % uint64(len(providers))
	return providers[idx]
}

// selectWeighted selects based on configured weights.
func (r *ProviderRouter) selectWeighted(providers []*ProviderEndpoint) *ProviderEndpoint {
	totalWeight := 0
	for _, p := range providers {
		weight := p.Config.Weight
		if weight <= 0 {
			weight = 1
		}
		totalWeight += weight
	}

	target := r.rng.Intn(totalWeight)
	for _, p := range providers {
		weight := p.Config.Weight
		if weight <= 0 {
			weight = 1
		}
		target -= weight
		if target < 0 {
			return p
		}
	}

	return providers[0]
}

// selectByCost selects the cheapest provider that can handle the request.
func (r *ProviderRouter) selectByCost(providers []*ProviderEndpoint, req *LLMRequest) *ProviderEndpoint {
	var cheapest *ProviderEndpoint
	lowestCost := float64(1e10)

	for _, p := range providers {
		cost := p.Config.CostPer1K
		if cost <= 0 {
			cost = 1.0 // Default cost
		}

		// Check if provider can handle the model
		if req.Model != "" && p.Config.Model != "" && p.Config.Model != req.Model {
			continue
		}

		if cost < lowestCost {
			lowestCost = cost
			cheapest = p
		}
	}

	if cheapest == nil && len(providers) > 0 {
		return providers[0]
	}
	return cheapest
}

// selectByLatency selects the provider with lowest active requests (proxy for latency).
func (r *ProviderRouter) selectByLatency(providers []*ProviderEndpoint) *ProviderEndpoint {
	var fastest *ProviderEndpoint
	lowestActive := int64(1e18)

	for _, p := range providers {
		active := p.activeReqs.Load()
		if active < lowestActive {
			lowestActive = active
			fastest = p
		}
	}

	if fastest == nil && len(providers) > 0 {
		return providers[0]
	}
	return fastest
}

// selectFailover returns first healthy provider (primary or failover).
func (r *ProviderRouter) selectFailover(providers []*ProviderEndpoint) *ProviderEndpoint {
	// Providers are sorted by priority, so first healthy is primary or first failover
	return providers[0]
}

// Execute routes and executes a request with retry logic.
func (r *ProviderRouter) Execute(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	var lastErr error
	attempted := make(map[string]bool)

	for attempt := 0; attempt <= r.retryConfig.MaxRetries; attempt++ {
		// Select provider
		provider, err := r.Route(req)
		if err != nil {
			return nil, err
		}

		// Skip already-attempted providers on retry
		if attempted[provider.Config.Name] {
			// Try to find an alternative
			provider = r.findAlternative(provider, attempted)
			if provider == nil {
				break
			}
		}
		attempted[provider.Config.Name] = true

		// Check rate limit
		if provider.rateLimiter != nil && !provider.rateLimiter.Allow() {
			lastErr = ErrRateLimitExceeded
			continue
		}

		// Execute request
		resp, err := r.executeRequest(ctx, provider, req)
		if err != nil {
			lastErr = err
			provider.lastError.Store(err.Error())

			// Mark unhealthy if too many consecutive failures
			// (health checker will re-enable)
			continue
		}

		return resp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoHealthyProviders
}

// findAlternative finds an alternative provider not yet attempted.
func (r *ProviderRouter) findAlternative(exclude *ProviderEndpoint, attempted map[string]bool) *ProviderEndpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.providers {
		if p.IsHealthy() && !attempted[p.Config.Name] && p != exclude {
			return p
		}
	}
	return nil
}

// executeRequest executes the actual HTTP request to the provider.
func (r *ProviderRouter) executeRequest(ctx context.Context, provider *ProviderEndpoint, llmReq *LLMRequest) (*LLMResponse, error) {
	provider.activeReqs.Add(1)
	defer provider.activeReqs.Add(-1)

	// Build HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Config.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set body
	if llmReq.RawBody != nil {
		req.Body = io.NopCloser(&bodyReader{data: llmReq.RawBody})
		req.ContentLength = int64(len(llmReq.RawBody))
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for k, v := range provider.Config.Headers {
		req.Header.Set(k, v)
	}

	// Set auth
	if provider.Config.APIKey != "" {
		switch provider.Config.Provider {
		case ProviderAnthropic:
			req.Header.Set("x-api-key", provider.Config.APIKey)
			req.Header.Set("anthropic-version", "2024-01-01")
		default:
			req.Header.Set("Authorization", "Bearer "+provider.Config.APIKey)
		}
	}

	if provider.Config.OrgID != "" {
		req.Header.Set("OpenAI-Organization", provider.Config.OrgID)
	}

	// Execute
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	latency := time.Since(start).Milliseconds()

	// Check for error status
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("provider error: status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	llmResp, err := ParseResponse(body, provider.Config.Provider)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	llmResp.Latency = latency
	provider.RecordRequest(llmResp.TotalTokens)

	return llmResp, nil
}

// bodyReader wraps a byte slice as an io.Reader.
type bodyReader struct {
	data []byte
	pos  int
}

func (r *bodyReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// AddProvider adds a provider dynamically.
func (r *ProviderRouter) AddProvider(cfg ProviderConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	endpoint := NewProviderEndpoint(cfg)
	r.providers = append(r.providers, endpoint)

	// Re-sort by priority
	sort.Slice(r.providers, func(i, j int) bool {
		return r.providers[i].Config.Priority > r.providers[j].Config.Priority
	})
}

// RemoveProvider removes a provider by name.
func (r *ProviderRouter) RemoveProvider(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, p := range r.providers {
		if p.Config.Name == name {
			r.providers = append(r.providers[:i], r.providers[i+1:]...)
			return nil
		}
	}
	return ErrProviderNotFound
}

// GetProvider returns a provider by name.
func (r *ProviderRouter) GetProvider(name string) (*ProviderEndpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.providers {
		if p.Config.Name == name {
			return p, true
		}
	}
	return nil, false
}

// ListProviders returns all providers.
func (r *ProviderRouter) ListProviders() []*ProviderEndpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ProviderEndpoint, len(r.providers))
	copy(result, r.providers)
	return result
}

// Stats returns router statistics.
func (r *ProviderRouter) Stats() RouterStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RouterStats{
		Strategy:  r.strategy,
		Providers: make([]ProviderStats, len(r.providers)),
	}

	for i, p := range r.providers {
		stats.Providers[i] = p.Stats()
		if p.IsHealthy() {
			stats.HealthyCount++
		}
	}
	stats.TotalCount = len(r.providers)

	return stats
}

// RouterStats contains router statistics.
type RouterStats struct {
	Strategy     RoutingStrategy `json:"strategy"`
	TotalCount   int             `json:"total_providers"`
	HealthyCount int             `json:"healthy_providers"`
	Providers    []ProviderStats `json:"providers"`
}

// Close stops the router and health checker.
func (r *ProviderRouter) Close() {
	if r.healthCheck != nil {
		r.healthCheck.Stop()
	}
}

// HealthChecker performs periodic health checks on providers.
type HealthChecker struct {
	providers []*ProviderEndpoint
	interval  time.Duration
	path      string
	client    *http.Client
	stopCh    chan struct{}
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(providers []*ProviderEndpoint, interval time.Duration, path string) *HealthChecker {
	if path == "" {
		path = "/health"
	}
	return &HealthChecker{
		providers: providers,
		interval:  interval,
		path:      path,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins periodic health checking.
func (hc *HealthChecker) Start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	// Initial check
	hc.checkAll()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

// Stop stops the health checker.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

// checkAll checks all providers concurrently.
func (hc *HealthChecker) checkAll() {
	var wg sync.WaitGroup
	for _, p := range hc.providers {
		wg.Add(1)
		go func(provider *ProviderEndpoint) {
			defer wg.Done()
			hc.check(provider)
		}(p)
	}
	wg.Wait()
}

// check performs a health check on a single provider.
func (hc *HealthChecker) check(provider *ProviderEndpoint) {
	healthPath := provider.Config.HealthPath
	if healthPath == "" {
		healthPath = hc.path
	}

	// Build health check URL
	url := provider.Config.Endpoint + healthPath
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		provider.SetHealthy(false)
		provider.lastError.Store(err.Error())
		return
	}

	// Set auth headers
	if provider.Config.APIKey != "" {
		switch provider.Config.Provider {
		case ProviderAnthropic:
			req.Header.Set("x-api-key", provider.Config.APIKey)
		default:
			req.Header.Set("Authorization", "Bearer "+provider.Config.APIKey)
		}
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		provider.SetHealthy(false)
		provider.lastError.Store(err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		provider.SetHealthy(true)
	} else {
		provider.SetHealthy(false)
		provider.lastError.Store(fmt.Sprintf("health check failed: status %d", resp.StatusCode))
	}
}

// ModelRouter routes requests based on model compatibility.
type ModelRouter struct {
	modelToProviders map[string][]*ProviderEndpoint
	defaultProviders []*ProviderEndpoint
	mu               sync.RWMutex
}

// NewModelRouter creates a new model-aware router.
func NewModelRouter() *ModelRouter {
	return &ModelRouter{
		modelToProviders: make(map[string][]*ProviderEndpoint),
		defaultProviders: make([]*ProviderEndpoint, 0),
	}
}

// Register registers a provider for specific models.
func (mr *ModelRouter) Register(provider *ProviderEndpoint, models []string) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if len(models) == 0 {
		mr.defaultProviders = append(mr.defaultProviders, provider)
		return
	}

	for _, model := range models {
		mr.modelToProviders[model] = append(mr.modelToProviders[model], provider)
	}
}

// Route returns providers that support the given model.
func (mr *ModelRouter) Route(model string) []*ProviderEndpoint {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	if providers, ok := mr.modelToProviders[model]; ok && len(providers) > 0 {
		return providers
	}
	return mr.defaultProviders
}
