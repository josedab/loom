// Package upstream provides health checking functionality.
package upstream

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/josedab/loom/internal/config"
)

// HealthChecker performs periodic health checks on endpoints.
type HealthChecker struct {
	manager   *Manager
	configs   map[string]HealthCheckOptions
	stopCh    chan struct{}
	wg        sync.WaitGroup
	client    *http.Client
	mu        sync.RWMutex
}

// HealthCheckOptions defines health check configuration.
type HealthCheckOptions struct {
	Path               string
	Interval           time.Duration
	Timeout            time.Duration
	HealthyThreshold   int
	UnhealthyThreshold int
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(manager *Manager) *HealthChecker {
	return &HealthChecker{
		manager: manager,
		configs: make(map[string]HealthCheckOptions),
		stopCh:  make(chan struct{}),
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

// Configure sets up health checks from configuration.
func (hc *HealthChecker) Configure(configs []config.UpstreamConfig) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	for _, cfg := range configs {
		if cfg.HealthCheck.Path == "" {
			continue
		}

		hc.configs[cfg.Name] = HealthCheckOptions{
			Path:               cfg.HealthCheck.Path,
			Interval:           config.ParseDuration(cfg.HealthCheck.Interval, 10*time.Second),
			Timeout:            config.ParseDuration(cfg.HealthCheck.Timeout, 2*time.Second),
			HealthyThreshold:   max(cfg.HealthCheck.HealthyThreshold, 1),
			UnhealthyThreshold: max(cfg.HealthCheck.UnhealthyThreshold, 1),
		}
	}
}

// Start begins health checking for all configured upstreams.
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	for upstreamName, opts := range hc.configs {
		upstream, ok := hc.manager.GetUpstream(upstreamName)
		if !ok {
			continue
		}

		hc.wg.Add(1)
		go hc.runHealthChecks(ctx, upstream, opts)
	}
}

// runHealthChecks runs health checks for a single upstream.
func (hc *HealthChecker) runHealthChecks(ctx context.Context, upstream *Upstream, opts HealthCheckOptions) {
	defer hc.wg.Done()

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	// Track consecutive successes/failures per endpoint
	healthyCount := make(map[string]int)
	unhealthyCount := make(map[string]int)

	// Initial check
	hc.checkUpstream(upstream, opts, healthyCount, unhealthyCount)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkUpstream(upstream, opts, healthyCount, unhealthyCount)
		}
	}
}

// checkUpstream checks all endpoints of an upstream.
func (hc *HealthChecker) checkUpstream(
	upstream *Upstream,
	opts HealthCheckOptions,
	healthyCount map[string]int,
	unhealthyCount map[string]int,
) {
	upstream.mu.RLock()
	endpoints := upstream.Endpoints
	upstream.mu.RUnlock()

	for _, endpoint := range endpoints {
		healthy := hc.checkEndpoint(endpoint, opts)
		addr := endpoint.Address

		if healthy {
			healthyCount[addr]++
			unhealthyCount[addr] = 0

			if healthyCount[addr] >= opts.HealthyThreshold {
				endpoint.SetHealthy(true)
			}
		} else {
			unhealthyCount[addr]++
			healthyCount[addr] = 0

			if unhealthyCount[addr] >= opts.UnhealthyThreshold {
				endpoint.SetHealthy(false)
			}
		}
	}
}

// checkEndpoint performs a health check on a single endpoint.
func (hc *HealthChecker) checkEndpoint(endpoint *Endpoint, opts HealthCheckOptions) bool {
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	url := fmt.Sprintf("http://%s%s", endpoint.Address, opts.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "Gateway-HealthCheck/1.0")

	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider 2xx status codes as healthy
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// Stop stops all health checks.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
	hc.wg.Wait()
}

// GetEndpointHealth returns the health status of all endpoints.
func (hc *HealthChecker) GetEndpointHealth() map[string][]EndpointHealth {
	result := make(map[string][]EndpointHealth)

	for _, upstream := range hc.manager.GetUpstreams() {
		upstream.mu.RLock()
		health := make([]EndpointHealth, len(upstream.Endpoints))
		for i, ep := range upstream.Endpoints {
			lastChecked, _ := ep.lastChecked.Load().(time.Time)
			health[i] = EndpointHealth{
				Address:     ep.Address,
				Healthy:     ep.IsHealthy(),
				LastChecked: lastChecked,
			}
		}
		upstream.mu.RUnlock()
		result[upstream.Name] = health
	}

	return result
}

// EndpointHealth represents the health status of an endpoint.
type EndpointHealth struct {
	Address     string    `json:"address"`
	Healthy     bool      `json:"healthy"`
	LastChecked time.Time `json:"last_checked"`
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PassiveHealthChecker tracks endpoint health based on actual traffic responses.
// It implements passive health checking by monitoring 5xx responses.
type PassiveHealthChecker struct {
	endpoints    map[string]*passiveEndpointStats
	mu           sync.RWMutex
	config       PassiveHealthConfig
	ejectedUntil map[string]time.Time // Tracks when ejected endpoints can be recovered
}

// PassiveHealthConfig configures passive health checking.
type PassiveHealthConfig struct {
	ConsecutiveErrors    int           // Number of consecutive 5xx errors to eject (default: 5)
	ErrorRatioThreshold  float64       // Error ratio threshold to eject (default: 0.5 = 50%)
	MinRequestsForRatio  int           // Minimum requests before ratio is checked (default: 10)
	EjectionDuration     time.Duration // How long to eject an endpoint (default: 30s)
	MaxEjectionPercent   float64       // Max percentage of endpoints that can be ejected (default: 0.5)
	WindowDuration       time.Duration // Sliding window for tracking errors (default: 60s)
	RecoveryRampPercent  float64       // Percentage of traffic during recovery (default: 0.25)
}

// DefaultPassiveHealthConfig returns sensible defaults for passive health checking.
func DefaultPassiveHealthConfig() PassiveHealthConfig {
	return PassiveHealthConfig{
		ConsecutiveErrors:   5,
		ErrorRatioThreshold: 0.5,
		MinRequestsForRatio: 10,
		EjectionDuration:    30 * time.Second,
		MaxEjectionPercent:  0.5,
		WindowDuration:      60 * time.Second,
		RecoveryRampPercent: 0.25,
	}
}

// passiveEndpointStats tracks statistics for a single endpoint.
type passiveEndpointStats struct {
	requests          int64
	errors            int64
	consecutiveErrors int64
	lastError         time.Time
	lastSuccess       time.Time
	windowStart       time.Time
	mu                sync.Mutex
}

// NewPassiveHealthChecker creates a new passive health checker.
func NewPassiveHealthChecker(config PassiveHealthConfig) *PassiveHealthChecker {
	if config.ConsecutiveErrors <= 0 {
		config.ConsecutiveErrors = 5
	}
	if config.ErrorRatioThreshold <= 0 {
		config.ErrorRatioThreshold = 0.5
	}
	if config.MinRequestsForRatio <= 0 {
		config.MinRequestsForRatio = 10
	}
	if config.EjectionDuration <= 0 {
		config.EjectionDuration = 30 * time.Second
	}
	if config.MaxEjectionPercent <= 0 {
		config.MaxEjectionPercent = 0.5
	}
	if config.WindowDuration <= 0 {
		config.WindowDuration = 60 * time.Second
	}
	if config.RecoveryRampPercent <= 0 {
		config.RecoveryRampPercent = 0.25
	}

	return &PassiveHealthChecker{
		endpoints:    make(map[string]*passiveEndpointStats),
		ejectedUntil: make(map[string]time.Time),
		config:       config,
	}
}

// RecordResponse records a response from an endpoint for passive health tracking.
// Returns true if the endpoint should be ejected.
func (phc *PassiveHealthChecker) RecordResponse(endpointAddr string, statusCode int, totalEndpoints int) bool {
	phc.mu.Lock()
	stats, exists := phc.endpoints[endpointAddr]
	if !exists {
		stats = &passiveEndpointStats{
			windowStart: time.Now(),
		}
		phc.endpoints[endpointAddr] = stats
	}
	phc.mu.Unlock()

	stats.mu.Lock()
	defer stats.mu.Unlock()

	// Reset window if expired
	if time.Since(stats.windowStart) > phc.config.WindowDuration {
		stats.requests = 0
		stats.errors = 0
		stats.consecutiveErrors = 0
		stats.windowStart = time.Now()
	}

	stats.requests++

	isError := statusCode >= 500
	if isError {
		stats.errors++
		stats.consecutiveErrors++
		stats.lastError = time.Now()
	} else {
		stats.consecutiveErrors = 0
		stats.lastSuccess = time.Now()
	}

	// Check if endpoint should be ejected
	return phc.shouldEject(endpointAddr, stats, totalEndpoints)
}

// shouldEject determines if an endpoint should be ejected based on its stats.
func (phc *PassiveHealthChecker) shouldEject(addr string, stats *passiveEndpointStats, totalEndpoints int) bool {
	// Check consecutive errors
	if stats.consecutiveErrors >= int64(phc.config.ConsecutiveErrors) {
		return phc.tryEject(addr, totalEndpoints)
	}

	// Check error ratio
	if stats.requests >= int64(phc.config.MinRequestsForRatio) {
		ratio := float64(stats.errors) / float64(stats.requests)
		if ratio >= phc.config.ErrorRatioThreshold {
			return phc.tryEject(addr, totalEndpoints)
		}
	}

	return false
}

// tryEject attempts to eject an endpoint, respecting the max ejection percentage.
func (phc *PassiveHealthChecker) tryEject(addr string, totalEndpoints int) bool {
	phc.mu.Lock()
	defer phc.mu.Unlock()

	// Count currently ejected endpoints
	now := time.Now()
	ejectedCount := 0
	for _, until := range phc.ejectedUntil {
		if until.After(now) {
			ejectedCount++
		}
	}

	// Check if already ejected
	if until, exists := phc.ejectedUntil[addr]; exists && until.After(now) {
		return true // Already ejected
	}

	// Check max ejection percentage
	maxEjected := int(float64(totalEndpoints) * phc.config.MaxEjectionPercent)
	if maxEjected < 1 {
		maxEjected = 1
	}
	if ejectedCount >= maxEjected {
		return false // Can't eject more
	}

	// Eject the endpoint
	phc.ejectedUntil[addr] = now.Add(phc.config.EjectionDuration)
	return true
}

// IsEjected checks if an endpoint is currently ejected.
func (phc *PassiveHealthChecker) IsEjected(addr string) bool {
	phc.mu.RLock()
	until, exists := phc.ejectedUntil[addr]
	phc.mu.RUnlock()

	if !exists {
		return false
	}
	return until.After(time.Now())
}

// GetEjectedEndpoints returns a list of currently ejected endpoints.
func (phc *PassiveHealthChecker) GetEjectedEndpoints() []string {
	phc.mu.RLock()
	defer phc.mu.RUnlock()

	now := time.Now()
	var ejected []string
	for addr, until := range phc.ejectedUntil {
		if until.After(now) {
			ejected = append(ejected, addr)
		}
	}
	return ejected
}

// ResetEndpoint clears the statistics and ejection status for an endpoint.
func (phc *PassiveHealthChecker) ResetEndpoint(addr string) {
	phc.mu.Lock()
	delete(phc.endpoints, addr)
	delete(phc.ejectedUntil, addr)
	phc.mu.Unlock()
}

// Stats returns passive health check statistics for all tracked endpoints.
func (phc *PassiveHealthChecker) Stats() map[string]PassiveEndpointStats {
	phc.mu.RLock()
	defer phc.mu.RUnlock()

	now := time.Now()
	result := make(map[string]PassiveEndpointStats)

	for addr, stats := range phc.endpoints {
		stats.mu.Lock()
		ejectedUntil := phc.ejectedUntil[addr]
		result[addr] = PassiveEndpointStats{
			Requests:          stats.requests,
			Errors:            stats.errors,
			ConsecutiveErrors: stats.consecutiveErrors,
			LastError:         stats.lastError,
			LastSuccess:       stats.lastSuccess,
			IsEjected:         ejectedUntil.After(now),
			EjectedUntil:      ejectedUntil,
		}
		stats.mu.Unlock()
	}

	return result
}

// PassiveEndpointStats contains statistics for passive health checking.
type PassiveEndpointStats struct {
	Requests          int64     `json:"requests"`
	Errors            int64     `json:"errors"`
	ConsecutiveErrors int64     `json:"consecutive_errors"`
	LastError         time.Time `json:"last_error,omitempty"`
	LastSuccess       time.Time `json:"last_success,omitempty"`
	IsEjected         bool      `json:"is_ejected"`
	EjectedUntil      time.Time `json:"ejected_until,omitempty"`
}

// OutlierDetector automatically detects and ejects unhealthy endpoints
// based on response patterns, and recovers them after the ejection period.
type OutlierDetector struct {
	passive     *PassiveHealthChecker
	endpoints   map[string]*Endpoint // Address -> Endpoint mapping
	mu          sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup
	recoveryInt time.Duration // Interval to check for endpoint recovery
}

// OutlierDetectorConfig configures the outlier detector.
type OutlierDetectorConfig struct {
	// Passive health check configuration
	Passive PassiveHealthConfig
	// RecoveryInterval is how often to check for endpoint recovery (default: 5s)
	RecoveryInterval time.Duration
}

// DefaultOutlierDetectorConfig returns sensible defaults.
func DefaultOutlierDetectorConfig() OutlierDetectorConfig {
	return OutlierDetectorConfig{
		Passive:          DefaultPassiveHealthConfig(),
		RecoveryInterval: 5 * time.Second,
	}
}

// NewOutlierDetector creates a new outlier detector.
func NewOutlierDetector(cfg OutlierDetectorConfig) *OutlierDetector {
	if cfg.RecoveryInterval <= 0 {
		cfg.RecoveryInterval = 5 * time.Second
	}

	return &OutlierDetector{
		passive:     NewPassiveHealthChecker(cfg.Passive),
		endpoints:   make(map[string]*Endpoint),
		stopCh:      make(chan struct{}),
		recoveryInt: cfg.RecoveryInterval,
	}
}

// RegisterEndpoint registers an endpoint for outlier detection.
func (od *OutlierDetector) RegisterEndpoint(ep *Endpoint) {
	od.mu.Lock()
	od.endpoints[ep.Address] = ep
	od.mu.Unlock()
}

// RegisterEndpoints registers multiple endpoints.
func (od *OutlierDetector) RegisterEndpoints(endpoints []*Endpoint) {
	od.mu.Lock()
	for _, ep := range endpoints {
		od.endpoints[ep.Address] = ep
	}
	od.mu.Unlock()
}

// UnregisterEndpoint removes an endpoint from outlier detection.
func (od *OutlierDetector) UnregisterEndpoint(addr string) {
	od.mu.Lock()
	delete(od.endpoints, addr)
	od.mu.Unlock()
	od.passive.ResetEndpoint(addr)
}

// RecordResponse records a response for outlier detection.
// This should be called after each response from an endpoint.
// Returns true if the endpoint was ejected as a result.
func (od *OutlierDetector) RecordResponse(endpointAddr string, statusCode int) bool {
	od.mu.RLock()
	totalEndpoints := len(od.endpoints)
	ep := od.endpoints[endpointAddr]
	od.mu.RUnlock()

	if ep == nil {
		return false
	}

	ejected := od.passive.RecordResponse(endpointAddr, statusCode, totalEndpoints)
	if ejected {
		ep.SetHealthy(false)
	}

	return ejected
}

// Start begins the recovery loop that checks for ejected endpoints
// that are ready to be recovered.
func (od *OutlierDetector) Start() {
	od.wg.Add(1)
	go od.recoveryLoop()
}

// Stop stops the outlier detector.
func (od *OutlierDetector) Stop() {
	close(od.stopCh)
	od.wg.Wait()
}

// recoveryLoop periodically checks for endpoints ready to be recovered.
func (od *OutlierDetector) recoveryLoop() {
	defer od.wg.Done()

	ticker := time.NewTicker(od.recoveryInt)
	defer ticker.Stop()

	for {
		select {
		case <-od.stopCh:
			return
		case <-ticker.C:
			od.checkRecovery()
		}
	}
}

// checkRecovery checks for endpoints that should be recovered.
func (od *OutlierDetector) checkRecovery() {
	od.mu.RLock()
	defer od.mu.RUnlock()

	for addr, ep := range od.endpoints {
		// If endpoint is marked unhealthy but no longer ejected, recover it
		if !ep.IsHealthy() && !od.passive.IsEjected(addr) {
			ep.SetHealthy(true)
		}
	}
}

// IsEjected checks if an endpoint is currently ejected.
func (od *OutlierDetector) IsEjected(addr string) bool {
	return od.passive.IsEjected(addr)
}

// GetEjectedEndpoints returns a list of currently ejected endpoints.
func (od *OutlierDetector) GetEjectedEndpoints() []string {
	return od.passive.GetEjectedEndpoints()
}

// Stats returns outlier detection statistics for all endpoints.
func (od *OutlierDetector) Stats() map[string]OutlierStats {
	passiveStats := od.passive.Stats()
	result := make(map[string]OutlierStats, len(passiveStats))

	od.mu.RLock()
	for addr, ps := range passiveStats {
		ep := od.endpoints[addr]
		healthy := false
		if ep != nil {
			healthy = ep.IsHealthy()
		}
		result[addr] = OutlierStats{
			Requests:          ps.Requests,
			Errors:            ps.Errors,
			ConsecutiveErrors: ps.ConsecutiveErrors,
			LastError:         ps.LastError,
			LastSuccess:       ps.LastSuccess,
			IsEjected:         ps.IsEjected,
			EjectedUntil:      ps.EjectedUntil,
			EndpointHealthy:   healthy,
		}
	}
	od.mu.RUnlock()

	return result
}

// OutlierStats contains outlier detection statistics for an endpoint.
type OutlierStats struct {
	Requests          int64     `json:"requests"`
	Errors            int64     `json:"errors"`
	ConsecutiveErrors int64     `json:"consecutive_errors"`
	LastError         time.Time `json:"last_error,omitempty"`
	LastSuccess       time.Time `json:"last_success,omitempty"`
	IsEjected         bool      `json:"is_ejected"`
	EjectedUntil      time.Time `json:"ejected_until,omitempty"`
	EndpointHealthy   bool      `json:"endpoint_healthy"`
}
