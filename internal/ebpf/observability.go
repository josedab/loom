// Package ebpf provides eBPF-based acceleration for Loom.
package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ObservabilityManager manages eBPF-based metrics and tracing.
type ObservabilityManager struct {
	config   Config
	logger   *slog.Logger
	loaded   atomic.Bool

	// Metrics storage
	counters   map[string]*Counter
	histograms map[string]*Histogram
	gauges     map[string]*Gauge
	metricsMu  sync.RWMutex

	// Event ring buffer simulation
	eventRing   chan Event
	eventHandlers []EventHandler
	handlerMu   sync.RWMutex

	// Latency tracking
	latencyBuckets []LatencyBucket
	latencyMu      sync.RWMutex

	// Per-service metrics
	serviceMetrics map[string]*ServiceMetrics
	svcMetricsMu   sync.RWMutex
}

// Counter is a monotonically increasing counter.
type Counter struct {
	name   string
	labels map[string]string
	value  atomic.Uint64
}

// Histogram tracks value distributions.
type Histogram struct {
	name    string
	labels  map[string]string
	buckets []uint64
	bounds  []float64
	count   atomic.Uint64
	sum     atomic.Uint64
	mu      sync.RWMutex
}

// Gauge is a value that can go up or down.
type Gauge struct {
	name   string
	labels map[string]string
	value  atomic.Int64
}

// ServiceMetrics contains per-service metrics.
type ServiceMetrics struct {
	ServiceKey     string
	RequestsTotal  atomic.Uint64
	BytesSent      atomic.Uint64
	BytesReceived  atomic.Uint64
	ErrorsTotal    atomic.Uint64
	ActiveConns    atomic.Int64
	LatencySum     atomic.Uint64
	LatencyCount   atomic.Uint64
	LatencyBuckets [10]atomic.Uint64
	LastUpdated    atomic.Int64
}

// NewObservabilityManager creates a new observability manager.
func NewObservabilityManager(config Config, logger *slog.Logger) *ObservabilityManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &ObservabilityManager{
		config:         config,
		logger:         logger,
		counters:       make(map[string]*Counter),
		histograms:     make(map[string]*Histogram),
		gauges:         make(map[string]*Gauge),
		eventRing:      make(chan Event, config.MetricsRingSize),
		serviceMetrics: make(map[string]*ServiceMetrics),
		latencyBuckets: DefaultLatencyBuckets(),
	}
}

// Load loads the observability eBPF programs.
func (m *ObservabilityManager) Load() error {
	if m.loaded.Load() {
		return ErrAlreadyLoaded
	}

	m.logger.Info("Loading observability eBPF programs")

	// Initialize default metrics
	m.registerDefaultMetrics()

	m.loaded.Store(true)
	m.logger.Info("Observability programs loaded")
	return nil
}

// Unload unloads the observability programs.
func (m *ObservabilityManager) Unload() error {
	if !m.loaded.Load() {
		return nil
	}

	m.loaded.Store(false)
	close(m.eventRing)
	m.logger.Info("Observability programs unloaded")
	return nil
}

// IsLoaded returns whether the programs are loaded.
func (m *ObservabilityManager) IsLoaded() bool {
	return m.loaded.Load()
}

// registerDefaultMetrics creates the default metrics.
func (m *ObservabilityManager) registerDefaultMetrics() {
	// Counters
	m.RegisterCounter("loom_requests_total", map[string]string{"type": "http"})
	m.RegisterCounter("loom_bytes_sent_total", nil)
	m.RegisterCounter("loom_bytes_received_total", nil)
	m.RegisterCounter("loom_connections_total", nil)
	m.RegisterCounter("loom_errors_total", nil)
	m.RegisterCounter("loom_xdp_packets_total", nil)
	m.RegisterCounter("loom_xdp_drops_total", nil)
	m.RegisterCounter("loom_xdp_redirects_total", nil)

	// Gauges
	m.RegisterGauge("loom_active_connections", nil)
	m.RegisterGauge("loom_backends_healthy", nil)
	m.RegisterGauge("loom_backends_total", nil)

	// Histograms
	m.RegisterHistogram("loom_request_duration_seconds", nil,
		[]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10})
	m.RegisterHistogram("loom_request_size_bytes", nil,
		[]float64{100, 1000, 10000, 100000, 1000000})
	m.RegisterHistogram("loom_response_size_bytes", nil,
		[]float64{100, 1000, 10000, 100000, 1000000})
}

// RegisterCounter registers a new counter metric.
func (m *ObservabilityManager) RegisterCounter(name string, labels map[string]string) *Counter {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	key := metricKey(name, labels)
	if c, exists := m.counters[key]; exists {
		return c
	}

	c := &Counter{
		name:   name,
		labels: labels,
	}
	m.counters[key] = c
	return c
}

// RegisterHistogram registers a new histogram metric.
func (m *ObservabilityManager) RegisterHistogram(name string, labels map[string]string, bounds []float64) *Histogram {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	key := metricKey(name, labels)
	if h, exists := m.histograms[key]; exists {
		return h
	}

	h := &Histogram{
		name:    name,
		labels:  labels,
		bounds:  bounds,
		buckets: make([]uint64, len(bounds)+1),
	}
	m.histograms[key] = h
	return h
}

// RegisterGauge registers a new gauge metric.
func (m *ObservabilityManager) RegisterGauge(name string, labels map[string]string) *Gauge {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	key := metricKey(name, labels)
	if g, exists := m.gauges[key]; exists {
		return g
	}

	g := &Gauge{
		name:   name,
		labels: labels,
	}
	m.gauges[key] = g
	return g
}

// IncCounter increments a counter.
func (m *ObservabilityManager) IncCounter(name string, labels map[string]string) {
	m.AddCounter(name, labels, 1)
}

// AddCounter adds to a counter.
func (m *ObservabilityManager) AddCounter(name string, labels map[string]string, value uint64) {
	m.metricsMu.RLock()
	key := metricKey(name, labels)
	c, exists := m.counters[key]
	m.metricsMu.RUnlock()

	if !exists {
		c = m.RegisterCounter(name, labels)
	}
	c.value.Add(value)
}

// ObserveHistogram records a value in a histogram.
func (m *ObservabilityManager) ObserveHistogram(name string, labels map[string]string, value float64) {
	m.metricsMu.RLock()
	key := metricKey(name, labels)
	h, exists := m.histograms[key]
	m.metricsMu.RUnlock()

	if !exists {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Find the bucket
	bucket := len(h.bounds)
	for i, bound := range h.bounds {
		if value <= bound {
			bucket = i
			break
		}
	}
	h.buckets[bucket]++
	h.count.Add(1)
	h.sum.Add(uint64(value * 1e9)) // Store in nanoseconds for precision
}

// SetGauge sets a gauge value.
func (m *ObservabilityManager) SetGauge(name string, labels map[string]string, value int64) {
	m.metricsMu.RLock()
	key := metricKey(name, labels)
	g, exists := m.gauges[key]
	m.metricsMu.RUnlock()

	if !exists {
		g = m.RegisterGauge(name, labels)
	}
	g.value.Store(value)
}

// IncGauge increments a gauge.
func (m *ObservabilityManager) IncGauge(name string, labels map[string]string) {
	m.metricsMu.RLock()
	key := metricKey(name, labels)
	g, exists := m.gauges[key]
	m.metricsMu.RUnlock()

	if !exists {
		g = m.RegisterGauge(name, labels)
	}
	g.value.Add(1)
}

// DecGauge decrements a gauge.
func (m *ObservabilityManager) DecGauge(name string, labels map[string]string) {
	m.metricsMu.RLock()
	key := metricKey(name, labels)
	g, exists := m.gauges[key]
	m.metricsMu.RUnlock()

	if !exists {
		return
	}
	g.value.Add(-1)
}

// RecordRequest records a request with all relevant metrics.
func (m *ObservabilityManager) RecordRequest(serviceKey string, latency time.Duration, requestSize, responseSize int64, err error) {
	// Get or create service metrics
	sm := m.getOrCreateServiceMetrics(serviceKey)

	// Update counters
	sm.RequestsTotal.Add(1)
	sm.BytesSent.Add(uint64(requestSize))
	sm.BytesReceived.Add(uint64(responseSize))
	if err != nil {
		sm.ErrorsTotal.Add(1)
	}

	// Update latency
	latencyUs := uint64(latency.Microseconds())
	sm.LatencySum.Add(latencyUs)
	sm.LatencyCount.Add(1)

	// Update latency bucket
	bucketIdx := m.getLatencyBucket(latency)
	if bucketIdx < len(sm.LatencyBuckets) {
		sm.LatencyBuckets[bucketIdx].Add(1)
	}

	sm.LastUpdated.Store(time.Now().UnixNano())

	// Update global metrics
	m.IncCounter("loom_requests_total", map[string]string{"service": serviceKey})
	m.AddCounter("loom_bytes_sent_total", nil, uint64(requestSize))
	m.AddCounter("loom_bytes_received_total", nil, uint64(responseSize))
	if err != nil {
		m.IncCounter("loom_errors_total", map[string]string{"service": serviceKey})
	}
	m.ObserveHistogram("loom_request_duration_seconds", nil, latency.Seconds())
}

// RecordConnection records a connection event.
func (m *ObservabilityManager) RecordConnection(serviceKey string, connected bool) {
	sm := m.getOrCreateServiceMetrics(serviceKey)

	if connected {
		sm.ActiveConns.Add(1)
		m.IncGauge("loom_active_connections", map[string]string{"service": serviceKey})
		m.IncCounter("loom_connections_total", nil)
	} else {
		sm.ActiveConns.Add(-1)
		m.DecGauge("loom_active_connections", map[string]string{"service": serviceKey})
	}
}

// RecordXDPEvent records an XDP processing event.
func (m *ObservabilityManager) RecordXDPEvent(action XDPAction, bytes uint64) {
	m.IncCounter("loom_xdp_packets_total", nil)
	m.AddCounter("loom_bytes_received_total", nil, bytes)

	switch action {
	case XDPDrop:
		m.IncCounter("loom_xdp_drops_total", nil)
	case XDPRedirect:
		m.IncCounter("loom_xdp_redirects_total", nil)
	}
}

// getOrCreateServiceMetrics gets or creates metrics for a service.
func (m *ObservabilityManager) getOrCreateServiceMetrics(serviceKey string) *ServiceMetrics {
	m.svcMetricsMu.RLock()
	sm, exists := m.serviceMetrics[serviceKey]
	m.svcMetricsMu.RUnlock()

	if exists {
		return sm
	}

	m.svcMetricsMu.Lock()
	defer m.svcMetricsMu.Unlock()

	// Double-check after acquiring write lock
	if sm, exists = m.serviceMetrics[serviceKey]; exists {
		return sm
	}

	sm = &ServiceMetrics{
		ServiceKey: serviceKey,
	}
	m.serviceMetrics[serviceKey] = sm
	return sm
}

// getLatencyBucket returns the bucket index for a latency value.
func (m *ObservabilityManager) getLatencyBucket(latency time.Duration) int {
	m.latencyMu.RLock()
	defer m.latencyMu.RUnlock()

	for i, bucket := range m.latencyBuckets {
		if latency <= bucket.UpperBound {
			return i
		}
	}
	return len(m.latencyBuckets) - 1
}

// OnEvent registers an event handler.
func (m *ObservabilityManager) OnEvent(handler EventHandler) {
	m.handlerMu.Lock()
	defer m.handlerMu.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// EmitEvent emits an event to the ring buffer and handlers.
func (m *ObservabilityManager) EmitEvent(event Event) {
	// Try to send to ring buffer (non-blocking)
	select {
	case m.eventRing <- event:
	default:
		// Ring buffer full, drop event
	}

	// Notify handlers
	m.handlerMu.RLock()
	handlers := m.eventHandlers
	m.handlerMu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}

// GetServiceMetrics returns metrics for a service.
func (m *ObservabilityManager) GetServiceMetrics(serviceKey string) *ServiceMetricsSnapshot {
	m.svcMetricsMu.RLock()
	sm, exists := m.serviceMetrics[serviceKey]
	m.svcMetricsMu.RUnlock()

	if !exists {
		return nil
	}

	return &ServiceMetricsSnapshot{
		ServiceKey:    serviceKey,
		RequestsTotal: sm.RequestsTotal.Load(),
		BytesSent:     sm.BytesSent.Load(),
		BytesReceived: sm.BytesReceived.Load(),
		ErrorsTotal:   sm.ErrorsTotal.Load(),
		ActiveConns:   sm.ActiveConns.Load(),
		AvgLatencyUs:  m.calculateAvgLatency(sm),
		LastUpdated:   time.Unix(0, sm.LastUpdated.Load()),
	}
}

// ServiceMetricsSnapshot is a point-in-time snapshot of service metrics.
type ServiceMetricsSnapshot struct {
	ServiceKey    string
	RequestsTotal uint64
	BytesSent     uint64
	BytesReceived uint64
	ErrorsTotal   uint64
	ActiveConns   int64
	AvgLatencyUs  float64
	LastUpdated   time.Time
}

// calculateAvgLatency calculates average latency from atomic counters.
func (m *ObservabilityManager) calculateAvgLatency(sm *ServiceMetrics) float64 {
	count := sm.LatencyCount.Load()
	if count == 0 {
		return 0
	}
	return float64(sm.LatencySum.Load()) / float64(count)
}

// GetAllServiceMetrics returns metrics for all services.
func (m *ObservabilityManager) GetAllServiceMetrics() []*ServiceMetricsSnapshot {
	m.svcMetricsMu.RLock()
	defer m.svcMetricsMu.RUnlock()

	result := make([]*ServiceMetricsSnapshot, 0, len(m.serviceMetrics))
	for key := range m.serviceMetrics {
		if snap := m.GetServiceMetrics(key); snap != nil {
			result = append(result, snap)
		}
	}

	// Sort by service key
	sort.Slice(result, func(i, j int) bool {
		return result[i].ServiceKey < result[j].ServiceKey
	})

	return result
}

// GetCounterValue returns the current value of a counter.
func (m *ObservabilityManager) GetCounterValue(name string, labels map[string]string) uint64 {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	key := metricKey(name, labels)
	if c, exists := m.counters[key]; exists {
		return c.value.Load()
	}
	return 0
}

// GetGaugeValue returns the current value of a gauge.
func (m *ObservabilityManager) GetGaugeValue(name string, labels map[string]string) int64 {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	key := metricKey(name, labels)
	if g, exists := m.gauges[key]; exists {
		return g.value.Load()
	}
	return 0
}

// ExportPrometheus exports metrics in Prometheus format.
func (m *ObservabilityManager) ExportPrometheus() string {
	var output string

	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	// Export counters
	for _, c := range m.counters {
		labels := formatLabels(c.labels)
		output += fmt.Sprintf("# TYPE %s counter\n", c.name)
		output += fmt.Sprintf("%s%s %d\n", c.name, labels, c.value.Load())
	}

	// Export gauges
	for _, g := range m.gauges {
		labels := formatLabels(g.labels)
		output += fmt.Sprintf("# TYPE %s gauge\n", g.name)
		output += fmt.Sprintf("%s%s %d\n", g.name, labels, g.value.Load())
	}

	// Export histograms
	for _, h := range m.histograms {
		labels := formatLabels(h.labels)
		output += fmt.Sprintf("# TYPE %s histogram\n", h.name)

		h.mu.RLock()
		var cumulative uint64
		for i, bound := range h.bounds {
			cumulative += h.buckets[i]
			output += fmt.Sprintf("%s_bucket%s{le=\"%.3f\"} %d\n", h.name, labels, bound, cumulative)
		}
		cumulative += h.buckets[len(h.bounds)]
		output += fmt.Sprintf("%s_bucket%s{le=\"+Inf\"} %d\n", h.name, labels, cumulative)
		output += fmt.Sprintf("%s_sum%s %d\n", h.name, labels, h.sum.Load())
		output += fmt.Sprintf("%s_count%s %d\n", h.name, labels, h.count.Load())
		h.mu.RUnlock()
	}

	return output
}

// Run starts the observability manager.
func (m *ObservabilityManager) Run(ctx context.Context) error {
	if err := m.Load(); err != nil && err != ErrAlreadyLoaded {
		return err
	}

	m.logger.Info("Observability manager started")

	// Process events from ring buffer
	go m.processEvents(ctx)

	<-ctx.Done()

	m.Unload()
	m.logger.Info("Observability manager stopped")
	return nil
}

// processEvents processes events from the ring buffer.
func (m *ObservabilityManager) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-m.eventRing:
			if !ok {
				return
			}
			m.handleEvent(event)
		}
	}
}

// handleEvent processes a single event.
func (m *ObservabilityManager) handleEvent(event Event) {
	switch event.Type {
	case EventTypeConnection:
		m.IncCounter("loom_connections_total", nil)
	case EventTypeRequest:
		m.IncCounter("loom_requests_total", nil)
		m.AddCounter("loom_bytes_sent_total", nil, event.Bytes)
	case EventTypeResponse:
		m.AddCounter("loom_bytes_received_total", nil, event.Bytes)
		if event.Latency > 0 {
			m.ObserveHistogram("loom_request_duration_seconds", nil, float64(event.Latency)/1e9)
		}
	case EventTypeError:
		m.IncCounter("loom_errors_total", nil)
	case EventTypeDrop:
		m.IncCounter("loom_xdp_drops_total", nil)
	}
}

// Helper functions

func metricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	// Sort label keys for consistent ordering
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := name
	for _, k := range keys {
		key += fmt.Sprintf("_%s_%s", k, labels[k])
	}
	return key
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := "{"
	for i, k := range keys {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, labels[k])
	}
	result += "}"
	return result
}
