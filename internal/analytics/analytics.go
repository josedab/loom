// Package analytics provides a real-time analytics pipeline for API gateway metrics.
package analytics

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event represents an analytics event.
type Event struct {
	// Timestamp when the event occurred.
	Timestamp time.Time `json:"timestamp"`
	// Type of event (request, response, error).
	Type EventType `json:"type"`
	// Method is the HTTP method.
	Method string `json:"method"`
	// Path is the request path.
	Path string `json:"path"`
	// StatusCode is the HTTP response status.
	StatusCode int `json:"status_code,omitempty"`
	// Duration is the request duration.
	Duration time.Duration `json:"duration_ns,omitempty"`
	// BytesSent is the response size.
	BytesSent int64 `json:"bytes_sent,omitempty"`
	// BytesReceived is the request size.
	BytesReceived int64 `json:"bytes_received,omitempty"`
	// ClientIP is the client IP address.
	ClientIP string `json:"client_ip,omitempty"`
	// UserAgent is the client user agent.
	UserAgent string `json:"user_agent,omitempty"`
	// Route is the matched route ID.
	Route string `json:"route,omitempty"`
	// Upstream is the backend that handled the request.
	Upstream string `json:"upstream,omitempty"`
	// TenantID is the tenant identifier.
	TenantID string `json:"tenant_id,omitempty"`
	// Error message if any.
	Error string `json:"error,omitempty"`
	// Labels are custom key-value pairs.
	Labels map[string]string `json:"labels,omitempty"`
}

// EventType represents the type of analytics event.
type EventType string

const (
	EventTypeRequest  EventType = "request"
	EventTypeResponse EventType = "response"
	EventTypeError    EventType = "error"
)

// Pipeline collects and processes analytics events.
type Pipeline struct {
	events     chan *Event
	aggregator *Aggregator
	storage    Storage
	logger     *slog.Logger
	done       chan struct{}
	wg         sync.WaitGroup
	config     PipelineConfig
}

// PipelineConfig configures the analytics pipeline.
type PipelineConfig struct {
	// BufferSize is the event buffer size.
	BufferSize int
	// FlushInterval is how often to flush aggregated data.
	FlushInterval time.Duration
	// Storage for persisting analytics.
	Storage Storage
	// Logger for pipeline events.
	Logger *slog.Logger
	// Workers is the number of event processing workers.
	Workers int
}

// NewPipeline creates a new analytics pipeline.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 10000
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Workers == 0 {
		cfg.Workers = 2
	}
	if cfg.Storage == nil {
		cfg.Storage = NewMemoryStorage(MemoryStorageConfig{})
	}

	return &Pipeline{
		events:     make(chan *Event, cfg.BufferSize),
		aggregator: NewAggregator(),
		storage:    cfg.Storage,
		logger:     cfg.Logger,
		done:       make(chan struct{}),
		config:     cfg,
	}
}

// Start begins processing events.
func (p *Pipeline) Start() {
	// Start event workers
	for i := 0; i < p.config.Workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	// Start aggregation flusher
	p.wg.Add(1)
	go p.flusher()

	p.logger.Info("analytics pipeline started",
		"workers", p.config.Workers,
		"buffer_size", p.config.BufferSize,
	)
}

// Stop gracefully stops the pipeline.
func (p *Pipeline) Stop() {
	close(p.done)
	p.wg.Wait()

	// Flush remaining data
	p.flush()

	p.logger.Info("analytics pipeline stopped")
}

func (p *Pipeline) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.done:
			return
		case event := <-p.events:
			if event != nil {
				p.processEvent(event)
			}
		}
	}
}

func (p *Pipeline) flusher() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.flush()
		}
	}
}

func (p *Pipeline) processEvent(event *Event) {
	p.aggregator.Record(event)
}

func (p *Pipeline) flush() {
	snapshot := p.aggregator.Snapshot()
	if err := p.storage.Store(snapshot); err != nil {
		p.logger.Error("failed to store analytics",
			"error", err,
		)
	}
}

// Record records an analytics event.
func (p *Pipeline) Record(event *Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case p.events <- event:
	default:
		p.logger.Warn("analytics buffer full, dropping event")
	}
}

// Query retrieves analytics data.
func (p *Pipeline) Query(q Query) (*QueryResult, error) {
	return p.storage.Query(q)
}

// GetAggregator returns the aggregator for direct access.
func (p *Pipeline) GetAggregator() *Aggregator {
	return p.aggregator
}

// Aggregator aggregates analytics events in real-time.
type Aggregator struct {
	mu sync.RWMutex

	// Request counters
	totalRequests   int64
	totalErrors     int64
	totalBytes      int64
	requestsByPath  map[string]*int64
	requestsByCode  map[int]*int64

	// Latency tracking
	latencies     []time.Duration
	latencySum    int64
	latencyCount  int64

	// Rate tracking
	requestsPerSecond float64
	lastSecondCount   int64
	lastSecondTime    time.Time

	// Status code distribution
	statusCodes map[int]int64

	// Path metrics
	pathMetrics map[string]*PathMetrics

	// Time series (last hour, per minute)
	timeSeries []*TimePoint
}

// PathMetrics holds per-path metrics.
type PathMetrics struct {
	Count       int64           `json:"count"`
	ErrorCount  int64           `json:"error_count"`
	TotalBytes  int64           `json:"total_bytes"`
	Latencies   []time.Duration `json:"-"`
	AvgLatency  float64         `json:"avg_latency_ms"`
	P50Latency  float64         `json:"p50_latency_ms"`
	P95Latency  float64         `json:"p95_latency_ms"`
	P99Latency  float64         `json:"p99_latency_ms"`
}

// TimePoint represents a point in the time series.
type TimePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Requests  int64     `json:"requests"`
	Errors    int64     `json:"errors"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	BytesSent int64     `json:"bytes_sent"`
}

// NewAggregator creates a new aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		requestsByPath: make(map[string]*int64),
		requestsByCode: make(map[int]*int64),
		statusCodes:    make(map[int]int64),
		pathMetrics:    make(map[string]*PathMetrics),
		latencies:      make([]time.Duration, 0, 10000),
		timeSeries:     make([]*TimePoint, 0, 60),
		lastSecondTime: time.Now(),
	}
}

// Record records an event.
func (a *Aggregator) Record(event *Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Basic counters
	atomic.AddInt64(&a.totalRequests, 1)
	atomic.AddInt64(&a.totalBytes, event.BytesSent+event.BytesReceived)

	if event.StatusCode >= 400 {
		atomic.AddInt64(&a.totalErrors, 1)
	}

	// Status codes
	a.statusCodes[event.StatusCode]++

	// Path metrics
	pm, exists := a.pathMetrics[event.Path]
	if !exists {
		pm = &PathMetrics{
			Latencies: make([]time.Duration, 0, 1000),
		}
		a.pathMetrics[event.Path] = pm
	}
	pm.Count++
	pm.TotalBytes += event.BytesSent
	if event.StatusCode >= 400 {
		pm.ErrorCount++
	}
	pm.Latencies = append(pm.Latencies, event.Duration)

	// Global latencies
	a.latencies = append(a.latencies, event.Duration)
	atomic.AddInt64(&a.latencySum, int64(event.Duration))
	atomic.AddInt64(&a.latencyCount, 1)

	// Rate tracking
	now := time.Now()
	if now.Sub(a.lastSecondTime) >= time.Second {
		a.requestsPerSecond = float64(a.totalRequests - a.lastSecondCount)
		a.lastSecondCount = a.totalRequests
		a.lastSecondTime = now
	}
}

// Snapshot returns a snapshot of the current metrics.
func (a *Aggregator) Snapshot() *Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	snapshot := &Snapshot{
		Timestamp:     time.Now(),
		TotalRequests: a.totalRequests,
		TotalErrors:   a.totalErrors,
		TotalBytes:    a.totalBytes,
		RPS:           a.requestsPerSecond,
		StatusCodes:   make(map[int]int64),
		PathMetrics:   make(map[string]*PathMetrics),
	}

	// Copy status codes
	for code, count := range a.statusCodes {
		snapshot.StatusCodes[code] = count
	}

	// Calculate latency percentiles
	if len(a.latencies) > 0 {
		sorted := make([]time.Duration, len(a.latencies))
		copy(sorted, a.latencies)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		snapshot.AvgLatency = float64(a.latencySum/a.latencyCount) / float64(time.Millisecond)
		snapshot.P50Latency = float64(percentile(sorted, 50)) / float64(time.Millisecond)
		snapshot.P95Latency = float64(percentile(sorted, 95)) / float64(time.Millisecond)
		snapshot.P99Latency = float64(percentile(sorted, 99)) / float64(time.Millisecond)
	}

	// Copy path metrics with calculated percentiles
	for path, pm := range a.pathMetrics {
		pmCopy := &PathMetrics{
			Count:      pm.Count,
			ErrorCount: pm.ErrorCount,
			TotalBytes: pm.TotalBytes,
		}

		if len(pm.Latencies) > 0 {
			sorted := make([]time.Duration, len(pm.Latencies))
			copy(sorted, pm.Latencies)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

			var sum int64
			for _, l := range pm.Latencies {
				sum += int64(l)
			}
			pmCopy.AvgLatency = float64(sum/int64(len(pm.Latencies))) / float64(time.Millisecond)
			pmCopy.P50Latency = float64(percentile(sorted, 50)) / float64(time.Millisecond)
			pmCopy.P95Latency = float64(percentile(sorted, 95)) / float64(time.Millisecond)
			pmCopy.P99Latency = float64(percentile(sorted, 99)) / float64(time.Millisecond)
		}

		snapshot.PathMetrics[path] = pmCopy
	}

	return snapshot
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(p/100.0*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

// Reset resets all counters.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.totalRequests = 0
	a.totalErrors = 0
	a.totalBytes = 0
	a.latencies = a.latencies[:0]
	a.latencySum = 0
	a.latencyCount = 0
	a.statusCodes = make(map[int]int64)
	a.pathMetrics = make(map[string]*PathMetrics)
}

// Snapshot represents a point-in-time snapshot of analytics.
type Snapshot struct {
	Timestamp     time.Time              `json:"timestamp"`
	TotalRequests int64                  `json:"total_requests"`
	TotalErrors   int64                  `json:"total_errors"`
	TotalBytes    int64                  `json:"total_bytes"`
	RPS           float64                `json:"requests_per_second"`
	AvgLatency    float64                `json:"avg_latency_ms"`
	P50Latency    float64                `json:"p50_latency_ms"`
	P95Latency    float64                `json:"p95_latency_ms"`
	P99Latency    float64                `json:"p99_latency_ms"`
	StatusCodes   map[int]int64          `json:"status_codes"`
	PathMetrics   map[string]*PathMetrics `json:"path_metrics"`
}

// Storage persists analytics data.
type Storage interface {
	// Store stores a snapshot.
	Store(snapshot *Snapshot) error
	// Query retrieves analytics data.
	Query(q Query) (*QueryResult, error)
	// GetSnapshots retrieves historical snapshots.
	GetSnapshots(start, end time.Time, limit int) ([]*Snapshot, error)
}

// Query represents an analytics query.
type Query struct {
	// StartTime for the query range.
	StartTime time.Time `json:"start_time"`
	// EndTime for the query range.
	EndTime time.Time `json:"end_time"`
	// Paths to filter by.
	Paths []string `json:"paths,omitempty"`
	// StatusCodes to filter by.
	StatusCodes []int `json:"status_codes,omitempty"`
	// GroupBy field.
	GroupBy string `json:"group_by,omitempty"`
	// Limit results.
	Limit int `json:"limit,omitempty"`
}

// QueryResult represents analytics query results.
type QueryResult struct {
	// TotalRequests in the time range.
	TotalRequests int64 `json:"total_requests"`
	// TotalErrors in the time range.
	TotalErrors int64 `json:"total_errors"`
	// AvgLatency in milliseconds.
	AvgLatency float64 `json:"avg_latency_ms"`
	// P95Latency in milliseconds.
	P95Latency float64 `json:"p95_latency_ms"`
	// P99Latency in milliseconds.
	P99Latency float64 `json:"p99_latency_ms"`
	// TimeSeries data points.
	TimeSeries []*TimePoint `json:"time_series,omitempty"`
	// ByPath metrics grouped by path.
	ByPath map[string]*PathMetrics `json:"by_path,omitempty"`
	// ByStatusCode metrics grouped by status code.
	ByStatusCode map[int]int64 `json:"by_status_code,omitempty"`
}

// MemoryStorage stores analytics in memory.
type MemoryStorage struct {
	snapshots []*Snapshot
	mu        sync.RWMutex
	maxSize   int
}

// MemoryStorageConfig configures memory storage.
type MemoryStorageConfig struct {
	// MaxSnapshots to retain.
	MaxSnapshots int
}

// NewMemoryStorage creates a new memory storage.
func NewMemoryStorage(cfg MemoryStorageConfig) *MemoryStorage {
	if cfg.MaxSnapshots == 0 {
		cfg.MaxSnapshots = 60 // 1 hour at 1-minute intervals
	}
	return &MemoryStorage{
		snapshots: make([]*Snapshot, 0, cfg.MaxSnapshots),
		maxSize:   cfg.MaxSnapshots,
	}
}

// Store stores a snapshot.
func (s *MemoryStorage) Store(snapshot *Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshots = append(s.snapshots, snapshot)
	if len(s.snapshots) > s.maxSize {
		s.snapshots = s.snapshots[1:]
	}

	return nil
}

// Query retrieves analytics data.
func (s *MemoryStorage) Query(q Query) (*QueryResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := &QueryResult{
		TimeSeries:   make([]*TimePoint, 0),
		ByPath:       make(map[string]*PathMetrics),
		ByStatusCode: make(map[int]int64),
	}

	var totalLatency float64
	var latencyCount int64

	for _, snap := range s.snapshots {
		if !q.StartTime.IsZero() && snap.Timestamp.Before(q.StartTime) {
			continue
		}
		if !q.EndTime.IsZero() && snap.Timestamp.After(q.EndTime) {
			continue
		}

		result.TotalRequests += snap.TotalRequests
		result.TotalErrors += snap.TotalErrors
		totalLatency += snap.AvgLatency * float64(snap.TotalRequests)
		latencyCount += snap.TotalRequests

		// Time series
		result.TimeSeries = append(result.TimeSeries, &TimePoint{
			Timestamp:    snap.Timestamp,
			Requests:     snap.TotalRequests,
			Errors:       snap.TotalErrors,
			AvgLatencyMs: snap.AvgLatency,
		})

		// Aggregate status codes
		for code, count := range snap.StatusCodes {
			result.ByStatusCode[code] += count
		}

		// Aggregate path metrics
		for path, pm := range snap.PathMetrics {
			if len(q.Paths) > 0 && !containsString(q.Paths, path) {
				continue
			}

			existing, ok := result.ByPath[path]
			if !ok {
				existing = &PathMetrics{}
				result.ByPath[path] = existing
			}
			existing.Count += pm.Count
			existing.ErrorCount += pm.ErrorCount
			existing.TotalBytes += pm.TotalBytes
		}
	}

	if latencyCount > 0 {
		result.AvgLatency = totalLatency / float64(latencyCount)
	}

	return result, nil
}

// GetSnapshots retrieves historical snapshots.
func (s *MemoryStorage) GetSnapshots(start, end time.Time, limit int) ([]*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Snapshot, 0)
	for _, snap := range s.snapshots {
		if !start.IsZero() && snap.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && snap.Timestamp.After(end) {
			continue
		}
		result = append(result, snap)
		if limit > 0 && len(result) >= limit {
			break
		}
	}

	return result, nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// Stats holds real-time statistics.
type Stats struct {
	TotalRequests     int64              `json:"total_requests"`
	TotalErrors       int64              `json:"total_errors"`
	TotalBytes        int64              `json:"total_bytes"`
	ErrorRate         float64            `json:"error_rate"`
	RequestsPerSecond float64            `json:"requests_per_second"`
	AvgLatencyMs      float64            `json:"avg_latency_ms"`
	P50LatencyMs      float64            `json:"p50_latency_ms"`
	P95LatencyMs      float64            `json:"p95_latency_ms"`
	P99LatencyMs      float64            `json:"p99_latency_ms"`
	StatusCodes       map[int]int64      `json:"status_codes"`
	TopPaths          []*PathSummary     `json:"top_paths"`
}

// PathSummary summarizes metrics for a path.
type PathSummary struct {
	Path        string  `json:"path"`
	Count       int64   `json:"count"`
	ErrorRate   float64 `json:"error_rate"`
	AvgLatency  float64 `json:"avg_latency_ms"`
}

// GetStats returns current statistics.
func (p *Pipeline) GetStats() *Stats {
	snapshot := p.aggregator.Snapshot()

	stats := &Stats{
		TotalRequests:     snapshot.TotalRequests,
		TotalErrors:       snapshot.TotalErrors,
		TotalBytes:        snapshot.TotalBytes,
		RequestsPerSecond: snapshot.RPS,
		AvgLatencyMs:      snapshot.AvgLatency,
		P50LatencyMs:      snapshot.P50Latency,
		P95LatencyMs:      snapshot.P95Latency,
		P99LatencyMs:      snapshot.P99Latency,
		StatusCodes:       snapshot.StatusCodes,
	}

	if snapshot.TotalRequests > 0 {
		stats.ErrorRate = float64(snapshot.TotalErrors) / float64(snapshot.TotalRequests) * 100
	}

	// Top paths by request count
	type pathEntry struct {
		path    string
		metrics *PathMetrics
	}
	paths := make([]pathEntry, 0, len(snapshot.PathMetrics))
	for path, pm := range snapshot.PathMetrics {
		paths = append(paths, pathEntry{path, pm})
	}
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].metrics.Count > paths[j].metrics.Count
	})

	stats.TopPaths = make([]*PathSummary, 0)
	for i := 0; i < len(paths) && i < 10; i++ {
		pm := paths[i].metrics
		errorRate := float64(0)
		if pm.Count > 0 {
			errorRate = float64(pm.ErrorCount) / float64(pm.Count) * 100
		}
		stats.TopPaths = append(stats.TopPaths, &PathSummary{
			Path:       paths[i].path,
			Count:      pm.Count,
			ErrorRate:  errorRate,
			AvgLatency: pm.AvgLatency,
		})
	}

	return stats
}

// Collector collects events from HTTP requests.
type Collector struct {
	pipeline *Pipeline
	logger   *slog.Logger
}

// NewCollector creates a new collector.
func NewCollector(pipeline *Pipeline, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		pipeline: pipeline,
		logger:   logger,
	}
}

// CollectRequest records a request event.
func (c *Collector) CollectRequest(r *http.Request, route, upstream string) {
	c.pipeline.Record(&Event{
		Type:          EventTypeRequest,
		Method:        r.Method,
		Path:          r.URL.Path,
		ClientIP:      getClientIP(r),
		UserAgent:     r.UserAgent(),
		Route:         route,
		Upstream:      upstream,
		BytesReceived: r.ContentLength,
	})
}

// CollectResponse records a response event.
func (c *Collector) CollectResponse(r *http.Request, statusCode int, bytesSent int64, duration time.Duration, route, upstream string) {
	eventType := EventTypeResponse
	var errMsg string
	if statusCode >= 400 {
		eventType = EventTypeError
		errMsg = http.StatusText(statusCode)
	}

	c.pipeline.Record(&Event{
		Type:       eventType,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: statusCode,
		Duration:   duration,
		BytesSent:  bytesSent,
		ClientIP:   getClientIP(r),
		UserAgent:  r.UserAgent(),
		Route:      route,
		Upstream:   upstream,
		Error:      errMsg,
	})
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// StreamSubscriber receives real-time analytics updates.
type StreamSubscriber interface {
	// OnEvent is called for each analytics event.
	OnEvent(event *Event)
	// OnSnapshot is called for each snapshot.
	OnSnapshot(snapshot *Snapshot)
}

// Stream provides real-time analytics streaming.
type Stream struct {
	subscribers []StreamSubscriber
	mu          sync.RWMutex
}

// NewStream creates a new analytics stream.
func NewStream() *Stream {
	return &Stream{
		subscribers: make([]StreamSubscriber, 0),
	}
}

// Subscribe adds a subscriber.
func (s *Stream) Subscribe(sub StreamSubscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers = append(s.subscribers, sub)
}

// Unsubscribe removes a subscriber.
func (s *Stream) Unsubscribe(sub StreamSubscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, existing := range s.subscribers {
		if existing == sub {
			s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
			return
		}
	}
}

// PublishEvent sends an event to all subscribers.
func (s *Stream) PublishEvent(event *Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subscribers {
		go sub.OnEvent(event)
	}
}

// PublishSnapshot sends a snapshot to all subscribers.
func (s *Stream) PublishSnapshot(snapshot *Snapshot) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subscribers {
		go sub.OnSnapshot(snapshot)
	}
}

// Middleware records analytics for HTTP requests.
func Middleware(collector *Collector, routeResolver func(*http.Request) (string, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			route, upstream := "", ""
			if routeResolver != nil {
				route, upstream = routeResolver(r)
			}

			// Wrap response writer to capture status and bytes
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			collector.CollectResponse(r, wrapped.statusCode, wrapped.bytesWritten, duration, route, upstream)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// StreamingPipeline extends Pipeline with streaming capabilities.
type StreamingPipeline struct {
	*Pipeline
	stream *Stream
}

// NewStreamingPipeline creates a pipeline with streaming support.
func NewStreamingPipeline(cfg PipelineConfig) *StreamingPipeline {
	return &StreamingPipeline{
		Pipeline: NewPipeline(cfg),
		stream:   NewStream(),
	}
}

// GetStream returns the analytics stream.
func (p *StreamingPipeline) GetStream() *Stream {
	return p.stream
}

// Record records an event and publishes to stream.
func (p *StreamingPipeline) Record(event *Event) {
	p.Pipeline.Record(event)
	p.stream.PublishEvent(event)
}

// QueryContext performs a query with context support.
func (p *Pipeline) QueryContext(ctx context.Context, q Query) (*QueryResult, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return p.Query(q)
}
