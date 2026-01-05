// Package anomaly provides API anomaly detection capabilities.
package anomaly

import (
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Detector detects anomalies in API traffic.
type Detector struct {
	config    DetectorConfig
	metrics   *MetricStore
	baselines map[string]*Baseline
	alerts    []Alert
	alertChan chan Alert
	logger    *slog.Logger
	mu        sync.RWMutex
}

// DetectorConfig configures the anomaly detector.
type DetectorConfig struct {
	// WindowSize is the sliding window for metrics (default: 5 minutes)
	WindowSize time.Duration
	// BaselinePeriod is how long to learn baseline (default: 1 hour)
	BaselinePeriod time.Duration
	// ZScoreThreshold for statistical anomaly detection (default: 3.0)
	ZScoreThreshold float64
	// MinSamples required before detecting anomalies (default: 100)
	MinSamples int
	// AlertCooldown prevents repeated alerts (default: 5 minutes)
	AlertCooldown time.Duration
	// EnableLatencyAnomalies enables latency spike detection
	EnableLatencyAnomalies bool
	// EnableErrorAnomalies enables error rate spike detection
	EnableErrorAnomalies bool
	// EnableRateAnomalies enables request rate anomaly detection
	EnableRateAnomalies bool
	// EnablePatternAnomalies enables unusual pattern detection
	EnablePatternAnomalies bool
	// Logger for detector events
	Logger *slog.Logger
}

// DefaultDetectorConfig returns sensible defaults.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		WindowSize:             5 * time.Minute,
		BaselinePeriod:         time.Hour,
		ZScoreThreshold:        3.0,
		MinSamples:             100,
		AlertCooldown:          5 * time.Minute,
		EnableLatencyAnomalies: true,
		EnableErrorAnomalies:   true,
		EnableRateAnomalies:    true,
		EnablePatternAnomalies: true,
	}
}

// Metric represents a single measurement.
type Metric struct {
	Timestamp   time.Time
	Route       string
	Method      string
	StatusCode  int
	Latency     time.Duration
	RequestSize int64
	IP          string
	UserAgent   string
}

// MetricStore stores metrics in a sliding window.
type MetricStore struct {
	metrics    []Metric
	maxAge     time.Duration
	maxSize    int
	mu         sync.RWMutex
}

// NewMetricStore creates a new metric store.
func NewMetricStore(maxAge time.Duration, maxSize int) *MetricStore {
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	if maxSize == 0 {
		maxSize = 100000
	}

	store := &MetricStore{
		metrics: make([]Metric, 0, maxSize),
		maxAge:  maxAge,
		maxSize: maxSize,
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Add adds a metric to the store.
func (s *MetricStore) Add(m Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.metrics) >= s.maxSize {
		// Remove oldest 10%
		s.metrics = s.metrics[s.maxSize/10:]
	}

	s.metrics = append(s.metrics, m)
}

// Query returns metrics matching the filter.
func (s *MetricStore) Query(filter MetricFilter) []Metric {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Metric
	cutoff := time.Now().Add(-filter.Duration)

	for _, m := range s.metrics {
		if m.Timestamp.Before(cutoff) {
			continue
		}
		if filter.Route != "" && m.Route != filter.Route {
			continue
		}
		if filter.Method != "" && m.Method != filter.Method {
			continue
		}
		results = append(results, m)
	}

	return results
}

// Count returns the number of metrics.
func (s *MetricStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.metrics)
}

// cleanupLoop removes expired metrics.
func (s *MetricStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

func (s *MetricStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-s.maxAge)
	i := 0
	for ; i < len(s.metrics); i++ {
		if s.metrics[i].Timestamp.After(cutoff) {
			break
		}
	}

	if i > 0 {
		s.metrics = s.metrics[i:]
	}
}

// MetricFilter filters metrics for queries.
type MetricFilter struct {
	Duration time.Duration
	Route    string
	Method   string
}

// Baseline represents learned normal behavior.
type Baseline struct {
	Route          string
	Method         string
	LatencyMean    float64
	LatencyStdDev  float64
	ErrorRate      float64
	RequestsPerMin float64
	Samples        int
	LastUpdated    time.Time
}

// Alert represents a detected anomaly.
type Alert struct {
	ID          string        `json:"id"`
	Type        AnomalyType   `json:"type"`
	Severity    Severity      `json:"severity"`
	Route       string        `json:"route"`
	Method      string        `json:"method,omitempty"`
	Description string        `json:"description"`
	Value       float64       `json:"value"`
	Expected    float64       `json:"expected"`
	Deviation   float64       `json:"deviation"`
	Timestamp   time.Time     `json:"timestamp"`
	Duration    time.Duration `json:"duration,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AnomalyType identifies the type of anomaly.
type AnomalyType string

const (
	AnomalyTypeLatency AnomalyType = "latency"
	AnomalyTypeError   AnomalyType = "error_rate"
	AnomalyTypeRate    AnomalyType = "request_rate"
	AnomalyTypePattern AnomalyType = "pattern"
)

// Severity indicates how serious the anomaly is.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// New creates a new anomaly detector.
func New(config DetectorConfig) *Detector {
	if config.WindowSize == 0 {
		config.WindowSize = 5 * time.Minute
	}
	if config.BaselinePeriod == 0 {
		config.BaselinePeriod = time.Hour
	}
	if config.ZScoreThreshold == 0 {
		config.ZScoreThreshold = 3.0
	}
	if config.MinSamples == 0 {
		config.MinSamples = 100
	}
	if config.AlertCooldown == 0 {
		config.AlertCooldown = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	d := &Detector{
		config:    config,
		metrics:   NewMetricStore(config.WindowSize*12, 0), // Store 12x window for baseline
		baselines: make(map[string]*Baseline),
		alerts:    make([]Alert, 0),
		alertChan: make(chan Alert, 100),
		logger:    config.Logger,
	}

	// Start baseline learning
	go d.baselineLearningLoop()

	return d
}

// Record records a metric and checks for anomalies.
func (d *Detector) Record(m Metric) []Alert {
	if m.Timestamp.IsZero() {
		m.Timestamp = time.Now()
	}

	d.metrics.Add(m)

	// Check for anomalies
	return d.detect(m)
}

// detect checks a metric for anomalies.
func (d *Detector) detect(m Metric) []Alert {
	d.mu.RLock()
	baseline := d.baselines[baselineKey(m.Route, m.Method)]
	d.mu.RUnlock()

	if baseline == nil || baseline.Samples < d.config.MinSamples {
		return nil // Not enough data for detection
	}

	var alerts []Alert

	// Check latency anomaly
	if d.config.EnableLatencyAnomalies {
		if alert := d.detectLatencyAnomaly(m, baseline); alert != nil {
			alerts = append(alerts, *alert)
		}
	}

	// Check error anomaly
	if d.config.EnableErrorAnomalies && m.StatusCode >= 500 {
		if alert := d.detectErrorAnomaly(m, baseline); alert != nil {
			alerts = append(alerts, *alert)
		}
	}

	// Store and notify alerts
	for _, alert := range alerts {
		d.storeAlert(alert)
	}

	return alerts
}

// detectLatencyAnomaly checks for latency spikes.
func (d *Detector) detectLatencyAnomaly(m Metric, baseline *Baseline) *Alert {
	if baseline.LatencyStdDev == 0 {
		return nil
	}

	latencyMs := float64(m.Latency.Milliseconds())
	zScore := (latencyMs - baseline.LatencyMean) / baseline.LatencyStdDev

	if zScore > d.config.ZScoreThreshold {
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypeLatency,
			Severity:    calculateSeverity(zScore, d.config.ZScoreThreshold),
			Route:       m.Route,
			Method:      m.Method,
			Description: "Latency spike detected",
			Value:       latencyMs,
			Expected:    baseline.LatencyMean,
			Deviation:   zScore,
			Timestamp:   m.Timestamp,
			Duration:    m.Latency,
		}
	}

	return nil
}

// detectErrorAnomaly checks for error rate spikes.
func (d *Detector) detectErrorAnomaly(m Metric, baseline *Baseline) *Alert {
	// Get recent error rate
	metrics := d.metrics.Query(MetricFilter{
		Duration: d.config.WindowSize,
		Route:    m.Route,
		Method:   m.Method,
	})

	if len(metrics) == 0 {
		return nil
	}

	errorCount := 0
	for _, metric := range metrics {
		if metric.StatusCode >= 500 {
			errorCount++
		}
	}

	currentErrorRate := float64(errorCount) / float64(len(metrics))

	// Check if significantly higher than baseline
	if baseline.ErrorRate == 0 {
		baseline.ErrorRate = 0.01 // Default 1% baseline
	}

	ratio := currentErrorRate / baseline.ErrorRate
	if ratio > 3.0 { // 3x normal error rate
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypeError,
			Severity:    calculateErrorSeverity(currentErrorRate),
			Route:       m.Route,
			Method:      m.Method,
			Description: "Error rate spike detected",
			Value:       currentErrorRate * 100,
			Expected:    baseline.ErrorRate * 100,
			Deviation:   ratio,
			Timestamp:   m.Timestamp,
			Metadata: map[string]interface{}{
				"error_count": errorCount,
				"total":       len(metrics),
			},
		}
	}

	return nil
}

// DetectRateAnomaly checks for unusual request rates.
func (d *Detector) DetectRateAnomaly(route, method string) *Alert {
	d.mu.RLock()
	baseline := d.baselines[baselineKey(route, method)]
	d.mu.RUnlock()

	if baseline == nil || baseline.Samples < d.config.MinSamples {
		return nil
	}

	metrics := d.metrics.Query(MetricFilter{
		Duration: time.Minute,
		Route:    route,
		Method:   method,
	})

	currentRate := float64(len(metrics))

	if baseline.RequestsPerMin == 0 {
		return nil
	}

	ratio := currentRate / baseline.RequestsPerMin
	if ratio > 5.0 { // 5x normal rate
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypeRate,
			Severity:    SeverityMedium,
			Route:       route,
			Method:      method,
			Description: "Request rate spike detected",
			Value:       currentRate,
			Expected:    baseline.RequestsPerMin,
			Deviation:   ratio,
			Timestamp:   time.Now(),
		}
	}

	if ratio < 0.1 && currentRate > 0 { // 10% of normal rate
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypeRate,
			Severity:    SeverityMedium,
			Route:       route,
			Method:      method,
			Description: "Request rate drop detected",
			Value:       currentRate,
			Expected:    baseline.RequestsPerMin,
			Deviation:   ratio,
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// storeAlert stores an alert and notifies listeners.
func (d *Detector) storeAlert(alert Alert) {
	d.mu.Lock()
	d.alerts = append(d.alerts, alert)

	// Keep last 1000 alerts
	if len(d.alerts) > 1000 {
		d.alerts = d.alerts[len(d.alerts)-1000:]
	}
	d.mu.Unlock()

	// Non-blocking send to channel
	select {
	case d.alertChan <- alert:
	default:
	}

	d.logger.Warn("anomaly detected",
		"type", alert.Type,
		"severity", alert.Severity,
		"route", alert.Route,
		"value", alert.Value,
		"expected", alert.Expected,
	)
}

// GetAlerts returns recent alerts.
func (d *Detector) GetAlerts(limit int) []Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if limit <= 0 || limit > len(d.alerts) {
		limit = len(d.alerts)
	}

	start := len(d.alerts) - limit
	result := make([]Alert, limit)
	copy(result, d.alerts[start:])

	return result
}

// AlertChannel returns a channel for receiving alerts.
func (d *Detector) AlertChannel() <-chan Alert {
	return d.alertChan
}

// baselineLearningLoop continuously updates baselines.
func (d *Detector) baselineLearningLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.updateBaselines()
	}
}

// updateBaselines recalculates baselines from historical data.
func (d *Detector) updateBaselines() {
	metrics := d.metrics.Query(MetricFilter{
		Duration: d.config.BaselinePeriod,
	})

	if len(metrics) == 0 {
		return
	}

	// Group by route/method
	groups := make(map[string][]Metric)
	for _, m := range metrics {
		key := baselineKey(m.Route, m.Method)
		groups[key] = append(groups[key], m)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for key, groupMetrics := range groups {
		baseline := d.calculateBaseline(groupMetrics)
		d.baselines[key] = baseline
	}
}

// calculateBaseline calculates baseline statistics.
func (d *Detector) calculateBaseline(metrics []Metric) *Baseline {
	if len(metrics) == 0 {
		return nil
	}

	// Calculate latency statistics
	latencies := make([]float64, 0, len(metrics))
	errorCount := 0

	for _, m := range metrics {
		latencies = append(latencies, float64(m.Latency.Milliseconds()))
		if m.StatusCode >= 500 {
			errorCount++
		}
	}

	mean := calculateMean(latencies)
	stdDev := calculateStdDev(latencies, mean)

	// Calculate time span
	if len(metrics) < 2 {
		return &Baseline{
			Route:         metrics[0].Route,
			Method:        metrics[0].Method,
			LatencyMean:   mean,
			LatencyStdDev: stdDev,
			Samples:       len(metrics),
			LastUpdated:   time.Now(),
		}
	}

	// Sort by timestamp
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Timestamp.Before(metrics[j].Timestamp)
	})

	timeSpan := metrics[len(metrics)-1].Timestamp.Sub(metrics[0].Timestamp)
	requestsPerMin := float64(len(metrics)) / timeSpan.Minutes()

	return &Baseline{
		Route:          metrics[0].Route,
		Method:         metrics[0].Method,
		LatencyMean:    mean,
		LatencyStdDev:  stdDev,
		ErrorRate:      float64(errorCount) / float64(len(metrics)),
		RequestsPerMin: requestsPerMin,
		Samples:        len(metrics),
		LastUpdated:    time.Now(),
	}
}

// GetBaseline returns the baseline for a route.
func (d *Detector) GetBaseline(route, method string) *Baseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.baselines[baselineKey(route, method)]
}

// GetAllBaselines returns all baselines.
func (d *Detector) GetAllBaselines() map[string]*Baseline {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]*Baseline)
	for k, v := range d.baselines {
		result[k] = v
	}
	return result
}

// Stats returns detector statistics.
func (d *Detector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"metric_count":   d.metrics.Count(),
		"baseline_count": len(d.baselines),
		"alert_count":    len(d.alerts),
	}
}

// APIHandler returns an HTTP handler for the anomaly detection API.
func (d *Detector) APIHandler() http.Handler {
	mux := http.NewServeMux()

	// Get alerts
	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		alerts := d.GetAlerts(100)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alerts)
	})

	// Get baselines
	mux.HandleFunc("/baselines", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		baselines := d.GetAllBaselines()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(baselines)
	})

	// Get stats
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		stats := d.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	// SSE for real-time alerts
	mux.HandleFunc("/alerts/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ctx := r.Context()
		alertChan := d.AlertChannel()

		for {
			select {
			case <-ctx.Done():
				return
			case alert := <-alertChan:
				data, _ := json.Marshal(alert)
				w.Write([]byte("data: "))
				w.Write(data)
				w.Write([]byte("\n\n"))
				flusher.Flush()
			}
		}
	})

	return mux
}

// Helper functions

func baselineKey(route, method string) string {
	return route + ":" + method
}

func generateID() string {
	return time.Now().Format("20060102150405.000000")
}

func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculateStdDev(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	return math.Sqrt(sumSquares / float64(len(values)-1))
}

func calculateSeverity(zScore, threshold float64) Severity {
	ratio := zScore / threshold
	if ratio > 3 {
		return SeverityCritical
	}
	if ratio > 2 {
		return SeverityHigh
	}
	if ratio > 1.5 {
		return SeverityMedium
	}
	return SeverityLow
}

func calculateErrorSeverity(errorRate float64) Severity {
	if errorRate > 0.5 {
		return SeverityCritical
	}
	if errorRate > 0.2 {
		return SeverityHigh
	}
	if errorRate > 0.1 {
		return SeverityMedium
	}
	return SeverityLow
}

// Close shuts down the detector.
func (d *Detector) Close() error {
	close(d.alertChan)
	return nil
}
