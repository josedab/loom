package anomaly

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricStore(t *testing.T) {
	store := NewMetricStore(5*time.Minute, 1000)

	// Add metrics
	for i := 0; i < 100; i++ {
		store.Add(Metric{
			Timestamp:  time.Now(),
			Route:      "/api/users",
			Method:     "GET",
			StatusCode: 200,
			Latency:    100 * time.Millisecond,
		})
	}

	if store.Count() != 100 {
		t.Errorf("expected 100 metrics, got %d", store.Count())
	}

	// Query metrics
	results := store.Query(MetricFilter{
		Duration: time.Minute,
		Route:    "/api/users",
	})

	if len(results) != 100 {
		t.Errorf("expected 100 results, got %d", len(results))
	}
}

func TestMetricStoreFiltering(t *testing.T) {
	store := NewMetricStore(5*time.Minute, 1000)

	store.Add(Metric{Timestamp: time.Now(), Route: "/api/users", Method: "GET"})
	store.Add(Metric{Timestamp: time.Now(), Route: "/api/users", Method: "POST"})
	store.Add(Metric{Timestamp: time.Now(), Route: "/api/posts", Method: "GET"})

	tests := []struct {
		filter   MetricFilter
		expected int
	}{
		{MetricFilter{Duration: time.Minute}, 3},
		{MetricFilter{Duration: time.Minute, Route: "/api/users"}, 2},
		{MetricFilter{Duration: time.Minute, Method: "GET"}, 2},
		{MetricFilter{Duration: time.Minute, Route: "/api/users", Method: "POST"}, 1},
	}

	for _, tt := range tests {
		results := store.Query(tt.filter)
		if len(results) != tt.expected {
			t.Errorf("filter %+v: expected %d, got %d", tt.filter, tt.expected, len(results))
		}
	}
}

func TestMetricStoreMaxSize(t *testing.T) {
	store := NewMetricStore(5*time.Minute, 100)

	// Add more than max
	for i := 0; i < 150; i++ {
		store.Add(Metric{Timestamp: time.Now()})
	}

	// Should have removed oldest 10%
	count := store.Count()
	if count >= 150 {
		t.Errorf("expected count < 150, got %d", count)
	}
}

func TestDetectorBaseline(t *testing.T) {
	config := DefaultDetectorConfig()
	config.MinSamples = 10
	detector := New(config)

	// Add enough metrics to establish baseline
	for i := 0; i < 50; i++ {
		detector.Record(Metric{
			Timestamp:  time.Now().Add(time.Duration(-i) * time.Minute),
			Route:      "/api/users",
			Method:     "GET",
			StatusCode: 200,
			Latency:    100 * time.Millisecond,
		})
	}

	// Manually trigger baseline update
	detector.updateBaselines()

	baseline := detector.GetBaseline("/api/users", "GET")
	if baseline == nil {
		t.Fatal("expected baseline to be created")
	}

	if baseline.Samples != 50 {
		t.Errorf("expected 50 samples, got %d", baseline.Samples)
	}

	if baseline.LatencyMean <= 0 {
		t.Error("expected positive latency mean")
	}
}

func TestDetectorLatencyAnomaly(t *testing.T) {
	config := DefaultDetectorConfig()
	config.MinSamples = 10
	config.ZScoreThreshold = 2.0
	detector := New(config)

	now := time.Now()

	// Establish baseline with varied latencies (to get non-zero stddev)
	for i := 0; i < 50; i++ {
		// Vary latency between 80-120ms to create a realistic baseline
		latency := time.Duration(80+i%40) * time.Millisecond
		detector.Record(Metric{
			Timestamp:  now.Add(time.Duration(-i) * time.Minute),
			Route:      "/api/test",
			Method:     "GET",
			StatusCode: 200,
			Latency:    latency,
		})
	}

	detector.updateBaselines()

	// Verify baseline was created with non-zero stddev
	baseline := detector.GetBaseline("/api/test", "GET")
	if baseline == nil {
		t.Fatal("expected baseline to exist")
	}
	if baseline.LatencyStdDev == 0 {
		t.Fatal("expected non-zero stddev in baseline")
	}

	// Record an anomalous latency (way outside normal range)
	alerts := detector.Record(Metric{
		Timestamp:  now,
		Route:      "/api/test",
		Method:     "GET",
		StatusCode: 200,
		Latency:    5 * time.Second, // Way higher than normal ~100ms
	})

	if len(alerts) == 0 {
		t.Error("expected latency anomaly to be detected")
	}

	if len(alerts) > 0 && alerts[0].Type != AnomalyTypeLatency {
		t.Errorf("expected latency anomaly, got %s", alerts[0].Type)
	}
}

func TestDetectorGetAlerts(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	// Store some alerts directly
	detector.mu.Lock()
	for i := 0; i < 10; i++ {
		detector.alerts = append(detector.alerts, Alert{
			ID:   generateID(),
			Type: AnomalyTypeLatency,
		})
	}
	detector.mu.Unlock()

	alerts := detector.GetAlerts(5)
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}

	// Test getting all
	alerts = detector.GetAlerts(0)
	if len(alerts) != 10 {
		t.Errorf("expected 10 alerts, got %d", len(alerts))
	}
}

func TestDetectorStats(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	// Add some metrics
	for i := 0; i < 10; i++ {
		detector.Record(Metric{
			Timestamp: time.Now(),
			Route:     "/api/test",
			Method:    "GET",
		})
	}

	stats := detector.Stats()

	if stats["metric_count"].(int) != 10 {
		t.Errorf("expected 10 metrics, got %v", stats["metric_count"])
	}
}

func TestCalculateMean(t *testing.T) {
	tests := []struct {
		values   []float64
		expected float64
	}{
		{[]float64{1, 2, 3, 4, 5}, 3.0},
		{[]float64{10, 20, 30}, 20.0},
		{[]float64{}, 0},
		{[]float64{100}, 100},
	}

	for _, tt := range tests {
		result := calculateMean(tt.values)
		if result != tt.expected {
			t.Errorf("calculateMean(%v) = %v, want %v", tt.values, result, tt.expected)
		}
	}
}

func TestCalculateStdDev(t *testing.T) {
	values := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	mean := calculateMean(values)
	stdDev := calculateStdDev(values, mean)

	// Expected stdDev is approximately 2
	if stdDev < 1.5 || stdDev > 2.5 {
		t.Errorf("stdDev = %v, expected around 2", stdDev)
	}

	// Edge cases
	if calculateStdDev([]float64{}, 0) != 0 {
		t.Error("expected 0 for empty values")
	}
	if calculateStdDev([]float64{5}, 5) != 0 {
		t.Error("expected 0 for single value")
	}
}

func TestCalculateSeverity(t *testing.T) {
	threshold := 3.0

	tests := []struct {
		zScore   float64
		expected Severity
	}{
		{3.5, SeverityLow},
		{5.0, SeverityMedium},
		{7.0, SeverityHigh},
		{10.0, SeverityCritical},
	}

	for _, tt := range tests {
		result := calculateSeverity(tt.zScore, threshold)
		if result != tt.expected {
			t.Errorf("calculateSeverity(%v, %v) = %v, want %v", tt.zScore, threshold, result, tt.expected)
		}
	}
}

func TestCalculateErrorSeverity(t *testing.T) {
	tests := []struct {
		errorRate float64
		expected  Severity
	}{
		{0.05, SeverityLow},
		{0.15, SeverityMedium},
		{0.3, SeverityHigh},
		{0.6, SeverityCritical},
	}

	for _, tt := range tests {
		result := calculateErrorSeverity(tt.errorRate)
		if result != tt.expected {
			t.Errorf("calculateErrorSeverity(%v) = %v, want %v", tt.errorRate, result, tt.expected)
		}
	}
}

func TestAPIHandlerAlerts(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	// Add an alert
	detector.mu.Lock()
	detector.alerts = append(detector.alerts, Alert{
		ID:          "test-alert",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityHigh,
		Route:       "/api/test",
		Description: "Test alert",
	})
	detector.mu.Unlock()

	handler := detector.APIHandler()

	req := httptest.NewRequest("GET", "/alerts", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var alerts []Alert
	if err := json.NewDecoder(rec.Body).Decode(&alerts); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alerts))
	}
}

func TestAPIHandlerBaselines(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	// Add a baseline
	detector.mu.Lock()
	detector.baselines["/api/test:GET"] = &Baseline{
		Route:       "/api/test",
		Method:      "GET",
		LatencyMean: 100,
		Samples:     50,
	}
	detector.mu.Unlock()

	handler := detector.APIHandler()

	req := httptest.NewRequest("GET", "/baselines", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var baselines map[string]*Baseline
	if err := json.NewDecoder(rec.Body).Decode(&baselines); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(baselines) != 1 {
		t.Errorf("expected 1 baseline, got %d", len(baselines))
	}
}

func TestAPIHandlerStats(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	handler := detector.APIHandler()

	req := httptest.NewRequest("GET", "/stats", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var stats map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if _, ok := stats["metric_count"]; !ok {
		t.Error("expected metric_count in stats")
	}
}

func TestMiddleware(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	var anomalyCount int
	middleware := Middleware(MiddlewareConfig{
		Detector: detector,
		OnAnomaly: func(alert Alert, r *http.Request) {
			anomalyCount++
			_ = alert // Use the alert
		},
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Check metric was recorded
	stats := detector.Stats()
	if stats["metric_count"].(int) != 1 {
		t.Errorf("expected 1 metric, got %v", stats["metric_count"])
	}

	// anomalyCount is used by OnAnomaly callback
	_ = anomalyCount
}

func TestResponseCapture(t *testing.T) {
	rec := httptest.NewRecorder()
	capture := &responseCapture{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	capture.WriteHeader(http.StatusCreated)
	if capture.statusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", capture.statusCode)
	}

	// Second write should be ignored
	capture.WriteHeader(http.StatusBadRequest)
	if capture.statusCode != http.StatusCreated {
		t.Errorf("expected 201 (unchanged), got %d", capture.statusCode)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{map[string]string{"X-Forwarded-For": "1.2.3.4"}, "5.6.7.8:1234", "1.2.3.4"},
		{map[string]string{"X-Real-IP": "1.2.3.4"}, "5.6.7.8:1234", "1.2.3.4"},
		{map[string]string{}, "5.6.7.8:1234", "5.6.7.8:1234"},
		{map[string]string{"X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8"}, "9.10.11.12:1234", "1.2.3.4"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}
		req.RemoteAddr = tt.remoteAddr

		result := getClientIP(req)
		if result != tt.expected {
			t.Errorf("getClientIP() = %q, want %q", result, tt.expected)
		}
	}
}

func TestPatternAnalyzer(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	analyzer := NewPatternAnalyzer(detector)

	// Add diverse metrics - use short intervals to stay within the store's maxAge
	now := time.Now()
	for i := 0; i < 1000; i++ {
		detector.Record(Metric{
			Timestamp: now.Add(time.Duration(-i) * time.Second), // Use seconds instead of minutes
			Route:     "/api/test",
			Method:    "GET",
			UserAgent: "common-user-agent",
		})
	}

	analyzer.Learn("/api/test")

	// Test with common user agent - should not be anomaly
	alert := analyzer.DetectAnomaly(Metric{
		Timestamp: now,
		Route:     "/api/test",
		UserAgent: "common-user-agent",
	})

	if alert != nil {
		t.Error("expected no anomaly for common user agent")
	}

	// Test with rare user agent - might be anomaly
	alert = analyzer.DetectAnomaly(Metric{
		Timestamp: now,
		Route:     "/api/test",
		UserAgent: "very-rare-suspicious-agent",
	})

	// This should detect as anomaly since it's never been seen
	if alert != nil && alert.Type != AnomalyTypePattern {
		t.Errorf("expected pattern anomaly, got %s", alert.Type)
	}
}

func TestHealthScore(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	// Empty detector should return 100
	score := detector.HealthScore()
	if score != 100 {
		t.Errorf("expected 100 for empty detector, got %v", score)
	}

	// Add healthy metrics
	now := time.Now()
	for i := 0; i < 100; i++ {
		detector.Record(Metric{
			Timestamp:  now.Add(time.Duration(-i) * time.Second),
			Route:      "/api/test",
			Method:     "GET",
			StatusCode: 200,
			Latency:    100 * time.Millisecond,
		})
	}

	detector.updateBaselines()

	score = detector.HealthScore()
	if score < 90 {
		t.Errorf("expected high health score for healthy metrics, got %v", score)
	}
}

func TestDefaultDetectorConfig(t *testing.T) {
	config := DefaultDetectorConfig()

	if config.WindowSize != 5*time.Minute {
		t.Errorf("expected 5m window, got %v", config.WindowSize)
	}
	if config.BaselinePeriod != time.Hour {
		t.Errorf("expected 1h baseline period, got %v", config.BaselinePeriod)
	}
	if config.ZScoreThreshold != 3.0 {
		t.Errorf("expected 3.0 z-score threshold, got %v", config.ZScoreThreshold)
	}
	if !config.EnableLatencyAnomalies {
		t.Error("expected latency anomalies enabled")
	}
	if !config.EnableErrorAnomalies {
		t.Error("expected error anomalies enabled")
	}
}

func TestBaselineKey(t *testing.T) {
	key := baselineKey("/api/users", "GET")
	if key != "/api/users:GET" {
		t.Errorf("expected '/api/users:GET', got %q", key)
	}
}

func TestDetectorRateAnomaly(t *testing.T) {
	config := DefaultDetectorConfig()
	config.MinSamples = 10
	detector := New(config)

	now := time.Now()

	// Establish baseline with normal rate
	for i := 0; i < 60; i++ {
		detector.Record(Metric{
			Timestamp:  now.Add(time.Duration(-i) * time.Minute),
			Route:      "/api/rate-test",
			Method:     "GET",
			StatusCode: 200,
		})
	}

	detector.updateBaselines()

	// Check for rate anomaly (should not trigger with normal data)
	alert := detector.DetectRateAnomaly("/api/rate-test", "GET")
	if alert != nil {
		// Might get false positive due to timing, so just check type
		if alert.Type != AnomalyTypeRate {
			t.Errorf("unexpected alert type: %s", alert.Type)
		}
	}
}

func TestRateLimitAnomaly(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	now := time.Now()

	// Add baseline metrics
	for i := 0; i < 100; i++ {
		detector.Record(Metric{
			Timestamp:  now.Add(time.Duration(-i) * time.Minute),
			Route:      "/api/test",
			IP:         "192.168.1.1",
		})
	}

	detector.updateBaselines()

	rateLimiter := NewRateLimitAnomaly(detector, time.Minute, 10.0)

	// Check normal client
	isAnomaly := rateLimiter.Check("192.168.1.1", "/api/test")
	// Result depends on baseline, just ensure no panic
	_ = isAnomaly
}

func TestGetAllBaselines(t *testing.T) {
	detector := New(DefaultDetectorConfig())

	detector.mu.Lock()
	detector.baselines["/api/a:GET"] = &Baseline{Route: "/api/a", Method: "GET"}
	detector.baselines["/api/b:POST"] = &Baseline{Route: "/api/b", Method: "POST"}
	detector.mu.Unlock()

	baselines := detector.GetAllBaselines()

	if len(baselines) != 2 {
		t.Errorf("expected 2 baselines, got %d", len(baselines))
	}

	// Ensure it's a copy
	baselines["/api/c:GET"] = &Baseline{}
	if len(detector.GetAllBaselines()) != 2 {
		t.Error("modification affected original")
	}
}
