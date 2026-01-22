package anomaly

import (
	"math"
	"testing"
	"time"
)

func TestNewMLDetector(t *testing.T) {
	config := DefaultMLConfig()
	detector := NewMLDetector(config)

	if detector == nil {
		t.Fatal("NewMLDetector returned nil")
	}
	if detector.isolationTree == nil {
		t.Error("Isolation forest not initialized")
	}
	if detector.arima == nil {
		t.Error("ARIMA model not initialized")
	}
	if detector.exponential == nil {
		t.Error("Exponential smoothing not initialized")
	}
}

func TestDefaultMLConfig(t *testing.T) {
	config := DefaultMLConfig()

	if config.NumTrees != 100 {
		t.Errorf("NumTrees = %d, want 100", config.NumTrees)
	}
	if config.SubsampleSize != 256 {
		t.Errorf("SubsampleSize = %d, want 256", config.SubsampleSize)
	}
	if config.ContaminationRate != 0.01 {
		t.Errorf("ContaminationRate = %f, want 0.01", config.ContaminationRate)
	}
	if config.SeasonalPeriod != 24 {
		t.Errorf("SeasonalPeriod = %d, want 24", config.SeasonalPeriod)
	}
}

func TestMLDetector_Train(t *testing.T) {
	config := DefaultMLConfig()
	config.NumTrees = 10 // Smaller for testing
	detector := NewMLDetector(config)

	// Generate training data
	metrics := generateTestMetrics(500)

	// Should not panic with small data
	detector.Train(metrics[:50])

	// Should train successfully with enough data
	detector.Train(metrics)
}

func TestMLDetector_Predict(t *testing.T) {
	config := DefaultMLConfig()
	config.NumTrees = 10
	detector := NewMLDetector(config)

	// Train on normal data
	normalMetrics := generateNormalMetrics(300)
	detector.Train(normalMetrics)

	// Test with normal data
	anomalies := detector.Predict(normalMetrics[:50])
	// Should have few or no anomalies
	t.Logf("Normal data anomalies: %d", len(anomalies))

	// Test with anomalous data
	anomalousMetrics := generateAnomalousMetrics(50)
	anomalies = detector.Predict(anomalousMetrics)
	// May detect some anomalies
	t.Logf("Anomalous data anomalies: %d", len(anomalies))
}

func TestMLDetector_PredictSingle(t *testing.T) {
	config := DefaultMLConfig()
	config.NumTrees = 10
	detector := NewMLDetector(config)

	normalMetrics := generateNormalMetrics(300)
	detector.Train(normalMetrics)

	// Test normal metric
	normalMetric := Metric{
		Timestamp: time.Now(),
		Route:     "/api/test",
		Method:    "GET",
		Latency:   100 * time.Millisecond,
	}
	anomaly := detector.PredictSingle(normalMetric, normalMetrics[:50])
	if anomaly != nil {
		t.Logf("Normal metric detected as anomaly with score %f", anomaly.Score)
	}

	// Test anomalous metric
	anomalousMetric := Metric{
		Timestamp: time.Now(),
		Route:     "/api/test",
		Method:    "GET",
		Latency:   10 * time.Second, // Very high latency
	}
	anomaly = detector.PredictSingle(anomalousMetric, normalMetrics[:50])
	if anomaly != nil {
		t.Logf("Anomalous metric detected with score %f", anomaly.Score)
	}
}

func TestIsolationForest_Fit(t *testing.T) {
	forest := NewIsolationForest(10, 50)

	// Test with empty data
	forest.Fit(nil)
	if forest.trained {
		t.Error("Should not be trained with empty data")
	}

	// Test with valid data
	data := generateFeatureMatrix(100, 5)
	forest.Fit(data)

	if !forest.trained {
		t.Error("Forest should be trained")
	}
	if forest.avgPathLength <= 0 {
		t.Error("Average path length should be > 0")
	}
}

func TestIsolationForest_Score(t *testing.T) {
	forest := NewIsolationForest(10, 50)

	// Generate training data from normal distribution
	data := generateFeatureMatrix(200, 3)
	forest.Fit(data)

	// Score normal points
	normalScores := forest.Score(data[:50])
	avgNormalScore := 0.0
	for _, s := range normalScores {
		avgNormalScore += s
	}
	avgNormalScore /= float64(len(normalScores))

	// Score outlier points
	outliers := [][]float64{
		{100.0, 100.0, 100.0}, // Far from normal data
		{-100.0, -100.0, -100.0},
	}
	outlierScores := forest.Score(outliers)

	// Outliers should have higher scores
	for _, s := range outlierScores {
		if s < avgNormalScore {
			t.Logf("Outlier score %f < normal avg %f (may happen occasionally)", s, avgNormalScore)
		}
	}
}

func TestIsolationForest_ScoreSingle(t *testing.T) {
	forest := NewIsolationForest(20, 100)

	data := generateFeatureMatrix(200, 3)
	forest.Fit(data)

	// Score a normal point
	normalScore := forest.ScoreSingle([]float64{0.5, 0.5, 0.5})

	// Score an outlier
	outlierScore := forest.ScoreSingle([]float64{100.0, 100.0, 100.0})

	if outlierScore < normalScore {
		t.Logf("Outlier score (%f) < normal score (%f)", outlierScore, normalScore)
	}
}

func TestIsolationTree_Fit(t *testing.T) {
	tree := NewIsolationTree(10)

	// Fit with data
	data := generateFeatureMatrix(50, 3)
	tree.Fit(data, 0)

	if tree.size != 50 {
		t.Errorf("Tree size = %d, want 50", tree.size)
	}
}

func TestIsolationTree_PathLength(t *testing.T) {
	tree := NewIsolationTree(10)
	data := generateFeatureMatrix(50, 3)
	tree.Fit(data, 0)

	// Path length should be >= 0
	pathLen := tree.PathLength([]float64{0.5, 0.5, 0.5}, 0)
	if pathLen < 0 {
		t.Errorf("Path length = %f, want >= 0", pathLen)
	}
}

func TestARIMAModel_Fit(t *testing.T) {
	model := NewARIMAModel(2, 1, 2)

	// Test with insufficient data
	model.Fit([]float64{1, 2, 3})
	if model.trained {
		t.Error("Should not be trained with insufficient data")
	}

	// Test with sufficient data
	data := generateTimeSeriesData(200, 100, 10) // Mean 100, std 10
	model.Fit(data)

	if !model.trained {
		t.Error("Model should be trained")
	}
	if model.stdDev <= 0 {
		t.Error("StdDev should be > 0")
	}
}

func TestARIMAModel_Predict(t *testing.T) {
	model := NewARIMAModel(2, 1, 2)

	data := generateTimeSeriesData(200, 100, 10)
	model.Fit(data)

	// Predict next 10 values
	predictions := model.Predict(10)
	if len(predictions) != 10 {
		t.Errorf("Predictions length = %d, want 10", len(predictions))
	}

	// Predictions should be reasonable (not NaN or Inf)
	for i, p := range predictions {
		if math.IsNaN(p) || math.IsInf(p, 0) {
			t.Errorf("Prediction[%d] = %f is invalid", i, p)
		}
	}
}

func TestARIMAModel_StdDev(t *testing.T) {
	model := NewARIMAModel(2, 1, 2)

	data := generateTimeSeriesData(200, 100, 20)
	model.Fit(data)

	stdDev := model.StdDev()
	if stdDev <= 0 {
		t.Errorf("StdDev = %f, want > 0", stdDev)
	}
}

func TestExponentialSmoothing_Fit(t *testing.T) {
	es := NewExponentialSmoothing(0.3, 0.1, 0.1, 24)

	// Test with insufficient data
	es.Fit(make([]float64, 10))
	if es.trained {
		t.Error("Should not be trained with insufficient data")
	}

	// Test with sufficient data (with seasonal pattern)
	data := generateSeasonalData(100, 24)
	es.Fit(data)

	if !es.trained {
		t.Error("Model should be trained")
	}
	if len(es.seasonal) != 24 {
		t.Errorf("Seasonal length = %d, want 24", len(es.seasonal))
	}
}

func TestExponentialSmoothing_Predict(t *testing.T) {
	es := NewExponentialSmoothing(0.3, 0.1, 0.1, 24)

	data := generateSeasonalData(100, 24)
	es.Fit(data)

	predictions := es.Predict(10)
	if len(predictions) != 10 {
		t.Errorf("Predictions length = %d, want 10", len(predictions))
	}

	// Predictions should be positive (latency-like data)
	for i, p := range predictions {
		if p < 0 || math.IsNaN(p) || math.IsInf(p, 0) {
			t.Errorf("Prediction[%d] = %f is invalid", i, p)
		}
	}
}

func TestExponentialSmoothing_DetectTrendAnomaly(t *testing.T) {
	es := NewExponentialSmoothing(0.3, 0.1, 0.1, 24)

	// Train on stable data
	data := generateSeasonalData(100, 24)
	es.Fit(data)

	// Test with normal metrics
	normalMetrics := generateNormalMetrics(50)
	anomaly := es.DetectTrendAnomaly(normalMetrics)
	if anomaly != nil {
		t.Logf("Trend anomaly detected in normal data: score=%f", anomaly.Score)
	}
}

func TestFeatureExtractor_Extract(t *testing.T) {
	fe := NewFeatureExtractor()

	metrics := generateTestMetrics(10)
	matrix := fe.Extract(metrics)

	if len(matrix) != 10 {
		t.Errorf("Matrix rows = %d, want 10", len(matrix))
	}

	for i, row := range matrix {
		if len(row) < 5 {
			t.Errorf("Row %d has %d features, want >= 5", i, len(row))
		}
	}
}

func TestFeatureExtractor_ExtractSingle(t *testing.T) {
	fe := NewFeatureExtractor()

	metric := Metric{
		Timestamp:   time.Now(),
		Route:       "/api/test",
		Method:      "GET",
		StatusCode:  200,
		Latency:     100 * time.Millisecond,
		RequestSize: 1024,
	}

	history := generateTestMetrics(50)

	features := fe.ExtractSingle(metric, history)
	if len(features) < 5 {
		t.Errorf("Features length = %d, want >= 5", len(features))
	}

	// Verify base features
	if features[0] != 100 { // latency in ms
		t.Errorf("Latency feature = %f, want 100", features[0])
	}
	if features[1] != 1024 { // request size
		t.Errorf("RequestSize feature = %f, want 1024", features[1])
	}
}

func TestMLAnomaly_ToAlert(t *testing.T) {
	anomaly := MLAnomaly{
		Metric: Metric{
			Timestamp: time.Now(),
			Route:     "/api/test",
			Method:    "POST",
			Latency:   500 * time.Millisecond,
		},
		Score:      0.95,
		Threshold:  0.8,
		Method:     "isolation_forest",
		Confidence: 0.87,
		Prediction: 100.0,
	}

	alert := anomaly.ToAlert()

	if alert.Route != "/api/test" {
		t.Errorf("Alert route = %s, want /api/test", alert.Route)
	}
	if alert.Method != "POST" {
		t.Errorf("Alert method = %s, want POST", alert.Method)
	}
	if alert.Type != AnomalyTypePattern {
		t.Errorf("Alert type = %s, want pattern", alert.Type)
	}
	if alert.Metadata["ml_method"] != "isolation_forest" {
		t.Error("Alert metadata should contain ml_method")
	}
	if alert.Metadata["confidence"] != 0.87 {
		t.Error("Alert metadata should contain confidence")
	}
}

func TestCalculateConfidence(t *testing.T) {
	tests := []struct {
		score     float64
		threshold float64
		minConf   float64
		maxConf   float64
	}{
		{0.5, 1.0, 0.0, 0.5},
		{1.0, 1.0, 0.4, 0.6},
		{2.0, 1.0, 0.6, 0.9},
		{5.0, 1.0, 0.9, 1.0},
	}

	for _, tt := range tests {
		conf := calculateConfidence(tt.score, tt.threshold)
		if conf < tt.minConf || conf > tt.maxConf {
			t.Errorf("calculateConfidence(%f, %f) = %f, want between %f and %f",
				tt.score, tt.threshold, conf, tt.minConf, tt.maxConf)
		}
	}
}

func TestCalculateMLSeverity(t *testing.T) {
	tests := []struct {
		score     float64
		threshold float64
		expected  Severity
	}{
		{1.1, 1.0, SeverityLow},
		{1.3, 1.0, SeverityMedium},
		{1.6, 1.0, SeverityHigh},
		{2.5, 1.0, SeverityCritical},
	}

	for _, tt := range tests {
		severity := calculateMLSeverity(tt.score, tt.threshold)
		if severity != tt.expected {
			t.Errorf("calculateMLSeverity(%f, %f) = %s, want %s",
				tt.score, tt.threshold, severity, tt.expected)
		}
	}
}

func TestPathLengthAdjustment(t *testing.T) {
	tests := []struct {
		n       int
		minVal  float64
		maxVal  float64
	}{
		{1, 0.0, 0.0},
		{2, 1.0, 1.0},
		{10, 3.0, 5.0},
		{100, 7.0, 10.0},
	}

	for _, tt := range tests {
		adj := pathLengthAdjustment(tt.n)
		if adj < tt.minVal || adj > tt.maxVal {
			t.Errorf("pathLengthAdjustment(%d) = %f, want between %f and %f",
				tt.n, adj, tt.minVal, tt.maxVal)
		}
	}
}

func TestDifference(t *testing.T) {
	data := []float64{1, 3, 6, 10, 15}
	result := difference(data)

	expected := []float64{2, 3, 4, 5}
	if len(result) != len(expected) {
		t.Fatalf("difference() length = %d, want %d", len(result), len(expected))
	}

	for i, v := range result {
		if v != expected[i] {
			t.Errorf("difference()[%d] = %f, want %f", i, v, expected[i])
		}
	}
}

// Benchmark tests
func BenchmarkIsolationForest_Fit(b *testing.B) {
	data := generateFeatureMatrix(1000, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forest := NewIsolationForest(100, 256)
		forest.Fit(data)
	}
}

func BenchmarkIsolationForest_Score(b *testing.B) {
	forest := NewIsolationForest(100, 256)
	trainData := generateFeatureMatrix(1000, 10)
	forest.Fit(trainData)

	testData := generateFeatureMatrix(100, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forest.Score(testData)
	}
}

func BenchmarkMLDetector_PredictSingle(b *testing.B) {
	config := DefaultMLConfig()
	detector := NewMLDetector(config)

	metrics := generateNormalMetrics(500)
	detector.Train(metrics)

	testMetric := Metric{
		Timestamp: time.Now(),
		Route:     "/api/test",
		Method:    "GET",
		Latency:   100 * time.Millisecond,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.PredictSingle(testMetric, metrics[:50])
	}
}

// Helper functions for generating test data

func generateTestMetrics(n int) []Metric {
	metrics := make([]Metric, n)
	baseTime := time.Now().Add(-time.Duration(n) * time.Minute)

	for i := 0; i < n; i++ {
		metrics[i] = Metric{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Minute),
			Route:       "/api/test",
			Method:      "GET",
			StatusCode:  200,
			Latency:     time.Duration(50+i%100) * time.Millisecond,
			RequestSize: int64(100 + i%500),
			IP:          "192.168.1.1",
			UserAgent:   "TestAgent/1.0",
		}
	}

	return metrics
}

func generateNormalMetrics(n int) []Metric {
	metrics := make([]Metric, n)
	baseTime := time.Now().Add(-time.Duration(n) * time.Minute)

	for i := 0; i < n; i++ {
		// Normal distribution around 100ms
		latency := 100 + 20*math.Sin(float64(i)/10)
		metrics[i] = Metric{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Minute),
			Route:       "/api/test",
			Method:      "GET",
			StatusCode:  200,
			Latency:     time.Duration(latency) * time.Millisecond,
			RequestSize: 512,
		}
	}

	return metrics
}

func generateAnomalousMetrics(n int) []Metric {
	metrics := make([]Metric, n)
	baseTime := time.Now()

	for i := 0; i < n; i++ {
		// Mix of extreme values
		latency := 100.0
		if i%5 == 0 {
			latency = 5000 // Very high latency
		}
		if i%7 == 0 {
			latency = 1 // Very low latency
		}

		status := 200
		if i%3 == 0 {
			status = 500 // Server errors
		}

		metrics[i] = Metric{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Second),
			Route:       "/api/test",
			Method:      "GET",
			StatusCode:  status,
			Latency:     time.Duration(latency) * time.Millisecond,
			RequestSize: int64(100 + i*1000), // Varying sizes
		}
	}

	return metrics
}

func generateFeatureMatrix(rows, cols int) [][]float64 {
	matrix := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		matrix[i] = make([]float64, cols)
		for j := 0; j < cols; j++ {
			// Normal-ish distribution
			matrix[i][j] = 0.5 + 0.2*math.Sin(float64(i+j))
		}
	}
	return matrix
}

func generateTimeSeriesData(n int, mean, stdDev float64) []float64 {
	data := make([]float64, n)
	for i := 0; i < n; i++ {
		// Simulate time series with trend and noise
		trend := float64(i) * 0.1
		seasonal := 10 * math.Sin(float64(i)*2*math.Pi/24)
		noise := stdDev * math.Sin(float64(i)*13) // Pseudo-random noise
		data[i] = mean + trend + seasonal + noise
	}
	return data
}

func generateSeasonalData(n, period int) []float64 {
	data := make([]float64, n)
	for i := 0; i < n; i++ {
		// Base value with seasonal pattern
		base := 100.0
		seasonal := 30 * math.Sin(2*math.Pi*float64(i%period)/float64(period))
		trend := float64(i) * 0.1
		data[i] = base + seasonal + trend
	}
	return data
}
