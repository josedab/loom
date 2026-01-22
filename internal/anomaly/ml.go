// Package anomaly provides API anomaly detection capabilities.
package anomaly

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// MLDetector provides machine learning-based anomaly detection.
type MLDetector struct {
	config        MLConfig
	isolationTree *IsolationForest
	arima         *ARIMAModel
	exponential   *ExponentialSmoothing
	features      *FeatureExtractor
	mu            sync.RWMutex
}

// MLConfig configures the ML detector.
type MLConfig struct {
	// IsolationForest settings
	NumTrees          int     // Number of trees (default: 100)
	SubsampleSize     int     // Subsample size for each tree (default: 256)
	ContaminationRate float64 // Expected anomaly rate (default: 0.01)

	// ARIMA settings
	AROrder int // Autoregressive order p (default: 2)
	IOrder  int // Differencing order d (default: 1)
	MAOrder int // Moving average order q (default: 2)

	// Exponential smoothing settings
	Alpha float64 // Level smoothing (default: 0.3)
	Beta  float64 // Trend smoothing (default: 0.1)
	Gamma float64 // Seasonal smoothing (default: 0.1)

	// Seasonality period (default: 24 for hourly data)
	SeasonalPeriod int
}

// DefaultMLConfig returns sensible defaults.
func DefaultMLConfig() MLConfig {
	return MLConfig{
		NumTrees:          100,
		SubsampleSize:     256,
		ContaminationRate: 0.01,
		AROrder:           2,
		IOrder:            1,
		MAOrder:           2,
		Alpha:             0.3,
		Beta:              0.1,
		Gamma:             0.1,
		SeasonalPeriod:    24,
	}
}

// NewMLDetector creates a new ML-based anomaly detector.
func NewMLDetector(config MLConfig) *MLDetector {
	if config.NumTrees == 0 {
		config.NumTrees = 100
	}
	if config.SubsampleSize == 0 {
		config.SubsampleSize = 256
	}
	if config.ContaminationRate == 0 {
		config.ContaminationRate = 0.01
	}
	if config.AROrder == 0 {
		config.AROrder = 2
	}
	if config.IOrder == 0 {
		config.IOrder = 1
	}
	if config.MAOrder == 0 {
		config.MAOrder = 2
	}
	if config.Alpha == 0 {
		config.Alpha = 0.3
	}
	if config.Beta == 0 {
		config.Beta = 0.1
	}
	if config.Gamma == 0 {
		config.Gamma = 0.1
	}
	if config.SeasonalPeriod == 0 {
		config.SeasonalPeriod = 24
	}

	return &MLDetector{
		config:        config,
		isolationTree: NewIsolationForest(config.NumTrees, config.SubsampleSize),
		arima:         NewARIMAModel(config.AROrder, config.IOrder, config.MAOrder),
		exponential:   NewExponentialSmoothing(config.Alpha, config.Beta, config.Gamma, config.SeasonalPeriod),
		features:      NewFeatureExtractor(),
	}
}

// Train trains the ML models on historical data.
func (ml *MLDetector) Train(metrics []Metric) {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	if len(metrics) < 100 {
		return // Not enough data
	}

	// Extract features for Isolation Forest
	featureMatrix := ml.features.Extract(metrics)
	ml.isolationTree.Fit(featureMatrix)

	// Train ARIMA on latency time series
	latencies := make([]float64, len(metrics))
	for i, m := range metrics {
		latencies[i] = float64(m.Latency.Milliseconds())
	}
	ml.arima.Fit(latencies)

	// Train exponential smoothing
	ml.exponential.Fit(latencies)
}

// Predict detects anomalies in new metrics.
func (ml *MLDetector) Predict(metrics []Metric) []MLAnomaly {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	var anomalies []MLAnomaly

	// Isolation Forest predictions
	featureMatrix := ml.features.Extract(metrics)
	scores := ml.isolationTree.Score(featureMatrix)

	threshold := ml.calculateThreshold(scores)

	for i, score := range scores {
		if score > threshold {
			anomalies = append(anomalies, MLAnomaly{
				Metric:     metrics[i],
				Score:      score,
				Threshold:  threshold,
				Method:     "isolation_forest",
				Confidence: calculateConfidence(score, threshold),
			})
		}
	}

	// ARIMA-based prediction anomalies
	if len(metrics) > 0 {
		latencies := make([]float64, len(metrics))
		for i, m := range metrics {
			latencies[i] = float64(m.Latency.Milliseconds())
		}

		predictions := ml.arima.Predict(len(latencies))
		for i, pred := range predictions {
			if i >= len(latencies) {
				break
			}
			residual := math.Abs(latencies[i] - pred)
			stdDev := ml.arima.StdDev()
			if stdDev > 0 && residual > 3*stdDev {
				anomalies = append(anomalies, MLAnomaly{
					Metric:     metrics[i],
					Score:      residual / stdDev,
					Threshold:  3.0,
					Method:     "arima",
					Confidence: calculateConfidence(residual/stdDev, 3.0),
					Prediction: pred,
				})
			}
		}
	}

	// Exponential smoothing trend anomalies
	if len(metrics) > ml.config.SeasonalPeriod {
		trendAnomaly := ml.exponential.DetectTrendAnomaly(metrics)
		if trendAnomaly != nil {
			anomalies = append(anomalies, *trendAnomaly)
		}
	}

	return anomalies
}

// PredictSingle detects if a single metric is anomalous.
func (ml *MLDetector) PredictSingle(m Metric, history []Metric) *MLAnomaly {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	// Extract features for single metric
	features := ml.features.ExtractSingle(m, history)
	score := ml.isolationTree.ScoreSingle(features)

	// Use contamination rate to determine threshold
	threshold := 1.0 - ml.config.ContaminationRate

	if score > threshold {
		return &MLAnomaly{
			Metric:     m,
			Score:      score,
			Threshold:  threshold,
			Method:     "isolation_forest",
			Confidence: calculateConfidence(score, threshold),
		}
	}

	return nil
}

// calculateThreshold calculates anomaly threshold based on contamination rate.
func (ml *MLDetector) calculateThreshold(scores []float64) float64 {
	if len(scores) == 0 {
		return 0.5
	}

	sorted := make([]float64, len(scores))
	copy(sorted, scores)
	sort.Float64s(sorted)

	// Threshold at (1 - contamination) percentile
	idx := int(float64(len(sorted)) * (1.0 - ml.config.ContaminationRate))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	return sorted[idx]
}

// MLAnomaly represents an ML-detected anomaly.
type MLAnomaly struct {
	Metric     Metric
	Score      float64
	Threshold  float64
	Method     string
	Confidence float64
	Prediction float64 // For ARIMA predictions
}

// ToAlert converts an MLAnomaly to a standard Alert.
func (a *MLAnomaly) ToAlert() Alert {
	return Alert{
		ID:          generateID(),
		Type:        AnomalyTypePattern,
		Severity:    calculateMLSeverity(a.Score, a.Threshold),
		Route:       a.Metric.Route,
		Method:      a.Metric.Method,
		Description: "ML-detected anomaly (" + a.Method + ")",
		Value:       float64(a.Metric.Latency.Milliseconds()),
		Expected:    a.Prediction,
		Deviation:   a.Score,
		Timestamp:   a.Metric.Timestamp,
		Metadata: map[string]interface{}{
			"ml_method":   a.Method,
			"confidence":  a.Confidence,
			"threshold":   a.Threshold,
			"anomaly_score": a.Score,
		},
	}
}

// calculateConfidence calculates detection confidence.
func calculateConfidence(score, threshold float64) float64 {
	if threshold == 0 {
		return 0
	}
	ratio := score / threshold
	confidence := 1.0 - 1.0/(1.0+math.Exp(ratio-1))
	return math.Min(confidence, 1.0)
}

// calculateMLSeverity calculates severity from ML score.
func calculateMLSeverity(score, threshold float64) Severity {
	ratio := score / threshold
	if ratio > 2.0 {
		return SeverityCritical
	}
	if ratio > 1.5 {
		return SeverityHigh
	}
	if ratio > 1.2 {
		return SeverityMedium
	}
	return SeverityLow
}

// IsolationForest implements the Isolation Forest algorithm for anomaly detection.
type IsolationForest struct {
	numTrees      int
	subsampleSize int
	trees         []*IsolationTree
	avgPathLength float64
	trained       bool
	mu            sync.RWMutex
}

// NewIsolationForest creates a new Isolation Forest.
func NewIsolationForest(numTrees, subsampleSize int) *IsolationForest {
	return &IsolationForest{
		numTrees:      numTrees,
		subsampleSize: subsampleSize,
		trees:         make([]*IsolationTree, numTrees),
	}
}

// Fit trains the Isolation Forest on a feature matrix.
func (f *IsolationForest) Fit(data [][]float64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(data) == 0 {
		return
	}

	// Calculate average path length for normalization
	n := float64(len(data))
	if n > 2 {
		f.avgPathLength = 2.0*(math.Log(n-1.0)+0.5772156649) - 2.0*(n-1.0)/n
	} else if n == 2 {
		f.avgPathLength = 1.0
	} else {
		f.avgPathLength = 0
	}

	maxHeight := int(math.Ceil(math.Log2(float64(f.subsampleSize))))

	// Build trees in parallel
	var wg sync.WaitGroup
	for i := 0; i < f.numTrees; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Random subsample
			sample := f.subsample(data)
			tree := NewIsolationTree(maxHeight)
			tree.Fit(sample, 0)
			f.trees[idx] = tree
		}(i)
	}
	wg.Wait()

	f.trained = true
}

// subsample creates a random subsample of the data.
func (f *IsolationForest) subsample(data [][]float64) [][]float64 {
	n := len(data)
	size := f.subsampleSize
	if size > n {
		size = n
	}

	// Fisher-Yates shuffle for first 'size' elements
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < size; i++ {
		j := i + r.Intn(n-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	sample := make([][]float64, size)
	for i := 0; i < size; i++ {
		sample[i] = data[indices[i]]
	}

	return sample
}

// Score returns anomaly scores for each sample.
func (f *IsolationForest) Score(data [][]float64) []float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.trained || len(data) == 0 {
		return make([]float64, len(data))
	}

	scores := make([]float64, len(data))
	for i, sample := range data {
		scores[i] = f.scoreSingle(sample)
	}

	return scores
}

// ScoreSingle returns anomaly score for a single sample.
func (f *IsolationForest) ScoreSingle(sample []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.trained {
		return 0
	}

	return f.scoreSingle(sample)
}

func (f *IsolationForest) scoreSingle(sample []float64) float64 {
	if f.avgPathLength == 0 {
		return 0.5
	}

	totalPath := 0.0
	for _, tree := range f.trees {
		if tree != nil {
			totalPath += tree.PathLength(sample, 0)
		}
	}

	avgPath := totalPath / float64(f.numTrees)
	// Anomaly score: s(x, n) = 2^(-E(h(x))/c(n))
	return math.Pow(2, -avgPath/f.avgPathLength)
}

// IsolationTree is a single tree in the Isolation Forest.
type IsolationTree struct {
	maxHeight    int
	splitFeature int
	splitValue   float64
	left         *IsolationTree
	right        *IsolationTree
	size         int
	isLeaf       bool
}

// NewIsolationTree creates a new isolation tree.
func NewIsolationTree(maxHeight int) *IsolationTree {
	return &IsolationTree{
		maxHeight: maxHeight,
	}
}

// Fit builds the isolation tree recursively.
func (t *IsolationTree) Fit(data [][]float64, depth int) {
	t.size = len(data)

	if len(data) <= 1 || depth >= t.maxHeight {
		t.isLeaf = true
		return
	}

	numFeatures := len(data[0])
	if numFeatures == 0 {
		t.isLeaf = true
		return
	}

	// Random feature selection
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	t.splitFeature = r.Intn(numFeatures)

	// Find min/max for the feature
	minVal, maxVal := data[0][t.splitFeature], data[0][t.splitFeature]
	for _, row := range data[1:] {
		if row[t.splitFeature] < minVal {
			minVal = row[t.splitFeature]
		}
		if row[t.splitFeature] > maxVal {
			maxVal = row[t.splitFeature]
		}
	}

	if minVal == maxVal {
		t.isLeaf = true
		return
	}

	// Random split value
	t.splitValue = minVal + r.Float64()*(maxVal-minVal)

	// Partition data
	var leftData, rightData [][]float64
	for _, row := range data {
		if row[t.splitFeature] < t.splitValue {
			leftData = append(leftData, row)
		} else {
			rightData = append(rightData, row)
		}
	}

	if len(leftData) == 0 || len(rightData) == 0 {
		t.isLeaf = true
		return
	}

	t.left = NewIsolationTree(t.maxHeight)
	t.right = NewIsolationTree(t.maxHeight)
	t.left.Fit(leftData, depth+1)
	t.right.Fit(rightData, depth+1)
}

// PathLength returns the path length for a sample.
func (t *IsolationTree) PathLength(sample []float64, depth int) float64 {
	if t.isLeaf {
		// Adjustment for unbuilt branches
		return float64(depth) + pathLengthAdjustment(t.size)
	}

	if len(sample) <= t.splitFeature {
		return float64(depth)
	}

	if sample[t.splitFeature] < t.splitValue {
		if t.left != nil {
			return t.left.PathLength(sample, depth+1)
		}
	} else {
		if t.right != nil {
			return t.right.PathLength(sample, depth+1)
		}
	}

	return float64(depth)
}

// pathLengthAdjustment calculates c(n) for unbuilt branches.
func pathLengthAdjustment(n int) float64 {
	if n > 2 {
		return 2.0*(math.Log(float64(n-1))+0.5772156649) - 2.0*float64(n-1)/float64(n)
	} else if n == 2 {
		return 1.0
	}
	return 0.0
}

// ARIMAModel implements ARIMA(p,d,q) for time series forecasting.
type ARIMAModel struct {
	p, d, q     int
	arCoeffs    []float64 // AR coefficients
	maCoeffs    []float64 // MA coefficients
	residuals   []float64
	fitted      []float64
	diffed      []float64
	original    []float64
	mean        float64
	stdDev      float64
	trained     bool
	mu          sync.RWMutex
}

// NewARIMAModel creates a new ARIMA model.
func NewARIMAModel(p, d, q int) *ARIMAModel {
	return &ARIMAModel{
		p: p,
		d: d,
		q: q,
	}
}

// Fit trains the ARIMA model on time series data.
func (m *ARIMAModel) Fit(data []float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(data) < m.p+m.d+m.q+10 {
		return
	}

	m.original = make([]float64, len(data))
	copy(m.original, data)

	// Apply differencing
	diffed := data
	for i := 0; i < m.d; i++ {
		diffed = difference(diffed)
	}
	m.diffed = diffed

	// Calculate mean
	m.mean = 0
	for _, v := range diffed {
		m.mean += v
	}
	m.mean /= float64(len(diffed))

	// Center the data
	centered := make([]float64, len(diffed))
	for i, v := range diffed {
		centered[i] = v - m.mean
	}

	// Estimate AR coefficients using Yule-Walker equations
	m.arCoeffs = m.estimateAR(centered)

	// Estimate MA coefficients from residuals
	m.residuals = m.calculateResiduals(centered)
	m.maCoeffs = m.estimateMA(m.residuals)

	// Calculate standard deviation of residuals
	m.stdDev = 0
	for _, r := range m.residuals {
		m.stdDev += r * r
	}
	if len(m.residuals) > 1 {
		m.stdDev = math.Sqrt(m.stdDev / float64(len(m.residuals)-1))
	}

	m.trained = true
}

// estimateAR estimates AR coefficients using Yule-Walker.
func (m *ARIMAModel) estimateAR(data []float64) []float64 {
	if m.p == 0 || len(data) < m.p+1 {
		return nil
	}

	// Calculate autocorrelations
	n := len(data)
	acf := make([]float64, m.p+1)
	for k := 0; k <= m.p; k++ {
		sum := 0.0
		for i := k; i < n; i++ {
			sum += data[i] * data[i-k]
		}
		acf[k] = sum / float64(n)
	}

	if acf[0] == 0 {
		return make([]float64, m.p)
	}

	// Normalize
	for i := 1; i <= m.p; i++ {
		acf[i] /= acf[0]
	}

	// Levinson-Durbin algorithm
	coeffs := make([]float64, m.p)
	if m.p >= 1 {
		coeffs[0] = acf[1]
	}

	if m.p >= 2 {
		prevCoeffs := make([]float64, m.p)
		copy(prevCoeffs, coeffs)

		for k := 1; k < m.p; k++ {
			// Calculate reflection coefficient
			num := acf[k+1]
			for j := 0; j < k; j++ {
				num -= prevCoeffs[j] * acf[k-j]
			}

			denom := 1.0
			for j := 0; j < k; j++ {
				denom -= prevCoeffs[j] * acf[j+1]
			}

			if denom == 0 {
				break
			}

			coeffs[k] = num / denom

			// Update coefficients
			for j := 0; j < k; j++ {
				coeffs[j] = prevCoeffs[j] - coeffs[k]*prevCoeffs[k-1-j]
			}

			copy(prevCoeffs, coeffs)
		}
	}

	return coeffs
}

// calculateResiduals calculates residuals from AR model.
func (m *ARIMAModel) calculateResiduals(data []float64) []float64 {
	residuals := make([]float64, len(data))

	for t := m.p; t < len(data); t++ {
		predicted := 0.0
		for i := 0; i < m.p && i < len(m.arCoeffs); i++ {
			predicted += m.arCoeffs[i] * data[t-1-i]
		}
		residuals[t] = data[t] - predicted
	}

	return residuals
}

// estimateMA estimates MA coefficients.
func (m *ARIMAModel) estimateMA(residuals []float64) []float64 {
	if m.q == 0 || len(residuals) < m.q+1 {
		return nil
	}

	// Simple autocorrelation-based estimation
	n := len(residuals)
	coeffs := make([]float64, m.q)

	var0 := 0.0
	for _, r := range residuals {
		var0 += r * r
	}
	var0 /= float64(n)

	if var0 == 0 {
		return coeffs
	}

	for k := 0; k < m.q; k++ {
		cov := 0.0
		for i := k + 1; i < n; i++ {
			cov += residuals[i] * residuals[i-k-1]
		}
		coeffs[k] = cov / (float64(n) * var0)
	}

	return coeffs
}

// difference applies first-order differencing.
func difference(data []float64) []float64 {
	if len(data) < 2 {
		return data
	}

	result := make([]float64, len(data)-1)
	for i := 1; i < len(data); i++ {
		result[i-1] = data[i] - data[i-1]
	}
	return result
}

// Predict generates predictions for n steps.
func (m *ARIMAModel) Predict(n int) []float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.trained || n <= 0 {
		return make([]float64, n)
	}

	predictions := make([]float64, n)
	history := make([]float64, len(m.diffed))
	copy(history, m.diffed)

	for t := 0; t < n; t++ {
		pred := m.mean

		// AR component
		for i := 0; i < m.p && i < len(m.arCoeffs); i++ {
			idx := len(history) - 1 - i
			if idx >= 0 {
				pred += m.arCoeffs[i] * (history[idx] - m.mean)
			}
		}

		// MA component
		for i := 0; i < m.q && i < len(m.maCoeffs) && i < len(m.residuals); i++ {
			idx := len(m.residuals) - 1 - i + t
			if idx >= 0 && idx < len(m.residuals) {
				pred += m.maCoeffs[i] * m.residuals[idx]
			}
		}

		predictions[t] = pred
		history = append(history, pred)
	}

	// Invert differencing
	if m.d > 0 && len(m.original) > 0 {
		result := make([]float64, n)
		lastVal := m.original[len(m.original)-1]
		for i := 0; i < n; i++ {
			result[i] = lastVal + predictions[i]
			lastVal = result[i]
		}
		return result
	}

	return predictions
}

// StdDev returns the standard deviation of residuals.
func (m *ARIMAModel) StdDev() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stdDev
}

// ExponentialSmoothing implements Holt-Winters triple exponential smoothing.
type ExponentialSmoothing struct {
	alpha    float64 // Level smoothing
	beta     float64 // Trend smoothing
	gamma    float64 // Seasonal smoothing
	period   int
	level    float64
	trend    float64
	seasonal []float64
	fitted   []float64
	trained  bool
	mu       sync.RWMutex
}

// NewExponentialSmoothing creates a new exponential smoothing model.
func NewExponentialSmoothing(alpha, beta, gamma float64, period int) *ExponentialSmoothing {
	return &ExponentialSmoothing{
		alpha:  alpha,
		beta:   beta,
		gamma:  gamma,
		period: period,
	}
}

// Fit trains the exponential smoothing model.
func (es *ExponentialSmoothing) Fit(data []float64) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if len(data) < es.period*2 {
		return
	}

	// Initialize level and trend
	es.level = 0
	for i := 0; i < es.period; i++ {
		es.level += data[i]
	}
	es.level /= float64(es.period)

	es.trend = 0
	for i := 0; i < es.period; i++ {
		es.trend += (data[es.period+i] - data[i])
	}
	es.trend /= float64(es.period * es.period)

	// Initialize seasonal indices
	es.seasonal = make([]float64, es.period)
	for i := 0; i < es.period; i++ {
		es.seasonal[i] = data[i] / es.level
	}

	// Fit the model
	es.fitted = make([]float64, len(data))
	level := es.level
	trend := es.trend
	seasonal := make([]float64, es.period)
	copy(seasonal, es.seasonal)

	for t := 0; t < len(data); t++ {
		seasonIdx := t % es.period
		predicted := (level + trend) * seasonal[seasonIdx]
		es.fitted[t] = predicted

		// Update components
		newLevel := es.alpha*(data[t]/seasonal[seasonIdx]) + (1-es.alpha)*(level+trend)
		newTrend := es.beta*(newLevel-level) + (1-es.beta)*trend
		newSeasonal := es.gamma*(data[t]/newLevel) + (1-es.gamma)*seasonal[seasonIdx]

		level = newLevel
		trend = newTrend
		seasonal[seasonIdx] = newSeasonal
	}

	es.level = level
	es.trend = trend
	es.seasonal = seasonal
	es.trained = true
}

// Predict generates forecasts for n steps ahead.
func (es *ExponentialSmoothing) Predict(n int) []float64 {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if !es.trained {
		return make([]float64, n)
	}

	predictions := make([]float64, n)
	for i := 0; i < n; i++ {
		seasonIdx := (len(es.fitted) + i) % es.period
		predictions[i] = (es.level + float64(i+1)*es.trend) * es.seasonal[seasonIdx]
	}

	return predictions
}

// DetectTrendAnomaly detects anomalies in trend changes.
func (es *ExponentialSmoothing) DetectTrendAnomaly(metrics []Metric) *MLAnomaly {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if !es.trained || len(metrics) < es.period {
		return nil
	}

	// Calculate current trend from recent data
	latencies := make([]float64, len(metrics))
	for i, m := range metrics {
		latencies[i] = float64(m.Latency.Milliseconds())
	}

	recentTrend := 0.0
	for i := 1; i < len(latencies); i++ {
		recentTrend += latencies[i] - latencies[i-1]
	}
	recentTrend /= float64(len(latencies) - 1)

	// Compare with expected trend
	trendDeviation := math.Abs(recentTrend - es.trend)
	threshold := math.Abs(es.trend) * 2.0
	if threshold < 1.0 {
		threshold = 1.0
	}

	if trendDeviation > threshold {
		return &MLAnomaly{
			Metric:     metrics[len(metrics)-1],
			Score:      trendDeviation / threshold,
			Threshold:  1.0,
			Method:     "exponential_smoothing",
			Confidence: calculateConfidence(trendDeviation/threshold, 1.0),
			Prediction: es.trend,
		}
	}

	return nil
}

// FeatureExtractor extracts features from metrics for ML models.
type FeatureExtractor struct {
	features []string
}

// NewFeatureExtractor creates a new feature extractor.
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		features: []string{
			"latency_ms",
			"request_size",
			"status_class",
			"hour_of_day",
			"minute_of_hour",
		},
	}
}

// Extract extracts feature matrix from metrics.
func (fe *FeatureExtractor) Extract(metrics []Metric) [][]float64 {
	matrix := make([][]float64, len(metrics))
	for i, m := range metrics {
		matrix[i] = fe.extractFeatures(m)
	}
	return matrix
}

// ExtractSingle extracts features for a single metric with history context.
func (fe *FeatureExtractor) ExtractSingle(m Metric, history []Metric) []float64 {
	features := fe.extractFeatures(m)

	// Add contextual features based on history
	if len(history) > 0 {
		// Recent average latency
		var avgLatency float64
		for _, h := range history {
			avgLatency += float64(h.Latency.Milliseconds())
		}
		avgLatency /= float64(len(history))
		features = append(features, avgLatency)

		// Latency delta from average
		features = append(features, float64(m.Latency.Milliseconds())-avgLatency)

		// Error rate in history
		errorCount := 0
		for _, h := range history {
			if h.StatusCode >= 500 {
				errorCount++
			}
		}
		features = append(features, float64(errorCount)/float64(len(history)))
	}

	return features
}

// extractFeatures extracts base features from a single metric.
func (fe *FeatureExtractor) extractFeatures(m Metric) []float64 {
	return []float64{
		float64(m.Latency.Milliseconds()),
		float64(m.RequestSize),
		float64(m.StatusCode / 100),
		float64(m.Timestamp.Hour()),
		float64(m.Timestamp.Minute()),
	}
}
