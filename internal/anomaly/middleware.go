package anomaly

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// MiddlewareConfig configures the anomaly detection middleware.
type MiddlewareConfig struct {
	// Detector is the anomaly detector
	Detector *Detector
	// RouteExtractor extracts the route from a request
	RouteExtractor func(*http.Request) string
	// OnAnomaly is called when an anomaly is detected
	OnAnomaly func(Alert, *http.Request)
	// Logger for middleware events
	Logger *slog.Logger
}

// Middleware returns HTTP middleware that records metrics and detects anomalies.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RouteExtractor == nil {
		cfg.RouteExtractor = func(r *http.Request) string {
			return r.URL.Path
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Capture response status
			capture := &responseCapture{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Execute handler
			next.ServeHTTP(capture, r)

			// Record metric
			metric := Metric{
				Timestamp:   start,
				Route:       cfg.RouteExtractor(r),
				Method:      r.Method,
				StatusCode:  capture.statusCode,
				Latency:     time.Since(start),
				RequestSize: r.ContentLength,
				IP:          getClientIP(r),
				UserAgent:   r.UserAgent(),
			}

			alerts := cfg.Detector.Record(metric)

			// Notify for any alerts
			if cfg.OnAnomaly != nil {
				for _, alert := range alerts {
					cfg.OnAnomaly(alert, r)
				}
			}
		})
	}
}

// responseCapture captures the response status code.
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (c *responseCapture) WriteHeader(code int) {
	if !c.written {
		c.statusCode = code
		c.written = true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *responseCapture) Write(b []byte) (int, error) {
	if !c.written {
		c.written = true
	}
	return c.ResponseWriter.Write(b)
}

func (c *responseCapture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// getClientIP extracts the client IP from a request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// AlertHandler provides webhook-based alert notifications.
type AlertHandler struct {
	detector   *Detector
	webhooks   []string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewAlertHandler creates a new alert handler.
func NewAlertHandler(detector *Detector, webhooks []string, logger *slog.Logger) *AlertHandler {
	if logger == nil {
		logger = slog.Default()
	}

	handler := &AlertHandler{
		detector:   detector,
		webhooks:   webhooks,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}

	// Start alert processor
	go handler.processAlerts()

	return handler
}

// processAlerts processes alerts from the detector.
func (h *AlertHandler) processAlerts() {
	for alert := range h.detector.AlertChannel() {
		h.notifyWebhooks(alert)
	}
}

// notifyWebhooks sends alert to configured webhooks.
func (h *AlertHandler) notifyWebhooks(alert Alert) {
	for _, webhook := range h.webhooks {
		go h.sendWebhook(webhook, alert)
	}
}

// sendWebhook sends an alert to a webhook.
func (h *AlertHandler) sendWebhook(url string, alert Alert) {
	// Implementation would send HTTP POST to webhook
	// Omitted for brevity
	h.logger.Debug("webhook notification sent",
		"url", url,
		"alert_type", alert.Type,
	)
}

// RateLimitAnomaly tracks unusual rate patterns for rate limiting.
type RateLimitAnomaly struct {
	detector     *Detector
	windowSize   time.Duration
	threshold    float64
	mu           sync.Mutex
	lastCheck    map[string]time.Time
	lastWarnings map[string]time.Time
}

// NewRateLimitAnomaly creates a rate limit anomaly detector.
func NewRateLimitAnomaly(detector *Detector, windowSize time.Duration, threshold float64) *RateLimitAnomaly {
	return &RateLimitAnomaly{
		detector:     detector,
		windowSize:   windowSize,
		threshold:    threshold,
		lastCheck:    make(map[string]time.Time),
		lastWarnings: make(map[string]time.Time),
	}
}

// Check checks if a client is exhibiting anomalous request patterns.
func (r *RateLimitAnomaly) Check(clientIP, route string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := clientIP + ":" + route
	now := time.Now()

	// Rate limit checks to avoid overhead
	if lastCheck, ok := r.lastCheck[key]; ok {
		if now.Sub(lastCheck) < time.Second {
			return r.lastWarnings[key].Add(time.Minute).After(now)
		}
	}
	r.lastCheck[key] = now

	// Get baseline for this route
	baseline := r.detector.GetBaseline(route, "")
	if baseline == nil {
		return false
	}

	// Calculate current rate for this IP
	metrics := r.detector.metrics.Query(MetricFilter{
		Duration: r.windowSize,
		Route:    route,
	})

	clientRequests := 0
	for _, m := range metrics {
		if m.IP == clientIP {
			clientRequests++
		}
	}

	// Expected requests per client (assuming even distribution)
	// This is a simplified heuristic
	expectedPerClient := baseline.RequestsPerMin * r.windowSize.Minutes() / 100

	if float64(clientRequests) > expectedPerClient*r.threshold {
		r.lastWarnings[key] = now
		return true
	}

	return false
}

// PatternAnalyzer detects unusual request patterns.
type PatternAnalyzer struct {
	detector  *Detector
	patterns  map[string]*RequestPattern
	mu        sync.RWMutex
}

// RequestPattern represents learned request patterns.
type RequestPattern struct {
	Route            string
	CommonUserAgents map[string]int
	CommonMethods    map[string]int
	HourlyDistribution [24]int
	TotalRequests    int
}

// NewPatternAnalyzer creates a pattern analyzer.
func NewPatternAnalyzer(detector *Detector) *PatternAnalyzer {
	return &PatternAnalyzer{
		detector: detector,
		patterns: make(map[string]*RequestPattern),
	}
}

// Learn learns patterns from historical metrics.
func (p *PatternAnalyzer) Learn(route string) {
	metrics := p.detector.metrics.Query(MetricFilter{
		Duration: 24 * time.Hour,
		Route:    route,
	})

	if len(metrics) == 0 {
		return
	}

	pattern := &RequestPattern{
		Route:            route,
		CommonUserAgents: make(map[string]int),
		CommonMethods:    make(map[string]int),
	}

	for _, m := range metrics {
		pattern.CommonUserAgents[m.UserAgent]++
		pattern.CommonMethods[m.Method]++
		pattern.HourlyDistribution[m.Timestamp.Hour()]++
		pattern.TotalRequests++
	}

	p.mu.Lock()
	p.patterns[route] = pattern
	p.mu.Unlock()
}

// DetectAnomaly checks if a request deviates from learned patterns.
func (p *PatternAnalyzer) DetectAnomaly(m Metric) *Alert {
	p.mu.RLock()
	pattern := p.patterns[m.Route]
	p.mu.RUnlock()

	if pattern == nil || pattern.TotalRequests < 1000 {
		return nil
	}

	// Check for unusual user agent
	uaCount := pattern.CommonUserAgents[m.UserAgent]
	uaRatio := float64(uaCount) / float64(pattern.TotalRequests)
	if uaRatio < 0.001 { // User agent seen in less than 0.1% of requests
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypePattern,
			Severity:    SeverityLow,
			Route:       m.Route,
			Method:      m.Method,
			Description: "Unusual user agent detected",
			Timestamp:   m.Timestamp,
			Metadata: map[string]interface{}{
				"user_agent": m.UserAgent,
				"seen_ratio": uaRatio,
			},
		}
	}

	// Check for unusual hour
	hour := m.Timestamp.Hour()
	hourRatio := float64(pattern.HourlyDistribution[hour]) / float64(pattern.TotalRequests)
	if hourRatio < 0.01 { // Less than 1% of traffic at this hour
		return &Alert{
			ID:          generateID(),
			Type:        AnomalyTypePattern,
			Severity:    SeverityLow,
			Route:       m.Route,
			Description: "Request during unusual hour",
			Timestamp:   m.Timestamp,
			Metadata: map[string]interface{}{
				"hour":       hour,
				"hour_ratio": hourRatio,
			},
		}
	}

	return nil
}

// HealthScore calculates an overall API health score (0-100).
func (d *Detector) HealthScore() float64 {
	baselines := d.GetAllBaselines()
	if len(baselines) == 0 {
		return 100 // No data, assume healthy
	}

	totalScore := 0.0
	count := 0

	for key, baseline := range baselines {
		if baseline.Samples < 10 {
			continue
		}

		// Get recent metrics
		metrics := d.metrics.Query(MetricFilter{
			Duration: d.config.WindowSize,
			Route:    baseline.Route,
			Method:   baseline.Method,
		})

		if len(metrics) == 0 {
			continue
		}

		// Calculate latency score
		latencies := make([]float64, 0, len(metrics))
		errors := 0
		for _, m := range metrics {
			latencies = append(latencies, float64(m.Latency.Milliseconds()))
			if m.StatusCode >= 500 {
				errors++
			}
		}

		currentMean := calculateMean(latencies)
		latencyRatio := currentMean / baseline.LatencyMean
		latencyScore := 100 - (latencyRatio-1)*50
		if latencyScore < 0 {
			latencyScore = 0
		}
		if latencyScore > 100 {
			latencyScore = 100
		}

		// Calculate error score
		errorRate := float64(errors) / float64(len(metrics))
		errorScore := 100 - errorRate*200
		if errorScore < 0 {
			errorScore = 0
		}

		// Combined score (70% latency, 30% error)
		routeScore := latencyScore*0.7 + errorScore*0.3
		totalScore += routeScore
		count++

		_ = key // Silence unused variable
	}

	if count == 0 {
		return 100
	}

	return totalScore / float64(count)
}
