// Package metrics provides Prometheus metrics exporting.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all loom metrics.
type Metrics struct {
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	requestSize       *prometheus.HistogramVec
	responseSize      *prometheus.HistogramVec
	upstreamDuration  *prometheus.HistogramVec
	upstreamRequests  *prometheus.CounterVec
	upstreamErrors    *prometheus.CounterVec
	activeConnections *prometheus.GaugeVec
	circuitState      *prometheus.GaugeVec
	pluginDuration    *prometheus.HistogramVec
	pluginErrors      *prometheus.CounterVec

	// Cache metrics
	cacheHitsTotal   *prometheus.CounterVec
	cacheMissesTotal *prometheus.CounterVec

	// Rate limit metrics
	rateLimitRejectionsTotal *prometheus.CounterVec

	// Auth metrics
	authFailuresTotal *prometheus.CounterVec

	// Upstream health metrics
	upstreamHealthStatus *prometheus.GaugeVec

	// Plugin cache metrics
	pluginCacheHitsTotal   prometheus.Counter
	pluginCacheMissesTotal prometheus.Counter

	registry *prometheus.Registry
}

// New creates a new metrics instance.
func New() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "route", "status"},
		),
		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "loom",
				Name:      "request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"method", "route"},
		),
		requestSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "loom",
				Name:      "request_size_bytes",
				Help:      "HTTP request size in bytes",
				Buckets:   prometheus.ExponentialBuckets(100, 10, 7),
			},
			[]string{"method", "route"},
		),
		responseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "loom",
				Name:      "response_size_bytes",
				Help:      "HTTP response size in bytes",
				Buckets:   prometheus.ExponentialBuckets(100, 10, 7),
			},
			[]string{"method", "route"},
		),
		upstreamDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "loom",
				Name:      "upstream_duration_seconds",
				Help:      "Upstream request duration in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			},
			[]string{"upstream", "endpoint"},
		),
		upstreamRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "upstream_requests_total",
				Help:      "Total number of upstream requests",
			},
			[]string{"upstream", "endpoint", "status"},
		),
		upstreamErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "upstream_errors_total",
				Help:      "Total number of upstream errors",
			},
			[]string{"upstream", "endpoint", "error_type"},
		),
		activeConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "loom",
				Name:      "active_connections",
				Help:      "Number of active connections",
			},
			[]string{"listener"},
		),
		circuitState: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "loom",
				Name:      "circuit_breaker_state",
				Help:      "Circuit breaker state (0=closed, 1=open, 2=half-open)",
			},
			[]string{"upstream"},
		),
		pluginDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "loom",
				Name:      "plugin_duration_seconds",
				Help:      "Plugin execution duration in seconds",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .05, .1},
			},
			[]string{"plugin", "phase"},
		),
		pluginErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "plugin_errors_total",
				Help:      "Total number of plugin errors",
			},
			[]string{"plugin", "phase"},
		),
		cacheHitsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"cache_type"},
		),
		cacheMissesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"cache_type"},
		),
		rateLimitRejectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "ratelimit_rejections_total",
				Help:      "Total number of rate limit rejections",
			},
			[]string{"route", "key"},
		),
		authFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "auth_failures_total",
				Help:      "Total number of authentication failures",
			},
			[]string{"method", "reason"},
		),
		upstreamHealthStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "loom",
				Name:      "upstream_health_status",
				Help:      "Upstream endpoint health status (0=unhealthy, 1=healthy)",
			},
			[]string{"upstream", "endpoint"},
		),
		pluginCacheHitsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "plugin_cache_hits_total",
				Help:      "Total number of compiled WASM plugin cache hits",
			},
		),
		pluginCacheMissesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "loom",
				Name:      "plugin_cache_misses_total",
				Help:      "Total number of compiled WASM plugin cache misses",
			},
		),
		registry: registry,
	}

	// Register all metrics
	registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.requestSize,
		m.responseSize,
		m.upstreamDuration,
		m.upstreamRequests,
		m.upstreamErrors,
		m.activeConnections,
		m.circuitState,
		m.pluginDuration,
		m.pluginErrors,
		m.cacheHitsTotal,
		m.cacheMissesTotal,
		m.rateLimitRejectionsTotal,
		m.authFailuresTotal,
		m.upstreamHealthStatus,
		m.pluginCacheHitsTotal,
		m.pluginCacheMissesTotal,
	)

	return m
}

// Handler returns the Prometheus HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// RecordRequest records a request metric.
func (m *Metrics) RecordRequest(method, route string, status int, duration time.Duration, reqSize, respSize int64) {
	statusStr := strconv.Itoa(status)
	m.requestsTotal.WithLabelValues(method, route, statusStr).Inc()
	m.requestDuration.WithLabelValues(method, route).Observe(duration.Seconds())
	m.requestSize.WithLabelValues(method, route).Observe(float64(reqSize))
	m.responseSize.WithLabelValues(method, route).Observe(float64(respSize))
}

// RecordUpstreamRequest records an upstream request metric.
func (m *Metrics) RecordUpstreamRequest(upstream, endpoint string, status int, duration time.Duration) {
	statusStr := strconv.Itoa(status)
	m.upstreamRequests.WithLabelValues(upstream, endpoint, statusStr).Inc()
	m.upstreamDuration.WithLabelValues(upstream, endpoint).Observe(duration.Seconds())
}

// RecordUpstreamError records an upstream error.
func (m *Metrics) RecordUpstreamError(upstream, endpoint, errorType string) {
	m.upstreamErrors.WithLabelValues(upstream, endpoint, errorType).Inc()
}

// SetActiveConnections sets the active connection count.
func (m *Metrics) SetActiveConnections(listener string, count float64) {
	m.activeConnections.WithLabelValues(listener).Set(count)
}

// SetCircuitState sets the circuit breaker state.
func (m *Metrics) SetCircuitState(upstream string, state int) {
	m.circuitState.WithLabelValues(upstream).Set(float64(state))
}

// RecordPluginExecution records plugin execution metrics.
func (m *Metrics) RecordPluginExecution(plugin, phase string, duration time.Duration, err error) {
	m.pluginDuration.WithLabelValues(plugin, phase).Observe(duration.Seconds())
	if err != nil {
		m.pluginErrors.WithLabelValues(plugin, phase).Inc()
	}
}

// RecordCacheHit records a cache hit.
func (m *Metrics) RecordCacheHit(cacheType string) {
	m.cacheHitsTotal.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records a cache miss.
func (m *Metrics) RecordCacheMiss(cacheType string) {
	m.cacheMissesTotal.WithLabelValues(cacheType).Inc()
}

// RecordRateLimitRejection records a rate limit rejection.
func (m *Metrics) RecordRateLimitRejection(route, key string) {
	m.rateLimitRejectionsTotal.WithLabelValues(route, key).Inc()
}

// RecordAuthFailure records an authentication failure.
func (m *Metrics) RecordAuthFailure(method, reason string) {
	m.authFailuresTotal.WithLabelValues(method, reason).Inc()
}

// SetUpstreamHealthStatus sets the health status for an upstream endpoint.
func (m *Metrics) SetUpstreamHealthStatus(upstream, endpoint string, healthy bool) {
	status := 0.0
	if healthy {
		status = 1.0
	}
	m.upstreamHealthStatus.WithLabelValues(upstream, endpoint).Set(status)
}

// RecordPluginCacheHit records a compiled WASM plugin cache hit.
func (m *Metrics) RecordPluginCacheHit() {
	m.pluginCacheHitsTotal.Inc()
}

// RecordPluginCacheMiss records a compiled WASM plugin cache miss.
func (m *Metrics) RecordPluginCacheMiss() {
	m.pluginCacheMissesTotal.Inc()
}

// Middleware returns an HTTP middleware for metrics collection.
func (m *Metrics) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status and size
			rw := &metricsResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			// Record metrics
			duration := time.Since(start)
			route := r.URL.Path
			m.RecordRequest(r.Method, route, rw.statusCode, duration, r.ContentLength, rw.bytesWritten)
		})
	}
}

// metricsResponseWriter wraps http.ResponseWriter to capture metrics.
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *metricsResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}
