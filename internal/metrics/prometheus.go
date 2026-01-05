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
