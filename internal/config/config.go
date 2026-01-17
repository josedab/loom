// Package config provides configuration loading and hot-reload functionality.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Config represents the complete gateway configuration.
type Config struct {
	Listeners   []ListenerConfig  `yaml:"listeners"`
	Routes      []RouteConfig     `yaml:"routes"`
	Upstreams   []UpstreamConfig  `yaml:"upstreams"`
	Plugins     []PluginConfig    `yaml:"plugins"`
	Admin       AdminConfig       `yaml:"admin"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	RateLimit   RateLimitConfig   `yaml:"rate_limit,omitempty"`
	Tracing     TracingConfig     `yaml:"tracing,omitempty"`
	CORS        CORSConfig        `yaml:"cors,omitempty"`
	Cache       CacheConfig       `yaml:"cache,omitempty"`
}

// ListenerConfig defines a listener endpoint.
type ListenerConfig struct {
	Name     string     `yaml:"name"`
	Address  string     `yaml:"address"`
	Protocol string     `yaml:"protocol"` // http, https, h2c, grpc, grpcs
	TLS      *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig defines TLS settings.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// RouteConfig defines a routing rule.
type RouteConfig struct {
	ID          string            `yaml:"id"`
	Host        string            `yaml:"host,omitempty"`
	Path        string            `yaml:"path"`
	Methods     []string          `yaml:"methods"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	QueryParams map[string]string `yaml:"query_params,omitempty"`
	Upstream    string            `yaml:"upstream"`
	Plugins     []string          `yaml:"plugins,omitempty"`
	StripPrefix bool              `yaml:"strip_prefix,omitempty"`
	Timeout     string            `yaml:"timeout,omitempty"`
	Priority    int               `yaml:"priority,omitempty"`
}

// UpstreamConfig defines a backend service.
type UpstreamConfig struct {
	Name             string                 `yaml:"name"`
	Endpoints        []string               `yaml:"endpoints"`
	LoadBalancer     string                 `yaml:"load_balancer"` // round_robin, weighted, least_conn, random, consistent_hash
	ConsistentHash   ConsistentHashConfig   `yaml:"consistent_hash,omitempty"`
	HealthCheck      HealthCheckConfig      `yaml:"health_check,omitempty"`
	CircuitBreaker   CircuitConfig          `yaml:"circuit_breaker,omitempty"`
	Retry            RetryConfig            `yaml:"retry,omitempty"`
	Bulkhead         BulkheadConfig         `yaml:"bulkhead,omitempty"`
	ServiceDiscovery ServiceDiscoveryConfig `yaml:"service_discovery,omitempty"`
}

// ServiceDiscoveryConfig defines service discovery settings for an upstream.
type ServiceDiscoveryConfig struct {
	// Enabled enables service discovery for this upstream
	Enabled bool `yaml:"enabled"`
	// Provider is the discovery provider to use (dns, consul, kubernetes)
	Provider string `yaml:"provider"`
	// ServiceName is the service name to discover (defaults to upstream name)
	ServiceName string `yaml:"service_name,omitempty"`
	// RefreshInterval is how often to refresh the service list
	RefreshInterval string `yaml:"refresh_interval,omitempty"`
}

// ConsistentHashConfig defines consistent hash load balancing settings.
type ConsistentHashConfig struct {
	// HashKey is the header or attribute to use for hashing (e.g., "X-User-ID", "Cookie:session")
	// If empty, client IP is used by default.
	HashKey string `yaml:"hash_key"`
	// Replicas is the number of virtual nodes per endpoint (default: 150)
	Replicas int `yaml:"replicas"`
}

// BulkheadConfig defines concurrent request limiting settings.
type BulkheadConfig struct {
	// Enabled enables the bulkhead pattern
	Enabled bool `yaml:"enabled"`
	// MaxConcurrent is the maximum number of concurrent requests (default: 100)
	MaxConcurrent int `yaml:"max_concurrent"`
	// QueueSize is the maximum number of requests to queue when at capacity (default: 0 = reject immediately)
	QueueSize int `yaml:"queue_size"`
	// Timeout is how long to wait for a slot when queueing (default: 0 = wait indefinitely)
	Timeout string `yaml:"timeout"`
}

// HealthCheckConfig defines health check settings.
type HealthCheckConfig struct {
	Path               string `yaml:"path"`
	Interval           string `yaml:"interval"`
	Timeout            string `yaml:"timeout"`
	HealthyThreshold   int    `yaml:"healthy_threshold"`
	UnhealthyThreshold int    `yaml:"unhealthy_threshold"`
}

// CircuitConfig defines circuit breaker settings.
type CircuitConfig struct {
	FailureThreshold int    `yaml:"failure_threshold"`
	SuccessThreshold int    `yaml:"success_threshold"`
	Timeout          string `yaml:"timeout"`
}

// RetryConfig defines retry policy.
type RetryConfig struct {
	MaxRetries     int    `yaml:"max_retries"`
	BackoffBase    string `yaml:"backoff_base"`
	BackoffMax     string `yaml:"backoff_max"`
	RetryableCodes []int  `yaml:"retryable_codes"`
}

// PluginConfig defines a WASM plugin.
type PluginConfig struct {
	Name        string                 `yaml:"name"`
	Path        string                 `yaml:"path"`
	Phase       string                 `yaml:"phase"` // on_request_headers, on_request_body, on_response_headers, on_response_body, on_log
	Priority    int                    `yaml:"priority"`
	Config      map[string]interface{} `yaml:"config,omitempty"`
	MemoryLimit string                 `yaml:"memory_limit,omitempty"`
	Timeout     string                 `yaml:"timeout,omitempty"`
}

// AdminConfig defines admin API settings.
type AdminConfig struct {
	Address string            `yaml:"address"`
	Enabled bool              `yaml:"enabled"`
	Auth    AdminAuthConfig   `yaml:"auth,omitempty"`
}

// AdminAuthConfig defines admin API authentication settings.
type AdminAuthConfig struct {
	Enabled bool              `yaml:"enabled"`
	Users   map[string]string `yaml:"users,omitempty"` // username -> password hash (SHA256 hex)
	Realm   string            `yaml:"realm,omitempty"`
}

// MetricsConfig defines metrics settings.
type MetricsConfig struct {
	Prometheus    PrometheusConfig    `yaml:"prometheus,omitempty"`
	OpenTelemetry OpenTelemetryConfig `yaml:"opentelemetry,omitempty"`
}

// PrometheusConfig defines Prometheus metrics settings.
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// OpenTelemetryConfig defines OpenTelemetry settings.
type OpenTelemetryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// RateLimitConfig defines rate limiting settings.
type RateLimitConfig struct {
	Enabled         bool    `yaml:"enabled"`
	Rate            float64 `yaml:"rate"`             // Requests per second
	Burst           int     `yaml:"burst"`            // Maximum burst size
	CleanupInterval string  `yaml:"cleanup_interval"` // Cleanup interval for stale buckets
}

// TracingConfig defines distributed tracing settings.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled"`
	Endpoint     string  `yaml:"endpoint"`     // OTLP endpoint
	ServiceName  string  `yaml:"service_name"` // Service name in traces
	SampleRate   float64 `yaml:"sample_rate"`  // Sampling rate (0.0 to 1.0)
	BatchTimeout string  `yaml:"batch_timeout"`
}

// CORSConfig defines CORS settings.
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowMethods     []string `yaml:"allow_methods"`
	AllowHeaders     []string `yaml:"allow_headers"`
	ExposeHeaders    []string `yaml:"expose_headers"`
	MaxAge           int      `yaml:"max_age"`
	AllowCredentials bool     `yaml:"allow_credentials"`
}

// CacheConfig defines response caching settings.
type CacheConfig struct {
	Enabled              bool     `yaml:"enabled"`
	MaxSize              string   `yaml:"max_size"`               // e.g., "100MB", "1GB"
	DefaultTTL           string   `yaml:"default_ttl"`            // e.g., "5m", "1h"
	CleanupInterval      string   `yaml:"cleanup_interval"`       // e.g., "1m"
	StaleWhileRevalidate string   `yaml:"stale_while_revalidate"` // e.g., "30s"
	ExcludedPaths        []string `yaml:"excluded_paths"`         // Paths to exclude from caching
	IncludedPaths        []string `yaml:"included_paths"`         // If set, only cache these paths
	BypassHeader         string   `yaml:"bypass_header"`          // Header to bypass cache
}

// Manager handles configuration loading and hot-reload.
type Manager struct {
	configPath string
	config     *Config
	watcher    *fsnotify.Watcher
	callbacks  []func(*Config)
	mu         sync.RWMutex
	stopCh     chan struct{}
}

// NewManager creates a new configuration manager.
func NewManager(configPath string) (*Manager, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating file watcher: %w", err)
	}

	cm := &Manager{
		configPath: configPath,
		watcher:    watcher,
		callbacks:  make([]func(*Config), 0),
		stopCh:     make(chan struct{}),
	}

	if err := cm.load(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("loading initial config: %w", err)
	}

	go cm.watchChanges()

	return cm, nil
}

// load reads and parses the configuration file.
func (m *Manager) load() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	if err := m.validate(&config); err != nil {
		return fmt.Errorf("validating config: %w", err)
	}

	m.mu.Lock()
	m.config = &config
	m.mu.Unlock()

	return nil
}

// validate checks configuration validity.
func (m *Manager) validate(cfg *Config) error {
	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("at least one listener is required")
	}

	for i, l := range cfg.Listeners {
		if l.Address == "" {
			return fmt.Errorf("listener[%d]: address is required", i)
		}
		if l.Protocol == "" {
			return fmt.Errorf("listener[%d]: protocol is required", i)
		}
	}

	upstreamNames := make(map[string]bool)
	for i, u := range cfg.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("upstream[%d]: name is required", i)
		}
		if len(u.Endpoints) == 0 {
			return fmt.Errorf("upstream[%d]: at least one endpoint is required", i)
		}
		upstreamNames[u.Name] = true
	}

	for i, r := range cfg.Routes {
		if r.Path == "" {
			return fmt.Errorf("route[%d]: path is required", i)
		}
		if r.Upstream == "" {
			return fmt.Errorf("route[%d]: upstream is required", i)
		}
		if !upstreamNames[r.Upstream] {
			return fmt.Errorf("route[%d]: upstream %q not found", i, r.Upstream)
		}
	}

	return nil
}

// watchChanges monitors the config file for changes.
func (m *Manager) watchChanges() {
	dir := filepath.Dir(m.configPath)
	if err := m.watcher.Add(dir); err != nil {
		return
	}

	debounce := time.NewTimer(0)
	<-debounce.C

	for {
		select {
		case <-m.stopCh:
			return
		case event := <-m.watcher.Events:
			if event.Name == m.configPath && (event.Op&fsnotify.Write != 0 || event.Op&fsnotify.Create != 0) {
				debounce.Reset(100 * time.Millisecond)
			}
		case <-debounce.C:
			if err := m.load(); err != nil {
				continue
			}
			m.notifyCallbacks()
		case <-m.watcher.Errors:
			// Log error but continue watching
		}
	}
}

// notifyCallbacks invokes all registered callbacks.
func (m *Manager) notifyCallbacks() {
	m.mu.RLock()
	config := m.config
	callbacks := m.callbacks
	m.mu.RUnlock()

	for _, cb := range callbacks {
		cb(config)
	}
}

// Get returns the current configuration.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// OnChange registers a callback for configuration changes.
func (m *Manager) OnChange(cb func(*Config)) {
	m.mu.Lock()
	m.callbacks = append(m.callbacks, cb)
	m.mu.Unlock()
}

// Close stops the configuration manager.
func (m *Manager) Close() error {
	close(m.stopCh)
	return m.watcher.Close()
}

// ParseDuration parses a duration string with default fallback.
func ParseDuration(s string, defaultVal time.Duration) time.Duration {
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}

// ParseSize parses a size string like "100MB", "1GB" with default fallback.
func ParseSize(s string, defaultVal int64) int64 {
	if s == "" {
		return defaultVal
	}

	s = strings.TrimSpace(strings.ToUpper(s))

	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "GB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}

	s = strings.TrimSpace(s)
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}

	return val * multiplier
}
