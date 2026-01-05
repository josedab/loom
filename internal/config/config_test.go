package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "gateway.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return configPath
}

func TestNewManager(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	m, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer m.Close()

	cfg := m.Get()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if len(cfg.Listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[0].Address != ":8080" {
		t.Errorf("expected address ':8080', got %s", cfg.Listeners[0].Address)
	}

	if len(cfg.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Routes))
	}

	if len(cfg.Upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
}

func TestNewManagerInvalidPath(t *testing.T) {
	_, err := NewManager("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestNewManagerInvalidYAML(t *testing.T) {
	content := `
listeners: [
  - this is not valid yaml
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidation_NoListeners(t *testing.T) {
	content := `
routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing listeners")
	}
}

func TestValidation_ListenerMissingAddress(t *testing.T) {
	content := `
listeners:
  - name: http
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing listener address")
	}
}

func TestValidation_ListenerMissingProtocol(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing listener protocol")
	}
}

func TestValidation_UpstreamMissingName(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

upstreams:
  - endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing upstream name")
	}
}

func TestValidation_UpstreamMissingEndpoints(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

upstreams:
  - name: backend
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing upstream endpoints")
	}
}

func TestValidation_RouteMissingPath(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing route path")
	}
}

func TestValidation_RouteMissingUpstream(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    path: /api/*

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for missing route upstream")
	}
}

func TestValidation_RouteUnknownUpstream(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: nonexistent

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	_, err := NewManager(configPath)
	if err == nil {
		t.Error("expected error for unknown upstream in route")
	}
}

func TestOnChange(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	m, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer m.Close()

	m.OnChange(func(cfg *Config) {
		// Callback registered
	})

	// Verify callback was registered (we can't easily trigger hot reload in test)
	if len(m.callbacks) != 1 {
		t.Errorf("expected 1 callback, got %d", len(m.callbacks))
	}
}

func TestClose(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	m, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	err = m.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal time.Duration
		expected   time.Duration
	}{
		{"5s", time.Second, 5 * time.Second},
		{"1m", time.Second, time.Minute},
		{"500ms", time.Second, 500 * time.Millisecond},
		{"2h", time.Second, 2 * time.Hour},
		{"", time.Second, time.Second},
		{"invalid", 10 * time.Second, 10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseDuration(tt.input, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("ParseDuration(%q, %v) = %v, expected %v", tt.input, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input      string
		defaultVal int64
		expected   int64
	}{
		{"100MB", 0, 100 * 1024 * 1024},
		{"1GB", 0, 1024 * 1024 * 1024},
		{"512KB", 0, 512 * 1024},
		{"1024B", 0, 1024},
		{"100", 0, 100},
		{"", 1024, 1024},
		{"invalid", 2048, 2048},
		{"100mb", 0, 100 * 1024 * 1024}, // case insensitive
		{"  50 MB  ", 0, 50 * 1024 * 1024}, // with whitespace
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseSize(tt.input, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("ParseSize(%q, %d) = %d, expected %d", tt.input, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

func TestConfigStructs(t *testing.T) {
	// Test that all config structs can be created and used
	cfg := &Config{
		Listeners: []ListenerConfig{
			{
				Name:     "http",
				Address:  ":8080",
				Protocol: "http",
			},
			{
				Name:     "https",
				Address:  ":8443",
				Protocol: "https",
				TLS: &TLSConfig{
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
		},
		Routes: []RouteConfig{
			{
				ID:          "api",
				Host:        "api.example.com",
				Path:        "/api/*",
				Methods:     []string{"GET", "POST"},
				Headers:     map[string]string{"X-Custom": "value"},
				QueryParams: map[string]string{"version": "v1"},
				Upstream:    "backend",
				Plugins:     []string{"auth", "ratelimit"},
				StripPrefix: true,
				Timeout:     "30s",
				Priority:    100,
			},
		},
		Upstreams: []UpstreamConfig{
			{
				Name:         "backend",
				Endpoints:    []string{"localhost:9090", "localhost:9091"},
				LoadBalancer: "round_robin",
				HealthCheck: HealthCheckConfig{
					Path:               "/health",
					Interval:           "10s",
					Timeout:            "5s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 3,
				},
				CircuitBreaker: CircuitConfig{
					FailureThreshold: 5,
					SuccessThreshold: 3,
					Timeout:          "30s",
				},
				Retry: RetryConfig{
					MaxRetries:     3,
					BackoffBase:    "100ms",
					BackoffMax:     "5s",
					RetryableCodes: []int{500, 502, 503},
				},
			},
		},
		Plugins: []PluginConfig{
			{
				Name:        "auth",
				Path:        "/plugins/auth.wasm",
				Phase:       "on_request_headers",
				Priority:    100,
				Config:      map[string]interface{}{"key": "value"},
				MemoryLimit: "10MB",
				Timeout:     "5s",
			},
		},
		Admin: AdminConfig{
			Address: ":9000",
			Enabled: true,
			Auth: AdminAuthConfig{
				Enabled: true,
				Users:   map[string]string{"admin": "hash"},
				Realm:   "Admin",
			},
		},
		Metrics: MetricsConfig{
			Prometheus: PrometheusConfig{
				Enabled: true,
				Path:    "/metrics",
			},
			OpenTelemetry: OpenTelemetryConfig{
				Enabled:  true,
				Endpoint: "localhost:4317",
			},
		},
		RateLimit: RateLimitConfig{
			Enabled:         true,
			Rate:            100,
			Burst:           200,
			CleanupInterval: "1m",
		},
		Tracing: TracingConfig{
			Enabled:      true,
			Endpoint:     "localhost:4317",
			ServiceName:  "gateway",
			SampleRate:   0.1,
			BatchTimeout: "5s",
		},
		CORS: CORSConfig{
			Enabled:          true,
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders:     []string{"Content-Type", "Authorization"},
			ExposeHeaders:    []string{"X-Request-ID"},
			MaxAge:           3600,
			AllowCredentials: true,
		},
		Cache: CacheConfig{
			Enabled:              true,
			MaxSize:              "100MB",
			DefaultTTL:           "5m",
			CleanupInterval:      "1m",
			StaleWhileRevalidate: "30s",
			ExcludedPaths:        []string{"/api/auth/*"},
			IncludedPaths:        []string{"/api/static/*"},
			BypassHeader:         "X-Cache-Bypass",
		},
	}

	// Verify the config was created correctly
	if len(cfg.Listeners) != 2 {
		t.Errorf("expected 2 listeners, got %d", len(cfg.Listeners))
	}

	if cfg.Listeners[1].TLS == nil {
		t.Error("expected TLS config for https listener")
	}

	if cfg.Admin.Auth.Realm != "Admin" {
		t.Errorf("expected realm 'Admin', got %s", cfg.Admin.Auth.Realm)
	}

	if cfg.RateLimit.Rate != 100 {
		t.Errorf("expected rate 100, got %f", cfg.RateLimit.Rate)
	}

	if cfg.Tracing.SampleRate != 0.1 {
		t.Errorf("expected sample rate 0.1, got %f", cfg.Tracing.SampleRate)
	}

	if len(cfg.CORS.AllowMethods) != 4 {
		t.Errorf("expected 4 allow methods, got %d", len(cfg.CORS.AllowMethods))
	}

	if cfg.Cache.MaxSize != "100MB" {
		t.Errorf("expected max size '100MB', got %s", cfg.Cache.MaxSize)
	}
}

func TestFullConfigParsing(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":8080"
    protocol: http
  - name: https
    address: ":8443"
    protocol: https
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem

routes:
  - id: api
    host: api.example.com
    path: /api/*
    methods:
      - GET
      - POST
    upstream: backend
    plugins:
      - auth
    strip_prefix: true
    timeout: 30s
    priority: 100

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3
    circuit_breaker:
      failure_threshold: 5
      success_threshold: 3
      timeout: 30s
    retry:
      max_retries: 3
      backoff_base: 100ms
      backoff_max: 5s
      retryable_codes:
        - 500
        - 502
        - 503

plugins:
  - name: auth
    path: /plugins/auth.wasm
    phase: on_request_headers
    priority: 100

admin:
  address: ":9000"
  enabled: true
  auth:
    enabled: true
    users:
      admin: hash123
    realm: Gateway Admin

metrics:
  prometheus:
    enabled: true
    path: /metrics
  opentelemetry:
    enabled: true
    endpoint: localhost:4317

rate_limit:
  enabled: true
  rate: 100
  burst: 200
  cleanup_interval: 1m

tracing:
  enabled: true
  endpoint: localhost:4317
  service_name: gateway
  sample_rate: 0.1
  batch_timeout: 5s

cors:
  enabled: true
  allow_origins:
    - "*"
  allow_methods:
    - GET
    - POST
  allow_headers:
    - Content-Type
  expose_headers:
    - X-Request-ID
  max_age: 3600
  allow_credentials: true

cache:
  enabled: true
  max_size: 100MB
  default_ttl: 5m
  cleanup_interval: 1m
  stale_while_revalidate: 30s
  excluded_paths:
    - /api/auth/*
  bypass_header: X-Cache-Bypass
`
	configPath := createTempConfig(t, content)

	m, err := NewManager(configPath)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer m.Close()

	cfg := m.Get()

	// Test listeners
	if len(cfg.Listeners) != 2 {
		t.Errorf("expected 2 listeners, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[1].TLS == nil {
		t.Error("expected TLS config for https listener")
	}

	// Test routes
	if len(cfg.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].Priority != 100 {
		t.Errorf("expected priority 100, got %d", cfg.Routes[0].Priority)
	}

	// Test upstreams
	if len(cfg.Upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].CircuitBreaker.FailureThreshold != 5 {
		t.Errorf("expected failure threshold 5, got %d", cfg.Upstreams[0].CircuitBreaker.FailureThreshold)
	}

	// Test plugins
	if len(cfg.Plugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(cfg.Plugins))
	}

	// Test admin
	if !cfg.Admin.Enabled {
		t.Error("expected admin to be enabled")
	}
	if cfg.Admin.Auth.Realm != "Gateway Admin" {
		t.Errorf("expected realm 'Gateway Admin', got %s", cfg.Admin.Auth.Realm)
	}

	// Test rate limit
	if cfg.RateLimit.Rate != 100 {
		t.Errorf("expected rate 100, got %f", cfg.RateLimit.Rate)
	}

	// Test tracing
	if cfg.Tracing.ServiceName != "gateway" {
		t.Errorf("expected service name 'gateway', got %s", cfg.Tracing.ServiceName)
	}

	// Test CORS
	if !cfg.CORS.AllowCredentials {
		t.Error("expected allow_credentials to be true")
	}

	// Test cache
	if cfg.Cache.MaxSize != "100MB" {
		t.Errorf("expected max size '100MB', got %s", cfg.Cache.MaxSize)
	}
}
