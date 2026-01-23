# Loom API Reference

Complete Go API reference for all internal packages.

## Table of Contents

- [Package Overview](#package-overview)
- [router](#router)
- [proxy](#proxy)
- [upstream](#upstream)
- [plugin](#plugin)
- [config](#config)
- [middleware](#middleware)
- [cache](#cache)
- [canary](#canary)
- [shadow](#shadow)
- [metrics](#metrics)
- [tracing](#tracing)
- [admin](#admin)
- [listener](#listener)

## Package Overview

| Package | Import Path | Purpose |
|---------|-------------|---------|
| router | `internal/router` | URL routing with radix tree |
| proxy | `internal/proxy` | HTTP proxy handler |
| upstream | `internal/upstream` | Backend management |
| plugin | `internal/plugin` | WASM plugin runtime |
| config | `internal/config` | Configuration loading |
| middleware | `internal/middleware` | HTTP middleware |
| cache | `internal/cache` | Response caching |
| canary | `internal/canary` | Canary deployments |
| shadow | `internal/shadow` | Traffic shadowing |
| metrics | `internal/metrics` | Prometheus metrics |
| tracing | `internal/tracing` | OpenTelemetry tracing |
| admin | `internal/admin` | Admin API server |
| listener | `internal/listener` | Protocol listeners |

---

## router

URL routing with radix tree for efficient path matching.

### Types

#### Router

```go
type Router struct {
    // unexported fields
}
```

Main router with lock-free reads and copy-on-write updates.

#### Route

```go
type Route struct {
    ID          string            // Unique identifier
    Host        string            // Host header matching
    Path        string            // URL path pattern
    Methods     []string          // Allowed HTTP methods
    Headers     map[string]string // Required headers
    QueryParams map[string]string // Required query params
    Upstream    string            // Target upstream
    Plugins     []string          // Plugin chain
    StripPrefix bool              // Remove prefix
    Timeout     time.Duration     // Request timeout
    Priority    int               // Match priority
    Metadata    map[string]string // Custom metadata
}
```

#### MatchResult

```go
type MatchResult struct {
    Route  *Route            // Matched route
    Params map[string]string // Extracted path parameters
}
```

### Functions

```go
// New creates a new Router with empty routing table.
func New() *Router

// Configure replaces all routes from configuration.
func (r *Router) Configure(configs []config.RouteConfig) error

// Match finds the route matching the request.
// Returns nil if no route matches.
func (r *Router) Match(req *http.Request) *MatchResult

// GetRoutes returns all configured routes.
func (r *Router) GetRoutes() []*Route

// GetRoute returns a route by ID.
func (r *Router) GetRoute(id string) (*Route, bool)

// AddRoute adds a single route dynamically.
func (r *Router) AddRoute(cfg config.RouteConfig) error

// UpdateRoute replaces an existing route.
func (r *Router) UpdateRoute(id string, cfg config.RouteConfig) error

// DeleteRoute removes a route by ID.
func (r *Router) DeleteRoute(id string) error

// SetNotFoundHandler sets the 404 handler.
func (r *Router) SetNotFoundHandler(handler http.Handler)

// NotFoundHandler returns the 404 handler.
func (r *Router) NotFoundHandler() http.Handler
```

### Errors

```go
var (
    ErrRouteNotFound      = errors.New("route not found")
    ErrRouteAlreadyExists = errors.New("route already exists")
)
```

---

## proxy

HTTP proxy handler and middleware.

### Types

#### Handler

```go
type Handler struct {
    // unexported fields
}
```

Main proxy handler implementing `http.Handler`.

#### HandlerOption

```go
type HandlerOption func(*Handler)
```

Functional option for Handler configuration.

#### WebSocketHandler

```go
type WebSocketHandler struct {
    // unexported fields
}
```

WebSocket connection proxy.

#### WorkerPool

```go
type WorkerPool struct {
    // unexported fields
}
```

Bounded worker pool for async task execution.

#### WorkerPoolConfig

```go
type WorkerPoolConfig struct {
    Workers   int // Number of workers (default: 10)
    QueueSize int // Queue buffer size (default: 1000)
}
```

### Functions

```go
// NewHandler creates a proxy handler.
func NewHandler(
    r *router.Router,
    u *upstream.Manager,
    p *plugin.Pipeline,
    m *metrics.Metrics,
    opts ...HandlerOption,
) *Handler

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)

// Close shuts down the handler.
func (h *Handler) Close()

// WithMaxResponseBodySize sets maximum response body size.
func WithMaxResponseBodySize(size int64) HandlerOption

// WithLogWorkerPool sets custom worker pool.
func WithLogWorkerPool(pool *WorkerPool) HandlerOption
```

#### WebSocket Functions

```go
// NewWebSocketHandler creates a WebSocket handler.
func NewWebSocketHandler() *WebSocketHandler

// IsWebSocket checks if request is WebSocket upgrade.
func IsWebSocket(r *http.Request) bool

// Proxy proxies a WebSocket connection.
func (h *WebSocketHandler) Proxy(w http.ResponseWriter, r *http.Request, upstream string) error

// WebSocketMiddleware adds WebSocket support.
func WebSocketMiddleware(ws *WebSocketHandler, getUpstream func(*http.Request) string) func(http.Handler) http.Handler
```

#### Middleware Functions

```go
// MiddlewareChain composes multiple middleware.
func MiddlewareChain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler

// RecoveryMiddleware recovers from panics.
func RecoveryMiddleware() func(http.Handler) http.Handler

// RequestIDMiddleware adds X-Request-ID header.
func RequestIDMiddleware() func(http.Handler) http.Handler

// CORSMiddleware adds CORS headers.
func CORSMiddleware(allowOrigin string) func(http.Handler) http.Handler
```

#### WorkerPool Functions

```go
// DefaultWorkerPoolConfig returns sensible defaults.
func DefaultWorkerPoolConfig() WorkerPoolConfig

// NewWorkerPool creates a bounded worker pool.
func NewWorkerPool(cfg WorkerPoolConfig) *WorkerPool

// Submit adds a task (non-blocking).
func (wp *WorkerPool) Submit(task func()) bool

// SubmitWait adds a task with blocking.
func (wp *WorkerPool) SubmitWait(ctx context.Context, task func()) bool

// Stop gracefully shuts down the pool.
func (wp *WorkerPool) Stop()

// Pending returns queued task count.
func (wp *WorkerPool) Pending() int
```

---

## upstream

Backend service management with load balancing, health checking, and circuit breaking.

### Types

#### Manager

```go
type Manager struct {
    // unexported fields
}
```

Manages upstreams and request routing.

#### Upstream

```go
type Upstream struct {
    Name         string
    Endpoints    []*Endpoint
    LoadBalancer LoadBalancer
    Circuit      *CircuitBreaker
    RetryPolicy  *RetryPolicy
    RetryBudget  *RetryBudget
    Bulkhead     *Bulkhead
}
```

#### Endpoint

```go
type Endpoint struct {
    Address string
    Weight  int
    // unexported atomic fields
}
```

#### LoadBalancer

```go
type LoadBalancer interface {
    Select(endpoints []*Endpoint) *Endpoint
}
```

#### CircuitBreaker

```go
type CircuitBreaker struct {
    // unexported fields
}
```

Three-state circuit breaker (Closed, Open, Half-Open).

#### HealthChecker

```go
type HealthChecker struct {
    // unexported fields
}
```

Active health checking.

#### RetryPolicy

```go
type RetryPolicy struct {
    MaxRetries     int
    BackoffBase    time.Duration
    BackoffMax     time.Duration
    RetryableCodes map[int]bool
    JitterMode     JitterMode
}
```

#### Bulkhead

```go
type Bulkhead struct {
    // unexported fields
}
```

Concurrency limiter.

### Functions

```go
// NewManager creates an upstream manager.
func NewManager() *Manager

// Configure loads upstreams from configuration.
func (m *Manager) Configure(configs []config.UpstreamConfig) error

// ProxyRequest forwards a request to an upstream.
func (m *Manager) ProxyRequest(ctx context.Context, upstream string, req *http.Request) (*http.Response, error)

// GetUpstream returns an upstream by name.
func (m *Manager) GetUpstream(name string) (*Upstream, bool)

// GetUpstreams returns all upstreams.
func (m *Manager) GetUpstreams() map[string]*Upstream

// AddUpstream adds an upstream dynamically.
func (m *Manager) AddUpstream(cfg config.UpstreamConfig) error

// UpdateUpstream updates an existing upstream.
func (m *Manager) UpdateUpstream(name string, cfg config.UpstreamConfig) error

// DeleteUpstream removes an upstream.
func (m *Manager) DeleteUpstream(name string) error

// Close shuts down the manager.
func (m *Manager) Close()
```

#### Load Balancers

```go
// NewRoundRobinBalancer creates round-robin load balancer.
func NewRoundRobinBalancer() *RoundRobinBalancer

// NewWeightedBalancer creates weighted load balancer.
func NewWeightedBalancer() *WeightedBalancer

// NewLeastConnBalancer creates least-connections load balancer.
func NewLeastConnBalancer() *LeastConnBalancer

// NewRandomBalancer creates random load balancer.
func NewRandomBalancer() *RandomBalancer

// NewConsistentHashBalancer creates consistent-hash load balancer.
func NewConsistentHashBalancer(replicas int) *ConsistentHashBalancer

// SelectWithKey selects endpoint by hash key.
func (b *ConsistentHashBalancer) SelectWithKey(endpoints []*Endpoint, key string) *Endpoint
```

#### Circuit Breaker

```go
// NewCircuitBreaker creates a circuit breaker.
func NewCircuitBreaker(cfg CircuitConfig) *CircuitBreaker

// Allow checks if request is allowed.
func (cb *CircuitBreaker) Allow() bool

// RecordSuccess records successful request.
func (cb *CircuitBreaker) RecordSuccess()

// RecordFailure records failed request.
func (cb *CircuitBreaker) RecordFailure()

// State returns current state.
func (cb *CircuitBreaker) State() CircuitState

// Reset resets to closed state.
func (cb *CircuitBreaker) Reset()

// Stats returns statistics.
func (cb *CircuitBreaker) Stats() CircuitStats
```

#### Health Checker

```go
// NewHealthChecker creates a health checker.
func NewHealthChecker(manager *Manager) *HealthChecker

// Configure sets up health checks.
func (hc *HealthChecker) Configure(configs []config.UpstreamConfig)

// Start begins health checking.
func (hc *HealthChecker) Start(ctx context.Context)

// Stop halts health checking.
func (hc *HealthChecker) Stop()

// IsHealthy returns endpoint health status.
func (hc *HealthChecker) IsHealthy(upstream, endpoint string) bool
```

### Errors

```go
var (
    ErrNoHealthyEndpoints    = errors.New("no healthy endpoints available")
    ErrCircuitOpen           = errors.New("circuit breaker is open")
    ErrUpstreamNotFound      = errors.New("upstream not found")
    ErrUpstreamAlreadyExists = errors.New("upstream already exists")
    ErrBulkheadFull          = errors.New("bulkhead is full")
    ErrBulkheadTimeout       = errors.New("bulkhead timeout")
)
```

---

## plugin

WASM plugin runtime with Proxy-Wasm ABI support.

### Types

#### Runtime

```go
type Runtime struct {
    // unexported fields
}
```

WASM runtime using wazero.

#### RuntimeConfig

```go
type RuntimeConfig struct {
    MemoryLimitPages int           // Memory pages (64KB each)
    ExecutionTimeout time.Duration // Per-invocation timeout
    EnableWASI       bool          // Enable WASI
    CacheDir         string        // Compilation cache
    PluginDir        string        // Allowed plugin directory
}
```

#### Pipeline

```go
type Pipeline struct {
    // unexported fields
}
```

Plugin execution orchestrator.

#### RequestContext

```go
type RequestContext struct {
    RequestHeaders   map[string]string
    RequestBody      []byte
    RequestBodyBuf   *BodyBuffer
    RequestTrailers  map[string]string
    ResponseHeaders  map[string]string
    ResponseBody     []byte
    ResponseBodyBuf  *BodyBuffer
    ResponseTrailers map[string]string
    Properties       map[string][]byte
    PluginConfig     []byte
}
```

#### BodyBuffer

```go
type BodyBuffer struct {
    // unexported fields
}
```

Request/response body buffer.

#### ExecutionPhase

```go
type ExecutionPhase int

const (
    PhaseOnRequestHeaders  ExecutionPhase = iota
    PhaseOnRequestBody
    PhaseOnResponseHeaders
    PhaseOnResponseBody
    PhaseOnLog
)
```

### Functions

```go
// NewRuntime creates a WASM runtime.
func NewRuntime(ctx context.Context, cfg RuntimeConfig) (*Runtime, error)

// Configure loads plugins from configuration.
func (r *Runtime) Configure(ctx context.Context, configs []config.PluginConfig) error

// LoadPlugin loads a single plugin.
func (r *Runtime) LoadPlugin(ctx context.Context, cfg config.PluginConfig) error

// UnloadPlugin removes a plugin.
func (r *Runtime) UnloadPlugin(name string) error

// ExecutePlugin runs a plugin phase.
func (r *Runtime) ExecutePlugin(ctx context.Context, name string, phase ExecutionPhase, reqCtx *RequestContext) (Action, error)

// Close shuts down the runtime.
func (r *Runtime) Close(ctx context.Context) error
```

#### Pipeline Functions

```go
// NewPipeline creates a plugin pipeline.
func NewPipeline(runtime *Runtime) *Pipeline

// BuildChain builds plugin chain for a route.
func (p *Pipeline) BuildChain(routeID string, plugins []string) error

// ExecuteRequestPhase runs request-phase plugins.
func (p *Pipeline) ExecuteRequestPhase(ctx context.Context, routeID string, phase ExecutionPhase, reqCtx *RequestContext) (Action, error)

// ExecuteResponsePhase runs response-phase plugins (reverse order).
func (p *Pipeline) ExecuteResponsePhase(ctx context.Context, routeID string, phase ExecutionPhase, reqCtx *RequestContext) (Action, error)

// ClearChains removes all chains.
func (p *Pipeline) ClearChains()

// Middleware returns HTTP middleware.
func (p *Pipeline) Middleware() func(http.Handler) http.Handler
```

#### Context Pool

```go
// AcquireRequestContext gets context from pool.
func AcquireRequestContext() *RequestContext

// ReleaseRequestContext returns context to pool.
func ReleaseRequestContext(ctx *RequestContext)
```

---

## config

YAML configuration loading with hot-reload support.

### Types

#### Config

```go
type Config struct {
    Listeners []ListenerConfig
    Routes    []RouteConfig
    Upstreams []UpstreamConfig
    Plugins   []PluginConfig
    Admin     AdminConfig
    Metrics   MetricsConfig
    RateLimit RateLimitConfig
    Tracing   TracingConfig
    CORS      CORSConfig
    Cache     CacheConfig
    AIGateway AIGatewayConfig
}
```

#### Manager

```go
type Manager struct {
    // unexported fields
}
```

Configuration manager with hot-reload.

### Functions

```go
// NewManager creates a configuration manager.
func NewManager(configPath string) (*Manager, error)

// Get returns current configuration.
func (m *Manager) Get() *Config

// OnChange registers reload callback.
func (m *Manager) OnChange(cb func(*Config))

// Close stops the manager.
func (m *Manager) Close()

// ParseDuration parses duration string.
func ParseDuration(s string, defaultVal time.Duration) time.Duration

// ParseSize parses size string (e.g., "100MB").
func ParseSize(s string, defaultVal int64) int64
```

---

## middleware

HTTP middleware implementations.

### Authentication

```go
// APIKeyMiddleware validates API keys.
func APIKeyMiddleware(cfg APIKeyConfig) func(http.Handler) http.Handler

// BasicAuthMiddleware validates Basic auth.
func BasicAuthMiddleware(cfg BasicAuthConfig) func(http.Handler) http.Handler

// GetAPIKeyInfo returns key info from context.
func GetAPIKeyInfo(ctx context.Context) *APIKeyInfo
```

### Rate Limiting

```go
// RateLimitMiddleware applies rate limiting.
func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter

// NewTrustedProxyExtractor creates IP extractor.
func NewTrustedProxyExtractor(trustedCIDRs []string) *TrustedProxyExtractor

// NewPerRouteRateLimiter creates per-route limiter.
func NewPerRouteRateLimiter() *PerRouteRateLimiter
```

### Other Middleware

```go
// CompressionMiddleware adds gzip compression.
func CompressionMiddleware(cfg CompressionConfig) func(http.Handler) http.Handler

// SecurityHeadersMiddleware adds security headers.
func SecurityHeadersMiddleware(cfg SecurityConfig) func(http.Handler) http.Handler

// LoggingMiddleware adds access logging.
func LoggingMiddleware(cfg LoggingConfig) func(http.Handler) http.Handler

// BodyLimitMiddleware limits request body size.
func BodyLimitMiddleware(cfg BodyLimitConfig) func(http.Handler) http.Handler

// CORSMiddleware handles CORS.
func CORSMiddleware(cfg CORSConfig) func(http.Handler) http.Handler

// MTLSMiddleware validates client certificates.
func MTLSMiddleware(cfg MTLSConfig) func(http.Handler) http.Handler

// HTTP3Advertise advertises HTTP/3 support.
func HTTP3Advertise(cfg HTTP3Config) func(http.Handler) http.Handler

// QUIC0RTTMiddleware protects against 0-RTT replay.
func QUIC0RTTMiddleware(cfg QUIC0RTTConfig) func(http.Handler) http.Handler
```

---

## cache

Response caching.

### Types

#### Cache

```go
type Cache struct {
    // unexported fields
}
```

Sharded in-memory cache.

### Functions

```go
// New creates a cache.
func New(cfg Config) *Cache

// Get retrieves a cached response.
func (c *Cache) Get(key string) (*CachedResponse, bool)

// Set stores a response.
func (c *Cache) Set(key string, resp *CachedResponse, ttl time.Duration)

// Delete removes a cached response.
func (c *Cache) Delete(key string)

// Clear removes all entries.
func (c *Cache) Clear()

// Stats returns cache statistics.
func (c *Cache) Stats() Stats

// Middleware returns HTTP caching middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler
```

---

## canary

Canary deployment management.

### Types

#### Manager

```go
type Manager struct {
    // unexported fields
}
```

#### Config

```go
type Config struct {
    RouteID      string
    Targets      []Target
    Sticky       bool
    StickyCookie string
    StickyTTL    time.Duration
    HeaderMatch  *HeaderMatch
}
```

### Functions

```go
// NewManager creates a canary manager.
func NewManager() *Manager

// CreateDeployment creates a canary deployment.
func (m *Manager) CreateDeployment(cfg Config) error

// GetDeployment returns a deployment.
func (m *Manager) GetDeployment(routeID string) (*Deployment, bool)

// UpdateWeights changes target weights.
func (m *Manager) UpdateWeights(routeID string, weights map[string]int) error

// DeleteDeployment removes a deployment.
func (m *Manager) DeleteDeployment(routeID string) error

// Middleware returns canary routing middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler
```

---

## shadow

Traffic shadowing (mirroring).

### Types

#### Manager

```go
type Manager struct {
    // unexported fields
}
```

### Functions

```go
// NewManager creates a shadow manager.
func NewManager() *Manager

// Configure sets up shadowing for a route.
func (m *Manager) Configure(cfg Config) error

// GetConfig returns shadow configuration.
func (m *Manager) GetConfig(routeID string) (*Config, bool)

// Middleware returns shadow middleware.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler
```

---

## metrics

Prometheus metrics.

### Types

#### Metrics

```go
type Metrics struct {
    // unexported fields
}
```

### Functions

```go
// New creates a metrics collector.
func New() *Metrics

// RecordRequest records request metrics.
func (m *Metrics) RecordRequest(method, route string, status int, duration time.Duration, size int64)

// RecordUpstreamRequest records upstream metrics.
func (m *Metrics) RecordUpstreamRequest(upstream, endpoint string, status int, duration time.Duration)

// RecordCircuitState records circuit breaker state.
func (m *Metrics) RecordCircuitState(upstream string, state int)

// RecordPluginDuration records plugin execution time.
func (m *Metrics) RecordPluginDuration(plugin, phase string, duration time.Duration)

// Handler returns Prometheus metrics handler.
func (m *Metrics) Handler() http.Handler

// Middleware returns metrics middleware.
func (m *Metrics) Middleware() func(http.Handler) http.Handler
```

---

## tracing

OpenTelemetry distributed tracing.

### Types

#### Provider

```go
type Provider struct {
    // unexported fields
}
```

### Functions

```go
// NewProvider creates a tracing provider.
func NewProvider(cfg Config) (*Provider, error)

// Shutdown stops the provider.
func (p *Provider) Shutdown(ctx context.Context) error

// Middleware returns tracing middleware.
func (p *Provider) Middleware() func(http.Handler) http.Handler

// StartSpan creates a new span.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span)

// SpanFromContext returns span from context.
func SpanFromContext(ctx context.Context) trace.Span

// AddEvent adds an event to current span.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue)

// RecordError records an error on current span.
func RecordError(ctx context.Context, err error)
```

---

## admin

Administrative API server.

### Types

#### Server

```go
type Server struct {
    // unexported fields
}
```

### Functions

```go
// NewServer creates an admin server.
func NewServer(cfg Config) *Server

// Start begins serving.
func (s *Server) Start(address string) error

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error
```

---

## listener

Protocol listener management.

### Types

#### Manager

```go
type Manager struct {
    // unexported fields
}
```

### Functions

```go
// NewManager creates a listener manager.
func NewManager() *Manager

// Configure sets up listeners.
func (m *Manager) Configure(configs []config.ListenerConfig) error

// SetHandler sets the HTTP handler.
func (m *Manager) SetHandler(handler http.Handler)

// Start begins listening.
func (m *Manager) Start(ctx context.Context) error

// Shutdown stops all listeners.
func (m *Manager) Shutdown(ctx context.Context) error
```
