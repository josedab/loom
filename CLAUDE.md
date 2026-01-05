# CLAUDE.md - Loom Project Guide

This file provides guidance for AI assistants working with the Loom codebase.

## Project Overview

Loom is a WASM-first API gateway built with Go and wazero. It provides high-performance HTTP proxying with WebAssembly plugin support using the Proxy-Wasm ABI.

## Quick Commands

```bash
# Build the project
go build ./...

# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific package tests
go test -v ./internal/proxy/...

# Run loom
go run ./cmd/loom -config configs/loom.yaml

# Check for issues
go vet ./...
```

## Project Structure

```
loom/
├── cmd/loom/              # Application entry point
│   └── main.go           # CLI with -config and -log-level flags
├── configs/
│   └── loom.yaml         # Example configuration
├── internal/
│   ├── admin/            # Admin API server (metrics, routes, upstreams)
│   ├── cache/            # High-performance response caching
│   │   ├── cache.go      # Sharded in-memory cache with TTL
│   │   └── middleware.go # Caching middleware with stale-while-revalidate
│   ├── canary/           # Canary deployments and traffic splitting
│   │   ├── canary.go     # Weighted routing, header-based targeting
│   │   └── middleware.go # Canary middleware with sticky sessions
│   ├── config/           # YAML configuration loading and hot-reload
│   ├── listener/         # HTTP/HTTPS/HTTP3/gRPC listener management
│   ├── metrics/          # Prometheus metrics integration
│   ├── middleware/       # HTTP middleware components
│   │   ├── auth.go       # API key and Basic auth
│   │   ├── bodylimit.go  # Request body size limiting
│   │   ├── compression.go # Gzip compression
│   │   ├── http3.go      # HTTP/3 Alt-Svc advertisement
│   │   ├── logging.go    # Access logging with slog
│   │   ├── ratelimit.go  # Token bucket rate limiting
│   │   └── security.go   # Security headers (HSTS, CSP, etc.)
│   ├── plugin/           # WASM plugin runtime
│   │   ├── runtime.go    # Wazero WASM runtime
│   │   ├── pipeline.go   # Plugin execution pipeline
│   │   ├── proxywasm.go  # Proxy-Wasm ABI implementation
│   │   └── buffer.go     # Body buffering for plugins
│   ├── proxy/            # Core proxy handler
│   │   ├── handler.go    # Main HTTP proxy logic
│   │   └── websocket.go  # WebSocket proxying
│   ├── router/           # Radix tree URL router
│   │   └── router.go     # Path matching, host-based routing
│   ├── server/           # Loom server orchestration
│   │   └── server.go     # Startup, shutdown, hot-reload
│   ├── shadow/           # Request shadowing (traffic mirroring)
│   │   ├── shadow.go     # Fire-and-forget traffic mirroring
│   │   └── middleware.go # Shadow middleware with percentage sampling
│   ├── tracing/          # OpenTelemetry integration
│   │   └── otel.go       # Distributed tracing
│   └── upstream/         # Backend service management
│       ├── upstream.go   # Load balancing, connection pooling
│       ├── health.go     # Health checking
│       └── circuit.go    # Circuit breaker pattern
└── go.mod
```

## Key Patterns

### Configuration API

Use `config.RouteConfig` and `config.UpstreamConfig` for configuring routes and upstreams:

```go
// Routes use r.Configure() not r.AddRoute()
r := router.New()
r.Configure([]config.RouteConfig{
    {ID: "api", Path: "/api/*", Upstream: "backend"},
})

// Upstreams use u.Configure()
u := upstream.NewManager()
u.Configure([]config.UpstreamConfig{
    {Name: "backend", Endpoints: []string{"localhost:8080"}},
})
```

### Upstream Endpoints

Endpoints are specified as `host:port` without scheme:

```go
// Correct
Endpoints: []string{"api.internal:8080", "api2.internal:8080"}

// Wrong - will cause "http://http://..." URL parsing errors
Endpoints: []string{"http://api.internal:8080"}
```

### Middleware Pattern

All middleware follows the standard Go pattern:

```go
func MyMiddleware(cfg Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Pre-processing
            next.ServeHTTP(w, r)
            // Post-processing
        })
    }
}
```

### Plugin Pipeline

Plugins execute in phases: `on_request_headers`, `on_request_body`, `on_response_headers`, `on_response_body`, `on_log`.

```go
p := plugin.NewPipeline(runtime) // runtime can be nil for no plugins
result, err := p.ExecuteRequestPhase(ctx, routeID, phase, reqCtx)
```

## Testing Patterns

### HTTP Handler Tests

```go
func TestHandler(t *testing.T) {
    // Create test backend
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    defer backend.Close()

    // Extract host:port for upstream config
    hostPort := getHostPort(backend.URL) // strips http:// prefix

    // Setup components
    r := router.New()
    u := upstream.NewManager()
    p := plugin.NewPipeline(nil)
    m := metrics.New()

    u.Configure([]config.UpstreamConfig{{Name: "test", Endpoints: []string{hostPort}}})
    r.Configure([]config.RouteConfig{{ID: "test", Path: "/api/*", Upstream: "test"}})

    handler := proxy.NewHandler(r, u, p, m)

    req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)

    // Assertions...
}
```

### Helper for extracting host:port from URL

```go
func getHostPort(serverURL string) string {
    u, _ := url.Parse(serverURL)
    return u.Host
}
```

## Important Files

| File | Purpose |
|------|---------|
| `internal/config/config.go` | All configuration structs |
| `internal/proxy/handler.go` | Main proxy request handling |
| `internal/router/router.go` | URL routing with radix tree |
| `internal/upstream/upstream.go` | Backend management, load balancing |
| `internal/server/server.go` | Server startup and orchestration |

## Configuration Reference

See `configs/loom.yaml` for a complete example. Key sections:

- `listeners`: HTTP/HTTPS/HTTP3/gRPC endpoints
- `routes`: URL paths to upstream mapping
- `upstreams`: Backend services with health checks
- `plugins`: WASM plugins with Proxy-Wasm ABI
- `admin`: Admin API configuration (with optional auth)
- `rate_limit`: Global rate limiting
- `tracing`: OpenTelemetry configuration
- `cors`: CORS headers configuration
- `cache`: Response caching with TTL

## Advanced Features

### HTTP/3 (QUIC) Support

Loom supports HTTP/3 over QUIC for reduced latency and better performance:

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

HTTP/3 provides:
- 0-RTT connection establishment
- No head-of-line blocking
- Connection migration (seamless network switches)

### Response Caching

High-performance sharded cache with stale-while-revalidate:

```go
c := cache.New(cache.Config{
    MaxSize:              100 * 1024 * 1024, // 100MB
    DefaultTTL:           5 * time.Minute,
    ShardCount:           256,
    StaleWhileRevalidate: 30 * time.Second,
})

handler := cache.Middleware(cache.MiddlewareConfig{
    Cache:         c,
    DefaultTTL:    5 * time.Minute,
    BypassHeader:  "X-Cache-Bypass",
    ExcludedPaths: []string{"/api/auth/*"},
})(proxyHandler)
```

### Canary Deployments

Weighted traffic splitting for gradual rollouts:

```go
m := canary.NewManager()

m.CreateDeployment(canary.Config{
    RouteID: "api",
    Targets: []canary.Target{
        {Name: "stable", Upstream: "backend-v1", Weight: 90},
        {Name: "canary", Upstream: "backend-v2", Weight: 10},
    },
    Sticky:       true,          // Sticky sessions via cookie
    StickyCookie: "canary-session",
    HeaderMatch: &canary.HeaderMatch{
        Header: "X-Canary",
        Values: map[string]string{"true": "canary"},
    },
})

// Gradual rollout
rollout := canary.NewAutoRollout(m, "api", "canary", "stable")
rollout.Advance()  // 1% -> 5% -> 25% -> 50% -> 100%
rollout.Complete() // Promote canary to 100%
```

### Request Shadowing

Mirror live traffic to test services:

```go
m := shadow.NewManager()

m.Configure(shadow.Config{
    RouteID: "api",
    Targets: []shadow.Target{
        {Name: "test-v2", Address: "test-backend:8080", Percentage: 10},
    },
    MaxConcurrent: 100,
})

handler := shadow.Middleware(shadow.MiddlewareConfig{
    Manager:     m,
    RouteIDFunc: func(r *http.Request) string { return "api" },
})(proxyHandler)
```

Shadow requests are fire-and-forget and don't affect the primary response.

## Dependencies

- **wazero**: Pure Go WebAssembly runtime (no CGO)
- **quic-go**: HTTP/3 and QUIC implementation
- **prometheus/client_golang**: Metrics
- **fsnotify**: Config file watching for hot-reload
- **golang.org/x/net**: HTTP/2, WebSocket support

## Common Issues

1. **502 Bad Gateway in tests**: Check that upstream endpoints don't include `http://` prefix
2. **Route not matching**: Verify path patterns use `/*` for wildcards, check host-based routing
3. **Plugin not executing**: Ensure plugin phase matches when it should run
4. **Circuit breaker open**: Check failure thresholds and backend health

## Code Style

- Use `slog` for structured logging
- Error wrapping with `fmt.Errorf("context: %w", err)`
- Context propagation through all async operations
- Interfaces defined at consumer, not provider
- Table-driven tests preferred
