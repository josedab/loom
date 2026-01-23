# Loom Architecture

This document provides a comprehensive overview of Loom's internal architecture, component interactions, and design decisions.

## Table of Contents

- [Overview](#overview)
- [Component Architecture](#component-architecture)
- [Request Flow](#request-flow)
- [Core Components](#core-components)
- [Plugin System](#plugin-system)
- [Upstream Management](#upstream-management)
- [Configuration System](#configuration-system)
- [Performance Optimizations](#performance-optimizations)

## Overview

Loom is a WASM-first API gateway built in Go using the wazero runtime for WebAssembly execution. It provides high-performance HTTP proxying with WebAssembly plugin support using the Proxy-Wasm ABI.

### Key Design Principles

1. **Zero Dependencies**: Pure Go implementation with no CGO, enabling single-binary deployment
2. **Lock-Free Hot Path**: Atomic operations for request processing to minimize contention
3. **Plugin Isolation**: WASM sandboxing provides memory safety and security
4. **Graceful Operations**: Hot-reload configuration and graceful shutdown support

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Loom API Gateway                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Listener Layer                                │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │   │
│  │  │ HTTP/1.1 │ │  HTTPS   │ │   h2c    │ │  HTTP/3  │ │   gRPC   │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       Middleware Chain                               │   │
│  │  Recovery → RequestID → Metrics → Tracing → RateLimit → CORS → WS   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌───────────────────┐  ┌─────────────────────┐  ┌───────────────────┐     │
│  │   Router          │  │   Plugin Pipeline   │  │   Proxy Handler   │     │
│  │  (Radix Tree)     │→ │   (wazero Runtime)  │→ │                   │     │
│  │  Lock-free reads  │  │   Instance Pooling  │  │   WebSocket/HTTP  │     │
│  └───────────────────┘  └─────────────────────┘  └───────────────────┘     │
│                                                           │                 │
│                                                           ▼                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       Upstream Manager                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │   │
│  │  │Load Balancer│  │Circuit Break│  │Health Check │  │ Conn Pool  │  │   │
│  │  │ RR/Weighted │  │ Open/Closed │  │Active/Pasv  │  │  Shared    │  │   │
│  │  │ LeastConn   │  │ Half-Open   │  │Thresholds   │  │  Transport │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────┐  ┌────────────────────────────────┐  │
│  │         Admin Server             │  │      Configuration Manager     │  │
│  │  Routes, Metrics, Health, Audit  │  │   YAML + fsnotify Hot-Reload   │  │
│  └──────────────────────────────────┘  └────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Request Flow

### Phase 1: Listener Reception
1. Request arrives at configured listener (HTTP/HTTPS/HTTP3/gRPC)
2. TLS termination (if applicable)
3. Protocol upgrade detection (WebSocket, HTTP/2)

### Phase 2: Middleware Processing
Middlewares execute in order:
1. **Recovery**: Panic recovery with stack trace logging
2. **Request ID**: Adds/preserves `X-Request-ID` header
3. **Metrics**: Records request start, captures response metrics
4. **Tracing**: Extracts/injects OpenTelemetry trace context
5. **Rate Limiting**: Token bucket per-client limiting
6. **CORS**: Cross-origin request handling
7. **WebSocket**: Upgrade detection and handling

### Phase 3: Routing
1. **Route Matching**: Radix tree lookup by path
2. **Criteria Filtering**: Host, headers, query params
3. **Priority Selection**: Higher priority routes checked first

### Phase 4: Plugin Execution
Plugins execute in phases:
```
Request Headers → Request Body → [Upstream] → Response Headers → Response Body → Log
```

### Phase 5: Upstream Proxying
1. **Load Balancing**: Select endpoint based on algorithm
2. **Circuit Breaker**: Check if circuit allows request
3. **Retry Logic**: Retry on configured status codes
4. **Connection Pool**: Reuse HTTP connections

### Phase 6: Response
1. Response headers plugin phase
2. Response body plugin phase (reverse order)
3. Log phase (async via worker pool)
4. Client response delivery

## Core Components

### Router (`internal/router`)

The router uses a **radix tree** (compact prefix tree) for efficient path matching.

**Key Features:**
- **Lock-free reads**: Uses `atomic.Value` for snapshot-based access
- **Copy-on-write**: Write operations create new snapshot
- **Priority-based matching**: Routes sorted by priority
- **Path parameters**: `/users/:id` extracts path segments
- **Wildcards**: `/api/*` matches any suffix

**Data Structures:**
```go
type Router struct {
    snapshot atomic.Value  // *routeSnapshot - lock-free reads
    mu       sync.Mutex    // Only protects writes
    notFound atomic.Value  // http.Handler
}

type routeSnapshot struct {
    trees  map[string]*radixNode  // Per-method radix trees
    routes []*Route               // Sorted by priority
}
```

**Match Algorithm:**
1. Get radix tree for HTTP method
2. Traverse tree matching path segments
3. Extract path parameters during traversal
4. Filter by host, headers, query params
5. Return first matching route

### Proxy Handler (`internal/proxy`)

The proxy handler orchestrates request forwarding.

**Components:**
- `Handler`: Main HTTP handler implementing `http.Handler`
- `WebSocketHandler`: WebSocket connection proxying
- `WorkerPool`: Bounded async execution for log phase

**Request Context Flow:**
```go
// Acquire pooled context
reqCtx := plugin.AcquireRequestContext()
defer plugin.ReleaseRequestContext(reqCtx)

// Copy headers to context
for k, v := range r.Header {
    reqCtx.RequestHeaders[k] = v[0]
}

// Execute plugins
result := pipeline.ExecuteRequestPhase(ctx, routeID, phase, reqCtx)

// Apply modified headers back
for k, v := range reqCtx.RequestHeaders {
    r.Header.Set(k, v)
}
```

**Error Mapping:**
| Upstream Error | HTTP Status |
|---------------|-------------|
| ErrNoHealthyEndpoints | 503 Service Unavailable |
| ErrCircuitOpen | 503 Service Unavailable |
| ErrUpstreamNotFound | 502 Bad Gateway |
| context.DeadlineExceeded | 504 Gateway Timeout |
| Default | 502 Bad Gateway |

## Plugin System

### WASM Runtime (`internal/plugin/runtime.go`)

Uses **wazero** - a pure Go WebAssembly runtime with no CGO dependencies.

**Features:**
- **AOT Compilation**: Pre-compiles WASM to machine code
- **Memory Sandboxing**: Configurable memory limits (default: 16MB)
- **Instance Pooling**: Reuses module instances via `sync.Pool`
- **Path Security**: Validates plugin paths against allowed directory

**Runtime Configuration:**
```go
type RuntimeConfig struct {
    MemoryLimitPages int           // WASM memory pages (64KB each)
    ExecutionTimeout time.Duration // Per-invocation timeout
    EnableWASI       bool          // Optional WASI support
    CacheDir         string        // AOT compilation cache
    PluginDir        string        // Restrict plugin loading path
}
```

### Proxy-Wasm ABI (`internal/plugin/proxywasm.go`)

Implements the **Proxy-Wasm ABI** for plugin portability across gateways.

**Host Functions (17 total):**

| Category | Functions |
|----------|-----------|
| Headers | get/add/replace/remove_header_map_value, get/set_header_map_pairs |
| Buffers | get/set_buffer_bytes |
| Properties | get/set_property |
| Metrics | define/increment/record/get_metric |
| HTTP | http_call (async upstream) |
| Response | send_local_response |
| Logging | log |
| Time | get_current_time_nanoseconds |
| Control | set_effective_context, done |

**Security Measures:**
- CRLF injection validation on headers
- Memory bounds checking on all pointer operations
- WASI disabled by default

### Plugin Pipeline (`internal/plugin/pipeline.go`)

Orchestrates plugin execution order.

**Execution Phases:**
```go
const (
    PhaseOnRequestHeaders  ExecutionPhase = iota  // 0
    PhaseOnRequestBody                            // 1
    PhaseOnResponseHeaders                        // 2
    PhaseOnResponseBody                           // 3
    PhaseOnLog                                    // 4
)
```

**Chain Building:**
- Plugins sorted by priority (descending)
- Request phases: forward order (high → low priority)
- Response phases: reverse order (low → high priority)
- Log phase: async via bounded worker pool

**Actions:**
- `ActionContinue`: Proceed to next plugin
- `ActionPause`: Stop processing, send immediate response
- `ActionEndStream`: End stream without response

## Upstream Management

### Manager (`internal/upstream/upstream.go`)

Manages backend connections and request routing.

**Components:**
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

### Load Balancing

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| Round Robin | Sequential rotation | Default, equal distribution |
| Weighted | Proportional by weight | Canary deployments |
| Least Connections | Fewest active connections | Long-lived connections |
| Random | Uniform random selection | Simple, high variance |
| Consistent Hash | Hash-ring based | Session affinity |

**Consistent Hash Details:**
- FNV-1a hash function
- 150 virtual nodes per endpoint
- Binary search for O(log n) lookup
- Header-based key routing for session affinity

### Circuit Breaker (`internal/upstream/circuit.go`)

Three-state machine protecting against cascade failures.

**States:**
```
CLOSED (normal) ─── failures ≥ threshold ───→ OPEN (failing)
                                                    │
                                              timeout elapsed
                                                    │
                                                    ▼
CLOSED ←── successes ≥ threshold ─── HALF-OPEN (testing)
                                         │
                                     any failure
                                         │
                                         ▼
                                       OPEN
```

**Lock-Free Design:**
- Hot path (`Allow()`) uses atomic reads only
- State transitions protected by mutex
- Jittered timeout prevents thundering herd

### Health Checking

**Active Health Checker:**
- Periodic HTTP GET to health endpoint
- Configurable healthy/unhealthy thresholds
- Per-endpoint health status tracking

**Passive Health Checker:**
- Tracks 5xx responses from live traffic
- Sliding window error ratio calculation
- Automatic ejection and recovery

**Outlier Detection:**
- Combines passive checking with recovery
- Respects max ejection percentage
- Gradual traffic ramping during recovery

### Retry Mechanism

**Retry Policy:**
```go
type RetryPolicy struct {
    MaxRetries     int           // Maximum attempts
    BackoffBase    time.Duration // Initial backoff (100ms)
    BackoffMax     time.Duration // Maximum backoff (10s)
    RetryableCodes map[int]bool  // Status codes to retry
    JitterMode     JitterMode    // Jitter strategy
}
```

**Jitter Modes:**
- `JitterNone`: Deterministic exponential backoff
- `JitterFull`: Random 0 to backoff
- `JitterEqual`: backoff/2 + random(0, backoff/2)
- `JitterDecorated`: random(base, prev*3)

**Retry Budget:**
- Prevents retry storms during degradation
- Configurable ratio (default: 20% of requests)
- Minimum retries always allowed (default: 3/sec)

## Configuration System

### Manager (`internal/config/config.go`)

Handles YAML configuration with hot-reload support.

**Loading Process:**
1. Read file with `os.ReadFile()`
2. Unmarshal YAML via `gopkg.in/yaml.v3`
3. Validate configuration (listeners, upstreams, routes)
4. Apply with RWMutex protection

**Hot-Reload:**
- Uses `fsnotify` for file system watching
- 100ms debounce prevents rapid reloads
- Validation before applying changes
- Callbacks notify components of changes

**Thread Safety:**
- `sync.RWMutex` for concurrent access
- Read lock for `Get()` operations
- Write lock only during reload

### Validation Rules

| Component | Requirement |
|-----------|-------------|
| Listeners | At least one with address and protocol |
| Upstreams | Each must have name and endpoints |
| Routes | Each must have path and existing upstream |

## Performance Optimizations

### Lock-Free Patterns

1. **Router**: Atomic snapshot swapping for zero-lock reads
2. **Circuit Breaker**: Atomic counters for failure/success tracking
3. **Endpoint Tracking**: Atomic counters for active connections

### Object Pooling

1. **Request Context**: `sync.Pool` for request state objects
2. **Plugin Instances**: Pool of WASM module instances
3. **Healthy Endpoint Slices**: Pool for load balancer filtering
4. **Gzip Writers**: Pool for compression middleware

### Connection Management

- **Shared Transport**: Single `http.Transport` for all upstreams
- **Connection Limits**: 1000 global, 100 per-host idle connections
- **Idle Timeout**: 90 seconds for connection reuse
- **HTTP/2 Support**: Forced attempt for reduced latency

### Worker Pool

The log phase uses a bounded worker pool:
- Default: 10 workers, 1000 task queue
- Non-blocking submission with drop-on-full
- Prevents unbounded goroutine creation
- Graceful shutdown waits for in-flight tasks

### Memory Efficiency

- **Lazy Body Buffering**: Only buffer when plugins need inspection
- **Streaming Support**: Chunked processing for large bodies
- **Size Limits**: Configurable maximum body sizes
- **Sharded Cache**: 256 shards for reduced lock contention

## File Reference

| Component | Location |
|-----------|----------|
| Entry Point | `cmd/loom/main.go` |
| Server Orchestration | `internal/server/server.go` |
| Configuration | `internal/config/config.go` |
| Router | `internal/router/router.go` |
| Proxy Handler | `internal/proxy/handler.go` |
| WebSocket | `internal/proxy/websocket.go` |
| Worker Pool | `internal/proxy/workerpool.go` |
| Plugin Runtime | `internal/plugin/runtime.go` |
| Proxy-Wasm ABI | `internal/plugin/proxywasm.go` |
| Plugin Pipeline | `internal/plugin/pipeline.go` |
| Body Buffering | `internal/plugin/buffer.go` |
| Upstream Manager | `internal/upstream/upstream.go` |
| Circuit Breaker | `internal/upstream/circuit.go` |
| Health Checker | `internal/upstream/health.go` |
| Service Discovery | `internal/upstream/discovery.go` |
| Listener Manager | `internal/listener/listener.go` |
| Middleware | `internal/middleware/*.go` |
| Admin API | `internal/admin/admin.go` |
| Metrics | `internal/metrics/prometheus.go` |
| Tracing | `internal/tracing/otel.go` |
| Cache | `internal/cache/*.go` |
| Canary | `internal/canary/*.go` |
| Shadow | `internal/shadow/*.go` |
