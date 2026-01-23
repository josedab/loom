# Loom Configuration Reference

Complete reference for all Loom configuration options.

## Table of Contents

- [Configuration File](#configuration-file)
- [Listeners](#listeners)
- [Routes](#routes)
- [Upstreams](#upstreams)
- [Plugins](#plugins)
- [Admin API](#admin-api)
- [Metrics](#metrics)
- [Rate Limiting](#rate-limiting)
- [Tracing](#tracing)
- [CORS](#cors)
- [Cache](#cache)
- [AI Gateway](#ai-gateway)

## Configuration File

Loom uses YAML configuration. By default, it looks for `loom.yaml` in the current directory.

```bash
# Specify custom config path
loom -config /path/to/config.yaml

# Set log level
loom -config config.yaml -log-level debug
```

### Hot Reload

Configuration changes are automatically detected and applied without restart. The reload process:

1. Watches config file for changes (100ms debounce)
2. Validates new configuration
3. Applies changes atomically
4. Logs success/failure

**Reloadable Components:**
- Routes
- Upstreams
- Plugins
- Health checks

**Non-Reloadable (requires restart):**
- Listeners (address, protocol, TLS)
- Admin server address

## Listeners

Configure network listeners for incoming traffic.

```yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http

  - name: https
    address: ":8443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem

  - name: h2c
    address: ":8081"
    protocol: h2c  # HTTP/2 cleartext

  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem

  - name: grpc
    address: ":9000"
    protocol: grpc

  - name: grpcs
    address: ":9443"
    protocol: grpcs
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
```

### Listener Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique listener identifier |
| `address` | string | Yes | Listen address (e.g., `:8080`, `0.0.0.0:8080`) |
| `protocol` | string | Yes | Protocol type (see below) |
| `tls` | object | For HTTPS/HTTP3/gRPCS | TLS configuration |

### Protocols

| Protocol | Description | TLS Required |
|----------|-------------|--------------|
| `http` | HTTP/1.1 | No |
| `https` | HTTP/1.1 + HTTP/2 with TLS | Yes |
| `h2c` | HTTP/2 cleartext | No |
| `http3` | HTTP/3 over QUIC | Yes |
| `grpc` | gRPC cleartext | No |
| `grpcs` | gRPC with TLS | Yes |

### TLS Configuration

```yaml
tls:
  cert_file: /path/to/cert.pem    # PEM-encoded certificate
  key_file: /path/to/key.pem      # PEM-encoded private key
```

## Routes

Define URL routing rules.

```yaml
routes:
  - id: api-v1
    host: api.example.com          # Optional: host-based routing
    path: /api/v1/*                # Path pattern (supports wildcards)
    methods: [GET, POST, PUT, DELETE]
    headers:                        # Optional: header matching
      X-API-Version: "1"
    query_params:                   # Optional: query param matching
      version: "1"
    upstream: backend-v1
    plugins:
      - auth
      - rate-limit
    strip_prefix: true             # Remove /api/v1 from upstream request
    timeout: 30s
    priority: 100                  # Higher = matched first

  - id: api-v2
    path: /api/v2/*
    upstream: backend-v2
    priority: 90

  - id: users
    path: /users/:id               # Path parameter extraction
    methods: [GET]
    upstream: users-service

  - id: catchall
    path: /*                       # Wildcard matches everything
    upstream: default
    priority: 1
```

### Route Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | string | Yes | - | Unique route identifier |
| `path` | string | Yes | - | URL path pattern |
| `upstream` | string | Yes | - | Target upstream name |
| `host` | string | No | - | Host header matching |
| `methods` | []string | No | All methods | Allowed HTTP methods |
| `headers` | map | No | - | Required header values |
| `query_params` | map | No | - | Required query parameters |
| `plugins` | []string | No | - | Plugin names to execute |
| `strip_prefix` | bool | No | false | Remove matched prefix |
| `timeout` | duration | No | 30s | Request timeout |
| `priority` | int | No | 0 | Matching priority |

### Path Patterns

| Pattern | Matches | Example |
|---------|---------|---------|
| `/exact` | Exact path only | `/exact` |
| `/api/*` | Any path under /api | `/api/users`, `/api/v1/posts` |
| `/users/:id` | Path parameter | `/users/123` → params["id"]="123" |
| `/users/:id/posts/:postId` | Multiple params | `/users/1/posts/2` |

## Upstreams

Configure backend services.

```yaml
upstreams:
  - name: backend
    endpoints:
      - "api1.internal:8080"       # host:port (no scheme!)
      - "api2.internal:8080"
    load_balancer: round_robin

  - name: weighted-backend
    endpoints:
      - "primary.internal:8080"
      - "secondary.internal:8080"
    load_balancer: weighted
    # Weights defined via endpoint metadata or config

  - name: session-backend
    endpoints:
      - "node1.internal:8080"
      - "node2.internal:8080"
    load_balancer: consistent_hash
    consistent_hash:
      hash_key: X-User-ID          # Header for hashing
      replicas: 150                # Virtual nodes per endpoint

  - name: resilient-backend
    endpoints:
      - "backend1:8080"
      - "backend2:8080"
    load_balancer: least_conn
    health_check:
      path: /health
      interval: 10s
      timeout: 2s
      healthy_threshold: 2
      unhealthy_threshold: 3
    circuit_breaker:
      failure_threshold: 5
      success_threshold: 3
      timeout: 30s
    retry:
      max_retries: 3
      backoff_base: 100ms
      backoff_max: 10s
      retryable_codes: [502, 503, 504]
    bulkhead:
      enabled: true
      max_concurrent: 100
      queue_size: 50
      timeout: 5s
```

### Upstream Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique upstream identifier |
| `endpoints` | []string | Yes | Backend addresses (host:port) |
| `load_balancer` | string | No | Load balancing algorithm |
| `consistent_hash` | object | No | Consistent hash config |
| `health_check` | object | No | Health check config |
| `circuit_breaker` | object | No | Circuit breaker config |
| `retry` | object | No | Retry policy config |
| `bulkhead` | object | No | Concurrency limiting config |
| `service_discovery` | object | No | Dynamic discovery config |

### Load Balancer Options

| Algorithm | Description |
|-----------|-------------|
| `round_robin` | Sequential rotation (default) |
| `weighted` | Weight-based distribution |
| `least_conn` | Fewest active connections |
| `random` | Uniform random selection |
| `consistent_hash` | Hash-ring for session affinity |

### Health Check Configuration

```yaml
health_check:
  path: /health              # Health check endpoint
  interval: 10s              # Check frequency
  timeout: 2s                # Request timeout
  healthy_threshold: 2       # Checks to mark healthy
  unhealthy_threshold: 3     # Checks to mark unhealthy
```

### Circuit Breaker Configuration

```yaml
circuit_breaker:
  failure_threshold: 5       # Failures before opening
  success_threshold: 3       # Successes to close (in half-open)
  timeout: 30s               # Time before half-open
```

**States:**
- **Closed**: Normal operation, requests pass through
- **Open**: Requests fail fast (503)
- **Half-Open**: Limited requests to test recovery

### Retry Configuration

```yaml
retry:
  max_retries: 3             # Maximum retry attempts
  backoff_base: 100ms        # Initial backoff duration
  backoff_max: 10s           # Maximum backoff duration
  retryable_codes:           # Status codes to retry on
    - 502
    - 503
    - 504
```

### Bulkhead Configuration

```yaml
bulkhead:
  enabled: true
  max_concurrent: 100        # Maximum concurrent requests
  queue_size: 50             # Queue size when at capacity
  timeout: 5s                # Maximum wait time for slot
```

### Service Discovery Configuration

```yaml
service_discovery:
  enabled: true
  provider: dns              # dns, consul, kubernetes
  service_name: my-service
  refresh_interval: 30s
```

## Plugins

Configure WASM plugins.

```yaml
plugins:
  - name: rate-limit
    path: /plugins/rate-limit.wasm
    phase: on_request_headers
    priority: 100
    config:
      requests_per_second: 100
      burst: 10
    memory_limit: 16MB
    timeout: 100ms

  - name: auth
    path: /plugins/auth.wasm
    phase: on_request_headers
    priority: 200              # Higher = executes first
    config:
      provider: jwt
      secret: ${JWT_SECRET}    # Environment variable

  - name: transform
    path: /plugins/transform.wasm
    phase: on_response_body
    priority: 50
```

### Plugin Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique plugin identifier |
| `path` | string | Yes | - | Path to .wasm file |
| `phase` | string | No | on_request_headers | Execution phase |
| `priority` | int | No | 0 | Execution order (higher first) |
| `config` | map | No | - | Plugin-specific configuration |
| `memory_limit` | string | No | 16MB | WASM memory limit |
| `timeout` | string | No | 100ms | Execution timeout |

### Plugin Phases

| Phase | Description | Order |
|-------|-------------|-------|
| `on_request_headers` | Before request body | Forward (high→low priority) |
| `on_request_body` | After request received | Forward |
| `on_response_headers` | After upstream response headers | Reverse (low→high priority) |
| `on_response_body` | After upstream response body | Reverse |
| `on_log` | After response sent | Async (background) |

## Admin API

Configure the administrative API.

```yaml
admin:
  enabled: true
  address: ":9091"
  auth:
    enabled: true
    users:
      admin: "$2a$10$..."       # bcrypt hash
    realm: "Loom Admin"
```

### Admin Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable admin API |
| `address` | string | No | :9091 | Listen address |
| `auth.enabled` | bool | No | false | Enable authentication |
| `auth.users` | map | No | - | Username to bcrypt hash |
| `auth.realm` | string | No | Loom Admin | HTTP Basic realm |

### Admin Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Liveness check |
| `/ready` | GET | No | Readiness check |
| `/info` | GET | Yes | Gateway information |
| `/routes` | GET, POST | Yes | List/create routes |
| `/routes/{id}` | GET, PUT, DELETE | Yes | Manage route |
| `/upstreams` | GET, POST | Yes | List/create upstreams |
| `/upstreams/{name}` | GET, PUT, DELETE | Yes | Manage upstream |
| `/plugins` | GET | Yes | List plugins |
| `/plugins/{name}` | GET, DELETE | Yes | Manage plugin |
| `/plugins/{name}/reload` | POST | Yes | Hot-reload plugin |
| `/metrics` | GET | Yes | Prometheus metrics |
| `/config` | GET | Yes | Current configuration |
| `/audit` | GET | Yes | Audit log |
| `/cache/stats` | GET | Yes | Cache statistics |
| `/ratelimit/stats` | GET | Yes | Rate limit statistics |

## Metrics

Configure metrics collection.

```yaml
metrics:
  prometheus:
    enabled: true
    path: /metrics

  opentelemetry:
    enabled: true
    endpoint: "localhost:4317"
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `loom_requests_total` | Counter | method, route, status | Total requests |
| `loom_request_duration_seconds` | Histogram | method, route | Request latency |
| `loom_request_size_bytes` | Histogram | - | Request body size |
| `loom_response_size_bytes` | Histogram | - | Response body size |
| `loom_upstream_requests_total` | Counter | upstream, endpoint, status | Upstream requests |
| `loom_upstream_duration_seconds` | Histogram | upstream, endpoint | Upstream latency |
| `loom_upstream_errors_total` | Counter | upstream, endpoint, error_type | Upstream errors |
| `loom_upstream_health_status` | Gauge | upstream, endpoint | Health (0/1) |
| `loom_active_connections` | Gauge | listener | Active connections |
| `loom_circuit_breaker_state` | Gauge | upstream | State (0/1/2) |
| `loom_plugin_duration_seconds` | Histogram | plugin, phase | Plugin latency |
| `loom_plugin_errors_total` | Counter | plugin, phase | Plugin errors |
| `loom_cache_hits_total` | Counter | - | Cache hits |
| `loom_cache_misses_total` | Counter | - | Cache misses |
| `loom_ratelimit_rejections_total` | Counter | route, key | Rate limit rejections |
| `loom_auth_failures_total` | Counter | method, reason | Auth failures |

## Rate Limiting

Configure global rate limiting.

```yaml
rate_limit:
  enabled: true
  rate: 1000                 # Requests per second
  burst: 100                 # Maximum burst size
  cleanup_interval: 1m       # Bucket cleanup interval
```

### Rate Limit Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable rate limiting |
| `rate` | float | No | 100 | Requests per second |
| `burst` | int | No | 10 | Maximum burst size |
| `cleanup_interval` | duration | No | 5m | Cleanup interval |

**Response Headers:**
- `X-RateLimit-Limit`: Configured rate
- `X-RateLimit-Remaining`: Remaining tokens
- `Retry-After`: Seconds until retry (on 429)

## Tracing

Configure distributed tracing.

```yaml
tracing:
  enabled: true
  endpoint: "localhost:4317"  # OTLP gRPC endpoint
  service_name: "loom-gateway"
  sample_rate: 1.0            # 1.0 = 100% sampling
  batch_timeout: 5s
```

### Tracing Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable tracing |
| `endpoint` | string | No | localhost:4317 | OTLP endpoint |
| `service_name` | string | No | loom | Service name in traces |
| `sample_rate` | float | No | 1.0 | Sampling rate (0.0-1.0) |
| `batch_timeout` | duration | No | 5s | Batch export timeout |

### Span Attributes

| Attribute | Description |
|-----------|-------------|
| `http.request.method` | HTTP method |
| `url.path` | Request path |
| `url.scheme` | http/https |
| `server.address` | Host header |
| `user_agent.original` | User-Agent header |
| `client.address` | Client IP |
| `http.response.status_code` | Response status |

## CORS

Configure Cross-Origin Resource Sharing.

```yaml
cors:
  enabled: true
  allow_origins:
    - "https://example.com"
    - "https://*.example.com"  # Wildcard subdomain
    - "*"                       # Allow all (use carefully)
  allow_methods:
    - GET
    - POST
    - PUT
    - DELETE
    - OPTIONS
  allow_headers:
    - Authorization
    - Content-Type
    - X-Requested-With
  expose_headers:
    - X-Request-ID
  max_age: 86400               # Preflight cache (24 hours)
  allow_credentials: true
```

### CORS Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable CORS |
| `allow_origins` | []string | No | * | Allowed origins |
| `allow_methods` | []string | No | Common methods | Allowed methods |
| `allow_headers` | []string | No | Common headers | Allowed headers |
| `expose_headers` | []string | No | - | Exposed headers |
| `max_age` | int | No | 86400 | Preflight cache (seconds) |
| `allow_credentials` | bool | No | false | Allow credentials |

## Cache

Configure response caching.

```yaml
cache:
  enabled: true
  max_size: 100MB
  default_ttl: 5m
  cleanup_interval: 1m
  stale_while_revalidate: 30s
  excluded_paths:
    - "/api/auth/*"
    - "/api/realtime/*"
  included_paths:
    - "/api/static/*"
  bypass_header: "X-Cache-Bypass"
```

### Cache Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | No | false | Enable caching |
| `max_size` | string | No | 100MB | Maximum cache size |
| `default_ttl` | duration | No | 5m | Default TTL |
| `cleanup_interval` | duration | No | 1m | Cleanup frequency |
| `stale_while_revalidate` | duration | No | 30s | Serve stale during revalidation |
| `excluded_paths` | []string | No | - | Paths to never cache |
| `included_paths` | []string | No | - | Paths to always cache |
| `bypass_header` | string | No | X-Cache-Bypass | Header to skip cache |

### Cache Behavior

- Respects `Cache-Control` headers
- Supports `ETag` and `If-Modified-Since`
- TTL extracted from `s-maxage` > `max-age` > `Expires`
- `Vary` header support for content negotiation

## AI Gateway

Configure AI/LLM provider routing.

```yaml
ai_gateway:
  enabled: true
  providers:
    - name: openai
      provider: openai
      endpoint: "https://api.openai.com/v1"
      api_key: ${OPENAI_API_KEY}
      model: gpt-4
      priority: 1
      rate_limit: 100
      timeout: 30s

    - name: anthropic
      provider: anthropic
      endpoint: "https://api.anthropic.com"
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-3-opus
      priority: 2

    - name: azure
      provider: azure
      endpoint: "https://myorg.openai.azure.com"
      api_key: ${AZURE_OPENAI_KEY}
      model: gpt-4
      priority: 3

  routing_strategy: priority    # priority, round_robin, least_latency

  cache:
    enabled: true
    max_size: 1GB
    default_ttl: 1h
    semantic_matching: true
    similarity_threshold: 0.95

  token_counting: true
  max_tokens_per_request: 4096
  request_timeout: 60s

  prompt_guard:
    enabled: true
    block_on_detection: true
```

### AI Gateway Fields

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable AI gateway |
| `providers` | []object | Provider configurations |
| `routing_strategy` | string | Routing algorithm |
| `cache` | object | Semantic caching config |
| `token_counting` | bool | Enable token accounting |
| `max_tokens_per_request` | int | Token limit per request |
| `request_timeout` | duration | Overall timeout |
| `prompt_guard` | object | Prompt injection protection |

### AI Provider Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Provider identifier |
| `provider` | string | Provider type (openai, anthropic, azure, local) |
| `endpoint` | string | API endpoint URL |
| `api_key` | string | API key (supports ${ENV_VAR}) |
| `model` | string | Default model |
| `priority` | int | Routing priority |
| `weight` | int | Weight for round-robin |
| `rate_limit` | int | Requests per minute |
| `timeout` | duration | Request timeout |
| `headers` | map | Custom headers |

## Duration Format

Durations use Go duration format:

| Unit | Example |
|------|---------|
| Nanoseconds | `100ns` |
| Microseconds | `100us` |
| Milliseconds | `100ms` |
| Seconds | `30s` |
| Minutes | `5m` |
| Hours | `2h` |

**Combined:** `1h30m`, `5m30s`

## Size Format

Sizes use standard units:

| Unit | Example |
|------|---------|
| Bytes | `1024B` |
| Kilobytes | `512KB` |
| Megabytes | `100MB` |
| Gigabytes | `1GB` |

## Environment Variables

Use `${VAR_NAME}` syntax to reference environment variables:

```yaml
upstreams:
  - name: backend
    endpoints:
      - "${BACKEND_HOST}:${BACKEND_PORT}"

plugins:
  - name: auth
    config:
      secret: ${JWT_SECRET}

ai_gateway:
  providers:
    - api_key: ${OPENAI_API_KEY}
```
