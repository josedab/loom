---
sidebar_position: 1
title: Configuration Reference
description: Complete reference for all Loom configuration options.
---

# Configuration Reference

Complete reference for all Loom configuration options.

## Configuration File

Loom uses YAML configuration files. By default, it looks for `loom.yaml` in the current directory.

```bash
# Use specific config file
loom -config /path/to/config.yaml

# Use multiple config files (merged in order)
loom -config base.yaml -config overrides.yaml
```

## Environment Variables

Environment variables can be used in configuration:

```yaml
listeners:
  - name: https
    tls:
      cert_file: ${TLS_CERT_PATH}
      key_file: ${TLS_KEY_PATH}

upstreams:
  - name: backend
    endpoints:
      - ${BACKEND_HOST}:${BACKEND_PORT}
```

## Top-Level Structure

```yaml
# Server configuration
listeners: []
admin: {}

# Routing
routes: []
upstreams: []

# Features
plugins: []
graphql: {}
ai_gateway: {}

# Middleware
rate_limit: {}
cors: {}
cache: {}
tracing: {}

# Advanced
multi_tenancy: {}
chaos: {}
ebpf: {}
```

## Listeners

Configure HTTP/HTTPS/gRPC listeners.

```yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http  # http, https, http3, grpc

  - name: https
    address: ":8443"
    protocol: https
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
      min_version: "1.2"           # TLS 1.2 minimum
      cipher_suites: []            # Default: secure ciphers
      client_auth: none            # none, request, require, verify
      client_ca_file: ""           # For mTLS

  - name: http3
    address: ":8443"
    protocol: http3
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem

  - name: grpc
    address: ":9090"
    protocol: grpc
    grpc:
      max_recv_msg_size: 4MB
      max_send_msg_size: 4MB
```

### Listener Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique listener name |
| `address` | string | required | Listen address (host:port) |
| `protocol` | string | `http` | Protocol: http, https, http3, grpc |
| `tls` | object | - | TLS configuration |
| `read_timeout` | duration | `30s` | Request read timeout |
| `write_timeout` | duration | `30s` | Response write timeout |
| `idle_timeout` | duration | `60s` | Keep-alive idle timeout |
| `max_header_size` | size | `1MB` | Maximum header size |

## Admin

Configure the admin API.

```yaml
admin:
  enabled: true
  address: ":9091"

  # Authentication
  auth:
    type: basic  # none, basic, bearer
    basic:
      username: admin
      password: ${ADMIN_PASSWORD}

  # Endpoints
  endpoints:
    metrics: true
    health: true
    ready: true
    routes: true
    upstreams: true
    plugins: true
```

### Admin Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable admin API |
| `address` | string | `:9091` | Listen address |
| `auth.type` | string | `none` | Auth type: none, basic, bearer |
| `endpoints.*` | bool | `true` | Enable/disable specific endpoints |

## Routes

Configure URL routing.

```yaml
routes:
  - id: api
    path: /api/*
    methods: [GET, POST, PUT, DELETE]
    upstream: backend

    # Optional settings
    strip_prefix: true
    timeout: 30s
    retries: 3

    # Middleware
    rate_limit:
      requests_per_second: 100

    # Headers
    headers:
      request:
        add:
          X-Request-ID: ${uuid}
      response:
        add:
          X-Response-Time: ${response_time}

    # Plugins
    plugins:
      - name: auth
        config:
          required: true
```

### Route Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | required | Unique route identifier |
| `path` | string | required | URL path pattern |
| `methods` | []string | all | Allowed HTTP methods |
| `upstream` | string | required | Target upstream name |
| `host` | string | - | Match specific host |
| `strip_prefix` | bool | `false` | Strip matched prefix |
| `add_prefix` | string | - | Add prefix to forwarded path |
| `timeout` | duration | `30s` | Request timeout |
| `retries` | int | `0` | Retry count |
| `retry_codes` | []int | `[502,503,504]` | Status codes to retry |
| `priority` | int | `0` | Route priority (higher = first) |

### Path Patterns

| Pattern | Description | Example Match |
|---------|-------------|---------------|
| `/api` | Exact match | `/api` |
| `/api/*` | Prefix match | `/api/users`, `/api/orders` |
| `/api/{id}` | Parameter | `/api/123` |
| `/api/{id}/items` | Mixed | `/api/123/items` |

## Upstreams

Configure backend services.

```yaml
upstreams:
  - name: backend
    endpoints:
      - host: api1.internal
        port: 8080
        weight: 100
      - host: api2.internal
        port: 8080
        weight: 100

    # Load balancing
    load_balancing:
      algorithm: round-robin  # round-robin, least-connections, random, ip-hash, consistent-hash

    # Health checks
    health_check:
      enabled: true
      interval: 10s
      timeout: 5s
      path: /health
      healthy_threshold: 2
      unhealthy_threshold: 3

    # Circuit breaker
    circuit_breaker:
      enabled: true
      failure_threshold: 5
      success_threshold: 2
      timeout: 30s

    # Connection pool
    connection:
      max_idle: 100
      max_per_host: 100
      idle_timeout: 90s
```

### Upstream Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique upstream name |
| `endpoints` | []object | required | Backend endpoints |
| `load_balancing.algorithm` | string | `round-robin` | LB algorithm |
| `health_check.enabled` | bool | `false` | Enable health checks |
| `health_check.interval` | duration | `10s` | Check interval |
| `circuit_breaker.enabled` | bool | `false` | Enable circuit breaker |

### Load Balancing Algorithms

| Algorithm | Description |
|-----------|-------------|
| `round-robin` | Sequential distribution |
| `least-connections` | Prefer less loaded backends |
| `random` | Random selection |
| `ip-hash` | Consistent by client IP |
| `consistent-hash` | Consistent hashing with key |

## Plugins

Configure WASM plugins.

```yaml
plugins:
  - name: auth
    path: /etc/loom/plugins/auth.wasm
    phase: on_request_headers

    # Plugin configuration
    config:
      jwt_secret: ${JWT_SECRET}
      required_claims:
        - sub
        - exp

  - name: transform
    path: /etc/loom/plugins/transform.wasm
    phase: on_response_headers
```

### Plugin Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Plugin name |
| `path` | string | required | Path to WASM file |
| `phase` | string | required | Execution phase |
| `config` | object | `{}` | Plugin-specific config |
| `routes` | []string | all | Apply to specific routes |

### Plugin Phases

| Phase | Description |
|-------|-------------|
| `on_request_headers` | After receiving request headers |
| `on_request_body` | After receiving request body |
| `on_response_headers` | After receiving response headers |
| `on_response_body` | After receiving response body |
| `on_log` | After request completes |

## Rate Limiting

Configure rate limiting.

```yaml
rate_limit:
  enabled: true

  # Default limits
  default:
    requests_per_second: 100
    burst: 200

  # Key extraction
  key: ${header:X-API-Key}  # or ${client_ip}, ${jwt:sub}

  # Storage
  store:
    type: memory  # memory, redis
    redis:
      address: redis:6379
      key_prefix: "loom:ratelimit:"

  # Response
  response:
    status: 429
    headers:
      X-RateLimit-Limit: ${limit}
      X-RateLimit-Remaining: ${remaining}
      X-RateLimit-Reset: ${reset}
```

## CORS

Configure Cross-Origin Resource Sharing.

```yaml
cors:
  enabled: true
  allowed_origins:
    - https://example.com
    - https://*.example.com
  allowed_methods:
    - GET
    - POST
    - PUT
    - DELETE
  allowed_headers:
    - Authorization
    - Content-Type
  exposed_headers:
    - X-Request-ID
  allow_credentials: true
  max_age: 86400
```

## Cache

Configure response caching.

```yaml
cache:
  enabled: true

  # Cache storage
  store:
    type: memory  # memory, redis
    max_size: 100MB
    redis:
      address: redis:6379
      key_prefix: "loom:cache:"

  # Default settings
  default_ttl: 5m
  stale_while_revalidate: 30s

  # Cache rules
  rules:
    - match:
        methods: [GET]
        paths: ["/api/products/*"]
      ttl: 1h
      vary: [Accept, Accept-Language]

  # Bypass
  bypass_header: X-Cache-Bypass
  excluded_paths:
    - /api/auth/*
    - /api/user/*
```

## Tracing

Configure distributed tracing.

```yaml
tracing:
  enabled: true
  provider: otlp  # otlp, jaeger, zipkin

  # OTLP exporter
  otlp:
    endpoint: otel-collector:4317
    insecure: false

  # Sampling
  sampling:
    type: ratio  # always, never, ratio, parent
    ratio: 0.1  # 10% of requests

  # Propagation
  propagation:
    - tracecontext  # W3C Trace Context
    - baggage

  # Tags
  tags:
    service.name: loom
    deployment.environment: production
```

## Metrics

Configure Prometheus metrics.

```yaml
metrics:
  enabled: true
  path: /metrics
  port: 9091  # Uses admin port by default

  # Histogram buckets
  buckets:
    latency: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

  # Labels
  labels:
    - route
    - method
    - status

  # Disable specific metrics
  disabled:
    - loom_request_size_bytes
```

## Logging

Configure logging.

```yaml
logging:
  level: info  # debug, info, warn, error
  format: json  # json, text

  # Output
  output: stdout  # stdout, stderr, file
  file:
    path: /var/log/loom/loom.log
    max_size: 100MB
    max_backups: 5
    max_age: 30d

  # Access logging
  access_log:
    enabled: true
    format: combined  # combined, json, custom
    fields:
      - timestamp
      - method
      - path
      - status
      - latency
      - client_ip
      - user_agent
```

## GraphQL

Configure GraphQL gateway.

```yaml
graphql:
  enabled: true

  # Services (federation)
  services:
    - name: users
      url: http://users-service:4000/graphql
    - name: orders
      url: http://orders-service:4000/graphql

  # Security
  security:
    max_depth: 10
    max_complexity: 1000
    introspection: true

  # Subscriptions
  subscriptions:
    enabled: true
    protocol: graphql-transport-ws

  # Caching
  cache:
    enabled: true
    ttl: 5m

  # Persisted queries
  persisted_queries:
    enabled: true
    required: false
```

## AI Gateway

Configure AI/LLM gateway.

```yaml
ai_gateway:
  enabled: true

  # Providers
  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}
      models: [gpt-4, gpt-3.5-turbo]
      priority: 1

    - name: anthropic
      type: anthropic
      api_key: ${ANTHROPIC_API_KEY}
      models: [claude-3-opus, claude-3-sonnet]
      priority: 2

  # Token accounting
  token_accounting:
    enabled: true
    store:
      type: redis
      redis:
        address: redis:6379

  # Semantic caching
  semantic_cache:
    enabled: true
    similarity_threshold: 0.95

  # Security
  security:
    content_filtering: true
    pii_detection: true
    max_tokens_per_request: 4096
```

## Complete Example

```yaml
# Listeners
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

# Admin
admin:
  enabled: true
  address: ":9091"

# Routes
routes:
  - id: api
    path: /api/*
    upstream: backend
    timeout: 30s

  - id: graphql
    path: /graphql
    graphql: true

# Upstreams
upstreams:
  - name: backend
    endpoints:
      - api1.internal:8080
      - api2.internal:8080
    load_balancing:
      algorithm: round-robin
    health_check:
      enabled: true
      interval: 10s
      path: /health

# Middleware
rate_limit:
  enabled: true
  default:
    requests_per_second: 100

cors:
  enabled: true
  allowed_origins: ["*"]

cache:
  enabled: true
  default_ttl: 5m

# Observability
tracing:
  enabled: true
  provider: otlp
  otlp:
    endpoint: otel-collector:4317

logging:
  level: info
  format: json
```

## Next Steps

- **[Admin API](./admin-api)** - API reference
- **[Metrics](./metrics)** - Metrics reference
- **[CLI](./cli)** - Command-line reference
