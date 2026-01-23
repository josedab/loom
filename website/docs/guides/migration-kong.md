---
sidebar_position: 12
title: Migrate from Kong
description: Step-by-step guide for migrating from Kong to Loom.
---

# Migrating from Kong

This guide helps you migrate from Kong Gateway to Loom, covering services, routes, plugins, and upstreams.

## Key Differences

| Aspect | Kong | Loom |
|--------|------|------|
| Configuration | Database + Admin API | YAML file |
| Plugin System | Lua, Go, JavaScript | WASM (Proxy-Wasm) |
| State | Stateful (PostgreSQL/Cassandra) | Stateless |
| Clustering | Database-backed | Load balancer |
| Admin UI | Kong Manager (Enterprise) | CLI + REST API |
| Health Checks | Kong Plus/Enterprise | Built-in (free) |

## Exporting Kong Configuration

First, export your Kong configuration:

```bash
# Export using decK
deck dump -o kong-config.yaml

# Or via Admin API
curl http://localhost:8001/services > services.json
curl http://localhost:8001/routes > routes.json
curl http://localhost:8001/upstreams > upstreams.json
curl http://localhost:8001/plugins > plugins.json
```

## Configuration Mapping

### Services to Upstreams

**Kong:**
```yaml
services:
  - name: user-service
    url: http://users.internal:8080
    connect_timeout: 60000
    read_timeout: 60000
    write_timeout: 60000
    retries: 5
```

**Loom:**
```yaml
upstreams:
  - name: user-service
    endpoints:
      - "users.internal:8080"
    connection:
      timeout: 60s
    retry:
      max_retries: 5
```

### Routes

**Kong:**
```yaml
routes:
  - name: user-routes
    service: user-service
    paths:
      - /users
      - /api/v1/users
    methods:
      - GET
      - POST
    strip_path: true
    preserve_host: false
```

**Loom:**
```yaml
routes:
  - id: users-v1
    path: /users/*
    methods: [GET, POST]
    upstream: user-service
    strip_prefix: true

  - id: users-api-v1
    path: /api/v1/users/*
    methods: [GET, POST]
    upstream: user-service
    strip_prefix: true
    add_prefix: /users
```

### Upstreams with Targets

**Kong:**
```yaml
upstreams:
  - name: api-upstream
    algorithm: round-robin
    healthchecks:
      active:
        healthy:
          interval: 5
          successes: 2
        unhealthy:
          interval: 5
          http_failures: 3
        http_path: /health

targets:
  - upstream: api-upstream
    target: api1.internal:8080
    weight: 100
  - upstream: api-upstream
    target: api2.internal:8080
    weight: 100
```

**Loom:**
```yaml
upstreams:
  - name: api-upstream
    endpoints:
      - host: api1.internal
        port: 8080
        weight: 100
      - host: api2.internal
        port: 8080
        weight: 100
    load_balancer: round_robin
    health_check:
      enabled: true
      path: /health
      interval: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3
```

### Plugin Migration

#### Rate Limiting

**Kong:**
```yaml
plugins:
  - name: rate-limiting
    service: user-service
    config:
      minute: 100
      policy: local
      fault_tolerant: true
      hide_client_headers: false
```

**Loom:**
```yaml
rate_limit:
  enabled: true
  default:
    requests_per_second: 1.67  # 100/minute
    burst: 10
  response:
    headers:
      X-RateLimit-Limit: ${limit}
      X-RateLimit-Remaining: ${remaining}
```

#### JWT Authentication

**Kong:**
```yaml
plugins:
  - name: jwt
    service: user-service
    config:
      secret_is_base64: false
      claims_to_verify:
        - exp
      key_claim_name: iss
```

**Loom:**
```yaml
middleware:
  auth:
    type: jwt
    secret: ${JWT_SECRET}
    algorithms: [HS256]
    required_claims:
      - exp
      - iss
```

Or use a WASM plugin for advanced JWT handling.

#### Key Authentication

**Kong:**
```yaml
plugins:
  - name: key-auth
    service: user-service
    config:
      key_names:
        - apikey
        - X-API-Key
      hide_credentials: true
```

**Loom:**
```yaml
middleware:
  auth:
    type: api_key
    headers:
      - apikey
      - X-API-Key
    hide_credentials: true
    keys:
      - ${API_KEY_1}
      - ${API_KEY_2}
```

#### CORS

**Kong:**
```yaml
plugins:
  - name: cors
    service: user-service
    config:
      origins:
        - https://example.com
      methods:
        - GET
        - POST
      headers:
        - Authorization
        - Content-Type
      max_age: 3600
      credentials: true
```

**Loom:**
```yaml
cors:
  enabled: true
  allowed_origins:
    - https://example.com
  allowed_methods:
    - GET
    - POST
  allowed_headers:
    - Authorization
    - Content-Type
  max_age: 3600
  allow_credentials: true
```

#### Request Transformer

**Kong:**
```yaml
plugins:
  - name: request-transformer
    service: user-service
    config:
      add:
        headers:
          - X-Request-ID:$(uuid)
      remove:
        headers:
          - X-Internal-Header
```

**Loom:**
```yaml
routes:
  - id: users
    path: /users/*
    upstream: user-service
    headers:
      request:
        add:
          X-Request-ID: ${uuid}
        remove:
          - X-Internal-Header
```

#### Response Transformer

**Kong:**
```yaml
plugins:
  - name: response-transformer
    service: user-service
    config:
      add:
        headers:
          - X-Response-Time:$(latency)
```

**Loom:**
```yaml
routes:
  - id: users
    path: /users/*
    upstream: user-service
    headers:
      response:
        add:
          X-Response-Time: ${response_time}
```

#### Proxy Caching

**Kong:**
```yaml
plugins:
  - name: proxy-cache
    service: user-service
    config:
      strategy: memory
      content_type:
        - application/json
      cache_ttl: 300
      cache_control: true
```

**Loom:**
```yaml
cache:
  enabled: true
  store:
    type: memory
    max_size: 100MB
  default_ttl: 5m
  vary:
    - Accept
    - Accept-Encoding
  rules:
    - match:
        content_types: [application/json]
      ttl: 5m
```

#### IP Restriction

**Kong:**
```yaml
plugins:
  - name: ip-restriction
    service: admin-service
    config:
      allow:
        - 10.0.0.0/8
        - 192.168.1.0/24
```

**Loom:**
```yaml
routes:
  - id: admin
    path: /admin/*
    upstream: admin-service
    middleware:
      ip_filter:
        allow:
          - 10.0.0.0/8
          - 192.168.1.0/24
```

### Consumer Credentials

Kong uses a Consumer model for credentials. In Loom, credentials are configured directly:

**Kong:**
```yaml
consumers:
  - username: mobile-app
    keyauth_credentials:
      - key: abc123

  - username: web-app
    jwt_secrets:
      - key: web-app
        secret: secret123
```

**Loom:**
```yaml
middleware:
  auth:
    type: api_key
    keys:
      - abc123  # mobile-app

# Or for JWT
middleware:
  auth:
    type: jwt
    secrets:
      web-app: secret123
```

## Complete Migration Example

### Original Kong Configuration

```yaml
# kong.yaml (decK format)
_format_version: "3.0"

services:
  - name: users-api
    url: http://users.internal:8080
    connect_timeout: 30000
    read_timeout: 60000
    retries: 3

  - name: orders-api
    url: http://orders.internal:8080
    connect_timeout: 30000
    read_timeout: 60000

routes:
  - name: users-routes
    service: users-api
    paths:
      - /api/users
    methods:
      - GET
      - POST
      - PUT
      - DELETE
    strip_path: false

  - name: orders-routes
    service: orders-api
    paths:
      - /api/orders
    methods:
      - GET
      - POST

upstreams:
  - name: users-upstream
    algorithm: round-robin
    healthchecks:
      active:
        http_path: /health
        interval: 10

targets:
  - upstream: users-upstream
    target: users1.internal:8080
    weight: 100
  - upstream: users-upstream
    target: users2.internal:8080
    weight: 100

plugins:
  - name: rate-limiting
    config:
      minute: 1000
      policy: local

  - name: cors
    config:
      origins:
        - "*"
      methods:
        - GET
        - POST
        - PUT
        - DELETE
      headers:
        - Authorization
        - Content-Type
      max_age: 86400

  - name: key-auth
    service: users-api
    config:
      key_names:
        - X-API-Key
```

### Equivalent Loom Configuration

```yaml
# loom.yaml
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

routes:
  - id: users
    path: /api/users/*
    methods: [GET, POST, PUT, DELETE]
    upstream: users-api
    timeout: 60s
    middleware:
      auth:
        type: api_key
        header: X-API-Key
        keys:
          - ${USER_API_KEY_1}
          - ${USER_API_KEY_2}

  - id: orders
    path: /api/orders/*
    methods: [GET, POST]
    upstream: orders-api
    timeout: 60s

upstreams:
  - name: users-api
    endpoints:
      - "users1.internal:8080"
      - "users2.internal:8080"
    load_balancer: round_robin
    health_check:
      enabled: true
      path: /health
      interval: 10s
    connection:
      timeout: 30s
    retry:
      max_retries: 3

  - name: orders-api
    endpoints:
      - "orders.internal:8080"
    connection:
      timeout: 30s

rate_limit:
  enabled: true
  default:
    requests_per_second: 16.67  # 1000/minute
    burst: 50

cors:
  enabled: true
  allowed_origins: ["*"]
  allowed_methods: [GET, POST, PUT, DELETE]
  allowed_headers: [Authorization, Content-Type]
  max_age: 86400

admin:
  enabled: true
  address: ":9091"
```

## Custom Lua Plugin Migration

If you have custom Lua plugins, you'll need to rewrite them as WASM plugins or use built-in features.

**Kong Lua Plugin (custom-auth.lua):**
```lua
local CustomAuth = {}

function CustomAuth:access(conf)
    local token = kong.request.get_header("X-Custom-Token")
    if not token or token ~= conf.expected_token then
        return kong.response.exit(401, { message = "Unauthorized" })
    end
end

return CustomAuth
```

**Loom WASM Plugin (Rust):**
```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

struct CustomAuth {
    expected_token: String,
}

impl HttpContext for CustomAuth {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        match self.get_http_request_header("X-Custom-Token") {
            Some(token) if token == self.expected_token => Action::Continue,
            _ => {
                self.send_http_response(401, vec![], Some(b"Unauthorized"));
                Action::Pause
            }
        }
    }
}
```

Or configure in Loom directly:
```yaml
routes:
  - id: protected
    path: /protected/*
    middleware:
      auth:
        type: custom_header
        header: X-Custom-Token
        value: ${EXPECTED_TOKEN}
```

## Data Migration

Kong stores consumer data in its database. For Loom:

1. **API Keys**: Export and configure as environment variables
2. **JWT Secrets**: Export and configure in Loom
3. **Rate Limit Counters**: Will reset (stateless)
4. **Cache**: Will rebuild (not migrated)

## Verification

```bash
# Test each route
curl -H "X-API-Key: your-key" http://localhost:8080/api/users
curl http://localhost:8080/api/orders

# Verify rate limiting
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/users
done

# Check upstreams health
curl http://localhost:9091/upstreams

# Verify metrics
curl http://localhost:9091/metrics | grep loom_
```

## Next Steps

- [Configuration Reference](/docs/reference/configuration)
- [Writing WASM Plugins](/docs/getting-started/first-plugin)
- [Troubleshooting](/docs/reference/troubleshooting)
