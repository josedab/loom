---
sidebar_position: 13
title: Migrate from Envoy
description: Step-by-step guide for migrating from Envoy to Loom.
---

# Migrating from Envoy

This guide helps you migrate from Envoy Proxy to Loom. Both support Proxy-Wasm plugins, making WASM plugin migration straightforward.

## Key Differences

| Aspect | Envoy | Loom |
|--------|-------|------|
| Language | C++ | Go |
| Configuration | xDS API or static YAML | YAML file |
| Deployment | Sidecar or edge | Edge gateway |
| WASM Runtime | V8/Wasmtime | wazero |
| Proxy-Wasm | Full support | Full support |
| Service Mesh | Istio, App Mesh | Standalone |
| Dependencies | libc++, etc. | None (pure Go) |

## When to Migrate

Consider migrating from Envoy to Loom when:

- You want simpler operations without xDS/control plane
- You need built-in AI/LLM or GraphQL gateway features
- You prefer zero external dependencies
- You're using Envoy as a standalone gateway (not in service mesh)

Stay with Envoy when:
- You're using Istio or another service mesh
- You need xDS for dynamic configuration
- You have extensive Envoy filter customizations

## Configuration Mapping

### Listeners

**Envoy:**
```yaml
static_resources:
  listeners:
    - name: http_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/api"
                          route:
                            cluster: backend_cluster
```

**Loom:**
```yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend
```

### Clusters to Upstreams

**Envoy:**
```yaml
clusters:
  - name: backend_cluster
    connect_timeout: 30s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: backend_cluster
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: backend.internal
                    port_value: 8080
    health_checks:
      - timeout: 5s
        interval: 10s
        unhealthy_threshold: 3
        healthy_threshold: 2
        http_health_check:
          path: /health
    circuit_breakers:
      thresholds:
        - max_connections: 1000
          max_pending_requests: 1000
          max_retries: 3
```

**Loom:**
```yaml
upstreams:
  - name: backend
    endpoints:
      - "backend.internal:8080"
    load_balancer: round_robin
    connection:
      timeout: 30s
      max_idle: 1000
    health_check:
      enabled: true
      path: /health
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3
    circuit_breaker:
      enabled: true
      max_retries: 3
```

### Route Matching

**Envoy:**
```yaml
routes:
  - match:
      prefix: "/api/v1"
      headers:
        - name: ":method"
          string_match:
            exact: "GET"
    route:
      cluster: api_v1_cluster
      timeout: 30s

  - match:
      safe_regex:
        google_re2: {}
        regex: "/users/[0-9]+"
    route:
      cluster: users_cluster

  - match:
      prefix: "/"
      headers:
        - name: "x-canary"
          string_match:
            exact: "true"
    route:
      cluster: canary_cluster
```

**Loom:**
```yaml
routes:
  - id: api-v1
    path: /api/v1/*
    methods: [GET]
    upstream: api-v1
    timeout: 30s

  - id: users
    path: /users/{id}
    upstream: users
    # Note: Loom uses path parameters, not regex

  - id: canary
    path: /*
    upstream: canary
    match:
      headers:
        x-canary: "true"
```

### TLS Configuration

**Envoy:**
```yaml
listeners:
  - name: https_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8443
    filter_chains:
      - transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            common_tls_context:
              tls_certificates:
                - certificate_chain:
                    filename: /etc/envoy/certs/cert.pem
                  private_key:
                    filename: /etc/envoy/certs/key.pem
              tls_params:
                tls_minimum_protocol_version: TLSv1_2
```

**Loom:**
```yaml
listeners:
  - name: https
    address: ":8443"
    protocol: https
    tls:
      cert_file: /etc/loom/certs/cert.pem
      key_file: /etc/loom/certs/key.pem
      min_version: "1.2"
```

### Rate Limiting

**Envoy (with rate limit service):**
```yaml
http_filters:
  - name: envoy.filters.http.ratelimit
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
      domain: production
      rate_limit_service:
        grpc_service:
          envoy_grpc:
            cluster_name: rate_limit_cluster
```

**Loom (built-in):**
```yaml
rate_limit:
  enabled: true
  key: ${client_ip}
  default:
    requests_per_second: 100
    burst: 200
  store:
    type: memory  # or redis for distributed
```

### Header Manipulation

**Envoy:**
```yaml
routes:
  - match:
      prefix: "/api"
    route:
      cluster: backend_cluster
    request_headers_to_add:
      - header:
          key: X-Request-ID
          value: "%REQ(X-REQUEST-ID)%"
    request_headers_to_remove:
      - X-Internal-Header
    response_headers_to_add:
      - header:
          key: X-Envoy-Upstream-Service-Time
          value: "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"
```

**Loom:**
```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
    headers:
      request:
        add:
          X-Request-ID: ${request_id}
        remove:
          - X-Internal-Header
      response:
        add:
          X-Upstream-Service-Time: ${upstream_time}
```

### Retry Policy

**Envoy:**
```yaml
routes:
  - match:
      prefix: "/api"
    route:
      cluster: backend_cluster
      retry_policy:
        retry_on: "5xx,connect-failure,retriable-4xx"
        num_retries: 3
        per_try_timeout: 10s
        retry_back_off:
          base_interval: 0.1s
          max_interval: 1s
```

**Loom:**
```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
    retry:
      max_retries: 3
      retry_codes: [500, 502, 503, 504]
      per_try_timeout: 10s
      backoff:
        base: 100ms
        max: 1s
```

### Circuit Breaker

**Envoy:**
```yaml
clusters:
  - name: backend_cluster
    circuit_breakers:
      thresholds:
        - priority: DEFAULT
          max_connections: 1000
          max_pending_requests: 1000
          max_requests: 1000
          max_retries: 3
    outlier_detection:
      consecutive_5xx: 5
      interval: 10s
      base_ejection_time: 30s
```

**Loom:**
```yaml
upstreams:
  - name: backend
    circuit_breaker:
      enabled: true
      failure_threshold: 5
      success_threshold: 2
      timeout: 30s
    connection:
      max_idle: 1000
      max_per_host: 1000
```

## WASM Plugin Migration

Since both Envoy and Loom support Proxy-Wasm ABI, your existing WASM plugins should work with minimal changes.

### Plugin Configuration

**Envoy:**
```yaml
http_filters:
  - name: envoy.filters.http.wasm
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
      config:
        name: my_plugin
        root_id: my_plugin_root
        vm_config:
          runtime: envoy.wasm.runtime.v8
          code:
            local:
              filename: /etc/envoy/plugins/my_plugin.wasm
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {"setting": "value"}
```

**Loom:**
```yaml
plugins:
  - name: my-plugin
    path: /etc/loom/plugins/my_plugin.wasm
    phase: on_request_headers
    config:
      setting: value
```

### Testing Plugin Compatibility

```bash
# Test your existing WASM plugin with Loom
loom -config test-config.yaml

# Verify plugin loads
curl http://localhost:9091/plugins

# Test plugin functionality
curl -v http://localhost:8080/api/test
```

### Common Compatibility Issues

1. **ABI Version**: Ensure plugin uses Proxy-Wasm ABI 0.2.x
2. **Host Functions**: Some Envoy-specific host functions may not be available
3. **Memory Limits**: Adjust WASM memory configuration if needed

```yaml
plugins:
  - name: my-plugin
    path: /etc/loom/plugins/my_plugin.wasm
    wasm:
      max_memory_pages: 100  # Increase if needed
```

## Complete Migration Example

### Original Envoy Configuration

```yaml
# envoy.yaml
admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901

static_resources:
  listeners:
    - name: http
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/api/v1"
                          route:
                            cluster: api_v1
                            timeout: 30s
                        - match:
                            prefix: "/api/v2"
                          route:
                            cluster: api_v2
                            timeout: 30s
                http_filters:
                  - name: envoy.filters.http.wasm
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
                      config:
                        name: auth
                        vm_config:
                          runtime: envoy.wasm.runtime.v8
                          code:
                            local:
                              filename: /etc/envoy/plugins/auth.wasm
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: api_v1
      connect_timeout: 30s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: api_v1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: api-v1.internal
                      port_value: 8080
              - endpoint:
                  address:
                    socket_address:
                      address: api-v1-2.internal
                      port_value: 8080
      health_checks:
        - timeout: 5s
          interval: 10s
          unhealthy_threshold: 3
          healthy_threshold: 2
          http_health_check:
            path: /health

    - name: api_v2
      connect_timeout: 30s
      type: STRICT_DNS
      lb_policy: LEAST_REQUEST
      load_assignment:
        cluster_name: api_v2
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: api-v2.internal
                      port_value: 8080
```

### Equivalent Loom Configuration

```yaml
# loom.yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api-v1
    path: /api/v1/*
    upstream: api-v1
    timeout: 30s
    plugins:
      - auth

  - id: api-v2
    path: /api/v2/*
    upstream: api-v2
    timeout: 30s
    plugins:
      - auth

upstreams:
  - name: api-v1
    endpoints:
      - "api-v1.internal:8080"
      - "api-v1-2.internal:8080"
    load_balancer: round_robin
    connection:
      timeout: 30s
    health_check:
      enabled: true
      path: /health
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3

  - name: api-v2
    endpoints:
      - "api-v2.internal:8080"
    load_balancer: least_conn
    connection:
      timeout: 30s

plugins:
  - name: auth
    path: /etc/loom/plugins/auth.wasm
    phase: on_request_headers

admin:
  enabled: true
  address: ":9091"
```

## xDS to Static Configuration

If you're using xDS for dynamic configuration, you'll need to convert to static YAML. Loom supports hot reload via file watching:

```bash
# Loom automatically reloads when config file changes
loom -config loom.yaml

# Or trigger reload manually
kill -SIGHUP $(pidof loom)
```

For dynamic configuration needs, consider:
1. Config management tools (Ansible, Puppet)
2. Kubernetes ConfigMaps with file sync
3. Custom automation to generate YAML

## Verification

```bash
# Compare responses
curl http://envoy:8080/api/v1/test > envoy_response.txt
curl http://loom:8080/api/v1/test > loom_response.txt
diff envoy_response.txt loom_response.txt

# Check metrics
curl http://localhost:9091/metrics | grep loom_

# Verify health checks
curl http://localhost:9091/upstreams

# Test WASM plugin
curl -v http://localhost:8080/api/v1/protected
```

## Next Steps

- [Configuration Reference](/docs/reference/configuration)
- [Writing WASM Plugins](/docs/getting-started/first-plugin)
- [Troubleshooting](/docs/reference/troubleshooting)
