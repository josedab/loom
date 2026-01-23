---
sidebar_position: 5
title: FAQ
description: Frequently asked questions about Loom API Gateway.
---

# Frequently Asked Questions

Common questions and answers about Loom.

## General

### What is Loom?

Loom is a high-performance API gateway built in Go with native WebAssembly (WASM) plugin support. It routes HTTP/gRPC traffic to backend services while providing features like load balancing, rate limiting, authentication, and observability.

### Why is it called "Loom"?

A loom weaves threads together into fabric. Similarly, Loom weaves together requests, plugins, and backend services. The name also reflects the "weaving" pattern of WASM plugins that intercept and transform requests.

### Is Loom production-ready?

Yes. Loom includes production-essential features:
- Circuit breakers for fault tolerance
- Health checks for backend monitoring
- Graceful shutdown with connection draining
- Hot reload without dropping requests
- Comprehensive metrics and tracing

### What license is Loom under?

Loom is released under the Apache 2.0 license, which allows commercial use, modification, and distribution.

## Architecture

### How does Loom compare to Envoy?

Both support Proxy-Wasm plugins, but they differ in:

| Aspect | Loom | Envoy |
|--------|------|-------|
| Language | Go | C++ |
| Configuration | YAML file | xDS API |
| Dependencies | None | libc++, etc. |
| AI Gateway | Built-in | No |
| GraphQL | Built-in | No |

Loom is simpler to deploy and operate, while Envoy excels in service mesh scenarios with Istio.

### Does Loom support service mesh?

Loom is designed as a standalone API gateway, not a service mesh sidecar. For service mesh use cases, consider Envoy with Istio or Linkerd.

### What load balancing algorithms are supported?

Loom supports:
- **Round Robin** - Sequential distribution
- **Weighted** - Weight-based distribution
- **Least Connections** - Prefer less loaded backends
- **Random** - Random selection
- **IP Hash** - Consistent by client IP
- **Consistent Hash** - Consistent hashing with custom key

### How does hot reload work?

When you modify the configuration file, Loom:
1. Detects the change via file system watching
2. Parses and validates the new configuration
3. Atomically swaps the routing table
4. Existing connections continue with old config until complete
5. New connections use the new config

No requests are dropped during reload.

## WASM Plugins

### What is Proxy-Wasm?

Proxy-Wasm is an ABI (Application Binary Interface) standard for WebAssembly plugins in network proxies. Plugins written to this standard work across multiple proxies including Loom, Envoy, and APISIX.

### What languages can I write plugins in?

Any language that compiles to WebAssembly:
- **Rust** - Best performance and ecosystem support
- **Go/TinyGo** - Familiar Go syntax with some limitations
- **TypeScript** - Via AssemblyScript
- **C/C++** - Low-level control

### How do I debug WASM plugins?

1. **Logging**: Use `proxy_log` to output debug information
2. **Local testing**: Use wazero's debugging features
3. **Metrics**: Loom exposes plugin execution time metrics
4. **Tracing**: Plugin execution is included in distributed traces

```rust
// Rust example: Debug logging
proxy_wasm::hostcalls::log(LogLevel::Debug, "Processing request");
```

### What's the performance overhead of WASM plugins?

With AOT compilation (default), plugin overhead is typically under 2ms per request. The wazero runtime compiles WASM to native code on first load, so subsequent executions run at near-native speed.

### Can plugins access the network?

By default, no. WASM plugins run in a sandboxed environment. If your plugin needs to make HTTP calls, you can:
1. Use the Proxy-Wasm HTTP call API
2. Configure allowed hosts in the plugin settings

## Configuration

### Can I use environment variables in config?

Yes. Use `${VAR_NAME}` syntax:

```yaml
upstreams:
  - name: backend
    endpoints:
      - ${BACKEND_HOST}:${BACKEND_PORT}

listeners:
  - name: https
    tls:
      cert_file: ${TLS_CERT_PATH}
```

### How do I configure TLS/HTTPS?

```yaml
listeners:
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
      min_version: "1.2"
```

For mTLS (mutual TLS):

```yaml
tls:
  client_auth: require
  client_ca_file: /path/to/ca.pem
```

### How do I enable HTTP/3?

```yaml
listeners:
  - name: http3
    address: ":443"
    protocol: http3
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

HTTP/3 requires TLS certificates and uses UDP instead of TCP.

### What's the difference between path patterns?

| Pattern | Matches | Example |
|---------|---------|---------|
| `/api` | Exact | `/api` only |
| `/api/*` | Prefix | `/api/users`, `/api/orders` |
| `/api/{id}` | Parameter | `/api/123`, `/api/abc` |
| `/api/{id}/items` | Mixed | `/api/123/items` |

### How do I strip the matched prefix?

```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
    strip_prefix: true  # /api/users becomes /users
```

## Operations

### How do I check if Loom is healthy?

The admin API provides health endpoints:

```bash
# Liveness check
curl http://localhost:9091/health

# Readiness check (includes backend health)
curl http://localhost:9091/ready
```

### How do I get Prometheus metrics?

Metrics are available on the admin port:

```bash
curl http://localhost:9091/metrics
```

Key metrics include:
- `loom_requests_total` - Request count by route/method/status
- `loom_request_duration_seconds` - Request latency histogram
- `loom_upstream_health` - Backend health status

### How do I enable distributed tracing?

```yaml
tracing:
  enabled: true
  provider: otlp
  otlp:
    endpoint: otel-collector:4317
  sampling:
    type: ratio
    ratio: 0.1  # 10% of requests
```

Loom supports OpenTelemetry (OTLP), Jaeger, and Zipkin.

### How do I gracefully shut down Loom?

Send SIGTERM or SIGINT:

```bash
kill -SIGTERM $(pidof loom)
```

Loom will:
1. Stop accepting new connections
2. Wait for existing requests to complete (up to 30s default)
3. Close all connections
4. Exit cleanly

### Can I run multiple Loom instances?

Yes. Loom is stateless, so you can run multiple instances behind a load balancer. For features requiring shared state (like distributed rate limiting), configure a Redis backend:

```yaml
rate_limit:
  store:
    type: redis
    redis:
      address: redis:6379
```

## Troubleshooting

### Why am I getting 502 Bad Gateway?

Common causes:
1. **Backend unreachable** - Check upstream endpoints are correct
2. **Connection refused** - Backend not running or wrong port
3. **Timeout** - Backend too slow, increase timeout
4. **Circuit breaker open** - Too many failures, check backend health

Check the logs and `/upstreams` admin endpoint for details.

### Why are my routes not matching?

1. **Path mismatch** - Ensure path pattern matches request
2. **Method not allowed** - Check `methods` list includes request method
3. **Host mismatch** - If using host-based routing, verify `host` field
4. **Priority conflict** - Higher priority routes match first

Use debug logging to see route matching:

```bash
loom -config config.yaml -log-level debug
```

### Why is my plugin not running?

1. **Phase mismatch** - Plugin phase must match when to run
2. **Route not associated** - Plugin must be in route's plugin list
3. **WASM error** - Check logs for compilation errors
4. **Config error** - Verify plugin config is valid

### How do I report a bug?

1. Check [existing issues](https://github.com/josedab/loom/issues)
2. Include: Loom version, config (redacted), steps to reproduce
3. Submit at [GitHub Issues](https://github.com/josedab/loom/issues/new)

## Performance

### What throughput can Loom handle?

Loom is designed for high throughput. Actual performance depends on:
- Hardware (CPU, network)
- Request complexity
- Plugin count and complexity
- Backend latency

Benchmark on your specific workload for accurate numbers.

### How do I optimize performance?

1. **Connection pooling** - Tune `max_idle` and `max_per_host`
2. **Reduce plugins** - Only enable needed plugins
3. **Enable caching** - Cache responses where appropriate
4. **eBPF acceleration** - Enable on Linux for kernel-bypass
5. **HTTP/2** - Use multiplexing for many concurrent requests

### Does Loom support eBPF acceleration?

Yes, on Linux. eBPF acceleration reduces kernel overhead for connection handling:

```yaml
ebpf:
  enabled: true
  socket_redirect: true
```

Requires Linux kernel 5.7+ and appropriate capabilities.
