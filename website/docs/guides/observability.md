---
sidebar_position: 9
title: Observability
description: Monitor Loom with Prometheus metrics, OpenTelemetry tracing, and structured logging.
---

# Observability

Loom provides comprehensive observability through metrics, tracing, and logging.

## Prometheus Metrics

### Enable Metrics

Metrics are exposed via the admin API:

```yaml
admin:
  address: ":9091"
  enabled: true

metrics:
  prometheus:
    enabled: true
    path: /metrics
```

Access metrics at `http://localhost:9091/metrics`

### Available Metrics

#### Request Metrics

```
# Total requests
loom_requests_total{method="GET",route="api",status="200"}

# Request duration histogram
loom_request_duration_seconds{method="GET",route="api"}
loom_request_duration_seconds_bucket{le="0.005",...}
loom_request_duration_seconds_sum
loom_request_duration_seconds_count

# Active requests
loom_requests_in_flight{route="api"}

# Request size
loom_request_size_bytes{route="api"}

# Response size
loom_response_size_bytes{route="api"}
```

#### Upstream Metrics

```
# Upstream requests
loom_upstream_requests_total{upstream="backend",status="success"}
loom_upstream_requests_total{upstream="backend",status="failure"}

# Upstream duration
loom_upstream_duration_seconds{upstream="backend"}

# Active connections
loom_upstream_connections_active{upstream="backend"}

# Health status
loom_upstream_health{upstream="backend",endpoint="api.internal:8080"}
```

#### Circuit Breaker Metrics

```
# Circuit state (0=closed, 1=open, 2=half-open)
loom_circuit_breaker_state{upstream="backend"}

# State transitions
loom_circuit_breaker_transitions_total{upstream="backend",to_state="open"}

# Blocked requests
loom_circuit_breaker_blocked_total{upstream="backend"}
```

#### Cache Metrics

```
# Cache operations
loom_cache_requests_total{status="hit"}
loom_cache_requests_total{status="miss"}

# Cache size
loom_cache_entries_total
loom_cache_bytes_total

# Cache latency
loom_cache_duration_seconds{operation="get"}
```

#### Plugin Metrics

```
# Plugin execution time
loom_plugin_duration_seconds{plugin="auth",phase="on_request_headers"}

# Plugin errors
loom_plugin_errors_total{plugin="auth",error="timeout"}
```

#### Rate Limit Metrics

```
# Rate limit status
loom_ratelimit_requests_total{status="allowed"}
loom_ratelimit_requests_total{status="rejected"}

# Current bucket tokens
loom_ratelimit_tokens{key="..."}
```

### Prometheus Configuration

```yaml title="prometheus.yml"
scrape_configs:
  - job_name: 'loom'
    static_configs:
      - targets: ['loom:9091']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Grafana Dashboard

Import the Loom dashboard or create your own:

```json
{
  "dashboard": {
    "title": "Loom API Gateway",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(loom_requests_total[5m])"
          }
        ]
      },
      {
        "title": "P99 Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(loom_request_duration_seconds_bucket[5m]))"
          }
        ]
      }
    ]
  }
}
```

## OpenTelemetry Tracing

### Enable Tracing

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector:4317"
  service_name: "loom"
  sample_rate: 1.0
  batch_timeout: 5s
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `endpoint` | - | OTLP gRPC endpoint |
| `service_name` | `loom` | Service name in traces |
| `sample_rate` | `1.0` | Sampling rate (0.0-1.0) |
| `batch_timeout` | `5s` | Batch export timeout |
| `insecure` | `false` | Disable TLS |

### Trace Propagation

Loom propagates trace context using:

- W3C Trace Context (`traceparent`, `tracestate`)
- Jaeger (`uber-trace-id`)
- B3 (`X-B3-TraceId`, `X-B3-SpanId`)

### Span Structure

```
Loom Request
├── Middleware Chain
│   ├── Rate Limit
│   └── Auth
├── Route Match
├── Plugin: auth (on_request_headers)
├── Upstream Request
│   └── Backend: api.internal:8080
├── Plugin: transform (on_response_headers)
└── Response
```

### Custom Attributes

```yaml
tracing:
  enabled: true
  attributes:
    environment: production
    region: us-east-1
  request_attributes:
    - header:X-Request-ID
    - header:X-User-ID
```

### Sampling

```yaml
tracing:
  sample_rate: 0.1  # 10% of requests

  # Or use parent-based sampling
  sampler:
    type: parent_based
    root:
      type: trace_id_ratio
      ratio: 0.1
```

### Example: Jaeger Setup

```yaml title="docker-compose.yml"
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # UI
      - "4317:4317"    # OTLP gRPC

  loom:
    image: ghcr.io/josedab/loom:latest
    environment:
      - LOOM_TRACING_ENABLED=true
      - LOOM_TRACING_ENDPOINT=jaeger:4317
```

## Structured Logging

### Configuration

```yaml
logging:
  level: info
  format: json
  output: stdout
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging |
| `info` | Normal operations |
| `warn` | Warning conditions |
| `error` | Error conditions |

### Access Logs

```yaml
logging:
  access:
    enabled: true
    format: json
    fields:
      - timestamp
      - method
      - path
      - status
      - duration
      - request_id
      - client_ip
      - user_agent
```

### Log Format

JSON format:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "info",
  "msg": "request completed",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "duration_ms": 45,
  "request_id": "abc123",
  "client_ip": "192.168.1.100"
}
```

### Request ID Propagation

```yaml
logging:
  request_id:
    header: X-Request-ID
    generate: true
```

Loom generates a request ID if not provided and propagates it to backends.

## Health Checks

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Liveness probe |
| `/ready` | Readiness probe |
| `/info` | Version info |

### Kubernetes Probes

```yaml title="deployment.yaml"
containers:
  - name: loom
    livenessProbe:
      httpGet:
        path: /health
        port: 9091
      initialDelaySeconds: 5
      periodSeconds: 10

    readinessProbe:
      httpGet:
        path: /ready
        port: 9091
      initialDelaySeconds: 5
      periodSeconds: 5
```

### Custom Health Checks

```yaml
admin:
  health:
    checks:
      - name: redis
        type: tcp
        address: redis:6379
        timeout: 2s

      - name: database
        type: http
        url: http://db:8080/health
        timeout: 5s
```

## Alerting

### Prometheus Alerts

```yaml title="alerts.yml"
groups:
  - name: loom
    rules:
      - alert: HighErrorRate
        expr: |
          rate(loom_requests_total{status=~"5.."}[5m])
          / rate(loom_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate on Loom"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.99, rate(loom_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High P99 latency on Loom"

      - alert: CircuitBreakerOpen
        expr: loom_circuit_breaker_state == 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Circuit breaker open for {{ $labels.upstream }}"

      - alert: UpstreamUnhealthy
        expr: loom_upstream_health == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Upstream {{ $labels.endpoint }} is unhealthy"
```

## Complete Example

```yaml
admin:
  address: ":9091"
  enabled: true

metrics:
  prometheus:
    enabled: true
    path: /metrics
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

tracing:
  enabled: true
  endpoint: "otel-collector:4317"
  service_name: "loom"
  sample_rate: 0.1
  attributes:
    environment: production
    version: "1.0.0"

logging:
  level: info
  format: json
  access:
    enabled: true
    fields:
      - timestamp
      - method
      - path
      - status
      - duration
      - request_id
      - upstream
      - cache_status
  request_id:
    header: X-Request-ID
    generate: true
```

## Dashboard Queries

### Request Rate by Route

```promql
sum(rate(loom_requests_total[5m])) by (route)
```

### P50/P95/P99 Latency

```promql
histogram_quantile(0.50, rate(loom_request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(loom_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(loom_request_duration_seconds_bucket[5m]))
```

### Error Rate

```promql
sum(rate(loom_requests_total{status=~"5.."}[5m]))
/ sum(rate(loom_requests_total[5m]))
```

### Cache Hit Rate

```promql
sum(rate(loom_cache_requests_total{status="hit"}[5m]))
/ sum(rate(loom_cache_requests_total[5m]))
```

## Next Steps

- **[Configuration Reference](/docs/reference/configuration)** - Full configuration
- **[Metrics Reference](/docs/reference/metrics)** - All available metrics
- **[Admin API Reference](/docs/reference/admin-api)** - Admin endpoints
