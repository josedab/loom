---
sidebar_position: 3
title: Metrics Reference
description: Complete reference for all Prometheus metrics exposed by Loom.
---

# Metrics Reference

Loom exposes Prometheus metrics on the admin port (default: 9091) at `/metrics`.

## Request Metrics

### loom_requests_total

Total number of HTTP requests processed.

**Type:** Counter

**Labels:**
- `route` - Route ID
- `method` - HTTP method
- `status` - HTTP status code
- `status_class` - Status class (2xx, 3xx, 4xx, 5xx)

```promql
# Total requests per route
sum(rate(loom_requests_total[5m])) by (route)

# Error rate
sum(rate(loom_requests_total{status_class="5xx"}[5m])) /
sum(rate(loom_requests_total[5m]))
```

### loom_request_duration_seconds

Request duration histogram.

**Type:** Histogram

**Labels:**
- `route` - Route ID
- `method` - HTTP method

**Buckets:** 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

```promql
# P99 latency by route
histogram_quantile(0.99, rate(loom_request_duration_seconds_bucket[5m])) by (route)

# Average latency
rate(loom_request_duration_seconds_sum[5m]) /
rate(loom_request_duration_seconds_count[5m])
```

### loom_request_size_bytes

Request body size histogram.

**Type:** Histogram

**Labels:**
- `route` - Route ID

**Buckets:** 100, 1000, 10000, 100000, 1000000, 10000000

### loom_response_size_bytes

Response body size histogram.

**Type:** Histogram

**Labels:**
- `route` - Route ID

**Buckets:** 100, 1000, 10000, 100000, 1000000, 10000000

### loom_requests_in_flight

Current number of requests being processed.

**Type:** Gauge

**Labels:**
- `route` - Route ID

```promql
# Current in-flight requests
sum(loom_requests_in_flight)
```

## Upstream Metrics

### loom_upstream_requests_total

Total requests to upstream backends.

**Type:** Counter

**Labels:**
- `upstream` - Upstream name
- `endpoint` - Endpoint address
- `status` - HTTP status code

```promql
# Requests per upstream endpoint
sum(rate(loom_upstream_requests_total[5m])) by (upstream, endpoint)
```

### loom_upstream_duration_seconds

Upstream request duration histogram.

**Type:** Histogram

**Labels:**
- `upstream` - Upstream name
- `endpoint` - Endpoint address

**Buckets:** 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10

### loom_upstream_connections_active

Active connections to upstream.

**Type:** Gauge

**Labels:**
- `upstream` - Upstream name
- `endpoint` - Endpoint address

### loom_upstream_connections_idle

Idle connections in pool.

**Type:** Gauge

**Labels:**
- `upstream` - Upstream name

### loom_upstream_health

Upstream endpoint health status (1=healthy, 0=unhealthy).

**Type:** Gauge

**Labels:**
- `upstream` - Upstream name
- `endpoint` - Endpoint address

```promql
# Alert on unhealthy endpoints
loom_upstream_health == 0
```

## Circuit Breaker Metrics

### loom_circuit_breaker_state

Circuit breaker state (0=closed, 1=half-open, 2=open).

**Type:** Gauge

**Labels:**
- `upstream` - Upstream name

```promql
# Alert on open circuits
loom_circuit_breaker_state == 2
```

### loom_circuit_breaker_trips_total

Total number of circuit breaker trips.

**Type:** Counter

**Labels:**
- `upstream` - Upstream name

### loom_circuit_breaker_successes_total

Successful requests during half-open state.

**Type:** Counter

**Labels:**
- `upstream` - Upstream name

### loom_circuit_breaker_failures_total

Failed requests that count toward threshold.

**Type:** Counter

**Labels:**
- `upstream` - Upstream name

## Rate Limiting Metrics

### loom_rate_limit_requests_total

Total rate-limited requests.

**Type:** Counter

**Labels:**
- `route` - Route ID
- `status` - allowed, limited

```promql
# Rate limit hit rate
sum(rate(loom_rate_limit_requests_total{status="limited"}[5m])) /
sum(rate(loom_rate_limit_requests_total[5m]))
```

### loom_rate_limit_current

Current request count for rate limit key.

**Type:** Gauge

**Labels:**
- `key` - Rate limit key

### loom_rate_limit_keys_active

Number of active rate limit keys.

**Type:** Gauge

## Cache Metrics

### loom_cache_requests_total

Total cache requests.

**Type:** Counter

**Labels:**
- `status` - hit, miss, bypass

```promql
# Cache hit rate
sum(rate(loom_cache_requests_total{status="hit"}[5m])) /
sum(rate(loom_cache_requests_total{status!="bypass"}[5m]))
```

### loom_cache_entries

Current number of cache entries.

**Type:** Gauge

### loom_cache_size_bytes

Current cache size in bytes.

**Type:** Gauge

### loom_cache_evictions_total

Total cache evictions.

**Type:** Counter

**Labels:**
- `reason` - expired, capacity, manual

## Plugin Metrics

### loom_plugin_duration_seconds

Plugin execution duration histogram.

**Type:** Histogram

**Labels:**
- `plugin` - Plugin name
- `phase` - Execution phase

**Buckets:** 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1

### loom_plugin_invocations_total

Total plugin invocations.

**Type:** Counter

**Labels:**
- `plugin` - Plugin name
- `phase` - Execution phase
- `result` - success, error

### loom_plugin_errors_total

Total plugin errors.

**Type:** Counter

**Labels:**
- `plugin` - Plugin name
- `error_type` - Error type

## GraphQL Metrics

### loom_graphql_requests_total

Total GraphQL requests.

**Type:** Counter

**Labels:**
- `operation` - query, mutation, subscription
- `status` - success, error

### loom_graphql_duration_seconds

GraphQL request duration histogram.

**Type:** Histogram

**Labels:**
- `operation` - query, mutation, subscription

### loom_graphql_depth

Query depth histogram.

**Type:** Histogram

**Buckets:** 1, 2, 3, 5, 7, 10, 15, 20

### loom_graphql_complexity

Query complexity histogram.

**Type:** Histogram

**Buckets:** 10, 50, 100, 250, 500, 1000, 2500, 5000

### loom_graphql_blocked_total

Blocked queries.

**Type:** Counter

**Labels:**
- `reason` - depth, complexity, unauthorized, rate_limit

### loom_graphql_apq_requests_total

Automatic Persisted Query requests.

**Type:** Counter

**Labels:**
- `status` - hit, miss, registered

### loom_graphql_ws_connections_active

Active WebSocket connections.

**Type:** Gauge

### loom_graphql_subscriptions_active

Active GraphQL subscriptions.

**Type:** Gauge

### loom_graphql_federation_requests_total

Requests to federated services.

**Type:** Counter

**Labels:**
- `service` - Service name
- `status` - HTTP status code

## AI Gateway Metrics

### loom_ai_requests_total

Total AI/LLM requests.

**Type:** Counter

**Labels:**
- `provider` - Provider name
- `model` - Model name
- `status` - success, error

### loom_ai_tokens_total

Total tokens processed.

**Type:** Counter

**Labels:**
- `provider` - Provider name
- `model` - Model name
- `type` - input, output

```promql
# Token cost calculation (example: $0.01 per 1K input tokens)
sum(rate(loom_ai_tokens_total{type="input"}[1h])) * 0.01 / 1000
```

### loom_ai_duration_seconds

AI request duration histogram.

**Type:** Histogram

**Labels:**
- `provider` - Provider name
- `model` - Model name

### loom_ai_cache_requests_total

Semantic cache requests.

**Type:** Counter

**Labels:**
- `status` - hit, miss

### loom_ai_fallback_total

Provider fallback events.

**Type:** Counter

**Labels:**
- `from_provider` - Original provider
- `to_provider` - Fallback provider
- `reason` - error, rate_limit, latency

## Multi-Tenancy Metrics

### loom_tenant_requests_total

Requests per tenant.

**Type:** Counter

**Labels:**
- `tenant` - Tenant ID
- `status_class` - Status class

### loom_tenant_rate_limit_exceeded_total

Rate limit exceeded per tenant.

**Type:** Counter

**Labels:**
- `tenant` - Tenant ID

### loom_tenant_bandwidth_bytes_total

Bandwidth usage per tenant.

**Type:** Counter

**Labels:**
- `tenant` - Tenant ID
- `direction` - ingress, egress

### loom_tenant_quota_usage_ratio

Quota usage ratio (0-1).

**Type:** Gauge

**Labels:**
- `tenant` - Tenant ID
- `quota` - Quota type

## Chaos Engineering Metrics

### loom_chaos_faults_total

Total faults injected.

**Type:** Counter

**Labels:**
- `experiment` - Experiment name
- `type` - Fault type

### loom_chaos_active_faults

Currently active faults.

**Type:** Gauge

**Labels:**
- `experiment` - Experiment name

### loom_chaos_experiment_enabled

Experiment enabled status (0/1).

**Type:** Gauge

**Labels:**
- `experiment` - Experiment name

## eBPF Metrics

### loom_ebpf_packets_total

Total packets processed by eBPF.

**Type:** Counter

**Labels:**
- `action` - forward, drop, pass

### loom_ebpf_bytes_total

Total bytes processed by eBPF.

**Type:** Counter

**Labels:**
- `direction` - rx, tx

### loom_ebpf_connections_active

Active connections tracked by eBPF.

**Type:** Gauge

### loom_ebpf_backend_connections_active

Active connections per backend.

**Type:** Gauge

**Labels:**
- `backend` - Backend address

## System Metrics

### loom_info

Loom build information.

**Type:** Gauge (always 1)

**Labels:**
- `version` - Loom version
- `go_version` - Go version
- `commit` - Git commit

### loom_uptime_seconds

Time since Loom started.

**Type:** Gauge

### loom_config_reload_total

Configuration reload count.

**Type:** Counter

**Labels:**
- `status` - success, error

### loom_config_last_reload_timestamp

Timestamp of last successful reload.

**Type:** Gauge

## Go Runtime Metrics

Standard Go runtime metrics are also exposed:

- `go_goroutines` - Number of goroutines
- `go_gc_duration_seconds` - GC pause duration
- `go_memstats_alloc_bytes` - Allocated memory
- `go_memstats_heap_objects` - Heap objects
- `process_cpu_seconds_total` - CPU usage
- `process_resident_memory_bytes` - Memory usage
- `process_open_fds` - Open file descriptors

## Example Queries

### Request Rate

```promql
sum(rate(loom_requests_total[5m]))
```

### Error Rate

```promql
sum(rate(loom_requests_total{status_class="5xx"}[5m])) /
sum(rate(loom_requests_total[5m])) * 100
```

### P99 Latency

```promql
histogram_quantile(0.99,
  sum(rate(loom_request_duration_seconds_bucket[5m])) by (le)
)
```

### Requests per Route

```promql
topk(10, sum(rate(loom_requests_total[5m])) by (route))
```

### Cache Effectiveness

```promql
sum(rate(loom_cache_requests_total{status="hit"}[5m])) /
sum(rate(loom_cache_requests_total[5m])) * 100
```

### Unhealthy Upstreams

```promql
loom_upstream_health == 0
```

### Token Usage (AI)

```promql
sum(increase(loom_ai_tokens_total[24h])) by (provider, model, type)
```

## Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: loom
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(loom_requests_total{status_class="5xx"}[5m])) /
          sum(rate(loom_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected

      - alert: HighLatency
        expr: |
          histogram_quantile(0.99,
            sum(rate(loom_request_duration_seconds_bucket[5m])) by (le)
          ) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High P99 latency

      - alert: UpstreamUnhealthy
        expr: loom_upstream_health == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: Upstream endpoint unhealthy

      - alert: CircuitBreakerOpen
        expr: loom_circuit_breaker_state == 2
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: Circuit breaker is open

      - alert: HighRateLimiting
        expr: |
          sum(rate(loom_rate_limit_requests_total{status="limited"}[5m])) /
          sum(rate(loom_rate_limit_requests_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High rate of rate-limited requests
```

## Next Steps

- **[Admin API](./admin-api)** - API reference
- **[Configuration](./configuration)** - Configuration reference
- **[Observability](../guides/observability)** - Monitoring guide
