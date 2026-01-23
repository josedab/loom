---
sidebar_position: 2
title: Admin API Reference
description: Complete reference for Loom's administration REST API.
---

# Admin API Reference

Loom provides a RESTful admin API for monitoring, configuration, and management.

## Base URL

The admin API runs on a separate port (default: 9091).

```
http://localhost:9091
```

## Authentication

Configure authentication in `loom.yaml`:

```yaml
admin:
  auth:
    type: basic
    basic:
      username: admin
      password: secret
```

Include credentials in requests:

```bash
curl -u admin:secret http://localhost:9091/routes
```

## Health Endpoints

### Health Check

Check overall health status.

```http
GET /health
```

**Response**

```json
{
  "status": "healthy",
  "checks": {
    "upstreams": "healthy",
    "plugins": "healthy",
    "cache": "healthy"
  }
}
```

**Status Codes**

| Code | Description |
|------|-------------|
| 200 | Healthy |
| 503 | Unhealthy |

### Readiness Check

Check if Loom is ready to accept traffic.

```http
GET /ready
```

**Response**

```json
{
  "ready": true
}
```

### Liveness Check

Simple liveness probe.

```http
GET /live
```

**Response**

```
OK
```

## Routes

### List Routes

Get all configured routes.

```http
GET /routes
```

**Response**

```json
{
  "routes": [
    {
      "id": "api",
      "path": "/api/*",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "upstream": "backend",
      "enabled": true
    }
  ]
}
```

### Get Route

Get a specific route by ID.

```http
GET /routes/{id}
```

**Response**

```json
{
  "id": "api",
  "path": "/api/*",
  "methods": ["GET", "POST", "PUT", "DELETE"],
  "upstream": "backend",
  "timeout": "30s",
  "retries": 3,
  "enabled": true,
  "stats": {
    "requests_total": 150000,
    "requests_per_second": 50,
    "latency_p50_ms": 12,
    "latency_p99_ms": 85
  }
}
```

### Create Route

Add a new route dynamically.

```http
POST /routes
Content-Type: application/json

{
  "id": "new-api",
  "path": "/v2/api/*",
  "upstream": "backend-v2",
  "methods": ["GET", "POST"]
}
```

**Response**

```json
{
  "id": "new-api",
  "created": true
}
```

### Update Route

Update an existing route.

```http
PUT /routes/{id}
Content-Type: application/json

{
  "timeout": "60s",
  "retries": 5
}
```

### Patch Route

Partially update a route.

```http
PATCH /routes/{id}
Content-Type: application/json

{
  "enabled": false
}
```

### Delete Route

Remove a route.

```http
DELETE /routes/{id}
```

## Upstreams

### List Upstreams

Get all configured upstreams.

```http
GET /upstreams
```

**Response**

```json
{
  "upstreams": [
    {
      "name": "backend",
      "endpoints": [
        {
          "address": "api1.internal:8080",
          "weight": 100,
          "healthy": true
        },
        {
          "address": "api2.internal:8080",
          "weight": 100,
          "healthy": true
        }
      ],
      "load_balancing": "round-robin",
      "active_connections": 45
    }
  ]
}
```

### Get Upstream

Get a specific upstream.

```http
GET /upstreams/{name}
```

**Response**

```json
{
  "name": "backend",
  "endpoints": [
    {
      "address": "api1.internal:8080",
      "weight": 100,
      "healthy": true,
      "stats": {
        "requests_total": 75000,
        "failures_total": 12,
        "latency_p50_ms": 10,
        "latency_p99_ms": 75,
        "active_connections": 23
      }
    }
  ],
  "circuit_breaker": {
    "state": "closed",
    "failure_count": 0,
    "last_failure": null
  }
}
```

### Add Endpoint

Add an endpoint to an upstream.

```http
POST /upstreams/{name}/endpoints
Content-Type: application/json

{
  "address": "api3.internal:8080",
  "weight": 100
}
```

### Remove Endpoint

Remove an endpoint from an upstream.

```http
DELETE /upstreams/{name}/endpoints/{address}
```

### Update Endpoint Weight

Change endpoint weight.

```http
PATCH /upstreams/{name}/endpoints/{address}
Content-Type: application/json

{
  "weight": 50
}
```

### Drain Endpoint

Drain connections before removing.

```http
POST /upstreams/{name}/endpoints/{address}/drain
Content-Type: application/json

{
  "timeout": "30s"
}
```

## Health Checks

### Get Upstream Health

Get health status of an upstream.

```http
GET /upstreams/{name}/health
```

**Response**

```json
{
  "upstream": "backend",
  "healthy": true,
  "endpoints": [
    {
      "address": "api1.internal:8080",
      "healthy": true,
      "last_check": "2024-01-15T10:30:00Z",
      "consecutive_successes": 10,
      "consecutive_failures": 0
    }
  ]
}
```

### Trigger Health Check

Force an immediate health check.

```http
POST /upstreams/{name}/health/check
```

### Set Endpoint Health

Manually set endpoint health (admin override).

```http
PUT /upstreams/{name}/endpoints/{address}/health
Content-Type: application/json

{
  "healthy": false,
  "reason": "Manual maintenance"
}
```

## Circuit Breaker

### Get Circuit Breaker State

```http
GET /upstreams/{name}/circuit-breaker
```

**Response**

```json
{
  "upstream": "backend",
  "state": "half-open",
  "failure_count": 5,
  "success_count": 2,
  "last_failure": "2024-01-15T10:25:00Z",
  "next_attempt": "2024-01-15T10:30:00Z"
}
```

### Reset Circuit Breaker

Force reset the circuit breaker.

```http
POST /upstreams/{name}/circuit-breaker/reset
```

### Trip Circuit Breaker

Manually trip the circuit breaker.

```http
POST /upstreams/{name}/circuit-breaker/trip
```

## Plugins

### List Plugins

Get all loaded plugins.

```http
GET /plugins
```

**Response**

```json
{
  "plugins": [
    {
      "name": "auth",
      "path": "/etc/loom/plugins/auth.wasm",
      "phase": "on_request_headers",
      "enabled": true,
      "stats": {
        "invocations": 150000,
        "avg_duration_us": 45
      }
    }
  ]
}
```

### Get Plugin

Get plugin details.

```http
GET /plugins/{name}
```

### Enable/Disable Plugin

```http
POST /plugins/{name}/enable
POST /plugins/{name}/disable
```

### Reload Plugin

Reload a plugin from disk.

```http
POST /plugins/{name}/reload
```

## Cache

### Get Cache Stats

```http
GET /cache/stats
```

**Response**

```json
{
  "entries": 5000,
  "size_bytes": 52428800,
  "max_size_bytes": 104857600,
  "hit_rate": 0.85,
  "hits_total": 850000,
  "misses_total": 150000,
  "evictions_total": 25000
}
```

### Clear Cache

Clear the entire cache.

```http
DELETE /cache
```

### Clear Cache by Pattern

Clear cache entries matching a pattern.

```http
DELETE /cache?pattern=/api/products/*
```

### Get Cache Entry

```http
GET /cache/entries/{key}
```

### Delete Cache Entry

```http
DELETE /cache/entries/{key}
```

## Rate Limiting

### Get Rate Limit Stats

```http
GET /rate-limit/stats
```

**Response**

```json
{
  "total_requests": 1000000,
  "limited_requests": 5000,
  "current_keys": 1500,
  "by_key": [
    {
      "key": "api-key-123",
      "requests": 500,
      "remaining": 500,
      "reset_at": "2024-01-15T11:00:00Z"
    }
  ]
}
```

### Get Key Status

```http
GET /rate-limit/keys/{key}
```

### Reset Key

Reset rate limit for a specific key.

```http
DELETE /rate-limit/keys/{key}
```

## GraphQL

### Get GraphQL Stats

```http
GET /graphql/stats
```

**Response**

```json
{
  "queries_total": 50000,
  "mutations_total": 10000,
  "subscriptions_active": 500,
  "avg_depth": 4.5,
  "avg_complexity": 150,
  "cache_hit_rate": 0.75
}
```

### List Persisted Queries

```http
GET /graphql/persisted-queries
```

### Get Persisted Query

```http
GET /graphql/persisted-queries/{hash}
```

### Delete Persisted Query

```http
DELETE /graphql/persisted-queries/{hash}
```

### Clear Persisted Queries

```http
DELETE /graphql/persisted-queries
```

### Get Federation Services

```http
GET /graphql/services
```

**Response**

```json
{
  "services": [
    {
      "name": "users",
      "url": "http://users-service:4000/graphql",
      "healthy": true,
      "schema_version": "abc123"
    }
  ]
}
```

### Refresh Schema

```http
POST /graphql/schema/refresh
```

## Configuration

### Get Current Config

```http
GET /config
```

### Reload Config

Reload configuration from disk.

```http
POST /config/reload
```

**Response**

```json
{
  "reloaded": true,
  "changes": [
    "routes.api.timeout: 30s -> 60s",
    "upstreams.backend.endpoints: added api3.internal:8080"
  ]
}
```

### Validate Config

Validate a configuration without applying.

```http
POST /config/validate
Content-Type: application/yaml

listeners:
  - name: http
    address: ":8080"
# ... rest of config
```

**Response**

```json
{
  "valid": true,
  "warnings": [
    "upstream 'backend-v2' is defined but not used by any route"
  ]
}
```

## Metrics

### Prometheus Metrics

```http
GET /metrics
```

Returns Prometheus-formatted metrics.

### JSON Metrics

```http
GET /metrics?format=json
```

Returns metrics in JSON format.

## Chaos Engineering

### List Experiments

```http
GET /chaos/experiments
```

### Get Experiment

```http
GET /chaos/experiments/{name}
```

### Enable Experiment

```http
POST /chaos/experiments/{name}/enable
```

### Disable Experiment

```http
POST /chaos/experiments/{name}/disable
```

### Update Experiment

```http
PATCH /chaos/experiments/{name}
Content-Type: application/json

{
  "percentage": 20
}
```

## Multi-Tenancy

### List Tenants

```http
GET /tenants
```

### Get Tenant

```http
GET /tenants/{id}
```

### Create Tenant

```http
POST /tenants
Content-Type: application/json

{
  "id": "new-tenant",
  "name": "New Tenant",
  "tier": "starter"
}
```

### Update Tenant

```http
PATCH /tenants/{id}
Content-Type: application/json

{
  "tier": "pro"
}
```

### Delete Tenant

```http
DELETE /tenants/{id}
```

### Get Tenant Stats

```http
GET /tenants/{id}/stats
```

## System

### Get System Info

```http
GET /system/info
```

**Response**

```json
{
  "version": "1.0.0",
  "go_version": "1.21.0",
  "os": "linux",
  "arch": "amd64",
  "uptime": "72h30m15s",
  "start_time": "2024-01-12T10:00:00Z"
}
```

### Get Runtime Stats

```http
GET /system/runtime
```

**Response**

```json
{
  "goroutines": 150,
  "memory": {
    "alloc_mb": 45,
    "sys_mb": 120,
    "gc_pause_ms": 0.5
  },
  "connections": {
    "active": 500,
    "idle": 100
  }
}
```

### Trigger GC

```http
POST /system/gc
```

### Get Debug Profile

```http
GET /debug/pprof/profile?seconds=30
GET /debug/pprof/heap
GET /debug/pprof/goroutine
```

## Error Responses

All error responses follow this format:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Route 'unknown' not found",
    "details": {}
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Resource not found |
| `INVALID_REQUEST` | 400 | Invalid request body |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Permission denied |
| `CONFLICT` | 409 | Resource conflict |
| `INTERNAL_ERROR` | 500 | Internal server error |

## Next Steps

- **[Metrics](./metrics)** - Prometheus metrics reference
- **[CLI](./cli)** - Command-line reference
- **[Configuration](./configuration)** - Configuration reference
