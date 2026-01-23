---
sidebar_position: 2
title: Routing
description: Configure URL routing, path matching, and host-based routing in Loom.
---

# Routing

Loom's router uses a high-performance radix tree to match incoming requests to backend services.

## Route Configuration

Each route defines how requests are matched and where they're sent:

```yaml
routes:
  - id: api-v1
    path: /api/v1/*
    methods: [GET, POST, PUT, DELETE]
    upstream: backend-api
    timeout: 30s
    priority: 100
```

### Route Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the route |
| `path` | Yes | URL path pattern to match |
| `upstream` | Yes | Target upstream name |
| `methods` | No | Allowed HTTP methods (default: all) |
| `host` | No | Host header to match |
| `timeout` | No | Request timeout |
| `priority` | No | Route priority (higher = matched first) |
| `plugins` | No | List of plugins to apply |
| `strip_prefix` | No | Remove matched prefix from path |
| `headers` | No | Required headers to match |

## Path Matching

### Exact Match

Matches only the exact path:

```yaml
routes:
  - id: health
    path: /health
    upstream: backend
```

Matches: `/health`
Does not match: `/health/`, `/health/check`, `/healthz`

### Prefix Match

Use `/*` to match any path that starts with the prefix:

```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
```

Matches: `/api/users`, `/api/users/123`, `/api/v1/orders`
Does not match: `/apiv2`, `/apis`

### Path Parameters

Capture path segments as parameters:

```yaml
routes:
  - id: user-detail
    path: /users/:id
    upstream: backend
```

Matches: `/users/123`, `/users/abc`
The `:id` value is available to plugins.

### Wildcard Segments

Match any single segment:

```yaml
routes:
  - id: resource
    path: /api/*/resource
    upstream: backend
```

Matches: `/api/v1/resource`, `/api/v2/resource`
Does not match: `/api/v1/v2/resource`

## Host-Based Routing

Route requests based on the `Host` header:

```yaml
routes:
  - id: api-prod
    host: api.example.com
    path: /*
    upstream: backend-prod

  - id: api-staging
    host: api.staging.example.com
    path: /*
    upstream: backend-staging
```

### Wildcard Hosts

Match subdomains with wildcards:

```yaml
routes:
  - id: tenant-api
    host: "*.api.example.com"
    path: /*
    upstream: tenant-backend
```

Matches: `tenant1.api.example.com`, `tenant2.api.example.com`

## Method Filtering

Restrict routes to specific HTTP methods:

```yaml
routes:
  - id: api-read
    path: /api/*
    methods: [GET, HEAD]
    upstream: backend-read

  - id: api-write
    path: /api/*
    methods: [POST, PUT, DELETE]
    upstream: backend-write
```

## Route Priority

When multiple routes could match, priority determines which one wins:

```yaml
routes:
  # Higher priority - matches first
  - id: api-v2
    path: /api/v2/*
    upstream: backend-v2
    priority: 100

  # Lower priority - fallback
  - id: api-catchall
    path: /api/*
    upstream: backend-v1
    priority: 50
```

Default priority is 0. Higher numbers match first.

## Path Rewriting

### Strip Prefix

Remove the matched prefix before forwarding:

```yaml
routes:
  - id: static
    path: /static/*
    upstream: cdn
    strip_prefix: true
```

Request `/static/images/logo.png` forwards as `/images/logo.png`

### Rewrite Path

Replace the path entirely:

```yaml
routes:
  - id: legacy
    path: /old-api/*
    upstream: backend
    rewrite:
      path: /api/v1/$1
```

Request `/old-api/users` forwards as `/api/v1/users`

## Header-Based Routing

Match requests based on headers:

```yaml
routes:
  - id: mobile-api
    path: /api/*
    headers:
      X-Client-Type: mobile
    upstream: mobile-backend

  - id: web-api
    path: /api/*
    headers:
      X-Client-Type: web
    upstream: web-backend
```

### Header Matching Modes

```yaml
routes:
  - id: example
    path: /api/*
    headers:
      # Exact match
      X-Version: "2.0"

      # Regex match
      X-Request-ID: "^[a-f0-9-]+$"

      # Presence check (any value)
      Authorization: "*"
```

## Query Parameter Routing

Route based on query parameters:

```yaml
routes:
  - id: search-v2
    path: /search
    query:
      version: "2"
    upstream: search-v2

  - id: search-default
    path: /search
    upstream: search-v1
```

## Timeouts

Configure per-route timeouts:

```yaml
routes:
  - id: fast-api
    path: /api/fast/*
    upstream: backend
    timeout: 5s

  - id: slow-api
    path: /api/reports/*
    upstream: backend
    timeout: 120s
```

## Route-Specific Plugins

Apply plugins to specific routes:

```yaml
plugins:
  - name: rate-limit
    path: /plugins/rate-limit.wasm

  - name: auth
    path: /plugins/auth.wasm

routes:
  - id: public-api
    path: /public/*
    upstream: backend
    plugins:
      - rate-limit

  - id: private-api
    path: /private/*
    upstream: backend
    plugins:
      - auth
      - rate-limit
```

## Complete Example

```yaml
routes:
  # Health check - highest priority
  - id: health
    path: /health
    upstream: backend
    timeout: 5s
    priority: 1000

  # API v2 - high priority
  - id: api-v2
    host: api.example.com
    path: /api/v2/*
    methods: [GET, POST, PUT, DELETE, PATCH]
    upstream: backend-v2
    timeout: 30s
    priority: 100
    plugins:
      - auth
      - rate-limit

  # API v1 - medium priority
  - id: api-v1
    host: api.example.com
    path: /api/v1/*
    upstream: backend-v1
    timeout: 30s
    priority: 50
    plugins:
      - auth

  # Static content
  - id: static
    path: /static/*
    upstream: cdn
    strip_prefix: true
    timeout: 10s
    priority: 10

  # Catch-all redirect
  - id: redirect-root
    path: /
    upstream: frontend
    priority: 1
```

## Debugging Routes

### List All Routes

```bash
curl http://localhost:9091/routes
```

### Test Route Matching

```bash
curl http://localhost:9091/routes/match?path=/api/v1/users&method=GET
```

### View Route Details

```bash
curl http://localhost:9091/routes/api-v1
```

## Next Steps

- **[Upstreams](./upstreams)** - Configure backend services
- **[Plugins](./plugins)** - Add custom logic to routes
- **[Configuration Reference](/docs/reference/configuration)** - Full configuration options
