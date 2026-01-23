---
sidebar_position: 3
title: Quickstart
description: Get a working Loom gateway running in under 5 minutes.
---

# Quickstart

This guide gets you from zero to a working API gateway in under 5 minutes.

## What We'll Build

By the end of this guide, you'll have:

- Loom proxying requests to a backend service
- Rate limiting enabled
- Health checks monitoring your backend
- Metrics available via Prometheus

## Step 1: Create a Backend Service

First, let's create a simple backend to proxy to. We'll use a basic HTTP server:

```bash
# Start a simple backend (requires Python)
python3 -m http.server 3000
```

Or use any existing service running on port 3000.

## Step 2: Create Configuration

Create a file named `loom.yaml`:

```yaml title="loom.yaml"
# Listeners define where Loom accepts connections
listeners:
  - name: http
    address: ":8080"
    protocol: http

# Routes map URL paths to upstreams
routes:
  - id: api
    path: /api/*
    methods: [GET, POST, PUT, DELETE]
    upstream: backend
    timeout: 30s

  - id: health
    path: /health
    methods: [GET]
    upstream: backend
    timeout: 5s

# Upstreams are your backend services
upstreams:
  - name: backend
    endpoints:
      - "localhost:3000"
    load_balancer: round_robin
    health_check:
      path: /
      interval: 10s
      timeout: 2s
      healthy_threshold: 2
      unhealthy_threshold: 3

# Admin API for metrics and management
admin:
  address: ":9091"
  enabled: true

# Global rate limiting
rate_limit:
  enabled: true
  rate: 100
  burst: 200
```

## Step 3: Start Loom

Run Loom with your configuration:

```bash
loom -config loom.yaml
```

You should see output like:

```
INFO  Starting Loom API Gateway
INFO  Loading configuration from loom.yaml
INFO  Listener http starting on :8080
INFO  Admin API starting on :9091
INFO  Health checker started for upstream backend
```

## Step 4: Test the Gateway

In another terminal, make requests through Loom:

```bash
# Request through the gateway
curl http://localhost:8080/api/test

# Check the admin health endpoint
curl http://localhost:9091/health
```

## Step 5: Explore the Admin API

Loom provides a built-in admin API for management and observability:

```bash
# List all routes
curl http://localhost:9091/routes

# List all upstreams with health status
curl http://localhost:9091/upstreams

# Get Prometheus metrics
curl http://localhost:9091/metrics
```

## Understanding the Configuration

Let's break down what each section does:

### Listeners

```yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http
```

Listeners define the network interfaces where Loom accepts incoming connections. The `protocol` can be `http`, `https`, `http3`, or `grpc`.

### Routes

```yaml
routes:
  - id: api
    path: /api/*
    methods: [GET, POST, PUT, DELETE]
    upstream: backend
    timeout: 30s
```

Routes match incoming requests and direct them to upstreams. The `path` supports wildcards (`*`) and the `upstream` references a named upstream.

### Upstreams

```yaml
upstreams:
  - name: backend
    endpoints:
      - "localhost:3000"
    load_balancer: round_robin
    health_check:
      path: /
      interval: 10s
```

Upstreams define your backend services. Multiple endpoints enable load balancing, and health checks automatically remove unhealthy backends.

## Adding More Features

### Enable HTTPS

```yaml
listeners:
  - name: https
    address: ":8443"
    protocol: https
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

### Add Circuit Breaker

```yaml
upstreams:
  - name: backend
    endpoints:
      - "localhost:3000"
    circuit_breaker:
      failure_threshold: 5
      success_threshold: 3
      timeout: 30s
```

### Enable Tracing

```yaml
tracing:
  enabled: true
  endpoint: "localhost:4317"
  service_name: "loom"
  sample_rate: 1.0
```

### Add CORS

```yaml
cors:
  enabled: true
  allow_origins: ["*"]
  allow_methods: [GET, POST, PUT, DELETE]
  allow_headers: [Authorization, Content-Type]
  max_age: 86400
```

## Complete Example

Here's a more complete configuration:

```yaml title="loom.yaml"
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
  - id: api-v1
    path: /api/v1/*
    methods: [GET, POST, PUT, DELETE]
    upstream: backend
    timeout: 30s
    priority: 100

  - id: public
    path: /public/*
    methods: [GET]
    upstream: static
    strip_prefix: true
    timeout: 10s

upstreams:
  - name: backend
    endpoints:
      - "api-1.internal:8080"
      - "api-2.internal:8080"
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s
    circuit_breaker:
      failure_threshold: 5
      timeout: 30s
    retry:
      max_retries: 3
      backoff_base: 100ms
      retryable_codes: [502, 503, 504]

  - name: static
    endpoints:
      - "cdn.internal:80"
    load_balancer: random

admin:
  address: ":9091"
  enabled: true

rate_limit:
  enabled: true
  rate: 1000
  burst: 2000

cors:
  enabled: true
  allow_origins: ["https://example.com"]
  allow_methods: [GET, POST, PUT, DELETE]
  allow_headers: [Authorization, Content-Type]
```

## Next Steps

Now that you have a working gateway:

- **[Write Your First Plugin](./first-plugin)** - Extend Loom with custom logic
- **[Core Concepts](../core-concepts/architecture)** - Understand how Loom works
- **[Configuration Reference](../reference/configuration)** - Full configuration options
