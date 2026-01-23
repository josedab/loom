---
sidebar_position: 10
title: Migration Overview
description: Guide for migrating to Loom from other API gateways.
---

# Migrating to Loom

This guide helps you migrate from other API gateways to Loom. We provide specific guides for:

- [Migrating from NGINX](./migration-nginx)
- [Migrating from Kong](./migration-kong)
- [Migrating from Envoy](./migration-envoy)

## General Migration Strategy

### 1. Assess Your Current Setup

Before migrating, document:

- **Routes**: All URL patterns and their backends
- **Upstreams**: Backend services and their endpoints
- **Authentication**: Auth methods and credentials
- **Rate Limits**: Current limits and quotas
- **Plugins/Modules**: Custom logic and extensions
- **TLS Configuration**: Certificates and settings

### 2. Plan the Migration

Choose a migration approach:

| Approach | Description | Risk | Downtime |
|----------|-------------|------|----------|
| **Blue-Green** | Run Loom parallel, switch traffic | Low | None |
| **Canary** | Gradually shift traffic to Loom | Low | None |
| **In-Place** | Replace existing gateway | Medium | Brief |

We recommend **Blue-Green** or **Canary** for production systems.

### 3. Set Up Loom

```bash
# Install Loom
go install github.com/josedab/loom/cmd/loom@latest

# Create initial configuration
cat > loom.yaml << 'EOF'
listeners:
  - name: http
    address: ":8080"
    protocol: http

admin:
  enabled: true
  address: ":9091"

routes: []
upstreams: []
EOF

# Test configuration
loom -config loom.yaml -validate
```

### 4. Migrate Configuration

Convert your existing configuration to Loom format. See the specific migration guides for detailed mappings.

### 5. Test Thoroughly

```bash
# Start Loom
loom -config loom.yaml

# Test routes
curl http://localhost:8080/api/test

# Verify metrics
curl http://localhost:9091/metrics

# Check health
curl http://localhost:9091/health
```

### 6. Shift Traffic

**Blue-Green Deployment:**
```bash
# Update load balancer to point to Loom
# Monitor for errors
# Rollback if needed
```

**Canary Deployment:**
```bash
# Send 10% of traffic to Loom
# Monitor metrics and errors
# Gradually increase to 100%
```

### 7. Decommission Old Gateway

After successful migration:
1. Monitor Loom for at least 24-48 hours
2. Keep old gateway available for quick rollback
3. Remove old gateway after confidence period

## Common Migration Tasks

### Converting Routes

Most gateways use similar routing concepts:

```yaml
# Generic pattern
routes:
  - id: unique-id
    path: /api/*           # URL pattern
    methods: [GET, POST]   # Allowed methods
    upstream: backend      # Target service
    timeout: 30s          # Request timeout
```

### Converting Upstreams

```yaml
upstreams:
  - name: backend
    endpoints:
      - "host1:8080"
      - "host2:8080"
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s
```

### Converting TLS

```yaml
listeners:
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

### Converting Rate Limits

```yaml
rate_limit:
  enabled: true
  default:
    requests_per_second: 100
    burst: 200
```

## Plugin Migration

### Proxy-Wasm Compatibility

If your existing plugins use Proxy-Wasm ABI, they likely work in Loom unchanged:

```yaml
plugins:
  - name: existing-plugin
    path: /path/to/plugin.wasm
    phase: on_request_headers
```

### Rewriting Plugins

For non-WASM plugins, you have options:

1. **Use built-in features**: Loom has built-in rate limiting, auth, caching
2. **Write a WASM plugin**: Port logic to Rust/Go WASM
3. **Use external service**: Call out to existing service via HTTP

## Verification Checklist

Before completing migration:

- [ ] All routes accessible
- [ ] Authentication working
- [ ] Rate limits enforced
- [ ] Health checks passing
- [ ] Metrics collecting
- [ ] Logs flowing
- [ ] Error rates normal
- [ ] Latency acceptable
- [ ] TLS working correctly
- [ ] WebSocket connections working (if used)

## Rollback Plan

Always have a rollback plan:

1. **Keep old config**: Don't delete old gateway configuration
2. **DNS TTL**: Use low TTL for quick DNS changes
3. **Load balancer**: Be ready to switch traffic back
4. **Monitoring**: Set up alerts for anomalies

## Getting Help

- [Loom Documentation](/docs/getting-started/introduction)
- [GitHub Discussions](https://github.com/josedab/loom/discussions)
- [Community Discord](https://discord.gg/loom)

## Next Steps

Choose your migration guide:
- [Migrating from NGINX](./migration-nginx)
- [Migrating from Kong](./migration-kong)
- [Migrating from Envoy](./migration-envoy)
