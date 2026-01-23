---
sidebar_position: 6
title: Troubleshooting
description: Solutions to common problems when running Loom API Gateway.
---

# Troubleshooting

This guide helps you diagnose and resolve common issues with Loom.

## Quick Diagnostics

Before diving into specific issues, gather diagnostic information:

```bash
# Check Loom is running
curl http://localhost:9091/health

# Check configuration is valid
loom -config config.yaml -validate

# View recent logs
journalctl -u loom -n 100  # If running as systemd service

# Check upstreams health
curl http://localhost:9091/upstreams

# Check route configuration
curl http://localhost:9091/routes
```

## Connection Issues

### 502 Bad Gateway

**Symptom**: Requests return HTTP 502 status.

**Causes and Solutions**:

1. **Backend not reachable**
   ```bash
   # Test connectivity to backend
   curl -v http://backend-host:8080/health
   ```
   - Verify backend is running
   - Check firewall rules
   - Verify DNS resolution

2. **Wrong endpoint format**
   ```yaml
   # Wrong - includes scheme
   endpoints:
     - "http://backend:8080"

   # Correct - host:port only
   endpoints:
     - "backend:8080"
   ```

3. **Timeout exceeded**
   ```yaml
   routes:
     - id: api
       timeout: 60s  # Increase if backend is slow
   ```

4. **Circuit breaker open**
   ```bash
   # Check circuit breaker state
   curl http://localhost:9091/upstreams/backend
   ```
   Wait for timeout or fix the underlying backend issue.

### 503 Service Unavailable

**Symptom**: Requests return HTTP 503 status.

**Causes and Solutions**:

1. **All backends unhealthy**
   ```bash
   # Check backend health status
   curl http://localhost:9091/upstreams
   ```
   Fix backend health issues or adjust health check thresholds.

2. **Rate limit exceeded**
   ```bash
   # Check rate limit headers in response
   curl -v http://localhost:8080/api/test
   # Look for: X-RateLimit-Remaining: 0
   ```
   Increase rate limits or implement client-side backoff.

### 504 Gateway Timeout

**Symptom**: Requests return HTTP 504 after delay.

**Solutions**:

1. **Increase route timeout**
   ```yaml
   routes:
     - id: slow-api
       timeout: 120s  # Default is 30s
   ```

2. **Check backend performance**
   ```bash
   # Test backend directly
   time curl http://backend:8080/slow-endpoint
   ```

3. **Enable request tracing**
   ```yaml
   tracing:
     enabled: true
     sampling:
       ratio: 1.0  # 100% for debugging
   ```

### Connection Refused

**Symptom**: `connection refused` in logs.

**Solutions**:

1. **Verify backend is listening**
   ```bash
   netstat -tlnp | grep 8080
   ```

2. **Check container networking** (if using Docker)
   ```bash
   docker network inspect bridge
   ```

3. **Verify endpoint configuration**
   ```yaml
   upstreams:
     - name: backend
       endpoints:
         - "host.docker.internal:8080"  # For Docker on Mac/Windows
   ```

## Routing Issues

### Route Not Matching

**Symptom**: Requests return 404 when route should match.

**Debugging Steps**:

1. **Enable debug logging**
   ```bash
   loom -config config.yaml -log-level debug
   ```

2. **Check route configuration**
   ```bash
   curl http://localhost:9091/routes
   ```

3. **Common path pattern issues**:
   ```yaml
   # This only matches exactly /api
   path: /api

   # This matches /api and anything under it
   path: /api/*

   # This matches /api/users, /api/orders, etc.
   path: /api/{resource}
   ```

4. **Method restrictions**
   ```yaml
   routes:
     - id: api
       path: /api/*
       methods: [GET, POST]  # PUT, DELETE will return 405
   ```

### Wrong Route Matched

**Symptom**: Request matches unexpected route.

**Solutions**:

1. **Use route priority**
   ```yaml
   routes:
     - id: specific
       path: /api/users/me
       priority: 100  # Higher priority matches first

     - id: general
       path: /api/users/*
       priority: 50
   ```

2. **Check route order** - Routes are evaluated in order of priority, then definition order.

### Host-Based Routing Not Working

**Symptom**: Host header not matching routes.

```yaml
routes:
  - id: api
    host: api.example.com
    path: /*
```

**Solutions**:

1. **Verify Host header is sent**
   ```bash
   curl -H "Host: api.example.com" http://localhost:8080/test
   ```

2. **Check for proxy interference** - Intermediate proxies may modify Host header.

## Plugin Issues

### Plugin Not Loading

**Symptom**: Plugin errors on startup.

**Solutions**:

1. **Verify WASM file exists and is readable**
   ```bash
   ls -la /path/to/plugin.wasm
   file /path/to/plugin.wasm  # Should say "WebAssembly"
   ```

2. **Check plugin compilation**
   ```bash
   # For Rust plugins
   cargo build --target wasm32-wasi --release
   ```

3. **Verify Proxy-Wasm compatibility**
   - Loom supports Proxy-Wasm ABI 0.2.x
   - Check plugin SDK version matches

### Plugin Not Executing

**Symptom**: Plugin loads but doesn't process requests.

**Solutions**:

1. **Verify plugin phase**
   ```yaml
   plugins:
     - name: auth
       phase: on_request_headers  # Must match when plugin should run
   ```

2. **Check route association**
   ```yaml
   routes:
     - id: api
       plugins:
         - auth  # Plugin must be listed here
   ```

3. **Enable plugin debugging**
   ```yaml
   plugins:
     - name: auth
       config:
         debug: true  # If plugin supports it
   ```

### Plugin Errors

**Symptom**: `wasm trap` or runtime errors.

**Solutions**:

1. **Check plugin logs**
   ```bash
   grep -i "plugin\|wasm" /var/log/loom/loom.log
   ```

2. **Verify plugin configuration**
   ```yaml
   plugins:
     - name: jwt-auth
       config:
         secret: "${JWT_SECRET}"  # Ensure env var is set
   ```

3. **Test plugin isolation**
   - Disable other plugins
   - Test with minimal configuration

## Performance Issues

### High Latency

**Symptom**: Requests are slow through gateway.

**Diagnostics**:

```bash
# Check latency metrics
curl -s http://localhost:9091/metrics | grep loom_request_duration
```

**Solutions**:

1. **Identify slow phase**
   ```yaml
   tracing:
     enabled: true
   ```
   Check traces for where time is spent.

2. **Optimize plugins**
   - Reduce plugin count
   - Optimize plugin logic
   - Use caching in plugins

3. **Tune connection pools**
   ```yaml
   upstreams:
     - name: backend
       connection:
         max_idle: 200
         max_per_host: 100
   ```

4. **Enable response caching**
   ```yaml
   cache:
     enabled: true
     default_ttl: 5m
   ```

### High Memory Usage

**Symptom**: Loom consuming excessive memory.

**Solutions**:

1. **Check for memory leaks in plugins**
   ```bash
   # Monitor memory over time
   watch -n 5 'ps -o rss= -p $(pidof loom)'
   ```

2. **Limit request body buffering**
   ```yaml
   body_limit:
     max_size: 10MB
   ```

3. **Tune cache size**
   ```yaml
   cache:
     store:
       max_size: 100MB  # Reduce if needed
   ```

### High CPU Usage

**Symptom**: Loom consuming excessive CPU.

**Solutions**:

1. **Profile the application**
   ```bash
   # Enable pprof endpoint
   curl http://localhost:9091/debug/pprof/profile > profile.out
   go tool pprof profile.out
   ```

2. **Check for expensive plugins**
   - Plugin execution time is in metrics
   - Consider plugin optimization

3. **Enable eBPF acceleration** (Linux)
   ```yaml
   ebpf:
     enabled: true
   ```

## Configuration Issues

### Config Validation Errors

**Symptom**: Loom won't start with configuration errors.

**Solutions**:

1. **Validate configuration**
   ```bash
   loom -config config.yaml -validate
   ```

2. **Check YAML syntax**
   ```bash
   # Use a YAML linter
   yamllint config.yaml
   ```

3. **Common mistakes**:
   ```yaml
   # Wrong: tabs instead of spaces
   routes:
   	- id: test  # Tab character

   # Correct: spaces only
   routes:
     - id: test
   ```

### Hot Reload Not Working

**Symptom**: Config changes not applied.

**Solutions**:

1. **Check file permissions**
   ```bash
   ls -la config.yaml
   ```

2. **Verify file system events**
   ```bash
   # Test with inotifywait
   inotifywait -m config.yaml
   ```

3. **Send reload signal manually**
   ```bash
   kill -SIGHUP $(pidof loom)
   ```

### Environment Variables Not Expanding

**Symptom**: `${VAR}` appears literally in config.

**Solutions**:

1. **Check variable is set**
   ```bash
   echo $BACKEND_HOST
   ```

2. **Use correct syntax**
   ```yaml
   # Correct
   endpoints:
     - "${BACKEND_HOST}:8080"

   # Wrong - no quotes
   endpoints:
     - ${BACKEND_HOST}:8080
   ```

## TLS/HTTPS Issues

### Certificate Errors

**Symptom**: TLS handshake failures.

**Solutions**:

1. **Verify certificate chain**
   ```bash
   openssl x509 -in cert.pem -text -noout
   openssl verify -CAfile ca.pem cert.pem
   ```

2. **Check key matches certificate**
   ```bash
   openssl x509 -noout -modulus -in cert.pem | md5sum
   openssl rsa -noout -modulus -in key.pem | md5sum
   # Should match
   ```

3. **Check file permissions**
   ```bash
   chmod 600 key.pem
   chmod 644 cert.pem
   ```

### mTLS Not Working

**Symptom**: Client certificate not verified.

```yaml
listeners:
  - name: https
    tls:
      client_auth: require
      client_ca_file: /path/to/ca.pem
```

**Solutions**:

1. **Verify client cert is signed by CA**
   ```bash
   openssl verify -CAfile ca.pem client.pem
   ```

2. **Test with curl**
   ```bash
   curl --cert client.pem --key client-key.pem https://localhost:8443/
   ```

## Logging and Debugging

### Enable Debug Logging

```bash
loom -config config.yaml -log-level debug
```

Or in configuration:
```yaml
logging:
  level: debug
  format: json
```

### Common Log Messages

| Message | Meaning | Action |
|---------|---------|--------|
| `upstream unhealthy` | Health check failed | Check backend |
| `circuit breaker open` | Too many failures | Investigate backend |
| `rate limit exceeded` | Client hit limit | Adjust limits or client |
| `plugin error` | WASM execution failed | Check plugin code |
| `route not found` | No matching route | Review route config |

### Getting Help

If you can't resolve an issue:

1. **Search existing issues**: [GitHub Issues](https://github.com/josedab/loom/issues)
2. **Ask the community**: [GitHub Discussions](https://github.com/josedab/loom/discussions)
3. **Report a bug**: Include version, config, logs, and reproduction steps
