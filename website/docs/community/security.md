---
sidebar_position: 3
title: Security Policy
description: Security policy and best practices for Loom API Gateway.
---

# Security Policy

This document outlines security practices for Loom and how to report vulnerabilities.

## Reporting Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it responsibly:

1. **Email**: Send details to security@loom.dev (or create a private security advisory on GitHub)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will work with you to understand and resolve the issue.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |
| 0.x.x   | Security fixes only |

## Security Features

Loom includes several built-in security features:

### TLS/HTTPS

```yaml
listeners:
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
      min_version: "1.2"  # TLS 1.2 minimum
      cipher_suites:      # Secure cipher suites only
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### Mutual TLS (mTLS)

```yaml
listeners:
  - name: mtls
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/server.pem
      key_file: /etc/loom/tls/server-key.pem
      client_auth: require
      client_ca_file: /etc/loom/tls/ca.pem
```

### Rate Limiting

Protect against abuse and DDoS:

```yaml
rate_limit:
  enabled: true
  default:
    requests_per_second: 100
    burst: 200
  key: ${client_ip}  # Rate limit by IP

  # Per-route overrides
  routes:
    auth:
      requests_per_second: 10  # Stricter for auth endpoints
```

### Authentication

Built-in support for common auth methods:

```yaml
# API Key authentication
middleware:
  auth:
    type: api_key
    header: X-API-Key
    keys:
      - ${API_KEY_1}
      - ${API_KEY_2}

# JWT authentication
middleware:
  auth:
    type: jwt
    secret: ${JWT_SECRET}
    algorithms: [HS256, RS256]
    required_claims:
      - sub
      - exp
```

### Security Headers

Automatic security headers:

```yaml
middleware:
  security_headers:
    enabled: true
    hsts:
      enabled: true
      max_age: 31536000
      include_subdomains: true
      preload: true
    content_security_policy: "default-src 'self'"
    x_frame_options: DENY
    x_content_type_options: nosniff
    referrer_policy: strict-origin-when-cross-origin
```

### Request Validation

Protect against malicious requests:

```yaml
middleware:
  body_limit:
    max_size: 10MB

  request_validation:
    max_header_size: 8KB
    max_uri_length: 2048
    allowed_methods: [GET, POST, PUT, DELETE, PATCH]
```

### Admin API Protection

Secure the admin API:

```yaml
admin:
  address: "127.0.0.1:9091"  # Bind to localhost only
  auth:
    type: basic
    username: admin
    password: ${ADMIN_PASSWORD}
```

Or use network policies to restrict access.

## Security Best Practices

### 1. Use TLS Everywhere

Always terminate TLS at Loom, even for internal traffic:

```yaml
listeners:
  - name: external
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
```

### 2. Secure Secrets Management

Never hardcode secrets in configuration:

```yaml
# Good - Use environment variables
ai_gateway:
  providers:
    - name: openai
      api_key: ${OPENAI_API_KEY}

# Bad - Hardcoded secret
ai_gateway:
  providers:
    - name: openai
      api_key: sk-abc123...  # Never do this!
```

Use a secrets manager:
- Kubernetes Secrets
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

### 3. Principle of Least Privilege

Only expose necessary endpoints:

```yaml
routes:
  - id: public-api
    path: /api/v1/public/*
    methods: [GET]  # Read-only
    upstream: backend

  - id: internal-api
    path: /api/v1/internal/*
    host: internal.example.com  # Only internal DNS
    upstream: backend
```

### 4. Enable Logging and Monitoring

Track security-relevant events:

```yaml
logging:
  level: info
  format: json
  access_log:
    enabled: true
    fields:
      - timestamp
      - client_ip
      - method
      - path
      - status
      - user_agent
```

Set up alerts for:
- Unusual traffic patterns
- Failed authentication attempts
- Rate limit triggers
- Error rate spikes

### 5. Regular Updates

Keep Loom and plugins updated:

```bash
# Check for updates
go list -m -u github.com/josedab/loom

# Update to latest
go install github.com/josedab/loom/cmd/loom@latest
```

### 6. WASM Plugin Security

WASM plugins run in sandboxed environments, but follow these practices:

- **Audit plugin code** before deployment
- **Use trusted sources** for plugins
- **Limit plugin capabilities**:
  ```yaml
  plugins:
    - name: custom
      capabilities:
        allow_http: false  # Disable network access
        allow_filesystem: false
  ```

### 7. Network Security

Restrict network access:

```yaml
# Only listen on internal interfaces
listeners:
  - name: internal
    address: "10.0.0.1:8080"
    protocol: http

# Restrict upstream access
upstreams:
  - name: backend
    endpoints:
      - "10.0.0.10:8080"  # Internal IPs only
```

### 8. Input Validation

Validate all input at the gateway:

```yaml
routes:
  - id: api
    path: /api/*
    plugins:
      - name: request-validator
        config:
          schema: /etc/loom/schemas/api.json
```

### 9. Circuit Breaker Protection

Prevent cascade failures:

```yaml
upstreams:
  - name: backend
    circuit_breaker:
      enabled: true
      failure_threshold: 5
      timeout: 30s
```

### 10. Audit and Compliance

Enable audit logging:

```yaml
audit:
  enabled: true
  output: /var/log/loom/audit.log
  events:
    - config_change
    - route_match
    - auth_failure
    - rate_limit
```

## AI Gateway Security

Additional security for AI/LLM workloads:

```yaml
ai_gateway:
  security:
    # Detect prompt injection attempts
    prompt_injection_detection: true

    # Filter sensitive content
    content_filtering: true

    # Detect and mask PII
    pii_detection: true
    pii_action: mask  # mask, block, or log

    # Token limits to prevent abuse
    max_tokens_per_request: 4096
    max_tokens_per_minute: 100000
```

## GraphQL Security

Protect GraphQL endpoints:

```yaml
graphql:
  security:
    # Prevent deeply nested queries
    max_depth: 10

    # Limit query complexity
    max_complexity: 1000

    # Disable introspection in production
    introspection: false

    # Require persisted queries
    persisted_queries:
      required: true
```

## Vulnerability Disclosure Timeline

When we receive a vulnerability report:

| Day | Action |
|-----|--------|
| 0 | Report received, acknowledgment sent |
| 1-2 | Initial assessment and severity classification |
| 3-7 | Develop and test fix |
| 7-14 | Release patch |
| 14-30 | Public disclosure (coordinated with reporter) |

Critical vulnerabilities may have accelerated timelines.

## Security Contacts

- **Security Issues**: security@loom.dev
- **General Questions**: [GitHub Discussions](https://github.com/josedab/loom/discussions)
- **Bug Reports**: [GitHub Issues](https://github.com/josedab/loom/issues)
