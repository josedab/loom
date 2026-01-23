# Loom Middleware Reference

Complete reference for all built-in middleware components.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Compression](#compression)
- [Security Headers](#security-headers)
- [Logging](#logging)
- [Body Limit](#body-limit)
- [CORS](#cors)
- [mTLS](#mtls)
- [HTTP/3](#http3)
- [Custom Middleware](#custom-middleware)

## Overview

Middleware in Loom follows the standard Go pattern:

```go
func Middleware(config Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Pre-processing
            next.ServeHTTP(w, r)
            // Post-processing
        })
    }
}
```

### Execution Order

Middlewares execute in configured order:

```
Request → Recovery → RequestID → Metrics → Tracing → RateLimit → CORS → Handler
Response ← Recovery ← RequestID ← Metrics ← Tracing ← RateLimit ← CORS ← Handler
```

## Authentication

### API Key Authentication

Validates requests using API keys from headers or query parameters.

**Configuration:**
```go
middleware.APIKeyMiddleware(middleware.APIKeyConfig{
    Header:       "X-API-Key",           // Header name (default)
    QueryParam:   "api_key",             // Query parameter name
    Keys:         map[string]APIKeyInfo{ // Valid keys
        "key123": {
            Name:      "production",
            Roles:     []string{"read", "write"},
            RateLimit: 1000,
            ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
            AllowedIPs: []string{"192.168.1."},
        },
    },
    ExcludedPaths: []string{"/health", "/healthz", "/ready"},
})
```

**Features:**
- Constant-time comparison (timing attack prevention)
- Per-key metadata (roles, rate limits, expiration)
- IP allowlist with prefix matching
- Context-based key info propagation

**Response Headers:**
- `401 Unauthorized` - Missing or invalid key
- `403 Forbidden` - Key expired or IP not allowed

**Context Access:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    keyInfo := middleware.GetAPIKeyInfo(r.Context())
    if keyInfo != nil {
        fmt.Printf("Key: %s, Roles: %v\n", keyInfo.Name, keyInfo.Roles)
    }
}
```

### Basic Authentication

HTTP Basic authentication with bcrypt password hashing.

**Configuration:**
```go
middleware.BasicAuthMiddleware(middleware.BasicAuthConfig{
    Users: map[string]string{
        "admin": "$2a$10$...",  // bcrypt hash
        "user":  "$2a$10$...",
    },
    Realm:         "Loom Admin",
    ExcludedPaths: []string{"/health"},
})
```

**Features:**
- bcrypt password verification
- Constant-time comparison
- Configurable realm
- Path exclusion

### JWT Authentication

JWT token validation (requires external library integration).

**Supported Algorithms:**
- HS256, HS384, HS512 (HMAC)
- RS256, RS384, RS512 (RSA)
- ES256, ES384, ES512 (ECDSA)

## Rate Limiting

Token bucket rate limiting per client.

**Configuration:**
```go
middleware.RateLimitMiddleware(middleware.RateLimitConfig{
    Rate:            100.0,           // Tokens per second
    Burst:           10,              // Maximum burst
    KeyFunc:         nil,             // Custom key extraction
    CleanupInterval: 5 * time.Minute, // Bucket cleanup
    TrustedProxies:  []string{"10.0.0.0/8"}, // Trust proxy headers
})
```

**Features:**
- Token bucket algorithm
- Per-client limiting (by IP)
- Trusted proxy support
- Automatic cleanup of unused buckets

**Response Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
Retry-After: 1  (when rate limited)
```

**Response:**
- `429 Too Many Requests` - Rate limit exceeded

### Trusted Proxy Configuration

```go
// Only trust X-Forwarded-For from these IPs
extractor := middleware.NewTrustedProxyExtractor([]string{
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
})

config := middleware.RateLimitConfig{
    KeyFunc: extractor.ExtractClientIP,
}
```

### Per-Route Rate Limiting

```go
limiter := middleware.NewPerRouteRateLimiter()

// Configure per route
limiter.Configure("api-v1", middleware.RateLimitConfig{
    Rate:  1000,
    Burst: 100,
})

limiter.Configure("api-v2", middleware.RateLimitConfig{
    Rate:  500,
    Burst: 50,
})
```

## Compression

Gzip compression for responses.

**Configuration:**
```go
middleware.CompressionMiddleware(middleware.CompressionConfig{
    Level:        gzip.DefaultCompression, // 1-9 or -1
    MinSize:      1024,                     // Minimum bytes
    ContentTypes: []string{                 // Types to compress
        "text/html",
        "text/css",
        "text/plain",
        "text/javascript",
        "application/json",
        "application/javascript",
        "application/xml",
    },
    ExcludedPaths: []string{"/metrics"},
})
```

**Features:**
- Writer pooling (reduces allocations)
- Content-Type filtering
- Minimum size threshold
- Streaming support via `Flush()`
- Respects `Accept-Encoding` header

**Response Headers:**
```
Content-Encoding: gzip
Vary: Accept-Encoding
```

## Security Headers

Adds security-related HTTP headers.

**Configuration:**
```go
middleware.SecurityHeadersMiddleware(middleware.SecurityConfig{
    // HSTS (only on HTTPS)
    HSTSMaxAge:            31536000, // 1 year
    HSTSIncludeSubdomains: true,
    HSTSPreload:           true,

    // Content Security Policy
    ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'",

    // Permissions Policy
    PermissionsPolicy: "camera=(), microphone=(), geolocation=()",

    // Standard headers
    XContentTypeOptions: "nosniff",        // Default
    XFrameOptions:       "DENY",           // Default
    XXSSProtection:      "1; mode=block",  // Default
    ReferrerPolicy:      "strict-origin-when-cross-origin", // Default

    // Custom headers
    CustomHeaders: map[string]string{
        "X-Custom": "value",
    },
})
```

**Headers Added:**
| Header | Default Value |
|--------|---------------|
| `Strict-Transport-Security` | max-age=31536000 (HTTPS only) |
| `Content-Security-Policy` | (if configured) |
| `Permissions-Policy` | (if configured) |
| `X-Content-Type-Options` | nosniff |
| `X-Frame-Options` | DENY |
| `X-XSS-Protection` | 1; mode=block |
| `Referrer-Policy` | strict-origin-when-cross-origin |

## Logging

Structured access logging with slog.

**Configuration:**
```go
middleware.LoggingMiddleware(middleware.LoggingConfig{
    Logger:             slog.Default(),
    SkipPaths:          []string{"/health", "/metrics"},
    SkipHealthChecks:   true,
    LogHeaders:         []string{"User-Agent", "X-Request-ID"},
    MaskHeaders:        []string{"Authorization", "Cookie", "X-API-Key"},
    IncludeQueryParams: false,
})
```

**Logged Attributes:**
```json
{
  "level": "INFO",
  "msg": "request",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "duration_ns": 1234567,
  "size": 1024,
  "remote_addr": "192.168.1.100",
  "protocol": "HTTP/2.0",
  "user_agent": "curl/7.68.0",
  "request_id": "abc123"
}
```

**Log Levels by Status:**
- 2xx, 3xx → INFO
- 4xx → WARN
- 5xx → ERROR

**Header Masking:**
Sensitive headers logged as `[MASKED]`:
```json
{
  "Authorization": "[MASKED]",
  "Cookie": "[MASKED]"
}
```

## Body Limit

Limits request body size.

**Configuration:**
```go
middleware.BodyLimitMiddleware(middleware.BodyLimitConfig{
    MaxSize:       1024 * 1024,          // 1MB (default)
    ExcludedPaths: []string{"/upload"},
})
```

**Features:**
- Early rejection via Content-Length check
- Streaming enforcement via limitedReader
- Path exclusion for large uploads

**Response:**
- `413 Request Entity Too Large` - Body exceeds limit

**Alternative using stdlib:**
```go
middleware.MaxBytesMiddleware(1024 * 1024) // Uses http.MaxBytesReader
```

## CORS

Cross-Origin Resource Sharing configuration.

**Configuration:**
```go
middleware.CORSMiddleware(middleware.CORSConfig{
    AllowOrigins: []string{
        "https://example.com",
        "https://*.example.com",  // Wildcard subdomain
        "*",                       // Allow all (careful!)
    },
    AllowMethods: []string{
        "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH",
    },
    AllowHeaders: []string{
        "Accept",
        "Authorization",
        "Content-Type",
        "X-Requested-With",
    },
    ExposeHeaders: []string{
        "X-Request-ID",
        "X-RateLimit-Remaining",
    },
    AllowCredentials:     true,
    MaxAge:               86400, // 24 hours
    PrivateNetworkAccess: true,  // For local development
})
```

**Origin Matching:**
| Pattern | Matches |
|---------|---------|
| `*` | All origins |
| `https://example.com` | Exact match |
| `https://*.example.com` | Single-level wildcard |

**Preflight Handling:**
- OPTIONS requests return `204 No Content`
- Sets `Access-Control-Allow-*` headers
- Caches preflight for `MaxAge` seconds

**Response Headers:**
```
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Vary: Origin
```

## mTLS

Mutual TLS client certificate validation.

**Configuration:**
```go
middleware.MTLSMiddleware(middleware.MTLSConfig{
    RequireClientCert: true,

    // Certificate validation
    AllowedCNs:   []string{"client.example.com"},
    AllowedOrgs:  []string{"Example Inc"},
    AllowedOUs:   []string{"Engineering"},
    AllowedDNSSANs: []string{"*.internal.example.com"},
    AllowedURISANs: []string{
        "spiffe://cluster.local/*",  // SPIFFE support
    },

    // Context extraction
    ExtractIdentity: true,

    // Path exclusion
    ExcludedPaths: []string{"/health", "/ready"},
})
```

**Features:**
- Certificate CN, Org, OU validation
- DNS and URI SAN validation
- SPIFFE ID support with helpers
- Wildcard matching in SANs
- Context-based identity extraction

**Context Access:**
```go
func handler(w http.ResponseWriter, r *http.Request) {
    identity := middleware.GetMTLSIdentity(r.Context())
    if identity != nil {
        fmt.Printf("CN: %s, Org: %v\n", identity.CommonName, identity.Organization)

        // SPIFFE helpers
        if middleware.ValidateSPIFFEID(identity.URIs[0]) {
            domain := middleware.ExtractSPIFFETrustDomain(identity.URIs[0])
            workload := middleware.ExtractSPIFFEWorkloadPath(identity.URIs[0])
        }
    }
}
```

**Response:**
- `400 Bad Request` - No TLS connection
- `401 Unauthorized` - No client certificate
- `403 Forbidden` - Certificate validation failed

## HTTP/3

HTTP/3 and QUIC-related middleware.

### Alt-Svc Advertisement

Advertises HTTP/3 availability to clients.

**Configuration:**
```go
middleware.HTTP3Advertise(middleware.HTTP3Config{
    Port:   443,
    MaxAge: 86400, // 24 hours
})
```

**Response Header (HTTPS only):**
```
Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
```

### 0-RTT Protection

Protects against 0-RTT replay attacks.

**Configuration:**
```go
middleware.QUIC0RTTMiddleware(middleware.QUIC0RTTConfig{
    AllowUnsafe: false, // Block POST/PUT/DELETE in 0-RTT
})
```

**Safe Methods (always allowed):**
- GET, HEAD, OPTIONS

**Unsafe Methods (blocked by default in 0-RTT):**
- POST, PUT, DELETE, PATCH

**Response:**
- `425 Too Early` - Unsafe method in 0-RTT
- `Retry-After: 0` header included

## Custom Middleware

### Creating Custom Middleware

```go
package middleware

import (
    "net/http"
)

type CustomConfig struct {
    Option1 string
    Option2 int
}

func CustomMiddleware(cfg CustomConfig) func(http.Handler) http.Handler {
    // Initialize resources here (runs once)
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Pre-processing
            // Modify request, check conditions, etc.

            // Call next handler
            next.ServeHTTP(w, r)

            // Post-processing
            // Modify response, log, etc.
        })
    }
}
```

### Middleware with Response Capture

```go
type responseWriter struct {
    http.ResponseWriter
    statusCode int
    size       int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
    n, err := rw.ResponseWriter.Write(b)
    rw.size += n
    return n, err
}

func MetricsMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()

            rw := &responseWriter{ResponseWriter: w, statusCode: 200}
            next.ServeHTTP(rw, r)

            duration := time.Since(start)
            log.Printf("status=%d size=%d duration=%v", rw.statusCode, rw.size, duration)
        })
    }
}
```

### Middleware Chain

```go
// Using MiddlewareChain helper
handler := proxy.MiddlewareChain(
    baseHandler,
    middleware.RecoveryMiddleware(),
    middleware.RequestIDMiddleware(),
    middleware.LoggingMiddleware(logConfig),
    middleware.RateLimitMiddleware(rlConfig),
)

// Manual chaining
handler := rateLimitMiddleware(
    loggingMiddleware(
        requestIDMiddleware(
            recoveryMiddleware(
                baseHandler,
            ),
        ),
    ),
)
```

### Context Propagation

```go
type contextKey string

const userIDKey contextKey = "userID"

func AuthMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract user ID from token
            userID := extractUserID(r)

            // Add to context
            ctx := context.WithValue(r.Context(), userIDKey, userID)
            r = r.WithContext(ctx)

            next.ServeHTTP(w, r)
        })
    }
}

// Access in handler
func handler(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value(userIDKey).(string)
    if ok {
        // Use userID
    }
}
```

## Middleware Order Recommendations

**Recommended Order:**
1. **Recovery** - Catch panics first
2. **Request ID** - Add tracing ID early
3. **Metrics** - Capture all requests
4. **Tracing** - OpenTelemetry context
5. **Security Headers** - Add headers early
6. **CORS** - Handle preflight before auth
7. **Rate Limiting** - Block before processing
8. **Authentication** - Validate identity
9. **Body Limit** - Prevent large payloads
10. **Compression** - Last before handler

**Example:**
```go
handler := proxy.MiddlewareChain(
    proxyHandler,
    middleware.RecoveryMiddleware(),
    middleware.RequestIDMiddleware(),
    metrics.Middleware(metricsConfig),
    tracing.Middleware(tracingConfig),
    middleware.SecurityHeadersMiddleware(securityConfig),
    middleware.CORSMiddleware(corsConfig),
    middleware.RateLimitMiddleware(rateLimitConfig),
    middleware.APIKeyMiddleware(authConfig),
    middleware.BodyLimitMiddleware(bodyLimitConfig),
    middleware.CompressionMiddleware(compressionConfig),
)
```
