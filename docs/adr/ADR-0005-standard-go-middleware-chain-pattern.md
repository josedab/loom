# ADR-0005: Standard Go Middleware Chain Pattern

## Status

Accepted

## Context

HTTP middleware is fundamental to API gateway functionality. Cross-cutting concerns like logging, authentication, rate limiting, compression, and tracing need to be applied consistently across all requests without cluttering core routing logic.

Loom needed a middleware architecture that would:

1. **Be composable** - Middlewares should combine cleanly without coupling
2. **Support ordering** - Some middlewares must run before others (auth before handler)
3. **Enable reuse** - Middlewares should work with any `http.Handler`
4. **Allow per-route configuration** - Different routes may need different middleware stacks
5. **Be testable** - Each middleware should be testable in isolation

Several patterns were considered:

- **Custom middleware interface** - Define our own middleware type
- **Framework-specific middleware** - Use a framework like Echo or Gin
- **Standard Go pattern** - `func(http.Handler) http.Handler`

## Decision

We adopted the **standard Go middleware pattern**: `func(http.Handler) http.Handler`.

```go
// internal/middleware/logging.go
func LoggingMiddleware(cfg LoggingConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()

            // Wrap response writer to capture status code
            wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

            // Call next handler
            next.ServeHTTP(wrapped, r)

            // Log after request completes
            slog.Info("request completed",
                "method", r.Method,
                "path", r.URL.Path,
                "status", wrapped.statusCode,
                "duration", time.Since(start),
                "bytes", wrapped.bytesWritten,
            )
        })
    }
}
```

Middleware chain composition:

```go
// internal/server/server.go
func (s *Server) buildHandler() http.Handler {
    handler := s.proxy // Core proxy handler

    // Apply middlewares in reverse order (last applied = first executed)
    middlewares := []func(http.Handler) http.Handler{
        middleware.Recovery(),
        middleware.RequestID(),
        s.metrics.Middleware(),
    }

    if s.config.Tracing.Enabled {
        middlewares = append(middlewares, s.tracing.Middleware())
    }

    if s.config.RateLimit.Enabled {
        middlewares = append(middlewares, s.rateLimiter.Middleware())
    }

    if s.config.CORS.Enabled {
        middlewares = append(middlewares, middleware.CORS(s.config.CORS))
    }

    // Chain them together
    for i := len(middlewares) - 1; i >= 0; i-- {
        handler = middlewares[i](handler)
    }

    return handler
}
```

## Consequences

### Positive

- **Standard idiom** - This pattern is used throughout the Go ecosystem (stdlib, popular frameworks, third-party libraries). Developers immediately understand it.

- **No framework lock-in** - Middlewares work with any `http.Handler`. Can use stdlib `http.ServeMux`, third-party routers, or custom handlers interchangeably.

- **Clean composition** - Middlewares are pure functions that wrap handlers. No global state, no side effects outside the closure.

- **Flexible ordering** - Chain order is explicit in code. Easy to reason about which middleware runs first.

- **Easy testing** - Each middleware can be tested independently:

```go
func TestLoggingMiddleware(t *testing.T) {
    // Create a test handler
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })

    // Wrap with middleware
    handler := LoggingMiddleware(LoggingConfig{})(inner)

    // Test
    req := httptest.NewRequest("GET", "/test", nil)
    rec := httptest.NewRecorder()
    handler.ServeHTTP(rec, req)

    assert.Equal(t, http.StatusOK, rec.Code)
}
```

- **Context propagation** - Request context flows naturally through the chain via `r.Context()`.

- **Pre/post processing** - Middlewares can execute logic before and after calling `next.ServeHTTP()`, enabling patterns like timing, response modification, and cleanup.

### Negative

- **Verbose for simple cases** - The nested function signature is verbose. Simple middlewares require boilerplate.

- **Ordering is implicit** - The reverse-order application can be confusing:
  ```go
  // This middleware runs FIRST despite being added LAST
  handler = middleware.Recovery()(handler)
  ```

- **No built-in short-circuiting** - To stop the chain (e.g., auth failure), middleware must not call `next.ServeHTTP()` and write its own response. This is correct but requires understanding.

- **Response modification is complex** - Modifying responses requires wrapping `http.ResponseWriter`, which doesn't implement all optional interfaces (Hijacker, Flusher, Pusher).

### Middleware Inventory

Loom includes these built-in middlewares:

| Middleware | Purpose | Configuration |
|------------|---------|---------------|
| Recovery | Panic recovery with stack traces | Always enabled |
| RequestID | Unique request ID generation | Always enabled |
| Logging | Structured access logging | `logging.enabled` |
| Metrics | Prometheus instrumentation | Always enabled |
| Tracing | OpenTelemetry spans | `tracing.enabled` |
| RateLimit | Token bucket rate limiting | `rate_limit.enabled` |
| CORS | Cross-origin headers | `cors.enabled` |
| Compression | Gzip response compression | `compression.enabled` |
| Security | Security headers (HSTS, CSP) | `security.enabled` |
| BodyLimit | Request body size limiting | `body_limit.max_size` |

### Request Flow

```
Request → Recovery → RequestID → Metrics → Tracing → RateLimit → CORS → Proxy → Response
```

Each middleware wraps the next, creating an onion-like structure where:
- Pre-processing happens outside-in (Recovery first)
- Post-processing happens inside-out (Recovery last)

## Alternatives Considered

1. **Custom Middleware interface** - `type Middleware interface { Handle(ctx, req, next) }` - Rejected; non-standard, requires learning, doesn't compose with ecosystem

2. **Echo/Gin framework** - Rejected; adds dependency, framework lock-in, overkill for gateway use case

3. **Interceptor pattern** - Rejected; more complex, doesn't fit HTTP request/response model well

4. **AOP-style decorators** - Rejected; Go doesn't have language-level support, would require code generation

## References

- [Go HTTP Middleware Guide](https://gobyexample.com/http-middleware)
- [Making and Using HTTP Middleware](https://www.alexedwards.net/blog/making-and-using-middleware)
- [Standard Library http.Handler](https://pkg.go.dev/net/http#Handler)
