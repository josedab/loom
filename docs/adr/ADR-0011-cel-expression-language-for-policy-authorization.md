# ADR-0011: CEL Expression Language for Policy Authorization

## Status

Accepted

## Context

Authorization in API gateways ranges from simple (API key validation) to complex (attribute-based access control with multiple conditions). Loom needed an authorization system that could:

1. **Express complex rules** - Combine multiple conditions: user roles, request attributes, time-based access
2. **Be configuration-driven** - Rules should be changeable without code deployment
3. **Be safe** - Untrusted expressions must not crash the gateway or access unauthorized resources
4. **Be fast** - Policy evaluation happens on every request
5. **Be familiar** - Operators should recognize the syntax

Options considered:

- **Hardcoded Go functions** - Fast but requires deployment for changes
- **JSON-based rule DSL** - Configuration-friendly but limited expressiveness
- **Lua scripting** - Powerful but requires embedding interpreter
- **OPA/Rego** - Full policy engine but heavy dependency
- **CEL (Common Expression Language)** - Google's expression language, designed for security policies

## Decision

We adopted **CEL (Common Expression Language)** for policy-based authorization, using the `google/cel-go` library.

```go
// internal/policy/cel.go
type PolicyEngine struct {
    env      *cel.Env
    programs map[string]cel.Program  // Compiled policies
    mu       sync.RWMutex
}

func NewPolicyEngine() (*PolicyEngine, error) {
    env, err := cel.NewEnv(
        cel.Declarations(
            // Request attributes
            decls.NewVar("request.method", decls.String),
            decls.NewVar("request.path", decls.String),
            decls.NewVar("request.headers", decls.NewMapType(decls.String, decls.String)),
            decls.NewVar("request.query", decls.NewMapType(decls.String, decls.String)),
            decls.NewVar("request.host", decls.String),

            // Auth context
            decls.NewVar("auth.principal", decls.String),
            decls.NewVar("auth.claims", decls.NewMapType(decls.String, decls.Dyn)),
            decls.NewVar("auth.roles", decls.NewListType(decls.String)),

            // Environment
            decls.NewVar("env.name", decls.String),
            decls.NewVar("time.now", decls.Timestamp),
        ),
    )
    if err != nil {
        return nil, err
    }

    return &PolicyEngine{
        env:      env,
        programs: make(map[string]cel.Program),
    }, nil
}

func (e *PolicyEngine) Compile(name, expression string) error {
    ast, issues := e.env.Compile(expression)
    if issues != nil && issues.Err() != nil {
        return fmt.Errorf("compile error: %w", issues.Err())
    }

    // Type-check the expression
    checked, issues := e.env.Check(ast)
    if issues != nil && issues.Err() != nil {
        return fmt.Errorf("type check error: %w", issues.Err())
    }

    // Ensure result is boolean
    if checked.OutputType() != cel.BoolType {
        return fmt.Errorf("policy must return bool, got %v", checked.OutputType())
    }

    program, err := e.env.Program(checked)
    if err != nil {
        return err
    }

    e.mu.Lock()
    e.programs[name] = program
    e.mu.Unlock()

    return nil
}

func (e *PolicyEngine) Evaluate(name string, input map[string]interface{}) (bool, error) {
    e.mu.RLock()
    program, ok := e.programs[name]
    e.mu.RUnlock()

    if !ok {
        return false, fmt.Errorf("policy not found: %s", name)
    }

    result, _, err := program.Eval(input)
    if err != nil {
        return false, err
    }

    return result.Value().(bool), nil
}
```

Integration with middleware:

```go
// internal/middleware/policy.go
func PolicyMiddleware(engine *policy.PolicyEngine) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Build evaluation context
            input := map[string]interface{}{
                "request.method":  r.Method,
                "request.path":    r.URL.Path,
                "request.headers": headerMap(r.Header),
                "request.query":   queryMap(r.URL.Query()),
                "request.host":    r.Host,
                "time.now":        time.Now(),
            }

            // Add auth context if available
            if claims := getAuthClaims(r.Context()); claims != nil {
                input["auth.principal"] = claims.Subject
                input["auth.claims"] = claims.Custom
                input["auth.roles"] = claims.Roles
            }

            // Evaluate route policy
            routeID := getRouteID(r.Context())
            allowed, err := engine.Evaluate(routeID, input)
            if err != nil {
                slog.Error("policy evaluation failed", "route", routeID, "error", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
            }

            if !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Consequences

### Positive

- **Expressive policies** - CEL supports complex boolean logic, string operations, list/map access, and temporal expressions:
  ```cel
  // Role-based access
  "admin" in auth.roles || "editor" in auth.roles

  // Path-based with method
  request.method == "GET" || auth.principal == "service-account"

  // Time-based access
  time.now.getHours() >= 9 && time.now.getHours() < 17

  // Header inspection
  request.headers["X-Internal"] == "true" && request.path.startsWith("/internal/")

  // Claim-based authorization
  auth.claims.department == "engineering" && auth.claims.level >= 3
  ```

- **Type safety** - CEL expressions are type-checked at compile time. Invalid expressions fail fast, not at runtime.

- **Sandboxed execution** - CEL is designed for untrusted input. No file system access, no network calls, no infinite loops (no recursion, bounded iteration).

- **Configuration-driven** - Policies defined in YAML, changeable via hot reload:
  ```yaml
  routes:
    - id: admin-api
      path: /admin/*
      upstream: admin-service
      policy: '"admin" in auth.roles'

    - id: user-api
      path: /users/*
      upstream: user-service
      policy: 'request.method == "GET" || auth.principal == request.path.split("/")[2]'
  ```

- **Familiar syntax** - CEL syntax is similar to C/Java/Go expressions. Operators learn it quickly.

- **Compilation caching** - Expressions are compiled once and reused. Evaluation is fast (microseconds).

### Negative

- **Learning curve** - CEL is another syntax to learn. Not as widely known as regex or SQL.

- **Limited standard library** - CEL has fewer built-in functions than full scripting languages. Complex transformations may be awkward.

- **Dependency size** - `google/cel-go` adds ~5MB to binary size.

- **Error messages** - CEL compile errors can be cryptic for complex expressions.

- **No state across requests** - Each evaluation is independent. Cannot implement rate limiting or counting in CEL.

### Policy Examples

```yaml
# Public read-only access
routes:
  - id: public-api
    path: /public/*
    policy: 'request.method in ["GET", "HEAD", "OPTIONS"]'

# Authenticated users only
routes:
  - id: user-api
    path: /api/v1/*
    policy: 'has(auth.principal) && auth.principal != ""'

# Admin endpoints
routes:
  - id: admin
    path: /admin/*
    policy: '"admin" in auth.roles || "superuser" in auth.roles'

# Resource ownership
routes:
  - id: user-profile
    path: /users/{id}/*
    policy: |
      request.method == "GET" ||
      auth.principal == request.path.split("/")[2] ||
      "admin" in auth.roles

# Business hours only
routes:
  - id: trading-api
    path: /trading/*
    policy: |
      time.now.getDayOfWeek() >= 1 &&
      time.now.getDayOfWeek() <= 5 &&
      time.now.getHours() >= 9 &&
      time.now.getHours() < 16

# IP allowlist for internal services
routes:
  - id: internal-api
    path: /internal/*
    policy: |
      request.headers["X-Forwarded-For"].startsWith("10.") ||
      request.headers["X-Forwarded-For"].startsWith("192.168.")

# Complex multi-factor authorization
routes:
  - id: sensitive-data
    path: /api/sensitive/*
    policy: |
      "data-access" in auth.roles &&
      auth.claims.mfa_verified == true &&
      auth.claims.session_age < duration("1h") &&
      request.headers["X-Request-Reason"] != ""
```

### Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | URL path |
| `request.host` | string | Host header |
| `request.headers` | map[string]string | Request headers |
| `request.query` | map[string]string | Query parameters |
| `auth.principal` | string | Authenticated user ID |
| `auth.roles` | list[string] | User roles |
| `auth.claims` | map[string]dyn | JWT/auth claims |
| `env.name` | string | Environment name (prod, staging) |
| `time.now` | timestamp | Current time |

### Performance

CEL evaluation is fast:
- Simple expression: ~1-5μs
- Complex expression: ~10-50μs
- Compilation: ~100-500μs (one-time)

For comparison, a single HTTP header lookup is ~100ns.

## Alternatives Considered

1. **Go code for policies** - Rejected; requires deployment for policy changes

2. **OPA/Rego** - Full policy engine with rich features. Rejected due to:
   - Larger dependency footprint
   - Separate Rego syntax to learn
   - Overkill for per-request authorization (OPA designed for broader policy use cases)

3. **Lua embedded** - Rejected; unsafe without sandboxing, complex to embed securely

4. **JSON rule DSL** - Rejected; limited expressiveness, awkward for complex conditions

5. **Casbin** - RBAC/ABAC library. Considered; CEL chosen for greater flexibility and expression power

## References

- [CEL Specification](https://github.com/google/cel-spec)
- [cel-go Library](https://github.com/google/cel-go)
- [CEL Language Definition](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
- [Kubernetes CEL Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
