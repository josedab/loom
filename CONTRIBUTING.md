# Contributing to Loom

Thank you for your interest in contributing to Loom! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Architecture Guidelines](#architecture-guidelines)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for using Makefile commands)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/josedab/loom.git
cd loom

# Install dependencies
go mod download

# Build
go build ./...

# Run tests
go test ./...
```

## Development Setup

### Building

```bash
# Standard build
go build ./cmd/loom

# Build with race detector (for development)
go build -race ./cmd/loom

# Build for specific platform
GOOS=linux GOARCH=amd64 go build ./cmd/loom
```

### Running

```bash
# Run with example config
go run ./cmd/loom -config configs/loom.yaml

# Run with debug logging
go run ./cmd/loom -config configs/loom.yaml -log-level debug
```

### Using Make

```bash
make build       # Build binary
make test        # Run tests
make test-race   # Run tests with race detector
make lint        # Run linter
make fmt         # Format code
make dev         # Run in development mode
```

## Project Structure

```
loom/
├── cmd/loom/              # Application entry point
│   └── main.go           # CLI flags, logging setup
├── configs/
│   └── loom.yaml         # Example configuration
├── internal/             # Private packages
│   ├── admin/            # Admin API server
│   ├── cache/            # Response caching
│   ├── canary/           # Canary deployments
│   ├── config/           # Configuration loading
│   ├── listener/         # Protocol listeners
│   ├── metrics/          # Prometheus metrics
│   ├── middleware/       # HTTP middleware
│   ├── plugin/           # WASM plugin runtime
│   ├── proxy/            # Core proxy handler
│   ├── router/           # URL routing
│   ├── server/           # Server orchestration
│   ├── shadow/           # Traffic shadowing
│   ├── tracing/          # OpenTelemetry
│   └── upstream/         # Backend management
├── docs/                 # Documentation
│   ├── adr/              # Architecture Decision Records
│   ├── ARCHITECTURE.md   # Architecture overview
│   ├── CONFIGURATION.md  # Configuration reference
│   ├── MIDDLEWARE.md     # Middleware reference
│   └── PLUGINS.md        # Plugin development
├── website/              # Docusaurus documentation site
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── CONTRIBUTING.md       # This file
```

## Making Changes

### Workflow

1. **Fork** the repository
2. **Create a branch** from `main`
3. **Make changes** following our guidelines
4. **Write tests** for new functionality
5. **Run tests** to ensure nothing is broken
6. **Submit a Pull Request**

### Branch Naming

Use descriptive branch names:

```
feature/add-grpc-support
fix/rate-limiter-memory-leak
docs/update-plugin-guide
refactor/simplify-router
```

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

**Examples:**
```
feat(router): add wildcard subdomain matching

fix(upstream): prevent connection leak on timeout

docs(plugins): add TinyGo development guide

test(middleware): add rate limiter edge cases
```

## Testing

### Running Tests

```bash
# All tests
go test ./...

# Verbose output
go test -v ./...

# Specific package
go test -v ./internal/router/...

# With coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Writing Tests

**Test File Naming:**
```
router.go       # Implementation
router_test.go  # Tests
```

**Table-Driven Tests (preferred):**
```go
func TestRouter_Match(t *testing.T) {
    tests := []struct {
        name     string
        path     string
        method   string
        expected string
        wantErr  bool
    }{
        {
            name:     "exact match",
            path:     "/api/users",
            method:   "GET",
            expected: "users-route",
        },
        {
            name:     "wildcard match",
            path:     "/api/v1/anything",
            method:   "GET",
            expected: "v1-wildcard",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

**Using httptest:**
```go
func TestHandler(t *testing.T) {
    // Create test backend
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    }))
    defer backend.Close()

    // Setup handler
    handler := NewHandler(...)

    // Make request
    req := httptest.NewRequest("GET", "/api/test", nil)
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)

    // Assert
    if rec.Code != http.StatusOK {
        t.Errorf("expected 200, got %d", rec.Code)
    }
}
```

### Benchmarks

```go
func BenchmarkRouter_Match(b *testing.B) {
    r := setupRouter()
    req := httptest.NewRequest("GET", "/api/users/123", nil)

    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            r.Match(req)
        }
    })
}
```

Run benchmarks:
```bash
go test -bench=. -benchmem ./internal/router/
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure CI passes** (tests, linting)
4. **Request review** from maintainers
5. **Address feedback** promptly

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed.

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Follows code style
- [ ] CI passes
```

### Review Process

- All PRs require at least one approval
- CI must pass before merging
- Squash commits when merging

## Code Style

### Go Style

Follow standard Go conventions:

- Use `gofmt` for formatting
- Follow [Effective Go](https://golang.org/doc/effective_go)
- Use `golint` and `go vet`

### Naming

```go
// Good
func NewRouter() *Router
func (r *Router) Match(req *http.Request) *MatchResult
type UpstreamConfig struct

// Bad
func MakeRouter() *Router
func (r *Router) DoMatch(req *http.Request) *MatchResult
type upstream_config struct
```

### Error Handling

```go
// Good - wrap errors with context
if err != nil {
    return fmt.Errorf("failed to load config: %w", err)
}

// Bad - lose context
if err != nil {
    return err
}
```

### Logging

Use structured logging with `slog`:

```go
// Good
slog.Info("request processed",
    "method", r.Method,
    "path", r.URL.Path,
    "status", status,
    "duration", duration,
)

// Bad
log.Printf("processed %s %s in %v", r.Method, r.URL.Path, duration)
```

### Comments

```go
// Package router implements URL routing with a radix tree.
package router

// Router matches HTTP requests to routes.
// It uses atomic operations for lock-free reads.
type Router struct {
    // ...
}

// Match finds the route matching the request.
// Returns nil if no route matches.
func (r *Router) Match(req *http.Request) *MatchResult {
    // ...
}
```

## Architecture Guidelines

### Design Principles

1. **Lock-Free Hot Path**: Use atomic operations for request processing
2. **Plugin Isolation**: WASM provides memory safety
3. **Graceful Operations**: Support hot-reload and graceful shutdown
4. **Zero Dependencies**: Avoid CGO for single-binary deployment

### Patterns to Follow

**Functional Options:**
```go
type Option func(*Config)

func WithTimeout(d time.Duration) Option {
    return func(c *Config) {
        c.Timeout = d
    }
}

func New(opts ...Option) *Handler {
    cfg := defaultConfig()
    for _, opt := range opts {
        opt(cfg)
    }
    return &Handler{config: cfg}
}
```

**Interface at Consumer:**
```go
// Good - interface defined where it's used
type Handler struct {
    balancer interface {
        Select(endpoints []*Endpoint) *Endpoint
    }
}

// Bad - interface defined at provider
type LoadBalancer interface {
    Select(endpoints []*Endpoint) *Endpoint
}
```

**Copy-on-Write:**
```go
type Router struct {
    snapshot atomic.Value // *routeSnapshot
    mu       sync.Mutex   // Only for writes
}

func (r *Router) Match(req *http.Request) *MatchResult {
    snap := r.snapshot.Load().(*routeSnapshot)
    // Lock-free read
    return snap.match(req)
}

func (r *Router) Configure(routes []RouteConfig) {
    r.mu.Lock()
    defer r.mu.Unlock()

    snap := buildSnapshot(routes)
    r.snapshot.Store(snap) // Atomic swap
}
```

### Performance Considerations

1. **Minimize Allocations**: Use object pools where appropriate
2. **Avoid Locks on Hot Path**: Use atomic operations
3. **Batch Operations**: Combine related operations
4. **Profile Before Optimizing**: Use pprof for evidence

### Testing Requirements

- All new features must have tests
- Bug fixes should include regression tests
- Aim for >80% coverage on new code
- Include benchmarks for performance-critical code

## Getting Help

- **Documentation**: Check `/docs` directory
- **Issues**: Search existing issues first
- **Discussions**: Use GitHub Discussions for questions

## Recognition

Contributors are recognized in:
- Release notes
- CONTRIBUTORS file
- Project documentation

Thank you for contributing to Loom!
