---
sidebar_position: 1
title: Contributing to Loom
description: Guide for contributing to the Loom project.
---

# Contributing to Loom

Thank you for your interest in contributing to Loom! This guide will help you get started.

## Ways to Contribute

- **Code** - Bug fixes, new features, performance improvements
- **Documentation** - Improve docs, add examples, fix typos
- **Testing** - Write tests, report bugs, test on different platforms
- **Design** - UI/UX for admin dashboard, architecture discussions
- **Community** - Answer questions, write blog posts, give talks

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for convenience commands)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/loom.git
cd loom
git remote add upstream https://github.com/loom/loom.git
```

### Build and Test

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test -v ./internal/proxy/...

# Run linter
golangci-lint run
```

### Run Locally

```bash
# Create a test config
cat > test-config.yaml << EOF
listeners:
  - name: http
    address: ":8080"

admin:
  enabled: true
  address: ":9091"

routes:
  - id: test
    path: /*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - httpbin.org:80
EOF

# Run Loom
go run ./cmd/loom -config test-config.yaml
```

## Development Workflow

### 1. Create a Branch

```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/my-feature
```

### 2. Make Changes

- Follow the code style (see below)
- Add tests for new functionality
- Update documentation if needed

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with conventional commit message
git commit -m "feat: add support for custom headers"
```

#### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Code style (formatting, semicolons, etc.)
- `refactor` - Code refactoring
- `perf` - Performance improvement
- `test` - Adding or updating tests
- `chore` - Build process, dependencies, etc.

**Examples:**
```
feat(router): add support for regex path matching
fix(upstream): handle connection timeout correctly
docs(readme): update installation instructions
perf(cache): reduce memory allocation in hot path
```

### 4. Push and Create PR

```bash
# Push to your fork
git push origin feature/my-feature
```

Then create a Pull Request on GitHub.

## Code Style

### Go Code

We follow standard Go conventions with some additions:

```go
// Package comment
package proxy

import (
    // Standard library
    "context"
    "net/http"

    // External packages
    "github.com/prometheus/client_golang/prometheus"

    // Internal packages
    "github.com/loom/loom/internal/config"
)

// Handler handles HTTP requests.
type Handler struct {
    router   Router
    upstream UpstreamManager
    metrics  *Metrics
}

// NewHandler creates a new Handler.
func NewHandler(r Router, u UpstreamManager, m *Metrics) *Handler {
    return &Handler{
        router:   r,
        upstream: u,
        metrics:  m,
    }
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Find route
    route, err := h.router.Match(r)
    if err != nil {
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    }

    // Forward request
    if err := h.forward(ctx, w, r, route); err != nil {
        h.handleError(w, err)
    }
}
```

### Style Guidelines

1. **Use descriptive names** - `connectionPool` not `cp`
2. **Handle all errors** - Don't ignore errors
3. **Add comments for exported types/functions**
4. **Keep functions focused** - One function, one purpose
5. **Use context for cancellation**
6. **Avoid global state**

### Formatting

```bash
# Format code
go fmt ./...

# Or use goimports for import organization
goimports -w .
```

## Testing

### Writing Tests

```go
func TestHandler_ServeHTTP(t *testing.T) {
    // Table-driven tests preferred
    tests := []struct {
        name       string
        path       string
        wantStatus int
    }{
        {
            name:       "valid route",
            path:       "/api/users",
            wantStatus: http.StatusOK,
        },
        {
            name:       "not found",
            path:       "/unknown",
            wantStatus: http.StatusNotFound,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            handler := setupTestHandler(t)

            // Execute
            req := httptest.NewRequest("GET", tt.path, nil)
            rec := httptest.NewRecorder()
            handler.ServeHTTP(rec, req)

            // Assert
            if rec.Code != tt.wantStatus {
                t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
            }
        })
    }
}
```

### Test Coverage

```bash
# Run tests with coverage
go test -coverprofile=coverage.out ./...

# View coverage report
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out
```

We aim for >80% test coverage on new code.

## Documentation

### Code Documentation

- Add comments for all exported types, functions, and methods
- Use complete sentences
- Start with the name of the thing being documented

```go
// Handler handles incoming HTTP requests and routes them
// to appropriate upstream backends.
type Handler struct {
    // ...
}

// NewHandler creates a new Handler with the given dependencies.
// It returns an error if the configuration is invalid.
func NewHandler(cfg Config) (*Handler, error) {
    // ...
}
```

### User Documentation

Documentation is in the `website/docs` directory using Docusaurus:

```bash
cd website

# Install dependencies
npm install

# Start dev server
npm start

# Build
npm run build
```

## Pull Request Process

### Before Submitting

- [ ] Code compiles without errors
- [ ] All tests pass
- [ ] New code has tests
- [ ] Documentation updated if needed
- [ ] Commit messages follow convention
- [ ] No merge conflicts with main

### PR Description Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing done.

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)
```

### Review Process

1. Automated checks run (CI, linting, tests)
2. Maintainer reviews code
3. Address feedback
4. Maintainer approves and merges

## Project Structure

```
loom/
├── cmd/
│   └── loom/           # CLI entry point
├── internal/           # Internal packages (not importable)
│   ├── admin/         # Admin API
│   ├── cache/         # Response caching
│   ├── config/        # Configuration
│   ├── middleware/    # HTTP middleware
│   ├── plugin/        # WASM plugin runtime
│   ├── proxy/         # Core proxy
│   ├── router/        # URL routing
│   ├── server/        # Server orchestration
│   ├── tracing/       # OpenTelemetry
│   └── upstream/      # Backend management
├── pkg/               # Public packages (importable)
├── configs/           # Example configurations
├── website/           # Documentation site
└── go.mod
```

## Getting Help

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and ideas
- **Discord** - Real-time chat with the community

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project README

Thank you for contributing to Loom!
