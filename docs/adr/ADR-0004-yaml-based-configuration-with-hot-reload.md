# ADR-0004: YAML-Based Configuration with Hot Reload

## Status

Accepted

## Context

API gateways require extensive configuration: routes, upstreams, plugins, TLS certificates, rate limits, and more. Loom needed a configuration approach that would:

1. **Support GitOps workflows** - Configuration should be version-controlled and reviewable
2. **Enable zero-downtime updates** - Changes should apply without restarting the gateway
3. **Be human-readable** - Operators should easily understand and modify configuration
4. **Support validation** - Invalid configuration should be rejected before applying
5. **Work in containerized environments** - ConfigMaps, mounted volumes, etc.

Two primary approaches were considered:

- **API-first configuration** - All configuration via REST/gRPC API, persisted to database
- **File-first configuration** - Configuration in files, watched for changes

## Decision

We chose **YAML file-based configuration with fsnotify-based hot reload**.

```go
// internal/config/config.go
type Manager struct {
    path      string
    config    atomic.Value  // *Config
    watcher   *fsnotify.Watcher
    callbacks []func(*Config)
    mu        sync.RWMutex
}

func (m *Manager) Watch(ctx context.Context) error {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    m.watcher = watcher

    if err := watcher.Add(filepath.Dir(m.path)); err != nil {
        return err
    }

    // Debounce rapid file changes (editors often write multiple times)
    debounce := time.NewTimer(0)
    <-debounce.C

    for {
        select {
        case event := <-watcher.Events:
            if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
                debounce.Reset(100 * time.Millisecond)
            }
        case <-debounce.C:
            if err := m.reload(); err != nil {
                slog.Error("config reload failed", "error", err)
                // Keep running with old config
            }
        case <-ctx.Done():
            return nil
        }
    }
}

func (m *Manager) reload() error {
    newConfig, err := m.load(m.path)
    if err != nil {
        return fmt.Errorf("load: %w", err)
    }

    if err := m.validate(newConfig); err != nil {
        return fmt.Errorf("validate: %w", err)
    }

    m.config.Store(newConfig)

    // Notify all registered components
    for _, cb := range m.callbacks {
        cb(newConfig)
    }

    slog.Info("configuration reloaded successfully")
    return nil
}
```

Configuration structure:

```yaml
# configs/loom.yaml
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
  - id: api
    path: /api/*
    upstream: backend
    plugins:
      - jwt-auth
      - rate-limit

upstreams:
  - name: backend
    endpoints:
      - api1.internal:8080
      - api2.internal:8080
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s
```

## Consequences

### Positive

- **GitOps native** - Configuration files are version-controlled, diff-able, and reviewable. Changes go through standard PR workflows with approval gates.

- **Zero-downtime updates** - fsnotify detects file changes and triggers reload. Components receive callbacks and update atomically. No connections are dropped.

- **Human-readable** - YAML is widely understood. Operators can read and modify configuration without special tools. Comments are supported.

- **Declarative** - Configuration describes desired state. The gateway reconciles to match. No imperative "add route" / "delete route" sequences to track.

- **Environment-agnostic** - Works with Kubernetes ConfigMaps, Docker bind mounts, Ansible templates, or direct file editing. No special deployment tooling required.

- **Validation before apply** - Invalid configuration is rejected entirely. The gateway continues running with the previous valid configuration, preventing outages from typos.

- **Atomic updates** - File writes are detected after completion (debounced). Partial writes don't trigger reloads.

### Negative

- **No real-time API** - Cannot add a route via API call; must modify file. For use cases requiring programmatic configuration (dynamic service discovery), this adds friction.

- **File system dependency** - Requires writable file system or file watching capability. Serverless environments may have limitations.

- **Merge conflicts** - Multiple operators modifying the same file can cause conflicts. Requires coordination or tooling.

- **No audit trail** - File changes don't inherently record who made them or why. Relies on Git history or external auditing.

- **Debounce delay** - 100ms debounce means changes aren't instant. Acceptable for configuration but not for real-time updates.

### Mitigation: Admin API for Observability

While configuration is file-based, Loom provides a read-only Admin API for observability:

```
GET /admin/routes      - View current routes
GET /admin/upstreams   - View upstream status
GET /admin/health      - View endpoint health
GET /admin/metrics     - Prometheus metrics
```

The Admin API can also accept writes that are persisted to the config file, bridging the gap for programmatic updates while maintaining file as source of truth.

## Alternatives Considered

1. **etcd/Consul-based configuration** - Rejected; adds operational dependency for features most users don't need

2. **Database-backed configuration** - Rejected; adds state management complexity, backup/restore concerns

3. **Environment variables only** - Rejected; doesn't scale to complex configurations with nested structures

4. **JSON configuration** - Rejected in favor of YAML; YAML supports comments and is more human-friendly

## References

- [fsnotify library](https://github.com/fsnotify/fsnotify)
- [YAML specification](https://yaml.org/spec/)
- [12-Factor App Config](https://12factor.net/config)
