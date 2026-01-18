# ADR-0007: Multi-Protocol Listener Architecture

## Status

Accepted

## Context

Modern API gateways must support diverse protocols to serve different client needs:

- **HTTP/1.1** - Universal compatibility, simple clients
- **HTTP/2** - Multiplexing, header compression, server push
- **HTTP/3 (QUIC)** - UDP-based, 0-RTT, connection migration
- **gRPC** - Protobuf-based RPC, streaming, service mesh integration
- **WebSocket** - Bidirectional real-time communication

Loom needed to support all these protocols while:

1. **Sharing routing logic** - All protocols should use the same route configuration
2. **Sharing middleware** - Common concerns (auth, logging) should apply uniformly
3. **Independent scaling** - Different protocols may have different resource needs
4. **TLS flexibility** - Some listeners need TLS, others don't
5. **Graceful shutdown** - All listeners must drain cleanly

## Decision

We implemented a **multi-listener architecture** where each protocol gets its own independent listener, but all share common routing and middleware.

```go
// internal/listener/listener.go
type Manager struct {
    listeners map[string]*Listener
    handler   http.Handler  // Shared handler for all protocols
    mu        sync.RWMutex
}

type Listener struct {
    Name     string
    Address  string
    Protocol Protocol
    TLS      *tls.Config
    server   interface{}  // *http.Server, *http3.Server, or *grpc.Server
}

type Protocol string

const (
    ProtocolHTTP  Protocol = "http"
    ProtocolHTTPS Protocol = "https"
    ProtocolH2C   Protocol = "h2c"    // HTTP/2 cleartext
    ProtocolHTTP3 Protocol = "http3"  // QUIC-based
    ProtocolGRPC  Protocol = "grpc"
    ProtocolGRPCS Protocol = "grpcs"  // gRPC with TLS
)
```

Listener initialization:

```go
func (m *Manager) Start(ctx context.Context, configs []config.ListenerConfig) error {
    for _, cfg := range configs {
        listener, err := m.createListener(cfg)
        if err != nil {
            return fmt.Errorf("create listener %s: %w", cfg.Name, err)
        }
        m.listeners[cfg.Name] = listener

        // Start in separate goroutine
        go func(l *Listener) {
            if err := l.serve(ctx); err != nil && err != http.ErrServerClosed {
                slog.Error("listener failed", "name", l.Name, "error", err)
            }
        }(listener)
    }
    return nil
}

func (m *Manager) createListener(cfg config.ListenerConfig) (*Listener, error) {
    l := &Listener{
        Name:     cfg.Name,
        Address:  cfg.Address,
        Protocol: Protocol(cfg.Protocol),
    }

    if cfg.TLS != nil {
        tlsConfig, err := loadTLSConfig(cfg.TLS)
        if err != nil {
            return nil, err
        }
        l.TLS = tlsConfig
    }

    switch l.Protocol {
    case ProtocolHTTP, ProtocolHTTPS:
        l.server = &http.Server{
            Addr:      cfg.Address,
            Handler:   m.handler,
            TLSConfig: l.TLS,
        }

    case ProtocolH2C:
        // HTTP/2 cleartext requires h2c wrapper
        h2s := &http2.Server{}
        l.server = &http.Server{
            Addr:    cfg.Address,
            Handler: h2c.NewHandler(m.handler, h2s),
        }

    case ProtocolHTTP3:
        l.server = &http3.Server{
            Addr:      cfg.Address,
            Handler:   m.handler,
            TLSConfig: l.TLS,
        }

    case ProtocolGRPC, ProtocolGRPCS:
        opts := []grpc.ServerOption{}
        if l.TLS != nil {
            opts = append(opts, grpc.Creds(credentials.NewTLS(l.TLS)))
        }
        l.server = grpc.NewServer(opts...)
    }

    return l, nil
}
```

## Consequences

### Positive

- **Protocol independence** - Each listener runs in its own goroutine with its own server instance. A problem with HTTP/3 doesn't affect HTTP/1.1.

- **Shared logic** - All HTTP-based protocols share the same `http.Handler`. Routing, middleware, and plugins work identically regardless of protocol.

- **Flexible deployment** - Operators can enable only the protocols they need:
  ```yaml
  listeners:
    - name: public-http
      address: ":80"
      protocol: http
    - name: public-https
      address: ":443"
      protocol: https
      tls:
        cert_file: /etc/loom/cert.pem
        key_file: /etc/loom/key.pem
    - name: internal-grpc
      address: ":9090"
      protocol: grpc
  ```

- **Independent TLS** - Each listener can have its own TLS configuration, certificates, and minimum version requirements.

- **Graceful shutdown** - Each listener shuts down independently with its own timeout:
  ```go
  func (m *Manager) Shutdown(ctx context.Context) error {
      var wg sync.WaitGroup
      for _, l := range m.listeners {
          wg.Add(1)
          go func(l *Listener) {
              defer wg.Done()
              l.shutdown(ctx)
          }(l)
      }
      wg.Wait()
      return nil
  }
  ```

- **HTTP/3 Alt-Svc advertisement** - HTTPS listeners can advertise HTTP/3 availability:
  ```go
  // Middleware adds Alt-Svc header
  w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
  ```

### Negative

- **Resource overhead** - Each listener has its own accept loop, connection tracking, and buffers. Many listeners = more memory.

- **Port management** - Multiple listeners on different ports may complicate firewall rules and load balancer configuration.

- **gRPC divergence** - gRPC uses `grpc.Server` which has a different interface than `http.Handler`. Requires separate handling for gRPC-specific features.

- **WebSocket special handling** - WebSocket upgrades happen within HTTP handlers, not as separate listeners. This is handled at the middleware layer.

### Protocol Details

#### HTTP/2 Cleartext (H2C)

For internal services that don't need TLS but want HTTP/2 benefits:

```go
h2s := &http2.Server{}
handler := h2c.NewHandler(httpHandler, h2s)
```

H2C allows HTTP/2 without the TLS handshake overhead, useful for service-to-service communication behind a TLS-terminating load balancer.

#### HTTP/3 (QUIC)

HTTP/3 provides significant benefits for mobile and lossy networks:

- **0-RTT connection establishment** - Returning clients can send data immediately
- **No head-of-line blocking** - Lost packets don't block other streams
- **Connection migration** - Seamless network switches (WiFi → cellular)

```go
server := &http3.Server{
    Addr:      ":443",
    Handler:   handler,
    TLSConfig: tlsConfig,
    QuicConfig: &quic.Config{
        MaxIdleTimeout:  30 * time.Second,
        KeepAlivePeriod: 10 * time.Second,
    },
}
```

#### gRPC Integration

gRPC services can be proxied through Loom for:
- Unified authentication
- Rate limiting
- Observability
- Load balancing

```yaml
routes:
  - id: grpc-api
    path: /myservice.MyService/*
    upstream: grpc-backend
    protocol: grpc
```

### Configuration Example

```yaml
listeners:
  # Public HTTP (redirects to HTTPS)
  - name: http
    address: ":80"
    protocol: http

  # Public HTTPS with HTTP/2
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
      min_version: "1.2"

  # HTTP/3 on same port (UDP)
  - name: http3
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem

  # Internal gRPC (no TLS, behind mesh)
  - name: grpc-internal
    address: ":9090"
    protocol: grpc

  # Internal HTTP/2 cleartext
  - name: h2c-internal
    address: ":8080"
    protocol: h2c
```

## Alternatives Considered

1. **Single multiplexed listener** - Rejected; protocol detection adds latency and complexity

2. **Protocol-specific gateway instances** - Rejected; operational overhead of running multiple processes

3. **nginx/envoy-style listener model** - Inspired our design but simplified for Go's concurrency model

4. **HTTP/3 as automatic upgrade only** - Rejected; explicit configuration gives operators control

## References

- [quic-go HTTP/3 implementation](https://github.com/quic-go/quic-go)
- [golang.org/x/net/http2](https://pkg.go.dev/golang.org/x/net/http2)
- [gRPC-Go](https://github.com/grpc/grpc-go)
- [RFC 9114 - HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
