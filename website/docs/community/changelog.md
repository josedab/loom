---
sidebar_position: 4
title: Changelog
description: Version history and release notes for Loom API Gateway.
---

# Changelog

All notable changes to Loom are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Kubernetes Gateway API conformance support
- eBPF acceleration for connection steering on Linux
- AI/LLM gateway with multi-provider routing

### Changed
- Improved circuit breaker state machine
- Enhanced health check reliability

### Fixed
- WebSocket connection handling under load
- Memory leak in WASM plugin cleanup

---

## [1.0.0] - 2024-01-15

First stable release of Loom API Gateway.

### Added

#### Core Features
- **HTTP/1.1, HTTP/2, HTTP/3 (QUIC)** protocol support
- **gRPC** native proxying with streaming support
- **WebSocket** proxying with automatic upgrade handling
- **gRPC-Web** for browser-based gRPC clients

#### Routing
- Radix tree router for high-performance path matching
- Path patterns: exact, prefix (`/*`), and parameters (`/{id}`)
- Host-based routing for multi-tenant deployments
- Method-based filtering
- Header-based routing

#### Load Balancing
- Round Robin
- Weighted Round Robin
- Least Connections
- Random
- IP Hash
- Consistent Hashing

#### Resilience
- Circuit breaker with configurable thresholds
- Automatic retries with exponential backoff
- Request timeouts
- Connection pooling

#### Health Checks
- Active HTTP health checks
- Configurable intervals and thresholds
- Automatic backend removal/restoration

#### WASM Plugins
- Full Proxy-Wasm ABI 0.2.x support
- AOT compilation via wazero for near-native performance
- Plugin phases: request headers, request body, response headers, response body, log
- Per-route plugin configuration

#### Security
- TLS 1.2/1.3 termination
- Mutual TLS (mTLS) support
- Built-in rate limiting (token bucket)
- API key authentication
- Basic authentication
- JWT validation
- CORS handling
- Security headers (HSTS, CSP, etc.)

#### Observability
- Prometheus metrics
- OpenTelemetry tracing (OTLP, Jaeger, Zipkin)
- Structured logging (JSON, text)
- Admin API for runtime inspection

#### Configuration
- YAML configuration with environment variable expansion
- Hot reload without dropping connections
- Configuration validation

#### Deployment
- Single binary, zero dependencies
- Docker images for linux/amd64 and linux/arm64
- Kubernetes manifests and Helm chart

---

## [0.9.0] - 2024-01-01

### Added
- GraphQL gateway with federation support
- WebSocket subscriptions for GraphQL
- Automatic persisted queries (APQ)
- Query depth and complexity limiting
- Response caching with normalized entities

### Changed
- Improved WASM plugin memory management
- Enhanced error messages for configuration issues

### Fixed
- Race condition in upstream health checker
- Incorrect Content-Length for chunked responses

---

## [0.8.0] - 2023-12-15

### Added
- AI/LLM gateway functionality
- Multi-provider support (OpenAI, Anthropic, Azure OpenAI)
- Token accounting and usage tracking
- Semantic caching for LLM responses
- Prompt injection detection
- Content filtering and PII detection

### Changed
- Refactored middleware chain for better performance
- Improved TLS handshake performance

### Fixed
- Memory leak in long-lived connections
- Incorrect handling of trailer headers

---

## [0.7.0] - 2023-12-01

### Added
- Response caching middleware
- Sharded in-memory cache with TTL
- Stale-while-revalidate support
- Cache bypass header
- Redis cache backend

### Changed
- Reduced memory allocations in hot path
- Improved connection pool management

### Fixed
- Panic on malformed request headers
- Incorrect upstream selection after health check failure

---

## [0.6.0] - 2023-11-15

### Added
- Canary deployment support
- Weighted traffic splitting
- Header-based targeting
- Sticky sessions via cookie
- Auto-rollout with configurable stages

### Changed
- Enhanced load balancer interface
- Improved metrics cardinality

### Fixed
- Race condition in route configuration update
- Incorrect handling of empty request bodies

---

## [0.5.0] - 2023-11-01

### Added
- Request shadowing (traffic mirroring)
- Fire-and-forget shadow requests
- Percentage-based sampling
- Shadow request timeout

### Changed
- Improved circuit breaker state transitions
- Enhanced health check reliability

### Fixed
- Connection leak in upstream manager
- Incorrect retry behavior for POST requests

---

## [0.4.0] - 2023-10-15

### Added
- HTTP/3 (QUIC) support via quic-go
- 0-RTT connection establishment
- Connection migration
- Alt-Svc header advertisement

### Changed
- Updated TLS configuration options
- Improved listener management

### Fixed
- TLS handshake timeout handling
- Incorrect HTTP/2 GOAWAY behavior

---

## [0.3.0] - 2023-10-01

### Added
- OpenTelemetry tracing integration
- Span propagation through plugins
- Context injection into upstream requests
- Sampling configuration

### Changed
- Enhanced middleware chain performance
- Improved logging context

### Fixed
- Missing trace context in error responses
- Incorrect span timing for async operations

---

## [0.2.0] - 2023-09-15

### Added
- WASM plugin support via wazero
- Proxy-Wasm ABI implementation
- Plugin lifecycle management
- Plugin configuration passing

### Changed
- Refactored request handling pipeline
- Improved error handling

### Fixed
- Memory leak in request context
- Incorrect handling of plugin errors

---

## [0.1.0] - 2023-09-01

Initial pre-release.

### Added
- Basic HTTP proxy functionality
- Radix tree router
- Round robin load balancing
- Health checks
- Prometheus metrics
- YAML configuration
- Admin API

---

## Upgrade Guide

### Upgrading to 1.0.0

No breaking changes from 0.9.x. Recommended steps:

1. Back up your configuration
2. Update binary: `go install github.com/josedab/loom/cmd/loom@v1.0.0`
3. Restart Loom
4. Verify functionality

### Upgrading from 0.8.x to 0.9.x

The GraphQL configuration section was added. Existing configurations work without changes.

### Upgrading from 0.7.x to 0.8.x

AI Gateway configuration section added. Existing configurations work without changes.

---

## Version Support

| Version | Status | Support Until |
|---------|--------|---------------|
| 1.x | Current | Active development |
| 0.9.x | Maintenance | 2024-06-01 |
| 0.8.x | End of Life | 2024-03-01 |
| < 0.8 | End of Life | No longer supported |

---

## Links

- [GitHub Releases](https://github.com/josedab/loom/releases)
- [Migration Guides](/docs/guides/migration-overview)
- [Configuration Reference](/docs/reference/configuration)
