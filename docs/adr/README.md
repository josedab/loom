# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Loom API Gateway project. ADRs document significant architectural decisions, the context that led to them, and their consequences.

## What is an ADR?

An ADR is a document that captures an important architectural decision made along with its context and consequences. They help new team members understand why the system is built the way it is.

## ADR Index

| ADR | Title | Status | Summary |
|-----|-------|--------|---------|
| [0001](ADR-0001-pure-go-webassembly-runtime-with-wazero.md) | Pure Go WebAssembly Runtime with Wazero | Accepted | Chose wazero for WASM plugins to enable single-binary deployment without CGO |
| [0002](ADR-0002-lock-free-router-with-atomic-copy-on-write.md) | Lock-Free Router with Atomic Copy-on-Write | Accepted | Implemented lock-free routing via atomic.Value for maximum request throughput |
| [0003](ADR-0003-sharded-in-memory-cache-architecture.md) | Sharded In-Memory Cache Architecture | Accepted | Designed 256-shard cache to minimize lock contention under high concurrency |
| [0004](ADR-0004-yaml-based-configuration-with-hot-reload.md) | YAML-Based Configuration with Hot Reload | Accepted | Adopted file-based config with fsnotify watching for zero-downtime updates |
| [0005](ADR-0005-standard-go-middleware-chain-pattern.md) | Standard Go Middleware Chain Pattern | Accepted | Used idiomatic `func(http.Handler) http.Handler` for composable request processing |
| [0006](ADR-0006-plugin-instance-pooling-with-sync-pool.md) | Plugin Instance Pooling with sync.Pool | Accepted | Implemented aggressive pooling to amortize WASM instantiation costs |
| [0007](ADR-0007-multi-protocol-listener-architecture.md) | Multi-Protocol Listener Architecture | Accepted | Designed independent listeners for HTTP/1.1, HTTP/2, HTTP/3, and gRPC |
| [0008](ADR-0008-circuit-breaker-state-machine-for-upstream-resilience.md) | Circuit Breaker State Machine | Accepted | Implemented three-state circuit breaker for upstream failure protection |
| [0009](ADR-0009-pluggable-load-balancing-strategy-interface.md) | Pluggable Load Balancing Strategy Interface | Accepted | Defined LoadBalancer interface with five built-in implementations |
| [0010](ADR-0010-async-log-phase-with-bounded-worker-pool.md) | Async Log Phase with Bounded Worker Pool | Accepted | Made plugin log phase async via bounded worker pool to avoid blocking requests |
| [0011](ADR-0011-cel-expression-language-for-policy-authorization.md) | CEL Expression Language for Policy | Accepted | Adopted Google CEL for flexible, safe policy-based authorization |
| [0012](ADR-0012-canary-deployments-with-sticky-sessions.md) | Canary Deployments with Sticky Sessions | Accepted | Built traffic splitting with weighted routing and cookie-based session affinity |

## Reading Order

For new team members, we recommend reading the ADRs in this order to understand how Loom evolved:

1. **Foundation** (Core Architecture)
   - ADR-0001: WASM Runtime (explains why we can deploy as a single binary)
   - ADR-0004: Configuration (explains how config works and hot-reload)
   - ADR-0005: Middleware Pattern (explains request processing model)

2. **Performance** (Why it's fast)
   - ADR-0002: Lock-Free Router (explains routing performance)
   - ADR-0003: Sharded Cache (explains caching architecture)
   - ADR-0006: Plugin Pooling (explains plugin performance)

3. **Protocols** (What it supports)
   - ADR-0007: Multi-Protocol Listeners (explains HTTP/2, HTTP/3, gRPC support)

4. **Resilience** (How it handles failures)
   - ADR-0008: Circuit Breaker (explains failure handling)
   - ADR-0009: Load Balancing (explains traffic distribution)

5. **Advanced Features**
   - ADR-0010: Async Logging (explains plugin log phase)
   - ADR-0011: CEL Policies (explains authorization)
   - ADR-0012: Canary Deployments (explains traffic management)

## ADR Template

When adding new ADRs, use this template:

```markdown
# ADR-NNNN: Title

## Status

[Proposed | Accepted | Deprecated | Superseded by ADR-XXXX]

## Context

What is the issue that we're seeing that is motivating this decision or change?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?
```

## Contributing

When making significant architectural decisions:

1. Create a new ADR with the next sequential number
2. Use the template above
3. Include code examples where helpful
4. Document both positive and negative consequences
5. Reference related ADRs if applicable
6. Submit for review with the implementing PR

## References

- [ADR GitHub Organization](https://adr.github.io/)
- [Documenting Architecture Decisions (Michael Nygard)](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
