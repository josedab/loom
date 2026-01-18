# ADR-0008: Circuit Breaker State Machine for Upstream Resilience

## Status

Accepted

## Context

Backend services fail. Networks partition. Databases slow down. An API gateway must handle these failures gracefully to prevent cascading failures across the system.

Without protection, a failing backend causes:

1. **Resource exhaustion** - Connections and goroutines pile up waiting for timeouts
2. **Latency amplification** - Every request waits for timeout before failing
3. **Cascade failures** - Gateway becomes unresponsive, affecting all routes
4. **Slow recovery** - Even after backend recovers, accumulated load causes re-failure

Loom needed a resilience mechanism that would:

- **Fail fast** - Reject requests immediately when backend is known-bad
- **Allow recovery** - Periodically test if backend has recovered
- **Be per-upstream** - Isolate failures to specific backends
- **Have low overhead** - Circuit breaker checks on every request must be fast

## Decision

We implemented the **Circuit Breaker pattern** as a three-state state machine with atomic state transitions.

```go
// internal/upstream/circuit.go
type State int32

const (
    StateClosed   State = iota  // Healthy: requests flow through
    StateOpen                    // Unhealthy: requests rejected immediately
    StateHalfOpen               // Testing: limited requests allowed
)

type CircuitBreaker struct {
    state           atomic.Int32
    failures        atomic.Int64
    successes       atomic.Int64
    lastFailureTime atomic.Int64

    // Configuration
    failureThreshold  int64         // Failures to trip open (default: 5)
    successThreshold  int64         // Successes to close (default: 3)
    timeout           time.Duration // Time in open before half-open (default: 30s)
    halfOpenRequests  int64         // Max concurrent in half-open (default: 3)

    mu sync.Mutex  // Only for state transitions
}
```

State machine diagram:

```
                    ┌─────────────────────────────────────┐
                    │                                     │
                    ▼                                     │
            ┌──────────────┐                              │
            │              │    failure_count >=          │
     ──────►│    CLOSED    │────threshold─────────────────┤
            │   (healthy)  │                              │
            │              │                              │
            └──────────────┘                              │
                    ▲                                     │
                    │                                     ▼
          success_count                           ┌──────────────┐
          >= threshold                            │              │
                    │                             │     OPEN     │
                    │                             │  (rejecting) │
            ┌──────────────┐                      │              │
            │              │                      └──────────────┘
            │  HALF-OPEN   │◄────timeout──────────────────┘
            │  (testing)   │              expires
            │              │
            └──────────────┘
                    │
                    │ any failure
                    │
                    └─────────────────────────────────────►OPEN
```

Implementation:

```go
func (cb *CircuitBreaker) Allow() (bool, func(success bool)) {
    state := State(cb.state.Load())

    switch state {
    case StateClosed:
        // Always allow, return recorder
        return true, cb.recordResult

    case StateOpen:
        // Check if timeout expired
        if cb.shouldAttemptReset() {
            if cb.transitionTo(StateHalfOpen) {
                return true, cb.recordHalfOpenResult
            }
        }
        return false, nil  // Reject immediately

    case StateHalfOpen:
        // Allow limited requests
        if cb.halfOpenCount.Add(1) <= cb.halfOpenRequests {
            return true, cb.recordHalfOpenResult
        }
        cb.halfOpenCount.Add(-1)
        return false, nil
    }

    return false, nil
}

func (cb *CircuitBreaker) recordResult(success bool) {
    if success {
        cb.failures.Store(0)  // Reset on success
        cb.successes.Add(1)
    } else {
        cb.successes.Store(0)
        failures := cb.failures.Add(1)
        cb.lastFailureTime.Store(time.Now().UnixNano())

        if failures >= cb.failureThreshold {
            cb.transitionTo(StateOpen)
        }
    }
}

func (cb *CircuitBreaker) recordHalfOpenResult(success bool) {
    defer cb.halfOpenCount.Add(-1)

    if success {
        successes := cb.successes.Add(1)
        if successes >= cb.successThreshold {
            cb.transitionTo(StateClosed)
        }
    } else {
        // Any failure in half-open returns to open
        cb.transitionTo(StateOpen)
    }
}
```

## Consequences

### Positive

- **Fast failure** - When circuit is open, requests fail in <1μs instead of waiting for timeout (potentially seconds). This preserves resources and improves user experience.

- **Automatic recovery** - The timeout mechanism automatically tests backend recovery without manual intervention. Operators don't need to "reset" circuits.

- **Isolation** - Each upstream has its own circuit breaker. A failing payment service doesn't affect the catalog service.

- **Observable** - Circuit state is exposed via metrics:
  ```
  loom_circuit_state{upstream="backend"} 0  # 0=closed, 1=open, 2=half-open
  loom_circuit_transitions_total{upstream="backend",from="closed",to="open"} 5
  ```

- **Low overhead** - Atomic operations for state checks mean no lock contention on the hot path. State transitions (rare) take a mutex.

- **Gradual recovery** - Half-open state limits concurrent requests to backend, preventing thundering herd on recovery.

### Negative

- **Threshold tuning required** - Default thresholds may not suit all backends. A backend with occasional slow requests might trip circuits unnecessarily.

- **False positives possible** - Network blips or client-side issues might be attributed to backend, tripping the circuit incorrectly.

- **Cold start penalty** - After circuit closes, backend receives full traffic immediately. No gradual ramp-up.

- **Per-endpoint not per-request** - Circuit state is per-upstream, not per-endpoint. One bad endpoint trips circuit for entire upstream.

### Configuration

```yaml
upstreams:
  - name: payment-service
    endpoints:
      - payment1.internal:8080
      - payment2.internal:8080
    circuit_breaker:
      failure_threshold: 5      # Failures before opening
      success_threshold: 3      # Successes before closing
      timeout: 30s              # Time open before half-open
      half_open_requests: 3     # Max concurrent in half-open
```

### Integration with Other Resilience Patterns

Circuit breaker works with other patterns in Loom:

```go
func (u *Upstream) ProxyRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
    // 1. Bulkhead check (concurrency limit)
    if !u.bulkhead.Acquire(ctx) {
        return nil, ErrBulkheadFull
    }
    defer u.bulkhead.Release()

    // 2. Circuit breaker check
    allowed, record := u.circuitBreaker.Allow()
    if !allowed {
        return nil, ErrCircuitOpen
    }

    // 3. Execute with retry
    var lastErr error
    for attempt := 0; attempt <= u.retryPolicy.MaxRetries; attempt++ {
        // Select endpoint (load balancer)
        endpoint := u.loadBalancer.Select(u.healthyEndpoints())

        // Make request with timeout
        resp, err := u.doRequest(ctx, endpoint, req)

        if err == nil && resp.StatusCode < 500 {
            record(true)
            return resp, nil
        }

        lastErr = err
        if !u.retryPolicy.ShouldRetry(resp, err) {
            break
        }

        // Exponential backoff
        time.Sleep(u.retryPolicy.Backoff(attempt))
    }

    record(false)
    return nil, lastErr
}
```

### Metrics and Alerting

```yaml
# Prometheus alerting rule
- alert: CircuitBreakerOpen
  expr: loom_circuit_state == 1
  for: 1m
  labels:
    severity: warning
  annotations:
    summary: "Circuit breaker open for {{ $labels.upstream }}"
```

## Alternatives Considered

1. **No circuit breaker (timeouts only)** - Rejected; timeouts alone don't provide fast failure or prevent resource exhaustion

2. **Hystrix-style with thread pools** - Rejected; Go's goroutines make thread pool isolation less relevant, adds complexity

3. **Retry-only resilience** - Rejected; retries without circuit breaker can amplify load on failing backends

4. **External circuit breaker (Istio, Linkerd)** - Valid for service mesh environments, but Loom should work standalone

5. **Sliding window failure rate** - Considered; simpler threshold approach chosen for v1, may add windowed tracking later

## References

- [Circuit Breaker Pattern (Martin Fowler)](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Release It! by Michael Nygard](https://pragprog.com/titles/mnee2/release-it-second-edition/)
- [Hystrix Circuit Breaker](https://github.com/Netflix/Hystrix/wiki/How-it-Works#circuit-breaker)
- [Resilience4j Circuit Breaker](https://resilience4j.readme.io/docs/circuitbreaker)
