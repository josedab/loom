// Package upstream provides the circuit breaker pattern implementation.
package upstream

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int32

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// String returns the string representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker prevents cascading failures.
// Optimized with atomics for lock-free reads in hot paths.
type CircuitBreaker struct {
	state            atomic.Int32  // CircuitState, atomic for lock-free reads
	failureCount     atomic.Int64  // Atomic counter
	successCount     atomic.Int64  // Atomic counter
	failureThreshold int64         // Immutable after creation
	successThreshold int64         // Immutable after creation
	timeout          time.Duration // Immutable after creation
	jitterRatio      atomic.Value  // float64, for timeout randomization
	lastStateChange  atomic.Value  // time.Time, atomic for lock-free reads
	mu               sync.Mutex    // Only for state transitions
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(failureThreshold, successThreshold int64, timeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if successThreshold <= 0 {
		successThreshold = 3
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	cb := &CircuitBreaker{
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
	}
	cb.state.Store(int32(CircuitClosed))
	cb.jitterRatio.Store(0.25) // Default: 25% jitter to prevent thundering herd
	cb.lastStateChange.Store(time.Now())
	return cb
}

// SetJitterRatio sets the jitter ratio for timeout randomization.
// The ratio should be between 0.0 and 1.0 (e.g., 0.25 = 25% jitter).
func (cb *CircuitBreaker) SetJitterRatio(ratio float64) {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	cb.jitterRatio.Store(ratio)
}

// getJitterRatio returns the current jitter ratio.
func (cb *CircuitBreaker) getJitterRatio() float64 {
	return cb.jitterRatio.Load().(float64)
}

// getLastStateChange returns the last state change time.
func (cb *CircuitBreaker) getLastStateChange() time.Time {
	return cb.lastStateChange.Load().(time.Time)
}

// jitteredTimeout returns the timeout with random jitter applied.
// Jitter is added (not subtracted) to prevent early retries.
func (cb *CircuitBreaker) jitteredTimeout() time.Duration {
	jitterRatio := cb.getJitterRatio()
	if jitterRatio <= 0 {
		return cb.timeout
	}
	// Add jitter: timeout + (0 to jitterRatio * timeout)
	jitter := time.Duration(float64(cb.timeout) * jitterRatio * rand.Float64())
	return cb.timeout + jitter
}

// Allow checks if a request is allowed through the circuit.
// Optimized for lock-free reads in the common case (closed circuit).
func (cb *CircuitBreaker) Allow() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		// Hot path: circuit is closed, allow request (lock-free)
		return true

	case CircuitOpen:
		// Check if timeout has elapsed
		lastChange := cb.getLastStateChange()
		jitteredTimeout := cb.jitteredTimeout()
		if time.Since(lastChange) <= jitteredTimeout {
			// Still in timeout, reject (lock-free)
			return false
		}

		// Timeout elapsed, attempt transition to half-open
		// Use mutex to ensure only one request triggers the transition
		cb.mu.Lock()
		// Double-check state after acquiring lock
		if CircuitState(cb.state.Load()) == CircuitOpen {
			if time.Since(cb.getLastStateChange()) > cb.jitteredTimeout() {
				cb.state.Store(int32(CircuitHalfOpen))
				cb.lastStateChange.Store(time.Now())
				cb.successCount.Store(0)
				cb.failureCount.Store(0)
				cb.mu.Unlock()
				return true
			}
		}
		cb.mu.Unlock()
		// Re-check state - might have changed
		return CircuitState(cb.state.Load()) != CircuitOpen

	case CircuitHalfOpen:
		// Allow request through (lock-free)
		return true
	}

	return false
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	newCount := cb.successCount.Add(1)
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitHalfOpen:
		if newCount >= cb.successThreshold {
			// Transition to closed
			cb.mu.Lock()
			// Double-check after lock
			if CircuitState(cb.state.Load()) == CircuitHalfOpen &&
				cb.successCount.Load() >= cb.successThreshold {
				cb.state.Store(int32(CircuitClosed))
				cb.failureCount.Store(0)
				cb.successCount.Store(0)
				cb.lastStateChange.Store(time.Now())
			}
			cb.mu.Unlock()
		}
	case CircuitClosed:
		// Reset failure count on success
		cb.failureCount.Store(0)
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	newCount := cb.failureCount.Add(1)
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		if newCount >= cb.failureThreshold {
			// Transition to open
			cb.mu.Lock()
			// Double-check after lock
			if CircuitState(cb.state.Load()) == CircuitClosed &&
				cb.failureCount.Load() >= cb.failureThreshold {
				cb.state.Store(int32(CircuitOpen))
				cb.lastStateChange.Store(time.Now())
			}
			cb.mu.Unlock()
		}
	case CircuitHalfOpen:
		// Any failure in half-open goes back to open
		cb.mu.Lock()
		if CircuitState(cb.state.Load()) == CircuitHalfOpen {
			cb.state.Store(int32(CircuitOpen))
			cb.lastStateChange.Store(time.Now())
			cb.failureCount.Store(0)
			cb.successCount.Store(0)
		}
		cb.mu.Unlock()
	}
}

// State returns the current circuit state.
// Lock-free using atomic operations.
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Stats returns circuit breaker statistics.
// Lock-free using atomic operations.
func (cb *CircuitBreaker) Stats() CircuitStats {
	return CircuitStats{
		State:           CircuitState(cb.state.Load()),
		FailureCount:    cb.failureCount.Load(),
		SuccessCount:    cb.successCount.Load(),
		LastStateChange: cb.getLastStateChange(),
	}
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state.Store(int32(CircuitClosed))
	cb.failureCount.Store(0)
	cb.successCount.Store(0)
	cb.lastStateChange.Store(time.Now())
}

// CircuitStats contains circuit breaker statistics.
type CircuitStats struct {
	State           CircuitState
	FailureCount    int64
	SuccessCount    int64
	LastStateChange time.Time
}
