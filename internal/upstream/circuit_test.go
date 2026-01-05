package upstream

import (
	"testing"
	"time"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := NewCircuitBreaker(5, 3, 30*time.Second)

	if cb.State() != CircuitClosed {
		t.Errorf("expected initial state Closed, got %s", cb.State())
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

	// Should be closed initially
	if !cb.Allow() {
		t.Error("circuit should allow requests when closed")
	}

	// Record failures
	cb.RecordFailure()
	cb.RecordFailure()

	// Still closed
	if cb.State() != CircuitClosed {
		t.Error("circuit should still be closed after 2 failures")
	}

	// Third failure should open
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("circuit should be open after 3 failures, got %s", cb.State())
	}

	// Should not allow requests when open
	if cb.Allow() {
		t.Error("circuit should not allow requests when open")
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(1, 1, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("circuit should be open")
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Should transition to half-open and allow
	if !cb.Allow() {
		t.Error("circuit should allow after timeout (half-open)")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("circuit should be half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_ClosesAfterSuccesses(t *testing.T) {
	cb := NewCircuitBreaker(1, 2, 10*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()

	// Wait and transition to half-open
	time.Sleep(15 * time.Millisecond)
	cb.Allow()

	// Record successes
	cb.RecordSuccess()
	if cb.State() != CircuitHalfOpen {
		t.Error("circuit should still be half-open after 1 success")
	}

	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("circuit should be closed after 2 successes, got %s", cb.State())
	}
}

func TestCircuitBreaker_ReopensOnFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(1, 2, 10*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()

	// Wait and transition to half-open
	time.Sleep(15 * time.Millisecond)
	cb.Allow()

	if cb.State() != CircuitHalfOpen {
		t.Fatal("circuit should be half-open")
	}

	// Failure in half-open should reopen
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("circuit should be open after failure in half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(3, 1, time.Second)

	// Record some failures
	cb.RecordFailure()
	cb.RecordFailure()

	// Success should reset
	cb.RecordSuccess()

	// Should need 3 more failures to open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Error("circuit should still be closed")
	}

	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Error("circuit should be open after 3 consecutive failures")
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(5, 3, time.Second)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // Resets failure count

	stats := cb.Stats()
	if stats.State != CircuitClosed {
		t.Errorf("expected Closed state, got %s", stats.State)
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker(1, 1, time.Second)

	// Open the circuit
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("circuit should be open")
	}

	// Reset
	cb.Reset()
	if cb.State() != CircuitClosed {
		t.Errorf("circuit should be closed after reset, got %s", cb.State())
	}

	if !cb.Allow() {
		t.Error("circuit should allow after reset")
	}
}

func TestCircuitBreaker_DefaultValues(t *testing.T) {
	// Test with zero/negative values - should use defaults
	cb := NewCircuitBreaker(0, -1, 0)

	// Should still function with defaults
	if cb.State() != CircuitClosed {
		t.Error("circuit should start closed")
	}
}

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func BenchmarkCircuitBreaker_Allow(b *testing.B) {
	cb := NewCircuitBreaker(100, 10, time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.Allow()
	}
}

func BenchmarkCircuitBreaker_RecordSuccess(b *testing.B) {
	cb := NewCircuitBreaker(100, 10, time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.RecordSuccess()
	}
}
