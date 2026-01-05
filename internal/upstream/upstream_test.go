package upstream

import (
	"context"
	"testing"
	"time"
)

func TestRoundRobinBalancer_Select(t *testing.T) {
	lb := &RoundRobinBalancer{}

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	// Should cycle through endpoints
	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		ep := lb.Select(endpoints)
		if ep == nil {
			t.Fatal("expected endpoint, got nil")
		}
		seen[ep.Address]++
	}

	// Each endpoint should be selected 3 times
	for addr, count := range seen {
		if count != 3 {
			t.Errorf("endpoint %s selected %d times, want 3", addr, count)
		}
	}
}

func TestRoundRobinBalancer_SkipsUnhealthy(t *testing.T) {
	lb := &RoundRobinBalancer{}

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	endpoints[0].SetHealthy(true)
	endpoints[1].SetHealthy(false) // Unhealthy
	endpoints[2].SetHealthy(true)

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		ep := lb.Select(endpoints)
		if ep == nil {
			t.Fatal("expected endpoint")
		}
		seen[ep.Address] = true
	}

	if seen["host2:8080"] {
		t.Error("unhealthy endpoint should not be selected")
	}
}

func TestRoundRobinBalancer_NoHealthyEndpoints(t *testing.T) {
	lb := &RoundRobinBalancer{}

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
	}
	endpoints[0].SetHealthy(false)

	ep := lb.Select(endpoints)
	if ep != nil {
		t.Error("expected nil when no healthy endpoints")
	}
}

func TestWeightedBalancer_Select(t *testing.T) {
	lb := NewWeightedBalancer()

	endpoints := []*Endpoint{
		{Address: "host1:8080", Weight: 1},
		{Address: "host2:8080", Weight: 9},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	// Run many selections and check distribution
	counts := make(map[string]int)
	iterations := 10000
	for i := 0; i < iterations; i++ {
		ep := lb.Select(endpoints)
		if ep == nil {
			t.Fatal("expected endpoint")
		}
		counts[ep.Address]++
	}

	// host2 should be selected ~9x more than host1
	ratio := float64(counts["host2:8080"]) / float64(counts["host1:8080"])
	if ratio < 7 || ratio > 11 {
		t.Errorf("weight ratio should be ~9, got %.2f", ratio)
	}
}

func TestLeastConnBalancer_Select(t *testing.T) {
	lb := &LeastConnBalancer{}

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	// Simulate connections
	endpoints[0].activeConns.Store(10)
	endpoints[1].activeConns.Store(5)
	endpoints[2].activeConns.Store(8)

	ep := lb.Select(endpoints)
	if ep == nil {
		t.Fatal("expected endpoint")
	}
	if ep.Address != "host2:8080" {
		t.Errorf("expected host2 (least connections), got %s", ep.Address)
	}
}

func TestRandomBalancer_Select(t *testing.T) {
	lb := NewRandomBalancer()

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	// Should select from all endpoints over many iterations
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ep := lb.Select(endpoints)
		if ep == nil {
			t.Fatal("expected endpoint")
		}
		seen[ep.Address] = true
	}

	if len(seen) != 3 {
		t.Errorf("expected all 3 endpoints to be selected, got %d", len(seen))
	}
}

func TestConsistentHashBalancer_Select(t *testing.T) {
	lb := NewConsistentHashBalancer(150, "")

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	// Build the ring
	lb.buildRing(endpoints)

	// Should select from all endpoints over many keys
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ep := lb.SelectWithKey(endpoints, "user-"+string(rune('a'+i)))
		if ep == nil {
			t.Fatal("expected endpoint")
		}
		seen[ep.Address] = true
	}

	// Consistent hash should distribute across all nodes
	if len(seen) < 2 {
		t.Errorf("expected distribution across multiple endpoints, got %d", len(seen))
	}
}

func TestConsistentHashBalancer_Consistency(t *testing.T) {
	lb := NewConsistentHashBalancer(150, "")

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	for _, ep := range endpoints {
		ep.SetHealthy(true)
	}

	lb.buildRing(endpoints)

	// Same key should always map to same endpoint
	key := "user-12345"
	first := lb.SelectWithKey(endpoints, key)
	if first == nil {
		t.Fatal("expected endpoint")
	}

	for i := 0; i < 100; i++ {
		ep := lb.SelectWithKey(endpoints, key)
		if ep.Address != first.Address {
			t.Errorf("consistent hash not consistent: got %s, want %s", ep.Address, first.Address)
		}
	}
}

func TestConsistentHashBalancer_SkipsUnhealthy(t *testing.T) {
	lb := NewConsistentHashBalancer(150, "")

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	endpoints[0].SetHealthy(true)
	endpoints[1].SetHealthy(false) // Unhealthy
	endpoints[2].SetHealthy(true)

	lb.buildRing(endpoints)

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		ep := lb.SelectWithKey(endpoints, "user-"+string(rune('a'+i)))
		if ep == nil {
			t.Fatal("expected endpoint")
		}
		seen[ep.Address] = true
	}

	if seen["host2:8080"] {
		t.Error("unhealthy endpoint should not be selected")
	}
}

func TestConsistentHashBalancer_NoHealthyEndpoints(t *testing.T) {
	lb := NewConsistentHashBalancer(150, "")

	endpoints := []*Endpoint{
		{Address: "host1:8080"},
	}
	endpoints[0].SetHealthy(false)

	lb.buildRing(endpoints)

	ep := lb.SelectWithKey(endpoints, "any-key")
	if ep != nil {
		t.Error("expected nil when no healthy endpoints")
	}
}

func TestConsistentHashBalancer_GetHashKey(t *testing.T) {
	lb := NewConsistentHashBalancer(150, "X-User-ID")

	if lb.GetHashKey() != "X-User-ID" {
		t.Errorf("expected hash key X-User-ID, got %s", lb.GetHashKey())
	}
}

func TestBulkhead_Acquire(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{
		MaxConcurrent: 2,
	})

	ctx := context.Background()

	// First two acquires should succeed
	release1, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}

	release2, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("second acquire should succeed: %v", err)
	}

	// Third acquire should fail (no queueing)
	_, err = b.Acquire(ctx)
	if err != ErrBulkheadFull {
		t.Errorf("expected ErrBulkheadFull, got %v", err)
	}

	// Release one slot
	release1()

	// Now acquire should succeed again
	release3, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire after release should succeed: %v", err)
	}

	release2()
	release3()
}

func TestBulkhead_TryAcquire(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{
		MaxConcurrent: 1,
	})

	// First TryAcquire should succeed
	release, ok := b.TryAcquire()
	if !ok {
		t.Fatal("first TryAcquire should succeed")
	}

	// Second should fail
	_, ok = b.TryAcquire()
	if ok {
		t.Error("second TryAcquire should fail")
	}

	release()

	// Now should succeed again
	release, ok = b.TryAcquire()
	if !ok {
		t.Error("TryAcquire after release should succeed")
	}
	release()
}

func TestBulkhead_WithQueue(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{
		MaxConcurrent: 1,
		QueueSize:     1,
		Timeout:       100 * time.Millisecond,
	})

	ctx := context.Background()

	// Acquire first slot
	release1, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("first acquire should succeed: %v", err)
	}

	// Start goroutine that waits in queue
	done := make(chan error, 1)
	go func() {
		release2, err := b.Acquire(ctx)
		if err == nil {
			release2()
		}
		done <- err
	}()

	// Give goroutine time to enter queue
	time.Sleep(20 * time.Millisecond)

	// Third request should fail (queue is full)
	_, err = b.Acquire(ctx)
	if err != ErrBulkheadFull {
		t.Errorf("expected ErrBulkheadFull when queue is full, got %v", err)
	}

	// Release first slot
	release1()

	// Queued request should complete
	err = <-done
	if err != nil {
		t.Errorf("queued request should succeed: %v", err)
	}
}

func TestBulkhead_Stats(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{
		MaxConcurrent: 5,
		QueueSize:     10,
	})

	stats := b.Stats()
	if stats.MaxConcurrent != 5 {
		t.Errorf("expected MaxConcurrent 5, got %d", stats.MaxConcurrent)
	}
	if stats.QueueSize != 10 {
		t.Errorf("expected QueueSize 10, got %d", stats.QueueSize)
	}
	if stats.CurrentConcurrent != 0 {
		t.Errorf("expected CurrentConcurrent 0, got %d", stats.CurrentConcurrent)
	}

	ctx := context.Background()
	release, _ := b.Acquire(ctx)

	stats = b.Stats()
	if stats.CurrentConcurrent != 1 {
		t.Errorf("expected CurrentConcurrent 1, got %d", stats.CurrentConcurrent)
	}

	release()

	stats = b.Stats()
	if stats.CurrentConcurrent != 0 {
		t.Errorf("expected CurrentConcurrent 0 after release, got %d", stats.CurrentConcurrent)
	}
}

func TestBulkhead_ContextCancellation(t *testing.T) {
	b := NewBulkhead(BulkheadConfig{
		MaxConcurrent: 1,
		QueueSize:     1,
	})

	ctx := context.Background()

	// Fill the bulkhead
	release, _ := b.Acquire(ctx)
	defer release()

	// Try to acquire with cancelled context
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := b.Acquire(cancelledCtx)
		done <- err
	}()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("acquire should have returned immediately with context error")
	}
}

func TestEndpoint_HealthStatus(t *testing.T) {
	ep := &Endpoint{Address: "host:8080"}

	// Initially not healthy (zero value)
	if ep.IsHealthy() {
		t.Error("endpoint should not be healthy initially")
	}

	// Set healthy
	ep.SetHealthy(true)
	if !ep.IsHealthy() {
		t.Error("endpoint should be healthy")
	}

	// Set unhealthy
	ep.SetHealthy(false)
	if ep.IsHealthy() {
		t.Error("endpoint should be unhealthy")
	}
}

func TestEndpoint_ActiveConnections(t *testing.T) {
	ep := &Endpoint{Address: "host:8080"}

	if ep.ActiveConnections() != 0 {
		t.Error("initial connections should be 0")
	}

	ep.activeConns.Store(5)
	if ep.ActiveConnections() != 5 {
		t.Errorf("expected 5 connections, got %d", ep.ActiveConnections())
	}
}

func TestRetryPolicy_ShouldRetry(t *testing.T) {
	t.Run("default codes", func(t *testing.T) {
		policy := &RetryPolicy{}

		if !policy.ShouldRetry(502) {
			t.Error("502 should be retryable by default")
		}
		if !policy.ShouldRetry(503) {
			t.Error("503 should be retryable by default")
		}
		if !policy.ShouldRetry(504) {
			t.Error("504 should be retryable by default")
		}
		if policy.ShouldRetry(500) {
			t.Error("500 should not be retryable by default")
		}
	})

	t.Run("custom codes", func(t *testing.T) {
		policy := &RetryPolicy{
			RetryableCodes: map[int]bool{500: true, 429: true},
		}

		if !policy.ShouldRetry(500) {
			t.Error("500 should be retryable")
		}
		if !policy.ShouldRetry(429) {
			t.Error("429 should be retryable")
		}
		if policy.ShouldRetry(502) {
			t.Error("502 should not be retryable with custom codes")
		}
	})
}

func TestRetryPolicy_BackoffDuration_NoJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		JitterMode:  JitterNone, // Deterministic for testing
	}

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 0},
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second},  // Capped at max
		{6, 1 * time.Second},  // Still capped
	}

	for _, tt := range tests {
		got := policy.BackoffDuration(tt.attempt)
		if got != tt.want {
			t.Errorf("attempt %d: got %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestRetryPolicy_BackoffDuration_FullJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		JitterMode:  JitterFull,
	}

	// Full jitter should return value between 0 and base backoff
	for attempt := 1; attempt <= 3; attempt++ {
		baseBackoff := 100 * time.Millisecond
		for i := 1; i < attempt; i++ {
			baseBackoff *= 2
		}

		for i := 0; i < 100; i++ {
			got := policy.BackoffDuration(attempt)
			if got < 0 || got > baseBackoff {
				t.Errorf("full jitter attempt %d: got %v, want 0-%v", attempt, got, baseBackoff)
			}
		}
	}
}

func TestRetryPolicy_BackoffDuration_EqualJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		JitterMode:  JitterEqual,
	}

	// Equal jitter should return value between backoff/2 and backoff
	for attempt := 1; attempt <= 3; attempt++ {
		baseBackoff := 100 * time.Millisecond
		for i := 1; i < attempt; i++ {
			baseBackoff *= 2
		}

		minExpected := baseBackoff / 2
		for i := 0; i < 100; i++ {
			got := policy.BackoffDuration(attempt)
			if got < minExpected || got > baseBackoff {
				t.Errorf("equal jitter attempt %d: got %v, want %v-%v", attempt, got, minExpected, baseBackoff)
			}
		}
	}
}

func TestRetryPolicy_BackoffDuration_DecorrelatedJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		JitterMode:  JitterDecorelated,
	}

	// Reset state before test
	policy.ResetJitter()

	// Decorrelated jitter should return value between base and prev*3
	prev := policy.BackoffDuration(1)
	if prev < 100*time.Millisecond || prev > 300*time.Millisecond {
		t.Errorf("decorrelated jitter attempt 1: got %v, want 100ms-300ms", prev)
	}

	// Subsequent calls should be based on previous value
	for i := 0; i < 10; i++ {
		got := policy.BackoffDuration(2)
		// Should be between base and prev*3, capped at max
		if got < 100*time.Millisecond || got > 1*time.Second {
			t.Errorf("decorrelated jitter: got %v out of expected range", got)
		}
	}
}

func TestRetryPolicy_BackoffDuration_DefaultIsEqualJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		// JitterMode not set - should default to JitterEqual
	}

	// Should behave like equal jitter (backoff/2 to backoff)
	for i := 0; i < 100; i++ {
		got := policy.BackoffDuration(1)
		if got < 50*time.Millisecond || got > 100*time.Millisecond {
			t.Errorf("default jitter: got %v, want 50ms-100ms", got)
		}
	}
}

func TestRetryPolicy_ResetJitter(t *testing.T) {
	policy := &RetryPolicy{
		BackoffBase: 100 * time.Millisecond,
		BackoffMax:  1 * time.Second,
		JitterMode:  JitterDecorelated,
	}

	// Make a few calls to build up state
	policy.BackoffDuration(1)
	policy.BackoffDuration(2)
	policy.BackoffDuration(3)

	// Reset and verify first call is within initial range
	policy.ResetJitter()
	got := policy.BackoffDuration(1)
	if got < 100*time.Millisecond || got > 300*time.Millisecond {
		t.Errorf("after reset, got %v, want 100ms-300ms", got)
	}
}

func TestFilterHealthy(t *testing.T) {
	endpoints := []*Endpoint{
		{Address: "host1:8080"},
		{Address: "host2:8080"},
		{Address: "host3:8080"},
	}
	endpoints[0].SetHealthy(true)
	endpoints[1].SetHealthy(false)
	endpoints[2].SetHealthy(true)

	healthy := filterHealthy(endpoints)

	if len(healthy) != 2 {
		t.Errorf("expected 2 healthy endpoints, got %d", len(healthy))
	}

	for _, ep := range healthy {
		if !ep.IsHealthy() {
			t.Errorf("endpoint %s should be healthy", ep.Address)
		}
	}
}

func BenchmarkRoundRobinBalancer_Select(b *testing.B) {
	lb := &RoundRobinBalancer{}
	endpoints := make([]*Endpoint, 10)
	for i := 0; i < 10; i++ {
		endpoints[i] = &Endpoint{Address: "host:8080"}
		endpoints[i].SetHealthy(true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Select(endpoints)
	}
}

func BenchmarkWeightedBalancer_Select(b *testing.B) {
	lb := NewWeightedBalancer()
	endpoints := make([]*Endpoint, 10)
	for i := 0; i < 10; i++ {
		endpoints[i] = &Endpoint{Address: "host:8080", Weight: i + 1}
		endpoints[i].SetHealthy(true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lb.Select(endpoints)
	}
}
