package upstream

import (
	"testing"
	"time"
)

func TestPassiveHealthChecker_RecordResponse(t *testing.T) {
	phc := NewPassiveHealthChecker(PassiveHealthConfig{
		ConsecutiveErrors:   3,
		ErrorRatioThreshold: 0.5,
		MinRequestsForRatio: 5,
		EjectionDuration:    100 * time.Millisecond,
		MaxEjectionPercent:  0.5,
		WindowDuration:      1 * time.Second,
	})

	// Success responses should not eject
	for i := 0; i < 5; i++ {
		if phc.RecordResponse("host1:8080", 200, 2) {
			t.Error("successful response should not trigger ejection")
		}
	}

	// Consecutive errors should trigger ejection
	for i := 0; i < 3; i++ {
		ejected := phc.RecordResponse("host1:8080", 500, 2)
		if i < 2 && ejected {
			t.Errorf("should not eject after %d errors", i+1)
		}
		if i == 2 && !ejected {
			t.Error("should eject after 3 consecutive errors")
		}
	}

	// Should be ejected
	if !phc.IsEjected("host1:8080") {
		t.Error("endpoint should be ejected")
	}
}

func TestPassiveHealthChecker_MaxEjectionPercent(t *testing.T) {
	phc := NewPassiveHealthChecker(PassiveHealthConfig{
		ConsecutiveErrors:  2,
		EjectionDuration:   1 * time.Second,
		MaxEjectionPercent: 0.5, // Can only eject 50%
		WindowDuration:     1 * time.Second,
	})

	// Eject first endpoint
	phc.RecordResponse("host1:8080", 500, 2)
	phc.RecordResponse("host1:8080", 500, 2)
	if !phc.IsEjected("host1:8080") {
		t.Error("first endpoint should be ejected")
	}

	// Second endpoint should not be ejected (would exceed 50%)
	phc.RecordResponse("host2:8080", 500, 2)
	phc.RecordResponse("host2:8080", 500, 2)
	if phc.IsEjected("host2:8080") {
		t.Error("second endpoint should not be ejected (max ejection percent)")
	}
}

func TestPassiveHealthChecker_EjectionExpiry(t *testing.T) {
	phc := NewPassiveHealthChecker(PassiveHealthConfig{
		ConsecutiveErrors: 1,
		EjectionDuration:  50 * time.Millisecond,
		WindowDuration:    1 * time.Second,
	})

	// Eject endpoint
	phc.RecordResponse("host1:8080", 500, 1)
	if !phc.IsEjected("host1:8080") {
		t.Error("endpoint should be ejected")
	}

	// Wait for ejection to expire
	time.Sleep(60 * time.Millisecond)

	// Should no longer be ejected
	if phc.IsEjected("host1:8080") {
		t.Error("endpoint should no longer be ejected after expiry")
	}
}

func TestPassiveHealthChecker_GetEjectedEndpoints(t *testing.T) {
	phc := NewPassiveHealthChecker(PassiveHealthConfig{
		ConsecutiveErrors:  1,
		EjectionDuration:   1 * time.Second,
		MaxEjectionPercent: 1.0,
		WindowDuration:     1 * time.Second,
	})

	// Eject two endpoints
	phc.RecordResponse("host1:8080", 500, 3)
	phc.RecordResponse("host2:8080", 500, 3)

	ejected := phc.GetEjectedEndpoints()
	if len(ejected) != 2 {
		t.Errorf("expected 2 ejected endpoints, got %d", len(ejected))
	}
}

func TestOutlierDetector_RecordResponse(t *testing.T) {
	od := NewOutlierDetector(OutlierDetectorConfig{
		Passive: PassiveHealthConfig{
			ConsecutiveErrors: 2,
			EjectionDuration:  100 * time.Millisecond,
			WindowDuration:    1 * time.Second,
		},
		RecoveryInterval: 10 * time.Millisecond,
	})

	// Create and register endpoint
	ep := &Endpoint{Address: "host1:8080"}
	ep.SetHealthy(true)
	od.RegisterEndpoint(ep)

	// Successful responses should not affect health
	od.RecordResponse("host1:8080", 200)
	if !ep.IsHealthy() {
		t.Error("endpoint should still be healthy after success")
	}

	// Consecutive errors should eject endpoint
	od.RecordResponse("host1:8080", 500)
	if !ep.IsHealthy() {
		t.Error("endpoint should be healthy after 1 error")
	}

	od.RecordResponse("host1:8080", 500)
	if ep.IsHealthy() {
		t.Error("endpoint should be unhealthy after 2 consecutive errors")
	}
}

func TestOutlierDetector_Recovery(t *testing.T) {
	od := NewOutlierDetector(OutlierDetectorConfig{
		Passive: PassiveHealthConfig{
			ConsecutiveErrors: 1,
			EjectionDuration:  50 * time.Millisecond,
			WindowDuration:    1 * time.Second,
		},
		RecoveryInterval: 10 * time.Millisecond,
	})
	od.Start()
	defer od.Stop()

	// Create and register endpoint
	ep := &Endpoint{Address: "host1:8080"}
	ep.SetHealthy(true)
	od.RegisterEndpoint(ep)

	// Eject the endpoint
	od.RecordResponse("host1:8080", 500)
	if ep.IsHealthy() {
		t.Error("endpoint should be unhealthy")
	}

	// Wait for ejection to expire and recovery to happen
	time.Sleep(100 * time.Millisecond)

	// Should be recovered
	if !ep.IsHealthy() {
		t.Error("endpoint should be recovered after ejection expiry")
	}
}

func TestOutlierDetector_RegisterUnregister(t *testing.T) {
	od := NewOutlierDetector(DefaultOutlierDetectorConfig())

	ep1 := &Endpoint{Address: "host1:8080"}
	ep2 := &Endpoint{Address: "host2:8080"}

	od.RegisterEndpoints([]*Endpoint{ep1, ep2})

	// Both should be tracked
	if len(od.endpoints) != 2 {
		t.Errorf("expected 2 registered endpoints, got %d", len(od.endpoints))
	}

	// Unregister one
	od.UnregisterEndpoint("host1:8080")

	if len(od.endpoints) != 1 {
		t.Errorf("expected 1 registered endpoint after unregister, got %d", len(od.endpoints))
	}
}

func TestOutlierDetector_Stats(t *testing.T) {
	od := NewOutlierDetector(OutlierDetectorConfig{
		Passive: PassiveHealthConfig{
			ConsecutiveErrors: 5,
			EjectionDuration:  1 * time.Second,
			WindowDuration:    1 * time.Second,
		},
	})

	ep := &Endpoint{Address: "host1:8080"}
	ep.SetHealthy(true)
	od.RegisterEndpoint(ep)

	// Record some responses
	od.RecordResponse("host1:8080", 200)
	od.RecordResponse("host1:8080", 200)
	od.RecordResponse("host1:8080", 500)

	stats := od.Stats()
	if len(stats) != 1 {
		t.Errorf("expected 1 stat entry, got %d", len(stats))
	}

	st := stats["host1:8080"]
	if st.Requests != 3 {
		t.Errorf("expected 3 requests, got %d", st.Requests)
	}
	if st.Errors != 1 {
		t.Errorf("expected 1 error, got %d", st.Errors)
	}
	if st.ConsecutiveErrors != 1 {
		t.Errorf("expected 1 consecutive error, got %d", st.ConsecutiveErrors)
	}
	if !st.EndpointHealthy {
		t.Error("endpoint should be healthy (not ejected yet)")
	}
}
