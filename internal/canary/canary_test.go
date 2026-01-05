package canary

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagerCreateDeployment(t *testing.T) {
	m := NewManager()

	cfg := Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 90},
			{Name: "v2", Upstream: "backend-v2", Weight: 10},
		},
	}

	d, err := m.CreateDeployment(cfg)
	if err != nil {
		t.Fatalf("CreateDeployment failed: %v", err)
	}

	if d.ID == "" {
		t.Error("expected deployment to have an ID")
	}

	// Check deployment can be retrieved
	got, ok := m.GetDeployment("route-1")
	if !ok {
		t.Fatal("expected to find deployment")
	}
	if got.ID != d.ID {
		t.Error("deployment ID mismatch")
	}
}

func TestManagerDeleteDeployment(t *testing.T) {
	m := NewManager()

	m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{{Name: "v1", Upstream: "backend", Weight: 100}},
	})

	m.DeleteDeployment("route-1")

	_, ok := m.GetDeployment("route-1")
	if ok {
		t.Error("expected deployment to be deleted")
	}
}

func TestDeploymentWeightedSelection(t *testing.T) {
	m := NewManager()

	d, _ := m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 90},
			{Name: "v2", Upstream: "backend-v2", Weight: 10},
		},
	})

	// Run many selections and check distribution
	counts := make(map[string]int)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		target, ok := d.SelectTarget(req)
		if !ok {
			t.Fatal("expected to select a target")
		}
		counts[target.Name]++
	}

	// Check that v1 gets roughly 90% (with some tolerance)
	v1Percent := float64(counts["v1"]) / float64(iterations) * 100
	if v1Percent < 80 || v1Percent > 100 {
		t.Errorf("expected v1 to get ~90%% of traffic, got %.1f%%", v1Percent)
	}
}

func TestDeploymentHeaderBasedRouting(t *testing.T) {
	m := NewManager()

	d, _ := m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 90},
			{Name: "v2", Upstream: "backend-v2", Weight: 10},
		},
		HeaderMatch: &HeaderMatch{
			Header: "X-Canary",
			Values: map[string]string{
				"true": "v2",
			},
		},
	})

	// Request without header should follow weight distribution
	req1 := httptest.NewRequest("GET", "/test", nil)
	target1, _ := d.SelectTarget(req1)
	// Can be either, just check it returns something

	// Request with header should always go to v2
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Canary", "true")

	for i := 0; i < 100; i++ {
		target, ok := d.SelectTarget(req2)
		if !ok || target.Name != "v2" {
			t.Errorf("expected header match to route to v2, got %s", target.Name)
		}
	}

	_ = target1 // Avoid unused variable
}

func TestDeploymentStickySession(t *testing.T) {
	m := NewManager()

	d, _ := m.CreateDeployment(Config{
		RouteID:      "route-1",
		Targets:      []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 50},
			{Name: "v2", Upstream: "backend-v2", Weight: 50},
		},
		Sticky:       true,
		StickyCookie: "canary-session",
		StickyTTL:    time.Hour,
	})

	// First request without cookie
	req1 := httptest.NewRequest("GET", "/test", nil)
	target1, _ := d.SelectTarget(req1)

	// Simulate setting cookie
	rec := httptest.NewRecorder()
	d.SetStickyCookie(rec, target1.Name)

	// Second request with cookie should get same target
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.AddCookie(&http.Cookie{Name: "canary-session", Value: target1.Name})

	for i := 0; i < 100; i++ {
		target, _ := d.SelectTarget(req2)
		if target.Name != target1.Name {
			t.Errorf("sticky session should always return %s, got %s", target1.Name, target.Name)
		}
	}
}

func TestUpdateWeights(t *testing.T) {
	m := NewManager()

	m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 90},
			{Name: "v2", Upstream: "backend-v2", Weight: 10},
		},
	})

	// Update weights to 50/50
	m.UpdateWeights("route-1", map[string]int{
		"v1": 50,
		"v2": 50,
	})

	d, _ := m.GetDeployment("route-1")

	// Verify weights are updated
	for _, target := range d.Targets {
		if target.Weight != 50 {
			t.Errorf("expected weight 50, got %d for %s", target.Weight, target.Name)
		}
	}
}

func TestPromoteTarget(t *testing.T) {
	m := NewManager()

	m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 90},
			{Name: "v2", Upstream: "backend-v2", Weight: 10},
		},
	})

	// Promote v2
	m.PromoteTarget("route-1", "v2")

	d, _ := m.GetDeployment("route-1")

	for _, target := range d.Targets {
		if target.Name == "v2" && target.Weight != 100 {
			t.Errorf("expected v2 weight to be 100, got %d", target.Weight)
		}
		if target.Name == "v1" && target.Weight != 0 {
			t.Errorf("expected v1 weight to be 0, got %d", target.Weight)
		}
	}
}

func TestDeploymentMetrics(t *testing.T) {
	m := NewManager()

	d, _ := m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 100},
		},
	})

	// Record requests and errors
	d.RecordRequest("v1")
	d.RecordRequest("v1")
	d.RecordRequest("v1")
	d.RecordError("v1")

	metrics := d.GetMetrics()

	if metrics["v1"].Requests != 3 {
		t.Errorf("expected 3 requests, got %d", metrics["v1"].Requests)
	}
	if metrics["v1"].Errors != 1 {
		t.Errorf("expected 1 error, got %d", metrics["v1"].Errors)
	}
}

func TestMiddleware(t *testing.T) {
	m := NewManager()

	m.CreateDeployment(Config{
		RouteID: "test-route",
		Targets: []Target{
			{Name: "v1", Upstream: "backend-v1", Weight: 100, Headers: Headers{"X-Version": "v1"}},
		},
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that target headers are set
		if r.Header.Get("X-Version") != "v1" {
			t.Error("expected X-Version header to be set")
		}

		// Check context values
		target, ok := GetTargetFromContext(r.Context())
		if !ok || target != "v1" {
			t.Error("expected target in context")
		}

		upstream, ok := GetUpstreamFromContext(r.Context())
		if !ok || upstream != "backend-v1" {
			t.Error("expected upstream in context")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		RouteIDFunc: func(r *http.Request) string {
			return "test-route"
		},
	})(backend)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check response headers
	if rec.Header().Get("X-Canary-Target") != "v1" {
		t.Error("expected X-Canary-Target header")
	}
}

func TestAutoRollout(t *testing.T) {
	m := NewManager()

	m.CreateDeployment(Config{
		RouteID: "route-1",
		Targets: []Target{
			{Name: "stable", Upstream: "backend-stable", Weight: 100},
			{Name: "canary", Upstream: "backend-canary", Weight: 0},
		},
	})

	rollout := NewAutoRollout(m, "route-1", "canary", "stable")
	rollout.SetStages([]RolloutStage{
		{Weight: 10, Duration: time.Minute},
		{Weight: 50, Duration: time.Minute},
		{Weight: 100, Duration: 0},
	})

	// Initial state (before any Advance calls)
	if rollout.CurrentStage() != -1 {
		t.Error("expected initial stage to be -1")
	}

	// Advance to first stage (10%)
	rollout.Advance()
	d, _ := m.GetDeployment("route-1")
	for _, target := range d.Targets {
		if target.Name == "canary" && target.Weight != 10 {
			t.Errorf("expected canary weight 10, got %d", target.Weight)
		}
	}

	// Advance to second stage (50%)
	rollout.Advance()
	d, _ = m.GetDeployment("route-1")
	for _, target := range d.Targets {
		if target.Name == "canary" && target.Weight != 50 {
			t.Errorf("expected canary weight 50, got %d", target.Weight)
		}
	}

	// Complete
	rollout.Complete()
	d, _ = m.GetDeployment("route-1")
	for _, target := range d.Targets {
		if target.Name == "canary" && target.Weight != 100 {
			t.Errorf("expected canary weight 100 after complete, got %d", target.Weight)
		}
	}
}
