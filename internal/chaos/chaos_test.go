package chaos

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name   string
		config EngineConfig
	}{
		{
			name:   "default config",
			config: EngineConfig{},
		},
		{
			name: "with enabled",
			config: EngineConfig{
				Enabled: true,
			},
		},
		{
			name: "with dry run",
			config: EngineConfig{
				Enabled: true,
				DryRun:  true,
			},
		},
		{
			name: "with seed",
			config: EngineConfig{
				Enabled: true,
				Seed:    12345,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(tt.config)
			if engine == nil {
				t.Fatal("expected non-nil engine")
			}
			if engine.faults == nil {
				t.Error("expected faults map to be initialized")
			}
		})
	}
}

func TestEngine_AddFault(t *testing.T) {
	tests := []struct {
		name    string
		fault   *Fault
		wantErr bool
	}{
		{
			name: "valid fault",
			fault: &Fault{
				ID:         "test-fault",
				Type:       FaultTypeLatency,
				Enabled:    true,
				Percentage: 50,
				Duration:   time.Second,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			fault: &Fault{
				Type:       FaultTypeLatency,
				Percentage: 50,
			},
			wantErr: true,
		},
		{
			name: "negative percentage",
			fault: &Fault{
				ID:         "test-fault",
				Type:       FaultTypeLatency,
				Percentage: -10,
			},
			wantErr: true,
		},
		{
			name: "percentage over 100",
			fault: &Fault{
				ID:         "test-fault",
				Type:       FaultTypeLatency,
				Percentage: 150,
			},
			wantErr: true,
		},
		{
			name: "zero percentage valid",
			fault: &Fault{
				ID:         "test-fault",
				Type:       FaultTypeLatency,
				Percentage: 0,
			},
			wantErr: false,
		},
		{
			name: "100 percentage valid",
			fault: &Fault{
				ID:         "test-fault",
				Type:       FaultTypeError,
				Percentage: 100,
				StatusCode: 500,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(EngineConfig{Enabled: true})
			err := engine.AddFault(tt.fault)

			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.wantErr {
				got := engine.GetFault(tt.fault.ID)
				if got == nil {
					t.Error("expected fault to be added")
				}
				if got.Stats == nil {
					t.Error("expected stats to be initialized")
				}
			}
		})
	}
}

func TestEngine_RemoveFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	fault := &Fault{ID: "test-fault", Type: FaultTypeLatency, Percentage: 50}
	engine.AddFault(fault)

	// Remove existing
	if !engine.RemoveFault("test-fault") {
		t.Error("expected true for existing fault")
	}
	if engine.GetFault("test-fault") != nil {
		t.Error("expected fault to be removed")
	}

	// Remove non-existing
	if engine.RemoveFault("non-existing") {
		t.Error("expected false for non-existing fault")
	}
}

func TestEngine_EnableDisableFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	fault := &Fault{ID: "test-fault", Type: FaultTypeLatency, Percentage: 50, Enabled: false}
	engine.AddFault(fault)

	// Enable
	if !engine.EnableFault("test-fault") {
		t.Error("expected true for enable")
	}
	if !engine.GetFault("test-fault").Enabled {
		t.Error("expected fault to be enabled")
	}

	// Disable
	if !engine.DisableFault("test-fault") {
		t.Error("expected true for disable")
	}
	if engine.GetFault("test-fault").Enabled {
		t.Error("expected fault to be disabled")
	}

	// Non-existing
	if engine.EnableFault("non-existing") {
		t.Error("expected false for non-existing")
	}
	if engine.DisableFault("non-existing") {
		t.Error("expected false for non-existing")
	}
}

func TestEngine_ListFaults(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	// Empty list
	faults := engine.ListFaults()
	if len(faults) != 0 {
		t.Errorf("expected 0 faults, got %d", len(faults))
	}

	// Add faults
	engine.AddFault(&Fault{ID: "fault-1", Type: FaultTypeLatency, Percentage: 50})
	engine.AddFault(&Fault{ID: "fault-2", Type: FaultTypeError, Percentage: 25})
	engine.AddFault(&Fault{ID: "fault-3", Type: FaultTypeAbort, Percentage: 10})

	faults = engine.ListFaults()
	if len(faults) != 3 {
		t.Errorf("expected 3 faults, got %d", len(faults))
	}
}

func TestMatchRoute(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "/any/path", true},
		{"/*", "/any/path", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", true},
		{"/api/*", "/other/path", false},
		{"/exact", "/exact", true},
		{"/exact", "/exact/more", false},
		{"/users", "/users", true},
		{"/users", "/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchRoute(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchRoute(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestEngine_ShouldInject(t *testing.T) {
	tests := []struct {
		name       string
		engineCfg  EngineConfig
		fault      *Fault
		request    *http.Request
		wantInject bool
	}{
		{
			name:       "engine disabled",
			engineCfg:  EngineConfig{Enabled: false},
			fault:      &Fault{ID: "test", Enabled: true, Percentage: 100},
			request:    httptest.NewRequest("GET", "/api/test", nil),
			wantInject: false,
		},
		{
			name:       "fault disabled",
			engineCfg:  EngineConfig{Enabled: true, Seed: 1},
			fault:      &Fault{ID: "test", Enabled: false, Percentage: 100},
			request:    httptest.NewRequest("GET", "/api/test", nil),
			wantInject: false,
		},
		{
			name:      "100% injection",
			engineCfg: EngineConfig{Enabled: true, Seed: 1},
			fault:     &Fault{ID: "test", Enabled: true, Percentage: 100},
			request:   httptest.NewRequest("GET", "/api/test", nil),
			wantInject: true,
		},
		{
			name:       "0% injection",
			engineCfg:  EngineConfig{Enabled: true, Seed: 1},
			fault:      &Fault{ID: "test", Enabled: true, Percentage: 0},
			request:    httptest.NewRequest("GET", "/api/test", nil),
			wantInject: false,
		},
		{
			name:      "route match",
			engineCfg: EngineConfig{Enabled: true, Seed: 1},
			fault:     &Fault{ID: "test", Enabled: true, Percentage: 100, Routes: []string{"/api/*"}},
			request:   httptest.NewRequest("GET", "/api/users", nil),
			wantInject: true,
		},
		{
			name:       "route no match",
			engineCfg:  EngineConfig{Enabled: true, Seed: 1},
			fault:      &Fault{ID: "test", Enabled: true, Percentage: 100, Routes: []string{"/api/*"}},
			request:    httptest.NewRequest("GET", "/other/path", nil),
			wantInject: false,
		},
		{
			name:      "method match",
			engineCfg: EngineConfig{Enabled: true, Seed: 1},
			fault:     &Fault{ID: "test", Enabled: true, Percentage: 100, Methods: []string{"POST", "PUT"}},
			request:   httptest.NewRequest("POST", "/api/test", nil),
			wantInject: true,
		},
		{
			name:       "method no match",
			engineCfg:  EngineConfig{Enabled: true, Seed: 1},
			fault:      &Fault{ID: "test", Enabled: true, Percentage: 100, Methods: []string{"POST", "PUT"}},
			request:    httptest.NewRequest("GET", "/api/test", nil),
			wantInject: false,
		},
		{
			name:      "header match",
			engineCfg: EngineConfig{Enabled: true, Seed: 1},
			fault:     &Fault{ID: "test", Enabled: true, Percentage: 100, Headers: map[string]string{"X-Test": "enabled"}},
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/test", nil)
				r.Header.Set("X-Test", "enabled")
				return r
			}(),
			wantInject: true,
		},
		{
			name:      "header no match",
			engineCfg: EngineConfig{Enabled: true, Seed: 1},
			fault:     &Fault{ID: "test", Enabled: true, Percentage: 100, Headers: map[string]string{"X-Test": "enabled"}},
			request:   httptest.NewRequest("GET", "/api/test", nil),
			wantInject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(tt.engineCfg)
			got := engine.ShouldInject(tt.fault, tt.request)
			if got != tt.wantInject {
				t.Errorf("ShouldInject() = %v, want %v", got, tt.wantInject)
			}
		})
	}
}

func TestEngine_ShouldInject_Expiration(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true, Seed: 1})

	// Expired fault
	past := time.Now().Add(-time.Hour)
	expiredFault := &Fault{
		ID:         "expired",
		Enabled:    true,
		Percentage: 100,
		ExpiresAt:  &past,
	}

	if engine.ShouldInject(expiredFault, httptest.NewRequest("GET", "/", nil)) {
		t.Error("expected expired fault to not inject")
	}

	// Non-expired fault
	future := time.Now().Add(time.Hour)
	validFault := &Fault{
		ID:         "valid",
		Enabled:    true,
		Percentage: 100,
		ExpiresAt:  &future,
	}

	if !engine.ShouldInject(validFault, httptest.NewRequest("GET", "/", nil)) {
		t.Error("expected non-expired fault to inject")
	}
}

func TestEngine_Execute_DryRun(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true, DryRun: true})

	fault := &Fault{
		ID:         "test",
		Type:       FaultTypeError,
		Enabled:    true,
		Percentage: 100,
		StatusCode: 500,
		Stats:      &FaultStats{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	stop := engine.Execute(context.Background(), fault, w, r)
	if stop {
		t.Error("dry-run should not stop request processing")
	}
	if w.Code != 200 {
		t.Errorf("dry-run should not modify response, got code %d", w.Code)
	}
	if fault.Stats.Triggered != 1 {
		t.Error("expected stats to be updated even in dry-run")
	}
}

func TestEngine_Execute_Latency(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	fault := &Fault{
		ID:       "latency",
		Type:     FaultTypeLatency,
		Enabled:  true,
		Duration: 50 * time.Millisecond,
		Stats:    &FaultStats{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	start := time.Now()
	stop := engine.Execute(context.Background(), fault, w, r)
	elapsed := time.Since(start)

	if stop {
		t.Error("latency fault should not stop request processing")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected latency injection, elapsed: %v", elapsed)
	}
}

func TestEngine_Execute_Latency_ContextCancellation(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	fault := &Fault{
		ID:       "latency",
		Type:     FaultTypeLatency,
		Enabled:  true,
		Duration: 5 * time.Second,
		Stats:    &FaultStats{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	start := time.Now()
	engine.Execute(ctx, fault, w, r)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("expected context cancellation to stop latency injection, elapsed: %v", elapsed)
	}
}

func TestEngine_Execute_Error(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	tests := []struct {
		name       string
		fault      *Fault
		wantCode   int
		wantMsg    string
	}{
		{
			name: "custom status and message",
			fault: &Fault{
				ID:         "error",
				Type:       FaultTypeError,
				Enabled:    true,
				StatusCode: 503,
				Message:    "Service temporarily unavailable",
				Stats:      &FaultStats{},
			},
			wantCode: 503,
			wantMsg:  "Service temporarily unavailable",
		},
		{
			name: "default status and message",
			fault: &Fault{
				ID:      "error",
				Type:    FaultTypeError,
				Enabled: true,
				Stats:   &FaultStats{},
			},
			wantCode: 500,
			wantMsg:  "Chaos fault injection: simulated error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			stop := engine.Execute(context.Background(), tt.fault, w, r)
			if !stop {
				t.Error("error fault should stop request processing")
			}
			if w.Code != tt.wantCode {
				t.Errorf("got code %d, want %d", w.Code, tt.wantCode)
			}
			if !strings.Contains(w.Body.String(), tt.wantMsg) {
				t.Errorf("expected message %q in body %q", tt.wantMsg, w.Body.String())
			}
			if w.Header().Get("X-Chaos-Injected") != "true" {
				t.Error("expected X-Chaos-Injected header")
			}
		})
	}
}

func TestEngine_Execute_Abort(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	fault := &Fault{
		ID:         "abort",
		Type:       FaultTypeAbort,
		Enabled:    true,
		StatusCode: 503,
		Stats:      &FaultStats{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	stop := engine.Execute(context.Background(), fault, w, r)
	if !stop {
		t.Error("abort fault should stop request processing")
	}
	if w.Code != 503 {
		t.Errorf("got code %d, want 503", w.Code)
	}
	if w.Header().Get("Connection") != "close" {
		t.Error("expected Connection: close header")
	}
}

func TestMiddleware(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true, Seed: 1})

	// Add 100% error fault
	fault := &Fault{
		ID:         "test-error",
		Type:       FaultTypeError,
		Enabled:    true,
		Percentage: 100,
		StatusCode: 500,
		Message:    "Injected error",
	}
	engine.AddFault(fault)

	var injected int32
	middleware := Middleware(MiddlewareConfig{
		Engine: engine,
		OnFaultInjected: func(f *Fault, r *http.Request) {
			atomic.AddInt32(&injected, 1)
		},
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 500 {
		t.Errorf("expected 500, got %d", rec.Code)
	}
	if atomic.LoadInt32(&injected) != 1 {
		t.Error("expected OnFaultInjected callback to be called")
	}
}

func TestMiddleware_NoFaults(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	middleware := Middleware(MiddlewareConfig{Engine: engine})

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected handler to be called when no faults")
	}
	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestMiddleware_Latency(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true, Seed: 1})

	// Add latency fault that doesn't stop request
	engine.AddFault(&Fault{
		ID:         "latency",
		Type:       FaultTypeLatency,
		Enabled:    true,
		Percentage: 100,
		Duration:   50 * time.Millisecond,
	})

	middleware := Middleware(MiddlewareConfig{Engine: engine})

	handlerCalled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	start := time.Now()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if !handlerCalled {
		t.Error("expected handler to be called after latency fault")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("expected latency injection, elapsed: %v", elapsed)
	}
}

func TestExperimentRunner_CreateExperiment(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	tests := []struct {
		name    string
		exp     *Experiment
		wantErr bool
	}{
		{
			name: "valid experiment",
			exp: &Experiment{
				ID:       "exp-1",
				Name:     "Test Experiment",
				Duration: time.Minute,
				Faults: []*Fault{
					{ID: "fault-1", Type: FaultTypeLatency, Percentage: 50},
				},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			exp: &Experiment{
				Name:     "Test",
				Duration: time.Minute,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runner.CreateExperiment(tt.exp)
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr {
				if tt.exp.Status != ExperimentStatusPending {
					t.Errorf("expected pending status, got %s", tt.exp.Status)
				}
			}
		})
	}
}

func TestExperimentRunner_StartStopExperiment(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	fault := &Fault{ID: "exp-fault", Type: FaultTypeLatency, Percentage: 50}
	exp := &Experiment{
		ID:       "exp-1",
		Name:     "Test Experiment",
		Duration: 0, // Manual stop
		Faults:   []*Fault{fault},
	}

	if err := runner.CreateExperiment(exp); err != nil {
		t.Fatalf("failed to create experiment: %v", err)
	}

	// Start experiment
	if err := runner.StartExperiment("exp-1"); err != nil {
		t.Fatalf("failed to start experiment: %v", err)
	}

	if exp.Status != ExperimentStatusRunning {
		t.Errorf("expected running status, got %s", exp.Status)
	}
	if exp.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}

	// Verify fault added to engine
	if engine.GetFault("exp-fault") == nil {
		t.Error("expected fault to be added to engine")
	}

	// Stop experiment
	if err := runner.StopExperiment("exp-1"); err != nil {
		t.Fatalf("failed to stop experiment: %v", err)
	}

	if exp.Status != ExperimentStatusCompleted {
		t.Errorf("expected completed status, got %s", exp.Status)
	}
	if exp.EndedAt == nil {
		t.Error("expected EndedAt to be set")
	}

	// Verify fault removed from engine
	if engine.GetFault("exp-fault") != nil {
		t.Error("expected fault to be removed from engine")
	}
}

func TestExperimentRunner_StartNonPending(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	exp := &Experiment{
		ID:     "exp-1",
		Name:   "Test",
		Faults: []*Fault{{ID: "f1", Type: FaultTypeLatency, Percentage: 50}},
	}

	runner.CreateExperiment(exp)
	runner.StartExperiment("exp-1")

	// Try to start again
	err := runner.StartExperiment("exp-1")
	if err == nil {
		t.Error("expected error when starting non-pending experiment")
	}
}

func TestExperimentRunner_StartNonExisting(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	err := runner.StartExperiment("non-existing")
	if err == nil {
		t.Error("expected error for non-existing experiment")
	}
}

func TestExperimentRunner_ListExperiments(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	// Initially empty
	if len(runner.ListExperiments()) != 0 {
		t.Error("expected empty list")
	}

	// Add experiments
	runner.CreateExperiment(&Experiment{ID: "exp-1", Name: "Exp 1"})
	runner.CreateExperiment(&Experiment{ID: "exp-2", Name: "Exp 2"})

	exps := runner.ListExperiments()
	if len(exps) != 2 {
		t.Errorf("expected 2 experiments, got %d", len(exps))
	}
}

func TestExperimentRunner_GetExperiment(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	runner.CreateExperiment(&Experiment{ID: "exp-1", Name: "Exp 1"})

	exp := runner.GetExperiment("exp-1")
	if exp == nil {
		t.Error("expected to find experiment")
	}

	exp = runner.GetExperiment("non-existing")
	if exp != nil {
		t.Error("expected nil for non-existing experiment")
	}
}

func TestExperimentRunner_AutoDuration(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)

	fault := &Fault{ID: "f1", Type: FaultTypeLatency, Percentage: 50}
	exp := &Experiment{
		ID:       "exp-1",
		Name:     "Auto-stop Experiment",
		Duration: 100 * time.Millisecond,
		Faults:   []*Fault{fault},
	}

	runner.CreateExperiment(exp)
	runner.StartExperiment("exp-1")

	// Wait for auto-stop
	time.Sleep(200 * time.Millisecond)

	if exp.Status != ExperimentStatusCompleted {
		t.Errorf("expected completed status after duration, got %s", exp.Status)
	}
}

func TestHandler_ListFaults(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	engine.AddFault(&Fault{ID: "f1", Type: FaultTypeLatency, Percentage: 50})
	engine.AddFault(&Fault{ID: "f2", Type: FaultTypeError, Percentage: 25})

	handler := NewHandler(engine, nil, nil)

	req := httptest.NewRequest("GET", "/chaos/faults", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var faults []*Fault
	if err := json.NewDecoder(rec.Body).Decode(&faults); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(faults) != 2 {
		t.Errorf("expected 2 faults, got %d", len(faults))
	}
}

func TestHandler_AddFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	handler := NewHandler(engine, nil, nil)

	fault := Fault{
		ID:         "new-fault",
		Type:       FaultTypeLatency,
		Percentage: 50,
		Duration:   time.Second,
	}

	body, _ := json.Marshal(fault)
	req := httptest.NewRequest("POST", "/chaos/faults", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Errorf("expected 201, got %d", rec.Code)
	}

	if engine.GetFault("new-fault") == nil {
		t.Error("expected fault to be added")
	}
}

func TestHandler_GetFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	engine.AddFault(&Fault{ID: "f1", Type: FaultTypeLatency, Percentage: 50})

	handler := NewHandler(engine, nil, nil)

	// Existing fault
	req := httptest.NewRequest("GET", "/chaos/faults/f1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Non-existing fault
	req = httptest.NewRequest("GET", "/chaos/faults/non-existing", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandler_RemoveFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	engine.AddFault(&Fault{ID: "f1", Type: FaultTypeLatency, Percentage: 50})

	handler := NewHandler(engine, nil, nil)

	req := httptest.NewRequest("DELETE", "/chaos/faults/f1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 204 {
		t.Errorf("expected 204, got %d", rec.Code)
	}

	if engine.GetFault("f1") != nil {
		t.Error("expected fault to be removed")
	}
}

func TestHandler_EnableDisableFault(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	engine.AddFault(&Fault{ID: "f1", Type: FaultTypeLatency, Percentage: 50, Enabled: false})

	handler := NewHandler(engine, nil, nil)

	// Enable
	req := httptest.NewRequest("POST", "/chaos/faults/f1/enable", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !engine.GetFault("f1").Enabled {
		t.Error("expected fault to be enabled")
	}

	// Disable
	req = httptest.NewRequest("POST", "/chaos/faults/f1/disable", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if engine.GetFault("f1").Enabled {
		t.Error("expected fault to be disabled")
	}
}

func TestHandler_Experiments(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	runner := NewExperimentRunner(engine, nil)
	handler := NewHandler(engine, runner, nil)

	// Create experiment
	exp := Experiment{
		ID:       "exp-1",
		Name:     "Test Experiment",
		Duration: time.Minute,
		Faults: []*Fault{
			{ID: "exp-fault", Type: FaultTypeLatency, Percentage: 50},
		},
	}

	body, _ := json.Marshal(exp)
	req := httptest.NewRequest("POST", "/chaos/experiments", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Errorf("expected 201, got %d", rec.Code)
	}

	// List experiments
	req = httptest.NewRequest("GET", "/chaos/experiments", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Start experiment
	req = httptest.NewRequest("POST", "/chaos/experiments/exp-1/start", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Stop experiment
	req = httptest.NewRequest("POST", "/chaos/experiments/exp-1/stop", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandler_ExperimentsNoRunner(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})
	handler := NewHandler(engine, nil, nil)

	req := httptest.NewRequest("GET", "/chaos/experiments", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 501 {
		t.Errorf("expected 501, got %d", rec.Code)
	}
}

func TestPresets(t *testing.T) {
	// Verify presets are configured correctly
	expected := []string{"slow-response", "random-500", "random-503", "connection-timeout"}

	for _, name := range expected {
		preset, ok := Presets[name]
		if !ok {
			t.Errorf("missing preset: %s", name)
			continue
		}
		if preset.ID != name {
			t.Errorf("preset %s has wrong ID: %s", name, preset.ID)
		}
		if preset.Enabled {
			t.Errorf("preset %s should be disabled by default", name)
		}
	}
}

func TestEngine_IsScheduledNow(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true})

	tests := []struct {
		name     string
		schedule *Schedule
		want     bool
	}{
		{
			name:     "empty schedule",
			schedule: &Schedule{},
			want:     true,
		},
		{
			name: "all days allowed",
			schedule: &Schedule{
				Days: []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.isScheduledNow(tt.schedule)
			if got != tt.want {
				t.Errorf("isScheduledNow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	engine := NewEngine(EngineConfig{Enabled: true, Seed: 1})

	// Concurrent adds
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			fault := &Fault{
				ID:         "fault-" + string(rune('0'+id)),
				Type:       FaultTypeLatency,
				Percentage: 50,
			}
			engine.AddFault(fault)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			engine.ListFaults()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have some faults (may have collisions from concurrent writes)
	faults := engine.ListFaults()
	if len(faults) == 0 {
		t.Error("expected some faults")
	}
}
