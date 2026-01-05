// Package chaos provides chaos engineering capabilities for testing resilience.
package chaos

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FaultType represents a type of fault injection.
type FaultType string

const (
	FaultTypeLatency  FaultType = "latency"
	FaultTypeError    FaultType = "error"
	FaultTypeAbort    FaultType = "abort"
	FaultTypeTimeout  FaultType = "timeout"
	FaultTypePartial  FaultType = "partial"
	FaultTypeCorrupt  FaultType = "corrupt"
)

// Fault represents a fault injection rule.
type Fault struct {
	ID          string    `json:"id"`
	Type        FaultType `json:"type"`
	Enabled     bool      `json:"enabled"`
	Percentage  float64   `json:"percentage"` // 0-100
	Duration    time.Duration `json:"duration,omitempty"`
	StatusCode  int       `json:"status_code,omitempty"`
	Message     string    `json:"message,omitempty"`
	Routes      []string  `json:"routes,omitempty"`
	Methods     []string  `json:"methods,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Schedule    *Schedule `json:"schedule,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Stats       *FaultStats `json:"stats,omitempty"`
}

// Schedule defines when a fault is active.
type Schedule struct {
	StartTime string   `json:"start_time,omitempty"` // HH:MM format
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"` // monday, tuesday, etc.
	Timezone  string   `json:"timezone,omitempty"`
}

// FaultStats tracks fault injection statistics.
type FaultStats struct {
	Triggered   int64     `json:"triggered"`
	Skipped     int64     `json:"skipped"`
	LastTriggered *time.Time `json:"last_triggered,omitempty"`
}

// Engine manages chaos engineering experiments.
type Engine struct {
	faults  map[string]*Fault
	mu      sync.RWMutex
	config  EngineConfig
	logger  *slog.Logger
	random  *rand.Rand
}

// EngineConfig configures the chaos engine.
type EngineConfig struct {
	// Enabled controls whether chaos engineering is active.
	Enabled bool
	// DryRun logs faults without executing them.
	DryRun bool
	// Seed for random number generator.
	Seed int64
	// Logger for engine events.
	Logger *slog.Logger
}

// NewEngine creates a new chaos engine.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	return &Engine{
		faults: make(map[string]*Fault),
		config: cfg,
		logger: cfg.Logger,
		random: rand.New(rand.NewSource(seed)),
	}
}

// AddFault adds a fault injection rule.
func (e *Engine) AddFault(fault *Fault) error {
	if fault.ID == "" {
		return fmt.Errorf("fault ID is required")
	}
	if fault.Percentage < 0 || fault.Percentage > 100 {
		return fmt.Errorf("percentage must be between 0 and 100")
	}

	fault.CreatedAt = time.Now()
	if fault.Stats == nil {
		fault.Stats = &FaultStats{}
	}

	e.mu.Lock()
	e.faults[fault.ID] = fault
	e.mu.Unlock()

	e.logger.Info("fault added",
		"id", fault.ID,
		"type", fault.Type,
		"percentage", fault.Percentage,
	)

	return nil
}

// RemoveFault removes a fault injection rule.
func (e *Engine) RemoveFault(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.faults[id]; ok {
		delete(e.faults, id)
		e.logger.Info("fault removed", "id", id)
		return true
	}
	return false
}

// GetFault returns a fault by ID.
func (e *Engine) GetFault(id string) *Fault {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.faults[id]
}

// ListFaults returns all faults.
func (e *Engine) ListFaults() []*Fault {
	e.mu.RLock()
	defer e.mu.RUnlock()

	faults := make([]*Fault, 0, len(e.faults))
	for _, f := range e.faults {
		faults = append(faults, f)
	}
	return faults
}

// EnableFault enables a fault.
func (e *Engine) EnableFault(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if fault, ok := e.faults[id]; ok {
		fault.Enabled = true
		return true
	}
	return false
}

// DisableFault disables a fault.
func (e *Engine) DisableFault(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if fault, ok := e.faults[id]; ok {
		fault.Enabled = false
		return true
	}
	return false
}

// ShouldInject determines if a fault should be injected.
func (e *Engine) ShouldInject(fault *Fault, r *http.Request) bool {
	if !e.config.Enabled || !fault.Enabled {
		return false
	}

	// Check expiration
	if fault.ExpiresAt != nil && time.Now().After(*fault.ExpiresAt) {
		return false
	}

	// Check schedule
	if fault.Schedule != nil && !e.isScheduledNow(fault.Schedule) {
		return false
	}

	// Check route match
	if len(fault.Routes) > 0 {
		matched := false
		for _, route := range fault.Routes {
			if matchRoute(route, r.URL.Path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check method match
	if len(fault.Methods) > 0 {
		matched := false
		for _, method := range fault.Methods {
			if strings.EqualFold(method, r.Method) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check header match
	for key, value := range fault.Headers {
		if r.Header.Get(key) != value {
			return false
		}
	}

	// Check percentage
	e.mu.Lock()
	inject := e.random.Float64()*100 < fault.Percentage
	e.mu.Unlock()

	return inject
}

// matchRoute checks if a path matches a route pattern.
func matchRoute(pattern, path string) bool {
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// isScheduledNow checks if a schedule is active.
func (e *Engine) isScheduledNow(schedule *Schedule) bool {
	now := time.Now()
	if schedule.Timezone != "" {
		if loc, err := time.LoadLocation(schedule.Timezone); err == nil {
			now = now.In(loc)
		}
	}

	// Check day
	if len(schedule.Days) > 0 {
		dayName := strings.ToLower(now.Weekday().String())
		matched := false
		for _, day := range schedule.Days {
			if strings.ToLower(day) == dayName {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check time range
	if schedule.StartTime != "" && schedule.EndTime != "" {
		currentTime := now.Format("15:04")
		if currentTime < schedule.StartTime || currentTime > schedule.EndTime {
			return false
		}
	}

	return true
}

// Execute executes a fault injection.
func (e *Engine) Execute(ctx context.Context, fault *Fault, w http.ResponseWriter, r *http.Request) bool {
	e.mu.Lock()
	fault.Stats.Triggered++
	now := time.Now()
	fault.Stats.LastTriggered = &now
	e.mu.Unlock()

	if e.config.DryRun {
		e.logger.Info("dry-run fault injection",
			"id", fault.ID,
			"type", fault.Type,
			"path", r.URL.Path,
		)
		return false
	}

	e.logger.Info("executing fault injection",
		"id", fault.ID,
		"type", fault.Type,
		"path", r.URL.Path,
	)

	switch fault.Type {
	case FaultTypeLatency:
		return e.executeLatency(ctx, fault)
	case FaultTypeError:
		return e.executeError(fault, w)
	case FaultTypeAbort:
		return e.executeAbort(fault, w)
	case FaultTypeTimeout:
		return e.executeTimeout(ctx, fault)
	default:
		return false
	}
}

// executeLatency injects latency.
func (e *Engine) executeLatency(ctx context.Context, fault *Fault) bool {
	if fault.Duration == 0 {
		return false
	}

	select {
	case <-time.After(fault.Duration):
	case <-ctx.Done():
	}

	return false // Continue to actual handler
}

// executeError returns an error response.
func (e *Engine) executeError(fault *Fault, w http.ResponseWriter) bool {
	code := fault.StatusCode
	if code == 0 {
		code = http.StatusInternalServerError
	}

	message := fault.Message
	if message == "" {
		message = "Chaos fault injection: simulated error"
	}

	w.Header().Set("X-Chaos-Injected", "true")
	w.Header().Set("X-Chaos-Fault-ID", fault.ID)
	http.Error(w, message, code)

	return true // Don't continue to handler
}

// executeAbort aborts the request.
func (e *Engine) executeAbort(fault *Fault, w http.ResponseWriter) bool {
	code := fault.StatusCode
	if code == 0 {
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("X-Chaos-Injected", "true")
	w.Header().Set("X-Chaos-Fault-ID", fault.ID)
	w.Header().Set("Connection", "close")
	w.WriteHeader(code)

	return true
}

// executeTimeout simulates a timeout.
func (e *Engine) executeTimeout(ctx context.Context, fault *Fault) bool {
	duration := fault.Duration
	if duration == 0 {
		duration = 30 * time.Second
	}

	select {
	case <-time.After(duration):
	case <-ctx.Done():
	}

	return false
}

// MiddlewareConfig configures the chaos middleware.
type MiddlewareConfig struct {
	// Engine is the chaos engine.
	Engine *Engine
	// OnFaultInjected is called when a fault is injected.
	OnFaultInjected func(fault *Fault, r *http.Request)
	// Logger for middleware events.
	Logger *slog.Logger
}

// Middleware returns HTTP middleware that injects faults.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check all enabled faults
			for _, fault := range cfg.Engine.ListFaults() {
				if cfg.Engine.ShouldInject(fault, r) {
					if cfg.OnFaultInjected != nil {
						cfg.OnFaultInjected(fault, r)
					}

					stop := cfg.Engine.Execute(r.Context(), fault, w, r)
					if stop {
						return
					}
				} else {
					cfg.Engine.mu.Lock()
					fault.Stats.Skipped++
					cfg.Engine.mu.Unlock()
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Experiment represents a chaos experiment.
type Experiment struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Faults      []*Fault      `json:"faults"`
	Duration    time.Duration `json:"duration"`
	Status      ExperimentStatus `json:"status"`
	StartedAt   *time.Time    `json:"started_at,omitempty"`
	EndedAt     *time.Time    `json:"ended_at,omitempty"`
	Results     *ExperimentResults `json:"results,omitempty"`
}

// ExperimentStatus represents the status of an experiment.
type ExperimentStatus string

const (
	ExperimentStatusPending   ExperimentStatus = "pending"
	ExperimentStatusRunning   ExperimentStatus = "running"
	ExperimentStatusCompleted ExperimentStatus = "completed"
	ExperimentStatusFailed    ExperimentStatus = "failed"
	ExperimentStatusAborted   ExperimentStatus = "aborted"
)

// ExperimentResults contains experiment results.
type ExperimentResults struct {
	TotalRequests     int64   `json:"total_requests"`
	FaultsInjected    int64   `json:"faults_injected"`
	ErrorsObserved    int64   `json:"errors_observed"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	ImpactScore       float64 `json:"impact_score"`
}

// ExperimentRunner runs chaos experiments.
type ExperimentRunner struct {
	engine      *Engine
	experiments map[string]*Experiment
	mu          sync.RWMutex
	logger      *slog.Logger
}

// NewExperimentRunner creates a new experiment runner.
func NewExperimentRunner(engine *Engine, logger *slog.Logger) *ExperimentRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &ExperimentRunner{
		engine:      engine,
		experiments: make(map[string]*Experiment),
		logger:      logger,
	}
}

// CreateExperiment creates a new experiment.
func (r *ExperimentRunner) CreateExperiment(exp *Experiment) error {
	if exp.ID == "" {
		return fmt.Errorf("experiment ID is required")
	}

	exp.Status = ExperimentStatusPending

	r.mu.Lock()
	r.experiments[exp.ID] = exp
	r.mu.Unlock()

	return nil
}

// StartExperiment starts an experiment.
func (r *ExperimentRunner) StartExperiment(id string) error {
	r.mu.Lock()
	exp, ok := r.experiments[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("experiment not found: %s", id)
	}
	r.mu.Unlock()

	if exp.Status != ExperimentStatusPending {
		return fmt.Errorf("experiment is not pending: %s", exp.Status)
	}

	// Add faults
	for _, fault := range exp.Faults {
		fault.Enabled = true
		r.engine.AddFault(fault)
	}

	now := time.Now()
	exp.StartedAt = &now
	exp.Status = ExperimentStatusRunning

	r.logger.Info("experiment started",
		"id", id,
		"name", exp.Name,
		"duration", exp.Duration,
	)

	// Schedule end
	if exp.Duration > 0 {
		go func() {
			time.Sleep(exp.Duration)
			r.StopExperiment(id)
		}()
	}

	return nil
}

// StopExperiment stops an experiment.
func (r *ExperimentRunner) StopExperiment(id string) error {
	r.mu.Lock()
	exp, ok := r.experiments[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("experiment not found: %s", id)
	}
	r.mu.Unlock()

	if exp.Status != ExperimentStatusRunning {
		return nil
	}

	// Remove faults
	for _, fault := range exp.Faults {
		r.engine.RemoveFault(fault.ID)
	}

	now := time.Now()
	exp.EndedAt = &now
	exp.Status = ExperimentStatusCompleted

	// Calculate results
	exp.Results = r.calculateResults(exp)

	r.logger.Info("experiment completed",
		"id", id,
		"name", exp.Name,
		"faults_injected", exp.Results.FaultsInjected,
	)

	return nil
}

// calculateResults calculates experiment results.
func (r *ExperimentRunner) calculateResults(exp *Experiment) *ExperimentResults {
	results := &ExperimentResults{}

	for _, fault := range exp.Faults {
		if fault.Stats != nil {
			results.FaultsInjected += fault.Stats.Triggered
			results.TotalRequests += fault.Stats.Triggered + fault.Stats.Skipped
		}
	}

	// Calculate impact score (simplified)
	if results.TotalRequests > 0 {
		results.ImpactScore = float64(results.FaultsInjected) / float64(results.TotalRequests) * 100
	}

	return results
}

// GetExperiment returns an experiment by ID.
func (r *ExperimentRunner) GetExperiment(id string) *Experiment {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.experiments[id]
}

// ListExperiments returns all experiments.
func (r *ExperimentRunner) ListExperiments() []*Experiment {
	r.mu.RLock()
	defer r.mu.RUnlock()

	exps := make([]*Experiment, 0, len(r.experiments))
	for _, exp := range r.experiments {
		exps = append(exps, exp)
	}
	return exps
}

// Handler provides an HTTP API for chaos engineering.
type Handler struct {
	engine *Engine
	runner *ExperimentRunner
	logger *slog.Logger
}

// NewHandler creates a new chaos handler.
func NewHandler(engine *Engine, runner *ExperimentRunner, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		engine: engine,
		runner: runner,
		logger: logger,
	}
}

// ServeHTTP handles chaos API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/chaos")

	switch {
	case path == "/faults" && r.Method == http.MethodGet:
		h.handleListFaults(w, r)
	case path == "/faults" && r.Method == http.MethodPost:
		h.handleAddFault(w, r)
	case strings.HasPrefix(path, "/faults/") && r.Method == http.MethodGet:
		h.handleGetFault(w, r, strings.TrimPrefix(path, "/faults/"))
	case strings.HasPrefix(path, "/faults/") && r.Method == http.MethodDelete:
		h.handleRemoveFault(w, r, strings.TrimPrefix(path, "/faults/"))
	case strings.HasSuffix(path, "/enable") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/faults/"), "/enable")
		h.handleEnableFault(w, r, id)
	case strings.HasSuffix(path, "/disable") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/faults/"), "/disable")
		h.handleDisableFault(w, r, id)
	case path == "/experiments" && r.Method == http.MethodGet:
		h.handleListExperiments(w, r)
	case path == "/experiments" && r.Method == http.MethodPost:
		h.handleCreateExperiment(w, r)
	case strings.HasSuffix(path, "/start") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/experiments/"), "/start")
		h.handleStartExperiment(w, r, id)
	case strings.HasSuffix(path, "/stop") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/experiments/"), "/stop")
		h.handleStopExperiment(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleListFaults(w http.ResponseWriter, r *http.Request) {
	faults := h.engine.ListFaults()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(faults)
}

func (h *Handler) handleAddFault(w http.ResponseWriter, r *http.Request) {
	var fault Fault
	if err := json.NewDecoder(r.Body).Decode(&fault); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.engine.AddFault(&fault); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(fault)
}

func (h *Handler) handleGetFault(w http.ResponseWriter, r *http.Request, id string) {
	fault := h.engine.GetFault(id)
	if fault == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fault)
}

func (h *Handler) handleRemoveFault(w http.ResponseWriter, r *http.Request, id string) {
	if !h.engine.RemoveFault(id) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleEnableFault(w http.ResponseWriter, r *http.Request, id string) {
	if !h.engine.EnableFault(id) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleDisableFault(w http.ResponseWriter, r *http.Request, id string) {
	if !h.engine.DisableFault(id) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleListExperiments(w http.ResponseWriter, r *http.Request) {
	if h.runner == nil {
		http.Error(w, "experiment runner not configured", http.StatusNotImplemented)
		return
	}

	exps := h.runner.ListExperiments()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exps)
}

func (h *Handler) handleCreateExperiment(w http.ResponseWriter, r *http.Request) {
	if h.runner == nil {
		http.Error(w, "experiment runner not configured", http.StatusNotImplemented)
		return
	}

	var exp Experiment
	if err := json.NewDecoder(r.Body).Decode(&exp); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.runner.CreateExperiment(&exp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(exp)
}

func (h *Handler) handleStartExperiment(w http.ResponseWriter, r *http.Request, id string) {
	if h.runner == nil {
		http.Error(w, "experiment runner not configured", http.StatusNotImplemented)
		return
	}

	if err := h.runner.StartExperiment(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleStopExperiment(w http.ResponseWriter, r *http.Request, id string) {
	if h.runner == nil {
		http.Error(w, "experiment runner not configured", http.StatusNotImplemented)
		return
	}

	if err := h.runner.StopExperiment(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Presets provides common fault presets.
var Presets = map[string]*Fault{
	"slow-response": {
		ID:         "slow-response",
		Type:       FaultTypeLatency,
		Enabled:    false,
		Percentage: 10,
		Duration:   2 * time.Second,
	},
	"random-500": {
		ID:         "random-500",
		Type:       FaultTypeError,
		Enabled:    false,
		Percentage: 5,
		StatusCode: 500,
		Message:    "Internal Server Error (chaos)",
	},
	"random-503": {
		ID:         "random-503",
		Type:       FaultTypeAbort,
		Enabled:    false,
		Percentage: 5,
		StatusCode: 503,
	},
	"connection-timeout": {
		ID:         "connection-timeout",
		Type:       FaultTypeTimeout,
		Enabled:    false,
		Percentage: 5,
		Duration:   30 * time.Second,
	},
}
