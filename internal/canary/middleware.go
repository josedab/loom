package canary

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// contextKey is the type for context keys.
type contextKey string

const (
	// ContextKeyTarget is the context key for the selected canary target.
	ContextKeyTarget contextKey = "canary-target"
	// ContextKeyUpstream is the context key for the selected upstream.
	ContextKeyUpstream contextKey = "canary-upstream"
)

// MiddlewareConfig configures the canary middleware.
type MiddlewareConfig struct {
	// Manager is the canary deployment manager
	Manager *Manager
	// RouteIDFunc extracts the route ID from the request
	RouteIDFunc func(*http.Request) string
	// Logger for canary events
	Logger *slog.Logger
}

// Middleware returns HTTP middleware that implements canary routing.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get route ID
			routeID := ""
			if cfg.RouteIDFunc != nil {
				routeID = cfg.RouteIDFunc(r)
			}

			if routeID == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if there's a canary deployment for this route
			deployment, ok := cfg.Manager.GetDeployment(routeID)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Select target based on deployment rules
			target, ok := deployment.SelectTarget(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Set sticky cookie if enabled
			deployment.SetStickyCookie(w, target.Name)

			// Add target headers
			for k, v := range target.Headers {
				r.Header.Set(k, v)
			}

			// Add canary info header for debugging/monitoring
			w.Header().Set("X-Canary-Target", target.Name)

			// Store target info in context for the proxy to use
			ctx := context.WithValue(r.Context(), ContextKeyTarget, target.Name)
			ctx = context.WithValue(ctx, ContextKeyUpstream, target.Upstream)
			r = r.WithContext(ctx)

			// Record the request
			deployment.RecordRequest(target.Name)

			// Create a response writer wrapper to detect errors
			recorder := &statusRecorder{ResponseWriter: w, statusCode: 200}

			next.ServeHTTP(recorder, r)

			// Record errors (5xx responses)
			if recorder.statusCode >= 500 {
				deployment.RecordError(target.Name)
			}
		})
	}
}

// statusRecorder wraps ResponseWriter to capture status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// GetTargetFromContext returns the canary target name from context.
func GetTargetFromContext(ctx context.Context) (string, bool) {
	target, ok := ctx.Value(ContextKeyTarget).(string)
	return target, ok
}

// GetUpstreamFromContext returns the canary upstream from context.
func GetUpstreamFromContext(ctx context.Context) (string, bool) {
	upstream, ok := ctx.Value(ContextKeyUpstream).(string)
	return upstream, ok
}

// GradualRollout represents a gradual rollout schedule.
type GradualRollout struct {
	Stages    []RolloutStage
	Current   int
	StartTime time.Time
}

// RolloutStage represents a single stage in a gradual rollout.
type RolloutStage struct {
	Weight   int           // Traffic percentage for canary
	Duration time.Duration // How long to stay at this stage
	Metrics  *StageMetrics // Metrics collected during this stage
}

// StageMetrics holds metrics for a rollout stage.
type StageMetrics struct {
	Requests     uint64
	Errors       uint64
	ErrorRate    float64
	P50Latency   time.Duration
	P99Latency   time.Duration
}

// AutoRollout manages automatic canary rollouts based on metrics.
type AutoRollout struct {
	manager     *Manager
	routeID     string
	stages      []RolloutStage
	currentIdx  int
	targetName  string
	baseTarget  string
	errorThresh float64 // Error rate threshold for rollback
	logger      *slog.Logger
}

// NewAutoRollout creates a new automatic rollout manager.
func NewAutoRollout(mgr *Manager, routeID, targetName, baseTarget string) *AutoRollout {
	return &AutoRollout{
		manager:     mgr,
		routeID:     routeID,
		targetName:  targetName,
		baseTarget:  baseTarget,
		currentIdx:  -1, // Start at -1 so first Advance() goes to stage 0
		errorThresh: 0.05, // 5% error threshold
		stages: []RolloutStage{
			{Weight: 1, Duration: 5 * time.Minute},
			{Weight: 5, Duration: 10 * time.Minute},
			{Weight: 25, Duration: 15 * time.Minute},
			{Weight: 50, Duration: 20 * time.Minute},
			{Weight: 100, Duration: 0}, // Final stage
		},
		logger: slog.Default(),
	}
}

// SetErrorThreshold sets the error rate threshold for automatic rollback.
func (a *AutoRollout) SetErrorThreshold(threshold float64) {
	a.errorThresh = threshold
}

// SetStages sets custom rollout stages.
func (a *AutoRollout) SetStages(stages []RolloutStage) {
	a.stages = stages
	a.currentIdx = -1 // Reset to initial state
}

// Advance moves to the next rollout stage.
func (a *AutoRollout) Advance() bool {
	if a.currentIdx >= len(a.stages)-1 {
		return false // Already at final stage
	}

	a.currentIdx++
	stage := a.stages[a.currentIdx]

	// Update weights
	weights := map[string]int{
		a.targetName: stage.Weight,
		a.baseTarget: 100 - stage.Weight,
	}
	a.manager.UpdateWeights(a.routeID, weights)

	a.logger.Info("advanced canary rollout",
		"route", a.routeID,
		"stage", a.currentIdx+1,
		"weight", stage.Weight)

	return true
}

// Rollback returns to the base target.
func (a *AutoRollout) Rollback() {
	a.manager.RollbackTarget(a.routeID, a.baseTarget)
	a.currentIdx = 0

	a.logger.Warn("rolled back canary deployment",
		"route", a.routeID,
		"target", a.targetName)
}

// Complete finalizes the rollout at 100%.
func (a *AutoRollout) Complete() {
	a.manager.PromoteTarget(a.routeID, a.targetName)

	a.logger.Info("completed canary rollout",
		"route", a.routeID,
		"target", a.targetName)
}

// CurrentStage returns the current rollout stage.
func (a *AutoRollout) CurrentStage() int {
	return a.currentIdx
}

// IsComplete returns true if the rollout is at the final stage.
func (a *AutoRollout) IsComplete() bool {
	return a.currentIdx >= len(a.stages)-1
}
