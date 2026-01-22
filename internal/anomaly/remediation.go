// Package anomaly provides API anomaly detection capabilities.
package anomaly

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// RemediationEngine handles automatic remediation of incidents.
type RemediationEngine struct {
	config      RemediationConfig
	detector    *Detector
	rca         *RootCauseAnalyzer
	actions     map[string]RemediationAction
	runbooks    map[string]*Runbook
	history     []*RemediationRecord
	pending     []*PendingApproval
	executors   map[ActionType]ActionExecutor
	logger      *slog.Logger
	mu          sync.RWMutex
}

// RemediationConfig configures the remediation engine.
type RemediationConfig struct {
	// Enabled controls whether auto-remediation is active
	Enabled bool
	// RequireApproval for critical actions
	RequireApproval bool
	// ApprovalTimeout is how long to wait for approval
	ApprovalTimeout time.Duration
	// MaxConcurrentActions limits parallel remediation actions
	MaxConcurrentActions int
	// CooldownPeriod between same actions
	CooldownPeriod time.Duration
	// SafetyThreshold - min confidence to auto-remediate
	SafetyThreshold float64
	// MaxActionAttempts for the same incident
	MaxActionAttempts int
	// Logger for remediation events
	Logger *slog.Logger
}

// DefaultRemediationConfig returns sensible defaults.
func DefaultRemediationConfig() RemediationConfig {
	return RemediationConfig{
		Enabled:              false, // Disabled by default for safety
		RequireApproval:      true,
		ApprovalTimeout:      5 * time.Minute,
		MaxConcurrentActions: 3,
		CooldownPeriod:       10 * time.Minute,
		SafetyThreshold:      0.8,
		MaxActionAttempts:    3,
	}
}

// NewRemediationEngine creates a new remediation engine.
func NewRemediationEngine(config RemediationConfig, detector *Detector, rca *RootCauseAnalyzer) *RemediationEngine {
	if config.ApprovalTimeout == 0 {
		config.ApprovalTimeout = 5 * time.Minute
	}
	if config.MaxConcurrentActions == 0 {
		config.MaxConcurrentActions = 3
	}
	if config.CooldownPeriod == 0 {
		config.CooldownPeriod = 10 * time.Minute
	}
	if config.SafetyThreshold == 0 {
		config.SafetyThreshold = 0.8
	}
	if config.MaxActionAttempts == 0 {
		config.MaxActionAttempts = 3
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	engine := &RemediationEngine{
		config:    config,
		detector:  detector,
		rca:       rca,
		actions:   make(map[string]RemediationAction),
		runbooks:  make(map[string]*Runbook),
		history:   make([]*RemediationRecord, 0),
		pending:   make([]*PendingApproval, 0),
		executors: make(map[ActionType]ActionExecutor),
		logger:    config.Logger,
	}

	// Register default executors
	engine.registerDefaultExecutors()

	return engine
}

// ActionType represents the type of remediation action.
type ActionType string

const (
	ActionTypeScale          ActionType = "scale"
	ActionTypeReroute        ActionType = "reroute"
	ActionTypeCircuitBreaker ActionType = "circuit_breaker"
	ActionTypeRateLimit      ActionType = "rate_limit"
	ActionTypeRestart        ActionType = "restart"
	ActionTypeNotify         ActionType = "notify"
	ActionTypeCustom         ActionType = "custom"
)

// ActionSeverity indicates the impact level of an action.
type ActionSeverity string

const (
	ActionSeverityLow      ActionSeverity = "low"      // Notifications, logging
	ActionSeverityMedium   ActionSeverity = "medium"   // Rate limiting, circuit breaker
	ActionSeverityHigh     ActionSeverity = "high"     // Rerouting, scaling
	ActionSeverityCritical ActionSeverity = "critical" // Restarts, failover
)

// RemediationAction represents a remediation action that can be taken.
type RemediationAction struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        ActionType        `json:"type"`
	Severity    ActionSeverity    `json:"severity"`
	Description string            `json:"description"`
	Parameters  map[string]string `json:"parameters"`
	Conditions  []ActionCondition `json:"conditions"`
	Cooldown    time.Duration     `json:"cooldown"`
	Reversible  bool              `json:"reversible"`
	RollbackID  string            `json:"rollback_id,omitempty"`
}

// ActionCondition defines when an action should be triggered.
type ActionCondition struct {
	AnomalyType AnomalyType       `json:"anomaly_type"`
	Severity    Severity          `json:"severity"`
	Service     string            `json:"service,omitempty"`
	Threshold   float64           `json:"threshold,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ActionExecutor executes a remediation action.
type ActionExecutor interface {
	Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error)
	Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error
	Validate(action RemediationAction) error
}

// ActionResult represents the result of executing an action.
type ActionResult struct {
	Success       bool              `json:"success"`
	Message       string            `json:"message"`
	Timestamp     time.Time         `json:"timestamp"`
	Duration      time.Duration     `json:"duration"`
	Metadata      map[string]string `json:"metadata"`
	RollbackData  interface{}       `json:"rollback_data,omitempty"`
}

// RemediationRecord records a remediation action taken.
type RemediationRecord struct {
	ID          string            `json:"id"`
	IncidentID  string            `json:"incident_id"`
	ActionID    string            `json:"action_id"`
	ActionType  ActionType        `json:"action_type"`
	Timestamp   time.Time         `json:"timestamp"`
	Status      RemediationStatus `json:"status"`
	Result      *ActionResult     `json:"result,omitempty"`
	ApprovedBy  string            `json:"approved_by,omitempty"`
	RolledBack  bool              `json:"rolled_back"`
	RollbackAt  *time.Time        `json:"rollback_at,omitempty"`
}

// RemediationStatus represents the status of a remediation.
type RemediationStatus string

const (
	RemediationStatusPending   RemediationStatus = "pending"
	RemediationStatusApproved  RemediationStatus = "approved"
	RemediationStatusExecuting RemediationStatus = "executing"
	RemediationStatusSuccess   RemediationStatus = "success"
	RemediationStatusFailed    RemediationStatus = "failed"
	RemediationStatusRolledBack RemediationStatus = "rolled_back"
)

// PendingApproval represents an action awaiting approval.
type PendingApproval struct {
	ID         string            `json:"id"`
	IncidentID string            `json:"incident_id"`
	Action     RemediationAction `json:"action"`
	Reason     string            `json:"reason"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Approved   bool              `json:"approved"`
	ApprovedBy string            `json:"approved_by,omitempty"`
	ApprovedAt *time.Time        `json:"approved_at,omitempty"`
}

// Runbook represents a series of remediation steps.
type Runbook struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Triggers    []ActionCondition `json:"triggers"`
	Steps       []RunbookStep  `json:"steps"`
	Timeout     time.Duration  `json:"timeout"`
	OnFailure   FailurePolicy  `json:"on_failure"`
}

// RunbookStep represents a step in a runbook.
type RunbookStep struct {
	Order      int               `json:"order"`
	ActionID   string            `json:"action_id"`
	Condition  string            `json:"condition,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Timeout    time.Duration     `json:"timeout"`
	OnFailure  FailurePolicy     `json:"on_failure"`
}

// FailurePolicy defines behavior on step failure.
type FailurePolicy string

const (
	FailurePolicyContinue FailurePolicy = "continue"
	FailurePolicyStop     FailurePolicy = "stop"
	FailurePolicyRollback FailurePolicy = "rollback"
)

// RegisterAction registers a remediation action.
func (e *RemediationEngine) RegisterAction(action RemediationAction) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.actions[action.ID] = action
}

// RegisterRunbook registers a runbook.
func (e *RemediationEngine) RegisterRunbook(runbook *Runbook) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runbooks[runbook.ID] = runbook
}

// RegisterExecutor registers an action executor.
func (e *RemediationEngine) RegisterExecutor(actionType ActionType, executor ActionExecutor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executors[actionType] = executor
}

// registerDefaultExecutors registers built-in executors.
func (e *RemediationEngine) registerDefaultExecutors() {
	e.executors[ActionTypeScale] = &ScaleExecutor{}
	e.executors[ActionTypeReroute] = &RerouteExecutor{}
	e.executors[ActionTypeCircuitBreaker] = &CircuitBreakerExecutor{}
	e.executors[ActionTypeRateLimit] = &RateLimitExecutor{}
	e.executors[ActionTypeNotify] = &NotifyExecutor{}
}

// ProcessIncident processes an incident and determines remediation actions.
func (e *RemediationEngine) ProcessIncident(ctx context.Context, incident *Incident) []*RemediationRecord {
	if !e.config.Enabled {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if we've already taken too many actions for this incident
	actionCount := 0
	for _, record := range e.history {
		if record.IncidentID == incident.ID {
			actionCount++
		}
	}
	if actionCount >= e.config.MaxActionAttempts {
		e.logger.Warn("max action attempts reached for incident",
			"incident_id", incident.ID,
			"attempts", actionCount,
		)
		return nil
	}

	// Find matching actions
	actions := e.findMatchingActions(incident)
	if len(actions) == 0 {
		// Try runbooks
		return e.executeRunbooks(ctx, incident)
	}

	var records []*RemediationRecord
	for _, action := range actions {
		// Check cooldown
		if e.isInCooldown(action.ID) {
			continue
		}

		record := e.executeOrRequestApproval(ctx, action, incident)
		if record != nil {
			records = append(records, record)
		}
	}

	return records
}

// findMatchingActions finds actions that match the incident.
func (e *RemediationEngine) findMatchingActions(incident *Incident) []RemediationAction {
	var matches []RemediationAction

	for _, action := range e.actions {
		if e.matchesConditions(action, incident) {
			matches = append(matches, action)
		}
	}

	return matches
}

// matchesConditions checks if an action's conditions match the incident.
func (e *RemediationEngine) matchesConditions(action RemediationAction, incident *Incident) bool {
	if len(action.Conditions) == 0 {
		return false
	}

	incident.mu.RLock()
	defer incident.mu.RUnlock()

	for _, condition := range action.Conditions {
		matched := false
		for _, alert := range incident.Alerts {
			if condition.AnomalyType != "" && alert.Type != condition.AnomalyType {
				continue
			}
			if condition.Severity != "" && alert.Severity != condition.Severity {
				continue
			}
			if condition.Service != "" && alert.Route != condition.Service {
				continue
			}
			if condition.Threshold > 0 && alert.Deviation < condition.Threshold {
				continue
			}
			matched = true
			break
		}
		if matched {
			return true
		}
	}

	return false
}

// isInCooldown checks if an action is in cooldown period.
func (e *RemediationEngine) isInCooldown(actionID string) bool {
	cooldown := e.config.CooldownPeriod
	action, exists := e.actions[actionID]
	if exists && action.Cooldown > 0 {
		cooldown = action.Cooldown
	}

	for i := len(e.history) - 1; i >= 0; i-- {
		record := e.history[i]
		if record.ActionID == actionID {
			if time.Since(record.Timestamp) < cooldown {
				return true
			}
			break
		}
	}

	return false
}

// executeOrRequestApproval executes action or requests approval.
func (e *RemediationEngine) executeOrRequestApproval(ctx context.Context, action RemediationAction, incident *Incident) *RemediationRecord {
	// Check if approval is required
	needsApproval := e.config.RequireApproval && (action.Severity == ActionSeverityHigh || action.Severity == ActionSeverityCritical)

	// Check safety threshold
	if len(incident.RootCauses) > 0 && incident.RootCauses[0].Confidence < e.config.SafetyThreshold {
		needsApproval = true
	}

	record := &RemediationRecord{
		ID:         generateID(),
		IncidentID: incident.ID,
		ActionID:   action.ID,
		ActionType: action.Type,
		Timestamp:  time.Now(),
		Status:     RemediationStatusPending,
	}

	if needsApproval {
		// Create pending approval
		approval := &PendingApproval{
			ID:         record.ID,
			IncidentID: incident.ID,
			Action:     action,
			Reason:     fmt.Sprintf("Auto-remediation for %s incident", incident.Severity),
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(e.config.ApprovalTimeout),
		}
		e.pending = append(e.pending, approval)

		e.logger.Info("remediation requires approval",
			"action_id", action.ID,
			"incident_id", incident.ID,
			"severity", action.Severity,
		)

		e.history = append(e.history, record)
		return record
	}

	// Execute immediately
	result := e.executeAction(ctx, action, incident)
	record.Result = result
	if result.Success {
		record.Status = RemediationStatusSuccess
	} else {
		record.Status = RemediationStatusFailed
	}

	e.history = append(e.history, record)
	return record
}

// executeAction executes a remediation action.
func (e *RemediationEngine) executeAction(ctx context.Context, action RemediationAction, incident *Incident) *ActionResult {
	executor, exists := e.executors[action.Type]
	if !exists {
		return &ActionResult{
			Success:   false,
			Message:   fmt.Sprintf("no executor for action type: %s", action.Type),
			Timestamp: time.Now(),
		}
	}

	// Validate action
	if err := executor.Validate(action); err != nil {
		return &ActionResult{
			Success:   false,
			Message:   fmt.Sprintf("action validation failed: %v", err),
			Timestamp: time.Now(),
		}
	}

	start := time.Now()
	result, err := executor.Execute(ctx, action, incident)
	if err != nil {
		return &ActionResult{
			Success:   false,
			Message:   fmt.Sprintf("execution failed: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}

	result.Duration = time.Since(start)

	e.logger.Info("remediation action executed",
		"action_id", action.ID,
		"action_type", action.Type,
		"success", result.Success,
		"duration", result.Duration,
	)

	return result
}

// executeRunbooks executes matching runbooks.
func (e *RemediationEngine) executeRunbooks(ctx context.Context, incident *Incident) []*RemediationRecord {
	var records []*RemediationRecord

	for _, runbook := range e.runbooks {
		if e.runbookMatches(runbook, incident) {
			record := e.executeRunbook(ctx, runbook, incident)
			if record != nil {
				records = append(records, record)
			}
		}
	}

	return records
}

// runbookMatches checks if a runbook matches the incident.
func (e *RemediationEngine) runbookMatches(runbook *Runbook, incident *Incident) bool {
	incident.mu.RLock()
	defer incident.mu.RUnlock()

	for _, trigger := range runbook.Triggers {
		for _, alert := range incident.Alerts {
			if trigger.AnomalyType != "" && alert.Type != trigger.AnomalyType {
				continue
			}
			if trigger.Severity != "" && alert.Severity != trigger.Severity {
				continue
			}
			if trigger.Service != "" && alert.Route != trigger.Service {
				continue
			}
			return true
		}
	}

	return false
}

// executeRunbook executes a runbook for an incident.
func (e *RemediationEngine) executeRunbook(ctx context.Context, runbook *Runbook, incident *Incident) *RemediationRecord {
	record := &RemediationRecord{
		ID:         generateID(),
		IncidentID: incident.ID,
		ActionID:   runbook.ID,
		ActionType: ActionTypeCustom,
		Timestamp:  time.Now(),
		Status:     RemediationStatusExecuting,
	}

	// Create timeout context
	runCtx := ctx
	if runbook.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, runbook.Timeout)
		defer cancel()
	}

	var executedActions []RemediationAction
	var lastResult *ActionResult

	for _, step := range runbook.Steps {
		select {
		case <-runCtx.Done():
			record.Status = RemediationStatusFailed
			record.Result = &ActionResult{
				Success:   false,
				Message:   "runbook timeout",
				Timestamp: time.Now(),
			}
			e.history = append(e.history, record)
			return record
		default:
		}

		action, exists := e.actions[step.ActionID]
		if !exists {
			if step.OnFailure == FailurePolicyStop {
				break
			}
			continue
		}

		// Merge step parameters
		if len(step.Parameters) > 0 {
			if action.Parameters == nil {
				action.Parameters = make(map[string]string)
			}
			for k, v := range step.Parameters {
				action.Parameters[k] = v
			}
		}

		lastResult = e.executeAction(runCtx, action, incident)
		executedActions = append(executedActions, action)

		if !lastResult.Success {
			switch step.OnFailure {
			case FailurePolicyStop:
				record.Status = RemediationStatusFailed
				record.Result = lastResult
				e.history = append(e.history, record)
				return record
			case FailurePolicyRollback:
				e.rollbackActions(runCtx, executedActions, incident)
				record.Status = RemediationStatusRolledBack
				record.Result = lastResult
				e.history = append(e.history, record)
				return record
			}
			// Continue on FailurePolicyContinue
		}
	}

	record.Status = RemediationStatusSuccess
	record.Result = lastResult
	e.history = append(e.history, record)
	return record
}

// rollbackActions rolls back executed actions in reverse order.
func (e *RemediationEngine) rollbackActions(ctx context.Context, actions []RemediationAction, incident *Incident) {
	for i := len(actions) - 1; i >= 0; i-- {
		action := actions[i]
		if !action.Reversible {
			continue
		}

		executor, exists := e.executors[action.Type]
		if !exists {
			continue
		}

		// Find the result for this action
		var result *ActionResult
		for j := len(e.history) - 1; j >= 0; j-- {
			if e.history[j].ActionID == action.ID && e.history[j].IncidentID == incident.ID {
				result = e.history[j].Result
				break
			}
		}

		if result != nil && result.RollbackData != nil {
			err := executor.Rollback(ctx, action, result)
			if err != nil {
				e.logger.Error("rollback failed",
					"action_id", action.ID,
					"error", err,
				)
			}
		}
	}
}

// ApproveAction approves a pending action.
func (e *RemediationEngine) ApproveAction(ctx context.Context, approvalID, approvedBy string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var approval *PendingApproval
	for _, p := range e.pending {
		if p.ID == approvalID {
			approval = p
			break
		}
	}

	if approval == nil {
		return fmt.Errorf("approval not found: %s", approvalID)
	}

	if time.Now().After(approval.ExpiresAt) {
		return fmt.Errorf("approval expired")
	}

	approval.Approved = true
	approval.ApprovedBy = approvedBy
	now := time.Now()
	approval.ApprovedAt = &now

	// Find the record and update status
	for _, record := range e.history {
		if record.ID == approvalID {
			record.Status = RemediationStatusApproved
			record.ApprovedBy = approvedBy

			// Execute the action
			incident := e.rca.GetIncident(record.IncidentID)
			if incident != nil {
				result := e.executeAction(ctx, approval.Action, incident)
				record.Result = result
				if result.Success {
					record.Status = RemediationStatusSuccess
				} else {
					record.Status = RemediationStatusFailed
				}
			}
			break
		}
	}

	return nil
}

// RejectAction rejects a pending action.
func (e *RemediationEngine) RejectAction(approvalID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, p := range e.pending {
		if p.ID == approvalID {
			e.pending = append(e.pending[:i], e.pending[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("approval not found: %s", approvalID)
}

// RollbackAction rolls back a previously executed action.
func (e *RemediationEngine) RollbackAction(ctx context.Context, recordID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var record *RemediationRecord
	for _, r := range e.history {
		if r.ID == recordID {
			record = r
			break
		}
	}

	if record == nil {
		return fmt.Errorf("record not found: %s", recordID)
	}

	if record.RolledBack {
		return fmt.Errorf("action already rolled back")
	}

	action, exists := e.actions[record.ActionID]
	if !exists {
		return fmt.Errorf("action not found: %s", record.ActionID)
	}

	if !action.Reversible {
		return fmt.Errorf("action is not reversible")
	}

	executor, exists := e.executors[action.Type]
	if !exists {
		return fmt.Errorf("no executor for action type: %s", action.Type)
	}

	if err := executor.Rollback(ctx, action, record.Result); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	record.RolledBack = true
	now := time.Now()
	record.RollbackAt = &now
	record.Status = RemediationStatusRolledBack

	return nil
}

// GetPendingApprovals returns all pending approvals.
func (e *RemediationEngine) GetPendingApprovals() []*PendingApproval {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Filter expired
	var active []*PendingApproval
	now := time.Now()
	for _, p := range e.pending {
		if !p.Approved && now.Before(p.ExpiresAt) {
			active = append(active, p)
		}
	}
	return active
}

// GetHistory returns remediation history.
func (e *RemediationEngine) GetHistory(limit int) []*RemediationRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > len(e.history) {
		limit = len(e.history)
	}

	start := len(e.history) - limit
	result := make([]*RemediationRecord, limit)
	copy(result, e.history[start:])
	return result
}

// APIHandler returns an HTTP handler for the remediation API.
func (e *RemediationEngine) APIHandler() http.Handler {
	mux := http.NewServeMux()

	// Get pending approvals
	mux.HandleFunc("/approvals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		approvals := e.GetPendingApprovals()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(approvals)
	})

	// Approve action
	mux.HandleFunc("/approvals/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ApprovalID string `json:"approval_id"`
			ApprovedBy string `json:"approved_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := e.ApproveAction(r.Context(), req.ApprovalID, req.ApprovedBy); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	// Reject action
	mux.HandleFunc("/approvals/reject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			ApprovalID string `json:"approval_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := e.RejectAction(req.ApprovalID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	// Get history
	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		history := e.GetHistory(100)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	// Rollback action
	mux.HandleFunc("/rollback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			RecordID string `json:"record_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := e.RollbackAction(r.Context(), req.RecordID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	// Register action
	mux.HandleFunc("/actions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			e.mu.RLock()
			actions := make([]RemediationAction, 0, len(e.actions))
			for _, a := range e.actions {
				actions = append(actions, a)
			}
			e.mu.RUnlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(actions)

		case http.MethodPost:
			var action RemediationAction
			if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			e.RegisterAction(action)
			w.WriteHeader(http.StatusCreated)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Register runbook
	mux.HandleFunc("/runbooks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			e.mu.RLock()
			runbooks := make([]*Runbook, 0, len(e.runbooks))
			for _, rb := range e.runbooks {
				runbooks = append(runbooks, rb)
			}
			e.mu.RUnlock()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(runbooks)

		case http.MethodPost:
			var runbook Runbook
			if err := json.NewDecoder(r.Body).Decode(&runbook); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			e.RegisterRunbook(&runbook)
			w.WriteHeader(http.StatusCreated)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// Built-in action executors

// ScaleExecutor handles scaling actions.
type ScaleExecutor struct{}

func (e *ScaleExecutor) Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error) {
	// In a real implementation, this would call Kubernetes API or cloud provider
	target := action.Parameters["target"]
	replicas := action.Parameters["replicas"]

	return &ActionResult{
		Success:   true,
		Message:   fmt.Sprintf("Scaled %s to %s replicas", target, replicas),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"target":   target,
			"replicas": replicas,
		},
		RollbackData: map[string]string{
			"previous_replicas": action.Parameters["current_replicas"],
		},
	}, nil
}

func (e *ScaleExecutor) Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error {
	// Rollback to previous replica count
	return nil
}

func (e *ScaleExecutor) Validate(action RemediationAction) error {
	if action.Parameters["target"] == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}

// RerouteExecutor handles traffic rerouting.
type RerouteExecutor struct{}

func (e *RerouteExecutor) Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error) {
	from := action.Parameters["from"]
	to := action.Parameters["to"]

	return &ActionResult{
		Success:   true,
		Message:   fmt.Sprintf("Rerouted traffic from %s to %s", from, to),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"from": from,
			"to":   to,
		},
		RollbackData: map[string]string{
			"original_route": from,
		},
	}, nil
}

func (e *RerouteExecutor) Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error {
	return nil
}

func (e *RerouteExecutor) Validate(action RemediationAction) error {
	if action.Parameters["from"] == "" || action.Parameters["to"] == "" {
		return fmt.Errorf("from and to are required")
	}
	return nil
}

// CircuitBreakerExecutor handles circuit breaker actions.
type CircuitBreakerExecutor struct{}

func (e *CircuitBreakerExecutor) Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error) {
	service := action.Parameters["service"]
	state := action.Parameters["state"]

	return &ActionResult{
		Success:   true,
		Message:   fmt.Sprintf("Circuit breaker for %s set to %s", service, state),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"service": service,
			"state":   state,
		},
	}, nil
}

func (e *CircuitBreakerExecutor) Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error {
	return nil
}

func (e *CircuitBreakerExecutor) Validate(action RemediationAction) error {
	if action.Parameters["service"] == "" {
		return fmt.Errorf("service is required")
	}
	return nil
}

// RateLimitExecutor handles rate limiting actions.
type RateLimitExecutor struct{}

func (e *RateLimitExecutor) Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error) {
	service := action.Parameters["service"]
	limit := action.Parameters["limit"]

	return &ActionResult{
		Success:   true,
		Message:   fmt.Sprintf("Rate limit for %s set to %s", service, limit),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"service": service,
			"limit":   limit,
		},
		RollbackData: map[string]string{
			"previous_limit": action.Parameters["current_limit"],
		},
	}, nil
}

func (e *RateLimitExecutor) Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error {
	return nil
}

func (e *RateLimitExecutor) Validate(action RemediationAction) error {
	if action.Parameters["service"] == "" {
		return fmt.Errorf("service is required")
	}
	return nil
}

// NotifyExecutor handles notification actions.
type NotifyExecutor struct{}

func (e *NotifyExecutor) Execute(ctx context.Context, action RemediationAction, incident *Incident) (*ActionResult, error) {
	channel := action.Parameters["channel"]
	message := action.Parameters["message"]

	return &ActionResult{
		Success:   true,
		Message:   fmt.Sprintf("Notification sent to %s: %s", channel, message),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"channel": channel,
		},
	}, nil
}

func (e *NotifyExecutor) Rollback(ctx context.Context, action RemediationAction, result *ActionResult) error {
	return nil // Notifications can't be rolled back
}

func (e *NotifyExecutor) Validate(action RemediationAction) error {
	if action.Parameters["channel"] == "" {
		return fmt.Errorf("channel is required")
	}
	return nil
}
