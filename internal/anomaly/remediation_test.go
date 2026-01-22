package anomaly

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRemediationEngine(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	rca := NewRootCauseAnalyzer(DefaultRootCauseConfig(), detector)
	config := DefaultRemediationConfig()
	engine := NewRemediationEngine(config, detector, rca)

	if engine == nil {
		t.Fatal("NewRemediationEngine returned nil")
	}
	if len(engine.executors) == 0 {
		t.Error("Default executors not registered")
	}
}

func TestDefaultRemediationConfig(t *testing.T) {
	config := DefaultRemediationConfig()

	if config.Enabled {
		t.Error("Auto-remediation should be disabled by default")
	}
	if !config.RequireApproval {
		t.Error("Approval should be required by default")
	}
	if config.ApprovalTimeout != 5*time.Minute {
		t.Errorf("ApprovalTimeout = %v, want 5m", config.ApprovalTimeout)
	}
	if config.SafetyThreshold != 0.8 {
		t.Errorf("SafetyThreshold = %f, want 0.8", config.SafetyThreshold)
	}
}

func TestRemediationEngine_RegisterAction(t *testing.T) {
	engine := createTestEngine()

	action := RemediationAction{
		ID:          "test-action",
		Name:        "Test Action",
		Type:        ActionTypeNotify,
		Severity:    ActionSeverityLow,
		Description: "Test notification",
		Parameters:  map[string]string{"channel": "test"},
	}

	engine.RegisterAction(action)

	engine.mu.RLock()
	_, exists := engine.actions[action.ID]
	engine.mu.RUnlock()

	if !exists {
		t.Error("Action not registered")
	}
}

func TestRemediationEngine_RegisterRunbook(t *testing.T) {
	engine := createTestEngine()

	runbook := &Runbook{
		ID:          "test-runbook",
		Name:        "Test Runbook",
		Description: "Test runbook description",
		Steps: []RunbookStep{
			{Order: 1, ActionID: "action-1"},
			{Order: 2, ActionID: "action-2"},
		},
	}

	engine.RegisterRunbook(runbook)

	engine.mu.RLock()
	_, exists := engine.runbooks[runbook.ID]
	engine.mu.RUnlock()

	if !exists {
		t.Error("Runbook not registered")
	}
}

func TestRemediationEngine_ProcessIncident_Disabled(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = false

	incident := createTestIncident()
	records := engine.ProcessIncident(context.Background(), incident)

	if records != nil {
		t.Error("Should not process incidents when disabled")
	}
}

func TestRemediationEngine_ProcessIncident_Enabled(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false

	// Register matching action
	action := RemediationAction{
		ID:       "notify-latency",
		Name:     "Notify on Latency",
		Type:     ActionTypeNotify,
		Severity: ActionSeverityLow,
		Parameters: map[string]string{
			"channel": "ops",
			"message": "High latency detected",
		},
		Conditions: []ActionCondition{
			{
				AnomalyType: AnomalyTypeLatency,
				Severity:    SeverityHigh,
			},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()
	records := engine.ProcessIncident(context.Background(), incident)

	if len(records) == 0 {
		t.Error("Should have processed and created records")
	}
}

func TestRemediationEngine_RequireApproval(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = true

	// Register high severity action
	action := RemediationAction{
		ID:       "scale-up",
		Name:     "Scale Up",
		Type:     ActionTypeScale,
		Severity: ActionSeverityHigh, // High severity requires approval
		Parameters: map[string]string{
			"target":   "api",
			"replicas": "10",
		},
		Conditions: []ActionCondition{
			{
				AnomalyType: AnomalyTypeLatency,
				Severity:    SeverityHigh,
			},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()
	engine.ProcessIncident(context.Background(), incident)

	approvals := engine.GetPendingApprovals()
	if len(approvals) == 0 {
		t.Error("High severity action should require approval")
	}
}

func TestRemediationEngine_ApproveAction(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = true

	action := RemediationAction{
		ID:       "scale-up",
		Name:     "Scale Up",
		Type:     ActionTypeScale,
		Severity: ActionSeverityHigh,
		Parameters: map[string]string{
			"target":   "api",
			"replicas": "10",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()
	engine.ProcessIncident(context.Background(), incident)

	approvals := engine.GetPendingApprovals()
	if len(approvals) == 0 {
		t.Fatal("No pending approvals")
	}

	err := engine.ApproveAction(context.Background(), approvals[0].ID, "admin")
	if err != nil {
		t.Errorf("ApproveAction failed: %v", err)
	}

	// Check that action was executed
	history := engine.GetHistory(10)
	var found bool
	for _, record := range history {
		if record.ApprovedBy == "admin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Approved action not found in history")
	}
}

func TestRemediationEngine_RejectAction(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = true

	action := RemediationAction{
		ID:       "scale-up",
		Name:     "Scale Up",
		Type:     ActionTypeScale,
		Severity: ActionSeverityCritical,
		Parameters: map[string]string{
			"target":   "api",
			"replicas": "10",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()
	engine.ProcessIncident(context.Background(), incident)

	approvals := engine.GetPendingApprovals()
	if len(approvals) == 0 {
		t.Fatal("No pending approvals")
	}

	err := engine.RejectAction(approvals[0].ID)
	if err != nil {
		t.Errorf("RejectAction failed: %v", err)
	}

	// Check that approval was removed
	approvals = engine.GetPendingApprovals()
	if len(approvals) != 0 {
		t.Error("Rejected approval should be removed")
	}
}

func TestRemediationEngine_Cooldown(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false
	engine.config.CooldownPeriod = time.Hour // Long cooldown

	action := RemediationAction{
		ID:       "notify",
		Name:     "Notify",
		Type:     ActionTypeNotify,
		Severity: ActionSeverityLow,
		Parameters: map[string]string{
			"channel": "ops",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()

	// First execution
	records1 := engine.ProcessIncident(context.Background(), incident)
	if len(records1) == 0 {
		t.Fatal("First execution should succeed")
	}

	// Second execution should be blocked by cooldown
	records2 := engine.ProcessIncident(context.Background(), incident)
	if len(records2) != 0 {
		t.Error("Second execution should be blocked by cooldown")
	}
}

func TestRemediationEngine_MaxActionAttempts(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false
	engine.config.CooldownPeriod = 0 // No cooldown
	engine.config.MaxActionAttempts = 2

	action := RemediationAction{
		ID:       "notify",
		Name:     "Notify",
		Type:     ActionTypeNotify,
		Severity: ActionSeverityLow,
		Parameters: map[string]string{
			"channel": "ops",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()

	// Execute max times
	for i := 0; i < 2; i++ {
		engine.ProcessIncident(context.Background(), incident)
	}

	// Should be blocked
	records := engine.ProcessIncident(context.Background(), incident)
	if len(records) != 0 {
		t.Error("Should be blocked after max attempts")
	}
}

func TestRemediationEngine_RunbookExecution(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false

	// Register actions for runbook
	engine.RegisterAction(RemediationAction{
		ID:         "notify",
		Name:       "Notify",
		Type:       ActionTypeNotify,
		Severity:   ActionSeverityLow,
		Parameters: map[string]string{"channel": "ops"},
	})

	engine.RegisterAction(RemediationAction{
		ID:         "rate-limit",
		Name:       "Rate Limit",
		Type:       ActionTypeRateLimit,
		Severity:   ActionSeverityMedium,
		Parameters: map[string]string{"service": "api", "limit": "100"},
	})

	runbook := &Runbook{
		ID:   "incident-response",
		Name: "Incident Response",
		Triggers: []ActionCondition{
			{AnomalyType: AnomalyTypeError, Severity: SeverityHigh},
		},
		Steps: []RunbookStep{
			{Order: 1, ActionID: "notify"},
			{Order: 2, ActionID: "rate-limit"},
		},
		OnFailure: FailurePolicyStop,
	}
	engine.RegisterRunbook(runbook)

	// Create incident that triggers runbook
	incident := &Incident{
		ID:        generateID(),
		Status:    IncidentStatusActive,
		StartTime: time.Now(),
		Alerts: []Alert{
			{
				Type:     AnomalyTypeError,
				Severity: SeverityHigh,
				Route:    "api",
			},
		},
		Impact: &ImpactAnalysis{ServiceImpact: make(map[string]float64)},
	}

	records := engine.ProcessIncident(context.Background(), incident)

	if len(records) == 0 {
		t.Error("Runbook should have been executed")
	}
}

func TestRemediationEngine_RollbackAction(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false

	action := RemediationAction{
		ID:         "scale-up",
		Name:       "Scale Up",
		Type:       ActionTypeScale,
		Severity:   ActionSeverityLow,
		Reversible: true,
		Parameters: map[string]string{
			"target":           "api",
			"replicas":         "10",
			"current_replicas": "5",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()
	records := engine.ProcessIncident(context.Background(), incident)

	if len(records) == 0 {
		t.Fatal("No records created")
	}

	err := engine.RollbackAction(context.Background(), records[0].ID)
	if err != nil {
		t.Errorf("RollbackAction failed: %v", err)
	}

	// Verify rollback
	history := engine.GetHistory(10)
	for _, record := range history {
		if record.ID == records[0].ID {
			if !record.RolledBack {
				t.Error("Action should be marked as rolled back")
			}
			if record.Status != RemediationStatusRolledBack {
				t.Errorf("Status = %s, want rolled_back", record.Status)
			}
			break
		}
	}
}

func TestScaleExecutor(t *testing.T) {
	executor := &ScaleExecutor{}

	action := RemediationAction{
		Parameters: map[string]string{
			"target":   "api",
			"replicas": "10",
		},
	}

	// Validate
	if err := executor.Validate(action); err != nil {
		t.Errorf("Validate failed: %v", err)
	}

	// Execute
	result, err := executor.Execute(context.Background(), action, nil)
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Execute should succeed")
	}

	// Validate without target
	action.Parameters = map[string]string{}
	if err := executor.Validate(action); err == nil {
		t.Error("Validate should fail without target")
	}
}

func TestCircuitBreakerExecutor(t *testing.T) {
	executor := &CircuitBreakerExecutor{}

	action := RemediationAction{
		Parameters: map[string]string{
			"service": "api",
			"state":   "open",
		},
	}

	result, err := executor.Execute(context.Background(), action, nil)
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Execute should succeed")
	}
}

func TestRateLimitExecutor(t *testing.T) {
	executor := &RateLimitExecutor{}

	action := RemediationAction{
		Parameters: map[string]string{
			"service": "api",
			"limit":   "100",
		},
	}

	result, err := executor.Execute(context.Background(), action, nil)
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Execute should succeed")
	}
}

func TestNotifyExecutor(t *testing.T) {
	executor := &NotifyExecutor{}

	action := RemediationAction{
		Parameters: map[string]string{
			"channel": "slack",
			"message": "Alert!",
		},
	}

	result, err := executor.Execute(context.Background(), action, nil)
	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
	if !result.Success {
		t.Error("Execute should succeed")
	}
}

func TestRemediationEngine_APIHandler_Approvals(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = true

	// Add pending approval
	engine.pending = append(engine.pending, &PendingApproval{
		ID:        "test-approval",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	handler := engine.APIHandler()

	req := httptest.NewRequest(http.MethodGet, "/approvals", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /approvals status = %d, want 200", rec.Code)
	}

	var approvals []*PendingApproval
	if err := json.NewDecoder(rec.Body).Decode(&approvals); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(approvals) != 1 {
		t.Errorf("Expected 1 approval, got %d", len(approvals))
	}
}

func TestRemediationEngine_APIHandler_History(t *testing.T) {
	engine := createTestEngine()

	// Add history record
	engine.history = append(engine.history, &RemediationRecord{
		ID:        "test-record",
		Status:    RemediationStatusSuccess,
		Timestamp: time.Now(),
	})

	handler := engine.APIHandler()

	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /history status = %d, want 200", rec.Code)
	}
}

func TestRemediationEngine_APIHandler_Actions(t *testing.T) {
	engine := createTestEngine()
	handler := engine.APIHandler()

	// Test POST /actions
	body := `{"id":"test","name":"Test","type":"notify","severity":"low","parameters":{"channel":"test"}}`
	req := httptest.NewRequest(http.MethodPost, "/actions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("POST /actions status = %d, want 201", rec.Code)
	}

	// Test GET /actions
	req = httptest.NewRequest(http.MethodGet, "/actions", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /actions status = %d, want 200", rec.Code)
	}
}

func TestRemediationEngine_APIHandler_Runbooks(t *testing.T) {
	engine := createTestEngine()
	handler := engine.APIHandler()

	// Test POST /runbooks
	body := `{"id":"test","name":"Test Runbook","steps":[]}`
	req := httptest.NewRequest(http.MethodPost, "/runbooks", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("POST /runbooks status = %d, want 201", rec.Code)
	}

	// Test GET /runbooks
	req = httptest.NewRequest(http.MethodGet, "/runbooks", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /runbooks status = %d, want 200", rec.Code)
	}
}

func TestRemediationEngine_SafetyThreshold(t *testing.T) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false
	engine.config.SafetyThreshold = 0.9 // High threshold

	action := RemediationAction{
		ID:       "scale-up",
		Name:     "Scale Up",
		Type:     ActionTypeScale,
		Severity: ActionSeverityLow, // Low severity normally doesn't require approval
		Parameters: map[string]string{
			"target":   "api",
			"replicas": "10",
		},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	// Create incident with low confidence root cause
	incident := &Incident{
		ID:        generateID(),
		Status:    IncidentStatusActive,
		StartTime: time.Now(),
		RootCauses: []*RootCause{
			{Service: "api", Confidence: 0.5}, // Below threshold
		},
		Alerts: []Alert{
			{Type: AnomalyTypeLatency, Severity: SeverityHigh},
		},
		Impact: &ImpactAnalysis{ServiceImpact: make(map[string]float64)},
	}

	engine.ProcessIncident(context.Background(), incident)

	// Should require approval due to low confidence
	approvals := engine.GetPendingApprovals()
	if len(approvals) == 0 {
		t.Error("Low confidence should trigger approval requirement")
	}
}

// Helper functions

func createTestEngine() *RemediationEngine {
	detector := New(DefaultDetectorConfig())
	rca := NewRootCauseAnalyzer(DefaultRootCauseConfig(), detector)
	config := DefaultRemediationConfig()
	return NewRemediationEngine(config, detector, rca)
}

func createTestIncident() *Incident {
	return &Incident{
		ID:        generateID(),
		Status:    IncidentStatusActive,
		StartTime: time.Now(),
		Severity:  SeverityHigh,
		RootCauses: []*RootCause{
			{Service: "api", Confidence: 0.9},
		},
		Alerts: []Alert{
			{
				ID:        "alert-1",
				Type:      AnomalyTypeLatency,
				Severity:  SeverityHigh,
				Route:     "api",
				Timestamp: time.Now(),
			},
		},
		Impact: &ImpactAnalysis{ServiceImpact: make(map[string]float64)},
	}
}

func BenchmarkRemediationEngine_ProcessIncident(b *testing.B) {
	engine := createTestEngine()
	engine.config.Enabled = true
	engine.config.RequireApproval = false
	engine.config.CooldownPeriod = 0

	action := RemediationAction{
		ID:         "notify",
		Name:       "Notify",
		Type:       ActionTypeNotify,
		Severity:   ActionSeverityLow,
		Parameters: map[string]string{"channel": "ops"},
		Conditions: []ActionCondition{
			{AnomalyType: AnomalyTypeLatency},
		},
	}
	engine.RegisterAction(action)

	incident := createTestIncident()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		incident.ID = generateID() // New ID to avoid max attempts
		engine.ProcessIncident(context.Background(), incident)
	}
}
