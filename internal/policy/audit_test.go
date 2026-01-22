package policy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuditLogger_Log(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	ctx := context.Background()
	input := &Input{
		Request: RequestInput{
			Method: "GET",
			Path:   "/api/users",
		},
		User: &UserInput{
			ID:       "user-123",
			Username: "testuser",
			Roles:    []string{"admin"},
		},
	}
	decision := &Decision{
		Allowed: true,
		Reason:  "policy allowed",
	}

	al.Log(ctx, "test-policy", input, decision, 5*time.Millisecond)

	// Wait for async processing
	time.Sleep(100 * time.Millisecond)

	// Query entries
	entries := al.Query(AuditFilter{PolicyID: "test-policy"})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.PolicyID != "test-policy" {
		t.Errorf("expected policy ID 'test-policy', got %s", entry.PolicyID)
	}
	if !entry.Decision.Allowed {
		t.Error("expected allowed decision")
	}
	if entry.Input == nil {
		t.Fatal("expected input to be included")
	}
	if entry.Input.UserID != "user-123" {
		t.Errorf("expected user ID 'user-123', got %s", entry.Input.UserID)
	}
}

func TestAuditLogger_LogWithVersion(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	ctx := context.Background()
	decision := &Decision{Allowed: true}

	al.LogWithVersion(ctx, "policy", 5, nil, decision, time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].PolicyVersion != 5 {
		t.Errorf("expected version 5, got %d", entries[0].PolicyVersion)
	}
}

func TestAuditLogger_RequestID(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	ctx := WithRequestID(context.Background(), "req-abc-123")
	decision := &Decision{Allowed: true}

	al.Log(ctx, "policy", nil, decision, time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].RequestID != "req-abc-123" {
		t.Errorf("expected request ID 'req-abc-123', got %s", entries[0].RequestID)
	}
}

func TestAuditLogger_LevelNone(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelNone,
		MaxEntries: 100,
	})
	defer al.Stop()

	ctx := context.Background()
	decision := &Decision{Allowed: true}

	al.Log(ctx, "policy", nil, decision, time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries when level is none, got %d", len(entries))
	}
}

func TestAuditLogger_Hooks(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	var mu sync.Mutex
	var hookedEntries []*AuditEntry

	al.AddHook(func(entry *AuditEntry) {
		mu.Lock()
		hookedEntries = append(hookedEntries, entry)
		mu.Unlock()
	})

	ctx := context.Background()
	al.Log(ctx, "policy", nil, &Decision{Allowed: true}, time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(hookedEntries)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 hooked entry, got %d", count)
	}
}

func TestAuditLogger_Query(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	ctx := context.Background()

	// Log several entries
	for i := 0; i < 5; i++ {
		input := &Input{
			Request: RequestInput{Method: "GET", Path: "/api/users"},
			User:    &UserInput{ID: "user-1"},
		}
		al.Log(ctx, "policy-a", input, &Decision{Allowed: true}, time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		input := &Input{
			Request: RequestInput{Method: "POST", Path: "/api/admin"},
			User:    &UserInput{ID: "user-2"},
		}
		al.Log(ctx, "policy-b", input, &Decision{Allowed: false}, time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	// Filter by policy
	entries := al.Query(AuditFilter{PolicyID: "policy-a"})
	if len(entries) != 5 {
		t.Errorf("expected 5 entries for policy-a, got %d", len(entries))
	}

	// Filter by user
	entries = al.Query(AuditFilter{UserID: "user-2"})
	if len(entries) != 3 {
		t.Errorf("expected 3 entries for user-2, got %d", len(entries))
	}

	// Filter by allowed
	allowed := true
	entries = al.Query(AuditFilter{Allowed: &allowed})
	if len(entries) != 5 {
		t.Errorf("expected 5 allowed entries, got %d", len(entries))
	}

	denied := false
	entries = al.Query(AuditFilter{Allowed: &denied})
	if len(entries) != 3 {
		t.Errorf("expected 3 denied entries, got %d", len(entries))
	}

	// Filter with limit
	entries = al.Query(AuditFilter{Limit: 3})
	if len(entries) != 3 {
		t.Errorf("expected 3 entries with limit, got %d", len(entries))
	}
}

func TestAuditLogger_Stats(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	ctx := context.Background()

	// Log entries
	for i := 0; i < 10; i++ {
		input := &Input{
			Request: RequestInput{Method: "GET", Path: "/api/users"},
			User:    &UserInput{ID: "user-1"},
		}
		al.Log(ctx, "policy-a", input, &Decision{Allowed: true}, time.Duration(i+1)*time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		input := &Input{
			Request: RequestInput{Method: "POST", Path: "/api/admin"},
			User:    &UserInput{ID: "user-2"},
		}
		al.Log(ctx, "policy-b", input, &Decision{Allowed: false}, time.Duration(i+1)*time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	stats := al.Stats(AuditFilter{})

	if stats.TotalDecisions != 15 {
		t.Errorf("expected 15 total decisions, got %d", stats.TotalDecisions)
	}
	if stats.AllowedDecisions != 10 {
		t.Errorf("expected 10 allowed decisions, got %d", stats.AllowedDecisions)
	}
	if stats.DeniedDecisions != 5 {
		t.Errorf("expected 5 denied decisions, got %d", stats.DeniedDecisions)
	}
	if stats.ByPolicy["policy-a"] != 10 {
		t.Errorf("expected 10 for policy-a, got %d", stats.ByPolicy["policy-a"])
	}
	if stats.ByUser["user-1"] != 10 {
		t.Errorf("expected 10 for user-1, got %d", stats.ByUser["user-1"])
	}
	if stats.AverageLatency <= 0 {
		t.Error("expected positive average latency")
	}
}

func TestAuditLogger_MaxEntries(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 5,
	})
	defer al.Stop()

	ctx := context.Background()

	// Log more than max
	for i := 0; i < 10; i++ {
		al.Log(ctx, "policy", nil, &Decision{Allowed: true}, time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	entries := al.Query(AuditFilter{})
	if len(entries) > 5 {
		t.Errorf("expected max 5 entries, got %d", len(entries))
	}
}

func TestAuditLogger_Persistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	al := NewAuditLogger(AuditLoggerConfig{
		Level:         AuditLevelBasic,
		MaxEntries:    100,
		StorageDir:    tempDir,
		FlushInterval: 100 * time.Millisecond,
	})

	ctx := context.Background()
	al.Log(ctx, "policy", nil, &Decision{Allowed: true}, time.Millisecond)

	// Wait for flush
	time.Sleep(300 * time.Millisecond)

	al.Stop()

	// Check files were created
	matches, err := filepath.Glob(filepath.Join(tempDir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) == 0 {
		t.Error("expected audit files to be created")
	}
}

func TestAuditLogger_GetEntry(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	ctx := context.Background()
	al.Log(ctx, "policy", nil, &Decision{Allowed: true}, time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Get by ID
	entry := al.GetEntry(entries[0].ID)
	if entry == nil {
		t.Fatal("expected to find entry by ID")
	}
	if entry.ID != entries[0].ID {
		t.Errorf("ID mismatch")
	}

	// Non-existent ID
	entry = al.GetEntry("non-existent")
	if entry != nil {
		t.Error("expected nil for non-existent ID")
	}
}

func TestAuditLogger_LogPolicyChange(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	event := PolicyChangeEvent{
		Type:      PolicyChangeCreated,
		PolicyID:  "new-policy",
		Version:   1,
		Timestamp: time.Now(),
	}
	al.LogPolicyChange(event, "admin@example.com")

	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{PolicyID: "new-policy"})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Source != "policy_change" {
		t.Errorf("expected source 'policy_change', got %s", entries[0].Source)
	}
	if entries[0].Labels["change_type"] != "created" {
		t.Errorf("expected change_type 'created', got %s", entries[0].Labels["change_type"])
	}
	if entries[0].Labels["actor"] != "admin@example.com" {
		t.Errorf("expected actor 'admin@example.com', got %s", entries[0].Labels["actor"])
	}
}

func TestFileAuditWriter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-writer-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "audit.jsonl")
	writer, err := NewFileAuditWriter(path)
	if err != nil {
		t.Fatalf("NewFileAuditWriter failed: %v", err)
	}
	defer writer.Close()

	entry := &AuditEntry{
		ID:        "test-1",
		Timestamp: time.Now(),
		PolicyID:  "policy",
		Decision:  &Decision{Allowed: true},
	}

	if err := writer.Write(entry); err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Errorf("Flush failed: %v", err)
	}

	// Verify file contents
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected file to have content")
	}
}

func TestAuditFilter_Matches(t *testing.T) {
	entry := &AuditEntry{
		Timestamp: time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC),
		PolicyID:  "policy-a",
		Decision:  &Decision{Allowed: true},
		Input: &AuditInput{
			UserID: "user-1",
			Method: "GET",
			Path:   "/api/users",
		},
	}

	tests := []struct {
		name   string
		filter AuditFilter
		match  bool
	}{
		{
			name:   "empty filter matches all",
			filter: AuditFilter{},
			match:  true,
		},
		{
			name:   "policy match",
			filter: AuditFilter{PolicyID: "policy-a"},
			match:  true,
		},
		{
			name:   "policy no match",
			filter: AuditFilter{PolicyID: "policy-b"},
			match:  false,
		},
		{
			name:   "user match",
			filter: AuditFilter{UserID: "user-1"},
			match:  true,
		},
		{
			name:   "time range match",
			filter: AuditFilter{
				StartTime: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
				EndTime:   time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC),
			},
			match: true,
		},
		{
			name:   "time range no match",
			filter: AuditFilter{
				StartTime: time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC),
			},
			match: false,
		},
		{
			name:   "allowed match",
			filter: AuditFilter{Allowed: boolPtr(true)},
			match:  true,
		},
		{
			name:   "allowed no match",
			filter: AuditFilter{Allowed: boolPtr(false)},
			match:  false,
		},
		{
			name:   "method match",
			filter: AuditFilter{Method: "GET"},
			match:  true,
		},
		{
			name:   "path match",
			filter: AuditFilter{Path: "/api/users"},
			match:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Matches(entry); got != tt.match {
				t.Errorf("Matches() = %v, want %v", got, tt.match)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestComplianceReporter_GenerateReport(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()
	store.Create(ctx, "policy-a", PolicyTypeCEL, "true", PolicyMetadata{})
	store.Create(ctx, "policy-b", PolicyTypeCEL, "false", PolicyMetadata{})

	// Log some entries
	for i := 0; i < 10; i++ {
		input := &Input{
			Request: RequestInput{Method: "GET"},
			User:    &UserInput{ID: "user-1"},
		}
		al.Log(ctx, "policy-a", input, &Decision{Allowed: true}, time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		input := &Input{
			Request: RequestInput{Method: "POST"},
			User:    &UserInput{ID: "user-2"},
		}
		al.Log(ctx, "policy-b", input, &Decision{Allowed: false}, time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	reporter := NewComplianceReporter(al, store, nil)

	start := time.Now().Add(-time.Hour)
	end := time.Now().Add(time.Hour)
	report := reporter.GenerateReport(start, end)

	if report.Summary.TotalRequests != 15 {
		t.Errorf("expected 15 total requests, got %d", report.Summary.TotalRequests)
	}

	expectedComplianceRate := float64(10) / float64(15) * 100
	if report.Summary.ComplianceRate != expectedComplianceRate {
		t.Errorf("expected compliance rate %.2f, got %.2f", expectedComplianceRate, report.Summary.ComplianceRate)
	}

	if len(report.PolicyStats) != 2 {
		t.Errorf("expected 2 policy stats, got %d", len(report.PolicyStats))
	}

	if report.ViolationSummary.TotalViolations != 5 {
		t.Errorf("expected 5 violations, got %d", report.ViolationSummary.TotalViolations)
	}
}

func TestComplianceReporter_ExportReport(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:      AuditLevelBasic,
		MaxEntries: 100,
	})
	defer al.Stop()

	reporter := NewComplianceReporter(al, nil, nil)

	report := &ComplianceReport{
		GeneratedAt: time.Now(),
		Summary: ComplianceSummary{
			TotalRequests:  100,
			ComplianceRate: 95.0,
		},
	}

	// Export as JSON
	data, err := reporter.ExportReport(report, "json")
	if err != nil {
		t.Fatalf("ExportReport failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON export")
	}

	// Unsupported format
	_, err = reporter.ExportReport(report, "csv")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestComplianceReporter_Recommendations(t *testing.T) {
	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()
	store.Create(ctx, "policy-a", PolicyTypeCEL, "true", PolicyMetadata{})

	// Log many denied requests to trigger recommendations
	for i := 0; i < 100; i++ {
		input := &Input{
			Request: RequestInput{Method: "POST"},
			User:    &UserInput{ID: "violator-user"},
		}
		al.Log(ctx, "policy-a", input, &Decision{Allowed: false}, 20*time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	reporter := NewComplianceReporter(al, store, nil)
	report := reporter.GenerateReport(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	// Should have recommendations due to high denial rate and frequent violator
	if len(report.Recommendations) == 0 {
		t.Error("expected recommendations to be generated")
	}

	// Check for high denial rate recommendation
	hasHighDenial := false
	for _, rec := range report.Recommendations {
		if contains(rec, "denial rate") {
			hasHighDenial = true
			break
		}
	}
	if !hasHighDenial {
		t.Error("expected high denial rate recommendation")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestAuditedEngine(t *testing.T) {
	// Create local evaluator
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("allow_all", func(ctx context.Context, input *Input) (*Decision, error) {
		return &Decision{Allowed: true, Reason: "allowed"}, nil
	})

	engine := NewEngine(local, EngineConfig{
		DefaultPolicy: "allow_all",
	})

	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()
	store.Create(ctx, "allow_all", PolicyTypeLocal, "allow all", PolicyMetadata{})

	al := NewAuditLogger(AuditLoggerConfig{
		Level:        AuditLevelBasic,
		MaxEntries:   100,
		IncludeInput: true,
	})
	defer al.Stop()

	auditedEngine := NewAuditedEngine(engine, al, store)

	input := &Input{
		Request: RequestInput{Method: "GET", Path: "/test"},
	}

	decision, err := auditedEngine.Evaluate(ctx, "allow_all", input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected allowed decision")
	}

	// Wait for audit
	time.Sleep(100 * time.Millisecond)

	entries := al.Query(AuditFilter{PolicyID: "allow_all"})
	if len(entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(entries))
	}

	if entries[0].PolicyVersion != 1 {
		t.Errorf("expected version 1, got %d", entries[0].PolicyVersion)
	}
}
