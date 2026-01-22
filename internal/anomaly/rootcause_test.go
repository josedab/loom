package anomaly

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRootCauseAnalyzer(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	if rca == nil {
		t.Fatal("NewRootCauseAnalyzer returned nil")
	}
	if rca.dependencies == nil {
		t.Error("Dependencies graph not initialized")
	}
}

func TestDefaultRootCauseConfig(t *testing.T) {
	config := DefaultRootCauseConfig()

	if config.CorrelationWindow != 5*time.Minute {
		t.Errorf("CorrelationWindow = %v, want 5m", config.CorrelationWindow)
	}
	if config.CascadeThreshold != 0.7 {
		t.Errorf("CascadeThreshold = %f, want 0.7", config.CascadeThreshold)
	}
	if config.MaxIncidents != 100 {
		t.Errorf("MaxIncidents = %d, want 100", config.MaxIncidents)
	}
}

func TestDependencyGraph_AddService(t *testing.T) {
	graph := NewDependencyGraph()

	graph.AddService("api-gateway", ServiceTypeAPI, CriticalityHigh)
	graph.AddService("database", ServiceTypeDatabase, CriticalityHigh)

	services := graph.GetAllServices()
	if len(services) != 2 {
		t.Errorf("Expected 2 services, got %d", len(services))
	}

	api := graph.GetService("api-gateway")
	if api == nil {
		t.Fatal("api-gateway service not found")
	}
	if api.Type != ServiceTypeAPI {
		t.Errorf("api-gateway type = %s, want api", api.Type)
	}
	if api.Criticality != CriticalityHigh {
		t.Errorf("api-gateway criticality = %s, want high", api.Criticality)
	}
}

func TestDependencyGraph_AddDependency(t *testing.T) {
	graph := NewDependencyGraph()

	graph.AddDependency("api", "database", 10*time.Millisecond)
	graph.AddDependency("api", "cache", 5*time.Millisecond)
	graph.AddDependency("api", "database", 15*time.Millisecond) // Update existing

	deps := graph.GetDependencies("api")
	if len(deps) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(deps))
	}

	// Check that database dependency was updated
	var dbDep *DependencyEdge
	for _, dep := range deps {
		if dep.To == "database" {
			dbDep = dep
			break
		}
	}
	if dbDep == nil {
		t.Fatal("database dependency not found")
	}
	if dbDep.Weight != 2 {
		t.Errorf("database dependency weight = %f, want 2", dbDep.Weight)
	}
}

func TestDependencyGraph_GetDependents(t *testing.T) {
	graph := NewDependencyGraph()

	graph.AddDependency("api", "database", 10*time.Millisecond)
	graph.AddDependency("worker", "database", 20*time.Millisecond)
	graph.AddDependency("scheduler", "database", 15*time.Millisecond)

	dependents := graph.GetDependents("database")
	if len(dependents) != 3 {
		t.Errorf("Expected 3 dependents, got %d", len(dependents))
	}
}

func TestDependencyGraph_RecordError(t *testing.T) {
	graph := NewDependencyGraph()

	graph.AddDependency("api", "database", 10*time.Millisecond)
	graph.RecordError("api", "database")
	graph.RecordError("api", "database")

	deps := graph.GetDependencies("api")
	for _, dep := range deps {
		if dep.To == "database" {
			if dep.ErrorRate <= 0 {
				t.Error("ErrorRate should be > 0 after recording errors")
			}
			return
		}
	}
	t.Error("database dependency not found")
}

func TestDependencyGraph_UpdateHealth(t *testing.T) {
	graph := NewDependencyGraph()
	graph.AddService("api", ServiceTypeAPI, CriticalityHigh)

	graph.UpdateHealth("api", HealthStatusDegraded)

	service := graph.GetService("api")
	if service.HealthStatus != HealthStatusDegraded {
		t.Errorf("HealthStatus = %s, want degraded", service.HealthStatus)
	}
}

func TestDependencyGraph_Export(t *testing.T) {
	graph := NewDependencyGraph()
	graph.AddService("api", ServiceTypeAPI, CriticalityHigh)
	graph.AddService("database", ServiceTypeDatabase, CriticalityHigh)
	graph.AddDependency("api", "database", 10*time.Millisecond)

	dot := graph.Export()

	if !strings.Contains(dot, "digraph dependencies") {
		t.Error("Export should contain digraph declaration")
	}
	if !strings.Contains(dot, "api") {
		t.Error("Export should contain api node")
	}
	if !strings.Contains(dot, "database") {
		t.Error("Export should contain database node")
	}
	if !strings.Contains(dot, "->") {
		t.Error("Export should contain edge")
	}
}

func TestRootCauseAnalyzer_Analyze(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	// Add service dependencies
	rca.dependencies.AddDependency("api", "database", 10*time.Millisecond)
	rca.dependencies.AddDependency("api", "cache", 5*time.Millisecond)

	// Create an alert
	alert := Alert{
		ID:          "test-1",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityHigh,
		Route:       "api",
		Description: "High latency detected",
		Value:       500,
		Expected:    100,
		Timestamp:   time.Now(),
	}

	incident := rca.Analyze(alert)

	if incident == nil {
		t.Fatal("Analyze returned nil")
	}
	if incident.Status != IncidentStatusActive {
		t.Errorf("Incident status = %s, want active", incident.Status)
	}
	if len(incident.Alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(incident.Alerts))
	}
	if len(incident.Timeline) == 0 {
		t.Error("Timeline should not be empty")
	}
}

func TestRootCauseAnalyzer_CorrelatedAlerts(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	now := time.Now()

	// First alert
	alert1 := Alert{
		ID:          "test-1",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityHigh,
		Route:       "api",
		Description: "High latency",
		Timestamp:   now,
	}

	// Second alert (correlated by time and same route)
	alert2 := Alert{
		ID:          "test-2",
		Type:        AnomalyTypeError,
		Severity:    SeverityHigh,
		Route:       "api",
		Description: "High error rate",
		Timestamp:   now.Add(time.Minute),
	}

	incident1 := rca.Analyze(alert1)
	incident2 := rca.Analyze(alert2)

	// Should be same incident
	if incident1.ID != incident2.ID {
		t.Error("Correlated alerts should be in same incident")
	}
	if len(incident2.Alerts) != 2 {
		t.Errorf("Expected 2 alerts in incident, got %d", len(incident2.Alerts))
	}
}

func TestRootCauseAnalyzer_CascadeDetection(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	// Set up dependency chain: frontend -> api -> database
	rca.dependencies.AddDependency("frontend", "api", 50*time.Millisecond)
	rca.dependencies.AddDependency("api", "database", 10*time.Millisecond)

	now := time.Now()

	// Database fails first (root cause)
	rca.Analyze(Alert{
		ID:          "db-1",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityCritical,
		Route:       "database",
		Description: "Database slow",
		Timestamp:   now,
	})

	// API fails next (cascade)
	rca.Analyze(Alert{
		ID:          "api-1",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityHigh,
		Route:       "api",
		Description: "API slow",
		Timestamp:   now.Add(30 * time.Second),
	})

	// Frontend fails last (cascade continues)
	incident := rca.Analyze(Alert{
		ID:          "fe-1",
		Type:        AnomalyTypeLatency,
		Severity:    SeverityMedium,
		Route:       "frontend",
		Description: "Frontend slow",
		Timestamp:   now.Add(time.Minute),
	})

	if incident.Impact.CascadeDepth == 0 {
		t.Error("Cascade depth should be > 0")
	}
	if len(incident.AffectedSvcs) < 3 {
		t.Errorf("Expected at least 3 affected services, got %d", len(incident.AffectedSvcs))
	}
}

func TestRootCauseAnalyzer_RootCauseIdentification(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	now := time.Now()

	// Root cause (first alert)
	rca.Analyze(Alert{
		ID:          "root-1",
		Type:        AnomalyTypeError,
		Severity:    SeverityCritical,
		Route:       "database",
		Description: "Database connection failed",
		Timestamp:   now,
	})

	// Dependent service failures
	rca.Analyze(Alert{
		ID:          "dep-1",
		Type:        AnomalyTypeError,
		Severity:    SeverityHigh,
		Route:       "api",
		Description: "API errors",
		Timestamp:   now.Add(10 * time.Second),
	})

	incidents := rca.GetActiveIncidents()
	if len(incidents) == 0 {
		t.Fatal("No active incidents")
	}

	incident := incidents[0]
	if len(incident.RootCauses) == 0 {
		t.Fatal("No root causes identified")
	}

	// Database should be identified as root cause
	rootCause := incident.RootCauses[0]
	if rootCause.Service != "database" {
		t.Errorf("Root cause service = %s, want database", rootCause.Service)
	}
	if rootCause.Confidence <= 0 {
		t.Error("Root cause confidence should be > 0")
	}
}

func TestRootCauseAnalyzer_GetActiveIncidents(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	// No incidents initially
	incidents := rca.GetActiveIncidents()
	if len(incidents) != 0 {
		t.Errorf("Expected 0 incidents, got %d", len(incidents))
	}

	// Create incident
	rca.Analyze(Alert{
		ID:        "test-1",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityHigh,
		Route:     "api",
		Timestamp: time.Now(),
	})

	incidents = rca.GetActiveIncidents()
	if len(incidents) != 1 {
		t.Errorf("Expected 1 incident, got %d", len(incidents))
	}
}

func TestRootCauseAnalyzer_GetIncident(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	incident := rca.Analyze(Alert{
		ID:        "test-1",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityHigh,
		Route:     "api",
		Timestamp: time.Now(),
	})

	found := rca.GetIncident(incident.ID)
	if found == nil {
		t.Error("GetIncident returned nil")
	}
	if found.ID != incident.ID {
		t.Error("GetIncident returned wrong incident")
	}

	notFound := rca.GetIncident("nonexistent")
	if notFound != nil {
		t.Error("GetIncident should return nil for nonexistent ID")
	}
}

func TestRootCauseAnalyzer_ResolveIncident(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	incident := rca.Analyze(Alert{
		ID:        "test-1",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityHigh,
		Route:     "api",
		Timestamp: time.Now(),
	})

	rca.ResolveIncident(incident.ID)

	resolved := rca.GetIncident(incident.ID)
	if resolved.Status != IncidentStatusResolved {
		t.Errorf("Incident status = %s, want resolved", resolved.Status)
	}
	if resolved.EndTime == nil {
		t.Error("EndTime should be set")
	}
}

func TestImpactAnalysis(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	// Set up dependency so alerts are correlated
	rca.dependencies.AddDependency("api", "worker", 10*time.Millisecond)

	now := time.Now()

	// Multiple alerts with different severities - same type so they correlate
	rca.Analyze(Alert{
		ID:        "alert-1",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityCritical,
		Route:     "api",
		Value:     500,
		Expected:  100,
		Timestamp: now,
	})

	rca.Analyze(Alert{
		ID:        "alert-2",
		Type:      AnomalyTypeLatency, // Same type for correlation
		Severity:  SeverityHigh,
		Route:     "worker",
		Value:     250,
		Expected:  50,
		Deviation: 5,
		Timestamp: now.Add(time.Second),
	})

	incidents := rca.GetActiveIncidents()
	if len(incidents) == 0 {
		t.Fatal("No incidents")
	}

	impact := incidents[0].Impact
	if impact.TotalAffectedServices < 1 {
		t.Errorf("TotalAffectedServices = %d, want >= 1", impact.TotalAffectedServices)
	}
	if len(impact.ServiceImpact) == 0 {
		t.Error("ServiceImpact should not be empty")
	}
}

func TestRootCauseAnalyzer_APIHandler_Incidents(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	// Create incident
	rca.Analyze(Alert{
		ID:        "test-1",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityHigh,
		Route:     "api",
		Timestamp: time.Now(),
	})

	handler := rca.APIHandler()

	// Test GET /incidents
	req := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /incidents status = %d, want 200", rec.Code)
	}

	var incidents []*Incident
	if err := json.NewDecoder(rec.Body).Decode(&incidents); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(incidents) != 1 {
		t.Errorf("Expected 1 incident, got %d", len(incidents))
	}
}

func TestRootCauseAnalyzer_APIHandler_Dependencies(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	rca.dependencies.AddService("api", ServiceTypeAPI, CriticalityHigh)

	handler := rca.APIHandler()

	// Test GET /dependencies
	req := httptest.NewRequest(http.MethodGet, "/dependencies", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /dependencies status = %d, want 200", rec.Code)
	}

	// Test GET /dependencies?format=dot
	req = httptest.NewRequest(http.MethodGet, "/dependencies?format=dot", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /dependencies?format=dot status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "digraph") {
		t.Error("DOT format should contain digraph")
	}
}

func TestRootCauseAnalyzer_APIHandler_AddService(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	handler := rca.APIHandler()

	body := `{"name":"test-service","type":"api","criticality":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/services", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("POST /services status = %d, want 201", rec.Code)
	}

	service := rca.dependencies.GetService("test-service")
	if service == nil {
		t.Error("Service not created")
	}
}

func TestRootCauseAnalyzer_APIHandler_AddDependency(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	handler := rca.APIHandler()

	body := `{"from":"api","to":"database","latency_ms":10}`
	req := httptest.NewRequest(http.MethodPost, "/dependencies/add", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("POST /dependencies/add status = %d, want 201", rec.Code)
	}

	deps := rca.dependencies.GetDependencies("api")
	if len(deps) == 0 {
		t.Error("Dependency not created")
	}
}

func TestCalculateOverallSeverity(t *testing.T) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	tests := []struct {
		name       string
		alerts     []Alert
		expected   Severity
	}{
		{
			name:     "empty alerts",
			alerts:   []Alert{},
			expected: SeverityLow,
		},
		{
			name: "single low alert",
			alerts: []Alert{
				{Severity: SeverityLow},
			},
			expected: SeverityLow,
		},
		{
			name: "single critical alert",
			alerts: []Alert{
				{Severity: SeverityCritical},
			},
			expected: SeverityCritical,
		},
		{
			name: "multiple medium alerts",
			alerts: []Alert{
				{Severity: SeverityMedium, Route: "a"},
				{Severity: SeverityMedium, Route: "b"},
				{Severity: SeverityMedium, Route: "c"},
			},
			expected: SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incident := &Incident{
				Alerts:       tt.alerts,
				AffectedSvcs: make([]string, len(tt.alerts)),
				Impact:       &ImpactAnalysis{ServiceImpact: make(map[string]float64)},
			}
			for i := range tt.alerts {
				incident.AffectedSvcs[i] = tt.alerts[i].Route
			}

			severity := rca.calculateOverallSeverity(incident)
			if severity != tt.expected {
				t.Errorf("calculateOverallSeverity() = %s, want %s", severity, tt.expected)
			}
		})
	}
}

func BenchmarkRootCauseAnalyzer_Analyze(b *testing.B) {
	detector := New(DefaultDetectorConfig())
	config := DefaultRootCauseConfig()
	rca := NewRootCauseAnalyzer(config, detector)

	alert := Alert{
		ID:        "test",
		Type:      AnomalyTypeLatency,
		Severity:  SeverityHigh,
		Route:     "api",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rca.Analyze(alert)
	}
}

func BenchmarkDependencyGraph_AddDependency(b *testing.B) {
	graph := NewDependencyGraph()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		graph.AddDependency("api", "database", 10*time.Millisecond)
	}
}
