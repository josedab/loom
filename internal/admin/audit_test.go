package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	logger := NewAuditLogger(AuditConfig{})

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	if logger.enabled {
		t.Error("expected disabled by default")
	}
	if logger.maxEvents != 1000 {
		t.Errorf("expected maxEvents 1000, got %d", logger.maxEvents)
	}
}

func TestNewAuditLogger_Enabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled:    true,
		Output:     &buf,
		MaxHistory: 500,
	})

	if !logger.enabled {
		t.Error("expected enabled")
	}
	if logger.maxEvents != 500 {
		t.Errorf("expected maxEvents 500, got %d", logger.maxEvents)
	}
}

func TestAuditLogger_Log_Disabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: false,
		Output:  &buf,
	})

	logger.Log(AuditEvent{
		EventType: AuditEventAPIAccess,
		Path:      "/test",
	})

	if buf.Len() > 0 {
		t.Error("expected no output when disabled")
	}
}

func TestAuditLogger_Log_Enabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: true,
		Output:  &buf,
	})

	logger.Log(AuditEvent{
		Timestamp: time.Now(),
		EventType: AuditEventAPIAccess,
		Username:  "admin",
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/routes",
	})

	output := buf.String()
	if !strings.Contains(output, "api_access") {
		t.Error("expected event_type in output")
	}
	if !strings.Contains(output, "admin") {
		t.Error("expected username in output")
	}
	if !strings.Contains(output, "192.168.1.1") {
		t.Error("expected client_ip in output")
	}
}

func TestAuditLogger_LogAuthSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: true,
		Output:  &buf,
	})

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	req.Header.Set("User-Agent", "test-agent")

	logger.LogAuthSuccess(req, "admin")

	output := buf.String()
	if !strings.Contains(output, "auth_success") {
		t.Error("expected auth_success event type")
	}
	if !strings.Contains(output, "admin") {
		t.Error("expected username in output")
	}
}

func TestAuditLogger_LogAuthFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: true,
		Output:  &buf,
	})

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)

	logger.LogAuthFailure(req, "baduser", "invalid_password")

	output := buf.String()
	if !strings.Contains(output, "auth_failure") {
		t.Error("expected auth_failure event type")
	}
	if !strings.Contains(output, "invalid_password") {
		t.Error("expected fail_reason in output")
	}
}

func TestAuditLogger_LogAPIAccess(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: true,
		Output:  &buf,
	})

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)

	logger.LogAPIAccess(req, "admin", 200, 100*time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "api_access") {
		t.Error("expected api_access event type")
	}
	if !strings.Contains(output, "\"status_code\":200") {
		t.Error("expected status_code in output")
	}
}

func TestAuditLogger_GetRecentEvents(t *testing.T) {
	logger := NewAuditLogger(AuditConfig{
		Enabled:    true,
		MaxHistory: 10,
	})

	// Log some events
	for i := 0; i < 5; i++ {
		logger.Log(AuditEvent{
			Timestamp: time.Now(),
			EventType: AuditEventAPIAccess,
			Path:      "/test",
		})
	}

	events := logger.GetRecentEvents(10)
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestAuditLogger_GetRecentEvents_RingBuffer(t *testing.T) {
	logger := NewAuditLogger(AuditConfig{
		Enabled:    true,
		MaxHistory: 5,
	})

	// Log more events than buffer can hold
	for i := 0; i < 10; i++ {
		logger.Log(AuditEvent{
			Timestamp: time.Now(),
			EventType: AuditEventAPIAccess,
			Path:      "/test",
			Username:  "user",
		})
	}

	events := logger.GetRecentEvents(10)
	if len(events) != 5 {
		t.Errorf("expected 5 events (buffer size), got %d", len(events))
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			name: "X-Forwarded-For single",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For multiple",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2, 10.0.0.3")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Real-IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "10.0.0.5")
			},
			expectedIP: "10.0.0.5",
		},
		{
			name: "RemoteAddr fallback",
			setupReq: func(r *http.Request) {
				// No headers set
			},
			expectedIP: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			ip := getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("expected %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestParseAPIRequest(t *testing.T) {
	tests := []struct {
		method         string
		path           string
		expectedRes    string
		expectedID     string
		expectedAction string
	}{
		{http.MethodGet, "/routes", "routes", "", "list"},
		{http.MethodGet, "/routes/api-v1", "route", "api-v1", "read"},
		{http.MethodPost, "/routes", "routes", "", "list"}, // list overrides method for collection endpoints
		{http.MethodDelete, "/plugins/auth", "plugin", "auth", "delete"},
		{http.MethodGet, "/upstreams", "upstreams", "", "list"},
		{http.MethodGet, "/upstreams/backend", "upstream", "backend", "read"},
		{http.MethodGet, "/config", "config", "", "read"},
		{http.MethodGet, "/info", "info", "", "read"},
		{http.MethodGet, "/metrics", "metrics", "", "read"},
		{http.MethodGet, "/health", "health", "", "read"},
		{http.MethodGet, "/unknown", "unknown", "", "read"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			res, id, action := parseAPIRequest(req)

			if res != tt.expectedRes {
				t.Errorf("resource: expected %s, got %s", tt.expectedRes, res)
			}
			if id != tt.expectedID {
				t.Errorf("resourceID: expected %s, got %s", tt.expectedID, id)
			}
			if action != tt.expectedAction {
				t.Errorf("action: expected %s, got %s", tt.expectedAction, action)
			}
		})
	}
}

func TestAuditResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	aw := &auditResponseWriter{ResponseWriter: rec}

	// Write without WriteHeader should default to 200
	aw.Write([]byte("hello"))

	if aw.statusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", aw.statusCode)
	}
	if !aw.written {
		t.Error("expected written to be true")
	}
}

func TestAuditResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	aw := &auditResponseWriter{ResponseWriter: rec}

	aw.WriteHeader(http.StatusCreated)

	if aw.statusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", aw.statusCode)
	}

	// Second WriteHeader should be ignored
	aw.WriteHeader(http.StatusBadRequest)
	if aw.statusCode != http.StatusCreated {
		t.Errorf("expected status still 201, got %d", aw.statusCode)
	}
}

func TestAuditMiddleware_Disabled(t *testing.T) {
	logger := NewAuditLogger(AuditConfig{Enabled: false})

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := logger.AuditMiddleware(next, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
}

func TestAuditMiddleware_Enabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(AuditConfig{
		Enabled: true,
		Output:  &buf,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := logger.AuditMiddleware(next, func(r *http.Request) string {
		return "testuser"
	})

	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "api_access") {
		t.Error("expected api_access event logged")
	}
	if !strings.Contains(output, "testuser") {
		t.Error("expected username in audit log")
	}
}

func TestHandleAudit(t *testing.T) {
	s, _ := createTestServer(t, AuthConfig{})
	s.audit = NewAuditLogger(AuditConfig{Enabled: true})

	// Log some events
	for i := 0; i < 3; i++ {
		s.audit.Log(AuditEvent{
			Timestamp: time.Now(),
			EventType: AuditEventAPIAccess,
			Path:      "/test",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()

	s.handleAudit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if count, ok := response["count"].(float64); !ok || count != 3 {
		t.Errorf("expected count 3, got %v", response["count"])
	}
}

func TestHandleAudit_WithLimit(t *testing.T) {
	s, _ := createTestServer(t, AuthConfig{})
	s.audit = NewAuditLogger(AuditConfig{Enabled: true})

	// Log 10 events
	for i := 0; i < 10; i++ {
		s.audit.Log(AuditEvent{
			Timestamp: time.Now(),
			EventType: AuditEventAPIAccess,
			Path:      "/test",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/audit?limit=5", nil)
	rec := httptest.NewRecorder()

	s.handleAudit(rec, req)

	var response map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&response)

	if count, ok := response["count"].(float64); !ok || count != 5 {
		t.Errorf("expected count 5, got %v", response["count"])
	}
}

func TestHandleAudit_MethodNotAllowed(t *testing.T) {
	s, _ := createTestServer(t, AuthConfig{})

	req := httptest.NewRequest(http.MethodPost, "/audit", nil)
	rec := httptest.NewRecorder()

	s.handleAudit(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestAuditEventTypes(t *testing.T) {
	if AuditEventAuthSuccess != "auth_success" {
		t.Error("wrong auth_success value")
	}
	if AuditEventAuthFailure != "auth_failure" {
		t.Error("wrong auth_failure value")
	}
	if AuditEventAPIAccess != "api_access" {
		t.Error("wrong api_access value")
	}
	if AuditEventPluginUnload != "plugin_unload" {
		t.Error("wrong plugin_unload value")
	}
}

func TestAuditEvent_Fields(t *testing.T) {
	event := AuditEvent{
		Timestamp:   time.Now(),
		EventType:   AuditEventAPIAccess,
		Username:    "admin",
		ClientIP:    "10.0.0.1",
		Method:      "GET",
		Path:        "/routes",
		StatusCode:  200,
		Duration:    100 * time.Millisecond,
		UserAgent:   "test-agent",
		Resource:    "routes",
		ResourceID:  "",
		Action:      "list",
		FailReason:  "",
	}

	if event.Username != "admin" {
		t.Error("username mismatch")
	}
	if event.StatusCode != 200 {
		t.Error("status code mismatch")
	}
	if event.Resource != "routes" {
		t.Error("resource mismatch")
	}
}
