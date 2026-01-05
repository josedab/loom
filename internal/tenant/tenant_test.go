package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	if manager.tenants == nil {
		t.Error("expected tenants map")
	}
	if manager.resolver == nil {
		t.Error("expected default resolver")
	}
	if manager.logger == nil {
		t.Error("expected logger")
	}
}

func TestManager_AddTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tenant := &Tenant{
		ID:     "tenant-1",
		Name:   "Test Tenant",
		Status: TenantStatusActive,
	}

	if err := manager.AddTenant(tenant); err != nil {
		t.Fatalf("failed to add tenant: %v", err)
	}

	if tenant.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if tenant.usage == nil {
		t.Error("expected usage to be initialized")
	}

	// Get tenant
	got, err := manager.GetTenant("tenant-1")
	if err != nil {
		t.Fatalf("failed to get tenant: %v", err)
	}
	if got.Name != "Test Tenant" {
		t.Error("tenant name mismatch")
	}
}

func TestManager_AddTenant_WithRateLimit(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tenant := &Tenant{
		ID:     "tenant-1",
		Status: TenantStatusActive,
		RateLimit: &RateLimit{
			RequestsPerSecond: 10,
			BurstSize:         20,
		},
	}

	if err := manager.AddTenant(tenant); err != nil {
		t.Fatalf("failed to add tenant: %v", err)
	}

	if tenant.rateLimiter == nil {
		t.Error("expected rate limiter to be initialized")
	}
}

func TestManager_AddTenant_MissingID(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tenant := &Tenant{Name: "Test"}
	if err := manager.AddTenant(tenant); err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestManager_GetTenant_NotFound(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	_, err := manager.GetTenant("unknown")
	if err != ErrTenantNotFound {
		t.Errorf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestManager_UpdateTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	original := &Tenant{
		ID:     "tenant-1",
		Name:   "Original Name",
		Status: TenantStatusActive,
	}
	manager.AddTenant(original)

	updated := &Tenant{
		ID:     "tenant-1",
		Name:   "Updated Name",
		Status: TenantStatusSuspended,
	}

	if err := manager.UpdateTenant(updated); err != nil {
		t.Fatalf("failed to update tenant: %v", err)
	}

	got, _ := manager.GetTenant("tenant-1")
	if got.Name != "Updated Name" {
		t.Error("name not updated")
	}
	if got.Status != TenantStatusSuspended {
		t.Error("status not updated")
	}
	if got.CreatedAt != original.CreatedAt {
		t.Error("CreatedAt should be preserved")
	}
}

func TestManager_UpdateTenant_NotFound(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tenant := &Tenant{ID: "unknown"}
	if err := manager.UpdateTenant(tenant); err != ErrTenantNotFound {
		t.Errorf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestManager_RemoveTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	manager.AddTenant(&Tenant{ID: "tenant-1", Status: TenantStatusActive})

	if !manager.RemoveTenant("tenant-1") {
		t.Error("expected true for existing tenant")
	}
	if manager.RemoveTenant("tenant-1") {
		t.Error("expected false for already removed tenant")
	}
}

func TestManager_ListTenants(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	// Empty list
	if len(manager.ListTenants()) != 0 {
		t.Error("expected empty list")
	}

	// Add tenants
	manager.AddTenant(&Tenant{ID: "t1", Status: TenantStatusActive})
	manager.AddTenant(&Tenant{ID: "t2", Status: TenantStatusActive})
	manager.AddTenant(&Tenant{ID: "t3", Status: TenantStatusActive})

	tenants := manager.ListTenants()
	if len(tenants) != 3 {
		t.Errorf("expected 3 tenants, got %d", len(tenants))
	}
}

func TestHeaderResolver(t *testing.T) {
	resolver := HeaderResolver("X-Tenant-ID")

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Tenant-ID", "tenant-123")

	id := resolver(r)
	if id != "tenant-123" {
		t.Errorf("got %q, want %q", id, "tenant-123")
	}

	r = httptest.NewRequest("GET", "/", nil)
	id = resolver(r)
	if id != "" {
		t.Errorf("got %q, want empty", id)
	}
}

func TestSubdomainResolver(t *testing.T) {
	resolver := SubdomainResolver()

	tests := []struct {
		host string
		want string
	}{
		{"tenant1.api.example.com", "tenant1"},
		{"api.example.com", "api"}, // 3 parts, returns first
		{"localhost", ""},
		{"example.com", ""},        // 2 parts, no subdomain
		{"tenant2.api.example.com:8080", "tenant2"},
	}

	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tt.host

		got := resolver(r)
		if got != tt.want {
			t.Errorf("host %q: got %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestPathResolver(t *testing.T) {
	resolver := PathResolver("/api/v1/tenants/")

	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/tenants/tenant1/users", "tenant1"},
		{"/api/v1/tenants/tenant2", "tenant2"},
		{"/api/v1/other/path", ""},
		{"/different/path", ""},
	}

	for _, tt := range tests {
		r := httptest.NewRequest("GET", tt.path, nil)
		got := resolver(r)
		if got != tt.want {
			t.Errorf("path %q: got %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestChainedResolver(t *testing.T) {
	resolver := ChainedResolver(
		HeaderResolver("X-Tenant-ID"),
		SubdomainResolver(),
	)

	// Header takes precedence
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Tenant-ID", "header-tenant")
	r.Host = "subdomain.example.com"

	if got := resolver(r); got != "header-tenant" {
		t.Errorf("got %q, want %q", got, "header-tenant")
	}

	// Falls back to subdomain
	r = httptest.NewRequest("GET", "/", nil)
	r.Host = "subdomain.api.example.com"

	if got := resolver(r); got != "subdomain" {
		t.Errorf("got %q, want %q", got, "subdomain")
	}
}

func TestManager_ResolveTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{
		DefaultTenant: "default",
	})

	r := httptest.NewRequest("GET", "/", nil)
	id := manager.ResolveTenant(r)
	if id != "default" {
		t.Errorf("got %q, want %q", id, "default")
	}

	r.Header.Set("X-Tenant-ID", "custom")
	id = manager.ResolveTenant(r)
	if id != "custom" {
		t.Errorf("got %q, want %q", id, "custom")
	}
}

func TestManager_CheckAccess(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tests := []struct {
		name    string
		tenant  *Tenant
		wantErr error
	}{
		{
			name:    "active tenant",
			tenant:  &Tenant{ID: "t1", Status: TenantStatusActive},
			wantErr: nil,
		},
		{
			name:    "disabled tenant",
			tenant:  &Tenant{ID: "t2", Status: TenantStatusDisabled},
			wantErr: ErrTenantDisabled,
		},
		{
			name:    "suspended tenant",
			tenant:  &Tenant{ID: "t3", Status: TenantStatusSuspended},
			wantErr: ErrTenantSuspended,
		},
		{
			name:    "trial tenant",
			tenant:  &Tenant{ID: "t4", Status: TenantStatusTrial},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.CheckAccess(tt.tenant)
			if err != tt.wantErr {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestManager_CheckAccess_RateLimit(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	tenant := &Tenant{
		ID:     "t1",
		Status: TenantStatusActive,
		RateLimit: &RateLimit{
			RequestsPerSecond: 1,
			BurstSize:         2,
		},
	}
	manager.AddTenant(tenant)

	// First two should pass (burst)
	if err := manager.CheckAccess(tenant); err != nil {
		t.Errorf("first request should pass: %v", err)
	}
	if err := manager.CheckAccess(tenant); err != nil {
		t.Errorf("second request should pass: %v", err)
	}

	// Third should fail (burst exhausted)
	if err := manager.CheckAccess(tenant); err != ErrRateLimitExceeded {
		t.Errorf("third request should fail with rate limit: %v", err)
	}
}

func TestManager_CheckAccess_Quota(t *testing.T) {
	manager := NewManager(ManagerConfig{EnableUsageTracking: true})

	tenant := &Tenant{
		ID:     "t1",
		Status: TenantStatusActive,
		Quota: &Quota{
			RequestsPerDay: 2,
		},
	}
	manager.AddTenant(tenant)

	// First should pass (0 requests used)
	if err := manager.CheckAccess(tenant); err != nil {
		t.Errorf("first request should pass: %v", err)
	}
	manager.RecordUsage(tenant, 100)

	// Second should pass (1 request used)
	if err := manager.CheckAccess(tenant); err != nil {
		t.Errorf("second request should pass: %v", err)
	}
	manager.RecordUsage(tenant, 100)

	// Third should fail (2 requests used, quota is 2)
	if err := manager.CheckAccess(tenant); err != ErrQuotaExceeded {
		t.Errorf("third request should fail with quota: %v", err)
	}
}

func TestManager_RecordUsage(t *testing.T) {
	manager := NewManager(ManagerConfig{EnableUsageTracking: true})

	tenant := &Tenant{ID: "t1", Status: TenantStatusActive}
	manager.AddTenant(tenant)

	manager.RecordUsage(tenant, 1000)
	manager.RecordUsage(tenant, 500)

	usage, _ := manager.GetUsage("t1")
	if usage.RequestsToday != 2 {
		t.Errorf("requests today = %d, want 2", usage.RequestsToday)
	}
	if usage.BandwidthToday != 1500 {
		t.Errorf("bandwidth today = %d, want 1500", usage.BandwidthToday)
	}
}

func TestTokenBucket(t *testing.T) {
	tb := newTokenBucket(&RateLimit{
		RequestsPerSecond: 10,
		BurstSize:         5,
	})

	// Use all burst
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Errorf("request %d should be allowed", i)
		}
	}

	// Should be denied
	if tb.Allow() {
		t.Error("request should be denied after burst")
	}

	// Wait for refill
	time.Sleep(200 * time.Millisecond)

	// Should have tokens now
	if !tb.Allow() {
		t.Error("request should be allowed after refill")
	}
}

func TestMiddleware(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	manager.AddTenant(&Tenant{
		ID:     "tenant-1",
		Name:   "Test",
		Status: TenantStatusActive,
		Config: TenantConfig{
			Headers: map[string]string{
				"X-Tenant-Header": "value",
			},
		},
	})

	middleware := Middleware(MiddlewareConfig{
		Manager: manager,
	})

	var capturedTenant *Tenant
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = GetTenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if capturedTenant == nil {
		t.Fatal("expected tenant in context")
	}
	if capturedTenant.ID != "tenant-1" {
		t.Error("tenant ID mismatch")
	}
	if r.Header.Get("X-Tenant-Header") != "value" {
		t.Error("expected tenant header to be added")
	}
}

func TestMiddleware_RequireTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{})

	middleware := Middleware(MiddlewareConfig{
		Manager:       manager,
		RequireTenant: true,
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_DisabledTenant(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	manager.AddTenant(&Tenant{
		ID:     "tenant-1",
		Status: TenantStatusDisabled,
	})

	middleware := Middleware(MiddlewareConfig{
		Manager: manager,
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestGetTenantFromContext(t *testing.T) {
	tenant := &Tenant{ID: "test"}
	ctx := context.WithValue(context.Background(), tenantContextKey{}, tenant)

	got := GetTenantFromContext(ctx)
	if got == nil {
		t.Fatal("expected tenant")
	}
	if got.ID != "test" {
		t.Error("ID mismatch")
	}

	got = GetTenantFromContext(context.Background())
	if got != nil {
		t.Error("expected nil for empty context")
	}
}

func TestHasFeature(t *testing.T) {
	tenant := &Tenant{
		ID: "test",
		Config: TenantConfig{
			Features: map[string]bool{
				"feature-a": true,
				"feature-b": false,
			},
		},
	}
	ctx := context.WithValue(context.Background(), tenantContextKey{}, tenant)

	if !HasFeature(ctx, "feature-a") {
		t.Error("expected feature-a to be enabled")
	}
	if HasFeature(ctx, "feature-b") {
		t.Error("expected feature-b to be disabled")
	}
	if HasFeature(ctx, "feature-c") {
		t.Error("expected feature-c to be disabled (not set)")
	}
	if HasFeature(context.Background(), "feature-a") {
		t.Error("expected false for no tenant")
	}
}

func TestFeatureMiddleware(t *testing.T) {
	tenant := &Tenant{
		ID: "test",
		Config: TenantConfig{
			Features: map[string]bool{
				"premium": true,
			},
		},
	}

	middleware := FeatureMiddleware("premium")

	handlerCalled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	// With feature
	r := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(r.Context(), tenantContextKey{}, tenant)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r.WithContext(ctx))
	if !handlerCalled {
		t.Error("expected handler to be called")
	}

	// Without feature
	tenant.Config.Features["premium"] = false
	handlerCalled = false
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, r.WithContext(ctx))
	if handlerCalled {
		t.Error("expected handler not to be called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandler_CRUD(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	handler := NewHandler(manager, nil)

	// Create
	body := `{"id": "t1", "name": "Test Tenant", "status": "active"}`
	r := httptest.NewRequest("POST", "/tenants", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("create: got status %d, want %d", w.Code, http.StatusCreated)
	}

	// List
	r = httptest.NewRequest("GET", "/tenants", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("list: got status %d, want %d", w.Code, http.StatusOK)
	}

	var tenants []*Tenant
	json.NewDecoder(w.Body).Decode(&tenants)
	if len(tenants) != 1 {
		t.Errorf("expected 1 tenant, got %d", len(tenants))
	}

	// Get
	r = httptest.NewRequest("GET", "/tenants/t1", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("get: got status %d, want %d", w.Code, http.StatusOK)
	}

	// Update
	body = `{"name": "Updated Tenant", "status": "suspended"}`
	r = httptest.NewRequest("PUT", "/tenants/t1", strings.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("update: got status %d, want %d", w.Code, http.StatusOK)
	}

	// Delete
	r = httptest.NewRequest("DELETE", "/tenants/t1", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("delete: got status %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify deleted
	r = httptest.NewRequest("GET", "/tenants/t1", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("get deleted: got status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandler_Usage(t *testing.T) {
	manager := NewManager(ManagerConfig{EnableUsageTracking: true})
	tenant := &Tenant{ID: "t1", Status: TenantStatusActive}
	manager.AddTenant(tenant)
	manager.RecordUsage(tenant, 1000)

	// Verify usage was recorded
	usage, err := manager.GetUsage("t1")
	if err != nil {
		t.Fatalf("failed to get usage: %v", err)
	}
	if usage.RequestsToday != 1 {
		t.Errorf("recorded usage = %d, want 1", usage.RequestsToday)
	}
}

func TestIsolationMiddleware(t *testing.T) {
	manager := NewManager(ManagerConfig{})
	manager.AddTenant(&Tenant{
		ID:     "t1",
		Status: TenantStatusActive,
		Config: TenantConfig{
			AllowedIPs: []string{"192.168.1.1"},
			BasePath:   "/api/v1",
		},
	})

	middleware := IsolationMiddleware(MiddlewareConfig{
		Manager: manager,
	})

	var capturedPath string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed IP
	r := httptest.NewRequest("GET", "/api/v1/users", nil)
	r.Header.Set("X-Tenant-ID", "t1")
	r.Header.Set("X-Forwarded-For", "192.168.1.1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("allowed IP: got status %d, want %d", w.Code, http.StatusOK)
	}
	if capturedPath != "/users" {
		t.Errorf("path = %q, want %q", capturedPath, "/users")
	}

	// Blocked IP
	r = httptest.NewRequest("GET", "/api/v1/users", nil)
	r.Header.Set("X-Tenant-ID", "t1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("blocked IP: got status %d, want error status", w.Code)
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := NewManager(ManagerConfig{EnableUsageTracking: true})
	tenant := &Tenant{
		ID:     "t1",
		Status: TenantStatusActive,
		RateLimit: &RateLimit{
			RequestsPerSecond: 1000,
			BurstSize:         1000,
		},
	}
	manager.AddTenant(tenant)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.CheckAccess(tenant)
			manager.RecordUsage(tenant, 100)
		}()
	}
	wg.Wait()

	usage, _ := manager.GetUsage("t1")
	if usage.RequestsToday != 100 {
		t.Errorf("requests = %d, want 100", usage.RequestsToday)
	}
}

func TestDefaultTenantErrorHandler(t *testing.T) {
	tests := []struct {
		err        error
		wantStatus int
	}{
		{ErrTenantNotFound, http.StatusUnauthorized},
		{ErrTenantDisabled, http.StatusForbidden},
		{ErrTenantSuspended, http.StatusForbidden},
		{ErrQuotaExceeded, http.StatusTooManyRequests},
		{ErrRateLimitExceeded, http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			defaultTenantErrorHandler(w, r, tt.err)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
