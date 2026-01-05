package versioning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(ManagerConfig{})

	if m == nil {
		t.Fatal("expected manager to be created")
	}
	if m.config.DefaultVersionHeader != "X-API-Version" {
		t.Errorf("DefaultVersionHeader = %v, want X-API-Version", m.config.DefaultVersionHeader)
	}
	if m.config.DefaultVersionQuery != "version" {
		t.Errorf("DefaultVersionQuery = %v, want version", m.config.DefaultVersionQuery)
	}
}

func TestManager_RegisterAPI(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:       "users-api",
		Name:     "Users API",
		BasePath: "/api/users",
	}

	err := m.RegisterAPI(api)
	if err != nil {
		t.Errorf("RegisterAPI() error = %v", err)
	}

	if api.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if api.VersioningScheme != SchemePathPrefix {
		t.Errorf("VersioningScheme = %v, want path", api.VersioningScheme)
	}

	// Test empty ID
	err = m.RegisterAPI(&API{})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestManager_GetListAPIs(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api1 := &API{ID: "api1", Name: "API 1", BasePath: "/api1"}
	api2 := &API{ID: "api2", Name: "API 2", BasePath: "/api2"}

	m.RegisterAPI(api1)
	m.RegisterAPI(api2)

	// Get
	got, err := m.GetAPI("api1")
	if err != nil {
		t.Errorf("GetAPI() error = %v", err)
	}
	if got.Name != "API 1" {
		t.Errorf("Name = %v, want API 1", got.Name)
	}

	// Get not found
	_, err = m.GetAPI("nonexistent")
	if err != ErrAPINotFound {
		t.Errorf("GetAPI() error = %v, want ErrAPINotFound", err)
	}

	// List
	apis := m.ListAPIs()
	if len(apis) != 2 {
		t.Errorf("ListAPIs() len = %d, want 2", len(apis))
	}
}

func TestManager_UnregisterAPI(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)

	err := m.UnregisterAPI("test")
	if err != nil {
		t.Errorf("UnregisterAPI() error = %v", err)
	}

	_, err = m.GetAPI("test")
	if err != ErrAPINotFound {
		t.Error("expected API to be removed")
	}

	// Unregister not found
	err = m.UnregisterAPI("nonexistent")
	if err != ErrAPINotFound {
		t.Errorf("UnregisterAPI() error = %v, want ErrAPINotFound", err)
	}
}

func TestManager_AddVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)

	version := &Version{
		Name:  "v1",
		Major: 1,
		Minor: 0,
	}

	err := m.AddVersion("test", version)
	if err != nil {
		t.Errorf("AddVersion() error = %v", err)
	}

	if version.Lifecycle != LifecycleActive {
		t.Errorf("Lifecycle = %v, want active", version.Lifecycle)
	}

	// Add to non-existent API
	err = m.AddVersion("nonexistent", version)
	if err != ErrAPINotFound {
		t.Errorf("AddVersion() error = %v, want ErrAPINotFound", err)
	}

	// Add duplicate version
	err = m.AddVersion("test", &Version{Name: "v1"})
	if err != ErrVersionExists {
		t.Errorf("AddVersion() error = %v, want ErrVersionExists", err)
	}
}

func TestManager_RemoveVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1})

	err := m.RemoveVersion("test", "v1")
	if err != nil {
		t.Errorf("RemoveVersion() error = %v", err)
	}

	// Remove from non-existent API
	err = m.RemoveVersion("nonexistent", "v1")
	if err != ErrAPINotFound {
		t.Errorf("RemoveVersion() error = %v, want ErrAPINotFound", err)
	}

	// Remove non-existent version
	err = m.RemoveVersion("test", "v2")
	if err != ErrVersionNotFound {
		t.Errorf("RemoveVersion() error = %v, want ErrVersionNotFound", err)
	}
}

func TestManager_GetVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1})

	version, err := m.GetVersion("test", "v1")
	if err != nil {
		t.Errorf("GetVersion() error = %v", err)
	}
	if version.Name != "v1" {
		t.Errorf("Name = %v, want v1", version.Name)
	}

	// Get from non-existent API
	_, err = m.GetVersion("nonexistent", "v1")
	if err != ErrAPINotFound {
		t.Errorf("GetVersion() error = %v, want ErrAPINotFound", err)
	}

	// Get non-existent version
	_, err = m.GetVersion("test", "v2")
	if err != ErrVersionNotFound {
		t.Errorf("GetVersion() error = %v, want ErrVersionNotFound", err)
	}
}

func TestManager_DeprecateVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1})

	sunsetAt := time.Now().Add(30 * 24 * time.Hour)
	err := m.DeprecateVersion("test", "v1", sunsetAt, "v2")
	if err != nil {
		t.Errorf("DeprecateVersion() error = %v", err)
	}

	version, _ := m.GetVersion("test", "v1")
	if version.Lifecycle != LifecycleDeprecated {
		t.Errorf("Lifecycle = %v, want deprecated", version.Lifecycle)
	}
	if version.DeprecatedAt == nil {
		t.Error("expected DeprecatedAt to be set")
	}
	if version.SunsetAt == nil {
		t.Error("expected SunsetAt to be set")
	}
	if version.SuccessorVersion != "v2" {
		t.Errorf("SuccessorVersion = %v, want v2", version.SuccessorVersion)
	}
}

func TestManager_SunsetVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1})

	err := m.SunsetVersion("test", "v1")
	if err != nil {
		t.Errorf("SunsetVersion() error = %v", err)
	}

	version, _ := m.GetVersion("test", "v1")
	if version.Lifecycle != LifecycleSunset {
		t.Errorf("Lifecycle = %v, want sunset", version.Lifecycle)
	}
}

func TestManager_GetActiveVersions(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v0", Major: 0, Lifecycle: LifecycleDeprecated})

	versions, err := m.GetActiveVersions("test")
	if err != nil {
		t.Errorf("GetActiveVersions() error = %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}
}

func TestManager_GetLatestVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Minor: 0, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v1.1", Major: 1, Minor: 1, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Minor: 0, Lifecycle: LifecycleActive})

	latest, err := m.GetLatestVersion("test")
	if err != nil {
		t.Errorf("GetLatestVersion() error = %v", err)
	}
	if latest.Name != "v2" {
		t.Errorf("latest = %v, want v2", latest.Name)
	}

	// Test with default version
	api.DefaultVersion = "v1.1"
	latest, _ = m.GetLatestVersion("test")
	if latest.Name != "v1.1" {
		t.Errorf("latest with default = %v, want v1.1", latest.Name)
	}

	// Test with no active versions
	m.RegisterAPI(&API{ID: "empty", Name: "Empty"})
	_, err = m.GetLatestVersion("empty")
	if err != ErrNoActiveVersion {
		t.Errorf("GetLatestVersion() error = %v, want ErrNoActiveVersion", err)
	}
}

func TestManager_ResolveVersion_PathPrefix(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Lifecycle: LifecycleActive})

	tests := []struct {
		name        string
		path        string
		wantVersion string
		wantErr     error
	}{
		{
			name:        "v1 in path",
			path:        "/api/v1/users",
			wantVersion: "v1",
		},
		{
			name:        "v2 in path",
			path:        "/api/v2/users",
			wantVersion: "v2",
		},
		{
			name:        "no version in path uses latest",
			path:        "/api/users",
			wantVersion: "v2", // latest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			version, err := m.ResolveVersion("test", req)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if version.Name != tt.wantVersion {
				t.Errorf("version = %v, want %v", version.Name, tt.wantVersion)
			}
		})
	}
}

func TestManager_ResolveVersion_Header(t *testing.T) {
	m := NewManager(ManagerConfig{
		DefaultVersionHeader: "X-API-Version",
	})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemeHeader,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Lifecycle: LifecycleActive})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Version", "v1")

	version, err := m.ResolveVersion("test", req)
	if err != nil {
		t.Errorf("error = %v", err)
	}
	if version.Name != "v1" {
		t.Errorf("version = %v, want v1", version.Name)
	}
}

func TestManager_ResolveVersion_Query(t *testing.T) {
	m := NewManager(ManagerConfig{
		DefaultVersionQuery: "version",
	})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemeQuery,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})

	req := httptest.NewRequest(http.MethodGet, "/api/users?version=v1", nil)

	version, err := m.ResolveVersion("test", req)
	if err != nil {
		t.Errorf("error = %v", err)
	}
	if version.Name != "v1" {
		t.Errorf("version = %v, want v1", version.Name)
	}
}

func TestManager_ResolveVersion_Accept(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemeAcceptHeader,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Accept", "application/vnd.api.v1+json")

	version, err := m.ResolveVersion("test", req)
	if err != nil {
		t.Errorf("error = %v", err)
	}
	if version.Name != "v1" {
		t.Errorf("version = %v, want v1", version.Name)
	}
}

func TestManager_ResolveVersion_SunsetVersion(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleSunset})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)

	_, err := m.ResolveVersion("test", req)
	if err != ErrVersionSunset {
		t.Errorf("error = %v, want ErrVersionSunset", err)
	}
}

func TestManager_ResolveVersion_PreRelease(t *testing.T) {
	m := NewManager(ManagerConfig{
		AllowPreRelease: false,
	})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Lifecycle: LifecycleBeta})

	req := httptest.NewRequest(http.MethodGet, "/api/v2/users", nil)

	_, err := m.ResolveVersion("test", req)
	if err == nil {
		t.Error("expected error for pre-release version")
	}

	// Allow pre-release
	m.config.AllowPreRelease = true
	version, err := m.ResolveVersion("test", req)
	if err != nil {
		t.Errorf("error = %v", err)
	}
	if version.Name != "v2" {
		t.Errorf("version = %v, want v2", version.Name)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{"v1", 1, 0, false},
		{"v2", 2, 0, false},
		{"v1.0", 1, 0, false},
		{"v1.2", 1, 2, false},
		{"v10.5", 10, 5, false},
		{"1", 1, 0, false},
		{"1.2", 1, 2, false},
		{"invalid", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, err := ParseVersion(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Errorf("got (%d, %d), want (%d, %d)", major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b *Version
		want int
	}{
		{&Version{Major: 1, Minor: 0}, &Version{Major: 2, Minor: 0}, -1},
		{&Version{Major: 2, Minor: 0}, &Version{Major: 1, Minor: 0}, 1},
		{&Version{Major: 1, Minor: 1}, &Version{Major: 1, Minor: 2}, -1},
		{&Version{Major: 1, Minor: 2}, &Version{Major: 1, Minor: 1}, 1},
		{&Version{Major: 1, Minor: 1}, &Version{Major: 1, Minor: 1}, 0},
	}

	for _, tt := range tests {
		got := CompareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("CompareVersions(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSortVersions(t *testing.T) {
	versions := []*Version{
		{Name: "v2", Major: 2, Minor: 0},
		{Name: "v1.1", Major: 1, Minor: 1},
		{Name: "v1", Major: 1, Minor: 0},
		{Name: "v3", Major: 3, Minor: 0},
	}

	SortVersions(versions)

	expected := []string{"v1", "v1.1", "v2", "v3"}
	for i, v := range versions {
		if v.Name != expected[i] {
			t.Errorf("versions[%d] = %v, want %v", i, v.Name, expected[i])
		}
	}
}

func TestVersionLifecycle(t *testing.T) {
	v := &Version{Lifecycle: LifecycleActive}
	if !v.IsActive() {
		t.Error("expected IsActive() to be true")
	}
	if v.IsDeprecated() {
		t.Error("expected IsDeprecated() to be false")
	}
	if v.IsSunset() {
		t.Error("expected IsSunset() to be false")
	}

	v.Lifecycle = LifecycleDeprecated
	if v.IsActive() {
		t.Error("expected IsActive() to be false")
	}
	if !v.IsDeprecated() {
		t.Error("expected IsDeprecated() to be true")
	}

	v.Lifecycle = LifecycleBeta
	if !v.IsPreRelease() {
		t.Error("expected IsPreRelease() to be true for beta")
	}

	v.Lifecycle = LifecycleAlpha
	if !v.IsPreRelease() {
		t.Error("expected IsPreRelease() to be true for alpha")
	}
}

func TestExtractPathVersion(t *testing.T) {
	tests := []struct {
		path     string
		basePath string
		want     string
	}{
		{"/api/v1/users", "/api", "v1"},
		{"/api/v2/users", "/api", "v2"},
		{"/api/v1.0/users", "/api", "v1.0"},
		{"/api/users", "/api", ""},
		{"/v1/users", "", "v1"},
		{"/api/something/users", "/api", ""},
	}

	for _, tt := range tests {
		got := extractPathVersion(tt.path, tt.basePath)
		if got != tt.want {
			t.Errorf("extractPathVersion(%q, %q) = %q, want %q", tt.path, tt.basePath, got, tt.want)
		}
	}
}

func TestExtractAcceptVersion(t *testing.T) {
	tests := []struct {
		accept string
		want   string
	}{
		{"application/vnd.api.v1+json", "v1"},
		{"application/vnd.myapi.v2+json", "v2"},
		{"application/vnd.api.v1.2+json", "v1.2"},
		{"application/json", ""},
		{"text/html", ""},
	}

	for _, tt := range tests {
		got := extractAcceptVersion(tt.accept)
		if got != tt.want {
			t.Errorf("extractAcceptVersion(%q) = %q, want %q", tt.accept, got, tt.want)
		}
	}
}

func TestMiddleware(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		APIResolver: func(r *http.Request) string {
			return "test"
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vc := GetVersionContext(r.Context())
		if vc == nil {
			t.Error("expected version context")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-API-Version") != "v1" {
		t.Errorf("X-API-Version = %v, want v1", rec.Header().Get("X-API-Version"))
	}
}

func TestMiddleware_Deprecated(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)

	sunsetAt := time.Now().Add(30 * 24 * time.Hour)
	m.AddVersion("test", &Version{
		Name:             "v1",
		Major:            1,
		Lifecycle:        LifecycleDeprecated,
		SunsetAt:         &sunsetAt,
		SuccessorVersion: "v2",
	})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		APIResolver: func(r *http.Request) string {
			return "test"
		},
		AddDeprecationHeaders: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Deprecation") == "" {
		t.Error("expected Deprecation header")
	}
	if rec.Header().Get("Sunset") == "" {
		t.Error("expected Sunset header")
	}
}

func TestMiddleware_BlockSunset(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleSunset})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		APIResolver: func(r *http.Request) string {
			return "test"
		},
		BlockSunsetVersions: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", rec.Code)
	}
}

func TestMiddleware_UnknownAPI(t *testing.T) {
	m := NewManager(ManagerConfig{})

	handler := Middleware(MiddlewareConfig{
		Manager: m,
		APIResolver: func(r *http.Request) string {
			return "unknown"
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should pass through when API not found
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandler_CRUD(t *testing.T) {
	m := NewManager(ManagerConfig{})
	h := NewHandler(m, nil)

	// Create API
	createBody := `{
		"id": "users",
		"name": "Users API",
		"base_path": "/api/users",
		"versioning_scheme": "path"
	}`

	req := httptest.NewRequest(http.MethodPost, "/versions", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Create status = %d, want 201", rec.Code)
	}

	// List APIs
	req = httptest.NewRequest(http.MethodGet, "/versions", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("List status = %d, want 200", rec.Code)
	}

	var apis []API
	json.NewDecoder(rec.Body).Decode(&apis)
	if len(apis) != 1 {
		t.Errorf("len(apis) = %d, want 1", len(apis))
	}

	// Get API
	req = httptest.NewRequest(http.MethodGet, "/versions/users", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Get status = %d, want 200", rec.Code)
	}

	// Add version
	addVersionBody := `{"name": "v1", "major": 1, "minor": 0}`
	req = httptest.NewRequest(http.MethodPost, "/versions/users/versions", strings.NewReader(addVersionBody))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Add version status = %d, want 201", rec.Code)
	}

	// List versions
	req = httptest.NewRequest(http.MethodGet, "/versions/users/versions", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("List versions status = %d, want 200", rec.Code)
	}

	// Get version
	req = httptest.NewRequest(http.MethodGet, "/versions/users/versions/v1", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Get version status = %d, want 200", rec.Code)
	}

	// Deprecate version
	deprecateBody := `{"sunset_at": "2025-12-31T23:59:59Z", "successor": "v2"}`
	req = httptest.NewRequest(http.MethodPost, "/versions/users/versions/v1/deprecate", strings.NewReader(deprecateBody))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Deprecate status = %d, want 200", rec.Code)
	}

	// Sunset version
	req = httptest.NewRequest(http.MethodPost, "/versions/users/versions/v1/sunset", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Sunset status = %d, want 200", rec.Code)
	}

	// Delete version
	req = httptest.NewRequest(http.MethodDelete, "/versions/users/versions/v1", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Delete version status = %d, want 204", rec.Code)
	}

	// Delete API
	req = httptest.NewRequest(http.MethodDelete, "/versions/users", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Delete API status = %d, want 204", rec.Code)
	}
}

func TestHandler_Stats(t *testing.T) {
	m := NewManager(ManagerConfig{})
	h := NewHandler(m, nil)

	// Register API and versions
	api := &API{ID: "test", Name: "Test", BasePath: "/test"}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{Name: "v1", Major: 1, Lifecycle: LifecycleActive})
	m.AddVersion("test", &Version{Name: "v2", Major: 2, Lifecycle: LifecycleDeprecated})

	req := httptest.NewRequest(http.MethodGet, "/versions/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Stats status = %d, want 200", rec.Code)
	}

	var stats Stats
	json.NewDecoder(rec.Body).Decode(&stats)

	if stats.TotalAPIs != 1 {
		t.Errorf("TotalAPIs = %d, want 1", stats.TotalAPIs)
	}
	if stats.TotalVersions != 2 {
		t.Errorf("TotalVersions = %d, want 2", stats.TotalVersions)
	}
	if stats.ActiveVersions != 1 {
		t.Errorf("ActiveVersions = %d, want 1", stats.ActiveVersions)
	}
	if stats.DeprecatedVersions != 1 {
		t.Errorf("DeprecatedVersions = %d, want 1", stats.DeprecatedVersions)
	}
}

func TestTransformMiddleware(t *testing.T) {
	m := NewManager(ManagerConfig{})

	api := &API{
		ID:               "test",
		Name:             "Test",
		BasePath:         "/api",
		VersioningScheme: SchemePathPrefix,
	}
	m.RegisterAPI(api)
	m.AddVersion("test", &Version{
		Name:       "v1",
		Major:      1,
		Lifecycle:  LifecycleActive,
		PathPrefix: "/v1-backend",
		Headers: map[string]string{
			"X-Version-Header": "v1-value",
		},
	})

	transform := NewTransformMiddleware(m, nil)

	var capturedPath string
	var capturedHeader string

	// Chain: versioning middleware -> transform middleware -> handler
	handler := Middleware(MiddlewareConfig{
		Manager: m,
		APIResolver: func(r *http.Request) string {
			return "test"
		},
	})(transform.Handler()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedHeader = r.Header.Get("X-Version-Header")
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	if capturedPath != "/v1-backend/api/users" {
		t.Errorf("path = %v, want /v1-backend/api/users", capturedPath)
	}

	if capturedHeader != "v1-value" {
		t.Errorf("header = %v, want v1-value", capturedHeader)
	}
}

func TestVersionContext(t *testing.T) {
	api := &API{ID: "test", Name: "Test"}
	version := &Version{Name: "v1"}
	vc := &VersionContext{API: api, Version: version}

	ctx := WithVersionContext(context.Background(), vc)
	if ctx == nil {
		t.Fatal("expected context")
	}

	got := GetVersionContext(ctx)
	if got == nil {
		t.Fatal("expected version context")
	}
	if got.API.ID != "test" {
		t.Errorf("API.ID = %v, want test", got.API.ID)
	}
	if got.Version.Name != "v1" {
		t.Errorf("Version.Name = %v, want v1", got.Version.Name)
	}

	// Test nil context returns nil
	got = GetVersionContext(context.Background())
	if got != nil {
		t.Error("expected nil for context without version")
	}
}
