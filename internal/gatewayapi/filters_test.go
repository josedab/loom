package gatewayapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilterChain_RequestHeaderModifier(t *testing.T) {
	filters := []HTTPRouteFilter{
		{
			Type: FilterTypeRequestHeaderModifier,
			RequestHeaderModifier: &HTTPHeaderFilter{
				Set:    []HTTPHeader{{Name: "X-Set", Value: "set-value"}},
				Add:    []HTTPHeader{{Name: "X-Add", Value: "add-value"}},
				Remove: []string{"X-Remove"},
			},
		},
	}

	chain := NewFilterChain(filters)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Remove", "should-be-removed")
	req.Header.Set("X-Keep", "keep-value")

	modifiedReq, redirect, continueProcessing := chain.ProcessRequest(req)

	if !continueProcessing {
		t.Error("ProcessRequest should continue processing")
	}
	if redirect != nil {
		t.Error("ProcessRequest should not return redirect")
	}

	// Check headers modified
	if modifiedReq.Header.Get("X-Set") != "set-value" {
		t.Errorf("X-Set = %q, want 'set-value'", modifiedReq.Header.Get("X-Set"))
	}
	if modifiedReq.Header.Get("X-Add") != "add-value" {
		t.Errorf("X-Add = %q, want 'add-value'", modifiedReq.Header.Get("X-Add"))
	}
	if modifiedReq.Header.Get("X-Remove") != "" {
		t.Error("X-Remove header should be removed")
	}
	if modifiedReq.Header.Get("X-Keep") != "keep-value" {
		t.Errorf("X-Keep = %q, want 'keep-value'", modifiedReq.Header.Get("X-Keep"))
	}
}

func TestFilterChain_ResponseHeaderModifier(t *testing.T) {
	filters := []HTTPRouteFilter{
		{
			Type: FilterTypeResponseHeaderModifier,
			ResponseHeaderModifier: &HTTPHeaderFilter{
				Set:    []HTTPHeader{{Name: "X-Response-Set", Value: "set-value"}},
				Add:    []HTTPHeader{{Name: "X-Response-Add", Value: "add-value"}},
				Remove: []string{"X-Response-Remove"},
			},
		},
	}

	chain := NewFilterChain(filters)

	rec := httptest.NewRecorder()
	rec.Header().Set("X-Response-Remove", "should-be-removed")
	rec.Header().Set("X-Response-Keep", "keep-value")

	chain.ProcessResponse(rec)

	// Check headers modified
	if rec.Header().Get("X-Response-Set") != "set-value" {
		t.Errorf("X-Response-Set = %q, want 'set-value'", rec.Header().Get("X-Response-Set"))
	}
	if rec.Header().Get("X-Response-Add") != "add-value" {
		t.Errorf("X-Response-Add = %q, want 'add-value'", rec.Header().Get("X-Response-Add"))
	}
	if rec.Header().Get("X-Response-Remove") != "" {
		t.Error("X-Response-Remove header should be removed")
	}
	if rec.Header().Get("X-Response-Keep") != "keep-value" {
		t.Errorf("X-Response-Keep = %q, want 'keep-value'", rec.Header().Get("X-Response-Keep"))
	}
}

func TestFilterChain_URLRewrite(t *testing.T) {
	tests := []struct {
		name          string
		rewrite       *HTTPURLRewriteFilter
		matchedPrefix string
		inputPath     string
		inputHost     string
		expectedPath  string
		expectedHost  string
	}{
		{
			name: "rewrite hostname",
			rewrite: &HTTPURLRewriteFilter{
				Hostname: ptrString("new.example.com"),
			},
			inputPath:    "/api/v1",
			inputHost:    "old.example.com",
			expectedPath: "/api/v1",
			expectedHost: "new.example.com",
		},
		{
			name: "replace full path",
			rewrite: &HTTPURLRewriteFilter{
				Path: &HTTPPathModifier{
					Type:            PathModifierReplaceFullPath,
					ReplaceFullPath: ptrString("/new/path"),
				},
			},
			inputPath:    "/old/path",
			inputHost:    "example.com",
			expectedPath: "/new/path",
			expectedHost: "example.com",
		},
		{
			name: "replace prefix match",
			rewrite: &HTTPURLRewriteFilter{
				Path: &HTTPPathModifier{
					Type:               PathModifierReplacePrefixMatch,
					ReplacePrefixMatch: ptrString("/v2"),
				},
			},
			matchedPrefix: "/api",
			inputPath:     "/api/users",
			inputHost:     "example.com",
			expectedPath:  "/v2/users",
			expectedHost:  "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := []HTTPRouteFilter{
				{
					Type:       FilterTypeURLRewrite,
					URLRewrite: tt.rewrite,
				},
			}

			chain := NewFilterChain(filters)
			if tt.matchedPrefix != "" {
				chain.SetMatchedPrefix(tt.matchedPrefix)
			}
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.inputHost+tt.inputPath, nil)

			modifiedReq, _, _ := chain.ProcessRequest(req)

			if modifiedReq.URL.Path != tt.expectedPath {
				t.Errorf("Path = %q, want %q", modifiedReq.URL.Path, tt.expectedPath)
			}
			if modifiedReq.Host != tt.expectedHost {
				t.Errorf("Host = %q, want %q", modifiedReq.Host, tt.expectedHost)
			}
		})
	}
}

func TestFilterChain_RequestRedirect(t *testing.T) {
	tests := []struct {
		name           string
		redirect       *HTTPRequestRedirectFilter
		inputPath      string
		inputHost      string
		expectedStatus int
		expectedScheme string
		expectedHost   string
		expectedPath   string
	}{
		{
			name: "redirect scheme",
			redirect: &HTTPRequestRedirectFilter{
				Scheme:     ptrString("https"),
				StatusCode: ptrInt(301),
			},
			inputPath:      "/api",
			inputHost:      "example.com",
			expectedStatus: 301,
			expectedScheme: "https",
			expectedHost:   "example.com",
			expectedPath:   "/api",
		},
		{
			name: "redirect hostname",
			redirect: &HTTPRequestRedirectFilter{
				Hostname:   ptrString("new.example.com"),
				StatusCode: ptrInt(302),
			},
			inputPath:      "/api",
			inputHost:      "old.example.com",
			expectedStatus: 302,
			expectedScheme: "http",
			expectedHost:   "new.example.com",
			expectedPath:   "/api",
		},
		{
			name: "redirect with port",
			redirect: &HTTPRequestRedirectFilter{
				Port:       ptrInt32(8443),
				StatusCode: ptrInt(301),
			},
			inputPath:      "/api",
			inputHost:      "example.com",
			expectedStatus: 301,
			expectedScheme: "http",
			expectedHost:   "example.com:8443",
			expectedPath:   "/api",
		},
		{
			name: "redirect with path replacement",
			redirect: &HTTPRequestRedirectFilter{
				Path: &HTTPPathModifier{
					Type:            PathModifierReplaceFullPath,
					ReplaceFullPath: ptrString("/new-path"),
				},
			},
			inputPath:      "/old-path",
			inputHost:      "example.com",
			expectedStatus: 302, // Default
			expectedScheme: "http",
			expectedHost:   "example.com",
			expectedPath:   "/new-path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := []HTTPRouteFilter{
				{
					Type:            FilterTypeRequestRedirect,
					RequestRedirect: tt.redirect,
				},
			}

			chain := NewFilterChain(filters)
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.inputHost+tt.inputPath, nil)

			_, redirect, continueProcessing := chain.ProcessRequest(req)

			if continueProcessing {
				t.Error("ProcessRequest should not continue after redirect")
			}
			if redirect == nil {
				t.Fatal("ProcessRequest should return redirect")
			}

			if redirect.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", redirect.StatusCode, tt.expectedStatus)
			}

			// Parse the location to verify components
			if redirect.Location == "" {
				t.Error("Location should not be empty")
			}
		})
	}
}

func TestPathMatcher(t *testing.T) {
	tests := []struct {
		name      string
		pathMatch *HTTPPathMatch
		path      string
		expected  bool
	}{
		{
			name:      "nil path match (default prefix /)",
			pathMatch: nil,
			path:      "/anything",
			expected:  true,
		},
		{
			name: "exact match",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchExact),
				Value: ptrString("/api"),
			},
			path:     "/api",
			expected: true,
		},
		{
			name: "exact no match",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchExact),
				Value: ptrString("/api"),
			},
			path:     "/api/v1",
			expected: false,
		},
		{
			name: "prefix match",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchPathPrefix),
				Value: ptrString("/api"),
			},
			path:     "/api/users",
			expected: true,
		},
		{
			name: "prefix exact boundary",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchPathPrefix),
				Value: ptrString("/api"),
			},
			path:     "/api",
			expected: true,
		},
		{
			name: "prefix no match (partial word)",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchPathPrefix),
				Value: ptrString("/api"),
			},
			path:     "/apikey", // Should not match - not a proper prefix
			expected: false,
		},
		{
			name: "regex match",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchRegularExpression),
				Value: ptrString("/api/v[0-9]+/.*"),
			},
			path:     "/api/v2/users",
			expected: true,
		},
		{
			name: "regex no match",
			pathMatch: &HTTPPathMatch{
				Type:  ptrPathMatchType(PathMatchRegularExpression),
				Value: ptrString("/api/v[0-9]+/.*"),
			},
			path:     "/api/latest/users",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPathMatcher(tt.pathMatch)
			if err != nil {
				t.Fatalf("NewPathMatcher() error = %v", err)
			}

			result := pm.Match(tt.path)
			if result != tt.expected {
				t.Errorf("Match(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestHeaderMatcher(t *testing.T) {
	tests := []struct {
		name        string
		headerMatch HTTPHeaderMatch
		value       string
		expected    bool
	}{
		{
			name: "exact match",
			headerMatch: HTTPHeaderMatch{
				Type:  ptrHeaderMatchType(HeaderMatchExact),
				Name:  "X-Test",
				Value: "test-value",
			},
			value:    "test-value",
			expected: true,
		},
		{
			name: "exact no match",
			headerMatch: HTTPHeaderMatch{
				Type:  ptrHeaderMatchType(HeaderMatchExact),
				Name:  "X-Test",
				Value: "test-value",
			},
			value:    "other-value",
			expected: false,
		},
		{
			name: "regex match",
			headerMatch: HTTPHeaderMatch{
				Type:  ptrHeaderMatchType(HeaderMatchRegularExpression),
				Name:  "X-Version",
				Value: "v[0-9]+",
			},
			value:    "v2",
			expected: true,
		},
		{
			name: "regex no match",
			headerMatch: HTTPHeaderMatch{
				Type:  ptrHeaderMatchType(HeaderMatchRegularExpression),
				Name:  "X-Version",
				Value: "v[0-9]+",
			},
			value:    "latest",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hm, err := NewHeaderMatcher(&tt.headerMatch)
			if err != nil {
				t.Fatalf("NewHeaderMatcher() error = %v", err)
			}

			result := hm.Match(tt.value)
			if result != tt.expected {
				t.Errorf("Match(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestQueryParamMatcher(t *testing.T) {
	tests := []struct {
		name     string
		qpMatch  HTTPQueryParamMatch
		value    string
		expected bool
	}{
		{
			name: "exact match",
			qpMatch: HTTPQueryParamMatch{
				Type:  ptrQueryParamMatchType(QueryParamMatchExact),
				Name:  "version",
				Value: "2",
			},
			value:    "2",
			expected: true,
		},
		{
			name: "regex match",
			qpMatch: HTTPQueryParamMatch{
				Type:  ptrQueryParamMatchType(QueryParamMatchRegularExpression),
				Name:  "id",
				Value: "[0-9]+",
			},
			value:    "12345",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qm, err := NewQueryParamMatcher(&tt.qpMatch)
			if err != nil {
				t.Fatalf("NewQueryParamMatcher() error = %v", err)
			}

			result := qm.Match(tt.value)
			if result != tt.expected {
				t.Errorf("Match(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestTrafficSplitter(t *testing.T) {
	backends := []HTTPBackendRef{
		{
			BackendObjectReference: BackendObjectReference{Name: "backend-a"},
			Weight:                 ptrInt32(80),
		},
		{
			BackendObjectReference: BackendObjectReference{Name: "backend-b"},
			Weight:                 ptrInt32(20),
		},
	}

	ts := NewTrafficSplitter(backends)

	if ts.TotalWeight() != 100 {
		t.Errorf("TotalWeight() = %d, want 100", ts.TotalWeight())
	}

	if ts.BackendCount() != 2 {
		t.Errorf("BackendCount() = %d, want 2", ts.BackendCount())
	}

	// Test selection distribution
	aCount := 0
	bCount := 0
	for i := int32(0); i < 100; i++ {
		backend := ts.Select(i)
		if backend.Name == "backend-a" {
			aCount++
		} else if backend.Name == "backend-b" {
			bCount++
		}
	}

	// With weights 80/20, we should get approximately 80/20 distribution
	if aCount != 80 {
		t.Errorf("backend-a selected %d times, want 80", aCount)
	}
	if bCount != 20 {
		t.Errorf("backend-b selected %d times, want 20", bCount)
	}
}

func TestTrafficSplitter_DefaultWeight(t *testing.T) {
	// Backends without explicit weight should default to 1
	backends := []HTTPBackendRef{
		{BackendObjectReference: BackendObjectReference{Name: "backend-a"}},
		{BackendObjectReference: BackendObjectReference{Name: "backend-b"}},
	}

	ts := NewTrafficSplitter(backends)

	if ts.TotalWeight() != 2 {
		t.Errorf("TotalWeight() = %d, want 2", ts.TotalWeight())
	}
}

func TestTrafficSplitter_Empty(t *testing.T) {
	ts := NewTrafficSplitter(nil)

	if ts.BackendCount() != 0 {
		t.Errorf("BackendCount() = %d, want 0", ts.BackendCount())
	}

	backend := ts.Select(0)
	if backend != nil {
		t.Error("Select() should return nil for empty splitter")
	}
}

func TestFilterResponseWriter(t *testing.T) {
	filters := []HTTPRouteFilter{
		{
			Type: FilterTypeResponseHeaderModifier,
			ResponseHeaderModifier: &HTTPHeaderFilter{
				Set: []HTTPHeader{{Name: "X-Custom", Value: "added"}},
			},
		},
	}

	chain := NewFilterChain(filters)
	rec := httptest.NewRecorder()

	rw := &filterResponseWriter{
		ResponseWriter: rec,
		chain:          chain,
		headerWritten:  false,
	}

	// Write should trigger header processing
	rw.Write([]byte("test"))

	if rec.Header().Get("X-Custom") != "added" {
		t.Error("Response header should be modified before write")
	}
}

// Helper functions
func ptrInt(i int) *int {
	return &i
}

func ptrPathMatchType(t PathMatchType) *PathMatchType {
	return &t
}

func ptrHeaderMatchType(t HeaderMatchType) *HeaderMatchType {
	return &t
}

func ptrQueryParamMatchType(t QueryParamMatchType) *QueryParamMatchType {
	return &t
}
