package router

import (
	"net/http/httptest"
	"testing"

	"github.com/josedab/loom/internal/config"
)

func TestRouter_Match_ExactPath(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "exact",
			Path:     "/api/users",
			Methods:  []string{"GET"},
			Upstream: "backend",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	tests := []struct {
		name       string
		method     string
		path       string
		wantMatch  bool
		wantRoute  string
	}{
		{"exact match", "GET", "/api/users", true, "exact"},
		{"wrong method", "POST", "/api/users", false, ""},
		{"wrong path", "GET", "/api/posts", false, ""},
		{"partial path", "GET", "/api", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := r.Match(req)

			if tt.wantMatch {
				if result == nil {
					t.Errorf("expected match, got nil")
					return
				}
				if result.Route.ID != tt.wantRoute {
					t.Errorf("got route %s, want %s", result.Route.ID, tt.wantRoute)
				}
			} else {
				if result != nil {
					t.Errorf("expected no match, got route %s", result.Route.ID)
				}
			}
		})
	}
}

func TestRouter_Match_WildcardPath(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "wildcard",
			Path:     "/api/*",
			Methods:  []string{"GET", "POST"},
			Upstream: "backend",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	tests := []struct {
		name      string
		method    string
		path      string
		wantMatch bool
	}{
		{"matches subpath", "GET", "/api/users", true},
		{"matches deep path", "GET", "/api/users/123/posts", true},
		{"matches root", "GET", "/api/", true},
		{"wrong method", "DELETE", "/api/users", false},
		{"wrong prefix", "GET", "/v2/api/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := r.Match(req)

			if tt.wantMatch && result == nil {
				t.Errorf("expected match, got nil")
			}
			if !tt.wantMatch && result != nil {
				t.Errorf("expected no match, got route %s", result.Route.ID)
			}
		})
	}
}

func TestRouter_Match_PathParams(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "user",
			Path:     "/users/:id",
			Methods:  []string{"GET"},
			Upstream: "backend",
		},
		{
			ID:       "user-posts",
			Path:     "/users/:id/posts/:postId",
			Methods:  []string{"GET"},
			Upstream: "backend",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantRoute  string
		wantParams map[string]string
	}{
		{
			"single param",
			"/users/123",
			"user",
			map[string]string{"id": "123"},
		},
		{
			"multiple params",
			"/users/456/posts/789",
			"user-posts",
			map[string]string{"id": "456", "postId": "789"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			result := r.Match(req)

			if result == nil {
				t.Fatalf("expected match, got nil")
			}
			if result.Route.ID != tt.wantRoute {
				t.Errorf("got route %s, want %s", result.Route.ID, tt.wantRoute)
			}
			for k, v := range tt.wantParams {
				if result.Params[k] != v {
					t.Errorf("param %s: got %s, want %s", k, result.Params[k], v)
				}
			}
		})
	}
}

func TestRouter_Match_HostBased(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "api-host",
			Host:     "api.example.com",
			Path:     "/users",
			Methods:  []string{"GET"},
			Upstream: "api-backend",
		},
		{
			ID:       "www-host",
			Host:     "www.example.com",
			Path:     "/users",
			Methods:  []string{"GET"},
			Upstream: "www-backend",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	tests := []struct {
		name      string
		host      string
		wantRoute string
	}{
		{"api host", "api.example.com", "api-host"},
		{"www host", "www.example.com", "www-host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/users", nil)
			req.Host = tt.host
			result := r.Match(req)

			if result == nil {
				t.Fatalf("expected match, got nil")
			}
			if result.Route.ID != tt.wantRoute {
				t.Errorf("got route %s, want %s", result.Route.ID, tt.wantRoute)
			}
		})
	}
}

func TestRouter_Match_Priority(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "low-priority",
			Path:     "/api/*",
			Methods:  []string{"GET"},
			Upstream: "backend",
			Priority: 10,
		},
		{
			ID:       "high-priority",
			Path:     "/api/admin/*",
			Methods:  []string{"GET"},
			Upstream: "admin-backend",
			Priority: 100,
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	// Higher priority route should be checked first
	routes := r.GetRoutes()
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[0].Priority < routes[1].Priority {
		t.Error("routes not sorted by priority")
	}
}

func TestRouter_Match_Headers(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{
			ID:       "versioned",
			Path:     "/api/users",
			Methods:  []string{"GET"},
			Headers:  map[string]string{"X-API-Version": "v2"},
			Upstream: "backend-v2",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	t.Run("with matching header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/users", nil)
		req.Header.Set("X-API-Version", "v2")
		result := r.Match(req)

		if result == nil {
			t.Error("expected match with correct header")
		}
	})

	t.Run("without matching header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/users", nil)
		req.Header.Set("X-API-Version", "v1")
		result := r.Match(req)

		if result != nil {
			t.Error("expected no match with wrong header")
		}
	})
}

func TestRouter_GetRoutes(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{ID: "route1", Path: "/a", Upstream: "backend"},
		{ID: "route2", Path: "/b", Upstream: "backend"},
		{ID: "route3", Path: "/c", Upstream: "backend"},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	routes := r.GetRoutes()
	if len(routes) != 3 {
		t.Errorf("got %d routes, want 3", len(routes))
	}
}

func TestRouter_GetRoute(t *testing.T) {
	r := New()
	err := r.Configure([]config.RouteConfig{
		{ID: "test-route", Path: "/test", Upstream: "backend"},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	t.Run("existing route", func(t *testing.T) {
		route, ok := r.GetRoute("test-route")
		if !ok {
			t.Error("expected to find route")
		}
		if route.ID != "test-route" {
			t.Errorf("got route ID %s, want test-route", route.ID)
		}
	})

	t.Run("non-existing route", func(t *testing.T) {
		_, ok := r.GetRoute("non-existent")
		if ok {
			t.Error("expected not to find route")
		}
	})
}

func BenchmarkRouter_Match(b *testing.B) {
	r := New()
	configs := make([]config.RouteConfig, 100)
	for i := 0; i < 100; i++ {
		configs[i] = config.RouteConfig{
			ID:       "route-" + string(rune(i)),
			Path:     "/api/v1/resource" + string(rune(i)) + "/*",
			Methods:  []string{"GET", "POST", "PUT", "DELETE"},
			Upstream: "backend",
		}
	}
	r.Configure(configs)

	req := httptest.NewRequest("GET", "/api/v1/resource50/items/123", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Match(req)
	}
}
