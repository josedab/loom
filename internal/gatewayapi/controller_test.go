package gatewayapi

import (
	"context"
	"testing"
)

func TestController_GatewayClass(t *testing.T) {
	c := NewController(nil)

	gc := &GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec: GatewayClassSpec{
			ControllerName: ControllerName,
			Description:    "Loom API Gateway",
		},
	}

	// Add GatewayClass
	err := c.SetGatewayClass(gc)
	if err != nil {
		t.Fatalf("SetGatewayClass() error = %v", err)
	}

	// Verify status
	if len(gc.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(gc.Status.Conditions))
	}
	if gc.Status.Conditions[0].Type != "Accepted" {
		t.Errorf("Expected Accepted condition, got %s", gc.Status.Conditions[0].Type)
	}

	// Wrong controller name should fail
	gc2 := &GatewayClass{
		ObjectMeta: ObjectMeta{Name: "other"},
		Spec: GatewayClassSpec{
			ControllerName: "other.io/controller",
		},
	}
	err = c.SetGatewayClass(gc2)
	if err == nil {
		t.Error("SetGatewayClass() should fail with wrong controller name")
	}

	// Delete
	c.DeleteGatewayClass("loom")
}

func TestController_Gateway(t *testing.T) {
	c := NewController(nil)

	// First add GatewayClass
	gc := &GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec: GatewayClassSpec{
			ControllerName: ControllerName,
		},
	}
	c.SetGatewayClass(gc)

	// Add Gateway
	gw := &Gateway{
		ObjectMeta: ObjectMeta{
			Name:      "main",
			Namespace: "default",
		},
		Spec: GatewaySpec{
			GatewayClassName: "loom",
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: HTTPSProtocolType,
				},
			},
		},
	}

	err := c.SetGateway(gw)
	if err != nil {
		t.Fatalf("SetGateway() error = %v", err)
	}

	// Verify status
	if len(gw.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions, got %d", len(gw.Status.Conditions))
	}
	if len(gw.Status.Listeners) != 2 {
		t.Errorf("Expected 2 listener statuses, got %d", len(gw.Status.Listeners))
	}

	// Get Gateway
	retrieved, ok := c.GetGateway("default", "main")
	if !ok {
		t.Error("GetGateway() should find the gateway")
	}
	if retrieved.Name != "main" {
		t.Errorf("GetGateway() name = %s, want main", retrieved.Name)
	}

	// Verify listeners config generated
	listeners := c.GetListeners()
	if len(listeners) != 2 {
		t.Errorf("Expected 2 listeners, got %d", len(listeners))
	}

	// Delete
	c.DeleteGateway("default", "main")
	_, ok = c.GetGateway("default", "main")
	if ok {
		t.Error("Gateway should be deleted")
	}
}

func TestController_HTTPRoute(t *testing.T) {
	c := NewController(nil)

	// Setup GatewayClass and Gateway
	c.SetGatewayClass(&GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec:       GatewayClassSpec{ControllerName: ControllerName},
	})

	c.SetGateway(&Gateway{
		ObjectMeta: ObjectMeta{Name: "main", Namespace: "default"},
		Spec: GatewaySpec{
			GatewayClassName: "loom",
			Listeners: []Listener{
				{Name: "http", Port: 80, Protocol: HTTPProtocolType},
			},
		},
	})

	// Add HTTPRoute
	pathPrefix := PathMatchPathPrefix
	pathValue := "/api"
	route := &HTTPRoute{
		ObjectMeta: ObjectMeta{
			Name:      "api-route",
			Namespace: "default",
		},
		Spec: HTTPRouteSpec{
			ParentRefs: []ParentReference{
				{Name: "main"},
			},
			Hostnames: []string{"api.example.com"},
			Rules: []HTTPRouteRule{
				{
					Matches: []HTTPRouteMatch{
						{
							Path: &HTTPPathMatch{
								Type:  &pathPrefix,
								Value: &pathValue,
							},
						},
					},
					BackendRefs: []HTTPBackendRef{
						{
							BackendObjectReference: BackendObjectReference{
								Name: "api-service",
								Port: ptrInt32(8080),
							},
						},
					},
				},
			},
		},
	}

	err := c.SetHTTPRoute(route)
	if err != nil {
		t.Fatalf("SetHTTPRoute() error = %v", err)
	}

	// Verify routes generated
	routes := c.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(routes))
	}
	if routes[0].Host != "api.example.com" {
		t.Errorf("Route host = %s, want api.example.com", routes[0].Host)
	}

	// Verify upstreams generated
	upstreams := c.GetUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("Expected 1 upstream, got %d", len(upstreams))
	}

	// Get HTTPRoute
	retrieved, ok := c.GetHTTPRoute("default", "api-route")
	if !ok {
		t.Error("GetHTTPRoute() should find the route")
	}
	if retrieved.Name != "api-route" {
		t.Errorf("GetHTTPRoute() name = %s, want api-route", retrieved.Name)
	}

	// Delete
	c.DeleteHTTPRoute("default", "api-route")
	routes = c.GetRoutes()
	if len(routes) != 0 {
		t.Errorf("Routes should be empty after delete")
	}
}

func TestController_MatchRequest(t *testing.T) {
	c := NewController(nil)

	// Setup
	c.SetGatewayClass(&GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec:       GatewayClassSpec{ControllerName: ControllerName},
	})

	c.SetGateway(&Gateway{
		ObjectMeta: ObjectMeta{Name: "main", Namespace: "default"},
		Spec: GatewaySpec{
			GatewayClassName: "loom",
			Listeners:        []Listener{{Name: "http", Port: 80, Protocol: HTTPProtocolType}},
		},
	})

	// Add routes with different matches
	exact := PathMatchExact
	exactPath := "/exact"
	prefix := PathMatchPathPrefix
	prefixPath := "/api"
	getMethod := HTTPMethodGet

	route := &HTTPRoute{
		ObjectMeta: ObjectMeta{Name: "test-route", Namespace: "default"},
		Spec: HTTPRouteSpec{
			ParentRefs: []ParentReference{{Name: "main"}},
			Hostnames:  []string{"test.example.com"},
			Rules: []HTTPRouteRule{
				{
					Matches: []HTTPRouteMatch{
						{
							Path:   &HTTPPathMatch{Type: &exact, Value: &exactPath},
							Method: &getMethod,
						},
					},
					BackendRefs: []HTTPBackendRef{
						{BackendObjectReference: BackendObjectReference{Name: "exact-svc"}},
					},
				},
				{
					Matches: []HTTPRouteMatch{
						{
							Path: &HTTPPathMatch{Type: &prefix, Value: &prefixPath},
						},
					},
					BackendRefs: []HTTPBackendRef{
						{BackendObjectReference: BackendObjectReference{Name: "api-svc"}},
					},
				},
			},
		},
	}
	c.SetHTTPRoute(route)

	ctx := context.Background()

	// Test exact match
	matches := c.MatchRequest(ctx, "test.example.com", "/exact", "GET", nil)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match for exact path, got %d", len(matches))
	}

	// Test prefix match
	matches = c.MatchRequest(ctx, "test.example.com", "/api/users", "POST", nil)
	if len(matches) != 1 {
		t.Errorf("Expected 1 match for prefix path, got %d", len(matches))
	}

	// Test no match (wrong host)
	matches = c.MatchRequest(ctx, "other.example.com", "/api", "GET", nil)
	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for wrong host, got %d", len(matches))
	}

	// Test no match (wrong method for exact path)
	matches = c.MatchRequest(ctx, "test.example.com", "/exact", "POST", nil)
	if len(matches) != 0 {
		t.Errorf("Expected 0 matches for wrong method, got %d", len(matches))
	}
}

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		hostnames []string
		expected  bool
	}{
		{
			name:      "exact match",
			host:      "api.example.com",
			hostnames: []string{"api.example.com"},
			expected:  true,
		},
		{
			name:      "wildcard match",
			host:      "api.example.com",
			hostnames: []string{"*.example.com"},
			expected:  true,
		},
		{
			name:      "wildcard no match",
			host:      "api.other.com",
			hostnames: []string{"*.example.com"},
			expected:  false,
		},
		{
			name:      "multiple hostnames",
			host:      "api.example.com",
			hostnames: []string{"web.example.com", "api.example.com"},
			expected:  true,
		},
		{
			name:      "no match",
			host:      "api.example.com",
			hostnames: []string{"web.example.com"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchHostname(tt.host, tt.hostnames)
			if result != tt.expected {
				t.Errorf("matchHostname(%q, %v) = %v, want %v",
					tt.host, tt.hostnames, result, tt.expected)
			}
		})
	}
}

func TestMatchHTTPRequest(t *testing.T) {
	exact := PathMatchExact
	prefix := PathMatchPathPrefix
	regex := PathMatchRegularExpression
	exactHeader := HeaderMatchExact

	tests := []struct {
		name     string
		match    HTTPRouteMatch
		path     string
		method   string
		headers  map[string]string
		expected bool
	}{
		{
			name: "exact path match",
			match: HTTPRouteMatch{
				Path: &HTTPPathMatch{Type: &exact, Value: ptrString("/api")},
			},
			path:     "/api",
			expected: true,
		},
		{
			name: "exact path no match",
			match: HTTPRouteMatch{
				Path: &HTTPPathMatch{Type: &exact, Value: ptrString("/api")},
			},
			path:     "/api/v1",
			expected: false,
		},
		{
			name: "prefix match",
			match: HTTPRouteMatch{
				Path: &HTTPPathMatch{Type: &prefix, Value: ptrString("/api")},
			},
			path:     "/api/users",
			expected: true,
		},
		{
			name: "regex match",
			match: HTTPRouteMatch{
				Path: &HTTPPathMatch{Type: &regex, Value: ptrString("/api/v[0-9]+")},
			},
			path:     "/api/v2",
			expected: true,
		},
		{
			name: "method match",
			match: HTTPRouteMatch{
				Method: ptrMethod(HTTPMethodGet),
			},
			path:     "/any",
			method:   "GET",
			expected: true,
		},
		{
			name: "method no match",
			match: HTTPRouteMatch{
				Method: ptrMethod(HTTPMethodGet),
			},
			path:     "/any",
			method:   "POST",
			expected: false,
		},
		{
			name: "header match",
			match: HTTPRouteMatch{
				Headers: []HTTPHeaderMatch{
					{Type: &exactHeader, Name: "X-Custom", Value: "test"},
				},
			},
			path:     "/any",
			headers:  map[string]string{"X-Custom": "test"},
			expected: true,
		},
		{
			name: "header no match",
			match: HTTPRouteMatch{
				Headers: []HTTPHeaderMatch{
					{Type: &exactHeader, Name: "X-Custom", Value: "test"},
				},
			},
			path:     "/any",
			headers:  map[string]string{"X-Custom": "other"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchHTTPRequest(&tt.match, tt.path, tt.method, tt.headers)
			if result != tt.expected {
				t.Errorf("matchHTTPRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestController_GRPCRoute(t *testing.T) {
	c := NewController(nil)

	// Setup
	c.SetGatewayClass(&GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec:       GatewayClassSpec{ControllerName: ControllerName},
	})

	c.SetGateway(&Gateway{
		ObjectMeta: ObjectMeta{Name: "main", Namespace: "default"},
		Spec: GatewaySpec{
			GatewayClassName: "loom",
			Listeners:        []Listener{{Name: "grpc", Port: 9090, Protocol: GRPCProtocolType}},
		},
	})

	// Add GRPCRoute
	route := &GRPCRoute{
		ObjectMeta: ObjectMeta{Name: "grpc-route", Namespace: "default"},
		Spec: GRPCRouteSpec{
			ParentRefs: []ParentReference{{Name: "main"}},
			Hostnames:  []string{"grpc.example.com"},
			Rules: []GRPCRouteRule{
				{
					Matches: []GRPCRouteMatch{
						{
							Method: &GRPCMethodMatch{
								Service: ptrString("mypackage.MyService"),
								Method:  ptrString("GetUser"),
							},
						},
					},
					BackendRefs: []GRPCBackendRef{
						{
							BackendObjectReference: BackendObjectReference{
								Name: "grpc-service",
								Port: ptrInt32(9090),
							},
						},
					},
				},
			},
		},
	}

	err := c.SetGRPCRoute(route)
	if err != nil {
		t.Fatalf("SetGRPCRoute() error = %v", err)
	}

	// Verify routes generated
	routes := c.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(routes))
	}
	if routes[0].Path != "/mypackage.MyService/GetUser" {
		t.Errorf("Route path = %s, want /mypackage.MyService/GetUser", routes[0].Path)
	}

	// Delete
	c.DeleteGRPCRoute("default", "grpc-route")
}

func TestController_Generation(t *testing.T) {
	c := NewController(nil)

	initialGen := c.Generation()

	// Setup and changes should increment generation
	c.SetGatewayClass(&GatewayClass{
		ObjectMeta: ObjectMeta{Name: "loom"},
		Spec:       GatewayClassSpec{ControllerName: ControllerName},
	})

	c.SetGateway(&Gateway{
		ObjectMeta: ObjectMeta{Name: "main", Namespace: "default"},
		Spec: GatewaySpec{
			GatewayClassName: "loom",
			Listeners:        []Listener{{Name: "http", Port: 80, Protocol: HTTPProtocolType}},
		},
	})

	if c.Generation() <= initialGen {
		t.Error("Generation should increase after changes")
	}
}

// Helper functions
func ptrString(s string) *string {
	return &s
}

func ptrInt32(i int32) *int32 {
	return &i
}

func ptrMethod(m HTTPMethod) *HTTPMethod {
	return &m
}
