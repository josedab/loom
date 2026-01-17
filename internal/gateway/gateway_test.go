package gateway

import (
	"context"
	"testing"
	"time"
)

func TestNewConverter(t *testing.T) {
	conv := NewConverter("test-controller")
	if conv == nil {
		t.Fatal("expected non-nil converter")
	}
	if conv.controllerName != "test-controller" {
		t.Errorf("expected controller name 'test-controller', got %q", conv.controllerName)
	}
}

func TestConvertGatewayToListeners(t *testing.T) {
	conv := NewConverter("test-controller")

	gw := &Gateway{
		Name:             "test-gateway",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{
				Name:     "http",
				Port:     80,
				Protocol: ProtocolHTTP,
			},
			{
				Name:     "https",
				Port:     443,
				Protocol: ProtocolHTTPS,
				TLS: &GatewayTLSConfig{
					Mode: TLSModeTerminate,
					CertificateRefs: []SecretObjectReference{
						{Name: "tls-secret", Namespace: "default"},
					},
				},
			},
		},
	}

	listeners, err := conv.ConvertGatewayToListeners(gw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}

	// Check HTTP listener
	if listeners[0].Name != "default-test-gateway-http" {
		t.Errorf("expected name 'default-test-gateway-http', got %q", listeners[0].Name)
	}
	if listeners[0].Address != ":80" {
		t.Errorf("expected address ':80', got %q", listeners[0].Address)
	}
	if listeners[0].Protocol != "http" {
		t.Errorf("expected protocol 'http', got %q", listeners[0].Protocol)
	}

	// Check HTTPS listener
	if listeners[1].Name != "default-test-gateway-https" {
		t.Errorf("expected name 'default-test-gateway-https', got %q", listeners[1].Name)
	}
	if listeners[1].TLS == nil {
		t.Error("expected TLS config for HTTPS listener")
	}
}

func TestConvertHTTPRouteToRoutes(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "test-route",
		Namespace: "default",
		Hostnames: []string{"api.example.com"},
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{
						Path: &HTTPPathMatch{
							Type:  PathMatchPathPrefix,
							Value: "/api",
						},
						Method: "GET",
					},
				},
				BackendRefs: []HTTPBackendRef{
					{
						BackendObjectReference: BackendObjectReference{
							Name:      "backend-svc",
							Namespace: "default",
							Port:      &port,
						},
					},
				},
			},
		},
	}

	routes, upstreams, err := conv.ConvertHTTPRouteToRoutes(route, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}

	// Check route
	if routes[0].Host != "api.example.com" {
		t.Errorf("expected host 'api.example.com', got %q", routes[0].Host)
	}
	if routes[0].Path != "/api/*" {
		t.Errorf("expected path '/api/*', got %q", routes[0].Path)
	}
	if len(routes[0].Methods) != 1 || routes[0].Methods[0] != "GET" {
		t.Errorf("expected methods [GET], got %v", routes[0].Methods)
	}

	// Check upstream
	if len(upstreams[0].Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(upstreams[0].Endpoints))
	}
	if upstreams[0].Endpoints[0] != "backend-svc.default:8080" {
		t.Errorf("expected endpoint 'backend-svc.default:8080', got %q", upstreams[0].Endpoints[0])
	}
}

func TestConvertPathMatch(t *testing.T) {
	conv := NewConverter("test-controller")

	tests := []struct {
		name     string
		match    *HTTPPathMatch
		expected string
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: "/*",
		},
		{
			name:     "exact match",
			match:    &HTTPPathMatch{Type: PathMatchExact, Value: "/api/v1"},
			expected: "/api/v1",
		},
		{
			name:     "prefix match",
			match:    &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api"},
			expected: "/api/*",
		},
		{
			name:     "prefix match with trailing slash",
			match:    &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api/"},
			expected: "/api/*",
		},
		{
			name:     "regex match",
			match:    &HTTPPathMatch{Type: PathMatchRegularExpression, Value: "/api/v[0-9]+"},
			expected: "/api/v[0-9]+",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := conv.convertPathMatch(tt.match)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestConvertProtocol(t *testing.T) {
	conv := NewConverter("test-controller")

	tests := []struct {
		input    Protocol
		expected string
	}{
		{ProtocolHTTP, "http"},
		{ProtocolHTTPS, "https"},
		{ProtocolTLS, "https"},
		{ProtocolTCP, "tcp"},
		{ProtocolUDP, "udp"},
		{"unknown", "http"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := conv.convertProtocol(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestValidateGateway(t *testing.T) {
	conv := NewConverter("test-controller")

	tests := []struct {
		name       string
		gateway    *Gateway
		expectErrs int
	}{
		{
			name: "valid gateway",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
				},
			},
			expectErrs: 0,
		},
		{
			name: "missing name",
			gateway: &Gateway{
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
				},
			},
			expectErrs: 1,
		},
		{
			name: "missing namespace",
			gateway: &Gateway{
				Name:             "test",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
				},
			},
			expectErrs: 1,
		},
		{
			name: "no listeners",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners:        []Listener{},
			},
			expectErrs: 1,
		},
		{
			name: "duplicate listener names",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
					{Name: "http", Port: 8080, Protocol: ProtocolHTTP},
				},
			},
			expectErrs: 1,
		},
		{
			name: "duplicate ports",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "http1", Port: 80, Protocol: ProtocolHTTP},
					{Name: "http2", Port: 80, Protocol: ProtocolHTTP},
				},
			},
			expectErrs: 1,
		},
		{
			name: "https without TLS",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{Name: "https", Port: 443, Protocol: ProtocolHTTPS},
				},
			},
			expectErrs: 1,
		},
		{
			name: "http with TLS",
			gateway: &Gateway{
				Name:             "test",
				Namespace:        "default",
				GatewayClassName: "loom",
				Listeners: []Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: ProtocolHTTP,
						TLS: &GatewayTLSConfig{
							CertificateRefs: []SecretObjectReference{
								{Name: "secret"},
							},
						},
					},
				},
			},
			expectErrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := conv.ValidateGateway(tt.gateway)
			if len(errs) != tt.expectErrs {
				t.Errorf("expected %d errors, got %d: %v", tt.expectErrs, len(errs), errs)
			}
		})
	}
}

func TestValidateHTTPRoute(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	negativeWeight := int32(-1)

	tests := []struct {
		name       string
		route      *HTTPRoute
		expectErrs int
	}{
		{
			name: "valid route",
			route: &HTTPRoute{
				Name:      "test",
				Namespace: "default",
				Rules: []HTTPRouteRule{
					{
						BackendRefs: []HTTPBackendRef{
							{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
						},
					},
				},
			},
			expectErrs: 0,
		},
		{
			name: "missing name",
			route: &HTTPRoute{
				Namespace: "default",
				Rules: []HTTPRouteRule{
					{BackendRefs: []HTTPBackendRef{{BackendObjectReference: BackendObjectReference{Name: "svc"}}}},
				},
			},
			expectErrs: 1,
		},
		{
			name: "no rules",
			route: &HTTPRoute{
				Name:      "test",
				Namespace: "default",
				Rules:     []HTTPRouteRule{},
			},
			expectErrs: 1,
		},
		{
			name: "no backend refs",
			route: &HTTPRoute{
				Name:      "test",
				Namespace: "default",
				Rules: []HTTPRouteRule{
					{BackendRefs: []HTTPBackendRef{}},
				},
			},
			expectErrs: 1,
		},
		{
			name: "backend without name",
			route: &HTTPRoute{
				Name:      "test",
				Namespace: "default",
				Rules: []HTTPRouteRule{
					{BackendRefs: []HTTPBackendRef{{BackendObjectReference: BackendObjectReference{Port: &port}}}},
				},
			},
			expectErrs: 1,
		},
		{
			name: "negative weight",
			route: &HTTPRoute{
				Name:      "test",
				Namespace: "default",
				Rules: []HTTPRouteRule{
					{BackendRefs: []HTTPBackendRef{{
						BackendObjectReference: BackendObjectReference{Name: "svc"},
						Weight:                 &negativeWeight,
					}}},
				},
			},
			expectErrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := conv.ValidateHTTPRoute(tt.route)
			if len(errs) != tt.expectErrs {
				t.Errorf("expected %d errors, got %d: %v", tt.expectErrs, len(errs), errs)
			}
		})
	}
}

func TestNewController(t *testing.T) {
	ctrl := NewController(ControllerConfig{})
	if ctrl == nil {
		t.Fatal("expected non-nil controller")
	}
	if ctrl.controllerName != DefaultControllerName {
		t.Errorf("expected default controller name, got %q", ctrl.controllerName)
	}
}

func TestControllerAddRemoveGateway(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	gw := &Gateway{
		Name:             "test-gw",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{Name: "http", Port: 80, Protocol: ProtocolHTTP},
		},
	}

	// Add gateway
	err := ctrl.AddGateway(gw)
	if err != nil {
		t.Fatalf("unexpected error adding gateway: %v", err)
	}

	// Get gateway
	got := ctrl.GetGateway("default", "test-gw")
	if got == nil {
		t.Fatal("expected to get gateway")
	}
	if got.Name != "test-gw" {
		t.Errorf("expected name 'test-gw', got %q", got.Name)
	}

	// List gateways
	gateways := ctrl.ListGateways()
	if len(gateways) != 1 {
		t.Errorf("expected 1 gateway, got %d", len(gateways))
	}

	// Remove gateway
	ctrl.RemoveGateway("default", "test-gw")

	// Verify removed
	got = ctrl.GetGateway("default", "test-gw")
	if got != nil {
		t.Error("expected gateway to be removed")
	}
}

func TestControllerAddRemoveHTTPRoute(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []HTTPRouteRule{
			{
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
				},
			},
		},
	}

	// Add route
	err := ctrl.AddHTTPRoute(route)
	if err != nil {
		t.Fatalf("unexpected error adding route: %v", err)
	}

	// Get route
	got := ctrl.GetHTTPRoute("default", "test-route")
	if got == nil {
		t.Fatal("expected to get route")
	}
	if got.Name != "test-route" {
		t.Errorf("expected name 'test-route', got %q", got.Name)
	}

	// List routes
	routes := ctrl.ListHTTPRoutes()
	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}

	// Remove route
	ctrl.RemoveHTTPRoute("default", "test-route")

	// Verify removed
	got = ctrl.GetHTTPRoute("default", "test-route")
	if got != nil {
		t.Error("expected route to be removed")
	}
}

func TestControllerGetConfig(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	// Add gateway
	gw := &Gateway{
		Name:             "test-gw",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{Name: "http", Port: 80, Protocol: ProtocolHTTP},
		},
	}
	_ = ctrl.AddGateway(gw)

	// Add route
	port := int32(8080)
	route := &HTTPRoute{
		Name:      "test-route",
		Namespace: "default",
		Hostnames: []string{"api.example.com"},
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api"}},
				},
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
				},
			},
		},
	}
	_ = ctrl.AddHTTPRoute(route)

	// Get config
	cfg, err := ctrl.GetConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if len(cfg.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Routes))
	}
	if len(cfg.Upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
}

func TestControllerOnConfigChange(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	var receivedConfig *GatewayAPIConfig
	ctrl.OnConfigChange(func(cfg *GatewayAPIConfig) {
		receivedConfig = cfg
	})

	// Start controller
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctrl.Start(ctx)

	// Add gateway to trigger sync
	gw := &Gateway{
		Name:             "test-gw",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{Name: "http", Port: 80, Protocol: ProtocolHTTP},
		},
	}
	_ = ctrl.AddGateway(gw)

	// Wait for sync
	time.Sleep(100 * time.Millisecond)

	if receivedConfig == nil {
		t.Error("expected config callback to be called")
	}
}

func TestControllerAddGatewayClass(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	gc := &GatewayClass{
		Name:           "loom",
		ControllerName: "loom.io/gateway-controller",
		Description:    "Loom API Gateway",
	}

	err := ctrl.AddGatewayClass(gc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Remove it
	ctrl.RemoveGatewayClass("loom")
}

func TestControllerExportToConfig(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	// Add gateway
	gw := &Gateway{
		Name:             "test-gw",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{Name: "http", Port: 80, Protocol: ProtocolHTTP},
		},
	}
	_ = ctrl.AddGateway(gw)

	// Export to config
	cfg, err := ctrl.ExportToConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(cfg.Listeners))
	}
}

func TestControllerLoadFromJSON(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	gatewaysJSON := []byte(`[
		{
			"name": "test-gw",
			"namespace": "default",
			"gatewayClassName": "loom",
			"listeners": [
				{"name": "http", "port": 80, "protocol": "HTTP"}
			]
		}
	]`)

	routesJSON := []byte(`[
		{
			"name": "test-route",
			"namespace": "default",
			"rules": [
				{
					"backendRefs": [
						{"name": "svc", "port": 8080}
					]
				}
			]
		}
	]`)

	err := ctrl.LoadFromJSON(gatewaysJSON, routesJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify loaded
	gw := ctrl.GetGateway("default", "test-gw")
	if gw == nil {
		t.Error("expected gateway to be loaded")
	}

	route := ctrl.GetHTTPRoute("default", "test-route")
	if route == nil {
		t.Error("expected route to be loaded")
	}
}

func TestBuildServiceEndpoint(t *testing.T) {
	endpoint := BuildServiceEndpoint("my-svc", "my-ns", 8080)
	expected := "my-svc.my-ns.svc.cluster.local:8080"
	if endpoint != expected {
		t.Errorf("expected %q, got %q", expected, endpoint)
	}
}

func TestParseServiceEndpoint(t *testing.T) {
	tests := []struct {
		endpoint  string
		name      string
		namespace string
		port      int32
		expectErr bool
	}{
		{
			endpoint:  "my-svc.my-ns.svc.cluster.local:8080",
			name:      "my-svc",
			namespace: "my-ns",
			port:      8080,
		},
		{
			endpoint:  "svc.default:80",
			name:      "svc",
			namespace: "default",
			port:      80,
		},
		{
			endpoint:  "invalid",
			expectErr: true,
		},
		{
			endpoint:  "svc:invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			name, ns, port, err := ParseServiceEndpoint(tt.endpoint)
			if tt.expectErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, name)
			}
			if ns != tt.namespace {
				t.Errorf("expected namespace %q, got %q", tt.namespace, ns)
			}
			if port != tt.port {
				t.Errorf("expected port %d, got %d", tt.port, port)
			}
		})
	}
}

func TestControllerStartStop(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start controller
	err := ctrl.Start(ctx)
	if err != nil {
		t.Fatalf("unexpected error starting controller: %v", err)
	}

	// Start again should fail
	err = ctrl.Start(ctx)
	if err == nil {
		t.Error("expected error starting controller twice")
	}

	// Stop controller
	ctrl.Stop()

	// Stop again should be safe
	ctrl.Stop()
}

func TestControllerCountRoutesForListener(t *testing.T) {
	ctrl := NewController(ControllerConfig{})

	// Add gateway
	gw := &Gateway{
		Name:             "test-gw",
		Namespace:        "default",
		GatewayClassName: "loom",
		Listeners: []Listener{
			{Name: "http", Port: 80, Protocol: ProtocolHTTP},
			{Name: "https", Port: 443, Protocol: ProtocolHTTPS},
		},
	}
	_ = ctrl.AddGateway(gw)

	// Add routes
	port := int32(8080)
	route1 := &HTTPRoute{
		Name:      "route1",
		Namespace: "default",
		ParentRefs: []ParentReference{
			{Name: "test-gw", SectionName: "http"},
		},
		Rules: []HTTPRouteRule{
			{BackendRefs: []HTTPBackendRef{{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}}}},
		},
	}
	_ = ctrl.AddHTTPRoute(route1)

	route2 := &HTTPRoute{
		Name:      "route2",
		Namespace: "default",
		ParentRefs: []ParentReference{
			{Name: "test-gw"}, // No section name - matches all
		},
		Rules: []HTTPRouteRule{
			{BackendRefs: []HTTPBackendRef{{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}}}},
		},
	}
	_ = ctrl.AddHTTPRoute(route2)

	// Count routes for http listener
	count := ctrl.countRoutesForListener(gw, "http")
	if count != 2 {
		t.Errorf("expected 2 routes for http listener, got %d", count)
	}

	// Count routes for https listener
	count = ctrl.countRoutesForListener(gw, "https")
	if count != 1 {
		t.Errorf("expected 1 route for https listener, got %d", count)
	}
}

func TestHTTPRouteMultipleRules(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "multi-rule",
		Namespace: "default",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{Path: &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api/v1"}},
				},
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc-v1", Port: &port}},
				},
			},
			{
				Matches: []HTTPRouteMatch{
					{Path: &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api/v2"}},
				},
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc-v2", Port: &port}},
				},
			},
		},
	}

	routes, upstreams, err := conv.ConvertHTTPRouteToRoutes(route, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}

	if len(upstreams) != 2 {
		t.Errorf("expected 2 upstreams, got %d", len(upstreams))
	}
}

func TestHTTPRouteWithHeaders(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "header-route",
		Namespace: "default",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{
						Path: &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api"},
						Headers: []HTTPHeaderMatch{
							{Name: "X-Version", Value: "v1", Type: HeaderMatchExact},
						},
					},
				},
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
				},
			},
		},
	}

	routes, _, err := conv.ConvertHTTPRouteToRoutes(route, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	if routes[0].Headers == nil {
		t.Fatal("expected headers to be set")
	}

	if routes[0].Headers["X-Version"] != "v1" {
		t.Errorf("expected header X-Version=v1, got %q", routes[0].Headers["X-Version"])
	}
}

func TestHTTPRouteWithQueryParams(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "query-route",
		Namespace: "default",
		Rules: []HTTPRouteRule{
			{
				Matches: []HTTPRouteMatch{
					{
						Path: &HTTPPathMatch{Type: PathMatchPathPrefix, Value: "/api"},
						QueryParams: []HTTPQueryParamMatch{
							{Name: "version", Value: "v1", Type: QueryParamMatchExact},
						},
					},
				},
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
				},
			},
		},
	}

	routes, _, err := conv.ConvertHTTPRouteToRoutes(route, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	if routes[0].QueryParams == nil {
		t.Fatal("expected query params to be set")
	}

	if routes[0].QueryParams["version"] != "v1" {
		t.Errorf("expected query param version=v1, got %q", routes[0].QueryParams["version"])
	}
}

func TestHTTPRouteWithTimeout(t *testing.T) {
	conv := NewConverter("test-controller")

	port := int32(8080)
	route := &HTTPRoute{
		Name:      "timeout-route",
		Namespace: "default",
		Rules: []HTTPRouteRule{
			{
				BackendRefs: []HTTPBackendRef{
					{BackendObjectReference: BackendObjectReference{Name: "svc", Port: &port}},
				},
				Timeouts: &HTTPRouteTimeouts{
					Request: "30s",
				},
			},
		},
	}

	routes, _, err := conv.ConvertHTTPRouteToRoutes(route, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	if routes[0].Timeout != "30s" {
		t.Errorf("expected timeout '30s', got %q", routes[0].Timeout)
	}
}

func TestConditionTypes(t *testing.T) {
	// Test condition status values
	if ConditionTrue != "True" {
		t.Errorf("expected ConditionTrue to be 'True'")
	}
	if ConditionFalse != "False" {
		t.Errorf("expected ConditionFalse to be 'False'")
	}
	if ConditionUnknown != "Unknown" {
		t.Errorf("expected ConditionUnknown to be 'Unknown'")
	}
}

func TestProtocolTypes(t *testing.T) {
	// Test protocol values
	if ProtocolHTTP != "HTTP" {
		t.Errorf("expected ProtocolHTTP to be 'HTTP'")
	}
	if ProtocolHTTPS != "HTTPS" {
		t.Errorf("expected ProtocolHTTPS to be 'HTTPS'")
	}
	if ProtocolTLS != "TLS" {
		t.Errorf("expected ProtocolTLS to be 'TLS'")
	}
}

func TestTLSModeTypes(t *testing.T) {
	if TLSModeTerminate != "Terminate" {
		t.Errorf("expected TLSModeTerminate to be 'Terminate'")
	}
	if TLSModePassthrough != "Passthrough" {
		t.Errorf("expected TLSModePassthrough to be 'Passthrough'")
	}
}
