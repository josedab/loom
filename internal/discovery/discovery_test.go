package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointHostPort(t *testing.T) {
	ep := Endpoint{Address: "192.168.1.1", Port: 8080}
	expected := "192.168.1.1:8080"
	if got := ep.HostPort(); got != expected {
		t.Errorf("HostPort() = %v, want %v", got, expected)
	}
}

func TestServiceHealthyEndpoints(t *testing.T) {
	service := &Service{
		Name: "test",
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Healthy: true},
			{Address: "2.2.2.2", Port: 80, Healthy: false},
			{Address: "3.3.3.3", Port: 80, Healthy: true},
		},
	}

	healthy := service.HealthyEndpoints()
	if len(healthy) != 2 {
		t.Errorf("HealthyEndpoints() returned %d, want 2", len(healthy))
	}

	for _, ep := range healthy {
		if !ep.Healthy {
			t.Error("HealthyEndpoints() returned unhealthy endpoint")
		}
	}
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	// Create static provider
	static := NewStaticProvider(nil)
	static.RegisterService("test-service", []Endpoint{
		{Address: "localhost", Port: 8080, Healthy: true},
	})

	registry.RegisterProvider(static)

	// Test discovery
	ctx := context.Background()
	service, err := registry.Discover(ctx, "test-service")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if service.Name != "test-service" {
		t.Errorf("service name = %v, want test-service", service.Name)
	}
	if len(service.Endpoints) != 1 {
		t.Errorf("endpoints count = %v, want 1", len(service.Endpoints))
	}

	// Test caching
	cached := registry.GetService("test-service")
	if cached == nil {
		t.Error("GetService() returned nil for cached service")
	}
}

func TestRegistryServiceNotFound(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	static := NewStaticProvider(nil)
	registry.RegisterProvider(static)

	ctx := context.Background()
	_, err := registry.Discover(ctx, "unknown-service")
	if err == nil {
		t.Error("Discover() should return error for unknown service")
	}
}

func TestRegistryWatch(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	static := NewStaticProvider(nil)
	static.RegisterService("watched-service", []Endpoint{
		{Address: "localhost", Port: 8080, Healthy: true},
	})

	registry.RegisterProvider(static)

	callbackCount := 0
	registry.Watch("watched-service", func(svc *Service) {
		callbackCount++
	})
	_ = callbackCount

	// Wait a bit for goroutines to start
	time.Sleep(50 * time.Millisecond)

	// Verify watcher was registered
	registry.mu.RLock()
	watchers := len(registry.watchers["watched-service"])
	registry.mu.RUnlock()

	if watchers != 1 {
		t.Errorf("expected 1 watcher, got %d", watchers)
	}
}

func TestStaticProvider(t *testing.T) {
	provider := NewStaticProvider(nil)

	if provider.Name() != "static" {
		t.Errorf("Name() = %v, want static", provider.Name())
	}

	// Register service
	provider.RegisterService("api", []Endpoint{
		{Address: "10.0.0.1", Port: 8080, Weight: 1, Healthy: true},
		{Address: "10.0.0.2", Port: 8080, Weight: 2, Healthy: true},
	})

	ctx := context.Background()
	service, err := provider.Discover(ctx, "api")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) != 2 {
		t.Errorf("endpoints count = %d, want 2", len(service.Endpoints))
	}
}

func TestStaticProviderNotFound(t *testing.T) {
	provider := NewStaticProvider(nil)
	ctx := context.Background()

	_, err := provider.Discover(ctx, "nonexistent")
	if err == nil {
		t.Error("Discover() should return error for nonexistent service")
	}
}

func TestDNSProvider(t *testing.T) {
	provider := NewDNSProvider(DNSConfig{
		DefaultPort: 80,
		TTL:         30 * time.Second,
	})

	if provider.Name() != "dns" {
		t.Errorf("Name() = %v, want dns", provider.Name())
	}

	// Test with localhost (should always resolve)
	ctx := context.Background()
	service, err := provider.Discover(ctx, "localhost")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) == 0 {
		t.Error("expected at least one endpoint for localhost")
	}

	// Verify endpoint port
	for _, ep := range service.Endpoints {
		if ep.Port != 80 {
			t.Errorf("endpoint port = %d, want 80", ep.Port)
		}
	}
}

func TestDNSProviderWithCustomDNS(t *testing.T) {
	provider := NewDNSProvider(DNSConfig{
		DNSServer:   "8.8.8.8:53",
		DefaultPort: 443,
		TTL:         1 * time.Minute,
	})

	if provider.dnsServer != "8.8.8.8:53" {
		t.Errorf("dnsServer = %v, want 8.8.8.8:53", provider.dnsServer)
	}
	if provider.port != 443 {
		t.Errorf("port = %d, want 443", provider.port)
	}
}

func TestConsulProvider(t *testing.T) {
	// Create mock Consul server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/health/service/") {
			w.Header().Set("X-Consul-Index", "1")
			json.NewEncoder(w).Encode([]consulServiceEntry{
				{
					Service: struct {
						ID      string            `json:"ID"`
						Service string            `json:"Service"`
						Tags    []string          `json:"Tags"`
						Address string            `json:"Address"`
						Port    int               `json:"Port"`
						Meta    map[string]string `json:"Meta"`
						Weights struct {
							Passing int `json:"Passing"`
							Warning int `json:"Warning"`
						} `json:"Weights"`
					}{
						ID:      "web-1",
						Service: "web",
						Tags:    []string{"v1", "primary"},
						Address: "10.0.0.1",
						Port:    8080,
						Meta:    map[string]string{"env": "prod"},
						Weights: struct {
							Passing int `json:"Passing"`
							Warning int `json:"Warning"`
						}{Passing: 10, Warning: 1},
					},
					Checks: []struct {
						Status string `json:"Status"`
					}{
						{Status: "passing"},
					},
				},
			})
		}
	}))
	defer server.Close()

	provider := NewConsulProvider(ConsulConfig{
		Address:    server.URL,
		Token:      "test-token",
		Datacenter: "dc1",
	})

	if provider.Name() != "consul" {
		t.Errorf("Name() = %v, want consul", provider.Name())
	}

	ctx := context.Background()
	service, err := provider.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) != 1 {
		t.Fatalf("endpoints count = %d, want 1", len(service.Endpoints))
	}

	ep := service.Endpoints[0]
	if ep.Address != "10.0.0.1" {
		t.Errorf("address = %v, want 10.0.0.1", ep.Address)
	}
	if ep.Port != 8080 {
		t.Errorf("port = %d, want 8080", ep.Port)
	}
	if ep.Weight != 10 {
		t.Errorf("weight = %d, want 10", ep.Weight)
	}
	if !ep.Healthy {
		t.Error("endpoint should be healthy")
	}
	if len(ep.Tags) != 2 {
		t.Errorf("tags count = %d, want 2", len(ep.Tags))
	}
}

func TestConsulProviderUnhealthyCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Consul-Index", "1")
		json.NewEncoder(w).Encode([]consulServiceEntry{
			{
				Service: struct {
					ID      string            `json:"ID"`
					Service string            `json:"Service"`
					Tags    []string          `json:"Tags"`
					Address string            `json:"Address"`
					Port    int               `json:"Port"`
					Meta    map[string]string `json:"Meta"`
					Weights struct {
						Passing int `json:"Passing"`
						Warning int `json:"Warning"`
					} `json:"Weights"`
				}{
					Address: "10.0.0.1",
					Port:    8080,
				},
				Checks: []struct {
					Status string `json:"Status"`
				}{
					{Status: "critical"},
				},
			},
		})
	}))
	defer server.Close()

	provider := NewConsulProvider(ConsulConfig{Address: server.URL})

	ctx := context.Background()
	service, err := provider.Discover(ctx, "test")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) != 1 {
		t.Fatalf("endpoints count = %d, want 1", len(service.Endpoints))
	}

	if service.Endpoints[0].Healthy {
		t.Error("endpoint should be unhealthy")
	}
}

func TestConsulProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	provider := NewConsulProvider(ConsulConfig{Address: server.URL})

	ctx := context.Background()
	_, err := provider.Discover(ctx, "test")
	if err == nil {
		t.Error("Discover() should return error for 500 response")
	}
}

func TestKubernetesProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/namespaces/default/endpoints/") {
			// Check authorization header
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			json.NewEncoder(w).Encode(k8sEndpoints{
				Kind: "Endpoints",
				Subsets: []struct {
					Addresses []struct {
						IP       string `json:"ip"`
						NodeName string `json:"nodeName"`
					} `json:"addresses"`
					NotReadyAddresses []struct {
						IP string `json:"ip"`
					} `json:"notReadyAddresses"`
					Ports []struct {
						Name string `json:"name"`
						Port int    `json:"port"`
					} `json:"ports"`
				}{
					{
						Addresses: []struct {
							IP       string `json:"ip"`
							NodeName string `json:"nodeName"`
						}{
							{IP: "10.0.0.1", NodeName: "node-1"},
							{IP: "10.0.0.2", NodeName: "node-2"},
						},
						NotReadyAddresses: []struct {
							IP string `json:"ip"`
						}{
							{IP: "10.0.0.3"},
						},
						Ports: []struct {
							Name string `json:"name"`
							Port int    `json:"port"`
						}{
							{Name: "http", Port: 8080},
						},
					},
				},
			})
		}
	}))
	defer server.Close()

	provider := NewKubernetesProvider(KubernetesConfig{
		APIServer: server.URL,
		Namespace: "default",
		Token:     "test-token",
	})

	if provider.Name() != "kubernetes" {
		t.Errorf("Name() = %v, want kubernetes", provider.Name())
	}

	ctx := context.Background()
	service, err := provider.Discover(ctx, "web")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) != 3 {
		t.Fatalf("endpoints count = %d, want 3", len(service.Endpoints))
	}

	// Check healthy endpoints
	healthy := 0
	unhealthy := 0
	for _, ep := range service.Endpoints {
		if ep.Healthy {
			healthy++
		} else {
			unhealthy++
		}
	}

	if healthy != 2 {
		t.Errorf("healthy count = %d, want 2", healthy)
	}
	if unhealthy != 1 {
		t.Errorf("unhealthy count = %d, want 1", unhealthy)
	}
}

func TestKubernetesProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	provider := NewKubernetesProvider(KubernetesConfig{
		APIServer: server.URL,
	})

	ctx := context.Background()
	_, err := provider.Discover(ctx, "nonexistent")
	if err == nil {
		t.Error("Discover() should return error for 404 response")
	}
}

func TestLoadBalancerRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)
	service := &Service{
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Healthy: true},
			{Address: "2.2.2.2", Port: 80, Healthy: true},
			{Address: "3.3.3.3", Port: 80, Healthy: true},
		},
	}

	// Should cycle through endpoints
	seen := make(map[string]int)
	for i := 0; i < 9; i++ {
		ep := lb.SelectEndpoint(service)
		seen[ep.Address]++
	}

	for addr, count := range seen {
		if count != 3 {
			t.Errorf("address %s selected %d times, want 3", addr, count)
		}
	}
}

func TestLoadBalancerSkipsUnhealthy(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)
	service := &Service{
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Healthy: true},
			{Address: "2.2.2.2", Port: 80, Healthy: false},
			{Address: "3.3.3.3", Port: 80, Healthy: true},
		},
	}

	for i := 0; i < 10; i++ {
		ep := lb.SelectEndpoint(service)
		if ep.Address == "2.2.2.2" {
			t.Error("should not select unhealthy endpoint")
		}
	}
}

func TestLoadBalancerNoHealthyEndpoints(t *testing.T) {
	lb := NewLoadBalancer(RoundRobin)
	service := &Service{
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Healthy: false},
			{Address: "2.2.2.2", Port: 80, Healthy: false},
		},
	}

	ep := lb.SelectEndpoint(service)
	if ep != nil {
		t.Error("should return nil when no healthy endpoints")
	}
}

func TestLoadBalancerWeighted(t *testing.T) {
	lb := NewLoadBalancer(WeightedRoundRobin)
	service := &Service{
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Weight: 3, Healthy: true},
			{Address: "2.2.2.2", Port: 80, Weight: 1, Healthy: true},
		},
	}

	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		ep := lb.SelectEndpoint(service)
		seen[ep.Address]++
	}

	// With weights 3:1, we expect roughly 75% and 25%
	if seen["1.1.1.1"] < 50 {
		t.Errorf("high-weight endpoint selected %d times, expected ~75", seen["1.1.1.1"])
	}
}

func TestHandler(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	static := NewStaticProvider(nil)
	static.RegisterService("api", []Endpoint{
		{Address: "localhost", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(static)

	// Cache the service
	ctx := context.Background()
	registry.Discover(ctx, "api")

	handler := NewHandler(registry, nil)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "list services",
			path:       "/discovery",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get service",
			path:       "/discovery/services/api",
			wantStatus: http.StatusOK,
		},
		{
			name:       "service not found",
			path:       "/discovery/services/unknown",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "not found path",
			path:       "/discovery/invalid",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandlerListServices(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	static := NewStaticProvider(nil)
	static.RegisterService("service1", []Endpoint{{Address: "1.1.1.1", Port: 80, Healthy: true}})
	static.RegisterService("service2", []Endpoint{{Address: "2.2.2.2", Port: 80, Healthy: true}})
	registry.RegisterProvider(static)

	// Cache services
	ctx := context.Background()
	registry.Discover(ctx, "service1")
	registry.Discover(ctx, "service2")

	handler := NewHandler(registry, nil)

	req := httptest.NewRequest("GET", "/discovery", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var services []*Service
	if err := json.NewDecoder(rec.Body).Decode(&services); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(services) != 2 {
		t.Errorf("services count = %d, want 2", len(services))
	}
}

func TestConsulProviderDefaults(t *testing.T) {
	provider := NewConsulProvider(ConsulConfig{})

	if provider.addr != "http://localhost:8500" {
		t.Errorf("default address = %v, want http://localhost:8500", provider.addr)
	}
}

func TestKubernetesProviderDefaults(t *testing.T) {
	provider := NewKubernetesProvider(KubernetesConfig{})

	if provider.namespace != "default" {
		t.Errorf("default namespace = %v, want default", provider.namespace)
	}
}

func TestDNSProviderDefaults(t *testing.T) {
	provider := NewDNSProvider(DNSConfig{})

	if provider.port != 80 {
		t.Errorf("default port = %d, want 80", provider.port)
	}
	if provider.ttl != 30*time.Second {
		t.Errorf("default TTL = %v, want 30s", provider.ttl)
	}
}

func TestRegistryMultipleProviders(t *testing.T) {
	registry := NewRegistry(nil)
	defer registry.Close()

	// First provider returns no results
	static1 := NewStaticProvider(nil)
	registry.RegisterProvider(static1)

	// Second provider has the service
	static2 := NewStaticProvider(nil)
	static2.RegisterService("test", []Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(static2)

	ctx := context.Background()
	service, err := registry.Discover(ctx, "test")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(service.Endpoints) != 1 {
		t.Errorf("endpoints count = %d, want 1", len(service.Endpoints))
	}
}

func TestConsulProviderEmptyAddress(t *testing.T) {
	// Test that when service address is empty, ID is used
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Consul-Index", "1")
		json.NewEncoder(w).Encode([]consulServiceEntry{
			{
				Service: struct {
					ID      string            `json:"ID"`
					Service string            `json:"Service"`
					Tags    []string          `json:"Tags"`
					Address string            `json:"Address"`
					Port    int               `json:"Port"`
					Meta    map[string]string `json:"Meta"`
					Weights struct {
						Passing int `json:"Passing"`
						Warning int `json:"Warning"`
					} `json:"Weights"`
				}{
					ID:      "service-id-fallback",
					Address: "", // Empty address
					Port:    8080,
				},
				Checks: []struct {
					Status string `json:"Status"`
				}{
					{Status: "passing"},
				},
			},
		})
	}))
	defer server.Close()

	provider := NewConsulProvider(ConsulConfig{Address: server.URL})

	ctx := context.Background()
	service, err := provider.Discover(ctx, "test")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if service.Endpoints[0].Address != "service-id-fallback" {
		t.Errorf("address = %v, want service-id-fallback", service.Endpoints[0].Address)
	}
}

func TestKubernetesProviderDefaultPort(t *testing.T) {
	// Test that when no ports are specified, default 80 is used
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(k8sEndpoints{
			Kind: "Endpoints",
			Subsets: []struct {
				Addresses []struct {
					IP       string `json:"ip"`
					NodeName string `json:"nodeName"`
				} `json:"addresses"`
				NotReadyAddresses []struct {
					IP string `json:"ip"`
				} `json:"notReadyAddresses"`
				Ports []struct {
					Name string `json:"name"`
					Port int    `json:"port"`
				} `json:"ports"`
			}{
				{
					Addresses: []struct {
						IP       string `json:"ip"`
						NodeName string `json:"nodeName"`
					}{
						{IP: "10.0.0.1"},
					},
					// No ports specified
				},
			},
		})
	}))
	defer server.Close()

	provider := NewKubernetesProvider(KubernetesConfig{APIServer: server.URL})

	ctx := context.Background()
	service, err := provider.Discover(ctx, "test")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if service.Endpoints[0].Port != 80 {
		t.Errorf("port = %d, want 80", service.Endpoints[0].Port)
	}
}

func TestLoadBalancerZeroWeight(t *testing.T) {
	lb := NewLoadBalancer(WeightedRoundRobin)
	service := &Service{
		Endpoints: []Endpoint{
			{Address: "1.1.1.1", Port: 80, Weight: 0, Healthy: true},
			{Address: "2.2.2.2", Port: 80, Weight: 0, Healthy: true},
		},
	}

	// Should still select endpoints when all weights are zero
	ep := lb.SelectEndpoint(service)
	if ep == nil {
		t.Error("should select endpoint even with zero weights")
	}
}
