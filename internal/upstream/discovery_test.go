package upstream

import (
	"testing"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/discovery"
)

func TestDiscoveryIntegration_ConfigureUpstream_Static(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name:      "test-upstream",
		Endpoints: []string{"localhost:8080", "localhost:8081"},
	}

	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	upstream, exists := manager.GetUpstream("test-upstream")
	if !exists {
		t.Fatal("upstream not found")
	}

	if len(upstream.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(upstream.Endpoints))
	}
}

func TestDiscoveryIntegration_ConfigureUpstream_WithDiscovery(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	// Register a static provider with test service
	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
		{Address: "10.0.0.2", Port: 8080, Healthy: true},
		{Address: "10.0.0.3", Port: 8080, Healthy: false}, // Unhealthy, should be excluded
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name: "test-upstream",
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			Provider:    "static",
			ServiceName: "my-service",
		},
	}

	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	upstream, exists := manager.GetUpstream("test-upstream")
	if !exists {
		t.Fatal("upstream not found")
	}

	// Should have 2 healthy endpoints
	if len(upstream.Endpoints) != 2 {
		t.Errorf("expected 2 healthy endpoints, got %d", len(upstream.Endpoints))
	}
}

func TestDiscoveryIntegration_RefreshUpstream(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name: "test-upstream",
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			ServiceName: "my-service",
		},
	}

	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update the service with more endpoints
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
		{Address: "10.0.0.2", Port: 8080, Healthy: true},
		{Address: "10.0.0.3", Port: 8080, Healthy: true},
	})

	// Refresh the upstream
	err = di.RefreshUpstream("test-upstream", "my-service")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	upstream, exists := manager.GetUpstream("test-upstream")
	if !exists {
		t.Fatal("upstream not found")
	}

	// Should now have 3 endpoints
	if len(upstream.Endpoints) != 3 {
		t.Errorf("expected 3 endpoints after refresh, got %d", len(upstream.Endpoints))
	}
}

func TestDiscoveryIntegration_GetDiscoveredEndpoints(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
		{Address: "10.0.0.2", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name: "test-upstream",
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			ServiceName: "my-service",
		},
	}

	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	endpoints := di.GetDiscoveredEndpoints("test-upstream")
	if len(endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(endpoints))
	}

	// Non-existent upstream should return nil
	endpoints = di.GetDiscoveredEndpoints("non-existent")
	if endpoints != nil {
		t.Error("expected nil for non-existent upstream")
	}
}

func TestDiscoveryIntegration_StopWatcher(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name: "test-upstream",
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			ServiceName: "my-service",
		},
	}

	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify watcher exists
	di.mu.Lock()
	_, exists := di.watchers["test-upstream"]
	di.mu.Unlock()
	if !exists {
		t.Error("expected watcher to be registered")
	}

	// Stop the watcher
	di.StopWatcher("test-upstream")

	// Verify watcher is removed
	di.mu.Lock()
	_, exists = di.watchers["test-upstream"]
	di.mu.Unlock()
	if exists {
		t.Error("expected watcher to be removed")
	}
}

func TestDiscoveryIntegration_Close(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("service-1", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
	})
	staticProvider.RegisterService("service-2", []discovery.Endpoint{
		{Address: "10.0.0.2", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)

	// Configure multiple upstreams
	for _, name := range []string{"upstream-1", "upstream-2"} {
		cfg := config.UpstreamConfig{
			Name: name,
			ServiceDiscovery: config.ServiceDiscoveryConfig{
				Enabled:     true,
				ServiceName: "service-1",
			},
		}
		if err := di.ConfigureUpstream(cfg); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Verify watchers exist
	di.mu.Lock()
	count := len(di.watchers)
	di.mu.Unlock()
	if count != 2 {
		t.Errorf("expected 2 watchers, got %d", count)
	}

	// Close should stop all watchers
	di.Close()

	di.mu.Lock()
	count = len(di.watchers)
	di.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 watchers after close, got %d", count)
	}
}

func TestDiscoveryIntegration_UpdateExistingUpstream(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	staticProvider := discovery.NewStaticProvider(nil)
	staticProvider.RegisterService("my-service", []discovery.Endpoint{
		{Address: "10.0.0.1", Port: 8080, Healthy: true},
	})
	registry.RegisterProvider(staticProvider)

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	// First, add a static upstream
	staticCfg := config.UpstreamConfig{
		Name:      "test-upstream",
		Endpoints: []string{"localhost:9999"},
	}
	err := manager.AddUpstream(staticCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now configure with discovery - should update
	cfg := config.UpstreamConfig{
		Name: "test-upstream",
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			ServiceName: "my-service",
		},
	}

	err = di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error updating upstream: %v", err)
	}

	upstream, exists := manager.GetUpstream("test-upstream")
	if !exists {
		t.Fatal("upstream not found")
	}

	// Should have discovered endpoint, not static
	if len(upstream.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(upstream.Endpoints))
	}
	if upstream.Endpoints[0].Address != "10.0.0.1:8080" {
		t.Errorf("expected discovered endpoint, got %s", upstream.Endpoints[0].Address)
	}
}

func TestDiscoveryIntegration_FallbackToStatic(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	// No providers registered, discovery will fail

	di := NewDiscoveryIntegration(manager, registry, nil)
	defer di.Close()

	cfg := config.UpstreamConfig{
		Name:      "test-upstream",
		Endpoints: []string{"fallback:8080"}, // Static fallback
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:     true,
			ServiceName: "unknown-service",
		},
	}

	// Should succeed even though discovery fails, using static endpoints
	err := di.ConfigureUpstream(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	upstream, exists := manager.GetUpstream("test-upstream")
	if !exists {
		t.Fatal("upstream not found")
	}

	// Should fall back to static endpoints
	if len(upstream.Endpoints) != 1 {
		t.Errorf("expected 1 fallback endpoint, got %d", len(upstream.Endpoints))
	}
}

func TestServiceToEndpoints(t *testing.T) {
	manager := NewManager()
	registry := discovery.NewRegistry(nil)
	defer registry.Close()

	di := NewDiscoveryIntegration(manager, registry, nil)

	service := &discovery.Service{
		Name: "test",
		Endpoints: []discovery.Endpoint{
			{Address: "10.0.0.1", Port: 8080, Healthy: true},
			{Address: "10.0.0.2", Port: 9090, Healthy: true},
			{Address: "10.0.0.3", Port: 7070, Healthy: false}, // Should be excluded
		},
	}

	endpoints := di.serviceToEndpoints(service)
	if len(endpoints) != 2 {
		t.Errorf("expected 2 healthy endpoints, got %d", len(endpoints))
	}

	expected := []string{"10.0.0.1:8080", "10.0.0.2:9090"}
	for i, ep := range endpoints {
		if ep != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], ep)
		}
	}
}
