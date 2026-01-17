// Package upstream provides backend connection management with load balancing.
package upstream

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/discovery"
)

// DiscoveryIntegration connects the upstream manager with service discovery.
type DiscoveryIntegration struct {
	manager  *Manager
	registry *discovery.Registry
	watchers map[string]context.CancelFunc
	mu       sync.Mutex
	logger   *slog.Logger
}

// NewDiscoveryIntegration creates a new discovery integration.
func NewDiscoveryIntegration(manager *Manager, registry *discovery.Registry, logger *slog.Logger) *DiscoveryIntegration {
	if logger == nil {
		logger = slog.Default()
	}
	return &DiscoveryIntegration{
		manager:  manager,
		registry: registry,
		watchers: make(map[string]context.CancelFunc),
		logger:   logger,
	}
}

// ConfigureUpstream sets up an upstream with optional service discovery.
// If service discovery is enabled, it registers a watcher to keep endpoints updated.
func (di *DiscoveryIntegration) ConfigureUpstream(cfg config.UpstreamConfig) error {
	// If service discovery is not enabled, use static configuration
	if !cfg.ServiceDiscovery.Enabled {
		return di.manager.AddUpstream(cfg)
	}

	// Determine service name
	serviceName := cfg.ServiceDiscovery.ServiceName
	if serviceName == "" {
		serviceName = cfg.Name
	}

	// Perform initial discovery
	ctx := context.Background()
	service, err := di.registry.Discover(ctx, serviceName)
	if err != nil {
		di.logger.Warn("initial discovery failed, using static endpoints",
			"upstream", cfg.Name,
			"service", serviceName,
			"error", err)
	} else {
		// Update config with discovered endpoints
		cfg.Endpoints = di.serviceToEndpoints(service)
	}

	// Add the upstream with initial endpoints
	if err := di.manager.AddUpstream(cfg); err != nil {
		// If upstream already exists, update it
		if err == ErrUpstreamAlreadyExists {
			if err := di.manager.UpdateUpstream(cfg.Name, cfg); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Start watching for changes
	di.startWatcher(cfg.Name, serviceName)

	return nil
}

// serviceToEndpoints converts a discovered service to endpoint strings.
func (di *DiscoveryIntegration) serviceToEndpoints(service *discovery.Service) []string {
	endpoints := make([]string, 0, len(service.Endpoints))
	for _, ep := range service.Endpoints {
		if ep.Healthy {
			endpoints = append(endpoints, ep.HostPort())
		}
	}
	return endpoints
}

// startWatcher starts watching a service for changes.
func (di *DiscoveryIntegration) startWatcher(upstreamName, serviceName string) {
	di.mu.Lock()
	defer di.mu.Unlock()

	// Cancel any existing watcher
	if cancel, exists := di.watchers[upstreamName]; exists {
		cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	di.watchers[upstreamName] = cancel

	go func() {
		di.registry.Watch(serviceName, func(service *discovery.Service) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			endpoints := di.serviceToEndpoints(service)
			if len(endpoints) == 0 {
				di.logger.Warn("service has no healthy endpoints",
					"upstream", upstreamName,
					"service", serviceName)
				return
			}

			di.logger.Info("updating upstream from discovery",
				"upstream", upstreamName,
				"service", serviceName,
				"endpoints", len(endpoints))

			di.updateUpstreamEndpoints(upstreamName, endpoints)
		})
	}()
}

// updateUpstreamEndpoints updates the endpoints for an upstream.
func (di *DiscoveryIntegration) updateUpstreamEndpoints(upstreamName string, endpoints []string) {
	di.manager.mu.Lock()
	defer di.manager.mu.Unlock()

	upstream, exists := di.manager.upstreams[upstreamName]
	if !exists {
		return
	}

	// Update the endpoints
	newEndpoints := make([]*Endpoint, len(endpoints))
	for i, addr := range endpoints {
		ep := &Endpoint{
			Address: addr,
			Weight:  1,
		}
		ep.SetHealthy(true)
		newEndpoints[i] = ep
	}

	upstream.mu.Lock()
	upstream.Endpoints = newEndpoints
	upstream.mu.Unlock()
}

// StopWatcher stops watching a specific upstream.
func (di *DiscoveryIntegration) StopWatcher(upstreamName string) {
	di.mu.Lock()
	defer di.mu.Unlock()

	if cancel, exists := di.watchers[upstreamName]; exists {
		cancel()
		delete(di.watchers, upstreamName)
	}
}

// Close stops all watchers.
func (di *DiscoveryIntegration) Close() {
	di.mu.Lock()
	defer di.mu.Unlock()

	for _, cancel := range di.watchers {
		cancel()
	}
	di.watchers = make(map[string]context.CancelFunc)
}

// RefreshUpstream forces a refresh of an upstream's endpoints from discovery.
func (di *DiscoveryIntegration) RefreshUpstream(upstreamName, serviceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	service, err := di.registry.Discover(ctx, serviceName)
	if err != nil {
		return err
	}

	endpoints := di.serviceToEndpoints(service)
	if len(endpoints) == 0 {
		di.logger.Warn("service has no healthy endpoints during refresh",
			"upstream", upstreamName,
			"service", serviceName)
		return nil
	}

	di.updateUpstreamEndpoints(upstreamName, endpoints)
	return nil
}

// GetDiscoveredEndpoints returns the current discovered endpoints for an upstream.
func (di *DiscoveryIntegration) GetDiscoveredEndpoints(upstreamName string) []string {
	di.manager.mu.RLock()
	defer di.manager.mu.RUnlock()

	upstream, exists := di.manager.upstreams[upstreamName]
	if !exists {
		return nil
	}

	upstream.mu.RLock()
	defer upstream.mu.RUnlock()

	endpoints := make([]string, len(upstream.Endpoints))
	for i, ep := range upstream.Endpoints {
		endpoints[i] = ep.Address
	}
	return endpoints
}
