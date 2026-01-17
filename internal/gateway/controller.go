package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/josedab/loom/internal/config"
)

const (
	// DefaultControllerName is the default name for the Loom Gateway controller.
	DefaultControllerName = "loom.io/gateway-controller"
	// DefaultResyncPeriod is the default period between full resyncs.
	DefaultResyncPeriod = 30 * time.Second
)

// Controller manages Gateway API resources and synchronizes them with Loom.
type Controller struct {
	controllerName string
	converter      *Converter
	logger         *slog.Logger

	// Resource storage
	gatewayClasses map[string]*GatewayClass
	gateways       map[string]*Gateway
	httpRoutes     map[string]*HTTPRoute

	// Configuration callbacks
	configCallbacks []func(*GatewayAPIConfig)

	// Kubernetes client interface (nil for standalone operation)
	kubeClient KubernetesClient

	// Synchronization
	mu       sync.RWMutex
	stopCh   chan struct{}
	syncCh   chan struct{}
	running  bool
}

// ControllerConfig configures the Gateway API controller.
type ControllerConfig struct {
	// ControllerName is the name of this controller (default: loom.io/gateway-controller).
	ControllerName string
	// Logger for controller events.
	Logger *slog.Logger
	// KubeClient is an optional Kubernetes client for watching resources.
	KubeClient KubernetesClient
	// ResyncPeriod is how often to do a full resync (default: 30s).
	ResyncPeriod time.Duration
}

// KubernetesClient is an interface for interacting with Kubernetes.
// This allows for mocking in tests and supporting different client implementations.
type KubernetesClient interface {
	// ListGatewayClasses lists all GatewayClass resources.
	ListGatewayClasses(ctx context.Context) ([]*GatewayClass, error)
	// ListGateways lists all Gateway resources.
	ListGateways(ctx context.Context, namespace string) ([]*Gateway, error)
	// ListHTTPRoutes lists all HTTPRoute resources.
	ListHTTPRoutes(ctx context.Context, namespace string) ([]*HTTPRoute, error)
	// UpdateGatewayStatus updates the status of a Gateway.
	UpdateGatewayStatus(ctx context.Context, gw *Gateway) error
	// UpdateHTTPRouteStatus updates the status of an HTTPRoute.
	UpdateHTTPRouteStatus(ctx context.Context, route *HTTPRoute) error
	// WatchGateways watches for Gateway resource changes.
	WatchGateways(ctx context.Context, namespace string) (<-chan WatchEvent, error)
	// WatchHTTPRoutes watches for HTTPRoute resource changes.
	WatchHTTPRoutes(ctx context.Context, namespace string) (<-chan WatchEvent, error)
}

// WatchEvent represents a change to a resource.
type WatchEvent struct {
	// Type is the type of event (Added, Modified, Deleted).
	Type WatchEventType
	// Object is the resource that changed.
	Object interface{}
}

// WatchEventType is the type of watch event.
type WatchEventType string

const (
	// WatchEventAdded indicates a resource was added.
	WatchEventAdded WatchEventType = "ADDED"
	// WatchEventModified indicates a resource was modified.
	WatchEventModified WatchEventType = "MODIFIED"
	// WatchEventDeleted indicates a resource was deleted.
	WatchEventDeleted WatchEventType = "DELETED"
)

// NewController creates a new Gateway API controller.
func NewController(cfg ControllerConfig) *Controller {
	if cfg.ControllerName == "" {
		cfg.ControllerName = DefaultControllerName
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Controller{
		controllerName: cfg.ControllerName,
		converter:      NewConverter(cfg.ControllerName),
		logger:         cfg.Logger,
		gatewayClasses: make(map[string]*GatewayClass),
		gateways:       make(map[string]*Gateway),
		httpRoutes:     make(map[string]*HTTPRoute),
		kubeClient:     cfg.KubeClient,
		stopCh:         make(chan struct{}),
		syncCh:         make(chan struct{}, 1),
	}
}

// Start begins watching for Gateway API resources.
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("controller already running")
	}
	c.running = true
	c.mu.Unlock()

	c.logger.Info("Starting Gateway API controller",
		"controllerName", c.controllerName,
	)

	// If we have a Kubernetes client, start watches
	if c.kubeClient != nil {
		go c.watchLoop(ctx)
	}

	// Start sync loop
	go c.syncLoop(ctx)

	return nil
}

// Stop stops the controller.
func (c *Controller) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.stopCh)
	c.running = false
	c.logger.Info("Gateway API controller stopped")
}

// OnConfigChange registers a callback for configuration changes.
func (c *Controller) OnConfigChange(cb func(*GatewayAPIConfig)) {
	c.mu.Lock()
	c.configCallbacks = append(c.configCallbacks, cb)
	c.mu.Unlock()
}

// AddGatewayClass adds a GatewayClass resource.
func (c *Controller) AddGatewayClass(gc *GatewayClass) error {
	c.mu.Lock()
	c.gatewayClasses[gc.Name] = gc
	c.mu.Unlock()

	c.logger.Info("GatewayClass added",
		"name", gc.Name,
		"controllerName", gc.ControllerName,
	)

	c.triggerSync()
	return nil
}

// RemoveGatewayClass removes a GatewayClass resource.
func (c *Controller) RemoveGatewayClass(name string) {
	c.mu.Lock()
	delete(c.gatewayClasses, name)
	c.mu.Unlock()

	c.logger.Info("GatewayClass removed", "name", name)
	c.triggerSync()
}

// AddGateway adds a Gateway resource.
func (c *Controller) AddGateway(gw *Gateway) error {
	// Validate the gateway
	if errs := c.converter.ValidateGateway(gw); len(errs) > 0 {
		for _, err := range errs {
			c.logger.Warn("Gateway validation error",
				"gateway", fmt.Sprintf("%s/%s", gw.Namespace, gw.Name),
				"error", err,
			)
		}
	}

	key := fmt.Sprintf("%s/%s", gw.Namespace, gw.Name)

	c.mu.Lock()
	c.gateways[key] = gw
	c.mu.Unlock()

	c.logger.Info("Gateway added",
		"name", gw.Name,
		"namespace", gw.Namespace,
		"listeners", len(gw.Listeners),
	)

	c.triggerSync()
	return nil
}

// UpdateGateway updates a Gateway resource.
func (c *Controller) UpdateGateway(gw *Gateway) error {
	return c.AddGateway(gw)
}

// RemoveGateway removes a Gateway resource.
func (c *Controller) RemoveGateway(namespace, name string) {
	key := fmt.Sprintf("%s/%s", namespace, name)

	c.mu.Lock()
	delete(c.gateways, key)
	c.mu.Unlock()

	c.logger.Info("Gateway removed",
		"name", name,
		"namespace", namespace,
	)

	c.triggerSync()
}

// AddHTTPRoute adds an HTTPRoute resource.
func (c *Controller) AddHTTPRoute(route *HTTPRoute) error {
	// Validate the route
	if errs := c.converter.ValidateHTTPRoute(route); len(errs) > 0 {
		for _, err := range errs {
			c.logger.Warn("HTTPRoute validation error",
				"route", fmt.Sprintf("%s/%s", route.Namespace, route.Name),
				"error", err,
			)
		}
	}

	key := fmt.Sprintf("%s/%s", route.Namespace, route.Name)

	c.mu.Lock()
	c.httpRoutes[key] = route
	c.mu.Unlock()

	c.logger.Info("HTTPRoute added",
		"name", route.Name,
		"namespace", route.Namespace,
		"rules", len(route.Rules),
	)

	c.triggerSync()
	return nil
}

// UpdateHTTPRoute updates an HTTPRoute resource.
func (c *Controller) UpdateHTTPRoute(route *HTTPRoute) error {
	return c.AddHTTPRoute(route)
}

// RemoveHTTPRoute removes an HTTPRoute resource.
func (c *Controller) RemoveHTTPRoute(namespace, name string) {
	key := fmt.Sprintf("%s/%s", namespace, name)

	c.mu.Lock()
	delete(c.httpRoutes, key)
	c.mu.Unlock()

	c.logger.Info("HTTPRoute removed",
		"name", name,
		"namespace", namespace,
	)

	c.triggerSync()
}

// GetGateway returns a Gateway by namespace/name.
func (c *Controller) GetGateway(namespace, name string) *Gateway {
	key := fmt.Sprintf("%s/%s", namespace, name)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gateways[key]
}

// GetHTTPRoute returns an HTTPRoute by namespace/name.
func (c *Controller) GetHTTPRoute(namespace, name string) *HTTPRoute {
	key := fmt.Sprintf("%s/%s", namespace, name)
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.httpRoutes[key]
}

// ListGateways returns all Gateways.
func (c *Controller) ListGateways() []*Gateway {
	c.mu.RLock()
	defer c.mu.RUnlock()

	gateways := make([]*Gateway, 0, len(c.gateways))
	for _, gw := range c.gateways {
		gateways = append(gateways, gw)
	}
	return gateways
}

// ListHTTPRoutes returns all HTTPRoutes.
func (c *Controller) ListHTTPRoutes() []*HTTPRoute {
	c.mu.RLock()
	defer c.mu.RUnlock()

	routes := make([]*HTTPRoute, 0, len(c.httpRoutes))
	for _, r := range c.httpRoutes {
		routes = append(routes, r)
	}
	return routes
}

// GetConfig returns the current Gateway API configuration.
func (c *Controller) GetConfig() (*GatewayAPIConfig, error) {
	c.mu.RLock()
	gateways := make([]*Gateway, 0, len(c.gateways))
	for _, gw := range c.gateways {
		gateways = append(gateways, gw)
	}
	routes := make([]*HTTPRoute, 0, len(c.httpRoutes))
	for _, r := range c.httpRoutes {
		routes = append(routes, r)
	}
	c.mu.RUnlock()

	return c.converter.ConvertAll(gateways, routes)
}

// triggerSync triggers a configuration sync.
func (c *Controller) triggerSync() {
	select {
	case c.syncCh <- struct{}{}:
	default:
		// Sync already pending
	}
}

// syncLoop periodically syncs configuration.
func (c *Controller) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(DefaultResyncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-c.syncCh:
			c.sync()
		case <-ticker.C:
			c.sync()
		}
	}
}

// sync performs a configuration sync.
func (c *Controller) sync() {
	cfg, err := c.GetConfig()
	if err != nil {
		c.logger.Error("Failed to get configuration", "error", err)
		return
	}

	c.mu.RLock()
	callbacks := c.configCallbacks
	c.mu.RUnlock()

	for _, cb := range callbacks {
		cb(cfg)
	}

	c.logger.Debug("Configuration synced",
		"listeners", len(cfg.Listeners),
		"routes", len(cfg.Routes),
		"upstreams", len(cfg.Upstreams),
	)
}

// watchLoop watches for Kubernetes resource changes.
func (c *Controller) watchLoop(ctx context.Context) {
	// Start watching gateways
	gwCh, err := c.kubeClient.WatchGateways(ctx, "")
	if err != nil {
		c.logger.Error("Failed to watch gateways", "error", err)
		return
	}

	// Start watching routes
	routeCh, err := c.kubeClient.WatchHTTPRoutes(ctx, "")
	if err != nil {
		c.logger.Error("Failed to watch routes", "error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case event := <-gwCh:
			c.handleGatewayEvent(event)
		case event := <-routeCh:
			c.handleHTTPRouteEvent(event)
		}
	}
}

// handleGatewayEvent handles a Gateway watch event.
func (c *Controller) handleGatewayEvent(event WatchEvent) {
	gw, ok := event.Object.(*Gateway)
	if !ok {
		return
	}

	switch event.Type {
	case WatchEventAdded, WatchEventModified:
		_ = c.AddGateway(gw)
	case WatchEventDeleted:
		c.RemoveGateway(gw.Namespace, gw.Name)
	}
}

// handleHTTPRouteEvent handles an HTTPRoute watch event.
func (c *Controller) handleHTTPRouteEvent(event WatchEvent) {
	route, ok := event.Object.(*HTTPRoute)
	if !ok {
		return
	}

	switch event.Type {
	case WatchEventAdded, WatchEventModified:
		_ = c.AddHTTPRoute(route)
	case WatchEventDeleted:
		c.RemoveHTTPRoute(route.Namespace, route.Name)
	}
}

// UpdateStatuses updates the status of all managed resources.
func (c *Controller) UpdateStatuses(ctx context.Context) error {
	if c.kubeClient == nil {
		return nil
	}

	c.mu.RLock()
	gateways := make([]*Gateway, 0, len(c.gateways))
	for _, gw := range c.gateways {
		gateways = append(gateways, gw)
	}
	routes := make([]*HTTPRoute, 0, len(c.httpRoutes))
	for _, r := range c.httpRoutes {
		routes = append(routes, r)
	}
	c.mu.RUnlock()

	// Update gateway statuses
	for _, gw := range gateways {
		gw.Status = c.buildGatewayStatus(gw)
		if err := c.kubeClient.UpdateGatewayStatus(ctx, gw); err != nil {
			c.logger.Error("Failed to update gateway status",
				"gateway", fmt.Sprintf("%s/%s", gw.Namespace, gw.Name),
				"error", err,
			)
		}
	}

	// Update route statuses
	for _, route := range routes {
		route.Status = c.buildHTTPRouteStatus(route)
		if err := c.kubeClient.UpdateHTTPRouteStatus(ctx, route); err != nil {
			c.logger.Error("Failed to update route status",
				"route", fmt.Sprintf("%s/%s", route.Namespace, route.Name),
				"error", err,
			)
		}
	}

	return nil
}

// buildGatewayStatus builds the status for a Gateway.
func (c *Controller) buildGatewayStatus(gw *Gateway) GatewayStatus {
	status := GatewayStatus{
		Conditions: []Condition{
			{
				Type:               "Accepted",
				Status:             ConditionTrue,
				Reason:             "Accepted",
				Message:            "Gateway accepted by Loom controller",
				LastTransitionTime: time.Now(),
			},
			{
				Type:               "Programmed",
				Status:             ConditionTrue,
				Reason:             "Programmed",
				Message:            "Gateway configuration applied",
				LastTransitionTime: time.Now(),
			},
		},
	}

	// Add listener statuses
	for _, l := range gw.Listeners {
		attachedRoutes := c.countRoutesForListener(gw, l.Name)
		status.Listeners = append(status.Listeners, ListenerStatus{
			Name:           l.Name,
			AttachedRoutes: int32(attachedRoutes),
			Conditions: []Condition{
				{
					Type:               "Accepted",
					Status:             ConditionTrue,
					Reason:             "Accepted",
					LastTransitionTime: time.Now(),
				},
				{
					Type:               "Programmed",
					Status:             ConditionTrue,
					Reason:             "Programmed",
					LastTransitionTime: time.Now(),
				},
			},
			SupportedKinds: []RouteGroupKind{
				{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"},
			},
		})
	}

	return status
}

// buildHTTPRouteStatus builds the status for an HTTPRoute.
func (c *Controller) buildHTTPRouteStatus(route *HTTPRoute) HTTPRouteStatus {
	status := HTTPRouteStatus{}

	for _, parent := range route.ParentRefs {
		status.Parents = append(status.Parents, RouteParentStatus{
			ParentRef:      parent,
			ControllerName: c.controllerName,
			Conditions: []Condition{
				{
					Type:               "Accepted",
					Status:             ConditionTrue,
					Reason:             "Accepted",
					Message:            "Route accepted by parent Gateway",
					LastTransitionTime: time.Now(),
				},
				{
					Type:               "ResolvedRefs",
					Status:             ConditionTrue,
					Reason:             "ResolvedRefs",
					Message:            "All references resolved",
					LastTransitionTime: time.Now(),
				},
			},
		})
	}

	return status
}

// countRoutesForListener counts routes attached to a specific listener.
func (c *Controller) countRoutesForListener(gw *Gateway, listenerName string) int {
	count := 0

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, route := range c.httpRoutes {
		for _, parent := range route.ParentRefs {
			if parent.Name == gw.Name {
				ns := parent.Namespace
				if ns == "" {
					ns = route.Namespace
				}
				if ns == gw.Namespace {
					if parent.SectionName == "" || parent.SectionName == listenerName {
						count++
						break
					}
				}
			}
		}
	}

	return count
}

// LoadFromJSON loads Gateway API resources from JSON.
func (c *Controller) LoadFromJSON(gatewaysJSON, routesJSON []byte) error {
	if len(gatewaysJSON) > 0 {
		var gateways []*Gateway
		if err := json.Unmarshal(gatewaysJSON, &gateways); err != nil {
			return fmt.Errorf("parsing gateways JSON: %w", err)
		}
		for _, gw := range gateways {
			if err := c.AddGateway(gw); err != nil {
				return fmt.Errorf("adding gateway %s/%s: %w", gw.Namespace, gw.Name, err)
			}
		}
	}

	if len(routesJSON) > 0 {
		var routes []*HTTPRoute
		if err := json.Unmarshal(routesJSON, &routes); err != nil {
			return fmt.Errorf("parsing routes JSON: %w", err)
		}
		for _, route := range routes {
			if err := c.AddHTTPRoute(route); err != nil {
				return fmt.Errorf("adding route %s/%s: %w", route.Namespace, route.Name, err)
			}
		}
	}

	return nil
}

// ExportToConfig exports the current configuration to Loom config format.
func (c *Controller) ExportToConfig() (*config.Config, error) {
	gwCfg, err := c.GetConfig()
	if err != nil {
		return nil, err
	}

	return &config.Config{
		Listeners: gwCfg.Listeners,
		Routes:    gwCfg.Routes,
		Upstreams: gwCfg.Upstreams,
	}, nil
}
