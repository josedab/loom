// Package gatewayapi provides Kubernetes Gateway API conformance for Loom.
package gatewayapi

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josedab/loom/internal/config"
)

// ControllerName is the name of the Loom Gateway API controller.
const ControllerName = "loom.gateway.io/controller"

// Controller manages Gateway API resources and translates them to Loom configuration.
type Controller struct {
	gatewayClasses map[string]*GatewayClass
	gateways       map[string]*Gateway
	httpRoutes     map[string]*HTTPRoute
	grpcRoutes     map[string]*GRPCRoute
	tlsRoutes      map[string]*TLSRoute

	// Computed configuration
	listeners     []config.ListenerConfig
	routes        []config.RouteConfig
	upstreams     []config.UpstreamConfig

	// Callbacks for configuration updates
	onConfigUpdate func([]config.ListenerConfig, []config.RouteConfig, []config.UpstreamConfig)

	logger        *slog.Logger
	mu            sync.RWMutex
	generation    atomic.Int64
}

// NewController creates a new Gateway API controller.
func NewController(logger *slog.Logger) *Controller {
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{
		gatewayClasses: make(map[string]*GatewayClass),
		gateways:       make(map[string]*Gateway),
		httpRoutes:     make(map[string]*HTTPRoute),
		grpcRoutes:     make(map[string]*GRPCRoute),
		tlsRoutes:      make(map[string]*TLSRoute),
		logger:         logger,
	}
}

// OnConfigUpdate sets a callback for configuration updates.
func (c *Controller) OnConfigUpdate(fn func([]config.ListenerConfig, []config.RouteConfig, []config.UpstreamConfig)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConfigUpdate = fn
}

// SetGatewayClass adds or updates a GatewayClass.
func (c *Controller) SetGatewayClass(gc *GatewayClass) error {
	if gc.Spec.ControllerName != ControllerName {
		return fmt.Errorf("controller name mismatch: expected %s, got %s", ControllerName, gc.Spec.ControllerName)
	}

	c.mu.Lock()
	c.gatewayClasses[gc.Name] = gc
	c.mu.Unlock()

	// Update status
	gc.Status.Conditions = []Condition{
		{
			Type:               "Accepted",
			Status:             "True",
			LastTransitionTime: time.Now(),
			Reason:             "Accepted",
			Message:            "GatewayClass is accepted by the controller",
		},
	}

	c.logger.Info("GatewayClass updated", "name", gc.Name)
	return nil
}

// DeleteGatewayClass removes a GatewayClass.
func (c *Controller) DeleteGatewayClass(name string) {
	c.mu.Lock()
	delete(c.gatewayClasses, name)
	c.mu.Unlock()
	c.logger.Info("GatewayClass deleted", "name", name)
}

// SetGateway adds or updates a Gateway.
func (c *Controller) SetGateway(gw *Gateway) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify GatewayClass exists and is accepted
	gc, ok := c.gatewayClasses[gw.Spec.GatewayClassName]
	if !ok {
		return fmt.Errorf("GatewayClass %s not found", gw.Spec.GatewayClassName)
	}
	if gc.Spec.ControllerName != ControllerName {
		return fmt.Errorf("GatewayClass %s is not managed by this controller", gw.Spec.GatewayClassName)
	}

	key := gw.Namespace + "/" + gw.Name
	c.gateways[key] = gw

	// Update status
	gw.Status.Conditions = []Condition{
		{
			Type:               "Accepted",
			Status:             "True",
			LastTransitionTime: time.Now(),
			Reason:             "Accepted",
			Message:            "Gateway is accepted",
		},
		{
			Type:               "Programmed",
			Status:             "True",
			LastTransitionTime: time.Now(),
			Reason:             "Programmed",
			Message:            "Gateway configuration is programmed",
		},
	}

	// Update listener status
	gw.Status.Listeners = make([]ListenerStatus, len(gw.Spec.Listeners))
	for i, l := range gw.Spec.Listeners {
		gw.Status.Listeners[i] = ListenerStatus{
			Name: l.Name,
			Conditions: []Condition{
				{
					Type:               "Accepted",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "Accepted",
				},
				{
					Type:               "Programmed",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "Programmed",
				},
			},
			SupportedKinds: []RouteGroupKind{
				{Kind: "HTTPRoute"},
				{Kind: "GRPCRoute"},
			},
		}
	}

	c.logger.Info("Gateway updated", "name", gw.Name, "namespace", gw.Namespace)
	c.reconcileUnlocked()
	return nil
}

// DeleteGateway removes a Gateway.
func (c *Controller) DeleteGateway(namespace, name string) {
	c.mu.Lock()
	key := namespace + "/" + name
	delete(c.gateways, key)
	c.mu.Unlock()

	c.logger.Info("Gateway deleted", "name", name, "namespace", namespace)
	c.reconcile()
}

// SetHTTPRoute adds or updates an HTTPRoute.
func (c *Controller) SetHTTPRoute(route *HTTPRoute) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := route.Namespace + "/" + route.Name
	c.httpRoutes[key] = route

	// Validate and update status
	route.Status.Parents = c.validateRouteParentsUnlocked(route.Spec.ParentRefs, route.Namespace)

	c.logger.Info("HTTPRoute updated", "name", route.Name, "namespace", route.Namespace)
	c.reconcileUnlocked()
	return nil
}

// DeleteHTTPRoute removes an HTTPRoute.
func (c *Controller) DeleteHTTPRoute(namespace, name string) {
	c.mu.Lock()
	key := namespace + "/" + name
	delete(c.httpRoutes, key)
	c.mu.Unlock()

	c.logger.Info("HTTPRoute deleted", "name", name, "namespace", namespace)
	c.reconcile()
}

// SetGRPCRoute adds or updates a GRPCRoute.
func (c *Controller) SetGRPCRoute(route *GRPCRoute) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := route.Namespace + "/" + route.Name
	c.grpcRoutes[key] = route

	route.Status.Parents = c.validateRouteParentsUnlocked(route.Spec.ParentRefs, route.Namespace)

	c.logger.Info("GRPCRoute updated", "name", route.Name, "namespace", route.Namespace)
	c.reconcileUnlocked()
	return nil
}

// DeleteGRPCRoute removes a GRPCRoute.
func (c *Controller) DeleteGRPCRoute(namespace, name string) {
	c.mu.Lock()
	key := namespace + "/" + name
	delete(c.grpcRoutes, key)
	c.mu.Unlock()

	c.logger.Info("GRPCRoute deleted", "name", name, "namespace", namespace)
	c.reconcile()
}

// SetTLSRoute adds or updates a TLSRoute.
func (c *Controller) SetTLSRoute(route *TLSRoute) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := route.Namespace + "/" + route.Name
	c.tlsRoutes[key] = route

	route.Status.Parents = c.validateRouteParentsUnlocked(route.Spec.ParentRefs, route.Namespace)

	c.logger.Info("TLSRoute updated", "name", route.Name, "namespace", route.Namespace)
	c.reconcileUnlocked()
	return nil
}

// DeleteTLSRoute removes a TLSRoute.
func (c *Controller) DeleteTLSRoute(namespace, name string) {
	c.mu.Lock()
	key := namespace + "/" + name
	delete(c.tlsRoutes, key)
	c.mu.Unlock()

	c.logger.Info("TLSRoute deleted", "name", name, "namespace", namespace)
	c.reconcile()
}

// validateRouteParentsUnlocked validates parent references for a route.
func (c *Controller) validateRouteParentsUnlocked(refs []ParentReference, routeNamespace string) []RouteParentStatus {
	statuses := make([]RouteParentStatus, 0, len(refs))

	for _, ref := range refs {
		status := RouteParentStatus{
			ParentRef:      ref,
			ControllerName: ControllerName,
		}

		// Determine namespace
		ns := routeNamespace
		if ref.Namespace != nil {
			ns = *ref.Namespace
		}

		// Look up gateway
		key := ns + "/" + ref.Name
		gw, ok := c.gateways[key]

		if !ok {
			status.Conditions = []Condition{
				{
					Type:               "Accepted",
					Status:             "False",
					LastTransitionTime: time.Now(),
					Reason:             "NoMatchingParent",
					Message:            fmt.Sprintf("Gateway %s not found", key),
				},
			}
		} else {
			status.Conditions = []Condition{
				{
					Type:               "Accepted",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "Accepted",
				},
				{
					Type:               "ResolvedRefs",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "ResolvedRefs",
				},
			}

			// Update listener attached routes count
			for i := range gw.Status.Listeners {
				gw.Status.Listeners[i].AttachedRoutes++
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}

// reconcile rebuilds the configuration from Gateway API resources.
func (c *Controller) reconcile() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcileUnlocked()
}

// reconcileUnlocked rebuilds configuration without holding the lock.
func (c *Controller) reconcileUnlocked() {
	c.generation.Add(1)

	listeners := make([]config.ListenerConfig, 0)
	routes := make([]config.RouteConfig, 0)
	upstreams := make([]config.UpstreamConfig, 0)
	upstreamMap := make(map[string]bool)

	// Process Gateways -> Listeners
	for _, gw := range c.gateways {
		for _, l := range gw.Spec.Listeners {
			listener := c.listenerToConfig(gw, &l)
			listeners = append(listeners, listener)
		}
	}

	// Process HTTPRoutes -> Routes + Upstreams
	for _, route := range c.httpRoutes {
		routeConfigs, upstreamConfigs := c.httpRouteToConfig(route)
		routes = append(routes, routeConfigs...)
		for _, u := range upstreamConfigs {
			if !upstreamMap[u.Name] {
				upstreams = append(upstreams, u)
				upstreamMap[u.Name] = true
			}
		}
	}

	// Process GRPCRoutes -> Routes + Upstreams
	for _, route := range c.grpcRoutes {
		routeConfigs, upstreamConfigs := c.grpcRouteToConfig(route)
		routes = append(routes, routeConfigs...)
		for _, u := range upstreamConfigs {
			if !upstreamMap[u.Name] {
				upstreams = append(upstreams, u)
				upstreamMap[u.Name] = true
			}
		}
	}

	// Sort routes by specificity (more specific first)
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority > routes[j].Priority
	})

	c.listeners = listeners
	c.routes = routes
	c.upstreams = upstreams

	// Notify callback
	if c.onConfigUpdate != nil {
		c.onConfigUpdate(listeners, routes, upstreams)
	}

	c.logger.Info("Configuration reconciled",
		"listeners", len(listeners),
		"routes", len(routes),
		"upstreams", len(upstreams),
		"generation", c.generation.Load())
}

// listenerToConfig converts a Gateway listener to Loom ListenerConfig.
func (c *Controller) listenerToConfig(gw *Gateway, l *Listener) config.ListenerConfig {
	cfg := config.ListenerConfig{
		Name:    fmt.Sprintf("%s-%s-%s", gw.Namespace, gw.Name, l.Name),
		Address: fmt.Sprintf(":%d", l.Port),
	}

	switch l.Protocol {
	case HTTPProtocolType:
		cfg.Protocol = "http"
	case HTTPSProtocolType:
		cfg.Protocol = "https"
		if l.TLS != nil {
			cfg.TLS = &config.TLSConfig{}
			// TLS config would be populated from Secret references
		}
	case GRPCProtocolType:
		cfg.Protocol = "grpc"
	default:
		cfg.Protocol = "http"
	}

	return cfg
}

// httpRouteToConfig converts an HTTPRoute to Loom RouteConfig and UpstreamConfig.
func (c *Controller) httpRouteToConfig(route *HTTPRoute) ([]config.RouteConfig, []config.UpstreamConfig) {
	var routes []config.RouteConfig
	var upstreams []config.UpstreamConfig

	for ruleIdx, rule := range route.Spec.Rules {
		// Create upstream from backend refs
		upstreamName := fmt.Sprintf("%s-%s-rule%d", route.Namespace, route.Name, ruleIdx)
		endpoints := make([]string, 0)

		for _, backendRef := range rule.BackendRefs {
			ns := route.Namespace
			if backendRef.Namespace != nil {
				ns = *backendRef.Namespace
			}
			port := int32(80)
			if backendRef.Port != nil {
				port = *backendRef.Port
			}
			endpoint := fmt.Sprintf("%s.%s.svc:%d", backendRef.Name, ns, port)
			endpoints = append(endpoints, endpoint)
		}

		if len(endpoints) > 0 {
			upstream := config.UpstreamConfig{
				Name:         upstreamName,
				Endpoints:    endpoints,
				LoadBalancer: "round_robin",
			}

			// Handle weighted backends
			if len(rule.BackendRefs) > 1 {
				upstream.LoadBalancer = "weighted"
			}

			upstreams = append(upstreams, upstream)
		}

		// Create route for each match
		if len(rule.Matches) == 0 {
			// Default match (match everything)
			routeCfg := c.createRouteConfig(route, ruleIdx, 0, nil, upstreamName, rule)
			routes = append(routes, routeCfg)
		} else {
			for matchIdx, match := range rule.Matches {
				routeCfg := c.createRouteConfig(route, ruleIdx, matchIdx, &match, upstreamName, rule)
				routes = append(routes, routeCfg)
			}
		}
	}

	return routes, upstreams
}

// createRouteConfig creates a Loom RouteConfig from an HTTPRoute match.
func (c *Controller) createRouteConfig(route *HTTPRoute, ruleIdx, matchIdx int, match *HTTPRouteMatch, upstreamName string, rule HTTPRouteRule) config.RouteConfig {
	routeID := fmt.Sprintf("%s-%s-rule%d-match%d", route.Namespace, route.Name, ruleIdx, matchIdx)

	cfg := config.RouteConfig{
		ID:       routeID,
		Upstream: upstreamName,
		Priority: 100, // Default priority
	}

	// Set path
	if match != nil && match.Path != nil && match.Path.Value != nil {
		pathValue := *match.Path.Value
		pathType := PathMatchPathPrefix
		if match.Path.Type != nil {
			pathType = *match.Path.Type
		}

		switch pathType {
		case PathMatchExact:
			cfg.Path = pathValue
			cfg.Priority += 100 // Exact matches have higher priority
		case PathMatchPathPrefix:
			if !strings.HasSuffix(pathValue, "*") {
				pathValue = strings.TrimSuffix(pathValue, "/") + "/*"
			}
			cfg.Path = pathValue
			cfg.Priority += 50
		case PathMatchRegularExpression:
			cfg.Path = pathValue
			cfg.Priority += 25
		}
	} else {
		cfg.Path = "/*"
	}

	// Set methods
	if match != nil && match.Method != nil {
		cfg.Methods = []string{string(*match.Method)}
		cfg.Priority += 10
	}

	// Set headers
	if match != nil && len(match.Headers) > 0 {
		cfg.Headers = make(map[string]string)
		for _, h := range match.Headers {
			cfg.Headers[h.Name] = h.Value
		}
		cfg.Priority += 20
	}

	// Set query params
	if match != nil && len(match.QueryParams) > 0 {
		cfg.QueryParams = make(map[string]string)
		for _, q := range match.QueryParams {
			cfg.QueryParams[q.Name] = q.Value
		}
		cfg.Priority += 15
	}

	// Set host from route hostnames
	if len(route.Spec.Hostnames) > 0 {
		cfg.Host = route.Spec.Hostnames[0]
		cfg.Priority += 30
	}

	// Set timeout
	if rule.Timeouts != nil && rule.Timeouts.Request != nil {
		cfg.Timeout = string(*rule.Timeouts.Request)
	}

	return cfg
}

// grpcRouteToConfig converts a GRPCRoute to Loom configuration.
func (c *Controller) grpcRouteToConfig(route *GRPCRoute) ([]config.RouteConfig, []config.UpstreamConfig) {
	var routes []config.RouteConfig
	var upstreams []config.UpstreamConfig

	for ruleIdx, rule := range route.Spec.Rules {
		// Create upstream from backend refs
		upstreamName := fmt.Sprintf("%s-%s-grpc-rule%d", route.Namespace, route.Name, ruleIdx)
		endpoints := make([]string, 0)

		for _, backendRef := range rule.BackendRefs {
			ns := route.Namespace
			if backendRef.Namespace != nil {
				ns = *backendRef.Namespace
			}
			port := int32(9090) // Default gRPC port
			if backendRef.Port != nil {
				port = *backendRef.Port
			}
			endpoint := fmt.Sprintf("%s.%s.svc:%d", backendRef.Name, ns, port)
			endpoints = append(endpoints, endpoint)
		}

		if len(endpoints) > 0 {
			upstreams = append(upstreams, config.UpstreamConfig{
				Name:         upstreamName,
				Endpoints:    endpoints,
				LoadBalancer: "round_robin",
			})
		}

		// Create route for each match
		if len(rule.Matches) == 0 {
			routeCfg := c.createGRPCRouteConfig(route, ruleIdx, 0, nil, upstreamName)
			routes = append(routes, routeCfg)
		} else {
			for matchIdx, match := range rule.Matches {
				routeCfg := c.createGRPCRouteConfig(route, ruleIdx, matchIdx, &match, upstreamName)
				routes = append(routes, routeCfg)
			}
		}
	}

	return routes, upstreams
}

// createGRPCRouteConfig creates a Loom RouteConfig from a GRPCRoute match.
func (c *Controller) createGRPCRouteConfig(route *GRPCRoute, ruleIdx, matchIdx int, match *GRPCRouteMatch, upstreamName string) config.RouteConfig {
	routeID := fmt.Sprintf("%s-%s-grpc-rule%d-match%d", route.Namespace, route.Name, ruleIdx, matchIdx)

	cfg := config.RouteConfig{
		ID:       routeID,
		Upstream: upstreamName,
		Priority: 100,
	}

	// Build path from gRPC service/method
	if match != nil && match.Method != nil {
		path := "/"
		if match.Method.Service != nil {
			path += *match.Method.Service
		}
		if match.Method.Method != nil {
			path += "/" + *match.Method.Method
		} else {
			path += "/*"
		}
		cfg.Path = path
		cfg.Priority += 50
	} else {
		cfg.Path = "/*"
	}

	// Set host from route hostnames
	if len(route.Spec.Hostnames) > 0 {
		cfg.Host = route.Spec.Hostnames[0]
		cfg.Priority += 30
	}

	// Set methods (gRPC uses POST)
	cfg.Methods = []string{"POST"}

	return cfg
}

// GetListeners returns the current listener configuration.
func (c *Controller) GetListeners() []config.ListenerConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]config.ListenerConfig, len(c.listeners))
	copy(result, c.listeners)
	return result
}

// GetRoutes returns the current route configuration.
func (c *Controller) GetRoutes() []config.RouteConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]config.RouteConfig, len(c.routes))
	copy(result, c.routes)
	return result
}

// GetUpstreams returns the current upstream configuration.
func (c *Controller) GetUpstreams() []config.UpstreamConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]config.UpstreamConfig, len(c.upstreams))
	copy(result, c.upstreams)
	return result
}

// GetGateway returns a Gateway by namespace/name.
func (c *Controller) GetGateway(namespace, name string) (*Gateway, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	gw, ok := c.gateways[namespace+"/"+name]
	return gw, ok
}

// GetHTTPRoute returns an HTTPRoute by namespace/name.
func (c *Controller) GetHTTPRoute(namespace, name string) (*HTTPRoute, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	route, ok := c.httpRoutes[namespace+"/"+name]
	return route, ok
}

// ListGateways returns all Gateways.
func (c *Controller) ListGateways() []*Gateway {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*Gateway, 0, len(c.gateways))
	for _, gw := range c.gateways {
		result = append(result, gw)
	}
	return result
}

// ListHTTPRoutes returns all HTTPRoutes.
func (c *Controller) ListHTTPRoutes() []*HTTPRoute {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*HTTPRoute, 0, len(c.httpRoutes))
	for _, route := range c.httpRoutes {
		result = append(result, route)
	}
	return result
}

// MatchHTTPRoute checks if an HTTPRoute matches a request.
type RouteMatch struct {
	Route       *HTTPRoute
	RuleIndex   int
	MatchIndex  int
	BackendRefs []HTTPBackendRef
	Filters     []HTTPRouteFilter
}

// MatchRequest finds matching routes for an HTTP request.
func (c *Controller) MatchRequest(ctx context.Context, host, path, method string, headers map[string]string) []RouteMatch {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var matches []RouteMatch

	for _, route := range c.httpRoutes {
		// Check hostname match
		if len(route.Spec.Hostnames) > 0 && !matchHostname(host, route.Spec.Hostnames) {
			continue
		}

		for ruleIdx, rule := range route.Spec.Rules {
			if len(rule.Matches) == 0 {
				// No matches = match everything
				matches = append(matches, RouteMatch{
					Route:       route,
					RuleIndex:   ruleIdx,
					MatchIndex:  -1,
					BackendRefs: rule.BackendRefs,
					Filters:     rule.Filters,
				})
				continue
			}

			for matchIdx, match := range rule.Matches {
				if matchHTTPRequest(&match, path, method, headers) {
					matches = append(matches, RouteMatch{
						Route:       route,
						RuleIndex:   ruleIdx,
						MatchIndex:  matchIdx,
						BackendRefs: rule.BackendRefs,
						Filters:     rule.Filters,
					})
				}
			}
		}
	}

	return matches
}

// matchHostname checks if a host matches any of the hostnames.
func matchHostname(host string, hostnames []string) bool {
	for _, h := range hostnames {
		if h == host {
			return true
		}
		// Wildcard matching
		if strings.HasPrefix(h, "*.") {
			suffix := h[1:] // Remove *
			if strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// matchHTTPRequest checks if a request matches an HTTPRouteMatch.
func matchHTTPRequest(match *HTTPRouteMatch, path, method string, headers map[string]string) bool {
	// Check path
	if match.Path != nil && match.Path.Value != nil {
		pathType := PathMatchPathPrefix
		if match.Path.Type != nil {
			pathType = *match.Path.Type
		}

		switch pathType {
		case PathMatchExact:
			if path != *match.Path.Value {
				return false
			}
		case PathMatchPathPrefix:
			if !strings.HasPrefix(path, *match.Path.Value) {
				return false
			}
		case PathMatchRegularExpression:
			re, err := regexp.Compile(*match.Path.Value)
			if err != nil || !re.MatchString(path) {
				return false
			}
		}
	}

	// Check method
	if match.Method != nil && string(*match.Method) != method {
		return false
	}

	// Check headers
	for _, h := range match.Headers {
		headerType := HeaderMatchExact
		if h.Type != nil {
			headerType = *h.Type
		}

		headerValue, ok := headers[h.Name]
		if !ok {
			return false
		}

		switch headerType {
		case HeaderMatchExact:
			if headerValue != h.Value {
				return false
			}
		case HeaderMatchRegularExpression:
			re, err := regexp.Compile(h.Value)
			if err != nil || !re.MatchString(headerValue) {
				return false
			}
		}
	}

	// Check query params would go here if we passed them

	return true
}

// Generation returns the current configuration generation.
func (c *Controller) Generation() int64 {
	return c.generation.Load()
}
