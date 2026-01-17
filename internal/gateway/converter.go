package gateway

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/josedab/loom/internal/config"
)

// Converter converts Gateway API resources to Loom configuration.
type Converter struct {
	// controllerName is the name of this controller.
	controllerName string
}

// NewConverter creates a new Gateway API converter.
func NewConverter(controllerName string) *Converter {
	return &Converter{
		controllerName: controllerName,
	}
}

// ConvertGatewayToListeners converts a Gateway to Loom ListenerConfigs.
func (c *Converter) ConvertGatewayToListeners(gw *Gateway) ([]config.ListenerConfig, error) {
	var listeners []config.ListenerConfig

	for _, l := range gw.Listeners {
		listener := config.ListenerConfig{
			Name:     fmt.Sprintf("%s-%s-%s", gw.Namespace, gw.Name, l.Name),
			Address:  fmt.Sprintf(":%d", l.Port),
			Protocol: c.convertProtocol(l.Protocol),
		}

		// Handle TLS configuration
		if l.TLS != nil && len(l.TLS.CertificateRefs) > 0 {
			// In a real implementation, we'd fetch the Secret and extract cert/key
			// For now, we'll use placeholders that can be resolved later
			listener.TLS = &config.TLSConfig{
				CertFile: fmt.Sprintf("/etc/loom/tls/%s/%s/tls.crt",
					l.TLS.CertificateRefs[0].Namespace,
					l.TLS.CertificateRefs[0].Name),
				KeyFile: fmt.Sprintf("/etc/loom/tls/%s/%s/tls.key",
					l.TLS.CertificateRefs[0].Namespace,
					l.TLS.CertificateRefs[0].Name),
			}
		}

		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// ConvertHTTPRouteToRoutes converts an HTTPRoute to Loom RouteConfigs.
func (c *Converter) ConvertHTTPRouteToRoutes(route *HTTPRoute, gateways map[string]*Gateway) ([]config.RouteConfig, []config.UpstreamConfig, error) {
	var routes []config.RouteConfig
	var upstreams []config.UpstreamConfig
	upstreamMap := make(map[string]bool)

	for ruleIdx, rule := range route.Rules {
		// Create upstream from backend refs
		upstreamName := fmt.Sprintf("%s-%s-rule%d", route.Namespace, route.Name, ruleIdx)
		upstream, err := c.createUpstreamFromBackendRefs(upstreamName, rule.BackendRefs)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %d: %w", ruleIdx, err)
		}

		if !upstreamMap[upstreamName] {
			upstreams = append(upstreams, upstream)
			upstreamMap[upstreamName] = true
		}

		// Create routes for each match
		if len(rule.Matches) == 0 {
			// Default match - matches everything
			routeCfg := c.createRouteConfig(route, ruleIdx, 0, nil, upstreamName, rule)
			routes = append(routes, routeCfg)
		} else {
			for matchIdx, match := range rule.Matches {
				routeCfg := c.createRouteConfig(route, ruleIdx, matchIdx, &match, upstreamName, rule)
				routes = append(routes, routeCfg)
			}
		}
	}

	return routes, upstreams, nil
}

// createRouteConfig creates a RouteConfig from an HTTPRouteMatch.
func (c *Converter) createRouteConfig(route *HTTPRoute, ruleIdx, matchIdx int, match *HTTPRouteMatch, upstreamName string, rule HTTPRouteRule) config.RouteConfig {
	routeCfg := config.RouteConfig{
		ID:       fmt.Sprintf("%s-%s-rule%d-match%d", route.Namespace, route.Name, ruleIdx, matchIdx),
		Upstream: upstreamName,
	}

	// Set hostnames
	if len(route.Hostnames) > 0 {
		routeCfg.Host = route.Hostnames[0]
	}

	// Set path from match
	if match != nil && match.Path != nil {
		routeCfg.Path = c.convertPathMatch(match.Path)
	} else {
		routeCfg.Path = "/*"
	}

	// Set method from match
	if match != nil && match.Method != "" {
		routeCfg.Methods = []string{match.Method}
	}

	// Set headers from match
	if match != nil && len(match.Headers) > 0 {
		routeCfg.Headers = make(map[string]string)
		for _, h := range match.Headers {
			routeCfg.Headers[h.Name] = h.Value
		}
	}

	// Set query params from match
	if match != nil && len(match.QueryParams) > 0 {
		routeCfg.QueryParams = make(map[string]string)
		for _, q := range match.QueryParams {
			routeCfg.QueryParams[q.Name] = q.Value
		}
	}

	// Set timeout from rule
	if rule.Timeouts != nil && rule.Timeouts.Request != "" {
		routeCfg.Timeout = rule.Timeouts.Request
	}

	return routeCfg
}

// createUpstreamFromBackendRefs creates an UpstreamConfig from HTTPBackendRefs.
func (c *Converter) createUpstreamFromBackendRefs(name string, refs []HTTPBackendRef) (config.UpstreamConfig, error) {
	upstream := config.UpstreamConfig{
		Name:         name,
		LoadBalancer: "weighted",
	}

	for _, ref := range refs {
		// Determine namespace (default to route namespace if not specified)
		ns := ref.Namespace
		if ns == "" {
			ns = "default"
		}

		// Build endpoint address
		port := int32(80)
		if ref.Port != nil {
			port = *ref.Port
		}

		// Format: servicename.namespace:port
		endpoint := fmt.Sprintf("%s.%s:%d", ref.Name, ns, port)
		upstream.Endpoints = append(upstream.Endpoints, endpoint)
	}

	if len(upstream.Endpoints) == 0 {
		return upstream, fmt.Errorf("no backends specified")
	}

	return upstream, nil
}

// convertProtocol converts Gateway API protocol to Loom protocol.
func (c *Converter) convertProtocol(p Protocol) string {
	switch p {
	case ProtocolHTTP:
		return "http"
	case ProtocolHTTPS:
		return "https"
	case ProtocolTLS:
		return "https"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "http"
	}
}

// convertPathMatch converts a Gateway API path match to a Loom path pattern.
func (c *Converter) convertPathMatch(match *HTTPPathMatch) string {
	if match == nil || match.Value == "" {
		return "/*"
	}

	switch match.Type {
	case PathMatchExact:
		return match.Value
	case PathMatchPathPrefix:
		// Loom uses /* suffix for prefix matching
		if strings.HasSuffix(match.Value, "/") {
			return match.Value + "*"
		}
		return match.Value + "/*"
	case PathMatchRegularExpression:
		// Loom doesn't directly support regex in paths
		// Return as-is and let routing handle it
		return match.Value
	default:
		return match.Value + "/*"
	}
}

// GatewayAPIConfig holds the combined configuration from Gateway API resources.
type GatewayAPIConfig struct {
	Listeners []config.ListenerConfig
	Routes    []config.RouteConfig
	Upstreams []config.UpstreamConfig
}

// ConvertAll converts all Gateway API resources to Loom configuration.
func (c *Converter) ConvertAll(gateways []*Gateway, httpRoutes []*HTTPRoute) (*GatewayAPIConfig, error) {
	result := &GatewayAPIConfig{}

	// Build gateway lookup map
	gatewayMap := make(map[string]*Gateway)
	for _, gw := range gateways {
		key := fmt.Sprintf("%s/%s", gw.Namespace, gw.Name)
		gatewayMap[key] = gw

		// Convert gateway listeners
		listeners, err := c.ConvertGatewayToListeners(gw)
		if err != nil {
			return nil, fmt.Errorf("converting gateway %s: %w", key, err)
		}
		result.Listeners = append(result.Listeners, listeners...)
	}

	// Convert HTTPRoutes
	for _, route := range httpRoutes {
		routes, upstreams, err := c.ConvertHTTPRouteToRoutes(route, gatewayMap)
		if err != nil {
			return nil, fmt.Errorf("converting route %s/%s: %w", route.Namespace, route.Name, err)
		}
		result.Routes = append(result.Routes, routes...)
		result.Upstreams = append(result.Upstreams, upstreams...)
	}

	return result, nil
}

// ApplyFiltersToRoute applies HTTPRouteFilters to route configuration.
func (c *Converter) ApplyFiltersToRoute(route *config.RouteConfig, filters []HTTPRouteFilter) {
	for _, filter := range filters {
		switch filter.Type {
		case HTTPRouteFilterURLRewrite:
			if filter.URLRewrite != nil && filter.URLRewrite.Path != nil {
				if filter.URLRewrite.Path.Type == PrefixMatchType {
					route.StripPrefix = true
				}
			}
		case HTTPRouteFilterRequestRedirect:
			// Redirects would need special handling in Loom
			// For now, this is informational
		}
	}
}

// ValidateHTTPRoute validates an HTTPRoute resource.
func (c *Converter) ValidateHTTPRoute(route *HTTPRoute) []error {
	var errs []error

	if route.Name == "" {
		errs = append(errs, fmt.Errorf("name is required"))
	}

	if route.Namespace == "" {
		errs = append(errs, fmt.Errorf("namespace is required"))
	}

	if len(route.Rules) == 0 {
		errs = append(errs, fmt.Errorf("at least one rule is required"))
	}

	for i, rule := range route.Rules {
		if len(rule.BackendRefs) == 0 {
			errs = append(errs, fmt.Errorf("rule[%d]: at least one backendRef is required", i))
		}

		for j, ref := range rule.BackendRefs {
			if ref.Name == "" {
				errs = append(errs, fmt.Errorf("rule[%d].backendRef[%d]: name is required", i, j))
			}
			if ref.Weight != nil && *ref.Weight < 0 {
				errs = append(errs, fmt.Errorf("rule[%d].backendRef[%d]: weight must be non-negative", i, j))
			}
		}

		for j, match := range rule.Matches {
			if match.Path != nil && match.Path.Type == PathMatchRegularExpression {
				// Validate regex syntax would go here
				_ = j // Use j to avoid unused variable warning
			}
		}
	}

	return errs
}

// ValidateGateway validates a Gateway resource.
func (c *Converter) ValidateGateway(gw *Gateway) []error {
	var errs []error

	if gw.Name == "" {
		errs = append(errs, fmt.Errorf("name is required"))
	}

	if gw.Namespace == "" {
		errs = append(errs, fmt.Errorf("namespace is required"))
	}

	if gw.GatewayClassName == "" {
		errs = append(errs, fmt.Errorf("gatewayClassName is required"))
	}

	if len(gw.Listeners) == 0 {
		errs = append(errs, fmt.Errorf("at least one listener is required"))
	}

	listenerNames := make(map[string]bool)
	listenerPorts := make(map[int32]bool)

	for i, l := range gw.Listeners {
		if l.Name == "" {
			errs = append(errs, fmt.Errorf("listener[%d]: name is required", i))
		} else if listenerNames[l.Name] {
			errs = append(errs, fmt.Errorf("listener[%d]: duplicate name %q", i, l.Name))
		} else {
			listenerNames[l.Name] = true
		}

		if l.Port <= 0 || l.Port > 65535 {
			errs = append(errs, fmt.Errorf("listener[%d]: invalid port %d", i, l.Port))
		} else if listenerPorts[l.Port] {
			errs = append(errs, fmt.Errorf("listener[%d]: duplicate port %d", i, l.Port))
		} else {
			listenerPorts[l.Port] = true
		}

		switch l.Protocol {
		case ProtocolHTTP, ProtocolHTTPS, ProtocolTLS, ProtocolTCP, ProtocolUDP:
			// Valid
		default:
			errs = append(errs, fmt.Errorf("listener[%d]: invalid protocol %q", i, l.Protocol))
		}

		if (l.Protocol == ProtocolHTTPS || l.Protocol == ProtocolTLS) && l.TLS == nil {
			errs = append(errs, fmt.Errorf("listener[%d]: TLS configuration required for protocol %s", i, l.Protocol))
		}

		if l.TLS != nil && l.Protocol == ProtocolHTTP {
			errs = append(errs, fmt.Errorf("listener[%d]: TLS configuration not allowed for HTTP protocol", i))
		}
	}

	return errs
}

// BuildServiceEndpoint builds a Kubernetes service endpoint string.
func BuildServiceEndpoint(name, namespace string, port int32) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, namespace, port)
}

// ParseServiceEndpoint parses a Kubernetes service endpoint string.
func ParseServiceEndpoint(endpoint string) (name, namespace string, port int32, err error) {
	// Format: servicename.namespace.svc.cluster.local:port
	parts := strings.SplitN(endpoint, ":", 2)
	if len(parts) != 2 {
		return "", "", 0, fmt.Errorf("invalid endpoint format: %s", endpoint)
	}

	portNum, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid port: %s", parts[1])
	}

	hostParts := strings.Split(parts[0], ".")
	if len(hostParts) < 2 {
		return "", "", 0, fmt.Errorf("invalid hostname format: %s", parts[0])
	}

	return hostParts[0], hostParts[1], int32(portNum), nil
}
