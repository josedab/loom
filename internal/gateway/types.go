// Package gateway provides Kubernetes Gateway API support for Loom.
package gateway

import (
	"time"
)

// GatewayClass defines a class of Gateways.
// This is analogous to IngressClass for Ingress.
type GatewayClass struct {
	// Name is the unique name of the GatewayClass.
	Name string `json:"name" yaml:"name"`
	// ControllerName is the name of the controller that manages Gateways of this class.
	// For Loom, this should be "loom.io/gateway-controller".
	ControllerName string `json:"controllerName" yaml:"controllerName"`
	// Description provides human-readable description of the class.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// ParametersRef references a resource containing additional parameters.
	ParametersRef *ParametersReference `json:"parametersRef,omitempty" yaml:"parametersRef,omitempty"`
}

// ParametersReference identifies a resource containing configuration parameters.
type ParametersReference struct {
	// Group is the API group of the referent.
	Group string `json:"group" yaml:"group"`
	// Kind is the kind of the referent.
	Kind string `json:"kind" yaml:"kind"`
	// Name is the name of the referent.
	Name string `json:"name" yaml:"name"`
	// Namespace is the namespace of the referent.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// Gateway represents a Kubernetes Gateway API Gateway resource.
type Gateway struct {
	// Name is the unique name of the Gateway.
	Name string `json:"name" yaml:"name"`
	// Namespace is the Kubernetes namespace of the Gateway.
	Namespace string `json:"namespace" yaml:"namespace"`
	// GatewayClassName references a GatewayClass.
	GatewayClassName string `json:"gatewayClassName" yaml:"gatewayClassName"`
	// Listeners define the ports/protocols the Gateway should listen on.
	Listeners []Listener `json:"listeners" yaml:"listeners"`
	// Addresses define the network addresses the Gateway should bind to.
	Addresses []GatewayAddress `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	// Status contains the runtime status of the Gateway.
	Status GatewayStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// Listener defines a port/protocol combination on the Gateway.
type Listener struct {
	// Name is the unique name of the listener within this Gateway.
	Name string `json:"name" yaml:"name"`
	// Hostname is the optional hostname to match.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Port is the network port to listen on.
	Port int32 `json:"port" yaml:"port"`
	// Protocol is the protocol for this listener (HTTP, HTTPS, TLS, TCP, UDP).
	Protocol Protocol `json:"protocol" yaml:"protocol"`
	// TLS configuration for HTTPS/TLS listeners.
	TLS *GatewayTLSConfig `json:"tls,omitempty" yaml:"tls,omitempty"`
	// AllowedRoutes specifies which routes can bind to this listener.
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty" yaml:"allowedRoutes,omitempty"`
}

// Protocol defines the protocol for a Gateway listener.
type Protocol string

const (
	// ProtocolHTTP is plain HTTP.
	ProtocolHTTP Protocol = "HTTP"
	// ProtocolHTTPS is HTTPS with TLS termination.
	ProtocolHTTPS Protocol = "HTTPS"
	// ProtocolTLS is TLS passthrough.
	ProtocolTLS Protocol = "TLS"
	// ProtocolTCP is raw TCP.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is raw UDP.
	ProtocolUDP Protocol = "UDP"
)

// GatewayTLSConfig defines TLS configuration for a Gateway listener.
type GatewayTLSConfig struct {
	// Mode defines how TLS is handled (Terminate, Passthrough).
	Mode TLSMode `json:"mode,omitempty" yaml:"mode,omitempty"`
	// CertificateRefs references Kubernetes Secrets containing TLS certificates.
	CertificateRefs []SecretObjectReference `json:"certificateRefs,omitempty" yaml:"certificateRefs,omitempty"`
	// Options are additional TLS options.
	Options map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
}

// TLSMode defines how TLS is handled by the Gateway.
type TLSMode string

const (
	// TLSModeTerminate terminates TLS at the Gateway.
	TLSModeTerminate TLSMode = "Terminate"
	// TLSModePassthrough passes TLS through to the backend.
	TLSModePassthrough TLSMode = "Passthrough"
)

// SecretObjectReference references a Kubernetes Secret.
type SecretObjectReference struct {
	// Group is the API group of the referent (typically "" for core resources).
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
	// Kind is the kind of the referent (typically "Secret").
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
	// Name is the name of the Secret.
	Name string `json:"name" yaml:"name"`
	// Namespace is the namespace of the Secret.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// AllowedRoutes defines which routes can bind to this listener.
type AllowedRoutes struct {
	// Namespaces defines which namespaces can have Routes bound to this listener.
	Namespaces *RouteNamespaces `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	// Kinds defines which route kinds can bind to this listener.
	Kinds []RouteGroupKind `json:"kinds,omitempty" yaml:"kinds,omitempty"`
}

// RouteNamespaces defines namespace selection for routes.
type RouteNamespaces struct {
	// From indicates where Routes can be selected from.
	From FromNamespaces `json:"from,omitempty" yaml:"from,omitempty"`
	// Selector is a label selector for namespaces when From is "Selector".
	Selector *LabelSelector `json:"selector,omitempty" yaml:"selector,omitempty"`
}

// FromNamespaces defines which namespaces routes can come from.
type FromNamespaces string

const (
	// NamespacesFromAll allows routes from all namespaces.
	NamespacesFromAll FromNamespaces = "All"
	// NamespacesFromSame allows routes only from the same namespace as the Gateway.
	NamespacesFromSame FromNamespaces = "Same"
	// NamespacesFromSelector allows routes from namespaces matching a selector.
	NamespacesFromSelector FromNamespaces = "Selector"
)

// LabelSelector is a label selector for filtering resources.
type LabelSelector struct {
	// MatchLabels is a map of label key/value pairs.
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// RouteGroupKind identifies a kind of route.
type RouteGroupKind struct {
	// Group is the API group of the route.
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
	// Kind is the kind of the route.
	Kind string `json:"kind" yaml:"kind"`
}

// GatewayAddress describes a Gateway address.
type GatewayAddress struct {
	// Type is the type of address (IPAddress, Hostname, NamedAddress).
	Type AddressType `json:"type,omitempty" yaml:"type,omitempty"`
	// Value is the address value.
	Value string `json:"value" yaml:"value"`
}

// AddressType defines the type of Gateway address.
type AddressType string

const (
	// AddressTypeIPAddress is an IP address.
	AddressTypeIPAddress AddressType = "IPAddress"
	// AddressTypeHostname is a DNS hostname.
	AddressTypeHostname AddressType = "Hostname"
	// AddressTypeNamedAddress is a named address.
	AddressTypeNamedAddress AddressType = "NamedAddress"
)

// GatewayStatus represents the runtime status of a Gateway.
type GatewayStatus struct {
	// Conditions describe the current state of the Gateway.
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	// Listeners contains status for each listener.
	Listeners []ListenerStatus `json:"listeners,omitempty" yaml:"listeners,omitempty"`
	// Addresses contains the addresses assigned to the Gateway.
	Addresses []GatewayAddress `json:"addresses,omitempty" yaml:"addresses,omitempty"`
}

// Condition describes a condition of a resource.
type Condition struct {
	// Type is the type of condition.
	Type string `json:"type" yaml:"type"`
	// Status is the status of the condition (True, False, Unknown).
	Status ConditionStatus `json:"status" yaml:"status"`
	// Reason is a machine-readable reason for the condition.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	// Message is a human-readable description of the condition.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
	// LastTransitionTime is the last time the condition changed.
	LastTransitionTime time.Time `json:"lastTransitionTime,omitempty" yaml:"lastTransitionTime,omitempty"`
	// ObservedGeneration is the generation observed when setting this condition.
	ObservedGeneration int64 `json:"observedGeneration,omitempty" yaml:"observedGeneration,omitempty"`
}

// ConditionStatus is the status of a condition.
type ConditionStatus string

const (
	// ConditionTrue indicates the condition is true.
	ConditionTrue ConditionStatus = "True"
	// ConditionFalse indicates the condition is false.
	ConditionFalse ConditionStatus = "False"
	// ConditionUnknown indicates the condition status is unknown.
	ConditionUnknown ConditionStatus = "Unknown"
)

// ListenerStatus describes the status of a listener.
type ListenerStatus struct {
	// Name is the name of the listener.
	Name string `json:"name" yaml:"name"`
	// SupportedKinds lists the route kinds supported by this listener.
	SupportedKinds []RouteGroupKind `json:"supportedKinds,omitempty" yaml:"supportedKinds,omitempty"`
	// AttachedRoutes is the number of routes attached to this listener.
	AttachedRoutes int32 `json:"attachedRoutes" yaml:"attachedRoutes"`
	// Conditions describe the state of this listener.
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// HTTPRoute defines HTTP routing rules.
type HTTPRoute struct {
	// Name is the unique name of the HTTPRoute.
	Name string `json:"name" yaml:"name"`
	// Namespace is the Kubernetes namespace of the HTTPRoute.
	Namespace string `json:"namespace" yaml:"namespace"`
	// Hostnames are the hostnames this route applies to.
	Hostnames []string `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	// ParentRefs are the Gateways this route attaches to.
	ParentRefs []ParentReference `json:"parentRefs,omitempty" yaml:"parentRefs,omitempty"`
	// Rules define the routing rules.
	Rules []HTTPRouteRule `json:"rules" yaml:"rules"`
	// Status contains the runtime status of the HTTPRoute.
	Status HTTPRouteStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// ParentReference identifies a parent Gateway.
type ParentReference struct {
	// Group is the API group of the parent.
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
	// Kind is the kind of the parent (typically "Gateway").
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
	// Namespace is the namespace of the parent.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// Name is the name of the parent Gateway.
	Name string `json:"name" yaml:"name"`
	// SectionName is the name of a specific listener in the parent Gateway.
	SectionName string `json:"sectionName,omitempty" yaml:"sectionName,omitempty"`
	// Port is the port of the parent Gateway.
	Port *int32 `json:"port,omitempty" yaml:"port,omitempty"`
}

// HTTPRouteRule defines a single HTTP routing rule.
type HTTPRouteRule struct {
	// Matches define the conditions for this rule.
	Matches []HTTPRouteMatch `json:"matches,omitempty" yaml:"matches,omitempty"`
	// Filters define processing to perform on requests matching this rule.
	Filters []HTTPRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
	// BackendRefs define the backends to forward matching requests to.
	BackendRefs []HTTPBackendRef `json:"backendRefs,omitempty" yaml:"backendRefs,omitempty"`
	// Timeouts define timeout settings for this rule.
	Timeouts *HTTPRouteTimeouts `json:"timeouts,omitempty" yaml:"timeouts,omitempty"`
}

// HTTPRouteMatch defines match conditions for an HTTP request.
type HTTPRouteMatch struct {
	// Path specifies a HTTP request path to match.
	Path *HTTPPathMatch `json:"path,omitempty" yaml:"path,omitempty"`
	// Headers specifies HTTP headers to match.
	Headers []HTTPHeaderMatch `json:"headers,omitempty" yaml:"headers,omitempty"`
	// QueryParams specifies query parameters to match.
	QueryParams []HTTPQueryParamMatch `json:"queryParams,omitempty" yaml:"queryParams,omitempty"`
	// Method specifies the HTTP method to match.
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
}

// HTTPPathMatch describes how to match an HTTP path.
type HTTPPathMatch struct {
	// Type is the type of path match (Exact, PathPrefix, RegularExpression).
	Type PathMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	// Value is the path to match.
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// PathMatchType defines the type of path matching.
type PathMatchType string

const (
	// PathMatchExact matches the path exactly.
	PathMatchExact PathMatchType = "Exact"
	// PathMatchPathPrefix matches path prefixes.
	PathMatchPathPrefix PathMatchType = "PathPrefix"
	// PathMatchRegularExpression matches using a regex.
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HTTPHeaderMatch describes how to match an HTTP header.
type HTTPHeaderMatch struct {
	// Type is the type of match (Exact, RegularExpression).
	Type HeaderMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	// Name is the header name.
	Name string `json:"name" yaml:"name"`
	// Value is the header value to match.
	Value string `json:"value" yaml:"value"`
}

// HeaderMatchType defines the type of header matching.
type HeaderMatchType string

const (
	// HeaderMatchExact matches the header exactly.
	HeaderMatchExact HeaderMatchType = "Exact"
	// HeaderMatchRegularExpression matches using a regex.
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// HTTPQueryParamMatch describes how to match a query parameter.
type HTTPQueryParamMatch struct {
	// Type is the type of match (Exact, RegularExpression).
	Type QueryParamMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	// Name is the query parameter name.
	Name string `json:"name" yaml:"name"`
	// Value is the value to match.
	Value string `json:"value" yaml:"value"`
}

// QueryParamMatchType defines the type of query parameter matching.
type QueryParamMatchType string

const (
	// QueryParamMatchExact matches the parameter exactly.
	QueryParamMatchExact QueryParamMatchType = "Exact"
	// QueryParamMatchRegularExpression matches using a regex.
	QueryParamMatchRegularExpression QueryParamMatchType = "RegularExpression"
)

// HTTPRouteFilter defines processing for matched requests.
type HTTPRouteFilter struct {
	// Type is the type of filter.
	Type HTTPRouteFilterType `json:"type" yaml:"type"`
	// RequestHeaderModifier modifies request headers.
	RequestHeaderModifier *HTTPHeaderFilter `json:"requestHeaderModifier,omitempty" yaml:"requestHeaderModifier,omitempty"`
	// ResponseHeaderModifier modifies response headers.
	ResponseHeaderModifier *HTTPHeaderFilter `json:"responseHeaderModifier,omitempty" yaml:"responseHeaderModifier,omitempty"`
	// RequestMirror mirrors requests to another backend.
	RequestMirror *HTTPRequestMirrorFilter `json:"requestMirror,omitempty" yaml:"requestMirror,omitempty"`
	// RequestRedirect redirects the request.
	RequestRedirect *HTTPRequestRedirectFilter `json:"requestRedirect,omitempty" yaml:"requestRedirect,omitempty"`
	// URLRewrite rewrites the request URL.
	URLRewrite *HTTPURLRewriteFilter `json:"urlRewrite,omitempty" yaml:"urlRewrite,omitempty"`
	// ExtensionRef references a custom filter resource.
	ExtensionRef *LocalObjectReference `json:"extensionRef,omitempty" yaml:"extensionRef,omitempty"`
}

// HTTPRouteFilterType is the type of an HTTP route filter.
type HTTPRouteFilterType string

const (
	// HTTPRouteFilterRequestHeaderModifier modifies request headers.
	HTTPRouteFilterRequestHeaderModifier HTTPRouteFilterType = "RequestHeaderModifier"
	// HTTPRouteFilterResponseHeaderModifier modifies response headers.
	HTTPRouteFilterResponseHeaderModifier HTTPRouteFilterType = "ResponseHeaderModifier"
	// HTTPRouteFilterRequestMirror mirrors requests.
	HTTPRouteFilterRequestMirror HTTPRouteFilterType = "RequestMirror"
	// HTTPRouteFilterRequestRedirect redirects requests.
	HTTPRouteFilterRequestRedirect HTTPRouteFilterType = "RequestRedirect"
	// HTTPRouteFilterURLRewrite rewrites URLs.
	HTTPRouteFilterURLRewrite HTTPRouteFilterType = "URLRewrite"
	// HTTPRouteFilterExtensionRef is a custom extension filter.
	HTTPRouteFilterExtensionRef HTTPRouteFilterType = "ExtensionRef"
)

// HTTPHeaderFilter defines header modification.
type HTTPHeaderFilter struct {
	// Set sets headers (replacing existing values).
	Set []HTTPHeader `json:"set,omitempty" yaml:"set,omitempty"`
	// Add adds headers (appending to existing values).
	Add []HTTPHeader `json:"add,omitempty" yaml:"add,omitempty"`
	// Remove removes headers by name.
	Remove []string `json:"remove,omitempty" yaml:"remove,omitempty"`
}

// HTTPHeader represents an HTTP header name/value pair.
type HTTPHeader struct {
	// Name is the header name.
	Name string `json:"name" yaml:"name"`
	// Value is the header value.
	Value string `json:"value" yaml:"value"`
}

// HTTPRequestMirrorFilter mirrors requests to another backend.
type HTTPRequestMirrorFilter struct {
	// BackendRef references the mirror backend.
	BackendRef BackendObjectReference `json:"backendRef" yaml:"backendRef"`
}

// HTTPRequestRedirectFilter defines a redirect.
type HTTPRequestRedirectFilter struct {
	// Scheme is the redirect scheme (http, https).
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	// Hostname is the redirect hostname.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Path is the redirect path.
	Path *HTTPPathModifier `json:"path,omitempty" yaml:"path,omitempty"`
	// Port is the redirect port.
	Port *int32 `json:"port,omitempty" yaml:"port,omitempty"`
	// StatusCode is the HTTP status code for the redirect.
	StatusCode int `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
}

// HTTPPathModifier modifies the request path.
type HTTPPathModifier struct {
	// Type is the type of path modification.
	Type HTTPPathModifierType `json:"type" yaml:"type"`
	// ReplaceFullPath replaces the entire path.
	ReplaceFullPath string `json:"replaceFullPath,omitempty" yaml:"replaceFullPath,omitempty"`
	// ReplacePrefixMatch replaces the matched prefix.
	ReplacePrefixMatch string `json:"replacePrefixMatch,omitempty" yaml:"replacePrefixMatch,omitempty"`
}

// HTTPPathModifierType is the type of path modification.
type HTTPPathModifierType string

const (
	// FullPathType replaces the entire path.
	FullPathType HTTPPathModifierType = "ReplaceFullPath"
	// PrefixMatchType replaces the prefix.
	PrefixMatchType HTTPPathModifierType = "ReplacePrefixMatch"
)

// HTTPURLRewriteFilter rewrites the URL.
type HTTPURLRewriteFilter struct {
	// Hostname rewrites the hostname.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Path modifies the path.
	Path *HTTPPathModifier `json:"path,omitempty" yaml:"path,omitempty"`
}

// LocalObjectReference identifies a resource in the same namespace.
type LocalObjectReference struct {
	// Group is the API group.
	Group string `json:"group" yaml:"group"`
	// Kind is the kind.
	Kind string `json:"kind" yaml:"kind"`
	// Name is the name.
	Name string `json:"name" yaml:"name"`
}

// HTTPBackendRef references a backend for HTTP routing.
type HTTPBackendRef struct {
	// BackendObjectReference identifies the backend.
	BackendObjectReference `json:",inline" yaml:",inline"`
	// Weight specifies the proportion of requests to send to this backend.
	Weight *int32 `json:"weight,omitempty" yaml:"weight,omitempty"`
	// Filters defines processing for requests to this backend.
	Filters []HTTPRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
}

// BackendObjectReference identifies a backend service.
type BackendObjectReference struct {
	// Group is the API group of the referent.
	Group string `json:"group,omitempty" yaml:"group,omitempty"`
	// Kind is the kind of the referent.
	Kind string `json:"kind,omitempty" yaml:"kind,omitempty"`
	// Name is the name of the referent.
	Name string `json:"name" yaml:"name"`
	// Namespace is the namespace of the referent.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// Port is the port of the referent.
	Port *int32 `json:"port,omitempty" yaml:"port,omitempty"`
}

// HTTPRouteTimeouts defines timeout settings.
type HTTPRouteTimeouts struct {
	// Request is the total timeout for the request.
	Request string `json:"request,omitempty" yaml:"request,omitempty"`
	// BackendRequest is the timeout for backend requests.
	BackendRequest string `json:"backendRequest,omitempty" yaml:"backendRequest,omitempty"`
}

// HTTPRouteStatus contains the status of an HTTPRoute.
type HTTPRouteStatus struct {
	// Parents contains the status for each parent Gateway.
	Parents []RouteParentStatus `json:"parents,omitempty" yaml:"parents,omitempty"`
}

// RouteParentStatus describes the status of a route with respect to a parent.
type RouteParentStatus struct {
	// ParentRef references the parent Gateway.
	ParentRef ParentReference `json:"parentRef" yaml:"parentRef"`
	// ControllerName is the name of the controller that wrote this status.
	ControllerName string `json:"controllerName" yaml:"controllerName"`
	// Conditions describe the state of the route with respect to this parent.
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}
