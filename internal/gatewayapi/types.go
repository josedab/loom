// Package gatewayapi provides Kubernetes Gateway API conformance for Loom.
// It implements the Gateway API specification for declarative traffic routing.
package gatewayapi

import (
	"time"
)

// ObjectMeta contains metadata for Gateway API objects.
type ObjectMeta struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Generation  int64             `json:"generation,omitempty" yaml:"generation,omitempty"`
}

// TypeMeta describes the type of a Gateway API object.
type TypeMeta struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
}

// GatewayClass represents a class of Gateway implementations.
// This is a cluster-scoped resource that defines which controller
// handles Gateways of this class.
type GatewayClass struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       GatewayClassSpec   `json:"spec" yaml:"spec"`
	Status     GatewayClassStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// GatewayClassSpec defines the desired state of GatewayClass.
type GatewayClassSpec struct {
	// ControllerName is the name of the controller that should handle this
	// class of Gateways.
	ControllerName string `json:"controllerName" yaml:"controllerName"`
	// Description is a description of this GatewayClass.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// ParametersRef references a resource that contains implementation-specific
	// configuration for this GatewayClass.
	ParametersRef *ParametersReference `json:"parametersRef,omitempty" yaml:"parametersRef,omitempty"`
}

// ParametersReference references a resource that contains configuration.
type ParametersReference struct {
	Group     string `json:"group" yaml:"group"`
	Kind      string `json:"kind" yaml:"kind"`
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// GatewayClassStatus defines the observed state of GatewayClass.
type GatewayClassStatus struct {
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// Gateway represents an instance of a Gateway implementation.
// It binds to a GatewayClass and defines listeners for traffic.
type Gateway struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       GatewaySpec   `json:"spec" yaml:"spec"`
	Status     GatewayStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// GatewaySpec defines the desired state of Gateway.
type GatewaySpec struct {
	// GatewayClassName is the name of the GatewayClass this Gateway belongs to.
	GatewayClassName string `json:"gatewayClassName" yaml:"gatewayClassName"`
	// Listeners define the traffic ports this Gateway handles.
	Listeners []Listener `json:"listeners" yaml:"listeners"`
	// Addresses define the addresses this Gateway should use.
	Addresses []GatewayAddress `json:"addresses,omitempty" yaml:"addresses,omitempty"`
}

// Listener defines a port on which the Gateway listens.
type Listener struct {
	// Name is a unique name for this listener within the Gateway.
	Name string `json:"name" yaml:"name"`
	// Hostname is the hostname to match for this listener.
	Hostname *string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Port is the network port to listen on.
	Port int32 `json:"port" yaml:"port"`
	// Protocol is the protocol (HTTP, HTTPS, TLS, TCP, UDP).
	Protocol ProtocolType `json:"protocol" yaml:"protocol"`
	// TLS defines TLS configuration for this listener.
	TLS *GatewayTLSConfig `json:"tls,omitempty" yaml:"tls,omitempty"`
	// AllowedRoutes defines which routes can bind to this listener.
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty" yaml:"allowedRoutes,omitempty"`
}

// ProtocolType defines the protocol for a listener.
type ProtocolType string

const (
	HTTPProtocolType   ProtocolType = "HTTP"
	HTTPSProtocolType  ProtocolType = "HTTPS"
	TLSProtocolType    ProtocolType = "TLS"
	TCPProtocolType    ProtocolType = "TCP"
	UDPProtocolType    ProtocolType = "UDP"
	GRPCProtocolType   ProtocolType = "GRPC"
)

// GatewayTLSConfig defines TLS configuration for a Gateway listener.
type GatewayTLSConfig struct {
	// Mode defines how TLS termination is handled.
	Mode *TLSModeType `json:"mode,omitempty" yaml:"mode,omitempty"`
	// CertificateRefs are references to TLS certificates.
	CertificateRefs []SecretObjectReference `json:"certificateRefs,omitempty" yaml:"certificateRefs,omitempty"`
	// Options are implementation-specific TLS options.
	Options map[string]string `json:"options,omitempty" yaml:"options,omitempty"`
}

// TLSModeType defines TLS termination mode.
type TLSModeType string

const (
	TLSModeTerminate TLSModeType = "Terminate"
	TLSModePassthrough TLSModeType = "Passthrough"
)

// SecretObjectReference references a Kubernetes Secret.
type SecretObjectReference struct {
	Group     *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind      *string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Name      string  `json:"name" yaml:"name"`
	Namespace *string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// AllowedRoutes defines which routes can attach to a listener.
type AllowedRoutes struct {
	// Namespaces defines which namespaces routes can come from.
	Namespaces *RouteNamespaces `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	// Kinds defines which route types are allowed.
	Kinds []RouteGroupKind `json:"kinds,omitempty" yaml:"kinds,omitempty"`
}

// RouteNamespaces defines namespace selection for routes.
type RouteNamespaces struct {
	// From determines which namespaces routes may attach from.
	From *FromNamespaces `json:"from,omitempty" yaml:"from,omitempty"`
	// Selector is a label selector for allowed namespaces.
	Selector *LabelSelector `json:"selector,omitempty" yaml:"selector,omitempty"`
}

// FromNamespaces defines namespace selection mode.
type FromNamespaces string

const (
	NamespacesFromAll      FromNamespaces = "All"
	NamespacesFromSame     FromNamespaces = "Same"
	NamespacesFromSelector FromNamespaces = "Selector"
)

// LabelSelector is a label-based selector.
type LabelSelector struct {
	MatchLabels      map[string]string    `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
	MatchExpressions []SelectorExpression `json:"matchExpressions,omitempty" yaml:"matchExpressions,omitempty"`
}

// SelectorExpression is a selector requirement.
type SelectorExpression struct {
	Key      string   `json:"key" yaml:"key"`
	Operator string   `json:"operator" yaml:"operator"`
	Values   []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// RouteGroupKind defines a route type.
type RouteGroupKind struct {
	Group *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind  string  `json:"kind" yaml:"kind"`
}

// GatewayAddress defines an address for the Gateway.
type GatewayAddress struct {
	Type  *AddressType `json:"type,omitempty" yaml:"type,omitempty"`
	Value string       `json:"value" yaml:"value"`
}

// AddressType defines the type of address.
type AddressType string

const (
	IPAddressType       AddressType = "IPAddress"
	HostnameAddressType AddressType = "Hostname"
)

// GatewayStatus defines the observed state of Gateway.
type GatewayStatus struct {
	Conditions []Condition       `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Listeners  []ListenerStatus  `json:"listeners,omitempty" yaml:"listeners,omitempty"`
	Addresses  []GatewayAddress  `json:"addresses,omitempty" yaml:"addresses,omitempty"`
}

// ListenerStatus is the status of a Gateway listener.
type ListenerStatus struct {
	Name           string       `json:"name" yaml:"name"`
	AttachedRoutes int32        `json:"attachedRoutes" yaml:"attachedRoutes"`
	Conditions     []Condition  `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	SupportedKinds []RouteGroupKind `json:"supportedKinds,omitempty" yaml:"supportedKinds,omitempty"`
}

// HTTPRoute defines HTTP routing rules.
type HTTPRoute struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       HTTPRouteSpec   `json:"spec" yaml:"spec"`
	Status     HTTPRouteStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// HTTPRouteSpec defines the desired state of HTTPRoute.
type HTTPRouteSpec struct {
	// ParentRefs are references to the Gateways this route attaches to.
	ParentRefs []ParentReference `json:"parentRefs,omitempty" yaml:"parentRefs,omitempty"`
	// Hostnames are the hostnames this route matches.
	Hostnames []string `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	// Rules define the routing rules.
	Rules []HTTPRouteRule `json:"rules" yaml:"rules"`
}

// ParentReference references a parent (usually a Gateway).
type ParentReference struct {
	Group       *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind        *string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Namespace   *string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name        string  `json:"name" yaml:"name"`
	SectionName *string `json:"sectionName,omitempty" yaml:"sectionName,omitempty"`
	Port        *int32  `json:"port,omitempty" yaml:"port,omitempty"`
}

// HTTPRouteRule defines a routing rule.
type HTTPRouteRule struct {
	// Matches define conditions for matching requests.
	Matches []HTTPRouteMatch `json:"matches,omitempty" yaml:"matches,omitempty"`
	// Filters define request/response modifications.
	Filters []HTTPRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
	// BackendRefs define the backends to route to.
	BackendRefs []HTTPBackendRef `json:"backendRefs,omitempty" yaml:"backendRefs,omitempty"`
	// Timeouts define request timeouts.
	Timeouts *HTTPRouteTimeouts `json:"timeouts,omitempty" yaml:"timeouts,omitempty"`
}

// HTTPRouteMatch defines conditions for matching HTTP requests.
type HTTPRouteMatch struct {
	// Path matches the URL path.
	Path *HTTPPathMatch `json:"path,omitempty" yaml:"path,omitempty"`
	// Headers match HTTP headers.
	Headers []HTTPHeaderMatch `json:"headers,omitempty" yaml:"headers,omitempty"`
	// QueryParams match query parameters.
	QueryParams []HTTPQueryParamMatch `json:"queryParams,omitempty" yaml:"queryParams,omitempty"`
	// Method matches the HTTP method.
	Method *HTTPMethod `json:"method,omitempty" yaml:"method,omitempty"`
}

// HTTPPathMatch defines path matching.
type HTTPPathMatch struct {
	Type  *PathMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	Value *string        `json:"value,omitempty" yaml:"value,omitempty"`
}

// PathMatchType defines how paths are matched.
type PathMatchType string

const (
	PathMatchExact             PathMatchType = "Exact"
	PathMatchPathPrefix        PathMatchType = "PathPrefix"
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HTTPHeaderMatch defines header matching.
type HTTPHeaderMatch struct {
	Type  *HeaderMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	Name  string           `json:"name" yaml:"name"`
	Value string           `json:"value" yaml:"value"`
}

// HeaderMatchType defines how headers are matched.
type HeaderMatchType string

const (
	HeaderMatchExact             HeaderMatchType = "Exact"
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// HTTPQueryParamMatch defines query parameter matching.
type HTTPQueryParamMatch struct {
	Type  *QueryParamMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	Name  string               `json:"name" yaml:"name"`
	Value string               `json:"value" yaml:"value"`
}

// QueryParamMatchType defines how query params are matched.
type QueryParamMatchType string

const (
	QueryParamMatchExact             QueryParamMatchType = "Exact"
	QueryParamMatchRegularExpression QueryParamMatchType = "RegularExpression"
)

// HTTPMethod is an HTTP method.
type HTTPMethod string

const (
	HTTPMethodGet     HTTPMethod = "GET"
	HTTPMethodHead    HTTPMethod = "HEAD"
	HTTPMethodPost    HTTPMethod = "POST"
	HTTPMethodPut     HTTPMethod = "PUT"
	HTTPMethodDelete  HTTPMethod = "DELETE"
	HTTPMethodConnect HTTPMethod = "CONNECT"
	HTTPMethodOptions HTTPMethod = "OPTIONS"
	HTTPMethodTrace   HTTPMethod = "TRACE"
	HTTPMethodPatch   HTTPMethod = "PATCH"
)

// HTTPRouteFilter defines filters for modifying requests/responses.
type HTTPRouteFilter struct {
	Type                   FilterType                    `json:"type" yaml:"type"`
	RequestHeaderModifier  *HTTPHeaderFilter             `json:"requestHeaderModifier,omitempty" yaml:"requestHeaderModifier,omitempty"`
	ResponseHeaderModifier *HTTPHeaderFilter             `json:"responseHeaderModifier,omitempty" yaml:"responseHeaderModifier,omitempty"`
	RequestMirror          *HTTPRequestMirrorFilter      `json:"requestMirror,omitempty" yaml:"requestMirror,omitempty"`
	RequestRedirect        *HTTPRequestRedirectFilter    `json:"requestRedirect,omitempty" yaml:"requestRedirect,omitempty"`
	URLRewrite             *HTTPURLRewriteFilter         `json:"urlRewrite,omitempty" yaml:"urlRewrite,omitempty"`
	ExtensionRef           *LocalObjectReference         `json:"extensionRef,omitempty" yaml:"extensionRef,omitempty"`
}

// FilterType defines the type of filter.
type FilterType string

const (
	FilterTypeRequestHeaderModifier  FilterType = "RequestHeaderModifier"
	FilterTypeResponseHeaderModifier FilterType = "ResponseHeaderModifier"
	FilterTypeRequestMirror          FilterType = "RequestMirror"
	FilterTypeRequestRedirect        FilterType = "RequestRedirect"
	FilterTypeURLRewrite             FilterType = "URLRewrite"
	FilterTypeExtensionRef           FilterType = "ExtensionRef"
)

// HTTPHeaderFilter defines header modifications.
type HTTPHeaderFilter struct {
	Set    []HTTPHeader `json:"set,omitempty" yaml:"set,omitempty"`
	Add    []HTTPHeader `json:"add,omitempty" yaml:"add,omitempty"`
	Remove []string     `json:"remove,omitempty" yaml:"remove,omitempty"`
}

// HTTPHeader is a name/value header pair.
type HTTPHeader struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// HTTPRequestMirrorFilter defines request mirroring.
type HTTPRequestMirrorFilter struct {
	BackendRef BackendObjectReference `json:"backendRef" yaml:"backendRef"`
}

// HTTPRequestRedirectFilter defines request redirection.
type HTTPRequestRedirectFilter struct {
	Scheme     *string                `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Hostname   *string                `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Path       *HTTPPathModifier      `json:"path,omitempty" yaml:"path,omitempty"`
	Port       *int32                 `json:"port,omitempty" yaml:"port,omitempty"`
	StatusCode *int                   `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
}

// HTTPPathModifier defines path modifications.
type HTTPPathModifier struct {
	Type               PathModifierType `json:"type" yaml:"type"`
	ReplaceFullPath    *string          `json:"replaceFullPath,omitempty" yaml:"replaceFullPath,omitempty"`
	ReplacePrefixMatch *string          `json:"replacePrefixMatch,omitempty" yaml:"replacePrefixMatch,omitempty"`
}

// PathModifierType defines how paths are modified.
type PathModifierType string

const (
	PathModifierReplaceFullPath    PathModifierType = "ReplaceFullPath"
	PathModifierReplacePrefixMatch PathModifierType = "ReplacePrefixMatch"
)

// HTTPURLRewriteFilter defines URL rewrites.
type HTTPURLRewriteFilter struct {
	Hostname *string           `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Path     *HTTPPathModifier `json:"path,omitempty" yaml:"path,omitempty"`
}

// LocalObjectReference references an object in the same namespace.
type LocalObjectReference struct {
	Group *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind  string  `json:"kind" yaml:"kind"`
	Name  string  `json:"name" yaml:"name"`
}

// HTTPBackendRef references a backend with weight.
type HTTPBackendRef struct {
	BackendObjectReference `json:",inline" yaml:",inline"`
	Weight                 *int32            `json:"weight,omitempty" yaml:"weight,omitempty"`
	Filters                []HTTPRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
}

// BackendObjectReference references a backend object.
type BackendObjectReference struct {
	Group     *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind      *string `json:"kind,omitempty" yaml:"kind,omitempty"`
	Name      string  `json:"name" yaml:"name"`
	Namespace *string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Port      *int32  `json:"port,omitempty" yaml:"port,omitempty"`
}

// HTTPRouteTimeouts defines request timeouts.
type HTTPRouteTimeouts struct {
	Request        *Duration `json:"request,omitempty" yaml:"request,omitempty"`
	BackendRequest *Duration `json:"backendRequest,omitempty" yaml:"backendRequest,omitempty"`
}

// Duration is a time duration string.
type Duration string

// ToDuration parses the duration string.
func (d Duration) ToDuration() time.Duration {
	if d == "" {
		return 0
	}
	parsed, err := time.ParseDuration(string(d))
	if err != nil {
		return 0
	}
	return parsed
}

// HTTPRouteStatus defines the observed state of HTTPRoute.
type HTTPRouteStatus struct {
	RouteStatus `json:",inline" yaml:",inline"`
}

// RouteStatus defines common route status.
type RouteStatus struct {
	Parents []RouteParentStatus `json:"parents" yaml:"parents"`
}

// RouteParentStatus describes the status of a route with respect to a parent.
type RouteParentStatus struct {
	ParentRef   ParentReference `json:"parentRef" yaml:"parentRef"`
	ControllerName string       `json:"controllerName" yaml:"controllerName"`
	Conditions  []Condition     `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// Condition describes the state of a resource.
type Condition struct {
	Type               string    `json:"type" yaml:"type"`
	Status             string    `json:"status" yaml:"status"`
	ObservedGeneration int64     `json:"observedGeneration,omitempty" yaml:"observedGeneration,omitempty"`
	LastTransitionTime time.Time `json:"lastTransitionTime" yaml:"lastTransitionTime"`
	Reason             string    `json:"reason" yaml:"reason"`
	Message            string    `json:"message,omitempty" yaml:"message,omitempty"`
}

// GRPCRoute defines gRPC routing rules.
type GRPCRoute struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       GRPCRouteSpec   `json:"spec" yaml:"spec"`
	Status     GRPCRouteStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// GRPCRouteSpec defines the desired state of GRPCRoute.
type GRPCRouteSpec struct {
	ParentRefs []ParentReference `json:"parentRefs,omitempty" yaml:"parentRefs,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	Rules      []GRPCRouteRule   `json:"rules" yaml:"rules"`
}

// GRPCRouteRule defines a gRPC routing rule.
type GRPCRouteRule struct {
	Matches     []GRPCRouteMatch  `json:"matches,omitempty" yaml:"matches,omitempty"`
	Filters     []GRPCRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
	BackendRefs []GRPCBackendRef  `json:"backendRefs,omitempty" yaml:"backendRefs,omitempty"`
}

// GRPCRouteMatch defines matching conditions for gRPC requests.
type GRPCRouteMatch struct {
	Method  *GRPCMethodMatch   `json:"method,omitempty" yaml:"method,omitempty"`
	Headers []GRPCHeaderMatch  `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// GRPCMethodMatch matches gRPC methods.
type GRPCMethodMatch struct {
	Type    *GRPCMethodMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	Service *string              `json:"service,omitempty" yaml:"service,omitempty"`
	Method  *string              `json:"method,omitempty" yaml:"method,omitempty"`
}

// GRPCMethodMatchType defines how methods are matched.
type GRPCMethodMatchType string

const (
	GRPCMethodMatchExact             GRPCMethodMatchType = "Exact"
	GRPCMethodMatchRegularExpression GRPCMethodMatchType = "RegularExpression"
)

// GRPCHeaderMatch matches gRPC headers.
type GRPCHeaderMatch struct {
	Type  *HeaderMatchType `json:"type,omitempty" yaml:"type,omitempty"`
	Name  string           `json:"name" yaml:"name"`
	Value string           `json:"value" yaml:"value"`
}

// GRPCRouteFilter defines filters for gRPC requests.
type GRPCRouteFilter struct {
	Type                   FilterType            `json:"type" yaml:"type"`
	RequestHeaderModifier  *HTTPHeaderFilter     `json:"requestHeaderModifier,omitempty" yaml:"requestHeaderModifier,omitempty"`
	ResponseHeaderModifier *HTTPHeaderFilter     `json:"responseHeaderModifier,omitempty" yaml:"responseHeaderModifier,omitempty"`
	RequestMirror          *HTTPRequestMirrorFilter `json:"requestMirror,omitempty" yaml:"requestMirror,omitempty"`
	ExtensionRef           *LocalObjectReference `json:"extensionRef,omitempty" yaml:"extensionRef,omitempty"`
}

// GRPCBackendRef references a gRPC backend.
type GRPCBackendRef struct {
	BackendObjectReference `json:",inline" yaml:",inline"`
	Weight                 *int32            `json:"weight,omitempty" yaml:"weight,omitempty"`
	Filters                []GRPCRouteFilter `json:"filters,omitempty" yaml:"filters,omitempty"`
}

// GRPCRouteStatus defines the observed state of GRPCRoute.
type GRPCRouteStatus struct {
	RouteStatus `json:",inline" yaml:",inline"`
}

// TLSRoute defines TLS routing rules for SNI-based routing.
type TLSRoute struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       TLSRouteSpec   `json:"spec" yaml:"spec"`
	Status     TLSRouteStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// TLSRouteSpec defines the desired state of TLSRoute.
type TLSRouteSpec struct {
	ParentRefs []ParentReference `json:"parentRefs,omitempty" yaml:"parentRefs,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty" yaml:"hostnames,omitempty"`
	Rules      []TLSRouteRule    `json:"rules" yaml:"rules"`
}

// TLSRouteRule defines a TLS routing rule.
type TLSRouteRule struct {
	BackendRefs []BackendRef `json:"backendRefs,omitempty" yaml:"backendRefs,omitempty"`
}

// BackendRef references a backend with weight.
type BackendRef struct {
	BackendObjectReference `json:",inline" yaml:",inline"`
	Weight                 *int32 `json:"weight,omitempty" yaml:"weight,omitempty"`
}

// TLSRouteStatus defines the observed state of TLSRoute.
type TLSRouteStatus struct {
	RouteStatus `json:",inline" yaml:",inline"`
}
