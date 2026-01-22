// Package gatewayapi provides Kubernetes Gateway API conformance for Loom.
package gatewayapi

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ReferenceGrant allows references from one namespace to another.
// This implements the Gateway API ReferenceGrant resource.
type ReferenceGrant struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       ReferenceGrantSpec `json:"spec" yaml:"spec"`
}

// ReferenceGrantSpec defines the desired state of ReferenceGrant.
type ReferenceGrantSpec struct {
	// From describes the trusted namespaces and kinds that can reference
	// the resources described in "To".
	From []ReferenceGrantFrom `json:"from" yaml:"from"`
	// To describes the resources that may be referenced by the subjects
	// described in "From".
	To []ReferenceGrantTo `json:"to" yaml:"to"`
}

// ReferenceGrantFrom describes a namespace and kinds that can reference resources.
type ReferenceGrantFrom struct {
	Group     string `json:"group" yaml:"group"`
	Kind      string `json:"kind" yaml:"kind"`
	Namespace string `json:"namespace" yaml:"namespace"`
}

// ReferenceGrantTo describes resources that can be referenced.
type ReferenceGrantTo struct {
	Group *string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind  string  `json:"kind" yaml:"kind"`
	Name  *string `json:"name,omitempty" yaml:"name,omitempty"`
}

// BackendTLSPolicy configures TLS settings for backend connections.
type BackendTLSPolicy struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       BackendTLSPolicySpec   `json:"spec" yaml:"spec"`
	Status     BackendTLSPolicyStatus `json:"status,omitempty" yaml:"status,omitempty"`
}

// BackendTLSPolicySpec defines the TLS configuration for backend connections.
type BackendTLSPolicySpec struct {
	// TargetRef identifies the backend to apply this policy to.
	TargetRef PolicyTargetReference `json:"targetRef" yaml:"targetRef"`
	// TLS defines the TLS configuration.
	TLS BackendTLSPolicyConfig `json:"tls" yaml:"tls"`
}

// PolicyTargetReference identifies a target for a policy.
type PolicyTargetReference struct {
	Group     string  `json:"group" yaml:"group"`
	Kind      string  `json:"kind" yaml:"kind"`
	Name      string  `json:"name" yaml:"name"`
	Namespace *string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// BackendTLSPolicyConfig defines TLS settings.
type BackendTLSPolicyConfig struct {
	// CACertRefs are references to CA certificates.
	CACertRefs []LocalObjectReference `json:"caCertRefs,omitempty" yaml:"caCertRefs,omitempty"`
	// Hostname is the hostname to verify in the backend's certificate.
	Hostname *string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// WellKnownCACerts allows using well-known CA bundles.
	WellKnownCACerts *WellKnownCACerts `json:"wellKnownCACerts,omitempty" yaml:"wellKnownCACerts,omitempty"`
}

// WellKnownCACerts defines well-known CA certificate bundles.
type WellKnownCACerts string

const (
	WellKnownCACertsSystem WellKnownCACerts = "System"
)

// BackendTLSPolicyStatus defines the observed state.
type BackendTLSPolicyStatus struct {
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

// HTTPRouteTimeoutsPolicy allows setting timeouts via policy.
type HTTPRouteTimeoutsPolicy struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       HTTPRouteTimeoutsPolicySpec `json:"spec" yaml:"spec"`
}

// HTTPRouteTimeoutsPolicySpec defines timeout settings.
type HTTPRouteTimeoutsPolicySpec struct {
	TargetRef PolicyTargetReference `json:"targetRef" yaml:"targetRef"`
	// Request timeout for the entire request.
	Request *Duration `json:"request,omitempty" yaml:"request,omitempty"`
	// BackendRequest timeout for backend connections.
	BackendRequest *Duration `json:"backendRequest,omitempty" yaml:"backendRequest,omitempty"`
	// Idle timeout for idle connections.
	Idle *Duration `json:"idle,omitempty" yaml:"idle,omitempty"`
}

// RetryPolicy defines retry behavior for requests.
type RetryPolicy struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       RetryPolicySpec `json:"spec" yaml:"spec"`
}

// RetryPolicySpec defines retry configuration.
type RetryPolicySpec struct {
	TargetRef PolicyTargetReference `json:"targetRef" yaml:"targetRef"`
	// NumRetries is the number of retries to attempt.
	NumRetries *int32 `json:"numRetries,omitempty" yaml:"numRetries,omitempty"`
	// RetryOn defines which conditions trigger a retry.
	RetryOn []string `json:"retryOn,omitempty" yaml:"retryOn,omitempty"`
	// PerTryTimeout is the timeout per retry attempt.
	PerTryTimeout *Duration `json:"perTryTimeout,omitempty" yaml:"perTryTimeout,omitempty"`
	// RetryBackoff defines backoff behavior between retries.
	RetryBackoff *RetryBackoff `json:"retryBackoff,omitempty" yaml:"retryBackoff,omitempty"`
}

// RetryBackoff defines retry backoff behavior.
type RetryBackoff struct {
	// BaseInterval is the initial backoff interval.
	BaseInterval *Duration `json:"baseInterval,omitempty" yaml:"baseInterval,omitempty"`
	// MaxInterval is the maximum backoff interval.
	MaxInterval *Duration `json:"maxInterval,omitempty" yaml:"maxInterval,omitempty"`
}

// RateLimitPolicy defines rate limiting for routes.
type RateLimitPolicy struct {
	TypeMeta   `json:",inline" yaml:",inline"`
	ObjectMeta `json:"metadata" yaml:"metadata"`
	Spec       RateLimitPolicySpec `json:"spec" yaml:"spec"`
}

// RateLimitPolicySpec defines rate limiting configuration.
type RateLimitPolicySpec struct {
	TargetRef PolicyTargetReference `json:"targetRef" yaml:"targetRef"`
	// Limits define the rate limit rules.
	Limits []RateLimitRule `json:"limits" yaml:"limits"`
}

// RateLimitRule defines a rate limit.
type RateLimitRule struct {
	// RequestsPerUnit is the number of allowed requests.
	RequestsPerUnit int32 `json:"requestsPerUnit" yaml:"requestsPerUnit"`
	// Unit is the time unit (second, minute, hour).
	Unit RateLimitUnit `json:"unit" yaml:"unit"`
	// Key defines what to rate limit on (client IP, header value, etc.).
	Key *RateLimitKey `json:"key,omitempty" yaml:"key,omitempty"`
}

// RateLimitUnit is a time unit for rate limiting.
type RateLimitUnit string

const (
	RateLimitUnitSecond RateLimitUnit = "second"
	RateLimitUnitMinute RateLimitUnit = "minute"
	RateLimitUnitHour   RateLimitUnit = "hour"
)

// RateLimitKey defines how to key rate limits.
type RateLimitKey struct {
	Type   RateLimitKeyType `json:"type" yaml:"type"`
	Header *string          `json:"header,omitempty" yaml:"header,omitempty"`
}

// RateLimitKeyType defines the key type.
type RateLimitKeyType string

const (
	RateLimitKeyTypeClientIP RateLimitKeyType = "ClientIP"
	RateLimitKeyTypeHeader   RateLimitKeyType = "Header"
)

// PolicyManager manages Gateway API extension policies.
type PolicyManager struct {
	referenceGrants    map[string]*ReferenceGrant
	backendTLSPolicies map[string]*BackendTLSPolicy
	timeoutPolicies    map[string]*HTTPRouteTimeoutsPolicy
	retryPolicies      map[string]*RetryPolicy
	rateLimitPolicies  map[string]*RateLimitPolicy
	mu                 sync.RWMutex
}

// NewPolicyManager creates a new policy manager.
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		referenceGrants:    make(map[string]*ReferenceGrant),
		backendTLSPolicies: make(map[string]*BackendTLSPolicy),
		timeoutPolicies:    make(map[string]*HTTPRouteTimeoutsPolicy),
		retryPolicies:      make(map[string]*RetryPolicy),
		rateLimitPolicies:  make(map[string]*RateLimitPolicy),
	}
}

// SetReferenceGrant adds or updates a ReferenceGrant.
func (pm *PolicyManager) SetReferenceGrant(rg *ReferenceGrant) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := rg.Namespace + "/" + rg.Name
	pm.referenceGrants[key] = rg
}

// DeleteReferenceGrant removes a ReferenceGrant.
func (pm *PolicyManager) DeleteReferenceGrant(namespace, name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.referenceGrants, namespace+"/"+name)
}

// IsReferenceAllowed checks if a reference is allowed by ReferenceGrants.
func (pm *PolicyManager) IsReferenceAllowed(fromGroup, fromKind, fromNamespace, toGroup, toKind, toNamespace, toName string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Same namespace references are always allowed
	if fromNamespace == toNamespace {
		return true
	}

	// Check reference grants in the target namespace
	for key, rg := range pm.referenceGrants {
		// Reference grant must be in the target namespace
		if rg.Namespace != toNamespace {
			continue
		}
		_ = key // Avoid unused variable warning

		// Check if the source is allowed
		fromAllowed := false
		for _, from := range rg.Spec.From {
			if from.Group == fromGroup && from.Kind == fromKind && from.Namespace == fromNamespace {
				fromAllowed = true
				break
			}
		}
		if !fromAllowed {
			continue
		}

		// Check if the target is allowed
		for _, to := range rg.Spec.To {
			targetGroup := ""
			if to.Group != nil {
				targetGroup = *to.Group
			}
			if targetGroup == toGroup && to.Kind == toKind {
				// Name can be specific or wildcard (nil = all)
				if to.Name == nil || *to.Name == toName {
					return true
				}
			}
		}
	}

	return false
}

// SetBackendTLSPolicy adds or updates a BackendTLSPolicy.
func (pm *PolicyManager) SetBackendTLSPolicy(policy *BackendTLSPolicy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := policy.Namespace + "/" + policy.Name
	pm.backendTLSPolicies[key] = policy
}

// DeleteBackendTLSPolicy removes a BackendTLSPolicy.
func (pm *PolicyManager) DeleteBackendTLSPolicy(namespace, name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.backendTLSPolicies, namespace+"/"+name)
}

// GetBackendTLSPolicy returns the TLS policy for a backend.
func (pm *PolicyManager) GetBackendTLSPolicy(group, kind, namespace, name string) *BackendTLSPolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.backendTLSPolicies {
		if policy.Namespace != namespace {
			continue
		}
		ref := policy.Spec.TargetRef
		refNs := namespace
		if ref.Namespace != nil {
			refNs = *ref.Namespace
		}
		if ref.Group == group && ref.Kind == kind && ref.Name == name && refNs == namespace {
			return policy
		}
	}
	return nil
}

// SetTimeoutPolicy adds or updates a timeout policy.
func (pm *PolicyManager) SetTimeoutPolicy(policy *HTTPRouteTimeoutsPolicy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := policy.Namespace + "/" + policy.Name
	pm.timeoutPolicies[key] = policy
}

// DeleteTimeoutPolicy removes a timeout policy.
func (pm *PolicyManager) DeleteTimeoutPolicy(namespace, name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.timeoutPolicies, namespace+"/"+name)
}

// GetTimeoutPolicy returns timeout settings for a target.
func (pm *PolicyManager) GetTimeoutPolicy(group, kind, namespace, name string) *HTTPRouteTimeoutsPolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.timeoutPolicies {
		ref := policy.Spec.TargetRef
		refNs := policy.Namespace
		if ref.Namespace != nil {
			refNs = *ref.Namespace
		}
		if ref.Group == group && ref.Kind == kind && ref.Name == name && refNs == namespace {
			return policy
		}
	}
	return nil
}

// SetRetryPolicy adds or updates a retry policy.
func (pm *PolicyManager) SetRetryPolicy(policy *RetryPolicy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := policy.Namespace + "/" + policy.Name
	pm.retryPolicies[key] = policy
}

// DeleteRetryPolicy removes a retry policy.
func (pm *PolicyManager) DeleteRetryPolicy(namespace, name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.retryPolicies, namespace+"/"+name)
}

// GetRetryPolicy returns retry settings for a target.
func (pm *PolicyManager) GetRetryPolicy(group, kind, namespace, name string) *RetryPolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.retryPolicies {
		ref := policy.Spec.TargetRef
		refNs := policy.Namespace
		if ref.Namespace != nil {
			refNs = *ref.Namespace
		}
		if ref.Group == group && ref.Kind == kind && ref.Name == name && refNs == namespace {
			return policy
		}
	}
	return nil
}

// SetRateLimitPolicy adds or updates a rate limit policy.
func (pm *PolicyManager) SetRateLimitPolicy(policy *RateLimitPolicy) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := policy.Namespace + "/" + policy.Name
	pm.rateLimitPolicies[key] = policy
}

// DeleteRateLimitPolicy removes a rate limit policy.
func (pm *PolicyManager) DeleteRateLimitPolicy(namespace, name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.rateLimitPolicies, namespace+"/"+name)
}

// GetRateLimitPolicy returns rate limit settings for a target.
func (pm *PolicyManager) GetRateLimitPolicy(group, kind, namespace, name string) *RateLimitPolicy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.rateLimitPolicies {
		ref := policy.Spec.TargetRef
		refNs := policy.Namespace
		if ref.Namespace != nil {
			refNs = *ref.Namespace
		}
		if ref.Group == group && ref.Kind == kind && ref.Name == name && refNs == namespace {
			return policy
		}
	}
	return nil
}

// PolicyAttachment represents the effective policies for a route.
type PolicyAttachment struct {
	TLSPolicy     *BackendTLSPolicy
	TimeoutPolicy *HTTPRouteTimeoutsPolicy
	RetryPolicy   *RetryPolicy
	RateLimitPolicy *RateLimitPolicy
}

// GetEffectivePolicies returns all effective policies for a route.
func (pm *PolicyManager) GetEffectivePolicies(routeGroup, routeKind, routeNamespace, routeName string) *PolicyAttachment {
	return &PolicyAttachment{
		TimeoutPolicy:   pm.GetTimeoutPolicy(routeGroup, routeKind, routeNamespace, routeName),
		RetryPolicy:     pm.GetRetryPolicy(routeGroup, routeKind, routeNamespace, routeName),
		RateLimitPolicy: pm.GetRateLimitPolicy(routeGroup, routeKind, routeNamespace, routeName),
	}
}

// StatusUpdater handles status updates for Gateway API resources.
type StatusUpdater struct {
	controller *Controller
	policies   *PolicyManager
	interval   time.Duration
	stopCh     chan struct{}
	mu         sync.Mutex
}

// NewStatusUpdater creates a new status updater.
func NewStatusUpdater(controller *Controller, policies *PolicyManager, interval time.Duration) *StatusUpdater {
	return &StatusUpdater{
		controller: controller,
		policies:   policies,
		interval:   interval,
		stopCh:     make(chan struct{}),
	}
}

// Start begins periodic status updates.
func (su *StatusUpdater) Start(ctx context.Context) {
	su.mu.Lock()
	su.stopCh = make(chan struct{})
	su.mu.Unlock()

	ticker := time.NewTicker(su.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-su.stopCh:
			return
		case <-ticker.C:
			su.updateStatuses()
		}
	}
}

// Stop stops the status updater.
func (su *StatusUpdater) Stop() {
	su.mu.Lock()
	defer su.mu.Unlock()
	close(su.stopCh)
}

// updateStatuses updates status for all resources.
func (su *StatusUpdater) updateStatuses() {
	// Update Gateway statuses
	gateways := su.controller.ListGateways()
	for _, gw := range gateways {
		su.updateGatewayStatus(gw)
	}

	// Update HTTPRoute statuses
	routes := su.controller.ListHTTPRoutes()
	for _, route := range routes {
		su.updateHTTPRouteStatus(route)
	}
}

// updateGatewayStatus updates the status of a Gateway.
func (su *StatusUpdater) updateGatewayStatus(gw *Gateway) {
	// Check if all listeners are programmed
	allProgrammed := true
	for _, ls := range gw.Status.Listeners {
		programmed := false
		for _, cond := range ls.Conditions {
			if cond.Type == "Programmed" && cond.Status == "True" {
				programmed = true
				break
			}
		}
		if !programmed {
			allProgrammed = false
			break
		}
	}

	// Update gateway conditions
	updated := false
	for i, cond := range gw.Status.Conditions {
		if cond.Type == "Programmed" {
			newStatus := "False"
			if allProgrammed {
				newStatus = "True"
			}
			if cond.Status != newStatus {
				gw.Status.Conditions[i].Status = newStatus
				gw.Status.Conditions[i].LastTransitionTime = time.Now()
				updated = true
			}
		}
	}
	_ = updated // Status is updated in place
}

// updateHTTPRouteStatus updates the status of an HTTPRoute.
func (su *StatusUpdater) updateHTTPRouteStatus(route *HTTPRoute) {
	for i := range route.Status.Parents {
		// Check if parent gateway exists and is programmed
		parentRef := route.Status.Parents[i].ParentRef
		ns := route.Namespace
		if parentRef.Namespace != nil {
			ns = *parentRef.Namespace
		}

		gw, ok := su.controller.GetGateway(ns, parentRef.Name)
		if !ok {
			// Parent not found
			for j, cond := range route.Status.Parents[i].Conditions {
				if cond.Type == "Accepted" {
					route.Status.Parents[i].Conditions[j].Status = "False"
					route.Status.Parents[i].Conditions[j].Reason = "NoMatchingParent"
					route.Status.Parents[i].Conditions[j].LastTransitionTime = time.Now()
				}
			}
			continue
		}

		// Parent found, check if it's accepting routes
		_ = gw // Gateway exists
		for j, cond := range route.Status.Parents[i].Conditions {
			if cond.Type == "Accepted" && cond.Status != "True" {
				route.Status.Parents[i].Conditions[j].Status = "True"
				route.Status.Parents[i].Conditions[j].Reason = "Accepted"
				route.Status.Parents[i].Conditions[j].LastTransitionTime = time.Now()
			}
		}
	}
}

// CrossNamespaceRef represents a cross-namespace reference.
type CrossNamespaceRef struct {
	FromGroup     string
	FromKind      string
	FromNamespace string
	ToGroup       string
	ToKind        string
	ToNamespace   string
	ToName        string
}

// ValidateCrossNamespaceRef validates a cross-namespace reference.
func (pm *PolicyManager) ValidateCrossNamespaceRef(ref CrossNamespaceRef) error {
	if pm.IsReferenceAllowed(
		ref.FromGroup, ref.FromKind, ref.FromNamespace,
		ref.ToGroup, ref.ToKind, ref.ToNamespace, ref.ToName,
	) {
		return nil
	}
	return fmt.Errorf(
		"cross-namespace reference from %s/%s in %s to %s/%s/%s in %s not allowed",
		ref.FromGroup, ref.FromKind, ref.FromNamespace,
		ref.ToGroup, ref.ToKind, ref.ToName, ref.ToNamespace,
	)
}
