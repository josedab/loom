package gatewayapi

import (
	"testing"
)

func TestPolicyManager_ReferenceGrant(t *testing.T) {
	pm := NewPolicyManager()

	// Create a reference grant
	rg := &ReferenceGrant{
		ObjectMeta: ObjectMeta{
			Name:      "allow-frontend",
			Namespace: "backend",
		},
		Spec: ReferenceGrantSpec{
			From: []ReferenceGrantFrom{
				{
					Group:     "gateway.networking.k8s.io",
					Kind:      "HTTPRoute",
					Namespace: "frontend",
				},
			},
			To: []ReferenceGrantTo{
				{
					Group: ptrString(""),
					Kind:  "Service",
				},
			},
		},
	}

	pm.SetReferenceGrant(rg)

	// Test allowed reference
	allowed := pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "frontend",
		"", "Service", "backend", "api-service",
	)
	if !allowed {
		t.Error("Reference should be allowed by ReferenceGrant")
	}

	// Test same namespace (always allowed)
	allowed = pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "backend",
		"", "Service", "backend", "api-service",
	)
	if !allowed {
		t.Error("Same namespace reference should always be allowed")
	}

	// Test disallowed reference (wrong source namespace)
	allowed = pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "other",
		"", "Service", "backend", "api-service",
	)
	if allowed {
		t.Error("Reference from wrong namespace should not be allowed")
	}

	// Test disallowed reference (wrong kind)
	allowed = pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "TCPRoute", "frontend",
		"", "Service", "backend", "api-service",
	)
	if allowed {
		t.Error("Reference from wrong kind should not be allowed")
	}

	// Delete and verify
	pm.DeleteReferenceGrant("backend", "allow-frontend")
	allowed = pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "frontend",
		"", "Service", "backend", "api-service",
	)
	if allowed {
		t.Error("Reference should not be allowed after ReferenceGrant deleted")
	}
}

func TestPolicyManager_ReferenceGrant_SpecificName(t *testing.T) {
	pm := NewPolicyManager()

	// Grant allowing only specific service name
	rg := &ReferenceGrant{
		ObjectMeta: ObjectMeta{
			Name:      "allow-specific",
			Namespace: "backend",
		},
		Spec: ReferenceGrantSpec{
			From: []ReferenceGrantFrom{
				{
					Group:     "gateway.networking.k8s.io",
					Kind:      "HTTPRoute",
					Namespace: "frontend",
				},
			},
			To: []ReferenceGrantTo{
				{
					Group: ptrString(""),
					Kind:  "Service",
					Name:  ptrString("allowed-service"),
				},
			},
		},
	}

	pm.SetReferenceGrant(rg)

	// Test allowed specific name
	allowed := pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "frontend",
		"", "Service", "backend", "allowed-service",
	)
	if !allowed {
		t.Error("Reference to specific allowed service should be allowed")
	}

	// Test disallowed name
	allowed = pm.IsReferenceAllowed(
		"gateway.networking.k8s.io", "HTTPRoute", "frontend",
		"", "Service", "backend", "other-service",
	)
	if allowed {
		t.Error("Reference to non-allowed service should not be allowed")
	}
}

func TestPolicyManager_BackendTLSPolicy(t *testing.T) {
	pm := NewPolicyManager()

	policy := &BackendTLSPolicy{
		ObjectMeta: ObjectMeta{
			Name:      "tls-policy",
			Namespace: "default",
		},
		Spec: BackendTLSPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "",
				Kind:  "Service",
				Name:  "api-service",
			},
			TLS: BackendTLSPolicyConfig{
				Hostname: ptrString("api.internal"),
				CACertRefs: []LocalObjectReference{
					{Kind: "Secret", Name: "ca-cert"},
				},
			},
		},
	}

	pm.SetBackendTLSPolicy(policy)

	// Get policy
	retrieved := pm.GetBackendTLSPolicy("", "Service", "default", "api-service")
	if retrieved == nil {
		t.Fatal("GetBackendTLSPolicy() should return the policy")
	}
	if *retrieved.Spec.TLS.Hostname != "api.internal" {
		t.Errorf("Hostname = %q, want 'api.internal'", *retrieved.Spec.TLS.Hostname)
	}

	// Get non-existent policy
	retrieved = pm.GetBackendTLSPolicy("", "Service", "default", "other-service")
	if retrieved != nil {
		t.Error("GetBackendTLSPolicy() should return nil for non-existent policy")
	}

	// Delete
	pm.DeleteBackendTLSPolicy("default", "tls-policy")
	retrieved = pm.GetBackendTLSPolicy("", "Service", "default", "api-service")
	if retrieved != nil {
		t.Error("Policy should be deleted")
	}
}

func TestPolicyManager_TimeoutPolicy(t *testing.T) {
	pm := NewPolicyManager()

	policy := &HTTPRouteTimeoutsPolicy{
		ObjectMeta: ObjectMeta{
			Name:      "timeout-policy",
			Namespace: "default",
		},
		Spec: HTTPRouteTimeoutsPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "api-route",
			},
			Request:        ptrDuration("30s"),
			BackendRequest: ptrDuration("25s"),
		},
	}

	pm.SetTimeoutPolicy(policy)

	// Get policy
	retrieved := pm.GetTimeoutPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved == nil {
		t.Fatal("GetTimeoutPolicy() should return the policy")
	}
	if *retrieved.Spec.Request != "30s" {
		t.Errorf("Request timeout = %q, want '30s'", *retrieved.Spec.Request)
	}

	// Delete
	pm.DeleteTimeoutPolicy("default", "timeout-policy")
	retrieved = pm.GetTimeoutPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved != nil {
		t.Error("Policy should be deleted")
	}
}

func TestPolicyManager_RetryPolicy(t *testing.T) {
	pm := NewPolicyManager()

	policy := &RetryPolicy{
		ObjectMeta: ObjectMeta{
			Name:      "retry-policy",
			Namespace: "default",
		},
		Spec: RetryPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "api-route",
			},
			NumRetries:    ptrInt32(3),
			RetryOn:       []string{"5xx", "reset", "connect-failure"},
			PerTryTimeout: ptrDuration("5s"),
			RetryBackoff: &RetryBackoff{
				BaseInterval: ptrDuration("100ms"),
				MaxInterval:  ptrDuration("10s"),
			},
		},
	}

	pm.SetRetryPolicy(policy)

	// Get policy
	retrieved := pm.GetRetryPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved == nil {
		t.Fatal("GetRetryPolicy() should return the policy")
	}
	if *retrieved.Spec.NumRetries != 3 {
		t.Errorf("NumRetries = %d, want 3", *retrieved.Spec.NumRetries)
	}

	// Delete
	pm.DeleteRetryPolicy("default", "retry-policy")
	retrieved = pm.GetRetryPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved != nil {
		t.Error("Policy should be deleted")
	}
}

func TestPolicyManager_RateLimitPolicy(t *testing.T) {
	pm := NewPolicyManager()

	keyType := RateLimitKeyTypeClientIP
	policy := &RateLimitPolicy{
		ObjectMeta: ObjectMeta{
			Name:      "ratelimit-policy",
			Namespace: "default",
		},
		Spec: RateLimitPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "api-route",
			},
			Limits: []RateLimitRule{
				{
					RequestsPerUnit: 100,
					Unit:            RateLimitUnitMinute,
					Key: &RateLimitKey{
						Type: keyType,
					},
				},
			},
		},
	}

	pm.SetRateLimitPolicy(policy)

	// Get policy
	retrieved := pm.GetRateLimitPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved == nil {
		t.Fatal("GetRateLimitPolicy() should return the policy")
	}
	if len(retrieved.Spec.Limits) != 1 {
		t.Errorf("Limits count = %d, want 1", len(retrieved.Spec.Limits))
	}
	if retrieved.Spec.Limits[0].RequestsPerUnit != 100 {
		t.Errorf("RequestsPerUnit = %d, want 100", retrieved.Spec.Limits[0].RequestsPerUnit)
	}

	// Delete
	pm.DeleteRateLimitPolicy("default", "ratelimit-policy")
	retrieved = pm.GetRateLimitPolicy("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")
	if retrieved != nil {
		t.Error("Policy should be deleted")
	}
}

func TestPolicyManager_GetEffectivePolicies(t *testing.T) {
	pm := NewPolicyManager()

	// Add various policies for the same route
	pm.SetTimeoutPolicy(&HTTPRouteTimeoutsPolicy{
		ObjectMeta: ObjectMeta{Name: "timeout", Namespace: "default"},
		Spec: HTTPRouteTimeoutsPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "api-route",
			},
			Request: ptrDuration("30s"),
		},
	})

	pm.SetRetryPolicy(&RetryPolicy{
		ObjectMeta: ObjectMeta{Name: "retry", Namespace: "default"},
		Spec: RetryPolicySpec{
			TargetRef: PolicyTargetReference{
				Group: "gateway.networking.k8s.io",
				Kind:  "HTTPRoute",
				Name:  "api-route",
			},
			NumRetries: ptrInt32(3),
		},
	})

	// Get all effective policies
	policies := pm.GetEffectivePolicies("gateway.networking.k8s.io", "HTTPRoute", "default", "api-route")

	if policies.TimeoutPolicy == nil {
		t.Error("TimeoutPolicy should not be nil")
	}
	if policies.RetryPolicy == nil {
		t.Error("RetryPolicy should not be nil")
	}
	if policies.RateLimitPolicy != nil {
		t.Error("RateLimitPolicy should be nil (not set)")
	}
}

func TestPolicyManager_ValidateCrossNamespaceRef(t *testing.T) {
	pm := NewPolicyManager()

	// Add reference grant
	pm.SetReferenceGrant(&ReferenceGrant{
		ObjectMeta: ObjectMeta{Name: "allow", Namespace: "backend"},
		Spec: ReferenceGrantSpec{
			From: []ReferenceGrantFrom{
				{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Namespace: "frontend"},
			},
			To: []ReferenceGrantTo{
				{Group: ptrString(""), Kind: "Service"},
			},
		},
	})

	// Valid reference
	err := pm.ValidateCrossNamespaceRef(CrossNamespaceRef{
		FromGroup:     "gateway.networking.k8s.io",
		FromKind:      "HTTPRoute",
		FromNamespace: "frontend",
		ToGroup:       "",
		ToKind:        "Service",
		ToNamespace:   "backend",
		ToName:        "api-service",
	})
	if err != nil {
		t.Errorf("ValidateCrossNamespaceRef() error = %v, want nil", err)
	}

	// Invalid reference
	err = pm.ValidateCrossNamespaceRef(CrossNamespaceRef{
		FromGroup:     "gateway.networking.k8s.io",
		FromKind:      "HTTPRoute",
		FromNamespace: "other",
		ToGroup:       "",
		ToKind:        "Service",
		ToNamespace:   "backend",
		ToName:        "api-service",
	})
	if err == nil {
		t.Error("ValidateCrossNamespaceRef() should return error for invalid reference")
	}
}

func TestDuration_ToDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration Duration
		expected string
	}{
		{
			name:     "seconds",
			duration: Duration("30s"),
			expected: "30s",
		},
		{
			name:     "minutes",
			duration: Duration("5m"),
			expected: "5m0s",
		},
		{
			name:     "empty",
			duration: Duration(""),
			expected: "0s",
		},
		{
			name:     "invalid",
			duration: Duration("invalid"),
			expected: "0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.duration.ToDuration()
			if result.String() != tt.expected {
				t.Errorf("ToDuration() = %s, want %s", result.String(), tt.expected)
			}
		})
	}
}

// Helper function
func ptrDuration(d string) *Duration {
	dur := Duration(d)
	return &dur
}
