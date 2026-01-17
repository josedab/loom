package policy

import (
	"context"
	"testing"
)

func TestNewCELEvaluator_Empty(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	policies := evaluator.GetPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(policies))
	}
}

func TestNewCELEvaluator_WithPolicies(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"allow_get":  `request.method == "GET"`,
			"admin_only": `user.roles.exists(r, r == "admin")`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	policies := evaluator.GetPolicies()
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestNewCELEvaluator_InvalidExpression(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"invalid": `request.method === "GET"`, // Invalid CEL syntax
		},
	}

	_, err := NewCELEvaluator(cfg)
	if err == nil {
		t.Error("expected error for invalid expression")
	}
}

func TestCELEvaluator_Evaluate_SimpleBoolean(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"allow_get": `request.method == "GET"`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// Test with GET request
	input := &Input{
		Request: RequestInput{
			Method: "GET",
			Path:   "/api/users",
		},
	}

	decision, err := evaluator.Evaluate(ctx, "allow_get", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected decision to be allowed for GET request")
	}

	// Test with POST request
	input.Request.Method = "POST"
	decision, err = evaluator.Evaluate(ctx, "allow_get", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected decision to be denied for POST request")
	}
}

func TestCELEvaluator_Evaluate_UserRoles(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"admin_only": `user.roles.exists(r, r == "admin")`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// Test with admin role
	input := &Input{
		Request: RequestInput{Method: "GET", Path: "/"},
		User: &UserInput{
			ID:    "user1",
			Roles: []string{"admin", "user"},
		},
	}

	decision, err := evaluator.Evaluate(ctx, "admin_only", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected decision to be allowed for admin user")
	}

	// Test without admin role
	input.User.Roles = []string{"user", "viewer"}
	decision, err = evaluator.Evaluate(ctx, "admin_only", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected decision to be denied for non-admin user")
	}
}

func TestCELEvaluator_Evaluate_ComplexExpression(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"public_api": `request.path.startsWith("/public/") || (request.method == "GET" && user.id != "")`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()
	tests := []struct {
		name     string
		input    *Input
		expected bool
	}{
		{
			name: "public_path",
			input: &Input{
				Request: RequestInput{Method: "POST", Path: "/public/docs"},
			},
			expected: true,
		},
		{
			name: "authenticated_get",
			input: &Input{
				Request: RequestInput{Method: "GET", Path: "/api/users"},
				User:    &UserInput{ID: "user123"},
			},
			expected: true,
		},
		{
			name: "unauthenticated_get",
			input: &Input{
				Request: RequestInput{Method: "GET", Path: "/api/users"},
			},
			expected: false,
		},
		{
			name: "authenticated_post_private",
			input: &Input{
				Request: RequestInput{Method: "POST", Path: "/api/users"},
				User:    &UserInput{ID: "user123"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(ctx, "public_api", tt.input)
			if err != nil {
				t.Fatalf("evaluation failed: %v", err)
			}

			if decision.Allowed != tt.expected {
				t.Errorf("expected allowed=%v, got allowed=%v", tt.expected, decision.Allowed)
			}
		})
	}
}

func TestCELEvaluator_Evaluate_Headers(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"api_key_required": `"X-Api-Key" in request.headers`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// With API key
	input := &Input{
		Request: RequestInput{
			Method:  "GET",
			Path:    "/api",
			Headers: map[string]string{"X-Api-Key": "secret123"},
		},
	}

	decision, err := evaluator.Evaluate(ctx, "api_key_required", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed with API key")
	}

	// Without API key
	input.Request.Headers = map[string]string{}
	decision, err = evaluator.Evaluate(ctx, "api_key_required", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected denied without API key")
	}
}

func TestCELEvaluator_Evaluate_Resource(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"owner_access": `resource.owner == user.id`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// Owner accessing their resource
	input := &Input{
		Request:  RequestInput{Method: "PUT", Path: "/documents/123"},
		User:     &UserInput{ID: "user1"},
		Resource: &ResourceInput{Type: "document", ID: "123", Owner: "user1"},
	}

	decision, err := evaluator.Evaluate(ctx, "owner_access", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected owner to be allowed")
	}

	// Non-owner accessing resource
	input.Resource.Owner = "user2"
	decision, err = evaluator.Evaluate(ctx, "owner_access", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected non-owner to be denied")
	}
}

func TestCELEvaluator_Evaluate_PolicyNotFound(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()
	input := &Input{Request: RequestInput{Method: "GET", Path: "/"}}

	_, err = evaluator.Evaluate(ctx, "nonexistent", input)
	if err == nil {
		t.Error("expected error for nonexistent policy")
	}
}

func TestCELEvaluator_AddPolicy(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	// Add a policy
	err = evaluator.AddPolicy("new_policy", `request.method == "DELETE"`)
	if err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	policies := evaluator.GetPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}

	// Evaluate the new policy
	ctx := context.Background()
	input := &Input{Request: RequestInput{Method: "DELETE", Path: "/resource"}}

	decision, err := evaluator.Evaluate(ctx, "new_policy", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected DELETE to be allowed")
	}
}

func TestCELEvaluator_AddPolicy_Invalid(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	err = evaluator.AddPolicy("invalid", `this is not valid CEL`)
	if err == nil {
		t.Error("expected error for invalid CEL expression")
	}
}

func TestCELEvaluator_RemovePolicy(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"test": `true`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	if len(evaluator.GetPolicies()) != 1 {
		t.Error("expected 1 policy")
	}

	evaluator.RemovePolicy("test")

	if len(evaluator.GetPolicies()) != 0 {
		t.Error("expected 0 policies after removal")
	}
}

func TestCELEvaluator_ValidateExpression(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	// Valid expression
	err = evaluator.ValidateExpression(`request.method == "GET"`)
	if err != nil {
		t.Errorf("expected valid expression: %v", err)
	}

	// Invalid expression
	err = evaluator.ValidateExpression(`request.method === "GET"`)
	if err == nil {
		t.Error("expected error for invalid expression")
	}
}

func TestCELEvaluator_Evaluate_NilInputs(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"check_user": `user.id == ""`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// Test with nil user (should use defaults)
	input := &Input{
		Request: RequestInput{Method: "GET", Path: "/"},
		User:    nil, // nil user
	}

	decision, err := evaluator.Evaluate(ctx, "check_user", input)
	if err != nil {
		t.Fatalf("evaluation failed with nil user: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed when user.id is empty (nil user)")
	}
}

func TestCELEvaluator_Evaluate_Context(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"feature_flag": `"beta" in context && context["beta"] == true`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// With beta flag enabled
	input := &Input{
		Request: RequestInput{Method: "GET", Path: "/"},
		Context: map[string]interface{}{"beta": true},
	}

	decision, err := evaluator.Evaluate(ctx, "feature_flag", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed with beta flag")
	}

	// Without beta flag
	input.Context = map[string]interface{}{}
	decision, err = evaluator.Evaluate(ctx, "feature_flag", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected denied without beta flag")
	}
}

func TestCELEvaluator_Evaluate_ResourceLabels(t *testing.T) {
	cfg := CELEvaluatorConfig{
		Policies: map[string]string{
			"production_only": `"env" in resource.labels && resource.labels["env"] == "production"`,
		},
	}

	evaluator, err := NewCELEvaluator(cfg)
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	ctx := context.Background()

	// Production resource
	input := &Input{
		Request:  RequestInput{Method: "GET", Path: "/"},
		Resource: &ResourceInput{Labels: map[string]string{"env": "production"}},
	}

	decision, err := evaluator.Evaluate(ctx, "production_only", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed for production resource")
	}

	// Non-production resource
	input.Resource.Labels["env"] = "staging"
	decision, err = evaluator.Evaluate(ctx, "production_only", input)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if decision.Allowed {
		t.Error("expected denied for staging resource")
	}
}
