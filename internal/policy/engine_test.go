package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecision(t *testing.T) {
	decision := &Decision{
		Allowed: true,
		Reason:  "test",
		Metadata: map[string]interface{}{
			"key": "value",
		},
		EvaluatedAt: time.Now(),
	}

	if !decision.Allowed {
		t.Error("expected allowed to be true")
	}
	if decision.Reason != "test" {
		t.Errorf("reason = %v, want test", decision.Reason)
	}
}

func TestLocalEvaluator(t *testing.T) {
	evaluator := NewLocalEvaluator(nil)

	// Register a simple policy
	evaluator.RegisterPolicy("test", func(ctx context.Context, input *Input) (*Decision, error) {
		if input.Request.Method == "GET" {
			return &Decision{Allowed: true, Reason: "GET allowed"}, nil
		}
		return &Decision{Allowed: false, Reason: "only GET allowed"}, nil
	})

	tests := []struct {
		name    string
		method  string
		want    bool
	}{
		{"GET allowed", "GET", true},
		{"POST denied", "POST", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			input := &Input{
				Request: RequestInput{Method: tt.method},
			}

			decision, err := evaluator.Evaluate(ctx, "test", input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if decision.Allowed != tt.want {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.want)
			}
		})
	}
}

func TestLocalEvaluatorPolicyNotFound(t *testing.T) {
	evaluator := NewLocalEvaluator(nil)

	ctx := context.Background()
	_, err := evaluator.Evaluate(ctx, "nonexistent", &Input{})
	if err == nil {
		t.Error("expected error for nonexistent policy")
	}
}

func TestOPAEvaluator(t *testing.T) {
	// Create mock OPA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/data/") {
			http.NotFound(w, r)
			return
		}

		var req opaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Parse policy from path
		policy := strings.TrimPrefix(r.URL.Path, "/v1/data/")

		var result interface{}
		switch policy {
		case "authz/allow":
			result = map[string]interface{}{
				"allow":  true,
				"reason": "opa approved",
			}
		case "authz/deny":
			result = map[string]interface{}{
				"allow":  false,
				"reason": "opa denied",
			}
		case "simple/bool":
			result = true
		default:
			result = nil
		}

		json.NewEncoder(w).Encode(opaResponse{Result: result})
	}))
	defer server.Close()

	evaluator := NewOPAEvaluator(OPAConfig{
		ServerURL: server.URL,
	})

	tests := []struct {
		name       string
		policy     string
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "allow policy",
			policy:     "authz.allow",
			wantAllow:  true,
			wantReason: "opa approved",
		},
		{
			name:       "deny policy",
			policy:     "authz.deny",
			wantAllow:  false,
			wantReason: "opa denied",
		},
		{
			name:      "simple bool",
			policy:    "simple.bool",
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			input := &Input{
				Request: RequestInput{Method: "GET", Path: "/test"},
			}

			decision, err := evaluator.Evaluate(ctx, tt.policy, input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
			if tt.wantReason != "" && decision.Reason != tt.wantReason {
				t.Errorf("Reason = %v, want %v", decision.Reason, tt.wantReason)
			}
		})
	}
}

func TestOPAEvaluatorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	evaluator := NewOPAEvaluator(OPAConfig{ServerURL: server.URL})

	ctx := context.Background()
	_, err := evaluator.Evaluate(ctx, "test", &Input{})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestEngine(t *testing.T) {
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("default", BuiltinPolicies["allow_all"])
	local.RegisterPolicy("authenticated", BuiltinPolicies["authenticated"])

	engine := NewEngine(local, EngineConfig{
		DefaultPolicy: "default",
		CacheTTL:      time.Minute,
	})

	tests := []struct {
		name      string
		policy    string
		input     *Input
		wantAllow bool
	}{
		{
			name:      "default allows",
			policy:    "",
			input:     &Input{Request: RequestInput{Method: "GET"}},
			wantAllow: true,
		},
		{
			name:      "authenticated with user",
			policy:    "authenticated",
			input:     &Input{User: &UserInput{ID: "user1"}},
			wantAllow: true,
		},
		{
			name:      "authenticated without user",
			policy:    "authenticated",
			input:     &Input{},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			decision, err := engine.Evaluate(ctx, tt.policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
		})
	}
}

func TestEngineCache(t *testing.T) {
	callCount := 0
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("counter", func(ctx context.Context, input *Input) (*Decision, error) {
		callCount++
		return &Decision{Allowed: true}, nil
	})

	engine := NewEngine(local, EngineConfig{
		CacheTTL: time.Minute,
	})

	ctx := context.Background()
	input := &Input{Request: RequestInput{Method: "GET", Path: "/test"}}

	// First call
	engine.Evaluate(ctx, "counter", input)
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}

	// Second call with same input should be cached
	engine.Evaluate(ctx, "counter", input)
	if callCount != 1 {
		t.Errorf("expected still 1 call (cached), got %d", callCount)
	}

	// Different input should trigger new call
	input2 := &Input{Request: RequestInput{Method: "POST", Path: "/test"}}
	engine.Evaluate(ctx, "counter", input2)
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestEngineFailOpen(t *testing.T) {
	local := NewLocalEvaluator(nil)
	// No policies registered - will fail

	engine := NewEngine(local, EngineConfig{
		FailOpen: true,
	})

	ctx := context.Background()
	decision, err := engine.Evaluate(ctx, "nonexistent", &Input{})
	if err != nil {
		t.Fatalf("Evaluate() should not error with FailOpen: %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed with FailOpen")
	}
}

func TestEngineFailClosed(t *testing.T) {
	local := NewLocalEvaluator(nil)

	engine := NewEngine(local, EngineConfig{
		FailOpen: false,
	})

	ctx := context.Background()
	_, err := engine.Evaluate(ctx, "nonexistent", &Input{})
	if err == nil {
		t.Error("expected error without FailOpen")
	}
}

func TestChainEvaluator(t *testing.T) {
	// First evaluator fails
	failing := NewLocalEvaluator(nil)

	// Second evaluator succeeds
	succeeding := NewLocalEvaluator(nil)
	succeeding.RegisterPolicy("test", func(ctx context.Context, input *Input) (*Decision, error) {
		return &Decision{Allowed: true, Reason: "from chain"}, nil
	})

	chain := NewChainEvaluator(failing, succeeding)

	ctx := context.Background()
	decision, err := chain.Evaluate(ctx, "test", &Input{})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !decision.Allowed {
		t.Error("expected allowed from chain")
	}
}

func TestChainEvaluatorAllFail(t *testing.T) {
	failing1 := NewLocalEvaluator(nil)
	failing2 := NewLocalEvaluator(nil)

	chain := NewChainEvaluator(failing1, failing2)

	ctx := context.Background()
	_, err := chain.Evaluate(ctx, "test", &Input{})
	if err == nil {
		t.Error("expected error when all evaluators fail")
	}
}

func TestDecisionCache(t *testing.T) {
	cache := NewDecisionCache(100, time.Minute)

	decision := &Decision{Allowed: true, Reason: "cached"}
	cache.Set("key1", decision)

	// Get should return cached value
	cached := cache.Get("key1")
	if cached == nil {
		t.Fatal("expected cached decision")
	}
	if !cached.Allowed {
		t.Error("expected allowed from cache")
	}

	// Non-existent key should return nil
	if cache.Get("nonexistent") != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestDecisionCacheExpiry(t *testing.T) {
	cache := NewDecisionCache(100, 50*time.Millisecond)

	cache.Set("key1", &Decision{Allowed: true})

	// Should be present immediately
	if cache.Get("key1") == nil {
		t.Error("expected cached decision")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cache.Get("key1") != nil {
		t.Error("expected nil for expired entry")
	}
}

func TestDecisionCacheEviction(t *testing.T) {
	cache := NewDecisionCache(2, time.Minute)

	cache.Set("key1", &Decision{Allowed: true})
	cache.Set("key2", &Decision{Allowed: true})
	cache.Set("key3", &Decision{Allowed: true})

	// Cache should still work after eviction
	if cache.Get("key3") == nil {
		t.Error("expected key3 to be cached")
	}
}

func TestRBACPolicy(t *testing.T) {
	tests := []struct {
		name      string
		user      *UserInput
		context   map[string]interface{}
		wantAllow bool
	}{
		{
			name:      "no user",
			user:      nil,
			wantAllow: false,
		},
		{
			name:      "no role requirement",
			user:      &UserInput{ID: "user1", Roles: []string{"reader"}},
			wantAllow: true,
		},
		{
			name:      "has required role",
			user:      &UserInput{ID: "user1", Roles: []string{"admin"}},
			context:   map[string]interface{}{"required_role": "admin"},
			wantAllow: true,
		},
		{
			name:      "missing required role",
			user:      &UserInput{ID: "user1", Roles: []string{"reader"}},
			context:   map[string]interface{}{"required_role": "admin"},
			wantAllow: false,
		},
		{
			name:      "admin bypasses role check",
			user:      &UserInput{ID: "user1", Roles: []string{"admin"}},
			context:   map[string]interface{}{"required_role": "super-admin"},
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			input := &Input{
				User:    tt.user,
				Context: tt.context,
			}

			decision, err := RBACPolicy(ctx, input)
			if err != nil {
				t.Fatalf("RBACPolicy() error = %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
		})
	}
}

func TestABACPolicy(t *testing.T) {
	rules := []ABACRule{
		{
			Name:   "allow admin",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"user.roles": []interface{}{"admin"},
			},
		},
		{
			Name:   "allow GET",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"request.method": "GET",
			},
		},
		{
			Name:   "allow api prefix",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"request.path": "prefix:/api/",
			},
		},
	}

	policy := ABACPolicy(rules)

	tests := []struct {
		name      string
		input     *Input
		wantAllow bool
	}{
		{
			name: "admin allowed",
			input: &Input{
				User: &UserInput{Roles: []string{"admin"}},
			},
			wantAllow: true,
		},
		{
			name: "GET allowed",
			input: &Input{
				Request: RequestInput{Method: "GET"},
			},
			wantAllow: true,
		},
		{
			name: "api prefix allowed",
			input: &Input{
				Request: RequestInput{Path: "/api/users"},
			},
			wantAllow: true,
		},
		{
			name: "no match denied",
			input: &Input{
				Request: RequestInput{Method: "POST", Path: "/other"},
			},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			decision, err := policy(ctx, tt.input)
			if err != nil {
				t.Fatalf("ABACPolicy() error = %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
		})
	}
}

func TestABACRuleInCondition(t *testing.T) {
	rules := []ABACRule{
		{
			Name:   "allow methods",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"request.method": "in:GET,POST,PUT",
			},
		},
	}

	policy := ABACPolicy(rules)

	tests := []struct {
		method    string
		wantAllow bool
	}{
		{"GET", true},
		{"POST", true},
		{"PUT", true},
		{"DELETE", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			ctx := context.Background()
			input := &Input{Request: RequestInput{Method: tt.method}}
			decision, _ := policy(ctx, input)

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
		})
	}
}

func TestBuiltinPolicies(t *testing.T) {
	ctx := context.Background()
	input := &Input{}

	// Test allow_all
	decision, _ := BuiltinPolicies["allow_all"](ctx, input)
	if !decision.Allowed {
		t.Error("allow_all should allow")
	}

	// Test deny_all
	decision, _ = BuiltinPolicies["deny_all"](ctx, input)
	if decision.Allowed {
		t.Error("deny_all should deny")
	}
}

func TestMiddleware(t *testing.T) {
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("test", func(ctx context.Context, input *Input) (*Decision, error) {
		if input.Request.Path == "/allowed" {
			return &Decision{Allowed: true}, nil
		}
		return &Decision{Allowed: false, Reason: "denied"}, nil
	})

	engine := NewEngine(local, EngineConfig{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	middleware := Middleware(MiddlewareConfig{
		Engine: engine,
		PolicyResolver: func(r *http.Request) string {
			return "test"
		},
	})

	wrapped := middleware(handler)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "allowed path",
			path:       "/allowed",
			wantStatus: http.StatusOK,
		},
		{
			name:       "denied path",
			path:       "/denied",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddlewareWithUserExtractor(t *testing.T) {
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("test", BuiltinPolicies["authenticated"])

	engine := NewEngine(local, EngineConfig{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(MiddlewareConfig{
		Engine: engine,
		PolicyResolver: func(r *http.Request) string {
			return "test"
		},
		UserExtractor: HeaderUserExtractor("X-User-ID", "X-User-Roles"),
	})

	wrapped := middleware(handler)

	tests := []struct {
		name       string
		userID     string
		wantStatus int
	}{
		{
			name:       "with user header",
			userID:     "user123",
			wantStatus: http.StatusOK,
		},
		{
			name:       "without user header",
			userID:     "",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.userID != "" {
				req.Header.Set("X-User-ID", tt.userID)
			}
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddlewareCustomDenyHandler(t *testing.T) {
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("deny", BuiltinPolicies["deny_all"])

	engine := NewEngine(local, EngineConfig{})

	customDenyCalled := false
	middleware := Middleware(MiddlewareConfig{
		Engine: engine,
		PolicyResolver: func(r *http.Request) string {
			return "deny"
		},
		OnDeny: func(w http.ResponseWriter, r *http.Request, decision *Decision) {
			customDenyCalled = true
			w.WriteHeader(http.StatusTeapot)
		},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !customDenyCalled {
		t.Error("custom deny handler should be called")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestPathPolicyResolver(t *testing.T) {
	resolver := PathPolicyResolver(map[string]string{
		"/api/":   "api-policy",
		"/admin/": "admin-policy",
	})

	tests := []struct {
		path       string
		wantPolicy string
	}{
		{"/api/users", "api-policy"},
		{"/admin/dashboard", "admin-policy"},
		{"/other", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			policy := resolver(req)

			if policy != tt.wantPolicy {
				t.Errorf("policy = %v, want %v", policy, tt.wantPolicy)
			}
		})
	}
}

func TestMethodPolicyResolver(t *testing.T) {
	resolver := MethodPolicyResolver(map[string]string{
		"GET":    "read-policy",
		"POST":   "write-policy",
		"DELETE": "delete-policy",
	})

	tests := []struct {
		method     string
		wantPolicy string
	}{
		{"GET", "read-policy"},
		{"POST", "write-policy"},
		{"DELETE", "delete-policy"},
		{"PATCH", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			policy := resolver(req)

			if policy != tt.wantPolicy {
				t.Errorf("policy = %v, want %v", policy, tt.wantPolicy)
			}
		})
	}
}

func TestHeaderUserExtractor(t *testing.T) {
	extractor := HeaderUserExtractor("X-User-ID", "X-User-Roles")

	tests := []struct {
		name      string
		userID    string
		roles     string
		wantNil   bool
		wantRoles int
	}{
		{
			name:    "with user and roles",
			userID:  "user1",
			roles:   "admin,editor",
			wantNil: false,
			wantRoles: 2,
		},
		{
			name:    "user only",
			userID:  "user1",
			roles:   "",
			wantNil: false,
			wantRoles: 0,
		},
		{
			name:    "no user",
			userID:  "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.userID != "" {
				req.Header.Set("X-User-ID", tt.userID)
			}
			if tt.roles != "" {
				req.Header.Set("X-User-Roles", tt.roles)
			}

			user := extractor(req)

			if tt.wantNil {
				if user != nil {
					t.Error("expected nil user")
				}
				return
			}

			if user == nil {
				t.Fatal("expected non-nil user")
			}
			if user.ID != tt.userID {
				t.Errorf("ID = %v, want %v", user.ID, tt.userID)
			}
			if len(user.Roles) != tt.wantRoles {
				t.Errorf("roles count = %d, want %d", len(user.Roles), tt.wantRoles)
			}
		})
	}
}

func TestPathResourceExtractor(t *testing.T) {
	extractor := PathResourceExtractor(0, 1)

	req := httptest.NewRequest("GET", "/users/123", nil)
	resource := extractor(req)

	if resource.Type != "users" {
		t.Errorf("Type = %v, want users", resource.Type)
	}
	if resource.ID != "123" {
		t.Errorf("ID = %v, want 123", resource.ID)
	}
}

func TestHandler(t *testing.T) {
	local := NewLocalEvaluator(nil)
	local.RegisterPolicy("test", BuiltinPolicies["allow_all"])

	engine := NewEngine(local, EngineConfig{})
	handler := NewHandler(engine, nil)

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "evaluate success",
			method:     "POST",
			path:       "/policy/evaluate",
			body:       `{"policy": "test", "input": {"request": {"method": "GET"}}}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "evaluate no input",
			method:     "POST",
			path:       "/policy/evaluate",
			body:       `{"policy": "test"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "not found",
			method:     "GET",
			path:       "/policy/unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d, body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestIPAllowListPolicy(t *testing.T) {
	policy := IPAllowListPolicy([]string{"10.0.0.1", "192.168.1.1"})

	tests := []struct {
		ip        string
		wantAllow bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ctx := context.Background()
			input := &Input{
				Request: RequestInput{RemoteAddr: tt.ip},
			}

			decision, err := policy(ctx, input)
			if err != nil {
				t.Fatalf("policy error: %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
		})
	}
}

func TestGetDecision(t *testing.T) {
	expected := &Decision{Allowed: true, Reason: "test"}

	ctx := context.WithValue(context.Background(), decisionKey{}, expected)
	decision := GetDecision(ctx)

	if decision != expected {
		t.Error("GetDecision should return stored decision")
	}

	// Test with no decision
	emptyCtx := context.Background()
	if GetDecision(emptyCtx) != nil {
		t.Error("GetDecision should return nil for empty context")
	}
}

func TestOPAEvaluatorDefaults(t *testing.T) {
	evaluator := NewOPAEvaluator(OPAConfig{})

	if evaluator.serverURL != "http://localhost:8181" {
		t.Errorf("default server URL = %v, want http://localhost:8181", evaluator.serverURL)
	}
}

func TestOPAParseResultNil(t *testing.T) {
	evaluator := NewOPAEvaluator(OPAConfig{})

	decision, err := evaluator.parseResult(nil)
	if err != nil {
		t.Fatalf("parseResult error: %v", err)
	}

	if decision.Allowed {
		t.Error("nil result should not be allowed")
	}
}
