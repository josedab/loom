package transform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransformerSetOperation(t *testing.T) {
	rules := []Rule{{
		Name: "set-test",
		Request: []Operation{
			{Type: "set", Target: "headers.X-Custom", Value: "custom-value"},
			{Type: "set", Target: "body.newField", Value: "new-value"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Headers: make(map[string][]string),
		Body:    map[string]interface{}{"existing": "value"},
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	if ctx.Headers["X-Custom"][0] != "custom-value" {
		t.Errorf("expected header X-Custom to be 'custom-value', got %v", ctx.Headers["X-Custom"])
	}

	if ctx.Body["newField"] != "new-value" {
		t.Errorf("expected body.newField to be 'new-value', got %v", ctx.Body["newField"])
	}
}

func TestTransformerDeleteOperation(t *testing.T) {
	rules := []Rule{{
		Name: "delete-test",
		Request: []Operation{
			{Type: "delete", Target: "headers.X-Remove"},
			{Type: "delete", Target: "body.sensitive"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Headers: map[string][]string{
			"X-Remove": {"value"},
			"X-Keep":   {"keep"},
		},
		Body: map[string]interface{}{
			"sensitive": "secret",
			"public":    "data",
		},
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	if _, exists := ctx.Headers["X-Remove"]; exists {
		t.Error("expected X-Remove header to be deleted")
	}
	if ctx.Headers["X-Keep"][0] != "keep" {
		t.Error("expected X-Keep header to be preserved")
	}

	if _, exists := ctx.Body["sensitive"]; exists {
		t.Error("expected sensitive field to be deleted")
	}
	if ctx.Body["public"] != "data" {
		t.Error("expected public field to be preserved")
	}
}

func TestTransformerCopyOperation(t *testing.T) {
	rules := []Rule{{
		Name: "copy-test",
		Request: []Operation{
			{Type: "copy", Source: "headers.Authorization", Target: "body.token"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Headers: map[string][]string{
			"Authorization": {"Bearer abc123"},
		},
		Body: make(map[string]interface{}),
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	if ctx.Body["token"] != "Bearer abc123" {
		t.Errorf("expected body.token to be 'Bearer abc123', got %v", ctx.Body["token"])
	}

	// Original should still exist
	if ctx.Headers["Authorization"][0] != "Bearer abc123" {
		t.Error("copy should not remove source")
	}
}

func TestTransformerRenameOperation(t *testing.T) {
	rules := []Rule{{
		Name: "rename-test",
		Request: []Operation{
			{Type: "rename", Source: "body.old_name", Target: "body.new_name"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Body: map[string]interface{}{
			"old_name": "value",
		},
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	if _, exists := ctx.Body["old_name"]; exists {
		t.Error("expected old_name to be removed")
	}
	if ctx.Body["new_name"] != "value" {
		t.Errorf("expected new_name to be 'value', got %v", ctx.Body["new_name"])
	}
}

func TestTransformerMapOperation(t *testing.T) {
	rules := []Rule{{
		Name: "map-test",
		Request: []Operation{
			{
				Type:   "map",
				Source: "body.status",
				Target: "body.status_code",
				Mapping: map[string]interface{}{
					"active":   1,
					"inactive": 0,
					"_default": -1,
				},
			},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		input    string
		expected interface{}
	}{
		{"active", 1},
		{"inactive", 0},
		{"unknown", -1},
	}

	for _, tt := range tests {
		ctx := &Context{
			Body: map[string]interface{}{
				"status": tt.input,
			},
		}

		if err := transformer.TransformRequest(ctx); err != nil {
			t.Fatalf("TransformRequest failed: %v", err)
		}

		if ctx.Body["status_code"] != tt.expected {
			t.Errorf("for input %q, expected %v, got %v", tt.input, tt.expected, ctx.Body["status_code"])
		}
	}
}

func TestTransformerExtractOperation(t *testing.T) {
	rules := []Rule{{
		Name: "extract-test",
		Request: []Operation{
			{
				Type:   "extract",
				Source: "headers.Authorization",
				Target: "var.token",
				Value:  `Bearer (.+)`,
			},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Headers: map[string][]string{
			"Authorization": {"Bearer abc123"},
		},
		Variables: make(map[string]interface{}),
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	if ctx.Variables["token"] != "abc123" {
		t.Errorf("expected token to be 'abc123', got %v", ctx.Variables["token"])
	}
}

func TestTransformerCondition(t *testing.T) {
	rules := []Rule{{
		Name: "conditional-test",
		Request: []Operation{
			{
				Type:      "set",
				Target:    "body.admin",
				Value:     true,
				Condition: "headers.X-Admin exists",
			},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// With header - should apply
	ctx1 := &Context{
		Headers: map[string][]string{"X-Admin": {"true"}},
		Body:    make(map[string]interface{}),
	}
	transformer.TransformRequest(ctx1)
	if ctx1.Body["admin"] != true {
		t.Error("expected admin=true when X-Admin header present")
	}

	// Without header - should not apply
	ctx2 := &Context{
		Headers: make(map[string][]string),
		Body:    make(map[string]interface{}),
	}
	transformer.TransformRequest(ctx2)
	if _, exists := ctx2.Body["admin"]; exists {
		t.Error("expected admin not set when X-Admin header missing")
	}
}

func TestTransformerMatchPaths(t *testing.T) {
	rules := []Rule{{
		Name:  "path-test",
		Match: Match{Paths: []string{"/api/*"}},
		Request: []Operation{
			{Type: "set", Target: "headers.X-API", Value: "true"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Matching path
	ctx1 := &Context{
		Path:    "/api/users",
		Headers: make(map[string][]string),
	}
	transformer.TransformRequest(ctx1)
	if _, exists := ctx1.Headers["X-API"]; !exists {
		t.Error("expected X-API header for matching path")
	}

	// Non-matching path
	ctx2 := &Context{
		Path:    "/other/path",
		Headers: make(map[string][]string),
	}
	transformer.TransformRequest(ctx2)
	if _, exists := ctx2.Headers["X-API"]; exists {
		t.Error("expected no X-API header for non-matching path")
	}
}

func TestTransformerMatchMethods(t *testing.T) {
	rules := []Rule{{
		Name:  "method-test",
		Match: Match{Methods: []string{"POST", "PUT"}},
		Request: []Operation{
			{Type: "set", Target: "headers.X-Write", Value: "true"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Matching method
	ctx1 := &Context{
		Method:  "POST",
		Headers: make(map[string][]string),
	}
	transformer.TransformRequest(ctx1)
	if _, exists := ctx1.Headers["X-Write"]; !exists {
		t.Error("expected X-Write header for POST")
	}

	// Non-matching method
	ctx2 := &Context{
		Method:  "GET",
		Headers: make(map[string][]string),
	}
	transformer.TransformRequest(ctx2)
	if _, exists := ctx2.Headers["X-Write"]; exists {
		t.Error("expected no X-Write header for GET")
	}
}

func TestTransformerTemplate(t *testing.T) {
	rules := []Rule{{
		Name: "template-test",
		Request: []Operation{
			{
				Type:     "template",
				Target:   "headers.X-Greeting",
				Template: "Hello, {{.Method}} request to {{.Path}}",
			},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Method:  "GET",
		Path:    "/users",
		Headers: make(map[string][]string),
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	expected := "Hello, GET request to /users"
	if ctx.Headers["X-Greeting"][0] != expected {
		t.Errorf("expected %q, got %q", expected, ctx.Headers["X-Greeting"][0])
	}
}

func TestNestedBodyOperations(t *testing.T) {
	rules := []Rule{{
		Name: "nested-test",
		Request: []Operation{
			{Type: "set", Target: "body.user.name", Value: "John"},
			{Type: "set", Target: "body.user.email", Value: "john@example.com"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Body: make(map[string]interface{}),
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	user, ok := ctx.Body["user"].(map[string]interface{})
	if !ok {
		t.Fatal("expected user to be a map")
	}
	if user["name"] != "John" {
		t.Errorf("expected name 'John', got %v", user["name"])
	}
	if user["email"] != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got %v", user["email"])
	}
}

func TestResponseTransformation(t *testing.T) {
	rules := []Rule{{
		Name: "response-test",
		Response: []Operation{
			{Type: "set", Target: "headers.X-Response", Value: "transformed"},
			{Type: "delete", Target: "body.internal"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Headers:    make(map[string][]string),
		StatusCode: 200,
		Body: map[string]interface{}{
			"public":   "data",
			"internal": "secret",
		},
	}

	if err := transformer.TransformResponse(ctx); err != nil {
		t.Fatalf("TransformResponse failed: %v", err)
	}

	if ctx.Headers["X-Response"][0] != "transformed" {
		t.Error("expected response header to be set")
	}
	if _, exists := ctx.Body["internal"]; exists {
		t.Error("expected internal field to be deleted")
	}
	if ctx.Body["public"] != "data" {
		t.Error("expected public field to be preserved")
	}
}

func TestEvaluateCondition(t *testing.T) {
	ctx := &Context{
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: map[string]interface{}{
			"status": "active",
			"count":  100,
		},
		StatusCode: 200,
	}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"headers.Content-Type exists", true},
		{"headers.X-Missing exists", false},
		{"headers.X-Missing not exists", true},
		{"body.status == active", true},
		{"body.status == inactive", false},
		{"body.status != inactive", true},
		{"body.count > 50", true},
		{"body.count < 50", false},
		{"body.count >= 100", true},
		{"body.count <= 100", true},
		{"status >= 200", true},
		{"status < 400", true},
		{"body.status contains act", true},
		{"body.status matches ^act.*", true},
	}

	for _, tt := range tests {
		result, err := evaluateCondition(ctx, tt.condition)
		if err != nil {
			t.Errorf("condition %q error: %v", tt.condition, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("condition %q: expected %v, got %v", tt.condition, tt.expected, result)
		}
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path     string
		pattern  string
		expected bool
	}{
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/*", true},
		{"/api/users/123", "/api/*", true},
		{"/other/path", "/api/*", false},
		{"/anything", "*", true},
		{"/api/v1/users", "/api/v1/*", true},
	}

	for _, tt := range tests {
		result := matchPath(tt.path, tt.pattern)
		if result != tt.expected {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, result, tt.expected)
		}
	}
}

func TestRuleBuilder(t *testing.T) {
	rule := NewRule("test-rule").
		MatchPaths("/api/*").
		MatchMethods("POST", "PUT").
		MatchHeader("Content-Type", "application/json").
		SetRequestHeader("X-Custom", "value").
		DeleteRequestHeader("X-Remove").
		SetResponseHeader("X-Response", "done").
		Build()

	if rule.Name != "test-rule" {
		t.Errorf("expected name 'test-rule', got %q", rule.Name)
	}
	if len(rule.Match.Paths) != 1 || rule.Match.Paths[0] != "/api/*" {
		t.Error("expected path pattern")
	}
	if len(rule.Match.Methods) != 2 {
		t.Error("expected 2 methods")
	}
	if len(rule.Request) != 2 {
		t.Errorf("expected 2 request ops, got %d", len(rule.Request))
	}
	if len(rule.Response) != 1 {
		t.Errorf("expected 1 response op, got %d", len(rule.Response))
	}
}

func TestMiddleware(t *testing.T) {
	rules := []Rule{{
		Name: "middleware-test",
		Request: []Operation{
			{Type: "set", Target: "headers.X-Transformed", Value: "request"},
		},
		Response: []Operation{
			{Type: "set", Target: "headers.X-Transformed", Value: "response"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request was transformed
		if r.Header.Get("X-Transformed") != "request" {
			t.Error("expected request header to be transformed")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	handler := Middleware(MiddlewareConfig{
		Transformer: transformer,
	})(backend)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Transformed") != "response" {
		t.Errorf("expected response header 'response', got %q", rec.Header().Get("X-Transformed"))
	}
}

func TestMiddlewareBodyTransformation(t *testing.T) {
	rules := []Rule{{
		Name: "body-test",
		Request: []Operation{
			{Type: "set", Target: "body.added", Value: "by-transform"},
		},
		Response: []Operation{
			{Type: "delete", Target: "body.internal"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Decode request body
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		// Verify request transformation
		if body["added"] != "by-transform" {
			t.Errorf("expected 'added' field, got %v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"public":   "data",
			"internal": "secret",
		})
	})

	handler := Middleware(MiddlewareConfig{
		Transformer: transformer,
	})(backend)

	reqBody := bytes.NewBufferString(`{"original":"value"}`)
	req := httptest.NewRequest("POST", "/api/test", reqBody)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var respBody map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&respBody)

	if respBody["public"] != "data" {
		t.Error("expected public field")
	}
	if _, exists := respBody["internal"]; exists {
		t.Error("expected internal field to be deleted")
	}
}

func TestOperationHelpers(t *testing.T) {
	op := SetOp("body.field", "value")
	if op.Type != "set" || op.Target != "body.field" || op.Value != "value" {
		t.Error("SetOp helper failed")
	}

	op = DeleteOp("headers.X-Remove")
	if op.Type != "delete" || op.Target != "headers.X-Remove" {
		t.Error("DeleteOp helper failed")
	}

	op = CopyOp("body.src", "body.dst")
	if op.Type != "copy" || op.Source != "body.src" || op.Target != "body.dst" {
		t.Error("CopyOp helper failed")
	}

	op = ConditionalOp("body.test exists", SetOp("body.result", true))
	if op.Condition != "body.test exists" {
		t.Error("ConditionalOp helper failed")
	}
}

func TestContextMarshalBody(t *testing.T) {
	ctx := &Context{
		Body: map[string]interface{}{
			"name": "test",
			"nested": map[string]interface{}{
				"field": "value",
			},
		},
	}

	data, err := ctx.MarshalBody()
	if err != nil {
		t.Fatalf("MarshalBody failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if result["name"] != "test" {
		t.Error("expected name field")
	}
}

func TestContextUnmarshalBody(t *testing.T) {
	ctx := &Context{}
	data := []byte(`{"name":"test","count":42}`)

	if err := ctx.UnmarshalBody(data); err != nil {
		t.Fatalf("UnmarshalBody failed: %v", err)
	}

	if ctx.Body["name"] != "test" {
		t.Error("expected name field")
	}
	// JSON numbers are float64
	if ctx.Body["count"].(float64) != 42 {
		t.Error("expected count field")
	}
}

func TestMergeOperation(t *testing.T) {
	rules := []Rule{{
		Name: "merge-test",
		Request: []Operation{
			{Type: "merge", Source: "body.extra", Target: "body.main"},
		},
	}}

	transformer, err := New(rules)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx := &Context{
		Body: map[string]interface{}{
			"main": map[string]interface{}{
				"existing": "value",
			},
			"extra": map[string]interface{}{
				"added": "new-value",
			},
		},
	}

	if err := transformer.TransformRequest(ctx); err != nil {
		t.Fatalf("TransformRequest failed: %v", err)
	}

	main := ctx.Body["main"].(map[string]interface{})
	if main["existing"] != "value" {
		t.Error("expected existing field to be preserved")
	}
	if main["added"] != "new-value" {
		t.Error("expected added field from merge")
	}
}
