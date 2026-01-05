package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeRegisterFunction(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	fn := &Function{
		ID:      "test-fn",
		Name:    "Test Function",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200, body: "hello" }`,
		Enabled: true,
	}

	if err := runtime.RegisterFunction(fn); err != nil {
		t.Fatalf("RegisterFunction failed: %v", err)
	}

	retrieved := runtime.GetFunction("test-fn")
	if retrieved == nil {
		t.Fatal("expected to retrieve function")
	}

	if retrieved.Name != "Test Function" {
		t.Errorf("expected name 'Test Function', got %q", retrieved.Name)
	}
}

func TestRuntimeRegisterFunctionErrors(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	// Missing ID
	err := runtime.RegisterFunction(&Function{})
	if err == nil {
		t.Error("expected error for missing ID")
	}

	// Missing code for script
	err = runtime.RegisterFunction(&Function{ID: "test", Type: FunctionTypeScript})
	if err == nil {
		t.Error("expected error for missing code")
	}
}

func TestRuntimeUnregisterFunction(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:   "to-remove",
		Type: FunctionTypeScript,
		Code: "return null",
	})

	runtime.UnregisterFunction("to-remove")

	if runtime.GetFunction("to-remove") != nil {
		t.Error("expected function to be removed")
	}
}

func TestRuntimeListFunctions(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	for i := 0; i < 3; i++ {
		runtime.RegisterFunction(&Function{
			ID:   string(rune('a' + i)),
			Type: FunctionTypeScript,
			Code: "return null",
		})
	}

	functions := runtime.ListFunctions()
	if len(functions) != 3 {
		t.Errorf("expected 3 functions, got %d", len(functions))
	}
}

func TestRuntimeExecuteScript(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:      "hello",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200, body: "Hello, World!" }`,
		Enabled: true,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	execCtx := &ExecutionContext{
		Request: req,
		Vars:    make(map[string]string),
	}

	result, err := runtime.Execute(context.Background(), "hello", execCtx)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.Error != nil {
		t.Fatalf("execution error: %v", result.Error)
	}

	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}

	if string(result.Body) != "Hello, World!" {
		t.Errorf("expected body 'Hello, World!', got %q", result.Body)
	}
}

func TestRuntimeExecuteWithRequestAccess(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:   "echo-method",
		Type: FunctionTypeScript,
		Code: `
			if request.method == "POST" {
				return { status: 201, body: "Created" }
			}
			return { status: 200, body: "OK" }
		`,
		Enabled: true,
	})

	// Test GET
	req := httptest.NewRequest("GET", "/test", nil)
	result, _ := runtime.Execute(context.Background(), "echo-method", &ExecutionContext{Request: req})
	if result.StatusCode != 200 {
		t.Errorf("GET: expected 200, got %d", result.StatusCode)
	}

	// Test POST
	req = httptest.NewRequest("POST", "/test", nil)
	result, _ = runtime.Execute(context.Background(), "echo-method", &ExecutionContext{Request: req})
	if result.StatusCode != 201 {
		t.Errorf("POST: expected 201, got %d", result.StatusCode)
	}
}

func TestRuntimeExecuteWithEnv(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:   "env-test",
		Type: FunctionTypeScript,
		Code: `
			if env.API_KEY {
				return { status: 200, body: env.API_KEY }
			}
			return { status: 401, body: "No API key" }
		`,
		Env: map[string]string{
			"API_KEY": "secret-key-123",
		},
		Enabled: true,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	result, _ := runtime.Execute(context.Background(), "env-test", &ExecutionContext{
		Request: req,
		Env:     map[string]string{"API_KEY": "secret-key-123"},
	})

	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if string(result.Body) != "secret-key-123" {
		t.Errorf("expected API key in body, got %q", result.Body)
	}
}

func TestRuntimeExecuteDisabledFunction(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:      "disabled",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200 }`,
		Enabled: false,
	})

	_, err := runtime.Execute(context.Background(), "disabled", &ExecutionContext{})
	if err == nil {
		t.Error("expected error for disabled function")
	}
}

func TestRuntimeExecuteNotFound(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	_, err := runtime.Execute(context.Background(), "nonexistent", &ExecutionContext{})
	if err == nil {
		t.Error("expected error for nonexistent function")
	}
}

func TestRuntimeMatchFunctions(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:   "api-handler",
		Type: FunctionTypeScript,
		Code: "return null",
		Triggers: []Trigger{
			{Type: TriggerTypePath, Path: "/api/*", Methods: []string{"GET", "POST"}},
		},
		Enabled: true,
	})

	runtime.RegisterFunction(&Function{
		ID:   "admin-handler",
		Type: FunctionTypeScript,
		Code: "return null",
		Triggers: []Trigger{
			{Type: TriggerTypePath, Path: "/admin/*"},
		},
		Enabled: true,
	})

	tests := []struct {
		method   string
		path     string
		expected int
	}{
		{"GET", "/api/users", 1},
		{"POST", "/api/items", 1},
		{"PUT", "/api/users", 0}, // PUT not in methods
		{"GET", "/admin/dashboard", 1},
		{"GET", "/other/path", 0},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		matches := runtime.MatchFunctions(req)
		if len(matches) != tt.expected {
			t.Errorf("%s %s: expected %d matches, got %d", tt.method, tt.path, tt.expected, len(matches))
		}
	}
}

func TestScriptInterpreterBasic(t *testing.T) {
	interp := NewScriptInterpreter()

	tests := []struct {
		name   string
		code   string
		expect interface{}
	}{
		{
			name:   "return number",
			code:   "return 42",
			expect: float64(42),
		},
		{
			name:   "return string",
			code:   `return "hello"`,
			expect: "hello",
		},
		{
			name:   "return boolean",
			code:   "return true",
			expect: true,
		},
		{
			name:   "return null",
			code:   "return null",
			expect: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interp.Execute(context.Background(), tt.code)
			if err != nil {
				t.Fatalf("execution failed: %v", err)
			}
			if result != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}
}

func TestScriptInterpreterObjects(t *testing.T) {
	interp := NewScriptInterpreter()

	code := `return { status: 200, headers: { "Content-Type": "application/json" }, body: "test" }`

	result, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	obj, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if obj["status"] != float64(200) {
		t.Errorf("expected status 200, got %v", obj["status"])
	}

	if obj["body"] != "test" {
		t.Errorf("expected body 'test', got %v", obj["body"])
	}

	headers, ok := obj["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("expected headers map")
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header")
	}
}

func TestScriptInterpreterArrays(t *testing.T) {
	interp := NewScriptInterpreter()

	code := `return [1, 2, 3, "four"]`

	result, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatal("expected array result")
	}

	if len(arr) != 4 {
		t.Errorf("expected 4 elements, got %d", len(arr))
	}
}

func TestScriptInterpreterVariables(t *testing.T) {
	interp := NewScriptInterpreter()

	interp.SetVariable("request", map[string]interface{}{
		"method": "POST",
		"path":   "/api/users",
		"headers": map[string]interface{}{
			"Content-Type": "application/json",
		},
	})

	code := `return { method: request.method, path: request.path }`

	result, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	obj := result.(map[string]interface{})
	if obj["method"] != "POST" {
		t.Errorf("expected method 'POST', got %v", obj["method"])
	}
	if obj["path"] != "/api/users" {
		t.Errorf("expected path '/api/users', got %v", obj["path"])
	}
}

func TestScriptInterpreterConditional(t *testing.T) {
	interp := NewScriptInterpreter()

	interp.SetVariable("request", map[string]interface{}{
		"method": "GET",
	})

	code := `
		if request.method == "GET" {
			return { status: 200, body: "GET request" }
		}
		return { status: 405, body: "Method not allowed" }
	`

	result, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	obj := result.(map[string]interface{})
	if obj["status"] != float64(200) {
		t.Errorf("expected status 200, got %v", obj["status"])
	}
}

func TestScriptInterpreterConsoleLog(t *testing.T) {
	interp := NewScriptInterpreter()

	code := `
		console.log("Hello")
		console.log("World")
		return null
	`

	_, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	logs := interp.GetLogs()
	if len(logs) != 2 {
		t.Errorf("expected 2 logs, got %d", len(logs))
	}
	if logs[0] != "Hello" {
		t.Errorf("expected first log 'Hello', got %q", logs[0])
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		matches bool
	}{
		{"/api/users", "/api/*", true},
		{"/api/users/123", "/api/*", true},
		{"/other/path", "/api/*", false},
		{"/api", "/api", true},
		{"/api/", "/api", false},
		{"/admin/dashboard", "/admin/*", true},
	}

	for _, tt := range tests {
		result := matchPath(tt.path, tt.pattern)
		if result != tt.matches {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, result, tt.matches)
		}
	}
}

func TestMatchesTrigger(t *testing.T) {
	tests := []struct {
		method  string
		path    string
		trigger Trigger
		matches bool
	}{
		{
			"GET", "/api/users",
			Trigger{Type: TriggerTypePath, Path: "/api/*"},
			true,
		},
		{
			"GET", "/api/users",
			Trigger{Type: TriggerTypePath, Path: "/api/*", Methods: []string{"GET", "POST"}},
			true,
		},
		{
			"PUT", "/api/users",
			Trigger{Type: TriggerTypePath, Path: "/api/*", Methods: []string{"GET", "POST"}},
			false,
		},
		{
			"GET", "/other",
			Trigger{Type: TriggerTypePath, Path: "/api/*"},
			false,
		},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		result := matchesTrigger(req, tt.trigger)
		if result != tt.matches {
			t.Errorf("%s %s: expected %v, got %v", tt.method, tt.path, tt.matches, result)
		}
	}
}

func TestRequestToMap(t *testing.T) {
	body := `{"name": "test"}`
	req := httptest.NewRequest("POST", "/api/users?page=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token123")

	m := requestToMap(req)

	if m["method"] != "POST" {
		t.Errorf("expected method 'POST', got %v", m["method"])
	}

	if m["path"] != "/api/users" {
		t.Errorf("expected path '/api/users', got %v", m["path"])
	}

	headers := m["headers"].(map[string]interface{})
	if headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header")
	}

	query := m["query"].(map[string]interface{})
	if query["page"] != "1" {
		t.Errorf("expected query param page=1")
	}

	// Body should be parsed as JSON
	bodyMap, ok := m["body"].(map[string]interface{})
	if !ok {
		t.Fatal("expected body to be parsed as JSON")
	}
	if bodyMap["name"] != "test" {
		t.Errorf("expected body.name='test'")
	}
}

func TestRuntimeStats(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:      "stats-test",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200 }`,
		Enabled: true,
	})

	// Execute a few times
	for i := 0; i < 5; i++ {
		runtime.Execute(context.Background(), "stats-test", &ExecutionContext{
			Request: httptest.NewRequest("GET", "/", nil),
		})
	}

	stats := runtime.Stats()

	if stats["function_count"].(int) != 1 {
		t.Errorf("expected 1 function, got %v", stats["function_count"])
	}
	if stats["exec_count"].(int64) != 5 {
		t.Errorf("expected 5 executions, got %v", stats["exec_count"])
	}
}

func TestMiddleware(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:   "intercept",
		Type: FunctionTypeScript,
		Code: `return { status: 418, body: "I'm a teapot" }`,
		Triggers: []Trigger{
			{Type: TriggerTypePath, Path: "/teapot"},
		},
		Enabled: true,
	})

	middleware := Middleware(MiddlewareConfig{
		Runtime: runtime,
	})

	// Test function interception
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Original"))
	}))

	req := httptest.NewRequest("GET", "/teapot", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("expected 418, got %d", rec.Code)
	}

	if rec.Body.String() != "I'm a teapot" {
		t.Errorf("expected teapot body, got %q", rec.Body.String())
	}
}

func TestMiddlewarePassthrough(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	middleware := Middleware(MiddlewareConfig{
		Runtime: runtime,
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Original"))
	}))

	req := httptest.NewRequest("GET", "/not-matched", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	if rec.Body.String() != "Original" {
		t.Errorf("expected 'Original', got %q", rec.Body.String())
	}
}

func TestHandler(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())

	runtime.RegisterFunction(&Function{
		ID:      "handler-test",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200, headers: { "X-Custom": "value" }, body: "Handler response" }`,
		Enabled: true,
	})

	handler := Handler(runtime, "handler-test")

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	if rec.Header().Get("X-Custom") != "value" {
		t.Errorf("expected X-Custom header")
	}

	if rec.Body.String() != "Handler response" {
		t.Errorf("expected body, got %q", rec.Body.String())
	}
}

func TestAPIHandler(t *testing.T) {
	runtime := New(DefaultRuntimeConfig())
	handler := runtime.APIHandler()

	// Create function
	fn := &Function{
		ID:      "api-test",
		Name:    "API Test",
		Type:    FunctionTypeScript,
		Code:    `return { status: 200 }`,
		Enabled: true,
	}
	body, _ := json.Marshal(fn)

	req := httptest.NewRequest("POST", "/functions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("POST /functions: expected 201, got %d", rec.Code)
	}

	// List functions
	req = httptest.NewRequest("GET", "/functions", nil)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /functions: expected 200, got %d", rec.Code)
	}

	var functions []*Function
	json.NewDecoder(rec.Body).Decode(&functions)

	if len(functions) != 1 {
		t.Errorf("expected 1 function, got %d", len(functions))
	}

	// Get function
	req = httptest.NewRequest("GET", "/functions/api-test", nil)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /functions/id: expected 200, got %d", rec.Code)
	}

	// Get stats
	req = httptest.NewRequest("GET", "/stats", nil)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /stats: expected 200, got %d", rec.Code)
	}

	// Delete function
	req = httptest.NewRequest("DELETE", "/functions/api-test", nil)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("DELETE /functions/id: expected 204, got %d", rec.Code)
	}
}

func TestFunctionBuilder(t *testing.T) {
	fn := NewFunction("builder-test").
		Name("Builder Test").
		Description("A test function").
		Type(FunctionTypeScript).
		Code(`return { status: 200 }`).
		OnPath("/api/*", "GET", "POST").
		OnEvent("user.created").
		Env("API_KEY", "secret").
		Timeout(10 * time.Second).
		Build()

	if fn.ID != "builder-test" {
		t.Errorf("expected ID 'builder-test', got %q", fn.ID)
	}
	if fn.Name != "Builder Test" {
		t.Errorf("expected name 'Builder Test', got %q", fn.Name)
	}
	if len(fn.Triggers) != 2 {
		t.Errorf("expected 2 triggers, got %d", len(fn.Triggers))
	}
	if fn.Env["API_KEY"] != "secret" {
		t.Error("expected API_KEY env var")
	}
	if fn.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", fn.Timeout)
	}
}

func TestDefaultRuntimeConfig(t *testing.T) {
	cfg := DefaultRuntimeConfig()

	if cfg.MaxExecutionTime != 30*time.Second {
		t.Errorf("expected 30s execution time, got %v", cfg.MaxExecutionTime)
	}
	if cfg.MaxMemory != 64*1024*1024 {
		t.Errorf("expected 64MB memory, got %d", cfg.MaxMemory)
	}
	if cfg.MaxConcurrent != 100 {
		t.Errorf("expected 100 concurrent, got %d", cfg.MaxConcurrent)
	}
}

func TestScriptParserNestedObjects(t *testing.T) {
	interp := NewScriptInterpreter()

	code := `return { outer: { inner: { deep: "value" } } }`

	result, err := interp.Execute(context.Background(), code)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	obj := result.(map[string]interface{})
	outer := obj["outer"].(map[string]interface{})
	inner := outer["inner"].(map[string]interface{})

	if inner["deep"] != "value" {
		t.Errorf("expected deep value")
	}
}

func TestExecuteTimeout(t *testing.T) {
	runtime := New(RuntimeConfig{
		MaxExecutionTime: 10 * time.Millisecond,
	})

	// This would need actual timeout implementation in the interpreter
	// For now, test that timeout config is set
	if runtime.config.MaxExecutionTime != 10*time.Millisecond {
		t.Errorf("expected 10ms timeout")
	}
}
