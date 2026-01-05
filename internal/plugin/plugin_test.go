package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExecutionPhaseString(t *testing.T) {
	tests := []struct {
		phase    ExecutionPhase
		expected string
	}{
		{PhaseOnRequestHeaders, "on_request_headers"},
		{PhaseOnRequestBody, "on_request_body"},
		{PhaseOnResponseHeaders, "on_response_headers"},
		{PhaseOnResponseBody, "on_response_body"},
		{PhaseOnLog, "on_log"},
		{ExecutionPhase(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.phase.String(); got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestParsePhase(t *testing.T) {
	tests := []struct {
		input    string
		expected ExecutionPhase
	}{
		{"on_request_headers", PhaseOnRequestHeaders},
		{"on_request_body", PhaseOnRequestBody},
		{"on_response_headers", PhaseOnResponseHeaders},
		{"on_response_body", PhaseOnResponseBody},
		{"on_log", PhaseOnLog},
		{"unknown", PhaseOnRequestHeaders}, // defaults to request headers
		{"", PhaseOnRequestHeaders},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParsePhase(tt.input); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestActionConstants(t *testing.T) {
	if ActionContinue != 0 {
		t.Errorf("expected ActionContinue to be 0, got %d", ActionContinue)
	}
	if ActionPause != 1 {
		t.Errorf("expected ActionPause to be 1, got %d", ActionPause)
	}
	if ActionEndStream != 2 {
		t.Errorf("expected ActionEndStream to be 2, got %d", ActionEndStream)
	}
}

func TestDefaultRuntimeConfig(t *testing.T) {
	cfg := DefaultRuntimeConfig()

	if cfg.MemoryLimitPages != 256 {
		t.Errorf("expected MemoryLimitPages 256, got %d", cfg.MemoryLimitPages)
	}

	if cfg.ExecutionTimeout != 100*time.Millisecond {
		t.Errorf("expected ExecutionTimeout 100ms, got %v", cfg.ExecutionTimeout)
	}

	if cfg.EnableWASI {
		t.Error("expected EnableWASI to be false by default (security hardening)")
	}

	if cfg.CacheDir != "" {
		t.Errorf("expected empty CacheDir, got %s", cfg.CacheDir)
	}
}

func TestNewRuntime(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		MemoryLimitPages: 256,
		ExecutionTimeout: 100 * time.Millisecond,
		EnableWASI:       true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	if runtime.runtime == nil {
		t.Error("expected non-nil wazero runtime")
	}

	if runtime.modules == nil {
		t.Error("expected non-nil modules map")
	}

	if runtime.host == nil {
		t.Error("expected non-nil host")
	}
}

func TestRuntimeClose(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		MemoryLimitPages: 256,
		ExecutionTimeout: 100 * time.Millisecond,
		EnableWASI:       true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}

	err = runtime.Close(ctx)
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestGetLoadedPlugins_Empty(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	plugins := runtime.GetLoadedPlugins()
	if len(plugins) != 0 {
		t.Errorf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestGetPlugin_NotFound(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	_, ok := runtime.GetPlugin("nonexistent")
	if ok {
		t.Error("expected plugin not to be found")
	}
}

func TestGetPluginsByPhase_Empty(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	plugins := runtime.GetPluginsByPhase(PhaseOnRequestHeaders)
	if len(plugins) != 0 {
		t.Errorf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestNewPipeline(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)
	if pipeline == nil {
		t.Fatal("expected non-nil pipeline")
	}

	if pipeline.runtime != runtime {
		t.Error("expected pipeline.runtime to be set")
	}

	if pipeline.chains == nil {
		t.Error("expected non-nil chains map")
	}
}

func TestPipelineGetChain_Empty(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)
	chain := pipeline.GetChain("nonexistent")
	if chain != nil {
		t.Error("expected nil chain for nonexistent route")
	}
}

func TestPipelineBuildChain_NoPlugins(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)

	// Build chain with non-existent plugins (should be skipped)
	pipeline.BuildChain("test-route", []string{"plugin1", "plugin2"})

	chain := pipeline.GetChain("test-route")
	if len(chain) != 0 {
		t.Errorf("expected empty chain, got %d entries", len(chain))
	}
}

func TestPipelineExecuteRequestPhase_NoChain(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)
	reqCtx := NewRequestContext()

	result, err := pipeline.ExecuteRequestPhase(ctx, "nonexistent", PhaseOnRequestHeaders, reqCtx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !result.Continue {
		t.Error("expected Continue to be true")
	}
}

func TestPipelineExecuteResponsePhase_NoChain(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)
	reqCtx := NewRequestContext()

	result, err := pipeline.ExecuteResponsePhase(ctx, "nonexistent", PhaseOnResponseHeaders, reqCtx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !result.Continue {
		t.Error("expected Continue to be true")
	}
}

func TestNewRequestContext(t *testing.T) {
	reqCtx := NewRequestContext()

	if reqCtx == nil {
		t.Fatal("expected non-nil request context")
	}

	if reqCtx.RequestHeaders == nil {
		t.Error("expected non-nil RequestHeaders")
	}

	if reqCtx.ResponseHeaders == nil {
		t.Error("expected non-nil ResponseHeaders")
	}

	if reqCtx.Properties == nil {
		t.Error("expected non-nil Properties")
	}
}

func TestRequestContextHeaders(t *testing.T) {
	reqCtx := NewRequestContext()

	// Set request headers
	reqCtx.RequestHeaders["Content-Type"] = "application/json"
	reqCtx.RequestHeaders["Authorization"] = "Bearer token"

	if reqCtx.RequestHeaders["Content-Type"] != "application/json" {
		t.Error("expected Content-Type header")
	}

	if reqCtx.RequestHeaders["Authorization"] != "Bearer token" {
		t.Error("expected Authorization header")
	}

	// Set response headers
	reqCtx.ResponseHeaders["X-Custom"] = "value"

	if reqCtx.ResponseHeaders["X-Custom"] != "value" {
		t.Error("expected X-Custom response header")
	}
}

func TestPluginResponse(t *testing.T) {
	resp := &PluginResponse{
		Action:          ActionContinue,
		ModifiedHeaders: map[string]string{"X-Modified": "true"},
		ModifiedBody:    []byte("modified body"),
	}

	if resp.Action != ActionContinue {
		t.Errorf("expected ActionContinue, got %v", resp.Action)
	}

	if resp.ModifiedHeaders["X-Modified"] != "true" {
		t.Error("expected modified header")
	}

	if string(resp.ModifiedBody) != "modified body" {
		t.Error("expected modified body")
	}
}

func TestImmediateResponse(t *testing.T) {
	imm := &ImmediateResponse{
		StatusCode: 403,
		Headers:    map[string]string{"X-Reason": "Forbidden"},
		Body:       []byte("Access denied"),
	}

	if imm.StatusCode != 403 {
		t.Errorf("expected status code 403, got %d", imm.StatusCode)
	}

	if imm.Headers["X-Reason"] != "Forbidden" {
		t.Error("expected X-Reason header")
	}

	if string(imm.Body) != "Access denied" {
		t.Error("expected body 'Access denied'")
	}
}

func TestPluginChainEntry(t *testing.T) {
	entry := &PluginChainEntry{
		Name:     "auth",
		Priority: 100,
		Phase:    PhaseOnRequestHeaders,
	}

	if entry.Name != "auth" {
		t.Errorf("expected name 'auth', got %s", entry.Name)
	}

	if entry.Priority != 100 {
		t.Errorf("expected priority 100, got %d", entry.Priority)
	}

	if entry.Phase != PhaseOnRequestHeaders {
		t.Errorf("expected PhaseOnRequestHeaders, got %v", entry.Phase)
	}
}

func TestPipelineResult(t *testing.T) {
	result := &PipelineResult{
		Continue: true,
		ImmediateResponse: &ImmediateResponse{
			StatusCode: 200,
		},
	}

	if !result.Continue {
		t.Error("expected Continue to be true")
	}

	if result.ImmediateResponse.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", result.ImmediateResponse.StatusCode)
	}
}

func TestPluginConfig(t *testing.T) {
	cfg := PluginConfig{
		Name:          "test-plugin",
		Path:          "/plugins/test.wasm",
		Phase:         PhaseOnRequestHeaders,
		Priority:      100,
		MemoryLimit:   16,
		TimeoutMs:     100,
		Configuration: map[string]interface{}{"key": "value"},
	}

	if cfg.Name != "test-plugin" {
		t.Errorf("expected name 'test-plugin', got %s", cfg.Name)
	}

	if cfg.Path != "/plugins/test.wasm" {
		t.Errorf("expected path '/plugins/test.wasm', got %s", cfg.Path)
	}

	if cfg.Phase != PhaseOnRequestHeaders {
		t.Errorf("expected PhaseOnRequestHeaders, got %v", cfg.Phase)
	}

	if cfg.Priority != 100 {
		t.Errorf("expected priority 100, got %d", cfg.Priority)
	}

	if cfg.MemoryLimit != 16 {
		t.Errorf("expected memory limit 16, got %d", cfg.MemoryLimit)
	}

	if cfg.TimeoutMs != 100 {
		t.Errorf("expected timeout 100, got %d", cfg.TimeoutMs)
	}

	if cfg.Configuration["key"] != "value" {
		t.Error("expected configuration key 'key' with value 'value'")
	}
}

func TestSetRouteID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetRouteID(req, "my-route")

	routeID, ok := req.Context().Value(routeIDKey).(string)
	if !ok {
		t.Error("expected route ID in context")
	}

	if routeID != "my-route" {
		t.Errorf("expected route ID 'my-route', got %s", routeID)
	}
}

func TestPipelineMiddleware_NoRouteID(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := pipeline.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPipelineMiddleware_WithRouteID(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pipeline := NewPipeline(runtime)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := pipeline.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetRouteID(req, "test-route")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPhaseToFuncName(t *testing.T) {
	tests := []struct {
		phase    ExecutionPhase
		expected string
	}{
		{PhaseOnRequestHeaders, "proxy_on_request_headers"},
		{PhaseOnRequestBody, "proxy_on_request_body"},
		{PhaseOnResponseHeaders, "proxy_on_response_headers"},
		{PhaseOnResponseBody, "proxy_on_response_body"},
		{PhaseOnLog, "proxy_on_log"},
		{ExecutionPhase(99), ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := phaseToFuncName(tt.phase); got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestResponseWriterWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	rw.WriteHeader(http.StatusCreated)

	if rw.statusCode != http.StatusCreated {
		t.Errorf("expected status code 201, got %d", rw.statusCode)
	}

	if !rw.written {
		t.Error("expected written to be true")
	}
}

func TestResponseWriterWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	data := []byte("test data")
	n, err := rw.Write(data)

	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	if !rw.written {
		t.Error("expected written to be true after Write")
	}

	// Should default to 200 if no WriteHeader called
	if rw.statusCode != http.StatusOK {
		t.Errorf("expected status code 200, got %d", rw.statusCode)
	}
}

func TestLoadPlugin_NonexistentFile(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	pluginCfg := PluginConfig{
		Name:  "nonexistent",
		Path:  "/nonexistent/plugin.wasm",
		Phase: PhaseOnRequestHeaders,
	}

	err = runtime.LoadPlugin(ctx, pluginCfg)
	if err == nil {
		t.Error("expected error for nonexistent plugin file")
	}
}

func TestUnloadPlugin_Nonexistent(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Unloading nonexistent plugin should not error
	err = runtime.UnloadPlugin(ctx, "nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecutePlugin_NotFound(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	reqCtx := NewRequestContext()

	_, err = runtime.ExecutePlugin(ctx, "nonexistent", PhaseOnRequestHeaders, reqCtx)
	if err == nil {
		t.Error("expected error for nonexistent plugin")
	}
}
