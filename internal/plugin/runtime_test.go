package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josedab/loom/internal/config"
)

func TestDefaultRuntimeConfig_Values(t *testing.T) {
	cfg := DefaultRuntimeConfig()

	if cfg.MemoryLimitPages != 256 {
		t.Errorf("expected MemoryLimitPages 256, got %d", cfg.MemoryLimitPages)
	}
	if cfg.ExecutionTimeout != 100*time.Millisecond {
		t.Errorf("expected ExecutionTimeout 100ms, got %v", cfg.ExecutionTimeout)
	}
	if cfg.EnableWASI {
		t.Error("expected EnableWASI to be false by default")
	}
	if cfg.CacheDir != "" {
		t.Errorf("expected empty CacheDir, got %s", cfg.CacheDir)
	}
	if cfg.PluginDir != "" {
		t.Errorf("expected empty PluginDir, got %s", cfg.PluginDir)
	}
}

func TestNewRuntime_WithCacheDir(t *testing.T) {
	ctx := context.Background()

	// Create a temporary cache directory
	tmpDir, err := os.MkdirTemp("", "plugin-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := RuntimeConfig{
		MemoryLimitPages: 128,
		ExecutionTimeout: 50 * time.Millisecond,
		EnableWASI:       true,
		CacheDir:         tmpDir,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	if runtime.compCache == nil {
		t.Error("expected compilation cache to be set")
	}
}

func TestNewRuntime_InvalidCacheDir(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		CacheDir: "/nonexistent/path/that/does/not/exist",
	}

	_, err := NewRuntime(ctx, cfg)
	if err == nil {
		t.Error("expected error for invalid cache directory")
	}
}

func TestRuntime_ValidatePluginPath_NoPluginDir(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
		PluginDir:  "", // No restriction
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Any path should be allowed when PluginDir is not set
	tests := []string{
		"/some/path/plugin.wasm",
		"relative/path/plugin.wasm",
		"../parent/plugin.wasm",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			result, err := runtime.validatePluginPath(path)
			if err != nil {
				t.Errorf("expected no error for path %s, got: %v", path, err)
			}
			if result == "" {
				t.Error("expected non-empty result")
			}
		})
	}
}

func TestRuntime_ValidatePluginPath_WithPluginDir(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "plugin-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := RuntimeConfig{
		EnableWASI: true,
		PluginDir:  tmpDir,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	t.Run("valid relative path", func(t *testing.T) {
		result, err := runtime.validatePluginPath("plugin.wasm")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		expected := filepath.Join(tmpDir, "plugin.wasm")
		if result != expected {
			t.Errorf("expected %s, got %s", expected, result)
		}
	})

	t.Run("valid absolute path within dir", func(t *testing.T) {
		validPath := filepath.Join(tmpDir, "subdir", "plugin.wasm")
		result, err := runtime.validatePluginPath(validPath)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if result != validPath {
			t.Errorf("expected %s, got %s", validPath, result)
		}
	})

	t.Run("path traversal attempt", func(t *testing.T) {
		_, err := runtime.validatePluginPath("../../../etc/passwd")
		if err == nil {
			t.Error("expected error for path traversal attempt")
		}
	})

	t.Run("absolute path outside dir", func(t *testing.T) {
		_, err := runtime.validatePluginPath("/etc/passwd")
		if err == nil {
			t.Error("expected error for path outside plugin dir")
		}
	})
}

func TestPluginConfig_Fields(t *testing.T) {
	cfg := PluginConfig{
		Name:          "test-plugin",
		Path:          "/plugins/test.wasm",
		Phase:         PhaseOnRequestBody,
		Priority:      50,
		MemoryLimit:   32,
		TimeoutMs:     200,
		Configuration: map[string]interface{}{"enabled": true, "threshold": 100},
	}

	if cfg.Name != "test-plugin" {
		t.Errorf("expected name 'test-plugin', got %s", cfg.Name)
	}
	if cfg.Path != "/plugins/test.wasm" {
		t.Errorf("expected path '/plugins/test.wasm', got %s", cfg.Path)
	}
	if cfg.Phase != PhaseOnRequestBody {
		t.Errorf("expected PhaseOnRequestBody, got %v", cfg.Phase)
	}
	if cfg.Priority != 50 {
		t.Errorf("expected priority 50, got %d", cfg.Priority)
	}
	if cfg.MemoryLimit != 32 {
		t.Errorf("expected memory limit 32, got %d", cfg.MemoryLimit)
	}
	if cfg.TimeoutMs != 200 {
		t.Errorf("expected timeout 200, got %d", cfg.TimeoutMs)
	}
	if cfg.Configuration["enabled"] != true {
		t.Error("expected configuration 'enabled' to be true")
	}
	if cfg.Configuration["threshold"] != 100 {
		t.Error("expected configuration 'threshold' to be 100")
	}
}

func TestPluginResponse_Fields(t *testing.T) {
	resp := &PluginResponse{
		Action:          ActionPause,
		ModifiedHeaders: map[string]string{"X-Modified": "yes"},
		ModifiedBody:    []byte("modified content"),
		ImmediateResponse: &ImmediateResponse{
			StatusCode: 401,
			Headers:    map[string]string{"WWW-Authenticate": "Bearer"},
			Body:       []byte("Unauthorized"),
		},
	}

	if resp.Action != ActionPause {
		t.Errorf("expected ActionPause, got %v", resp.Action)
	}
	if resp.ModifiedHeaders["X-Modified"] != "yes" {
		t.Error("expected X-Modified header")
	}
	if string(resp.ModifiedBody) != "modified content" {
		t.Error("expected modified body content")
	}
	if resp.ImmediateResponse.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.ImmediateResponse.StatusCode)
	}
}

func TestImmediateResponse_Fields(t *testing.T) {
	resp := &ImmediateResponse{
		StatusCode: 503,
		Headers: map[string]string{
			"Retry-After":  "60",
			"Content-Type": "text/plain",
		},
		Body: []byte("Service Unavailable"),
	}

	if resp.StatusCode != 503 {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}
	if resp.Headers["Retry-After"] != "60" {
		t.Error("expected Retry-After header")
	}
	if resp.Headers["Content-Type"] != "text/plain" {
		t.Error("expected Content-Type header")
	}
	if string(resp.Body) != "Service Unavailable" {
		t.Error("expected body 'Service Unavailable'")
	}
}

func TestRuntime_GetLoadedPlugins_Multiple(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Initially empty
	plugins := runtime.GetLoadedPlugins()
	if len(plugins) != 0 {
		t.Errorf("expected 0 plugins initially, got %d", len(plugins))
	}
}

func TestRuntime_GetPluginsByPhase_Various(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	phases := []ExecutionPhase{
		PhaseOnRequestHeaders,
		PhaseOnRequestBody,
		PhaseOnResponseHeaders,
		PhaseOnResponseBody,
		PhaseOnLog,
	}

	for _, phase := range phases {
		t.Run(phase.String(), func(t *testing.T) {
			plugins := runtime.GetPluginsByPhase(phase)
			// GetPluginsByPhase returns nil when no plugins match
			if len(plugins) != 0 {
				t.Errorf("expected 0 plugins for phase %s, got %d", phase.String(), len(plugins))
			}
		})
	}
}

func TestAction_Values(t *testing.T) {
	if ActionContinue != 0 {
		t.Errorf("expected ActionContinue=0, got %d", ActionContinue)
	}
	if ActionPause != 1 {
		t.Errorf("expected ActionPause=1, got %d", ActionPause)
	}
	if ActionEndStream != 2 {
		t.Errorf("expected ActionEndStream=2, got %d", ActionEndStream)
	}
}

func TestRuntimeConfig_AllFields(t *testing.T) {
	cfg := RuntimeConfig{
		MemoryLimitPages: 512,
		ExecutionTimeout: 500 * time.Millisecond,
		EnableWASI:       true,
		CacheDir:         "/tmp/cache",
		PluginDir:        "/opt/plugins",
	}

	if cfg.MemoryLimitPages != 512 {
		t.Errorf("MemoryLimitPages mismatch")
	}
	if cfg.ExecutionTimeout != 500*time.Millisecond {
		t.Errorf("ExecutionTimeout mismatch")
	}
	if !cfg.EnableWASI {
		t.Error("EnableWASI should be true")
	}
	if cfg.CacheDir != "/tmp/cache" {
		t.Error("CacheDir mismatch")
	}
	if cfg.PluginDir != "/opt/plugins" {
		t.Error("PluginDir mismatch")
	}
}

func TestRuntime_ConcurrentPluginAccess(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	done := make(chan bool, 30)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = runtime.GetLoadedPlugins()
			done <- true
		}()

		go func() {
			_, _ = runtime.GetPlugin("nonexistent")
			done <- true
		}()

		go func() {
			_ = runtime.GetPluginsByPhase(PhaseOnRequestHeaders)
			done <- true
		}()
	}

	for i := 0; i < 30; i++ {
		<-done
	}
}

func TestLoadPlugin_NonExistentFile(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	err = runtime.LoadPlugin(ctx, PluginConfig{
		Name: "nonexistent",
		Path: "/nonexistent/plugin.wasm",
	})

	if err == nil {
		t.Error("expected error for non-existent plugin file")
	}
}

func TestUnloadPlugin_NonExistent(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Should not return error for non-existent plugin
	err = runtime.UnloadPlugin(ctx, "nonexistent")
	if err != nil {
		t.Errorf("unexpected error for non-existent plugin: %v", err)
	}
}

func TestConfigure_EmptyConfig(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Empty config should succeed
	err = runtime.Configure(ctx, nil)
	if err != nil {
		t.Errorf("unexpected error for empty config: %v", err)
	}
}

func TestExecutePlugin_NonExistent(t *testing.T) {
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
		t.Error("expected error for non-existent plugin")
	}
}

func TestExecutionPhase_String_Unknown(t *testing.T) {
	unknown := ExecutionPhase(999)
	result := unknown.String()
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %s", result)
	}
}

func TestParsePhase_AllPhases(t *testing.T) {
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
			result := ParsePhase(tt.input)
			if result != tt.expected {
				t.Errorf("ParsePhase(%s) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewRuntime_NoMemoryLimit(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		MemoryLimitPages: 0, // No limit
		EnableWASI:       true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	if runtime == nil {
		t.Fatal("expected non-nil runtime")
	}
}

func TestNewRuntime_NoCacheDir(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		CacheDir: "", // No cache
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	if runtime.compCache != nil {
		t.Error("expected nil compilation cache when CacheDir is empty")
	}
}

func TestRuntime_CloseEmpty(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}

	// Close should succeed even with no plugins loaded
	err = runtime.Close(ctx)
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestRuntime_GetPlugin_NotFound(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	plugin, found := runtime.GetPlugin("nonexistent")
	if found {
		t.Error("expected plugin not to be found")
	}
	if plugin != nil {
		t.Error("expected nil plugin")
	}
}

func TestPhaseToFuncName_AllPhases(t *testing.T) {
	tests := []struct {
		phase    ExecutionPhase
		expected string
	}{
		{PhaseOnRequestHeaders, "proxy_on_request_headers"},
		{PhaseOnRequestBody, "proxy_on_request_body"},
		{PhaseOnResponseHeaders, "proxy_on_response_headers"},
		{PhaseOnResponseBody, "proxy_on_response_body"},
		{PhaseOnLog, "proxy_on_log"},
		{ExecutionPhase(999), ""}, // unknown phase
	}

	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			result := phaseToFuncName(tt.phase)
			if result != tt.expected {
				t.Errorf("phaseToFuncName(%v) = %s, want %s", tt.phase, result, tt.expected)
			}
		})
	}
}

func TestConfigure_WithPluginConfigs(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{
		EnableWASI: true,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Test with non-existent plugin - should return error
	pluginConfigs := []config.PluginConfig{
		{
			Name:        "test-plugin",
			Path:        "/nonexistent/plugin.wasm",
			Phase:       "on_request_headers",
			Priority:    10,
			MemoryLimit: "32MB",
			Timeout:     "100ms",
			Config:      map[string]interface{}{"key": "value"},
		},
	}

	err = runtime.Configure(ctx, pluginConfigs)
	if err == nil {
		t.Error("expected error for non-existent plugin file")
	}
}

func TestConfigure_EmptySlice(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Empty slice should succeed
	err = runtime.Configure(ctx, []config.PluginConfig{})
	if err != nil {
		t.Errorf("unexpected error for empty config slice: %v", err)
	}
}

func TestConfigure_NoMemoryLimit(t *testing.T) {
	ctx := context.Background()
	cfg := RuntimeConfig{}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	// Config without memory limit - will still fail on file read but exercises the path
	pluginConfigs := []config.PluginConfig{
		{
			Name:        "test-plugin",
			Path:        "/nonexistent/plugin.wasm",
			Phase:       "on_request_body",
			Priority:    5,
			MemoryLimit: "", // No memory limit
			Timeout:     "",
		},
	}

	err = runtime.Configure(ctx, pluginConfigs)
	if err == nil {
		t.Error("expected error for non-existent plugin file")
	}
}

func TestRuntime_LoadPlugin_PathTraversal(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "plugin-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := RuntimeConfig{
		PluginDir: tmpDir,
	}

	runtime, err := NewRuntime(ctx, cfg)
	if err != nil {
		t.Fatalf("NewRuntime failed: %v", err)
	}
	defer runtime.Close(ctx)

	err = runtime.LoadPlugin(ctx, PluginConfig{
		Name: "malicious",
		Path: "../../../etc/passwd",
	})

	if err == nil {
		t.Error("expected error for path traversal attempt")
	}
}

func TestCompiledPlugin_Fields(t *testing.T) {
	plugin := &CompiledPlugin{
		Name: "test-plugin",
		Config: PluginConfig{
			Name:     "test-plugin",
			Path:     "/path/to/plugin.wasm",
			Phase:    PhaseOnRequestHeaders,
			Priority: 100,
		},
	}

	if plugin.Name != "test-plugin" {
		t.Errorf("expected name 'test-plugin', got %s", plugin.Name)
	}
	if plugin.Config.Priority != 100 {
		t.Errorf("expected priority 100, got %d", plugin.Config.Priority)
	}
}

func TestPluginInfo_Fields(t *testing.T) {
	info := PluginInfo{
		Name:      "auth",
		Path:      "/plugins/auth.wasm",
		Phase:     "on_request_headers",
		Priority:  100,
		Version:   2,
		MemoryMB:  32,
		TimeoutMs: 50,
		Config:    map[string]interface{}{"key": "value"},
	}

	if info.Name != "auth" {
		t.Errorf("expected name 'auth', got %s", info.Name)
	}
	if info.Version != 2 {
		t.Errorf("expected version 2, got %d", info.Version)
	}
	if info.LoadedAt.IsZero() {
		// LoadedAt should be set, but in this test it's zero
		// which is expected since we're just testing fields
	}
}

func TestGetPluginInfo_NotFound(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(ctx, DefaultRuntimeConfig())
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	info, ok := runtime.GetPluginInfo("nonexistent")
	if ok {
		t.Error("expected ok to be false for nonexistent plugin")
	}
	if info != nil {
		t.Error("expected nil info for nonexistent plugin")
	}
}

func TestGetAllPluginInfo_Empty(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(ctx, DefaultRuntimeConfig())
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	infos := runtime.GetAllPluginInfo()
	if len(infos) != 0 {
		t.Errorf("expected 0 plugins, got %d", len(infos))
	}
}

func TestGetGlobalVersion_Initial(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(ctx, DefaultRuntimeConfig())
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	version := runtime.GetGlobalVersion()
	if version != 0 {
		t.Errorf("expected initial global version 0, got %d", version)
	}
}

func TestReconfigure_NoChange(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(ctx, DefaultRuntimeConfig())
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	// Reconfigure with empty config
	added, updated, removed, err := runtime.Reconfigure(ctx, []config.PluginConfig{})
	if err != nil {
		t.Fatalf("reconfigure failed: %v", err)
	}

	if len(added) != 0 {
		t.Errorf("expected 0 added, got %d", len(added))
	}
	if len(updated) != 0 {
		t.Errorf("expected 0 updated, got %d", len(updated))
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(removed))
	}

	// Global version should be incremented
	if runtime.GetGlobalVersion() != 1 {
		t.Errorf("expected global version 1, got %d", runtime.GetGlobalVersion())
	}
}

func TestReloadPlugin_NotFound(t *testing.T) {
	ctx := context.Background()
	runtime, err := NewRuntime(ctx, DefaultRuntimeConfig())
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer runtime.Close(ctx)

	err = runtime.ReloadPlugin(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent plugin")
	}
}
