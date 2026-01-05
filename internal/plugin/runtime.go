// Package plugin provides the WASM plugin runtime using wazero.
package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ExecutionPhase represents when a plugin executes.
type ExecutionPhase int

const (
	PhaseOnRequestHeaders ExecutionPhase = iota
	PhaseOnRequestBody
	PhaseOnResponseHeaders
	PhaseOnResponseBody
	PhaseOnLog
)

// String returns the string representation of the phase.
func (p ExecutionPhase) String() string {
	switch p {
	case PhaseOnRequestHeaders:
		return "on_request_headers"
	case PhaseOnRequestBody:
		return "on_request_body"
	case PhaseOnResponseHeaders:
		return "on_response_headers"
	case PhaseOnResponseBody:
		return "on_response_body"
	case PhaseOnLog:
		return "on_log"
	default:
		return "unknown"
	}
}

// ParsePhase parses a phase string.
func ParsePhase(s string) ExecutionPhase {
	switch s {
	case "on_request_headers":
		return PhaseOnRequestHeaders
	case "on_request_body":
		return PhaseOnRequestBody
	case "on_response_headers":
		return PhaseOnResponseHeaders
	case "on_response_body":
		return PhaseOnResponseBody
	case "on_log":
		return PhaseOnLog
	default:
		return PhaseOnRequestHeaders
	}
}

// Action represents the action to take after plugin execution.
type Action int

const (
	ActionContinue Action = iota
	ActionPause
	ActionEndStream
)

// RuntimeConfig configures the WASM runtime.
type RuntimeConfig struct {
	MemoryLimitPages uint32        // Memory limit in 64KB pages
	ExecutionTimeout time.Duration // Per-invocation timeout
	EnableWASI       bool          // Enable WASI for file/network access
	CacheDir         string        // Directory for compilation cache
	PluginDir        string        // Allowed directory for plugin files (path traversal protection)
}

// DefaultRuntimeConfig returns default runtime configuration.
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		MemoryLimitPages: 256,              // 16MB default
		ExecutionTimeout: 100 * time.Millisecond,
		EnableWASI:       false,            // Disabled by default for security (limits file/network access)
		CacheDir:         "",
	}
}

// CompiledPlugin represents a pre-compiled WASM module.
type CompiledPlugin struct {
	Name         string
	Module       wazero.CompiledModule
	Config       PluginConfig
	instancePool sync.Pool
	runtime      wazero.Runtime
}

// PluginConfig defines plugin behavior.
type PluginConfig struct {
	Name          string
	Path          string
	Phase         ExecutionPhase
	Priority      int
	MemoryLimit   uint32 // in MB
	TimeoutMs     int
	Configuration map[string]interface{}
}

// Runtime manages WASM plugin execution.
type Runtime struct {
	runtime    wazero.Runtime
	modules    map[string]*CompiledPlugin
	mu         sync.RWMutex
	config     RuntimeConfig
	host       *ProxyWasmHost
	compCache  wazero.CompilationCache
}

// NewRuntime creates a new WASM runtime.
func NewRuntime(ctx context.Context, cfg RuntimeConfig) (*Runtime, error) {
	// Create compilation cache
	var cache wazero.CompilationCache
	var err error
	if cfg.CacheDir != "" {
		cache, err = wazero.NewCompilationCacheWithDir(cfg.CacheDir)
		if err != nil {
			return nil, fmt.Errorf("creating compilation cache: %w", err)
		}
	}

	// Create wazero runtime with AOT compilation (compiler mode)
	runtimeConfig := wazero.NewRuntimeConfig()
	if cache != nil {
		runtimeConfig = runtimeConfig.WithCompilationCache(cache)
	}

	// Enforce memory limit if configured (prevents memory exhaustion attacks)
	if cfg.MemoryLimitPages > 0 {
		runtimeConfig = runtimeConfig.WithMemoryLimitPages(cfg.MemoryLimitPages)
	}

	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)

	// Initialize WASI if enabled
	if cfg.EnableWASI {
		wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	}

	pr := &Runtime{
		runtime:   runtime,
		modules:   make(map[string]*CompiledPlugin),
		config:    cfg,
		compCache: cache,
	}

	// Create host for Proxy-Wasm ABI
	pr.host = NewProxyWasmHost(runtime)

	// Register host functions
	if err := pr.host.RegisterHostFunctions(ctx); err != nil {
		runtime.Close(ctx)
		return nil, fmt.Errorf("registering host functions: %w", err)
	}

	return pr, nil
}

// Configure loads plugins from configuration.
func (r *Runtime) Configure(ctx context.Context, configs []config.PluginConfig) error {
	for _, cfg := range configs {
		pluginCfg := PluginConfig{
			Name:          cfg.Name,
			Path:          cfg.Path,
			Phase:         ParsePhase(cfg.Phase),
			Priority:      cfg.Priority,
			Configuration: cfg.Config,
			TimeoutMs:     int(config.ParseDuration(cfg.Timeout, 100*time.Millisecond).Milliseconds()),
		}

		// Parse memory limit
		if cfg.MemoryLimit != "" {
			var limit uint32
			fmt.Sscanf(cfg.MemoryLimit, "%dMB", &limit)
			pluginCfg.MemoryLimit = limit
		}

		if err := r.LoadPlugin(ctx, pluginCfg); err != nil {
			return fmt.Errorf("loading plugin %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// validatePluginPath ensures the plugin path doesn't escape the allowed directory (path traversal protection).
func (r *Runtime) validatePluginPath(path string) (string, error) {
	// If no plugin directory is configured, allow any path (backward compatibility)
	if r.config.PluginDir == "" {
		return filepath.Clean(path), nil
	}

	cleanBase := filepath.Clean(r.config.PluginDir)

	// Handle both absolute and relative paths
	var fullPath string
	if filepath.IsAbs(path) {
		fullPath = filepath.Clean(path)
	} else {
		fullPath = filepath.Clean(filepath.Join(cleanBase, path))
	}

	// Verify the path is within the allowed directory
	if !strings.HasPrefix(fullPath, cleanBase+string(filepath.Separator)) && fullPath != cleanBase {
		return "", fmt.Errorf("path traversal attempt detected: %s is not within %s", path, r.config.PluginDir)
	}

	return fullPath, nil
}

// LoadPlugin loads and compiles a WASM plugin.
func (r *Runtime) LoadPlugin(ctx context.Context, cfg PluginConfig) error {
	// Validate plugin path to prevent path traversal attacks
	validPath, err := r.validatePluginPath(cfg.Path)
	if err != nil {
		return err
	}

	wasmBytes, err := os.ReadFile(validPath)
	if err != nil {
		return fmt.Errorf("reading plugin file: %w", err)
	}

	// Pre-compile for best performance
	compiled, err := r.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return fmt.Errorf("compiling plugin: %w", err)
	}

	plugin := &CompiledPlugin{
		Name:    cfg.Name,
		Module:  compiled,
		Config:  cfg,
		runtime: r.runtime,
	}

	// Initialize instance pool
	plugin.instancePool = sync.Pool{
		New: func() interface{} {
			inst, err := r.instantiateModule(ctx, plugin)
			if err != nil {
				return nil
			}
			return inst
		},
	}

	r.mu.Lock()
	r.modules[cfg.Name] = plugin
	r.mu.Unlock()

	return nil
}

// instantiateModule creates a new instance from a compiled module.
func (r *Runtime) instantiateModule(ctx context.Context, plugin *CompiledPlugin) (api.Module, error) {
	moduleConfig := wazero.NewModuleConfig().
		WithName(plugin.Name + "_" + fmt.Sprintf("%d", time.Now().UnixNano())).
		WithStartFunctions() // Don't auto-call _start

	inst, err := r.runtime.InstantiateModule(ctx, plugin.Module, moduleConfig)
	if err != nil {
		return nil, err
	}

	return inst, nil
}

// UnloadPlugin removes a plugin.
func (r *Runtime) UnloadPlugin(ctx context.Context, name string) error {
	r.mu.Lock()
	plugin, ok := r.modules[name]
	if ok {
		delete(r.modules, name)
	}
	r.mu.Unlock()

	if ok && plugin.Module != nil {
		return plugin.Module.Close(ctx)
	}
	return nil
}

// GetPlugin returns a plugin by name.
func (r *Runtime) GetPlugin(name string) (*CompiledPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.modules[name]
	return p, ok
}

// GetPluginsByPhase returns plugins that execute in a specific phase.
func (r *Runtime) GetPluginsByPhase(phase ExecutionPhase) []*CompiledPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var plugins []*CompiledPlugin
	for _, p := range r.modules {
		if p.Config.Phase == phase {
			plugins = append(plugins, p)
		}
	}
	return plugins
}

// ExecutePlugin runs a plugin phase.
func (r *Runtime) ExecutePlugin(
	ctx context.Context,
	pluginName string,
	phase ExecutionPhase,
	reqCtx *RequestContext,
) (*PluginResponse, error) {
	r.mu.RLock()
	plugin, ok := r.modules[pluginName]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Get instance from pool
	inst := plugin.instancePool.Get()
	if inst == nil {
		return nil, fmt.Errorf("failed to get plugin instance")
	}
	module := inst.(api.Module)
	defer plugin.instancePool.Put(inst)

	// Set timeout for execution (use plugin-specific or runtime default)
	timeout := time.Duration(plugin.Config.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = r.config.ExecutionTimeout
	}
	if timeout <= 0 {
		timeout = 100 * time.Millisecond // absolute fallback
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Set request context for host functions
	r.host.SetRequestContext(reqCtx)

	// Call the appropriate phase function
	funcName := phaseToFuncName(phase)
	fn := module.ExportedFunction(funcName)
	if fn == nil {
		// Plugin doesn't implement this phase, skip
		return &PluginResponse{Action: ActionContinue}, nil
	}

	// Call plugin function with headers count and end of stream flag
	results, err := fn.Call(ctx, uint64(len(reqCtx.RequestHeaders)), 0)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("plugin execution timeout after %v: %w", timeout, err)
		}
		return nil, fmt.Errorf("plugin execution failed: %w", err)
	}

	// Parse result
	action := Action(results[0])
	return &PluginResponse{Action: action}, nil
}

// phaseToFuncName converts a phase to the Proxy-Wasm function name.
func phaseToFuncName(phase ExecutionPhase) string {
	switch phase {
	case PhaseOnRequestHeaders:
		return "proxy_on_request_headers"
	case PhaseOnRequestBody:
		return "proxy_on_request_body"
	case PhaseOnResponseHeaders:
		return "proxy_on_response_headers"
	case PhaseOnResponseBody:
		return "proxy_on_response_body"
	case PhaseOnLog:
		return "proxy_on_log"
	default:
		return ""
	}
}

// PluginResponse contains the result of plugin execution.
type PluginResponse struct {
	Action           Action
	ModifiedHeaders  map[string]string
	ModifiedBody     []byte
	ImmediateResponse *ImmediateResponse
}

// ImmediateResponse represents an immediate response from a plugin.
type ImmediateResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// Close closes the runtime.
func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, plugin := range r.modules {
		if plugin.Module != nil {
			plugin.Module.Close(ctx)
		}
		delete(r.modules, name)
	}

	return r.runtime.Close(ctx)
}

// GetLoadedPlugins returns the names of all loaded plugins.
func (r *Runtime) GetLoadedPlugins() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.modules))
	for name := range r.modules {
		names = append(names, name)
	}
	return names
}
