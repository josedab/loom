// Package edge provides edge function execution capabilities.
package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runtime executes edge functions.
type Runtime struct {
	functions map[string]*Function
	config    RuntimeConfig
	logger    *slog.Logger
	mu        sync.RWMutex

	// Execution metrics
	execCount  int64
	execErrors int64
	execTimeNs int64
}

// RuntimeConfig configures the edge runtime.
type RuntimeConfig struct {
	// MaxExecutionTime limits function execution time
	MaxExecutionTime time.Duration
	// MaxMemory limits function memory usage (bytes)
	MaxMemory int64
	// MaxConcurrent limits concurrent function executions
	MaxConcurrent int
	// Logger for runtime events
	Logger *slog.Logger
}

// DefaultRuntimeConfig returns sensible defaults.
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		MaxExecutionTime: 30 * time.Second,
		MaxMemory:        64 * 1024 * 1024, // 64MB
		MaxConcurrent:    100,
	}
}

// Function represents an edge function.
type Function struct {
	// ID is a unique identifier
	ID string `json:"id"`
	// Name is a human-readable name
	Name string `json:"name"`
	// Description of the function
	Description string `json:"description,omitempty"`
	// Type is the function type (script, wasm, fetch)
	Type FunctionType `json:"type"`
	// Code contains the function code (for script type)
	Code string `json:"code,omitempty"`
	// WASMModule is the compiled WASM module (for wasm type)
	WASMModule []byte `json:"-"`
	// WASMPath is the path to the WASM file
	WASMPath string `json:"wasm_path,omitempty"`
	// Triggers define when this function executes
	Triggers []Trigger `json:"triggers,omitempty"`
	// Environment variables for the function
	Env map[string]string `json:"env,omitempty"`
	// Timeout overrides the default execution timeout
	Timeout time.Duration `json:"timeout,omitempty"`
	// Enabled determines if the function is active
	Enabled bool `json:"enabled"`
}

// FunctionType defines the type of edge function.
type FunctionType string

const (
	// FunctionTypeScript is a JavaScript-like script
	FunctionTypeScript FunctionType = "script"
	// FunctionTypeWASM is a WebAssembly module
	FunctionTypeWASM FunctionType = "wasm"
	// FunctionTypeFetch is a fetch handler for service worker style
	FunctionTypeFetch FunctionType = "fetch"
)

// Trigger defines when a function executes.
type Trigger struct {
	// Type is the trigger type (path, event, schedule)
	Type TriggerType `json:"type"`
	// Path pattern for path triggers
	Path string `json:"path,omitempty"`
	// Method filters for path triggers
	Methods []string `json:"methods,omitempty"`
	// Event name for event triggers
	Event string `json:"event,omitempty"`
	// Schedule cron expression for scheduled triggers
	Schedule string `json:"schedule,omitempty"`
}

// TriggerType defines types of triggers.
type TriggerType string

const (
	TriggerTypePath     TriggerType = "path"
	TriggerTypeEvent    TriggerType = "event"
	TriggerTypeSchedule TriggerType = "schedule"
)

// New creates a new edge runtime.
func New(config RuntimeConfig) *Runtime {
	if config.MaxExecutionTime == 0 {
		config.MaxExecutionTime = 30 * time.Second
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 100
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &Runtime{
		functions: make(map[string]*Function),
		config:    config,
		logger:    config.Logger,
	}
}

// RegisterFunction registers an edge function.
func (r *Runtime) RegisterFunction(fn *Function) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if fn.ID == "" {
		return errors.New("function ID is required")
	}

	if fn.Type == "" {
		fn.Type = FunctionTypeScript
	}

	if fn.Type == FunctionTypeScript && fn.Code == "" {
		return errors.New("script function requires code")
	}

	r.functions[fn.ID] = fn
	r.logger.Info("registered edge function", "id", fn.ID, "type", fn.Type)

	return nil
}

// UnregisterFunction removes an edge function.
func (r *Runtime) UnregisterFunction(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.functions, id)
}

// GetFunction returns a function by ID.
func (r *Runtime) GetFunction(id string) *Function {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.functions[id]
}

// ListFunctions returns all registered functions.
func (r *Runtime) ListFunctions() []*Function {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Function, 0, len(r.functions))
	for _, fn := range r.functions {
		result = append(result, fn)
	}
	return result
}

// ExecutionContext provides request context to edge functions.
type ExecutionContext struct {
	// Request is the incoming HTTP request
	Request *http.Request
	// ResponseWriter for writing response
	ResponseWriter http.ResponseWriter
	// Vars are path variables extracted from the URL
	Vars map[string]string
	// Env contains environment variables
	Env map[string]string
	// Data is arbitrary data passed to the function
	Data map[string]interface{}
}

// ExecutionResult is the result of function execution.
type ExecutionResult struct {
	// Response indicates if a response was written
	Response bool
	// StatusCode if response was generated
	StatusCode int
	// Headers to add to response
	Headers map[string]string
	// Body is the response body
	Body []byte
	// Modified request (for middleware mode)
	ModifiedRequest *http.Request
	// Error if execution failed
	Error error
	// Duration of execution
	Duration time.Duration
	// Logs from the function
	Logs []string
}

// Execute executes a function.
func (r *Runtime) Execute(ctx context.Context, functionID string, execCtx *ExecutionContext) (*ExecutionResult, error) {
	r.mu.RLock()
	fn := r.functions[functionID]
	r.mu.RUnlock()

	if fn == nil {
		return nil, fmt.Errorf("function not found: %s", functionID)
	}

	if !fn.Enabled {
		return nil, fmt.Errorf("function is disabled: %s", functionID)
	}

	// Set timeout
	timeout := r.config.MaxExecutionTime
	if fn.Timeout > 0 {
		timeout = fn.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var result *ExecutionResult

	switch fn.Type {
	case FunctionTypeScript:
		result = r.executeScript(ctx, fn, execCtx)
	case FunctionTypeFetch:
		result = r.executeFetch(ctx, fn, execCtx)
	case FunctionTypeWASM:
		result = r.executeWASM(ctx, fn, execCtx)
	default:
		return nil, fmt.Errorf("unknown function type: %s", fn.Type)
	}

	result.Duration = time.Since(start)

	// Update metrics
	r.mu.Lock()
	r.execCount++
	r.execTimeNs += result.Duration.Nanoseconds()
	if result.Error != nil {
		r.execErrors++
	}
	r.mu.Unlock()

	return result, nil
}

// executeScript executes a JavaScript-like script.
func (r *Runtime) executeScript(ctx context.Context, fn *Function, execCtx *ExecutionContext) *ExecutionResult {
	result := &ExecutionResult{
		Headers: make(map[string]string),
	}

	// Create script interpreter
	interp := NewScriptInterpreter()

	// Inject request context
	interp.SetVariable("request", requestToMap(execCtx.Request))
	interp.SetVariable("env", fn.Env)
	interp.SetVariable("vars", execCtx.Vars)

	// Execute script
	output, err := interp.Execute(ctx, fn.Code)
	if err != nil {
		result.Error = err
		return result
	}

	result.Logs = interp.GetLogs()

	// Parse output
	if out, ok := output.(map[string]interface{}); ok {
		if status, ok := out["status"].(float64); ok {
			result.StatusCode = int(status)
			result.Response = true
		}
		if headers, ok := out["headers"].(map[string]interface{}); ok {
			for k, v := range headers {
				result.Headers[k] = fmt.Sprint(v)
			}
		}
		if body, ok := out["body"].(string); ok {
			result.Body = []byte(body)
		}
	}

	return result
}

// executeFetch executes a fetch-style handler.
func (r *Runtime) executeFetch(ctx context.Context, fn *Function, execCtx *ExecutionContext) *ExecutionResult {
	// Fetch handlers work like service workers
	return r.executeScript(ctx, fn, execCtx)
}

// executeWASM executes a WebAssembly module.
func (r *Runtime) executeWASM(ctx context.Context, fn *Function, execCtx *ExecutionContext) *ExecutionResult {
	result := &ExecutionResult{
		Headers: make(map[string]string),
	}

	// WASM execution would use wazero runtime
	// For now, return a placeholder
	result.Error = errors.New("WASM execution not yet implemented")
	return result
}

// MatchFunctions returns functions matching a request.
func (r *Runtime) MatchFunctions(req *http.Request) []*Function {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []*Function

	for _, fn := range r.functions {
		if !fn.Enabled {
			continue
		}

		for _, trigger := range fn.Triggers {
			if trigger.Type == TriggerTypePath && matchesTrigger(req, trigger) {
				matches = append(matches, fn)
				break
			}
		}
	}

	return matches
}

// matchesTrigger checks if a request matches a trigger.
func matchesTrigger(req *http.Request, trigger Trigger) bool {
	// Check method
	if len(trigger.Methods) > 0 {
		matched := false
		for _, m := range trigger.Methods {
			if strings.EqualFold(m, req.Method) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check path
	if trigger.Path != "" {
		return matchPath(req.URL.Path, trigger.Path)
	}

	return true
}

// matchPath matches a URL path against a pattern.
func matchPath(path, pattern string) bool {
	// Convert glob pattern to regex
	regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	matched, _ := regexp.MatchString(regexPattern, path)
	return matched
}

// requestToMap converts an HTTP request to a map for scripting.
func requestToMap(req *http.Request) map[string]interface{} {
	headers := make(map[string]interface{})
	for k, v := range req.Header {
		if len(v) == 1 {
			headers[k] = v[0]
		} else {
			headers[k] = v
		}
	}

	query := make(map[string]interface{})
	for k, v := range req.URL.Query() {
		if len(v) == 1 {
			query[k] = v[0]
		} else {
			query[k] = v
		}
	}

	var body interface{}
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Try to parse as JSON
		var jsonBody interface{}
		if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
			body = jsonBody
		} else {
			body = string(bodyBytes)
		}
	}

	return map[string]interface{}{
		"method":  req.Method,
		"url":     req.URL.String(),
		"path":    req.URL.Path,
		"host":    req.Host,
		"headers": headers,
		"query":   query,
		"body":    body,
	}
}

// ScriptInterpreter executes simple JavaScript-like scripts.
type ScriptInterpreter struct {
	variables map[string]interface{}
	logs      []string
}

// NewScriptInterpreter creates a new script interpreter.
func NewScriptInterpreter() *ScriptInterpreter {
	return &ScriptInterpreter{
		variables: make(map[string]interface{}),
		logs:      make([]string, 0),
	}
}

// SetVariable sets a variable in the interpreter.
func (i *ScriptInterpreter) SetVariable(name string, value interface{}) {
	i.variables[name] = value
}

// GetLogs returns logs from script execution.
func (i *ScriptInterpreter) GetLogs() []string {
	return i.logs
}

// Execute executes a script and returns the result.
func (i *ScriptInterpreter) Execute(ctx context.Context, code string) (interface{}, error) {
	// This is a simplified script interpreter for edge functions
	// It supports basic operations like:
	// - Variable access: request.method, env.API_KEY
	// - Conditionals: if request.method == "GET" { ... }
	// - Return statements: return { status: 200, body: "Hello" }
	// - Console.log: console.log("message")

	parser := &ScriptParser{
		code:      code,
		variables: i.variables,
		logs:      &i.logs,
	}

	return parser.Parse(ctx)
}

// ScriptParser parses and executes scripts.
type ScriptParser struct {
	code      string
	pos       int
	variables map[string]interface{}
	logs      *[]string
}

// Parse parses and executes the script.
func (p *ScriptParser) Parse(ctx context.Context) (interface{}, error) {
	p.skipWhitespace()

	// Look for return statement
	if strings.HasPrefix(p.code[p.pos:], "return") {
		p.pos += 6
		p.skipWhitespace()
		return p.parseValue()
	}

	// Parse statements
	for p.pos < len(p.code) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		p.skipWhitespace()
		if p.pos >= len(p.code) {
			break
		}

		// Check for console.log
		if strings.HasPrefix(p.code[p.pos:], "console.log") {
			if err := p.parseConsoleLog(); err != nil {
				return nil, err
			}
			continue
		}

		// Check for if statement
		if strings.HasPrefix(p.code[p.pos:], "if") {
			result, returned, err := p.parseIf()
			if err != nil {
				return nil, err
			}
			if returned {
				return result, nil
			}
			continue
		}

		// Check for return
		if strings.HasPrefix(p.code[p.pos:], "return") {
			p.pos += 6
			p.skipWhitespace()
			return p.parseValue()
		}

		// Skip unknown statement
		for p.pos < len(p.code) && p.code[p.pos] != ';' && p.code[p.pos] != '\n' {
			p.pos++
		}
		p.pos++
	}

	return nil, nil
}

// skipWhitespace skips whitespace and comments.
func (p *ScriptParser) skipWhitespace() {
	for p.pos < len(p.code) {
		c := p.code[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' {
			p.pos++
		} else if p.pos+1 < len(p.code) && p.code[p.pos:p.pos+2] == "//" {
			// Skip line comment
			for p.pos < len(p.code) && p.code[p.pos] != '\n' {
				p.pos++
			}
		} else {
			break
		}
	}
}

// parseValue parses a value expression.
func (p *ScriptParser) parseValue() (interface{}, error) {
	p.skipWhitespace()

	if p.pos >= len(p.code) {
		return nil, nil
	}

	c := p.code[p.pos]

	// Object literal
	if c == '{' {
		return p.parseObject()
	}

	// Array literal
	if c == '[' {
		return p.parseArray()
	}

	// String literal
	if c == '"' || c == '\'' {
		return p.parseString()
	}

	// Number
	if c >= '0' && c <= '9' || c == '-' {
		return p.parseNumber()
	}

	// Boolean or null
	if strings.HasPrefix(p.code[p.pos:], "true") {
		p.pos += 4
		return true, nil
	}
	if strings.HasPrefix(p.code[p.pos:], "false") {
		p.pos += 5
		return false, nil
	}
	if strings.HasPrefix(p.code[p.pos:], "null") {
		p.pos += 4
		return nil, nil
	}

	// Variable reference
	return p.parseVariable()
}

// parseObject parses an object literal.
func (p *ScriptParser) parseObject() (map[string]interface{}, error) {
	p.pos++ // Skip {
	result := make(map[string]interface{})

	for {
		p.skipWhitespace()
		if p.pos >= len(p.code) {
			return nil, errors.New("unexpected end of object")
		}
		if p.code[p.pos] == '}' {
			p.pos++
			break
		}

		// Parse key
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}

		p.skipWhitespace()
		if p.pos >= len(p.code) || p.code[p.pos] != ':' {
			return nil, errors.New("expected : after key")
		}
		p.pos++

		// Parse value
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}

		result[key] = value

		p.skipWhitespace()
		if p.pos < len(p.code) && p.code[p.pos] == ',' {
			p.pos++
		}
	}

	return result, nil
}

// parseArray parses an array literal.
func (p *ScriptParser) parseArray() ([]interface{}, error) {
	p.pos++ // Skip [
	var result []interface{}

	for {
		p.skipWhitespace()
		if p.pos >= len(p.code) {
			return nil, errors.New("unexpected end of array")
		}
		if p.code[p.pos] == ']' {
			p.pos++
			break
		}

		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}

		result = append(result, value)

		p.skipWhitespace()
		if p.pos < len(p.code) && p.code[p.pos] == ',' {
			p.pos++
		}
	}

	return result, nil
}

// parseKey parses an object key.
func (p *ScriptParser) parseKey() (string, error) {
	p.skipWhitespace()

	if p.code[p.pos] == '"' || p.code[p.pos] == '\'' {
		return p.parseString()
	}

	// Unquoted key
	start := p.pos
	for p.pos < len(p.code) {
		c := p.code[p.pos]
		if c == ':' || c == ' ' || c == '\t' {
			break
		}
		p.pos++
	}

	return p.code[start:p.pos], nil
}

// parseString parses a string literal.
func (p *ScriptParser) parseString() (string, error) {
	quote := p.code[p.pos]
	p.pos++

	start := p.pos
	for p.pos < len(p.code) && p.code[p.pos] != quote {
		if p.code[p.pos] == '\\' && p.pos+1 < len(p.code) {
			p.pos += 2
		} else {
			p.pos++
		}
	}

	result := p.code[start:p.pos]
	if p.pos < len(p.code) {
		p.pos++ // Skip closing quote
	}

	return result, nil
}

// parseNumber parses a number.
func (p *ScriptParser) parseNumber() (float64, error) {
	start := p.pos

	if p.code[p.pos] == '-' {
		p.pos++
	}

	for p.pos < len(p.code) {
		c := p.code[p.pos]
		if (c >= '0' && c <= '9') || c == '.' {
			p.pos++
		} else {
			break
		}
	}

	return strconv.ParseFloat(p.code[start:p.pos], 64)
}

// parseVariable parses a variable reference.
func (p *ScriptParser) parseVariable() (interface{}, error) {
	start := p.pos

	for p.pos < len(p.code) {
		c := p.code[p.pos]
		if c == '.' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.pos++
		} else {
			break
		}
	}

	path := p.code[start:p.pos]
	return p.resolveVariable(path)
}

// resolveVariable resolves a dotted variable path.
func (p *ScriptParser) resolveVariable(path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil, nil
	}

	current, ok := p.variables[parts[0]]
	if !ok {
		return nil, nil
	}

	for _, part := range parts[1:] {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case map[string]string:
			current = v[part]
		default:
			return nil, nil
		}
	}

	return current, nil
}

// parseConsoleLog parses and executes console.log.
func (p *ScriptParser) parseConsoleLog() error {
	p.pos += 11 // Skip "console.log"
	p.skipWhitespace()

	if p.pos >= len(p.code) || p.code[p.pos] != '(' {
		return errors.New("expected ( after console.log")
	}
	p.pos++

	value, err := p.parseValue()
	if err != nil {
		return err
	}

	*p.logs = append(*p.logs, fmt.Sprint(value))

	p.skipWhitespace()
	if p.pos < len(p.code) && p.code[p.pos] == ')' {
		p.pos++
	}

	return nil
}

// parseIf parses an if statement.
func (p *ScriptParser) parseIf() (interface{}, bool, error) {
	p.pos += 2 // Skip "if"
	p.skipWhitespace()

	// Parse condition
	condition, err := p.parseCondition()
	if err != nil {
		return nil, false, err
	}

	p.skipWhitespace()

	// Parse block
	if p.pos >= len(p.code) || p.code[p.pos] != '{' {
		return nil, false, errors.New("expected { after if condition")
	}
	p.pos++

	// Find matching }
	depth := 1
	start := p.pos
	for p.pos < len(p.code) && depth > 0 {
		if p.code[p.pos] == '{' {
			depth++
		} else if p.code[p.pos] == '}' {
			depth--
		}
		if depth > 0 {
			p.pos++
		}
	}
	blockCode := p.code[start:p.pos]
	p.pos++ // Skip }

	if condition {
		// Execute block
		blockParser := &ScriptParser{
			code:      blockCode,
			variables: p.variables,
			logs:      p.logs,
		}
		result, err := blockParser.Parse(context.Background())
		if err != nil {
			return nil, false, err
		}
		if result != nil {
			return result, true, nil
		}
	}

	return nil, false, nil
}

// parseCondition parses a simple condition.
func (p *ScriptParser) parseCondition() (bool, error) {
	p.skipWhitespace()

	// Get left operand
	left, err := p.parseValue()
	if err != nil {
		return false, err
	}

	p.skipWhitespace()

	// Check for operator
	if p.pos+1 < len(p.code) && p.code[p.pos:p.pos+2] == "==" {
		p.pos += 2
		p.skipWhitespace()
		right, err := p.parseValue()
		if err != nil {
			return false, err
		}
		return fmt.Sprint(left) == fmt.Sprint(right), nil
	}

	if p.pos+1 < len(p.code) && p.code[p.pos:p.pos+2] == "!=" {
		p.pos += 2
		p.skipWhitespace()
		right, err := p.parseValue()
		if err != nil {
			return false, err
		}
		return fmt.Sprint(left) != fmt.Sprint(right), nil
	}

	// Truthy check
	return left != nil && left != false && left != 0 && left != "", nil
}

// Stats returns runtime statistics.
func (r *Runtime) Stats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	avgTime := int64(0)
	if r.execCount > 0 {
		avgTime = r.execTimeNs / r.execCount
	}

	return map[string]interface{}{
		"function_count": len(r.functions),
		"exec_count":     r.execCount,
		"exec_errors":    r.execErrors,
		"avg_exec_ns":    avgTime,
	}
}
