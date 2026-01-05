// Package policy provides policy-based access control using Open Policy Agent (OPA).
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Decision represents a policy decision.
type Decision struct {
	Allowed    bool                   `json:"allowed"`
	Reason     string                 `json:"reason,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
}

// Input represents the input to a policy evaluation.
type Input struct {
	Request  RequestInput           `json:"request"`
	User     *UserInput             `json:"user,omitempty"`
	Resource *ResourceInput         `json:"resource,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// RequestInput contains HTTP request information.
type RequestInput struct {
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Query      map[string][]string `json:"query,omitempty"`
	Headers    map[string]string   `json:"headers,omitempty"`
	Host       string              `json:"host,omitempty"`
	RemoteAddr string              `json:"remote_addr,omitempty"`
	Body       interface{}         `json:"body,omitempty"`
}

// UserInput contains user/identity information.
type UserInput struct {
	ID       string   `json:"id,omitempty"`
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
}

// ResourceInput contains resource information.
type ResourceInput struct {
	Type   string                 `json:"type,omitempty"`
	ID     string                 `json:"id,omitempty"`
	Owner  string                 `json:"owner,omitempty"`
	Labels map[string]string      `json:"labels,omitempty"`
	Attrs  map[string]interface{} `json:"attrs,omitempty"`
}

// Engine is the policy evaluation engine.
type Engine struct {
	evaluator Evaluator
	cache     *DecisionCache
	config    EngineConfig
	logger    *slog.Logger
	mu        sync.RWMutex
}

// EngineConfig configures the policy engine.
type EngineConfig struct {
	// DefaultPolicy is the default policy when none is specified.
	DefaultPolicy string
	// CacheTTL is the cache duration for decisions.
	CacheTTL time.Duration
	// CacheSize is the maximum number of cached decisions.
	CacheSize int
	// FailOpen determines if requests are allowed when evaluation fails.
	FailOpen bool
	// Logger for policy engine events.
	Logger *slog.Logger
}

// NewEngine creates a new policy engine.
func NewEngine(evaluator Evaluator, cfg EngineConfig) *Engine {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.CacheSize == 0 {
		cfg.CacheSize = 10000
	}

	return &Engine{
		evaluator: evaluator,
		cache:     NewDecisionCache(cfg.CacheSize, cfg.CacheTTL),
		config:    cfg,
		logger:    cfg.Logger,
	}
}

// Evaluate evaluates a policy with the given input.
func (e *Engine) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	if policy == "" {
		policy = e.config.DefaultPolicy
	}

	// Check cache
	cacheKey := e.cacheKey(policy, input)
	if decision := e.cache.Get(cacheKey); decision != nil {
		return decision, nil
	}

	// Evaluate policy
	decision, err := e.evaluator.Evaluate(ctx, policy, input)
	if err != nil {
		e.logger.Error("policy evaluation failed",
			"policy", policy,
			"error", err,
		)
		if e.config.FailOpen {
			return &Decision{
				Allowed:     true,
				Reason:      "fail-open: evaluation error",
				EvaluatedAt: time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	decision.EvaluatedAt = time.Now()

	// Cache decision
	e.cache.Set(cacheKey, decision)

	return decision, nil
}

// cacheKey generates a cache key for the policy and input.
func (e *Engine) cacheKey(policy string, input *Input) string {
	data, _ := json.Marshal(input)
	return fmt.Sprintf("%s:%x", policy, data[:min(100, len(data))])
}

// Evaluator is the interface for policy evaluators.
type Evaluator interface {
	// Evaluate evaluates a policy with the given input.
	Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error)
}

// OPAEvaluator evaluates policies using an OPA server.
type OPAEvaluator struct {
	serverURL  string
	httpClient *http.Client
	logger     *slog.Logger
}

// OPAConfig configures the OPA evaluator.
type OPAConfig struct {
	// ServerURL is the OPA server URL.
	ServerURL string
	// Timeout is the HTTP request timeout.
	Timeout time.Duration
	// Logger for OPA evaluator events.
	Logger *slog.Logger
}

// NewOPAEvaluator creates a new OPA evaluator.
func NewOPAEvaluator(cfg OPAConfig) *OPAEvaluator {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "http://localhost:8181"
	}

	return &OPAEvaluator{
		serverURL:  strings.TrimSuffix(cfg.ServerURL, "/"),
		httpClient: &http.Client{Timeout: cfg.Timeout},
		logger:     cfg.Logger,
	}
}

// opaRequest represents an OPA query request.
type opaRequest struct {
	Input interface{} `json:"input"`
}

// opaResponse represents an OPA query response.
type opaResponse struct {
	Result interface{} `json:"result"`
}

// Evaluate evaluates a policy using the OPA server.
func (e *OPAEvaluator) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	// Build URL: /v1/data/{policy}
	url := fmt.Sprintf("%s/v1/data/%s", e.serverURL, strings.ReplaceAll(policy, ".", "/"))

	reqBody, err := json.Marshal(opaRequest{Input: input})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OPA returned %d: %s", resp.StatusCode, string(body))
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return e.parseResult(opaResp.Result)
}

// parseResult parses OPA result into a Decision.
func (e *OPAEvaluator) parseResult(result interface{}) (*Decision, error) {
	if result == nil {
		return &Decision{Allowed: false, Reason: "policy returned no result"}, nil
	}

	switch v := result.(type) {
	case bool:
		return &Decision{Allowed: v}, nil
	case map[string]interface{}:
		decision := &Decision{Metadata: v}

		if allowed, ok := v["allow"].(bool); ok {
			decision.Allowed = allowed
		} else if allowed, ok := v["allowed"].(bool); ok {
			decision.Allowed = allowed
		}

		if reason, ok := v["reason"].(string); ok {
			decision.Reason = reason
		}
		if msg, ok := v["message"].(string); ok {
			decision.Reason = msg
		}

		return decision, nil
	default:
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
}

// LocalEvaluator evaluates policies using local Rego.
type LocalEvaluator struct {
	policies map[string]PolicyFunc
	mu       sync.RWMutex
	logger   *slog.Logger
}

// PolicyFunc is a function that evaluates a policy.
type PolicyFunc func(ctx context.Context, input *Input) (*Decision, error)

// NewLocalEvaluator creates a new local policy evaluator.
func NewLocalEvaluator(logger *slog.Logger) *LocalEvaluator {
	if logger == nil {
		logger = slog.Default()
	}
	return &LocalEvaluator{
		policies: make(map[string]PolicyFunc),
		logger:   logger,
	}
}

// RegisterPolicy registers a policy function.
func (e *LocalEvaluator) RegisterPolicy(name string, fn PolicyFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[name] = fn
}

// Evaluate evaluates a policy locally.
func (e *LocalEvaluator) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	e.mu.RLock()
	fn, ok := e.policies[policy]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policy)
	}

	return fn(ctx, input)
}

// ChainEvaluator chains multiple evaluators together.
type ChainEvaluator struct {
	evaluators []Evaluator
	logger     *slog.Logger
}

// NewChainEvaluator creates a new chain evaluator.
func NewChainEvaluator(evaluators ...Evaluator) *ChainEvaluator {
	return &ChainEvaluator{
		evaluators: evaluators,
		logger:     slog.Default(),
	}
}

// Evaluate tries each evaluator in order until one succeeds.
func (e *ChainEvaluator) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	var lastErr error

	for _, evaluator := range e.evaluators {
		decision, err := evaluator.Evaluate(ctx, policy, input)
		if err == nil {
			return decision, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all evaluators failed: %w", lastErr)
}

// DecisionCache caches policy decisions.
type DecisionCache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	maxSize int
	mu      sync.RWMutex
}

type cacheEntry struct {
	decision  *Decision
	expiresAt time.Time
}

// NewDecisionCache creates a new decision cache.
func NewDecisionCache(maxSize int, ttl time.Duration) *DecisionCache {
	cache := &DecisionCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached decision.
func (c *DecisionCache) Get(key string) *Decision {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.decision
}

// Set caches a decision.
func (c *DecisionCache) Set(key string, decision *Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[key] = &cacheEntry{
		decision:  decision,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// evict removes expired entries.
func (c *DecisionCache) evict() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}

	// If still at capacity, remove oldest
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time

		for key, entry := range c.entries {
			if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.expiresAt
			}
		}

		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
}

// cleanup periodically removes expired entries.
func (c *DecisionCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		c.evict()
		c.mu.Unlock()
	}
}

// BuiltinPolicies provides commonly used policy functions.
var BuiltinPolicies = map[string]PolicyFunc{
	"allow_all": func(ctx context.Context, input *Input) (*Decision, error) {
		return &Decision{Allowed: true, Reason: "allow all"}, nil
	},
	"deny_all": func(ctx context.Context, input *Input) (*Decision, error) {
		return &Decision{Allowed: false, Reason: "deny all"}, nil
	},
	"authenticated": func(ctx context.Context, input *Input) (*Decision, error) {
		if input.User == nil || input.User.ID == "" {
			return &Decision{Allowed: false, Reason: "authentication required"}, nil
		}
		return &Decision{Allowed: true}, nil
	},
	"rbac": RBACPolicy,
}

// RBACPolicy implements role-based access control.
func RBACPolicy(ctx context.Context, input *Input) (*Decision, error) {
	if input.User == nil {
		return &Decision{Allowed: false, Reason: "user required for RBAC"}, nil
	}

	// Check if user has required role
	requiredRole, ok := input.Context["required_role"].(string)
	if !ok {
		return &Decision{Allowed: true, Reason: "no role requirement"}, nil
	}

	for _, role := range input.User.Roles {
		if role == requiredRole || role == "admin" {
			return &Decision{Allowed: true, Reason: "role match"}, nil
		}
	}

	return &Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("requires role: %s", requiredRole),
	}, nil
}

// ABACPolicy implements attribute-based access control.
func ABACPolicy(rules []ABACRule) PolicyFunc {
	return func(ctx context.Context, input *Input) (*Decision, error) {
		for _, rule := range rules {
			if rule.Matches(input) {
				return &Decision{
					Allowed: rule.Effect == "allow",
					Reason:  rule.Name,
				}, nil
			}
		}
		return &Decision{Allowed: false, Reason: "no matching rule"}, nil
	}
}

// ABACRule represents an ABAC rule.
type ABACRule struct {
	Name       string                 `json:"name"`
	Effect     string                 `json:"effect"` // "allow" or "deny"
	Conditions map[string]interface{} `json:"conditions"`
}

// Matches checks if the rule matches the input.
func (r *ABACRule) Matches(input *Input) bool {
	for key, expected := range r.Conditions {
		actual := r.getField(input, key)
		if !r.matchValue(actual, expected) {
			return false
		}
	}
	return true
}

// getField gets a field value from input.
func (r *ABACRule) getField(input *Input, key string) interface{} {
	parts := strings.Split(key, ".")
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "request":
		if len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "method":
			return input.Request.Method
		case "path":
			return input.Request.Path
		case "host":
			return input.Request.Host
		}
	case "user":
		if input.User == nil || len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "id":
			return input.User.ID
		case "username":
			return input.User.Username
		case "roles":
			return input.User.Roles
		case "groups":
			return input.User.Groups
		}
	case "resource":
		if input.Resource == nil || len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "type":
			return input.Resource.Type
		case "id":
			return input.Resource.ID
		case "owner":
			return input.Resource.Owner
		}
	}

	return nil
}

// matchValue matches a value against expected.
func (r *ABACRule) matchValue(actual, expected interface{}) bool {
	switch exp := expected.(type) {
	case string:
		if strings.HasPrefix(exp, "in:") {
			values := strings.Split(strings.TrimPrefix(exp, "in:"), ",")
			actualStr, ok := actual.(string)
			if !ok {
				return false
			}
			for _, v := range values {
				if strings.TrimSpace(v) == actualStr {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(exp, "prefix:") {
			actualStr, ok := actual.(string)
			if !ok {
				return false
			}
			return strings.HasPrefix(actualStr, strings.TrimPrefix(exp, "prefix:"))
		}
		return actual == exp
	case []interface{}:
		// Check if actual contains any of expected
		actualSlice, ok := actual.([]string)
		if !ok {
			return false
		}
		for _, e := range exp {
			expStr, ok := e.(string)
			if !ok {
				continue
			}
			for _, a := range actualSlice {
				if a == expStr {
					return true
				}
			}
		}
		return false
	default:
		return actual == expected
	}
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
