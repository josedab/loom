// Package policy provides CEL-based policy evaluation.
package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
)

// CELEvaluator evaluates policies using the Common Expression Language (CEL).
type CELEvaluator struct {
	env      *cel.Env
	policies map[string]cel.Program
	mu       sync.RWMutex
	logger   *slog.Logger
}

// CELEvaluatorConfig configures the CEL evaluator.
type CELEvaluatorConfig struct {
	// Policies maps policy names to CEL expressions.
	Policies map[string]string
	// Logger for evaluation events.
	Logger *slog.Logger
}

// NewCELEvaluator creates a new CEL evaluator with the given configuration.
func NewCELEvaluator(cfg CELEvaluatorConfig) (*CELEvaluator, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Create CEL environment with input variable declarations
	env, err := cel.NewEnv(
		cel.Declarations(
			// Request variables
			decls.NewVar("request.method", decls.String),
			decls.NewVar("request.path", decls.String),
			decls.NewVar("request.host", decls.String),
			decls.NewVar("request.remote_addr", decls.String),
			decls.NewVar("request.headers", decls.NewMapType(decls.String, decls.String)),
			decls.NewVar("request.query", decls.NewMapType(decls.String, decls.NewListType(decls.String))),

			// User variables
			decls.NewVar("user.id", decls.String),
			decls.NewVar("user.username", decls.String),
			decls.NewVar("user.roles", decls.NewListType(decls.String)),
			decls.NewVar("user.groups", decls.NewListType(decls.String)),
			decls.NewVar("user.claims", decls.NewMapType(decls.String, decls.Dyn)),

			// Resource variables
			decls.NewVar("resource.type", decls.String),
			decls.NewVar("resource.id", decls.String),
			decls.NewVar("resource.owner", decls.String),
			decls.NewVar("resource.labels", decls.NewMapType(decls.String, decls.String)),

			// Context variables
			decls.NewVar("context", decls.NewMapType(decls.String, decls.Dyn)),

			// Helper variables
			decls.NewVar("now", decls.Timestamp),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	evaluator := &CELEvaluator{
		env:      env,
		policies: make(map[string]cel.Program),
		logger:   cfg.Logger,
	}

	// Compile policies
	for name, expr := range cfg.Policies {
		if err := evaluator.AddPolicy(name, expr); err != nil {
			return nil, fmt.Errorf("failed to compile policy %q: %w", name, err)
		}
	}

	return evaluator, nil
}

// AddPolicy adds or updates a CEL policy.
func (e *CELEvaluator) AddPolicy(name, expression string) error {
	// Parse the expression
	ast, issues := e.env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("parse error: %w", issues.Err())
	}

	// Type-check the expression
	checked, issues := e.env.Check(ast)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("type-check error: %w", issues.Err())
	}

	// Compile the expression
	program, err := e.env.Program(checked)
	if err != nil {
		return fmt.Errorf("compile error: %w", err)
	}

	e.mu.Lock()
	e.policies[name] = program
	e.mu.Unlock()

	e.logger.Info("CEL policy compiled",
		"policy", name,
		"expression", expression,
	)

	return nil
}

// RemovePolicy removes a CEL policy.
func (e *CELEvaluator) RemovePolicy(name string) {
	e.mu.Lock()
	delete(e.policies, name)
	e.mu.Unlock()
}

// GetPolicies returns the names of all loaded policies.
func (e *CELEvaluator) GetPolicies() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// Evaluate evaluates a policy with the given input.
func (e *CELEvaluator) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	e.mu.RLock()
	program, ok := e.policies[policy]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policy)
	}

	// Build activation (variables for CEL evaluation)
	activation := e.buildActivation(input)

	// Evaluate the expression
	result, _, err := program.Eval(activation)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	// Convert result to decision
	decision := &Decision{
		EvaluatedAt: time.Now(),
	}

	// Handle different result types
	switch v := result.Value().(type) {
	case bool:
		decision.Allowed = v
		if v {
			decision.Reason = "policy allowed"
		} else {
			decision.Reason = "policy denied"
		}
	case map[string]interface{}:
		// Structured response with allowed and reason
		if allowed, ok := v["allowed"].(bool); ok {
			decision.Allowed = allowed
		}
		if reason, ok := v["reason"].(string); ok {
			decision.Reason = reason
		}
		if metadata, ok := v["metadata"].(map[string]interface{}); ok {
			decision.Metadata = metadata
		}
	default:
		return nil, fmt.Errorf("unexpected result type: %T", result.Value())
	}

	e.logger.Debug("CEL policy evaluated",
		"policy", policy,
		"allowed", decision.Allowed,
		"reason", decision.Reason,
	)

	return decision, nil
}

// buildActivation creates a CEL activation from the policy input.
func (e *CELEvaluator) buildActivation(input *Input) map[string]interface{} {
	activation := make(map[string]interface{})

	// Request variables
	activation["request.method"] = input.Request.Method
	activation["request.path"] = input.Request.Path
	activation["request.host"] = input.Request.Host
	activation["request.remote_addr"] = input.Request.RemoteAddr

	headers := make(map[string]string)
	if input.Request.Headers != nil {
		headers = input.Request.Headers
	}
	activation["request.headers"] = headers

	query := make(map[string][]string)
	if input.Request.Query != nil {
		query = input.Request.Query
	}
	activation["request.query"] = query

	// User variables (with defaults for nil)
	if input.User != nil {
		activation["user.id"] = input.User.ID
		activation["user.username"] = input.User.Username
		activation["user.roles"] = input.User.Roles
		activation["user.groups"] = input.User.Groups
		claims := make(map[string]interface{})
		if input.User.Claims != nil {
			claims = input.User.Claims
		}
		activation["user.claims"] = claims
	} else {
		activation["user.id"] = ""
		activation["user.username"] = ""
		activation["user.roles"] = []string{}
		activation["user.groups"] = []string{}
		activation["user.claims"] = map[string]interface{}{}
	}

	// Resource variables (with defaults for nil)
	if input.Resource != nil {
		activation["resource.type"] = input.Resource.Type
		activation["resource.id"] = input.Resource.ID
		activation["resource.owner"] = input.Resource.Owner
		labels := make(map[string]string)
		if input.Resource.Labels != nil {
			labels = input.Resource.Labels
		}
		activation["resource.labels"] = labels
	} else {
		activation["resource.type"] = ""
		activation["resource.id"] = ""
		activation["resource.owner"] = ""
		activation["resource.labels"] = map[string]string{}
	}

	// Context variables
	ctx := make(map[string]interface{})
	if input.Context != nil {
		ctx = input.Context
	}
	activation["context"] = ctx

	// Helper variables
	activation["now"] = time.Now()

	return activation
}

// ValidateExpression validates a CEL expression without adding it as a policy.
func (e *CELEvaluator) ValidateExpression(expression string) error {
	// Parse the expression
	ast, issues := e.env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("parse error: %w", issues.Err())
	}

	// Type-check the expression
	_, issues = e.env.Check(ast)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("type-check error: %w", issues.Err())
	}

	return nil
}

// CELPolicyConfig holds a single CEL policy configuration.
type CELPolicyConfig struct {
	Name        string `json:"name" yaml:"name"`
	Expression  string `json:"expression" yaml:"expression"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}
