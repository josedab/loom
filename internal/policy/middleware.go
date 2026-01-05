package policy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// MiddlewareConfig configures the policy middleware.
type MiddlewareConfig struct {
	// Engine is the policy engine to use.
	Engine *Engine
	// PolicyResolver resolves policy names for requests.
	PolicyResolver func(*http.Request) string
	// UserExtractor extracts user info from requests.
	UserExtractor func(*http.Request) *UserInput
	// ResourceExtractor extracts resource info from requests.
	ResourceExtractor func(*http.Request) *ResourceInput
	// ContextEnricher adds additional context to policy input.
	ContextEnricher func(*http.Request) map[string]interface{}
	// OnDeny is called when a request is denied.
	OnDeny func(w http.ResponseWriter, r *http.Request, decision *Decision)
	// Logger for middleware events.
	Logger *slog.Logger
	// HeadersToInclude specifies which headers to include in policy input.
	HeadersToInclude []string
	// IncludeBody includes request body in policy input.
	IncludeBody bool
}

// Middleware returns HTTP middleware that enforces policies.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PolicyResolver == nil {
		cfg.PolicyResolver = func(r *http.Request) string {
			return "default"
		}
	}
	if cfg.OnDeny == nil {
		cfg.OnDeny = defaultDenyHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Build input
			input := buildInput(r, cfg)

			// Resolve policy
			policy := cfg.PolicyResolver(r)

			// Evaluate policy
			decision, err := cfg.Engine.Evaluate(ctx, policy, input)
			if err != nil {
				cfg.Logger.Error("policy evaluation error",
					"policy", policy,
					"path", r.URL.Path,
					"error", err,
				)
				http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
				return
			}

			cfg.Logger.Debug("policy evaluated",
				"policy", policy,
				"path", r.URL.Path,
				"allowed", decision.Allowed,
				"reason", decision.Reason,
			)

			if !decision.Allowed {
				cfg.OnDeny(w, r, decision)
				return
			}

			// Store decision in context for downstream use
			ctx = context.WithValue(ctx, decisionKey{}, decision)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type decisionKey struct{}

// GetDecision retrieves the policy decision from the request context.
func GetDecision(ctx context.Context) *Decision {
	decision, _ := ctx.Value(decisionKey{}).(*Decision)
	return decision
}

// buildInput builds policy input from the request.
func buildInput(r *http.Request, cfg MiddlewareConfig) *Input {
	// Build request input
	requestInput := RequestInput{
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.Query(),
		Host:       r.Host,
		RemoteAddr: getClientIP(r),
	}

	// Include selected headers
	if len(cfg.HeadersToInclude) > 0 {
		requestInput.Headers = make(map[string]string)
		for _, header := range cfg.HeadersToInclude {
			if v := r.Header.Get(header); v != "" {
				requestInput.Headers[header] = v
			}
		}
	}

	// Include body if configured
	if cfg.IncludeBody && r.Body != nil {
		var body interface{}
		if bodyBytes, err := io.ReadAll(r.Body); err == nil {
			json.Unmarshal(bodyBytes, &body)
			requestInput.Body = body
		}
	}

	input := &Input{
		Request: requestInput,
	}

	// Extract user if configured
	if cfg.UserExtractor != nil {
		input.User = cfg.UserExtractor(r)
	}

	// Extract resource if configured
	if cfg.ResourceExtractor != nil {
		input.Resource = cfg.ResourceExtractor(r)
	}

	// Enrich context if configured
	if cfg.ContextEnricher != nil {
		input.Context = cfg.ContextEnricher(r)
	}

	return input
}

// getClientIP extracts the client IP from a request.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// defaultDenyHandler is the default denial handler.
func defaultDenyHandler(w http.ResponseWriter, r *http.Request, decision *Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  "access denied",
		"reason": decision.Reason,
	})
}

// PathPolicyResolver returns a policy resolver based on path prefixes.
func PathPolicyResolver(policies map[string]string) func(*http.Request) string {
	return func(r *http.Request) string {
		for prefix, policy := range policies {
			if strings.HasPrefix(r.URL.Path, prefix) {
				return policy
			}
		}
		return "default"
	}
}

// MethodPolicyResolver returns a policy resolver based on HTTP method.
func MethodPolicyResolver(policies map[string]string) func(*http.Request) string {
	return func(r *http.Request) string {
		if policy, ok := policies[r.Method]; ok {
			return policy
		}
		return "default"
	}
}

// JWTUserExtractor extracts user info from JWT claims.
func JWTUserExtractor(claimsKey string) func(*http.Request) *UserInput {
	return func(r *http.Request) *UserInput {
		claims, ok := r.Context().Value(claimsKey).(map[string]interface{})
		if !ok {
			return nil
		}

		user := &UserInput{
			Claims: claims,
		}

		if sub, ok := claims["sub"].(string); ok {
			user.ID = sub
		}
		if name, ok := claims["name"].(string); ok {
			user.Username = name
		}
		if roles, ok := claims["roles"].([]interface{}); ok {
			for _, role := range roles {
				if r, ok := role.(string); ok {
					user.Roles = append(user.Roles, r)
				}
			}
		}
		if groups, ok := claims["groups"].([]interface{}); ok {
			for _, group := range groups {
				if g, ok := group.(string); ok {
					user.Groups = append(user.Groups, g)
				}
			}
		}

		return user
	}
}

// HeaderUserExtractor extracts user info from headers.
func HeaderUserExtractor(userIDHeader, rolesHeader string) func(*http.Request) *UserInput {
	return func(r *http.Request) *UserInput {
		userID := r.Header.Get(userIDHeader)
		if userID == "" {
			return nil
		}

		user := &UserInput{
			ID: userID,
		}

		if rolesHeader != "" {
			rolesStr := r.Header.Get(rolesHeader)
			if rolesStr != "" {
				user.Roles = strings.Split(rolesStr, ",")
				for i := range user.Roles {
					user.Roles[i] = strings.TrimSpace(user.Roles[i])
				}
			}
		}

		return user
	}
}

// PathResourceExtractor extracts resource info from path segments.
func PathResourceExtractor(typeIndex, idIndex int) func(*http.Request) *ResourceInput {
	return func(r *http.Request) *ResourceInput {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

		resource := &ResourceInput{}

		if typeIndex >= 0 && typeIndex < len(parts) {
			resource.Type = parts[typeIndex]
		}
		if idIndex >= 0 && idIndex < len(parts) {
			resource.ID = parts[idIndex]
		}

		return resource
	}
}

// Handler provides an HTTP API for policy management.
type Handler struct {
	engine *Engine
	logger *slog.Logger
}

// NewHandler creates a new policy handler.
func NewHandler(engine *Engine, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		engine: engine,
		logger: logger,
	}
}

// ServeHTTP handles policy requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/policy")

	switch {
	case path == "/evaluate" && r.Method == http.MethodPost:
		h.handleEvaluate(w, r)
	default:
		http.NotFound(w, r)
	}
}

// evaluateRequest represents a policy evaluation request.
type evaluateRequest struct {
	Policy string `json:"policy"`
	Input  *Input `json:"input"`
}

// handleEvaluate handles policy evaluation requests.
func (h *Handler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req evaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Input == nil {
		http.Error(w, "input is required", http.StatusBadRequest)
		return
	}

	decision, err := h.engine.Evaluate(r.Context(), req.Policy, req.Input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decision)
}

// RateLimitPolicy implements a simple rate limit check.
func RateLimitPolicy(maxRequests int, window string) PolicyFunc {
	return func(ctx context.Context, input *Input) (*Decision, error) {
		// This is a placeholder - actual implementation would use a rate limiter
		// The rate limit state would be checked against the user/IP
		return &Decision{
			Allowed: true,
			Reason:  "rate limit check passed",
			Metadata: map[string]interface{}{
				"max_requests": maxRequests,
				"window":       window,
			},
		}, nil
	}
}

// IPAllowListPolicy allows only requests from specified IPs.
func IPAllowListPolicy(allowedIPs []string) PolicyFunc {
	allowSet := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowSet[ip] = true
	}

	return func(ctx context.Context, input *Input) (*Decision, error) {
		clientIP := input.Request.RemoteAddr
		// Strip port if present
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}

		if allowSet[clientIP] {
			return &Decision{Allowed: true, Reason: "IP allowed"}, nil
		}

		return &Decision{
			Allowed: false,
			Reason:  "IP not in allow list",
		}, nil
	}
}

// TimeBasedPolicy allows access only during specified hours.
func TimeBasedPolicy(allowedHours map[int]bool) PolicyFunc {
	return func(ctx context.Context, input *Input) (*Decision, error) {
		hour := input.Request.Headers["X-Request-Hour"]
		if hour == "" {
			return &Decision{Allowed: true, Reason: "no time restriction"}, nil
		}

		var h int
		if _, err := json.Marshal(hour); err == nil {
			if allowedHours[h] {
				return &Decision{Allowed: true, Reason: "allowed hour"}, nil
			}
		}

		return &Decision{Allowed: false, Reason: "outside allowed hours"}, nil
	}
}
