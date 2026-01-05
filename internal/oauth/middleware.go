package oauth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// MiddlewareConfig configures the OAuth middleware.
type MiddlewareConfig struct {
	// Validator for JWT tokens.
	Validator *Validator
	// TokenExtractor extracts token from request.
	TokenExtractor TokenExtractor
	// OnError is called when authentication fails.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// SkipPaths are paths that don't require authentication.
	SkipPaths []string
	// RequiredScopes that must be present in token.
	RequiredScopes []string
	// RequiredRoles that must be present in token.
	RequiredRoles []string
	// Logger for middleware events.
	Logger *slog.Logger
}

// TokenExtractor extracts a token from a request.
type TokenExtractor func(*http.Request) string

// BearerTokenExtractor extracts Bearer token from Authorization header.
func BearerTokenExtractor(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

// QueryTokenExtractor extracts token from query parameter.
func QueryTokenExtractor(param string) TokenExtractor {
	return func(r *http.Request) string {
		return r.URL.Query().Get(param)
	}
}

// CookieTokenExtractor extracts token from cookie.
func CookieTokenExtractor(name string) TokenExtractor {
	return func(r *http.Request) string {
		cookie, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
}

// ChainedTokenExtractor tries multiple extractors in order.
func ChainedTokenExtractor(extractors ...TokenExtractor) TokenExtractor {
	return func(r *http.Request) string {
		for _, extractor := range extractors {
			if token := extractor(r); token != "" {
				return token
			}
		}
		return ""
	}
}

// Middleware returns HTTP middleware for OAuth authentication.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TokenExtractor == nil {
		cfg.TokenExtractor = BearerTokenExtractor
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check skip paths
			for _, path := range cfg.SkipPaths {
				if matchPath(path, r.URL.Path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract token
			tokenString := cfg.TokenExtractor(r)
			if tokenString == "" {
				cfg.OnError(w, r, ErrTokenMissing)
				return
			}

			// Validate token
			token, err := cfg.Validator.Validate(r.Context(), tokenString)
			if err != nil {
				cfg.Logger.Debug("token validation failed",
					"path", r.URL.Path,
					"error", err,
				)
				cfg.OnError(w, r, err)
				return
			}

			// Check required scopes
			for _, scope := range cfg.RequiredScopes {
				if !token.Claims.HasScope(scope) {
					cfg.Logger.Debug("missing required scope",
						"path", r.URL.Path,
						"scope", scope,
					)
					cfg.OnError(w, r, &ScopeError{Required: scope})
					return
				}
			}

			// Check required roles
			for _, role := range cfg.RequiredRoles {
				if !token.Claims.HasRole(role) {
					cfg.Logger.Debug("missing required role",
						"path", r.URL.Path,
						"role", role,
					)
					cfg.OnError(w, r, &RoleError{Required: role})
					return
				}
			}

			cfg.Logger.Debug("authentication successful",
				"path", r.URL.Path,
				"subject", token.Claims.Subject,
			)

			// Store token in context
			ctx := context.WithValue(r.Context(), tokenContextKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type tokenContextKey struct{}

// GetToken retrieves the validated token from context.
func GetToken(ctx context.Context) *Token {
	token, _ := ctx.Value(tokenContextKey{}).(*Token)
	return token
}

// GetClaims retrieves the claims from context.
func GetClaims(ctx context.Context) *Claims {
	token := GetToken(ctx)
	if token == nil {
		return nil
	}
	return &token.Claims
}

// ScopeError indicates a missing scope.
type ScopeError struct {
	Required string
}

func (e *ScopeError) Error() string {
	return "missing required scope: " + e.Required
}

// RoleError indicates a missing role.
type RoleError struct {
	Required string
}

func (e *RoleError) Error() string {
	return "missing required role: " + e.Required
}

// matchPath checks if a path matches a pattern.
func matchPath(pattern, path string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// defaultErrorHandler returns JSON error responses.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	var status int
	var message string

	switch {
	case err == ErrTokenMissing:
		status = http.StatusUnauthorized
		message = "authentication required"
		w.Header().Set("WWW-Authenticate", "Bearer")
	case err == ErrTokenExpired:
		status = http.StatusUnauthorized
		message = "token expired"
	case err == ErrTokenInvalid:
		status = http.StatusUnauthorized
		message = "invalid token"
	case err == ErrInvalidSignature:
		status = http.StatusUnauthorized
		message = "invalid token signature"
	case err == ErrIssuerMismatch:
		status = http.StatusUnauthorized
		message = "invalid token issuer"
	case err == ErrAudienceMismatch:
		status = http.StatusUnauthorized
		message = "invalid token audience"
	default:
		switch err.(type) {
		case *ScopeError:
			status = http.StatusForbidden
			message = "insufficient scope"
		case *RoleError:
			status = http.StatusForbidden
			message = "insufficient permissions"
		default:
			status = http.StatusUnauthorized
			message = "authentication failed"
		}
	}

	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   message,
		"details": err.Error(),
	})
}

// RequireScopes returns middleware that requires specific scopes.
func RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := GetToken(r.Context())
			if token == nil {
				defaultErrorHandler(w, r, ErrTokenMissing)
				return
			}

			for _, scope := range scopes {
				if !token.Claims.HasScope(scope) {
					defaultErrorHandler(w, r, &ScopeError{Required: scope})
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoles returns middleware that requires specific roles.
func RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := GetToken(r.Context())
			if token == nil {
				defaultErrorHandler(w, r, ErrTokenMissing)
				return
			}

			for _, role := range roles {
				if !token.Claims.HasRole(role) {
					defaultErrorHandler(w, r, &RoleError{Required: role})
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireGroups returns middleware that requires specific groups.
func RequireGroups(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := GetToken(r.Context())
			if token == nil {
				defaultErrorHandler(w, r, ErrTokenMissing)
				return
			}

			for _, group := range groups {
				if !token.Claims.HasGroup(group) {
					defaultErrorHandler(w, r, &RoleError{Required: "group:" + group})
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Handler provides HTTP API for OAuth management.
type Handler struct {
	validator *Validator
	logger    *slog.Logger
}

// NewHandler creates a new OAuth handler.
func NewHandler(validator *Validator, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		validator: validator,
		logger:    logger,
	}
}

// ServeHTTP handles OAuth API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/oauth")

	switch {
	case path == "/validate" && r.Method == http.MethodPost:
		h.handleValidate(w, r)
	case path == "/userinfo" && r.Method == http.MethodGet:
		h.handleUserInfo(w, r)
	case path == "/providers" && r.Method == http.MethodGet:
		h.handleListProviders(w, r)
	default:
		http.NotFound(w, r)
	}
}

type validateRequest struct {
	Token string `json:"token"`
}

func (h *Handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.validator.Validate(r.Context(), req.Token)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":   true,
		"subject": token.Claims.Subject,
		"issuer":  token.Claims.Issuer,
		"expires": token.Claims.ExpiresAt,
	})
}

func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := GetToken(r.Context())
	if token == nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":            token.Claims.Subject,
		"name":           token.Claims.Name,
		"email":          token.Claims.Email,
		"email_verified": token.Claims.EmailVerified,
		"picture":        token.Claims.Picture,
		"roles":          token.Claims.Roles,
		"groups":         token.Claims.Groups,
	})
}

func (h *Handler) handleListProviders(w http.ResponseWriter, r *http.Request) {
	h.validator.mu.RLock()
	providers := make([]map[string]string, 0, len(h.validator.providers))
	for issuer, p := range h.validator.providers {
		providers = append(providers, map[string]string{
			"name":   p.Name,
			"issuer": issuer,
		})
	}
	h.validator.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(providers)
}
