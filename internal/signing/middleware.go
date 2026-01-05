package signing

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// SigningMiddlewareConfig configures the signing middleware.
type SigningMiddlewareConfig struct {
	// Signer for signing outgoing requests.
	Signer interface{ Sign(*http.Request) error }
	// Logger for middleware events.
	Logger *slog.Logger
	// OnError is called when signing fails.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// SigningMiddleware creates middleware that signs outgoing requests.
func SigningMiddleware(cfg SigningMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultSigningErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := cfg.Signer.Sign(r); err != nil {
				cfg.Logger.Error("request signing failed",
					"path", r.URL.Path,
					"error", err,
				)
				cfg.OnError(w, r, err)
				return
			}

			cfg.Logger.Debug("request signed",
				"path", r.URL.Path,
				"method", r.Method,
			)

			next.ServeHTTP(w, r)
		})
	}
}

// VerificationMiddlewareConfig configures the verification middleware.
type VerificationMiddlewareConfig struct {
	// HMACVerifier for HMAC signature verification.
	HMACVerifier *HMACVerifier
	// AWS4Verifier for AWS SigV4 signature verification.
	AWS4Verifier *AWS4Verifier
	// Logger for middleware events.
	Logger *slog.Logger
	// OnError is called when verification fails.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// SkipPaths are paths that don't require signature verification.
	SkipPaths []string
}

// VerificationMiddleware creates middleware that verifies request signatures.
func VerificationMiddleware(cfg VerificationMiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultVerificationErrorHandler
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

			// Determine signature type
			var err error
			if r.Header.Get("Authorization") != "" && strings.HasPrefix(r.Header.Get("Authorization"), "AWS4") {
				// AWS SigV4
				if cfg.AWS4Verifier == nil {
					cfg.OnError(w, r, ErrMissingSignature)
					return
				}
				err = cfg.AWS4Verifier.Verify(r)
			} else if r.Header.Get("X-Signature") != "" {
				// HMAC
				if cfg.HMACVerifier == nil {
					cfg.OnError(w, r, ErrMissingSignature)
					return
				}
				err = cfg.HMACVerifier.Verify(r)
			} else {
				cfg.OnError(w, r, ErrMissingSignature)
				return
			}

			if err != nil {
				cfg.Logger.Warn("signature verification failed",
					"path", r.URL.Path,
					"error", err,
				)
				cfg.OnError(w, r, err)
				return
			}

			cfg.Logger.Debug("signature verified",
				"path", r.URL.Path,
				"method", r.Method,
			)

			next.ServeHTTP(w, r)
		})
	}
}

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

func defaultSigningErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "request signing failed",
	})
}

func defaultVerificationErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	var status int
	var message string

	switch err {
	case ErrMissingSignature:
		status = http.StatusUnauthorized
		message = "signature required"
	case ErrInvalidSignature:
		status = http.StatusUnauthorized
		message = "invalid signature"
	case ErrExpiredSignature:
		status = http.StatusUnauthorized
		message = "signature expired"
	case ErrInvalidCredentials:
		status = http.StatusUnauthorized
		message = "invalid credentials"
	case ErrReplayDetected:
		status = http.StatusUnauthorized
		message = "replay attack detected"
	default:
		status = http.StatusUnauthorized
		message = "signature verification failed"
	}

	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// Handler provides HTTP API for credential management.
type Handler struct {
	keyStore KeyStore
	logger   *slog.Logger
}

// NewHandler creates a new signing handler.
func NewHandler(keyStore KeyStore, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		keyStore: keyStore,
		logger:   logger,
	}
}

// ServeHTTP handles signing API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/signing")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/keys" || path == "/keys/":
		switch r.Method {
		case http.MethodGet:
			h.handleListKeys(w, r)
		case http.MethodPost:
			h.handleCreateKey(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/stats":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case strings.HasPrefix(path, "/keys/"):
		keyID := strings.TrimPrefix(path, "/keys/")
		switch r.Method {
		case http.MethodGet:
			h.handleGetKey(w, r, keyID)
		case http.MethodDelete:
			h.handleDeleteKey(w, r, keyID)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys := h.keyStore.ListKeys()

	// Get key details (without secrets)
	result := make([]map[string]interface{}, 0, len(keys))
	for _, id := range keys {
		creds, err := h.keyStore.GetKey(id)
		if err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"id":          creds.ID,
			"description": creds.Description,
			"enabled":     creds.Enabled,
			"expires_at":  creds.ExpiresAt,
			"created_at":  creds.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type createKeyRequest struct {
	ID          string     `json:"id"`
	Secret      string     `json:"secret"`
	Description string     `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *string    `json:"expires_at,omitempty"`
}

func (h *Handler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Secret == "" {
		h.jsonError(w, "id and secret are required", http.StatusBadRequest)
		return
	}

	creds := &Credentials{
		ID:          req.ID,
		Secret:      req.Secret,
		Description: req.Description,
		Enabled:     req.Enabled,
	}

	if err := h.keyStore.AddKey(creds); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("signing key created", "id", creds.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          creds.ID,
		"description": creds.Description,
		"enabled":     creds.Enabled,
		"created_at":  creds.CreatedAt,
	})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request, keyID string) {
	creds, err := h.keyStore.GetKey(keyID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          creds.ID,
		"description": creds.Description,
		"enabled":     creds.Enabled,
		"expires_at":  creds.ExpiresAt,
		"created_at":  creds.CreatedAt,
	})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request, keyID string) {
	if err := h.keyStore.RemoveKey(keyID); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.logger.Info("signing key deleted", "id", keyID)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := GetStats(h.keyStore)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}
