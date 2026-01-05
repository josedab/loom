package versioning

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// MiddlewareConfig configures the versioning middleware.
type MiddlewareConfig struct {
	// Manager for version resolution.
	Manager *Manager
	// APIResolver determines which API a request belongs to.
	APIResolver func(*http.Request) string
	// OnError is called when version resolution fails.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// Logger for middleware events.
	Logger *slog.Logger
	// AddDeprecationHeaders adds deprecation headers to responses.
	AddDeprecationHeaders bool
	// BlockSunsetVersions returns 410 Gone for sunset versions.
	BlockSunsetVersions bool
	// BlockDeprecatedVersions returns 400 for deprecated versions.
	BlockDeprecatedVersions bool
}

// Middleware returns HTTP middleware for API versioning.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultVersionErrorHandler
	}
	if cfg.APIResolver == nil {
		cfg.APIResolver = func(r *http.Request) string {
			return "default"
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiID := cfg.APIResolver(r)

			version, err := cfg.Manager.ResolveVersion(apiID, r)
			if err != nil {
				if err == ErrAPINotFound {
					// API not managed, pass through
					next.ServeHTTP(w, r)
					return
				}
				cfg.OnError(w, r, err)
				return
			}

			// Handle sunset versions
			if version.IsSunset() {
				if cfg.BlockSunsetVersions {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusGone)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":   "API version has been sunset",
						"version": version.Name,
						"message": "This API version is no longer available",
					})
					return
				}
			}

			// Handle deprecated versions
			if version.IsDeprecated() {
				if cfg.BlockDeprecatedVersions {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":     "API version is deprecated",
						"version":   version.Name,
						"successor": version.SuccessorVersion,
						"sunset_at": version.SunsetAt,
					})
					return
				}

				// Add deprecation headers
				if cfg.AddDeprecationHeaders {
					addDeprecationHeaders(w, version)
				}

				cfg.Logger.Warn("deprecated API version used",
					"api", apiID,
					"version", version.Name,
					"successor", version.SuccessorVersion,
					"path", r.URL.Path,
				)
			}

			// Store version context
			api, _ := cfg.Manager.GetAPI(apiID)
			ctx := WithVersionContext(r.Context(), &VersionContext{
				API:     api,
				Version: version,
			})

			// Add version response headers
			w.Header().Set("X-API-Version", version.Name)

			cfg.Logger.Debug("version resolved",
				"api", apiID,
				"version", version.Name,
				"lifecycle", version.Lifecycle,
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func addDeprecationHeaders(w http.ResponseWriter, version *Version) {
	// Standard Deprecation header (RFC 8594)
	w.Header().Set("Deprecation", "true")

	if version.DeprecatedAt != nil {
		w.Header().Set("Deprecation", version.DeprecatedAt.Format(time.RFC1123))
	}

	// Sunset header (RFC 8594)
	if version.SunsetAt != nil {
		w.Header().Set("Sunset", version.SunsetAt.Format(time.RFC1123))
	}

	// Link to successor version
	if version.SuccessorVersion != "" {
		w.Header().Add("Link", fmt.Sprintf(`</api/%s>; rel="successor-version"`, version.SuccessorVersion))
	}

	// Link to documentation
	if version.DocsURL != "" {
		w.Header().Add("Link", fmt.Sprintf(`<%s>; rel="deprecation"`, version.DocsURL))
	}
}

func defaultVersionErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch err {
	case ErrVersionNotFound:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "API version not found",
		})
	case ErrVersionSunset:
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "API version has been sunset",
		})
	case ErrNoActiveVersion:
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "No active API version available",
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
	}
}

// TransformMiddleware transforms requests based on version.
type TransformMiddleware struct {
	manager *Manager
	logger  *slog.Logger
}

// NewTransformMiddleware creates middleware that transforms requests by version.
func NewTransformMiddleware(manager *Manager, logger *slog.Logger) *TransformMiddleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &TransformMiddleware{
		manager: manager,
		logger:  logger,
	}
}

// Handler returns the HTTP handler for request transformation.
func (t *TransformMiddleware) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vc := GetVersionContext(r.Context())
			if vc == nil || vc.Version == nil {
				next.ServeHTTP(w, r)
				return
			}

			version := vc.Version

			// Transform path if PathPrefix is set
			if version.PathPrefix != "" {
				originalPath := r.URL.Path
				// Remove version from path if present
				newPath := removeVersionFromPath(originalPath, version.Name)
				// Add version-specific prefix
				r.URL.Path = version.PathPrefix + newPath

				t.logger.Debug("path transformed",
					"original", originalPath,
					"transformed", r.URL.Path,
					"version", version.Name,
				)
			}

			// Add version-specific headers
			for key, value := range version.Headers {
				r.Header.Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func removeVersionFromPath(path, version string) string {
	// Remove the version segment from the path
	segments := strings.Split(path, "/")
	result := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg != version {
			result = append(result, seg)
		}
	}
	return strings.Join(result, "/")
}

// Handler provides HTTP API for version management.
type Handler struct {
	manager *Manager
	logger  *slog.Logger
}

// NewHandler creates a new versioning handler.
func NewHandler(manager *Manager, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		manager: manager,
		logger:  logger,
	}
}

// ServeHTTP handles versioning API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/versions")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" || path == "":
		switch r.Method {
		case http.MethodGet:
			h.handleListAPIs(w, r)
		case http.MethodPost:
			h.handleCreateAPI(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/stats":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case strings.HasPrefix(path, "/"):
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		apiID := parts[0]

		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				h.handleGetAPI(w, r, apiID)
			case http.MethodDelete:
				h.handleDeleteAPI(w, r, apiID)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		} else if len(parts) >= 2 && parts[1] == "versions" {
			if len(parts) == 2 {
				switch r.Method {
				case http.MethodGet:
					h.handleListVersions(w, r, apiID)
				case http.MethodPost:
					h.handleAddVersion(w, r, apiID)
				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			} else if len(parts) >= 3 {
				versionName := parts[2]

				if len(parts) == 3 {
					switch r.Method {
					case http.MethodGet:
						h.handleGetVersion(w, r, apiID, versionName)
					case http.MethodDelete:
						h.handleRemoveVersion(w, r, apiID, versionName)
					default:
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					}
				} else if len(parts) == 4 {
					switch parts[3] {
					case "deprecate":
						if r.Method == http.MethodPost {
							h.handleDeprecateVersion(w, r, apiID, versionName)
						} else {
							http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						}
					case "sunset":
						if r.Method == http.MethodPost {
							h.handleSunsetVersion(w, r, apiID, versionName)
						} else {
							http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						}
					default:
						http.NotFound(w, r)
					}
				} else {
					http.NotFound(w, r)
				}
			}
		} else {
			http.NotFound(w, r)
		}

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleListAPIs(w http.ResponseWriter, r *http.Request) {
	apis := h.manager.ListAPIs()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apis)
}

type createAPIRequest struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Description      string           `json:"description,omitempty"`
	BasePath         string           `json:"base_path"`
	DefaultVersion   string           `json:"default_version,omitempty"`
	VersioningScheme VersioningScheme `json:"versioning_scheme,omitempty"`
}

func (h *Handler) handleCreateAPI(w http.ResponseWriter, r *http.Request) {
	var req createAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	api := &API{
		ID:               req.ID,
		Name:             req.Name,
		Description:      req.Description,
		BasePath:         req.BasePath,
		DefaultVersion:   req.DefaultVersion,
		VersioningScheme: req.VersioningScheme,
	}

	if err := h.manager.RegisterAPI(api); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(api)
}

func (h *Handler) handleGetAPI(w http.ResponseWriter, r *http.Request, apiID string) {
	api, err := h.manager.GetAPI(apiID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api)
}

func (h *Handler) handleDeleteAPI(w http.ResponseWriter, r *http.Request, apiID string) {
	if err := h.manager.UnregisterAPI(apiID); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleListVersions(w http.ResponseWriter, r *http.Request, apiID string) {
	api, err := h.manager.GetAPI(apiID)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	versions := make([]*Version, 0, len(api.Versions))
	for _, v := range api.Versions {
		versions = append(versions, v)
	}

	SortVersions(versions)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

type addVersionRequest struct {
	Name             string            `json:"name"`
	Major            int               `json:"major"`
	Minor            int               `json:"minor"`
	Lifecycle        Lifecycle         `json:"lifecycle,omitempty"`
	Upstream         string            `json:"upstream,omitempty"`
	PathPrefix       string            `json:"path_prefix,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	DocsURL          string            `json:"docs_url,omitempty"`
	ChangelogURL     string            `json:"changelog_url,omitempty"`
	SuccessorVersion string            `json:"successor_version,omitempty"`
}

func (h *Handler) handleAddVersion(w http.ResponseWriter, r *http.Request, apiID string) {
	var req addVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	version := &Version{
		Name:             req.Name,
		Major:            req.Major,
		Minor:            req.Minor,
		Lifecycle:        req.Lifecycle,
		Upstream:         req.Upstream,
		PathPrefix:       req.PathPrefix,
		Headers:          req.Headers,
		DocsURL:          req.DocsURL,
		ChangelogURL:     req.ChangelogURL,
		SuccessorVersion: req.SuccessorVersion,
	}

	if err := h.manager.AddVersion(apiID, version); err != nil {
		status := http.StatusBadRequest
		if err == ErrAPINotFound {
			status = http.StatusNotFound
		}
		h.jsonError(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(version)
}

func (h *Handler) handleGetVersion(w http.ResponseWriter, r *http.Request, apiID, versionName string) {
	version, err := h.manager.GetVersion(apiID, versionName)
	if err != nil {
		status := http.StatusNotFound
		h.jsonError(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}

func (h *Handler) handleRemoveVersion(w http.ResponseWriter, r *http.Request, apiID, versionName string) {
	if err := h.manager.RemoveVersion(apiID, versionName); err != nil {
		status := http.StatusNotFound
		h.jsonError(w, err.Error(), status)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type deprecateRequest struct {
	SunsetAt  time.Time `json:"sunset_at"`
	Successor string    `json:"successor,omitempty"`
}

func (h *Handler) handleDeprecateVersion(w http.ResponseWriter, r *http.Request, apiID, versionName string) {
	var req deprecateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.DeprecateVersion(apiID, versionName, req.SunsetAt, req.Successor); err != nil {
		status := http.StatusNotFound
		h.jsonError(w, err.Error(), status)
		return
	}

	version, _ := h.manager.GetVersion(apiID, versionName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}

func (h *Handler) handleSunsetVersion(w http.ResponseWriter, r *http.Request, apiID, versionName string) {
	if err := h.manager.SunsetVersion(apiID, versionName); err != nil {
		status := http.StatusNotFound
		h.jsonError(w, err.Error(), status)
		return
	}

	version, _ := h.manager.GetVersion(apiID, versionName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version)
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.manager.Stats()

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
