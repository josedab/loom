// Package versioning provides API versioning and lifecycle management.
package versioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrVersionNotFound     = errors.New("version not found")
	ErrVersionDeprecated   = errors.New("API version is deprecated")
	ErrVersionSunset       = errors.New("API version has been sunset")
	ErrNoActiveVersion     = errors.New("no active version available")
	ErrInvalidVersion      = errors.New("invalid version format")
	ErrAPINotFound         = errors.New("API not found")
	ErrVersionExists       = errors.New("version already exists")
)

// Lifecycle represents the lifecycle state of an API version.
type Lifecycle string

const (
	// LifecycleActive indicates the version is fully supported.
	LifecycleActive Lifecycle = "active"
	// LifecycleDeprecated indicates the version is deprecated but functional.
	LifecycleDeprecated Lifecycle = "deprecated"
	// LifecycleSunset indicates the version is no longer available.
	LifecycleSunset Lifecycle = "sunset"
	// LifecycleBeta indicates the version is in beta.
	LifecycleBeta Lifecycle = "beta"
	// LifecycleAlpha indicates the version is in alpha.
	LifecycleAlpha Lifecycle = "alpha"
)

// Version represents an API version.
type Version struct {
	// Name is the version identifier (e.g., "v1", "2024-01-15").
	Name string `json:"name"`
	// Major version number.
	Major int `json:"major"`
	// Minor version number.
	Minor int `json:"minor"`
	// Lifecycle state.
	Lifecycle Lifecycle `json:"lifecycle"`
	// DeprecatedAt is when this version was deprecated.
	DeprecatedAt *time.Time `json:"deprecated_at,omitempty"`
	// SunsetAt is when this version will be/was sunset.
	SunsetAt *time.Time `json:"sunset_at,omitempty"`
	// SuccessorVersion is the recommended version to migrate to.
	SuccessorVersion string `json:"successor_version,omitempty"`
	// Upstream is the backend for this version.
	Upstream string `json:"upstream,omitempty"`
	// PathPrefix is an optional path prefix transformation.
	PathPrefix string `json:"path_prefix,omitempty"`
	// Headers to add to requests for this version.
	Headers map[string]string `json:"headers,omitempty"`
	// Documentation URL.
	DocsURL string `json:"docs_url,omitempty"`
	// Changelog URL.
	ChangelogURL string `json:"changelog_url,omitempty"`
	// CreatedAt is when this version was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this version was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// IsActive returns true if the version is active.
func (v *Version) IsActive() bool {
	return v.Lifecycle == LifecycleActive
}

// IsDeprecated returns true if the version is deprecated.
func (v *Version) IsDeprecated() bool {
	return v.Lifecycle == LifecycleDeprecated
}

// IsSunset returns true if the version has been sunset.
func (v *Version) IsSunset() bool {
	return v.Lifecycle == LifecycleSunset
}

// IsPreRelease returns true if the version is alpha or beta.
func (v *Version) IsPreRelease() bool {
	return v.Lifecycle == LifecycleAlpha || v.Lifecycle == LifecycleBeta
}

// API represents a versioned API.
type API struct {
	// ID is a unique identifier.
	ID string `json:"id"`
	// Name is a human-readable name.
	Name string `json:"name"`
	// Description of the API.
	Description string `json:"description,omitempty"`
	// BasePath is the base path for this API.
	BasePath string `json:"base_path"`
	// Versions is a map of version name to version.
	Versions map[string]*Version `json:"versions"`
	// DefaultVersion is the version to use when none specified.
	DefaultVersion string `json:"default_version,omitempty"`
	// VersioningScheme determines how versions are extracted.
	VersioningScheme VersioningScheme `json:"versioning_scheme"`
	// CreatedAt is when this API was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this API was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// VersioningScheme determines how API versions are extracted from requests.
type VersioningScheme string

const (
	// SchemeHeader extracts version from a header (e.g., "X-API-Version").
	SchemeHeader VersioningScheme = "header"
	// SchemePathPrefix extracts version from URL path (e.g., "/v1/users").
	SchemePathPrefix VersioningScheme = "path"
	// SchemeQuery extracts version from query parameter (e.g., "?version=v1").
	SchemeQuery VersioningScheme = "query"
	// SchemeAcceptHeader extracts version from Accept header media type.
	SchemeAcceptHeader VersioningScheme = "accept"
	// SchemeDate extracts date-based version (e.g., "2024-01-15").
	SchemeDate VersioningScheme = "date"
)

// Manager manages API versions and lifecycles.
type Manager struct {
	apis   map[string]*API
	mu     sync.RWMutex
	logger *slog.Logger
	config ManagerConfig
}

// ManagerConfig configures the versioning manager.
type ManagerConfig struct {
	// Logger for versioning events.
	Logger *slog.Logger
	// DefaultVersionHeader is the header to check for version.
	DefaultVersionHeader string
	// DefaultVersionQuery is the query parameter to check for version.
	DefaultVersionQuery string
	// AllowPreRelease allows alpha/beta versions in production.
	AllowPreRelease bool
	// StrictVersioning fails if no version can be determined.
	StrictVersioning bool
}

// NewManager creates a new versioning manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DefaultVersionHeader == "" {
		cfg.DefaultVersionHeader = "X-API-Version"
	}
	if cfg.DefaultVersionQuery == "" {
		cfg.DefaultVersionQuery = "version"
	}

	return &Manager{
		apis:   make(map[string]*API),
		logger: cfg.Logger,
		config: cfg,
	}
}

// RegisterAPI registers a new API.
func (m *Manager) RegisterAPI(api *API) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if api.ID == "" {
		return errors.New("API ID is required")
	}
	if api.Versions == nil {
		api.Versions = make(map[string]*Version)
	}
	if api.VersioningScheme == "" {
		api.VersioningScheme = SchemePathPrefix
	}

	api.CreatedAt = time.Now()
	api.UpdatedAt = api.CreatedAt
	m.apis[api.ID] = api

	m.logger.Info("API registered",
		"api_id", api.ID,
		"name", api.Name,
		"base_path", api.BasePath,
	)

	return nil
}

// UnregisterAPI removes an API.
func (m *Manager) UnregisterAPI(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.apis[id]; !exists {
		return ErrAPINotFound
	}

	delete(m.apis, id)
	m.logger.Info("API unregistered", "api_id", id)

	return nil
}

// GetAPI retrieves an API by ID.
func (m *Manager) GetAPI(id string) (*API, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	api, exists := m.apis[id]
	if !exists {
		return nil, ErrAPINotFound
	}

	return api, nil
}

// ListAPIs returns all registered APIs.
func (m *Manager) ListAPIs() []*API {
	m.mu.RLock()
	defer m.mu.RUnlock()

	apis := make([]*API, 0, len(m.apis))
	for _, api := range m.apis {
		apis = append(apis, api)
	}

	return apis
}

// AddVersion adds a version to an API.
func (m *Manager) AddVersion(apiID string, version *Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	api, exists := m.apis[apiID]
	if !exists {
		return ErrAPINotFound
	}

	if _, exists := api.Versions[version.Name]; exists {
		return ErrVersionExists
	}

	if version.Lifecycle == "" {
		version.Lifecycle = LifecycleActive
	}

	version.CreatedAt = time.Now()
	version.UpdatedAt = version.CreatedAt
	api.Versions[version.Name] = version
	api.UpdatedAt = time.Now()

	m.logger.Info("version added",
		"api_id", apiID,
		"version", version.Name,
		"lifecycle", version.Lifecycle,
	)

	return nil
}

// RemoveVersion removes a version from an API.
func (m *Manager) RemoveVersion(apiID, versionName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	api, exists := m.apis[apiID]
	if !exists {
		return ErrAPINotFound
	}

	if _, exists := api.Versions[versionName]; !exists {
		return ErrVersionNotFound
	}

	delete(api.Versions, versionName)
	api.UpdatedAt = time.Now()

	m.logger.Info("version removed",
		"api_id", apiID,
		"version", versionName,
	)

	return nil
}

// GetVersion retrieves a specific version.
func (m *Manager) GetVersion(apiID, versionName string) (*Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	api, exists := m.apis[apiID]
	if !exists {
		return nil, ErrAPINotFound
	}

	version, exists := api.Versions[versionName]
	if !exists {
		return nil, ErrVersionNotFound
	}

	return version, nil
}

// DeprecateVersion marks a version as deprecated.
func (m *Manager) DeprecateVersion(apiID, versionName string, sunsetAt time.Time, successor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	api, exists := m.apis[apiID]
	if !exists {
		return ErrAPINotFound
	}

	version, exists := api.Versions[versionName]
	if !exists {
		return ErrVersionNotFound
	}

	now := time.Now()
	version.Lifecycle = LifecycleDeprecated
	version.DeprecatedAt = &now
	version.SunsetAt = &sunsetAt
	version.SuccessorVersion = successor
	version.UpdatedAt = now
	api.UpdatedAt = now

	m.logger.Info("version deprecated",
		"api_id", apiID,
		"version", versionName,
		"sunset_at", sunsetAt,
		"successor", successor,
	)

	return nil
}

// SunsetVersion marks a version as sunset (no longer available).
func (m *Manager) SunsetVersion(apiID, versionName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	api, exists := m.apis[apiID]
	if !exists {
		return ErrAPINotFound
	}

	version, exists := api.Versions[versionName]
	if !exists {
		return ErrVersionNotFound
	}

	now := time.Now()
	version.Lifecycle = LifecycleSunset
	if version.SunsetAt == nil {
		version.SunsetAt = &now
	}
	version.UpdatedAt = now
	api.UpdatedAt = now

	m.logger.Info("version sunset",
		"api_id", apiID,
		"version", versionName,
	)

	return nil
}

// GetActiveVersions returns all active versions for an API.
func (m *Manager) GetActiveVersions(apiID string) ([]*Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	api, exists := m.apis[apiID]
	if !exists {
		return nil, ErrAPINotFound
	}

	versions := make([]*Version, 0)
	for _, v := range api.Versions {
		if v.IsActive() {
			versions = append(versions, v)
		}
	}

	return versions, nil
}

// GetLatestVersion returns the latest active version for an API.
func (m *Manager) GetLatestVersion(apiID string) (*Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	api, exists := m.apis[apiID]
	if !exists {
		return nil, ErrAPINotFound
	}

	// If default version is set and active, use it
	if api.DefaultVersion != "" {
		if v, exists := api.Versions[api.DefaultVersion]; exists && v.IsActive() {
			return v, nil
		}
	}

	// Find the latest active version by major.minor
	var latest *Version
	for _, v := range api.Versions {
		if !v.IsActive() {
			continue
		}
		if latest == nil || v.Major > latest.Major ||
			(v.Major == latest.Major && v.Minor > latest.Minor) {
			latest = v
		}
	}

	if latest == nil {
		return nil, ErrNoActiveVersion
	}

	return latest, nil
}

// ResolveVersion resolves the version for a request.
func (m *Manager) ResolveVersion(apiID string, r *http.Request) (*Version, error) {
	m.mu.RLock()
	api, exists := m.apis[apiID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrAPINotFound
	}

	versionName := m.extractVersion(api, r)

	if versionName == "" {
		if api.DefaultVersion != "" {
			versionName = api.DefaultVersion
		} else if m.config.StrictVersioning {
			return nil, ErrVersionNotFound
		} else {
			return m.GetLatestVersion(apiID)
		}
	}

	m.mu.RLock()
	version, exists := api.Versions[versionName]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrVersionNotFound
	}

	// Check if version is sunset
	if version.IsSunset() {
		return nil, ErrVersionSunset
	}

	// Check if pre-release is allowed
	if version.IsPreRelease() && !m.config.AllowPreRelease {
		return nil, fmt.Errorf("pre-release version %s is not allowed", versionName)
	}

	return version, nil
}

func (m *Manager) extractVersion(api *API, r *http.Request) string {
	switch api.VersioningScheme {
	case SchemeHeader:
		return r.Header.Get(m.config.DefaultVersionHeader)

	case SchemeQuery:
		return r.URL.Query().Get(m.config.DefaultVersionQuery)

	case SchemePathPrefix:
		return extractPathVersion(r.URL.Path, api.BasePath)

	case SchemeAcceptHeader:
		return extractAcceptVersion(r.Header.Get("Accept"))

	case SchemeDate:
		// Check header first, then query
		if v := r.Header.Get(m.config.DefaultVersionHeader); v != "" {
			return v
		}
		return r.URL.Query().Get(m.config.DefaultVersionQuery)

	default:
		return ""
	}
}

// versionPattern matches versions like "v1", "v2", "v1.0", "v2.1"
var versionPattern = regexp.MustCompile(`^v\d+(\.\d+)?$`)

func extractPathVersion(path, basePath string) string {
	// Remove base path
	path = strings.TrimPrefix(path, basePath)
	path = strings.TrimPrefix(path, "/")

	// Get first path segment
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		return ""
	}

	segment := parts[0]
	if versionPattern.MatchString(segment) {
		return segment
	}

	return ""
}

// acceptVersionPattern matches vendor media types like "application/vnd.api.v1+json"
var acceptVersionPattern = regexp.MustCompile(`application/vnd\.[^.]+\.(v\d+(?:\.\d+)?)\+`)

func extractAcceptVersion(accept string) string {
	matches := acceptVersionPattern.FindStringSubmatch(accept)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// ParseVersion parses a version string like "v1" or "v1.2".
func ParseVersion(s string) (major, minor int, err error) {
	s = strings.TrimPrefix(s, "v")

	var parsed int
	if strings.Contains(s, ".") {
		_, err = fmt.Sscanf(s, "%d.%d", &major, &minor)
		parsed = 2
	} else {
		_, err = fmt.Sscanf(s, "%d", &major)
		parsed = 1
	}

	if err != nil || parsed == 0 {
		return 0, 0, ErrInvalidVersion
	}

	return major, minor, nil
}

// CompareVersions compares two versions.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b *Version) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	return 0
}

// SortVersions sorts versions in ascending order.
func SortVersions(versions []*Version) {
	sort.Slice(versions, func(i, j int) bool {
		return CompareVersions(versions[i], versions[j]) < 0
	})
}

// VersionContext holds version information in request context.
type VersionContext struct {
	API     *API
	Version *Version
}

type versionContextKey struct{}

// WithVersionContext adds version context to a context.
func WithVersionContext(ctx context.Context, vc *VersionContext) context.Context {
	return context.WithValue(ctx, versionContextKey{}, vc)
}

// GetVersionContext retrieves version context from a context.
func GetVersionContext(ctx context.Context) *VersionContext {
	vc, _ := ctx.Value(versionContextKey{}).(*VersionContext)
	return vc
}

// Stats holds versioning statistics.
type Stats struct {
	TotalAPIs          int                      `json:"total_apis"`
	TotalVersions      int                      `json:"total_versions"`
	ActiveVersions     int                      `json:"active_versions"`
	DeprecatedVersions int                      `json:"deprecated_versions"`
	SunsetVersions     int                      `json:"sunset_versions"`
	ByLifecycle        map[Lifecycle]int        `json:"by_lifecycle"`
	ByAPI              map[string]*APIStats     `json:"by_api"`
}

// APIStats holds statistics for a single API.
type APIStats struct {
	Name           string   `json:"name"`
	VersionCount   int      `json:"version_count"`
	ActiveVersions []string `json:"active_versions"`
	DefaultVersion string   `json:"default_version,omitempty"`
}

// Stats returns versioning statistics.
func (m *Manager) Stats() *Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &Stats{
		TotalAPIs:   len(m.apis),
		ByLifecycle: make(map[Lifecycle]int),
		ByAPI:       make(map[string]*APIStats),
	}

	for _, api := range m.apis {
		apiStats := &APIStats{
			Name:           api.Name,
			VersionCount:   len(api.Versions),
			ActiveVersions: make([]string, 0),
			DefaultVersion: api.DefaultVersion,
		}

		for _, v := range api.Versions {
			stats.TotalVersions++
			stats.ByLifecycle[v.Lifecycle]++

			switch v.Lifecycle {
			case LifecycleActive:
				stats.ActiveVersions++
				apiStats.ActiveVersions = append(apiStats.ActiveVersions, v.Name)
			case LifecycleDeprecated:
				stats.DeprecatedVersions++
			case LifecycleSunset:
				stats.SunsetVersions++
			}
		}

		stats.ByAPI[api.ID] = apiStats
	}

	return stats
}
