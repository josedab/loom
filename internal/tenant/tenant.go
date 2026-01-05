// Package tenant provides multi-tenancy support for the API gateway.
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors.
var (
	ErrTenantNotFound   = errors.New("tenant not found")
	ErrTenantDisabled   = errors.New("tenant disabled")
	ErrTenantSuspended  = errors.New("tenant suspended")
	ErrQuotaExceeded    = errors.New("quota exceeded")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// Tenant represents a tenant configuration.
type Tenant struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Status      TenantStatus      `json:"status"`
	Plan        string            `json:"plan,omitempty"`
	Config      TenantConfig      `json:"config"`
	Quota       *Quota            `json:"quota,omitempty"`
	RateLimit   *RateLimit        `json:"rate_limit,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`

	// Runtime state
	usage       *Usage
	rateLimiter *tokenBucket
}

// TenantStatus represents the status of a tenant.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusDisabled  TenantStatus = "disabled"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusTrial     TenantStatus = "trial"
)

// TenantConfig holds tenant-specific configuration.
type TenantConfig struct {
	// Upstream overrides the default upstream for this tenant.
	Upstream string `json:"upstream,omitempty"`
	// BasePath is prepended to all routes for this tenant.
	BasePath string `json:"base_path,omitempty"`
	// Headers to add to all requests for this tenant.
	Headers map[string]string `json:"headers,omitempty"`
	// AllowedOrigins for CORS.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AllowedIPs restricts access to specific IPs.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// Features enabled for this tenant.
	Features map[string]bool `json:"features,omitempty"`
	// CustomRoutes for this tenant.
	CustomRoutes []RouteOverride `json:"custom_routes,omitempty"`
	// Timeout overrides default timeout.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// RouteOverride represents a tenant-specific route override.
type RouteOverride struct {
	Path     string `json:"path"`
	Upstream string `json:"upstream"`
	Enabled  bool   `json:"enabled"`
}

// Quota defines usage quotas for a tenant.
type Quota struct {
	// RequestsPerDay limits daily requests.
	RequestsPerDay int64 `json:"requests_per_day,omitempty"`
	// RequestsPerMonth limits monthly requests.
	RequestsPerMonth int64 `json:"requests_per_month,omitempty"`
	// BandwidthPerDay in bytes.
	BandwidthPerDay int64 `json:"bandwidth_per_day,omitempty"`
	// BandwidthPerMonth in bytes.
	BandwidthPerMonth int64 `json:"bandwidth_per_month,omitempty"`
}

// RateLimit defines rate limiting for a tenant.
type RateLimit struct {
	// RequestsPerSecond is the rate limit.
	RequestsPerSecond float64 `json:"requests_per_second"`
	// BurstSize is the maximum burst.
	BurstSize int `json:"burst_size"`
}

// Usage tracks tenant usage.
type Usage struct {
	RequestsToday  int64     `json:"requests_today"`
	RequestsMonth  int64     `json:"requests_month"`
	BandwidthToday int64     `json:"bandwidth_today"`
	BandwidthMonth int64     `json:"bandwidth_month"`
	LastReset      time.Time `json:"last_reset"`
	mu             sync.Mutex
}

// tokenBucket implements a token bucket rate limiter.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func newTokenBucket(rateLimit *RateLimit) *tokenBucket {
	if rateLimit == nil {
		return nil
	}
	return &tokenBucket{
		tokens:     float64(rateLimit.BurstSize),
		maxTokens:  float64(rateLimit.BurstSize),
		refillRate: rateLimit.RequestsPerSecond,
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// Manager manages tenants.
type Manager struct {
	tenants  map[string]*Tenant
	mu       sync.RWMutex
	resolver TenantResolver
	store    TenantStore
	logger   *slog.Logger
	config   ManagerConfig
}

// ManagerConfig configures the tenant manager.
type ManagerConfig struct {
	// DefaultTenant is used when no tenant is identified.
	DefaultTenant string
	// Resolver determines how to identify tenants.
	Resolver TenantResolver
	// Store for persistent tenant storage.
	Store TenantStore
	// Logger for manager events.
	Logger *slog.Logger
	// EnableUsageTracking enables usage tracking.
	EnableUsageTracking bool
}

// TenantResolver identifies a tenant from a request.
type TenantResolver func(*http.Request) string

// TenantStore provides persistent tenant storage.
type TenantStore interface {
	Get(ctx context.Context, id string) (*Tenant, error)
	List(ctx context.Context) ([]*Tenant, error)
	Save(ctx context.Context, tenant *Tenant) error
	Delete(ctx context.Context, id string) error
}

// NewManager creates a new tenant manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Resolver == nil {
		cfg.Resolver = HeaderResolver("X-Tenant-ID")
	}

	return &Manager{
		tenants:  make(map[string]*Tenant),
		resolver: cfg.Resolver,
		store:    cfg.Store,
		logger:   cfg.Logger,
		config:   cfg,
	}
}

// HeaderResolver identifies tenant from a header.
func HeaderResolver(header string) TenantResolver {
	return func(r *http.Request) string {
		return r.Header.Get(header)
	}
}

// SubdomainResolver identifies tenant from subdomain.
func SubdomainResolver() TenantResolver {
	return func(r *http.Request) string {
		host := r.Host
		// Remove port if present
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		parts := strings.Split(host, ".")
		if len(parts) > 2 {
			return parts[0]
		}
		return ""
	}
}

// PathResolver identifies tenant from path prefix.
func PathResolver(prefix string) TenantResolver {
	re := regexp.MustCompile(fmt.Sprintf(`^%s([^/]+)`, regexp.QuoteMeta(prefix)))
	return func(r *http.Request) string {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 1 {
			return matches[1]
		}
		return ""
	}
}

// ChainedResolver tries multiple resolvers in order.
func ChainedResolver(resolvers ...TenantResolver) TenantResolver {
	return func(r *http.Request) string {
		for _, resolver := range resolvers {
			if id := resolver(r); id != "" {
				return id
			}
		}
		return ""
	}
}

// AddTenant adds a tenant.
func (m *Manager) AddTenant(tenant *Tenant) error {
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID is required")
	}

	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()
	tenant.usage = &Usage{LastReset: time.Now()}

	if tenant.RateLimit != nil {
		tenant.rateLimiter = newTokenBucket(tenant.RateLimit)
	}

	m.mu.Lock()
	m.tenants[tenant.ID] = tenant
	m.mu.Unlock()

	m.logger.Info("tenant added",
		"id", tenant.ID,
		"name", tenant.Name,
		"status", tenant.Status,
	)

	return nil
}

// GetTenant returns a tenant by ID.
func (m *Manager) GetTenant(id string) (*Tenant, error) {
	m.mu.RLock()
	tenant := m.tenants[id]
	m.mu.RUnlock()

	if tenant == nil {
		// Try store if available
		if m.store != nil {
			var err error
			tenant, err = m.store.Get(context.Background(), id)
			if err != nil {
				return nil, err
			}
			if tenant != nil {
				m.mu.Lock()
				m.tenants[id] = tenant
				m.mu.Unlock()
			}
		}
	}

	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	return tenant, nil
}

// UpdateTenant updates a tenant.
func (m *Manager) UpdateTenant(tenant *Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing := m.tenants[tenant.ID]
	if existing == nil {
		return ErrTenantNotFound
	}

	tenant.CreatedAt = existing.CreatedAt
	tenant.UpdatedAt = time.Now()
	tenant.usage = existing.usage

	if tenant.RateLimit != nil {
		tenant.rateLimiter = newTokenBucket(tenant.RateLimit)
	}

	m.tenants[tenant.ID] = tenant

	m.logger.Info("tenant updated",
		"id", tenant.ID,
	)

	return nil
}

// RemoveTenant removes a tenant.
func (m *Manager) RemoveTenant(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tenants[id]; ok {
		delete(m.tenants, id)
		m.logger.Info("tenant removed", "id", id)
		return true
	}
	return false
}

// ListTenants returns all tenants.
func (m *Manager) ListTenants() []*Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]*Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, t)
	}
	return tenants
}

// ResolveTenant identifies tenant from request.
func (m *Manager) ResolveTenant(r *http.Request) string {
	id := m.resolver(r)
	if id == "" {
		id = m.config.DefaultTenant
	}
	return id
}

// CheckAccess verifies tenant can make a request.
func (m *Manager) CheckAccess(tenant *Tenant) error {
	switch tenant.Status {
	case TenantStatusDisabled:
		return ErrTenantDisabled
	case TenantStatusSuspended:
		return ErrTenantSuspended
	}

	// Check rate limit
	if tenant.rateLimiter != nil && !tenant.rateLimiter.Allow() {
		return ErrRateLimitExceeded
	}

	// Check quota
	if tenant.Quota != nil && tenant.usage != nil {
		tenant.usage.mu.Lock()
		defer tenant.usage.mu.Unlock()

		// Reset counters if needed
		now := time.Now()
		if tenant.usage.LastReset.Day() != now.Day() {
			tenant.usage.RequestsToday = 0
			tenant.usage.BandwidthToday = 0
		}
		if tenant.usage.LastReset.Month() != now.Month() {
			tenant.usage.RequestsMonth = 0
			tenant.usage.BandwidthMonth = 0
		}
		tenant.usage.LastReset = now

		if tenant.Quota.RequestsPerDay > 0 && tenant.usage.RequestsToday >= tenant.Quota.RequestsPerDay {
			return ErrQuotaExceeded
		}
		if tenant.Quota.RequestsPerMonth > 0 && tenant.usage.RequestsMonth >= tenant.Quota.RequestsPerMonth {
			return ErrQuotaExceeded
		}
	}

	return nil
}

// RecordUsage records a request for a tenant.
func (m *Manager) RecordUsage(tenant *Tenant, bytes int64) {
	if tenant.usage == nil || !m.config.EnableUsageTracking {
		return
	}

	tenant.usage.mu.Lock()
	defer tenant.usage.mu.Unlock()

	tenant.usage.RequestsToday++
	tenant.usage.RequestsMonth++
	tenant.usage.BandwidthToday += bytes
	tenant.usage.BandwidthMonth += bytes
}

// GetUsage returns usage for a tenant.
func (m *Manager) GetUsage(tenantID string) (*Usage, error) {
	tenant, err := m.GetTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return tenant.usage, nil
}

// MiddlewareConfig configures the tenant middleware.
type MiddlewareConfig struct {
	// Manager is the tenant manager.
	Manager *Manager
	// OnError is called when tenant access fails.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// RequireTenant rejects requests without a tenant.
	RequireTenant bool
	// Logger for middleware events.
	Logger *slog.Logger
}

// Middleware returns HTTP middleware for tenant handling.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OnError == nil {
		cfg.OnError = defaultTenantErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Resolve tenant
			tenantID := cfg.Manager.ResolveTenant(r)

			if tenantID == "" {
				if cfg.RequireTenant {
					cfg.OnError(w, r, ErrTenantNotFound)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Get tenant
			tenant, err := cfg.Manager.GetTenant(tenantID)
			if err != nil {
				if cfg.RequireTenant {
					cfg.OnError(w, r, err)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Check access
			if err := cfg.Manager.CheckAccess(tenant); err != nil {
				cfg.OnError(w, r, err)
				return
			}

			// Add tenant headers
			for key, value := range tenant.Config.Headers {
				r.Header.Set(key, value)
			}

			// Track response size for usage
			rw := &responseWriter{ResponseWriter: w}

			// Store tenant in context
			ctx := context.WithValue(r.Context(), tenantContextKey{}, tenant)
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Record usage
			cfg.Manager.RecordUsage(tenant, rw.bytesWritten)
		})
	}
}

type tenantContextKey struct{}

// GetTenantFromContext retrieves tenant from request context.
func GetTenantFromContext(ctx context.Context) *Tenant {
	tenant, _ := ctx.Value(tenantContextKey{}).(*Tenant)
	return tenant
}

// responseWriter wraps http.ResponseWriter to track bytes written.
type responseWriter struct {
	http.ResponseWriter
	bytesWritten int64
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	atomic.AddInt64(&rw.bytesWritten, int64(n))
	return n, err
}

// defaultTenantErrorHandler returns JSON error responses.
func defaultTenantErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	var status int
	var message string

	switch {
	case errors.Is(err, ErrTenantNotFound):
		status = http.StatusUnauthorized
		message = "tenant not found"
	case errors.Is(err, ErrTenantDisabled):
		status = http.StatusForbidden
		message = "tenant disabled"
	case errors.Is(err, ErrTenantSuspended):
		status = http.StatusForbidden
		message = "tenant suspended"
	case errors.Is(err, ErrQuotaExceeded):
		status = http.StatusTooManyRequests
		message = "quota exceeded"
	case errors.Is(err, ErrRateLimitExceeded):
		status = http.StatusTooManyRequests
		message = "rate limit exceeded"
		w.Header().Set("Retry-After", "1")
	default:
		status = http.StatusInternalServerError
		message = "internal error"
	}

	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
	})
}

// Handler provides HTTP API for tenant management.
type Handler struct {
	manager *Manager
	logger  *slog.Logger
}

// NewHandler creates a new tenant handler.
func NewHandler(manager *Manager, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		manager: manager,
		logger:  logger,
	}
}

// ServeHTTP handles tenant API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/tenants")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.handleList(w, r)
	case path == "" && r.Method == http.MethodPost:
		h.handleCreate(w, r)
	case strings.HasPrefix(path, "/") && r.Method == http.MethodGet:
		h.handleGet(w, r, strings.TrimPrefix(path, "/"))
	case strings.HasPrefix(path, "/") && r.Method == http.MethodPut:
		h.handleUpdate(w, r, strings.TrimPrefix(path, "/"))
	case strings.HasPrefix(path, "/") && r.Method == http.MethodDelete:
		h.handleDelete(w, r, strings.TrimPrefix(path, "/"))
	case strings.HasSuffix(path, "/usage"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/usage")
		h.handleUsage(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	tenants := h.manager.ListTenants()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenants)
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var tenant Tenant
	if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.AddTenant(&tenant); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tenant)
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	// Remove any trailing path segments
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}

	tenant, err := h.manager.GetTenant(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var tenant Tenant
	if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tenant.ID = id
	if err := h.manager.UpdateTenant(&tenant); err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	if !h.manager.RemoveTenant(id) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleUsage(w http.ResponseWriter, r *http.Request, id string) {
	usage, err := h.manager.GetUsage(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usage)
}

// IsolationMiddleware provides complete tenant isolation.
func IsolationMiddleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	baseMiddleware := Middleware(cfg)

	return func(next http.Handler) http.Handler {
		return baseMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := GetTenantFromContext(r.Context())
			if tenant == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Check IP allowlist
			if len(tenant.Config.AllowedIPs) > 0 {
				clientIP := getClientIP(r)
				allowed := false
				for _, ip := range tenant.Config.AllowedIPs {
					if ip == clientIP {
						allowed = true
						break
					}
				}
				if !allowed {
					defaultTenantErrorHandler(w, r, fmt.Errorf("IP not allowed"))
					return
				}
			}

			// Modify path if base path is set
			if tenant.Config.BasePath != "" {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, tenant.Config.BasePath)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// getClientIP extracts client IP from request.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// HasFeature checks if tenant has a feature enabled.
func HasFeature(ctx context.Context, feature string) bool {
	tenant := GetTenantFromContext(ctx)
	if tenant == nil {
		return false
	}
	return tenant.Config.Features[feature]
}

// FeatureMiddleware returns middleware that requires a feature.
func FeatureMiddleware(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasFeature(r.Context(), feature) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "feature not available: " + feature,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
