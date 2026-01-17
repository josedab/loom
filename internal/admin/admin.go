// Package admin provides the administrative API for the gateway.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/upstream"
)

// CacheStatsProvider provides cache statistics.
type CacheStatsProvider interface {
	GetStats() CacheStats
}

// CacheStats contains cache statistics.
type CacheStats struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Evictions   uint64 `json:"evictions,omitempty"`
	Expirations uint64 `json:"expirations,omitempty"`
	StaleHits   uint64 `json:"stale_hits,omitempty"`
	Errors      uint64 `json:"errors,omitempty"`
}

// RateLimitStatsProvider provides rate limit statistics.
type RateLimitStatsProvider interface {
	GetRateLimitStats() RateLimitStats
}

// RateLimitStats contains rate limit statistics.
type RateLimitStats struct {
	ActiveKeys   int   `json:"active_keys"`
	TotalAllowed int64 `json:"total_allowed"`
	TotalDenied  int64 `json:"total_denied"`
}

// RouteCreateRequest is the request body for creating a route.
type RouteCreateRequest struct {
	ID       string   `json:"id"`
	Host     string   `json:"host,omitempty"`
	Path     string   `json:"path"`
	Methods  []string `json:"methods,omitempty"`
	Upstream string   `json:"upstream"`
	Plugins  []string `json:"plugins,omitempty"`
	Priority int      `json:"priority,omitempty"`
}

// UpstreamCreateRequest is the request body for creating an upstream.
type UpstreamCreateRequest struct {
	Name         string   `json:"name"`
	Endpoints    []string `json:"endpoints"`
	LoadBalancer string   `json:"load_balancer,omitempty"`
}

// AuthConfig configures admin API authentication.
type AuthConfig struct {
	Enabled bool              // Enable authentication
	Users   map[string]string // Username -> password hash (bcrypt)
	Realm   string            // HTTP Basic Auth realm
}

// Server provides the admin API server.
type Server struct {
	router        *router.Router
	upstreams     *upstream.Manager
	plugins       *plugin.Runtime
	health        *upstream.HealthChecker
	metrics       *metrics.Metrics
	config        *config.Manager
	auth          AuthConfig
	audit         *AuditLogger
	authRateLimit *AuthRateLimiter
	httpServer    *http.Server
	startTime     time.Time

	// Optional stats providers
	cacheStats     CacheStatsProvider
	rateLimitStats RateLimitStatsProvider
}

// NewServer creates a new admin server.
func NewServer(
	r *router.Router,
	u *upstream.Manager,
	p *plugin.Runtime,
	h *upstream.HealthChecker,
	m *metrics.Metrics,
	c *config.Manager,
	auth AuthConfig,
) *Server {
	return NewServerWithOptions(r, u, p, h, m, c, auth, AuditConfig{}, AuthRateLimitConfig{})
}

// NewServerWithAudit creates a new admin server with audit logging.
func NewServerWithAudit(
	r *router.Router,
	u *upstream.Manager,
	p *plugin.Runtime,
	h *upstream.HealthChecker,
	m *metrics.Metrics,
	c *config.Manager,
	auth AuthConfig,
	audit AuditConfig,
) *Server {
	return NewServerWithOptions(r, u, p, h, m, c, auth, audit, AuthRateLimitConfig{})
}

// NewServerWithOptions creates a new admin server with all options.
func NewServerWithOptions(
	r *router.Router,
	u *upstream.Manager,
	p *plugin.Runtime,
	h *upstream.HealthChecker,
	m *metrics.Metrics,
	c *config.Manager,
	auth AuthConfig,
	audit AuditConfig,
	rateLimit AuthRateLimitConfig,
) *Server {
	if auth.Realm == "" {
		auth.Realm = "Gateway Admin"
	}
	return &Server{
		router:        r,
		upstreams:     u,
		plugins:       p,
		health:        h,
		metrics:       m,
		config:        c,
		auth:          auth,
		audit:         NewAuditLogger(audit),
		authRateLimit: NewAuthRateLimiter(rateLimit),
		startTime:     time.Now(),
	}
}

// SetCacheStatsProvider sets the cache statistics provider.
func (s *Server) SetCacheStatsProvider(provider CacheStatsProvider) {
	s.cacheStats = provider
}

// SetRateLimitStatsProvider sets the rate limit statistics provider.
func (s *Server) SetRateLimitStatsProvider(provider RateLimitStatsProvider) {
	s.rateLimitStats = provider
}

// Start starts the admin server.
func (s *Server) Start(address string) error {
	mux := http.NewServeMux()

	// Health endpoints (no auth required)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// Protected endpoints
	protectedMux := http.NewServeMux()

	// Info endpoint
	protectedMux.HandleFunc("/info", s.handleInfo)

	// Routes endpoints
	protectedMux.HandleFunc("/routes", s.handleRoutes)
	protectedMux.HandleFunc("/routes/", s.handleRoute)

	// Upstreams endpoints
	protectedMux.HandleFunc("/upstreams", s.handleUpstreams)
	protectedMux.HandleFunc("/upstreams/", s.handleUpstream)

	// Plugins endpoints
	protectedMux.HandleFunc("/plugins", s.handlePlugins)
	protectedMux.HandleFunc("/plugins/", s.handlePlugin)

	// Metrics endpoint
	protectedMux.Handle("/metrics", s.metrics.Handler())

	// Config endpoint
	protectedMux.HandleFunc("/config", s.handleConfig)

	// Audit endpoint
	protectedMux.HandleFunc("/audit", s.handleAudit)

	// Cache stats endpoint
	protectedMux.HandleFunc("/cache/stats", s.handleCacheStats)

	// Rate limit stats endpoint
	protectedMux.HandleFunc("/ratelimit/stats", s.handleRateLimitStats)

	// Wrap protected endpoints with auth if enabled
	var protectedHandler http.Handler = protectedMux
	if s.auth.Enabled && len(s.auth.Users) > 0 {
		protectedHandler = s.basicAuthMiddleware(protectedMux)
	}

	// Wrap with audit middleware
	protectedHandler = s.audit.AuditMiddleware(protectedHandler, s.getUsernameFromContext)

	// Mount protected handler under root
	mux.Handle("/info", protectedHandler)
	mux.Handle("/routes", protectedHandler)
	mux.Handle("/routes/", protectedHandler)
	mux.Handle("/upstreams", protectedHandler)
	mux.Handle("/upstreams/", protectedHandler)
	mux.Handle("/plugins", protectedHandler)
	mux.Handle("/plugins/", protectedHandler)
	mux.Handle("/metrics", protectedHandler)
	mux.Handle("/config", protectedHandler)
	mux.Handle("/audit", protectedHandler)
	mux.Handle("/cache/", protectedHandler)
	mux.Handle("/ratelimit/", protectedHandler)

	s.httpServer = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// contextKey is the type for context keys.
type contextKey string

const usernameContextKey contextKey = "username"

// basicAuthMiddleware provides HTTP Basic authentication with rate limiting.
func (s *Server) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getAuthClientIP(r)

		// Check if rate limited
		if !s.authRateLimit.CheckAllowed(clientIP) {
			remaining := s.authRateLimit.LockoutRemaining(clientIP)
			s.audit.LogAuthFailure(r, "", "rate_limited")
			w.Header().Set("Retry-After", formatDuration(remaining))
			http.Error(w, "Too many authentication attempts. Please try again later.", http.StatusTooManyRequests)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			s.authRateLimit.RecordAttempt(clientIP, false)
			s.audit.LogAuthFailure(r, "", "no_credentials")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedHash, exists := s.auth.Users[username]
		if !exists {
			// Perform a dummy bcrypt comparison to prevent timing attacks
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy"), []byte(password))
			s.authRateLimit.RecordAttempt(clientIP, false)
			s.audit.LogAuthFailure(r, username, "user_not_found")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Compare the provided password with the stored bcrypt hash
		if err := bcrypt.CompareHashAndPassword([]byte(expectedHash), []byte(password)); err != nil {
			s.authRateLimit.RecordAttempt(clientIP, false)
			s.audit.LogAuthFailure(r, username, "invalid_password")
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Record successful authentication (resets rate limit counter)
		s.authRateLimit.RecordAttempt(clientIP, true)

		// Log successful authentication
		s.audit.LogAuthSuccess(r, username)

		// Store username in context for audit logging
		ctx := context.WithValue(r.Context(), usernameContextKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// formatDuration formats a duration as seconds for Retry-After header.
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

// getUsernameFromContext retrieves the username from the request context.
func (s *Server) getUsernameFromContext(r *http.Request) string {
	if username, ok := r.Context().Value(usernameContextKey).(string); ok {
		return username
	}
	return ""
}

// DefaultBcryptCost is the default cost factor for bcrypt hashing.
// Cost of 10 provides a good balance between security and performance.
const DefaultBcryptCost = 10

// HashPassword hashes a password for storage using bcrypt.
// Returns the bcrypt hash string or an error if hashing fails.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), DefaultBcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword checks if a password matches a bcrypt hash.
// Returns nil if the password matches, or an error otherwise.
func VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Shutdown gracefully shuts down the admin server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleHealth returns the health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// handleReady returns the readiness status.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

// handleInfo returns gateway information.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := map[string]interface{}{
		"version":    "1.0.0",
		"go_version": "go1.22",
		"uptime":     time.Since(s.startTime).String(),
		"routes":     len(s.router.GetRoutes()),
		"upstreams":  len(s.upstreams.GetUpstreams()),
		"plugins":    len(s.plugins.GetLoadedPlugins()),
	}

	json.NewEncoder(w).Encode(info)
}

// handleRoutes handles route listing and creation.
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleRoutesGet(w, r)
	case http.MethodPost:
		s.handleRoutesPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRoutesGet lists all routes.
func (s *Server) handleRoutesGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	routes := s.router.GetRoutes()
	routeInfos := make([]RouteInfo, len(routes))

	for i, route := range routes {
		routeInfos[i] = RouteInfo{
			ID:       route.ID,
			Host:     route.Host,
			Path:     route.Path,
			Methods:  route.Methods,
			Upstream: route.Upstream,
			Plugins:  route.Plugins,
			Priority: route.Priority,
		}
	}

	json.NewEncoder(w).Encode(routeInfos)
}

// handleRoutesPost creates a new route.
func (s *Server) handleRoutesPost(w http.ResponseWriter, r *http.Request) {
	var req RouteCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "Route ID is required", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "Route path is required", http.StatusBadRequest)
		return
	}
	if req.Upstream == "" {
		http.Error(w, "Route upstream is required", http.StatusBadRequest)
		return
	}

	cfg := config.RouteConfig{
		ID:       req.ID,
		Host:     req.Host,
		Path:     req.Path,
		Methods:  req.Methods,
		Upstream: req.Upstream,
		Plugins:  req.Plugins,
		Priority: req.Priority,
	}

	if err := s.router.AddRoute(cfg); err != nil {
		if err == router.ErrRouteAlreadyExists {
			http.Error(w, "Route already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create route: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":      req.ID,
		"message": "Route created successfully",
	})
}

// handleRoute handles individual route operations.
func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request) {
	routeID := r.URL.Path[len("/routes/"):]
	if routeID == "" {
		http.Error(w, "Route ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		route, ok := s.router.GetRoute(routeID)
		if !ok {
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RouteInfo{
			ID:       route.ID,
			Host:     route.Host,
			Path:     route.Path,
			Methods:  route.Methods,
			Upstream: route.Upstream,
			Plugins:  route.Plugins,
			Priority: route.Priority,
		})

	case http.MethodPut:
		var req RouteCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Use the route ID from the URL if not provided in body
		if req.ID == "" {
			req.ID = routeID
		}

		if req.Path == "" {
			http.Error(w, "Route path is required", http.StatusBadRequest)
			return
		}
		if req.Upstream == "" {
			http.Error(w, "Route upstream is required", http.StatusBadRequest)
			return
		}

		cfg := config.RouteConfig{
			ID:       req.ID,
			Host:     req.Host,
			Path:     req.Path,
			Methods:  req.Methods,
			Upstream: req.Upstream,
			Plugins:  req.Plugins,
			Priority: req.Priority,
		}

		if err := s.router.UpdateRoute(routeID, cfg); err != nil {
			if err == router.ErrRouteNotFound {
				http.Error(w, "Route not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update route: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":      req.ID,
			"message": "Route updated successfully",
		})

	case http.MethodDelete:
		if err := s.router.DeleteRoute(routeID); err != nil {
			if err == router.ErrRouteNotFound {
				http.Error(w, "Route not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to delete route: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUpstreams handles upstream listing and creation.
func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleUpstreamsGet(w, r)
	case http.MethodPost:
		s.handleUpstreamsPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUpstreamsGet lists all upstreams.
func (s *Server) handleUpstreamsGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	upstreams := s.upstreams.GetUpstreams()
	upstreamInfos := make([]UpstreamInfo, len(upstreams))

	healthStatus := s.health.GetEndpointHealth()

	for i, u := range upstreams {
		endpoints := make([]EndpointInfo, len(u.Endpoints))
		for j, ep := range u.Endpoints {
			endpoints[j] = EndpointInfo{
				Address:     ep.Address,
				Weight:      ep.Weight,
				Healthy:     ep.IsHealthy(),
				ActiveConns: ep.ActiveConnections(),
			}
		}

		upstreamInfos[i] = UpstreamInfo{
			Name:          u.Name,
			Endpoints:     endpoints,
			CircuitState:  u.Circuit.State().String(),
			HealthStatus:  healthStatus[u.Name],
		}
	}

	json.NewEncoder(w).Encode(upstreamInfos)
}

// handleUpstreamsPost creates a new upstream.
func (s *Server) handleUpstreamsPost(w http.ResponseWriter, r *http.Request) {
	var req UpstreamCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Upstream name is required", http.StatusBadRequest)
		return
	}
	if len(req.Endpoints) == 0 {
		http.Error(w, "At least one endpoint is required", http.StatusBadRequest)
		return
	}

	cfg := config.UpstreamConfig{
		Name:         req.Name,
		Endpoints:    req.Endpoints,
		LoadBalancer: req.LoadBalancer,
	}

	if err := s.upstreams.AddUpstream(cfg); err != nil {
		if err == upstream.ErrUpstreamAlreadyExists {
			http.Error(w, "Upstream already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create upstream: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"name":    req.Name,
		"message": "Upstream created successfully",
	})
}

// handleUpstream handles individual upstream operations.
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	upstreamName := r.URL.Path[len("/upstreams/"):]
	if upstreamName == "" {
		http.Error(w, "Upstream name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		u, ok := s.upstreams.GetUpstream(upstreamName)
		if !ok {
			http.Error(w, "Upstream not found", http.StatusNotFound)
			return
		}

		endpoints := make([]EndpointInfo, len(u.Endpoints))
		for i, ep := range u.Endpoints {
			endpoints[i] = EndpointInfo{
				Address:     ep.Address,
				Weight:      ep.Weight,
				Healthy:     ep.IsHealthy(),
				ActiveConns: ep.ActiveConnections(),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(UpstreamInfo{
			Name:         u.Name,
			Endpoints:    endpoints,
			CircuitState: u.Circuit.State().String(),
		})

	case http.MethodPut:
		var req UpstreamCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Use the upstream name from the URL if not provided in body
		if req.Name == "" {
			req.Name = upstreamName
		}

		if len(req.Endpoints) == 0 {
			http.Error(w, "At least one endpoint is required", http.StatusBadRequest)
			return
		}

		cfg := config.UpstreamConfig{
			Name:         req.Name,
			Endpoints:    req.Endpoints,
			LoadBalancer: req.LoadBalancer,
		}

		if err := s.upstreams.UpdateUpstream(upstreamName, cfg); err != nil {
			if err == upstream.ErrUpstreamNotFound {
				http.Error(w, "Upstream not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to update upstream: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"name":    req.Name,
			"message": "Upstream updated successfully",
		})

	case http.MethodDelete:
		if err := s.upstreams.DeleteUpstream(upstreamName); err != nil {
			if err == upstream.ErrUpstreamNotFound {
				http.Error(w, "Upstream not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to delete upstream: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePlugins handles plugin listing.
func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Use the richer plugin info from runtime
	pluginInfos := s.plugins.GetAllPluginInfo()
	json.NewEncoder(w).Encode(pluginInfos)
}

// handlePlugin handles individual plugin operations.
func (s *Server) handlePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := r.URL.Path[len("/plugins/"):]
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	// Check for reload action: POST /plugins/{name}/reload
	if strings.HasSuffix(pluginName, "/reload") {
		pluginName = strings.TrimSuffix(pluginName, "/reload")
		s.handlePluginReload(w, r, pluginName)
		return
	}

	switch r.Method {
	case http.MethodGet:
		info, ok := s.plugins.GetPluginInfo(pluginName)
		if !ok {
			http.Error(w, "Plugin not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)

	case http.MethodDelete:
		if err := s.plugins.UnloadPlugin(r.Context(), pluginName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePluginReload handles POST /plugins/{name}/reload to hot-reload a plugin from disk.
func (s *Server) handlePluginReload(w http.ResponseWriter, r *http.Request, pluginName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if plugin exists
	info, ok := s.plugins.GetPluginInfo(pluginName)
	if !ok {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	oldVersion := info.Version

	// Reload the plugin
	if err := s.plugins.ReloadPlugin(r.Context(), pluginName); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload plugin: %v", err), http.StatusInternalServerError)
		return
	}

	// Get new info
	newInfo, _ := s.plugins.GetPluginInfo(pluginName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Plugin reloaded successfully",
		"plugin":       pluginName,
		"old_version":  oldVersion,
		"new_version":  newInfo.Version,
		"reloaded_at":  newInfo.LoadedAt,
	})
}

// handleConfig returns the current configuration.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config.Get())
}

// handleAudit returns recent audit log events.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse limit query parameter
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	events := s.audit.GetRecentEvents(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

// handleCacheStats returns cache statistics.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cacheStats == nil {
		http.Error(w, "Cache statistics not available", http.StatusNotImplemented)
		return
	}

	stats := s.cacheStats.GetStats()

	// Calculate hit rate
	var hitRate float64
	total := stats.Hits + stats.Misses
	if total > 0 {
		hitRate = float64(stats.Hits) / float64(total) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hits":        stats.Hits,
		"misses":      stats.Misses,
		"hit_rate":    hitRate,
		"evictions":   stats.Evictions,
		"expirations": stats.Expirations,
		"stale_hits":  stats.StaleHits,
		"errors":      stats.Errors,
	})
}

// handleRateLimitStats returns rate limiter statistics.
func (s *Server) handleRateLimitStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.rateLimitStats == nil {
		http.Error(w, "Rate limit statistics not available", http.StatusNotImplemented)
		return
	}

	stats := s.rateLimitStats.GetRateLimitStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_keys":   stats.ActiveKeys,
		"total_allowed": stats.TotalAllowed,
		"total_denied":  stats.TotalDenied,
	})
}

// RouteInfo represents route information for the API.
type RouteInfo struct {
	ID       string   `json:"id"`
	Host     string   `json:"host,omitempty"`
	Path     string   `json:"path"`
	Methods  []string `json:"methods"`
	Upstream string   `json:"upstream"`
	Plugins  []string `json:"plugins,omitempty"`
	Priority int      `json:"priority"`
}

// UpstreamInfo represents upstream information for the API.
type UpstreamInfo struct {
	Name         string                   `json:"name"`
	Endpoints    []EndpointInfo           `json:"endpoints"`
	CircuitState string                   `json:"circuit_state"`
	HealthStatus []upstream.EndpointHealth `json:"health_status,omitempty"`
}

// EndpointInfo represents endpoint information for the API.
type EndpointInfo struct {
	Address     string `json:"address"`
	Weight      int    `json:"weight"`
	Healthy     bool   `json:"healthy"`
	ActiveConns int64  `json:"active_connections"`
}

