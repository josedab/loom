// Package admin provides the administrative API for the gateway.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/upstream"
)

// AuthConfig configures admin API authentication.
type AuthConfig struct {
	Enabled  bool              // Enable authentication
	Users    map[string]string // Username -> password hash (SHA256 hex)
	Realm    string            // HTTP Basic Auth realm
}

// Server provides the admin API server.
type Server struct {
	router     *router.Router
	upstreams  *upstream.Manager
	plugins    *plugin.Runtime
	health     *upstream.HealthChecker
	metrics    *metrics.Metrics
	config     *config.Manager
	auth       AuthConfig
	httpServer *http.Server
	startTime  time.Time
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
	if auth.Realm == "" {
		auth.Realm = "Gateway Admin"
	}
	return &Server{
		router:    r,
		upstreams: u,
		plugins:   p,
		health:    h,
		metrics:   m,
		config:    c,
		auth:      auth,
		startTime: time.Now(),
	}
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

	// Wrap protected endpoints with auth if enabled
	var protectedHandler http.Handler = protectedMux
	if s.auth.Enabled && len(s.auth.Users) > 0 {
		protectedHandler = s.basicAuthMiddleware(protectedMux)
	}

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

	s.httpServer = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// basicAuthMiddleware provides HTTP Basic authentication.
func (s *Server) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedHash, exists := s.auth.Users[username]
		if !exists {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Hash the provided password and compare
		hash := sha256.Sum256([]byte(password))
		passwordHash := hex.EncodeToString(hash[:])

		if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(passwordHash)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.auth.Realm+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HashPassword hashes a password for storage using SHA256.
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
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

// handleRoutes handles route listing.
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUpstreams handles upstream listing.
func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	pluginNames := s.plugins.GetLoadedPlugins()
	pluginInfos := make([]PluginInfo, len(pluginNames))

	for i, name := range pluginNames {
		p, ok := s.plugins.GetPlugin(name)
		if !ok {
			continue
		}

		pluginInfos[i] = PluginInfo{
			Name:     name,
			Phase:    p.Config.Phase.String(),
			Priority: p.Config.Priority,
			Path:     p.Config.Path,
		}
	}

	json.NewEncoder(w).Encode(pluginInfos)
}

// handlePlugin handles individual plugin operations.
func (s *Server) handlePlugin(w http.ResponseWriter, r *http.Request) {
	pluginName := r.URL.Path[len("/plugins/"):]
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok := s.plugins.GetPlugin(pluginName)
		if !ok {
			http.Error(w, "Plugin not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PluginInfo{
			Name:     pluginName,
			Phase:    p.Config.Phase.String(),
			Priority: p.Config.Priority,
			Path:     p.Config.Path,
		})

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

// handleConfig returns the current configuration.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config.Get())
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

// PluginInfo represents plugin information for the API.
type PluginInfo struct {
	Name     string `json:"name"`
	Phase    string `json:"phase"`
	Priority int    `json:"priority"`
	Path     string `json:"path"`
}
