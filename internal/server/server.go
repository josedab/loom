// Package server provides the main loom server orchestration.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/josedab/loom/internal/admin"
	"github.com/josedab/loom/internal/config"
	"github.com/josedab/loom/internal/listener"
	"github.com/josedab/loom/internal/metrics"
	"github.com/josedab/loom/internal/middleware"
	"github.com/josedab/loom/internal/plugin"
	"github.com/josedab/loom/internal/proxy"
	"github.com/josedab/loom/internal/router"
	"github.com/josedab/loom/internal/tracing"
	"github.com/josedab/loom/internal/upstream"
)

// Loom represents the complete loom server.
type Loom struct {
	config        *config.Manager
	router        *router.Router
	upstreams     *upstream.Manager
	healthCheck   *upstream.HealthChecker
	pluginRT      *plugin.Runtime
	pipeline      *plugin.Pipeline
	listeners     *listener.Manager
	adminServer   *admin.Server
	metrics       *metrics.Metrics
	rateLimiter   *middleware.RateLimiter
	tracing       *tracing.Provider
	wsHandler     *proxy.WebSocketHandler
	logger        *slog.Logger
}

// Run starts the loom server with the given configuration file.
func Run(ctx context.Context, configPath string) error {
	logger := slog.Default()
	logger.Info("starting loom", "config", configPath)

	// Load configuration
	cfgManager, err := config.NewManager(configPath)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	defer cfgManager.Close()

	cfg := cfgManager.Get()

	// Initialize metrics
	m := metrics.New()

	// Initialize router
	r := router.New()
	if err := r.Configure(cfg.Routes); err != nil {
		return fmt.Errorf("configuring routes: %w", err)
	}

	// Initialize upstream manager
	u := upstream.NewManager()
	if err := u.Configure(cfg.Upstreams); err != nil {
		return fmt.Errorf("configuring upstreams: %w", err)
	}

	// Initialize health checker
	hc := upstream.NewHealthChecker(u)
	hc.Configure(cfg.Upstreams)

	// Initialize plugin runtime
	pluginCfg := plugin.DefaultRuntimeConfig()
	pluginRT, err := plugin.NewRuntime(ctx, pluginCfg)
	if err != nil {
		return fmt.Errorf("initializing plugin runtime: %w", err)
	}
	defer pluginRT.Close(ctx)

	// Load plugins (if any exist)
	if err := pluginRT.Configure(ctx, cfg.Plugins); err != nil {
		// Log warning but don't fail - plugins might not exist
		logger.Warn("loading plugins", "error", err)
	}

	// Initialize plugin pipeline
	pipeline := plugin.NewPipeline(pluginRT)

	// Build plugin chains for routes
	for _, route := range cfg.Routes {
		pipeline.BuildChain(route.ID, route.Plugins)
	}

	// Initialize tracing if enabled
	var tracingProvider *tracing.Provider
	if cfg.Tracing.Enabled {
		tracingCfg := tracing.Config{
			Enabled:      true,
			Endpoint:     cfg.Tracing.Endpoint,
			ServiceName:  cfg.Tracing.ServiceName,
			SampleRate:   cfg.Tracing.SampleRate,
			BatchTimeout: config.ParseDuration(cfg.Tracing.BatchTimeout, 5*time.Second),
		}
		if tracingCfg.ServiceName == "" {
			tracingCfg.ServiceName = "loom"
		}
		if tracingCfg.Endpoint == "" {
			tracingCfg.Endpoint = "localhost:4317"
		}
		var err error
		tracingProvider, err = tracing.NewProvider(ctx, tracingCfg)
		if err != nil {
			logger.Warn("initializing tracing", "error", err)
		} else {
			logger.Info("tracing enabled", "endpoint", tracingCfg.Endpoint)
		}
	}

	// Initialize rate limiter if enabled
	var rateLimiter *middleware.RateLimiter
	if cfg.RateLimit.Enabled {
		rateLimiter = middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:            cfg.RateLimit.Rate,
			Burst:           cfg.RateLimit.Burst,
			CleanupInterval: config.ParseDuration(cfg.RateLimit.CleanupInterval, 5*time.Minute),
		})
		logger.Info("rate limiting enabled", "rate", cfg.RateLimit.Rate, "burst", cfg.RateLimit.Burst)
	}

	// Initialize WebSocket handler
	wsHandler := proxy.NewWebSocketHandler()

	// Create proxy handler
	handler := proxy.NewHandler(r, u, pipeline, m)

	// Build middleware chain
	middlewares := []func(http.Handler) http.Handler{
		proxy.RecoveryMiddleware(),
		proxy.RequestIDMiddleware(),
		m.Middleware(),
	}

	// Add tracing middleware if enabled
	if tracingProvider != nil {
		middlewares = append(middlewares, tracingProvider.Middleware())
	}

	// Add rate limiting middleware if enabled
	if rateLimiter != nil {
		middlewares = append(middlewares, rateLimiter.Middleware())
	}

	// Add CORS middleware if enabled
	if cfg.CORS.Enabled {
		allowOrigin := "*"
		if len(cfg.CORS.AllowOrigins) > 0 {
			allowOrigin = cfg.CORS.AllowOrigins[0]
		}
		middlewares = append(middlewares, proxy.CORSMiddleware(allowOrigin))
		logger.Info("CORS enabled", "origin", allowOrigin)
	}

	// Add WebSocket middleware
	middlewares = append(middlewares, proxy.WebSocketMiddleware(wsHandler, func(req *http.Request) string {
		match := r.Match(req)
		if match == nil {
			return ""
		}
		return u.GetUpstreamAddress(match.Route.Upstream)
	}))

	// Apply middleware chain
	finalHandler := proxy.MiddlewareChain(handler, middlewares...)

	// Initialize listener manager
	listenerMgr := listener.NewManager(finalHandler)
	if err := listenerMgr.Configure(cfg.Listeners); err != nil {
		return fmt.Errorf("configuring listeners: %w", err)
	}

	// Create loom instance
	lm := &Loom{
		config:        cfgManager,
		router:        r,
		upstreams:     u,
		healthCheck:   hc,
		pluginRT:      pluginRT,
		pipeline:      pipeline,
		listeners:     listenerMgr,
		metrics:       m,
		rateLimiter:   rateLimiter,
		tracing:       tracingProvider,
		wsHandler:     wsHandler,
		logger:        logger,
	}

	// Setup hot reload
	cfgManager.OnChange(func(newCfg *config.Config) {
		lm.reload(ctx, newCfg)
	})

	// Start health checks
	hc.Start(ctx)
	defer hc.Stop()

	// Start admin server
	if cfg.Admin.Enabled {
		adminAuth := admin.AuthConfig{
			Enabled: cfg.Admin.Auth.Enabled,
			Users:   cfg.Admin.Auth.Users,
			Realm:   cfg.Admin.Auth.Realm,
		}
		lm.adminServer = admin.NewServer(r, u, pluginRT, hc, m, cfgManager, adminAuth)
		go func() {
			logger.Info("starting admin server", "address", cfg.Admin.Address)
			if err := lm.adminServer.Start(cfg.Admin.Address); err != nil {
				logger.Error("admin server error", "error", err)
			}
		}()
	}

	// Start listeners
	logger.Info("starting listeners", "count", lm.listeners.ListenerCount())
	if err := lm.listeners.Start(ctx); err != nil {
		return fmt.Errorf("starting listeners: %w", err)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("shutdown signal received")

	// Graceful shutdown
	return lm.shutdown()
}

// reload handles configuration hot-reload.
func (lm *Loom) reload(ctx context.Context, cfg *config.Config) {
	lm.logger.Info("reloading configuration")

	// Reload routes
	if err := lm.router.Configure(cfg.Routes); err != nil {
		lm.logger.Error("reloading routes", "error", err)
		return
	}

	// Reload upstreams
	if err := lm.upstreams.Configure(cfg.Upstreams); err != nil {
		lm.logger.Error("reloading upstreams", "error", err)
		return
	}

	// Reload health check configuration
	lm.healthCheck.Configure(cfg.Upstreams)

	// Reload plugins
	if err := lm.pluginRT.Configure(ctx, cfg.Plugins); err != nil {
		lm.logger.Warn("reloading plugins", "error", err)
	}

	// Rebuild plugin chains
	for _, route := range cfg.Routes {
		lm.pipeline.BuildChain(route.ID, route.Plugins)
	}

	lm.logger.Info("configuration reloaded successfully")
}

// shutdown performs graceful shutdown.
func (lm *Loom) shutdown() error {
	lm.logger.Info("shutting down loom")

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	// Shutdown admin server
	if lm.adminServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := lm.adminServer.Shutdown(context.Background()); err != nil {
				errCh <- fmt.Errorf("admin server shutdown: %w", err)
			}
		}()
	}

	// Shutdown listeners
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := lm.listeners.Shutdown(context.Background()); err != nil {
			errCh <- fmt.Errorf("listener shutdown: %w", err)
		}
	}()

	// Shutdown tracing
	if lm.tracing != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := lm.tracing.Shutdown(ctx); err != nil {
				errCh <- fmt.Errorf("tracing shutdown: %w", err)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Collect errors
	for err := range errCh {
		lm.logger.Error("shutdown error", "error", err)
	}

	// Stop rate limiter
	if lm.rateLimiter != nil {
		lm.rateLimiter.Stop()
	}

	// Close upstream connections
	lm.upstreams.Close()

	lm.logger.Info("loom shutdown complete")
	return nil
}
