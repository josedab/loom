// Package admin provides the administrative API for the gateway.
package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event.
type AuditEventType string

const (
	// AuditEventAuthSuccess indicates successful authentication.
	AuditEventAuthSuccess AuditEventType = "auth_success"
	// AuditEventAuthFailure indicates failed authentication.
	AuditEventAuthFailure AuditEventType = "auth_failure"
	// AuditEventAPIAccess indicates an API access event.
	AuditEventAPIAccess AuditEventType = "api_access"
	// AuditEventPluginUnload indicates a plugin was unloaded.
	AuditEventPluginUnload AuditEventType = "plugin_unload"
)

// AuditEvent represents a single audit log entry.
type AuditEvent struct {
	Timestamp   time.Time      `json:"timestamp"`
	EventType   AuditEventType `json:"event_type"`
	Username    string         `json:"username,omitempty"`
	ClientIP    string         `json:"client_ip"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	StatusCode  int            `json:"status_code,omitempty"`
	Duration    time.Duration  `json:"duration_ms,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	ResourceID  string         `json:"resource_id,omitempty"`
	Action      string         `json:"action,omitempty"`
	FailReason  string         `json:"fail_reason,omitempty"`
}

// AuditLogger handles audit logging for the admin API.
type AuditLogger struct {
	logger   *slog.Logger
	enabled  bool
	mu       sync.RWMutex
	events   []AuditEvent // ring buffer for recent events
	maxEvents int
	eventIdx  int
}

// AuditConfig configures the audit logger.
type AuditConfig struct {
	Enabled    bool      // Enable audit logging
	Output     io.Writer // Output destination (nil for default slog)
	MaxHistory int       // Maximum events to keep in memory (default 1000)
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(cfg AuditConfig) *AuditLogger {
	maxEvents := cfg.MaxHistory
	if maxEvents <= 0 {
		maxEvents = 1000
	}

	var logger *slog.Logger
	if cfg.Output != nil {
		logger = slog.New(slog.NewJSONHandler(cfg.Output, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	} else {
		logger = slog.Default()
	}

	return &AuditLogger{
		logger:    logger,
		enabled:   cfg.Enabled,
		events:    make([]AuditEvent, maxEvents),
		maxEvents: maxEvents,
	}
}

// Log records an audit event.
func (a *AuditLogger) Log(event AuditEvent) {
	if !a.enabled {
		return
	}

	// Store in ring buffer
	a.mu.Lock()
	a.events[a.eventIdx] = event
	a.eventIdx = (a.eventIdx + 1) % a.maxEvents
	a.mu.Unlock()

	// Write to structured log
	attrs := []slog.Attr{
		slog.String("event_type", string(event.EventType)),
		slog.String("client_ip", event.ClientIP),
		slog.String("method", event.Method),
		slog.String("path", event.Path),
	}

	if event.Username != "" {
		attrs = append(attrs, slog.String("username", event.Username))
	}
	if event.StatusCode != 0 {
		attrs = append(attrs, slog.Int("status_code", event.StatusCode))
	}
	if event.Duration > 0 {
		attrs = append(attrs, slog.Int64("duration_ms", event.Duration.Milliseconds()))
	}
	if event.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", event.UserAgent))
	}
	if event.Resource != "" {
		attrs = append(attrs, slog.String("resource", event.Resource))
	}
	if event.ResourceID != "" {
		attrs = append(attrs, slog.String("resource_id", event.ResourceID))
	}
	if event.Action != "" {
		attrs = append(attrs, slog.String("action", event.Action))
	}
	if event.FailReason != "" {
		attrs = append(attrs, slog.String("fail_reason", event.FailReason))
	}

	a.logger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}

// LogAuthSuccess logs a successful authentication.
func (a *AuditLogger) LogAuthSuccess(r *http.Request, username string) {
	a.Log(AuditEvent{
		Timestamp: time.Now(),
		EventType: AuditEventAuthSuccess,
		Username:  username,
		ClientIP:  getClientIP(r),
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
	})
}

// LogAuthFailure logs a failed authentication attempt.
func (a *AuditLogger) LogAuthFailure(r *http.Request, username, reason string) {
	a.Log(AuditEvent{
		Timestamp:  time.Now(),
		EventType:  AuditEventAuthFailure,
		Username:   username,
		ClientIP:   getClientIP(r),
		Method:     r.Method,
		Path:       r.URL.Path,
		UserAgent:  r.UserAgent(),
		FailReason: reason,
	})
}

// LogAPIAccess logs an API access event.
func (a *AuditLogger) LogAPIAccess(r *http.Request, username string, statusCode int, duration time.Duration) {
	resource, resourceID, action := parseAPIRequest(r)

	a.Log(AuditEvent{
		Timestamp:  time.Now(),
		EventType:  AuditEventAPIAccess,
		Username:   username,
		ClientIP:   getClientIP(r),
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: statusCode,
		Duration:   duration,
		UserAgent:  r.UserAgent(),
		Resource:   resource,
		ResourceID: resourceID,
		Action:     action,
	})
}

// GetRecentEvents returns the most recent audit events.
func (a *AuditLogger) GetRecentEvents(limit int) []AuditEvent {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if limit <= 0 || limit > a.maxEvents {
		limit = a.maxEvents
	}

	result := make([]AuditEvent, 0, limit)

	// Read backwards from current position
	for i := 0; i < limit; i++ {
		idx := (a.eventIdx - 1 - i + a.maxEvents) % a.maxEvents
		event := a.events[idx]
		if event.Timestamp.IsZero() {
			break
		}
		result = append(result, event)
	}

	return result
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// parseAPIRequest extracts resource information from the request.
func parseAPIRequest(r *http.Request) (resource, resourceID, action string) {
	path := r.URL.Path

	// Determine action from HTTP method
	switch r.Method {
	case http.MethodGet:
		action = "read"
	case http.MethodPost:
		action = "create"
	case http.MethodPut, http.MethodPatch:
		action = "update"
	case http.MethodDelete:
		action = "delete"
	default:
		action = r.Method
	}

	// Parse resource from path
	switch {
	case strings.HasPrefix(path, "/routes/"):
		resource = "route"
		resourceID = strings.TrimPrefix(path, "/routes/")
	case path == "/routes":
		resource = "routes"
		action = "list"
	case strings.HasPrefix(path, "/upstreams/"):
		resource = "upstream"
		resourceID = strings.TrimPrefix(path, "/upstreams/")
	case path == "/upstreams":
		resource = "upstreams"
		action = "list"
	case strings.HasPrefix(path, "/plugins/"):
		resource = "plugin"
		resourceID = strings.TrimPrefix(path, "/plugins/")
	case path == "/plugins":
		resource = "plugins"
		action = "list"
	case path == "/config":
		resource = "config"
	case path == "/info":
		resource = "info"
	case path == "/metrics":
		resource = "metrics"
	case path == "/health":
		resource = "health"
	case path == "/ready":
		resource = "ready"
	default:
		resource = "unknown"
	}

	return resource, resourceID, action
}

// auditResponseWriter wraps http.ResponseWriter to capture status code.
type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *auditResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// AuditMiddleware wraps a handler to log all requests.
func (a *AuditLogger) AuditMiddleware(next http.Handler, getUsername func(*http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		aw := &auditResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(aw, r)

		username := ""
		if getUsername != nil {
			username = getUsername(r)
		}

		a.LogAPIAccess(r, username, aw.statusCode, time.Since(start))
	})
}
