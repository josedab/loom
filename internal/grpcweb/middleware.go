package grpcweb

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// MiddlewareConfig configures the gRPC-Web middleware.
type MiddlewareConfig struct {
	// Transcoder handles the actual transcoding
	Transcoder *Transcoder
	// Paths that should be transcoded (prefix match)
	Paths []string
	// Logger for middleware events
	Logger *slog.Logger
}

// Middleware returns HTTP middleware that handles gRPC-Web transcoding.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this path should be transcoded
			if !shouldTranscode(r, cfg.Paths) {
				next.ServeHTTP(w, r)
				return
			}

			// Check content type for gRPC-Web
			contentType := r.Header.Get("Content-Type")
			if isGRPCWeb(contentType) {
				// Already gRPC-Web, pass through with CORS handling
				handleGRPCWebRequest(w, r, cfg.Transcoder, cfg.Logger)
				return
			}

			// Transcode JSON to gRPC-Web
			cfg.Transcoder.Handler().ServeHTTP(w, r)
		})
	}
}

// shouldTranscode checks if a request should be transcoded.
func shouldTranscode(r *http.Request, paths []string) bool {
	if len(paths) == 0 {
		return true
	}

	for _, path := range paths {
		if strings.HasPrefix(r.URL.Path, path) {
			return true
		}
	}

	return false
}

// isGRPCWeb checks if content type indicates gRPC-Web.
func isGRPCWeb(contentType string) bool {
	return strings.HasPrefix(contentType, "application/grpc-web") ||
		strings.HasPrefix(contentType, "application/grpc-web+proto") ||
		strings.HasPrefix(contentType, "application/grpc-web+json") ||
		strings.HasPrefix(contentType, "application/grpc-web-text")
}

// handleGRPCWebRequest handles native gRPC-Web requests with CORS.
func handleGRPCWebRequest(w http.ResponseWriter, r *http.Request, t *Transcoder, logger *slog.Logger) {
	// Handle CORS preflight
	if r.Method == "OPTIONS" {
		handleCORSPreflight(w, r)
		return
	}

	// Add CORS headers
	addCORSHeaders(w, r)

	// Handle the gRPC-Web request
	t.Handler().ServeHTTP(w, r)
}

// handleCORSPreflight handles CORS preflight requests.
func handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
	addCORSHeaders(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// addCORSHeaders adds CORS headers for gRPC-Web.
func addCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-User-Agent, X-Grpc-Web, Grpc-Timeout")
	w.Header().Set("Access-Control-Expose-Headers", "Grpc-Status, Grpc-Message, X-Grpc-Web")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

// ProxyConfig configures the gRPC-Web proxy.
type ProxyConfig struct {
	// Upstream is the gRPC server address
	Upstream string
	// Paths to proxy (empty = all)
	Paths []string
	// Logger for proxy events
	Logger *slog.Logger
}

// Proxy returns middleware that proxies gRPC-Web requests to a gRPC backend.
func Proxy(cfg ProxyConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	client := &http.Client{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this path should be proxied
			if !shouldTranscode(r, cfg.Paths) {
				next.ServeHTTP(w, r)
				return
			}

			contentType := r.Header.Get("Content-Type")
			if !isGRPCWeb(contentType) {
				next.ServeHTTP(w, r)
				return
			}

			// Handle CORS preflight
			if r.Method == "OPTIONS" {
				handleCORSPreflight(w, r)
				return
			}

			// Proxy to upstream
			proxyGRPCWeb(w, r, cfg.Upstream, client, cfg.Logger)
		})
	}
}

// proxyGRPCWeb proxies a gRPC-Web request to an upstream server.
func proxyGRPCWeb(w http.ResponseWriter, r *http.Request, upstream string, client *http.Client, logger *slog.Logger) {
	// Build upstream URL
	upstreamURL := "http://" + upstream + r.URL.Path

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("failed to read request body", "error", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Create upstream request
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		logger.Error("failed to create upstream request", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			upstreamReq.Header.Add(key, v)
		}
	}

	// Execute request
	resp, err := client.Do(upstreamReq)
	if err != nil {
		logger.Error("upstream request failed", "error", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Add CORS headers
	addCORSHeaders(w, r)

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// Copy status and body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// WebSocketBridge provides WebSocket to gRPC-Web streaming bridge.
type WebSocketBridge struct {
	transcoder *Transcoder
	logger     *slog.Logger
}

// NewWebSocketBridge creates a WebSocket bridge for gRPC streaming.
func NewWebSocketBridge(t *Transcoder, logger *slog.Logger) *WebSocketBridge {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebSocketBridge{
		transcoder: t,
		logger:     logger,
	}
}

// ResponseInterceptor allows modifying responses before sending to client.
type ResponseInterceptor interface {
	InterceptResponse(method string, body []byte) ([]byte, error)
}

// JSONFieldMapper maps gRPC field names to JSON field names.
type JSONFieldMapper struct {
	// FieldMappings maps protobuf field names to JSON names
	FieldMappings map[string]string
	// CamelCase enables automatic snake_case to camelCase conversion
	CamelCase bool
}

// MapFields maps field names in a JSON message.
func (m *JSONFieldMapper) MapFields(body []byte) ([]byte, error) {
	if !m.CamelCase && len(m.FieldMappings) == 0 {
		return body, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body, nil // Return original if not valid JSON object
	}

	mapped := m.mapObject(data)
	return json.Marshal(mapped)
}

func (m *JSONFieldMapper) mapObject(data map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		newKey := key

		// Check explicit mapping
		if mapped, ok := m.FieldMappings[key]; ok {
			newKey = mapped
		} else if m.CamelCase {
			newKey = snakeToCamel(key)
		}

		// Recursively map nested objects
		switch v := value.(type) {
		case map[string]interface{}:
			result[newKey] = m.mapObject(v)
		case []interface{}:
			result[newKey] = m.mapArray(v)
		default:
			result[newKey] = value
		}
	}

	return result
}

func (m *JSONFieldMapper) mapArray(data []interface{}) []interface{} {
	result := make([]interface{}, len(data))
	for i, item := range data {
		if obj, ok := item.(map[string]interface{}); ok {
			result[i] = m.mapObject(obj)
		} else {
			result[i] = item
		}
	}
	return result
}

// snakeToCamel converts snake_case to camelCase.
func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// camelToSnake converts camelCase to snake_case.
func camelToSnake(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// Well-known type converters for google.protobuf types.

// ConvertTimestamp converts google.protobuf.Timestamp to RFC3339 string.
func ConvertTimestamp(data map[string]interface{}) string {
	// Protobuf timestamp: {"seconds": 123, "nanos": 456}
	// JSON: "2024-01-01T00:00:00.000000456Z"
	seconds, _ := data["seconds"].(float64)
	nanos, _ := data["nanos"].(float64)

	t := time.Unix(int64(seconds), int64(nanos))
	return t.Format(time.RFC3339Nano)
}

// ConvertDuration converts google.protobuf.Duration to string.
func ConvertDuration(data map[string]interface{}) string {
	seconds, _ := data["seconds"].(float64)
	nanos, _ := data["nanos"].(float64)

	d := time.Duration(seconds)*time.Second + time.Duration(nanos)*time.Nanosecond
	return d.String()
}

