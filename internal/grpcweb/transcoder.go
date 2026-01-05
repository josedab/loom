// Package grpcweb provides gRPC-Web transcoding for HTTP/JSON to gRPC.
package grpcweb

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Transcoder handles HTTP/JSON to gRPC-Web transcoding.
type Transcoder struct {
	// services maps service names to their methods
	services map[string]*ServiceDescriptor
	// upstreams maps service names to upstream addresses
	upstreams map[string]string
	// httpClient for making gRPC-Web requests
	httpClient *http.Client
	// logger for transcoding events
	logger *slog.Logger
	mu     sync.RWMutex
}

// ServiceDescriptor describes a gRPC service.
type ServiceDescriptor struct {
	// Name is the fully qualified service name
	Name string `json:"name" yaml:"name"`
	// Methods maps method names to descriptors
	Methods map[string]*MethodDescriptor `json:"methods" yaml:"methods"`
}

// MethodDescriptor describes a gRPC method.
type MethodDescriptor struct {
	// Name of the method
	Name string `json:"name" yaml:"name"`
	// HTTPPath is the HTTP endpoint for this method
	HTTPPath string `json:"http_path" yaml:"http_path"`
	// HTTPMethod is the HTTP method (GET, POST, etc.)
	HTTPMethod string `json:"http_method" yaml:"http_method"`
	// RequestType is the protobuf message type name
	RequestType string `json:"request_type" yaml:"request_type"`
	// ResponseType is the protobuf message type name
	ResponseType string `json:"response_type" yaml:"response_type"`
	// ClientStreaming indicates client streaming
	ClientStreaming bool `json:"client_streaming" yaml:"client_streaming"`
	// ServerStreaming indicates server streaming
	ServerStreaming bool `json:"server_streaming" yaml:"server_streaming"`
	// PathParams maps URL path segments to message fields
	PathParams map[string]string `json:"path_params" yaml:"path_params"`
	// QueryParams maps URL query params to message fields
	QueryParams []string `json:"query_params" yaml:"query_params"`
	// BodyField is the field name containing the body (* for whole message)
	BodyField string `json:"body_field" yaml:"body_field"`
}

// Config configures the transcoder.
type Config struct {
	// Services to expose
	Services []ServiceDescriptor `json:"services" yaml:"services"`
	// DefaultUpstream is used when service-specific upstream is not set
	DefaultUpstream string `json:"default_upstream" yaml:"default_upstream"`
	// Upstreams maps service names to addresses
	Upstreams map[string]string `json:"upstreams" yaml:"upstreams"`
	// Timeout for gRPC calls
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// Logger for events
	Logger *slog.Logger
}

// New creates a new Transcoder.
func New(cfg Config) *Transcoder {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	t := &Transcoder{
		services:  make(map[string]*ServiceDescriptor),
		upstreams: make(map[string]string),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: cfg.Logger,
	}

	// Register services
	for _, svc := range cfg.Services {
		t.RegisterService(&svc)
	}

	// Set upstreams
	for name, addr := range cfg.Upstreams {
		t.upstreams[name] = addr
	}
	if cfg.DefaultUpstream != "" {
		t.upstreams["_default"] = cfg.DefaultUpstream
	}

	return t
}

// RegisterService registers a gRPC service.
func (t *Transcoder) RegisterService(svc *ServiceDescriptor) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.services[svc.Name] = svc
}

// SetUpstream sets the upstream address for a service.
func (t *Transcoder) SetUpstream(service, address string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.upstreams[service] = address
}

// Handler returns an HTTP handler for the transcoder.
func (t *Transcoder) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find matching method
		svc, method, pathParams := t.matchRequest(r)
		if method == nil {
			http.Error(w, "Method not found", http.StatusNotFound)
			return
		}

		// Get upstream
		upstream := t.getUpstream(svc.Name)
		if upstream == "" {
			http.Error(w, "No upstream configured", http.StatusBadGateway)
			return
		}

		// Build gRPC request
		grpcReq, err := t.buildGRPCRequest(r, method, pathParams)
		if err != nil {
			t.logger.Debug("failed to build gRPC request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Execute gRPC call
		if method.ServerStreaming {
			t.handleServerStreaming(w, r, upstream, svc.Name, method.Name, grpcReq)
		} else {
			t.handleUnary(w, r, upstream, svc.Name, method.Name, grpcReq)
		}
	})
}

// matchRequest finds the service and method for an HTTP request.
func (t *Transcoder) matchRequest(r *http.Request) (*ServiceDescriptor, *MethodDescriptor, map[string]string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	path := r.URL.Path
	method := r.Method

	for _, svc := range t.services {
		for _, m := range svc.Methods {
			if m.HTTPMethod != "" && !strings.EqualFold(m.HTTPMethod, method) {
				continue
			}

			pathParams := matchPath(path, m.HTTPPath)
			if pathParams != nil {
				return svc, m, pathParams
			}
		}
	}

	return nil, nil, nil
}

// matchPath matches a path against a pattern with path parameters.
// Pattern: /api/users/{user_id}/posts/{post_id}
// Returns: map[string]string{"user_id": "123", "post_id": "456"}
func matchPath(path, pattern string) map[string]string {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(pathParts) != len(patternParts) {
		return nil
	}

	params := make(map[string]string)

	for i, pp := range patternParts {
		if strings.HasPrefix(pp, "{") && strings.HasSuffix(pp, "}") {
			// Path parameter
			paramName := pp[1 : len(pp)-1]
			params[paramName] = pathParts[i]
		} else if pp != pathParts[i] {
			return nil
		}
	}

	return params
}

// getUpstream returns the upstream address for a service.
func (t *Transcoder) getUpstream(service string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if addr, ok := t.upstreams[service]; ok {
		return addr
	}
	return t.upstreams["_default"]
}

// buildGRPCRequest constructs the gRPC message from HTTP request.
func (t *Transcoder) buildGRPCRequest(r *http.Request, method *MethodDescriptor, pathParams map[string]string) ([]byte, error) {
	msg := make(map[string]interface{})

	// Add path parameters
	for urlParam, fieldName := range method.PathParams {
		if value, ok := pathParams[urlParam]; ok {
			setNestedField(msg, fieldName, value)
		}
	}

	// Add query parameters
	for _, param := range method.QueryParams {
		if values := r.URL.Query()[param]; len(values) > 0 {
			if len(values) == 1 {
				setNestedField(msg, param, values[0])
			} else {
				setNestedField(msg, param, values)
			}
		}
	}

	// Parse body
	if r.Body != nil && r.ContentLength > 0 {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("parsing request body: %w", err)
		}

		if method.BodyField == "*" || method.BodyField == "" {
			// Merge body into message
			for k, v := range body {
				msg[k] = v
			}
		} else {
			// Set body at specific field
			setNestedField(msg, method.BodyField, body)
		}
	}

	// Serialize to JSON (will be converted to protobuf by gRPC-Web)
	return json.Marshal(msg)
}

// setNestedField sets a nested field in a map.
func setNestedField(msg map[string]interface{}, field string, value interface{}) {
	parts := strings.Split(field, ".")
	current := msg

	for _, part := range parts[:len(parts)-1] {
		if _, ok := current[part]; !ok {
			current[part] = make(map[string]interface{})
		}
		current = current[part].(map[string]interface{})
	}

	current[parts[len(parts)-1]] = value
}

// handleUnary handles a unary gRPC call.
func (t *Transcoder) handleUnary(w http.ResponseWriter, r *http.Request, upstream, service, method string, reqBody []byte) {
	// Build gRPC-Web request
	grpcPath := fmt.Sprintf("/%s/%s", service, method)
	grpcReq, err := t.buildGRPCWebRequest(r.Context(), upstream, grpcPath, reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward headers
	for key, values := range r.Header {
		if isForwardableHeader(key) {
			for _, v := range values {
				grpcReq.Header.Add(key, v)
			}
		}
	}

	// Execute request
	resp, err := t.httpClient.Do(grpcReq)
	if err != nil {
		t.logger.Error("gRPC request failed", "error", err)
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Parse gRPC-Web response
	jsonResp, grpcStatus, err := t.parseGRPCWebResponse(resp)
	if err != nil {
		t.logger.Error("failed to parse gRPC response", "error", err)
		http.Error(w, "Invalid gRPC response", http.StatusBadGateway)
		return
	}

	// Map gRPC status to HTTP status
	httpStatus := grpcStatusToHTTP(grpcStatus)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-gRPC-Status", fmt.Sprintf("%d", grpcStatus))
	w.WriteHeader(httpStatus)
	w.Write(jsonResp)
}

// handleServerStreaming handles a server-streaming gRPC call.
func (t *Transcoder) handleServerStreaming(w http.ResponseWriter, r *http.Request, upstream, service, method string, reqBody []byte) {
	// Build gRPC-Web request
	grpcPath := fmt.Sprintf("/%s/%s", service, method)
	grpcReq, err := t.buildGRPCWebRequest(r.Context(), upstream, grpcPath, reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Execute request
	resp, err := t.httpClient.Do(grpcReq)
	if err != nil {
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Set up SSE streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Parse streaming response
	if err := t.streamGRPCWebResponse(w, flusher, resp.Body); err != nil {
		t.logger.Debug("streaming error", "error", err)
	}
}

// buildGRPCWebRequest creates a gRPC-Web HTTP request.
func (t *Transcoder) buildGRPCWebRequest(ctx context.Context, upstream, path string, body []byte) (*http.Request, error) {
	// Frame the message (gRPC-Web format)
	framedBody := frameGRPCMessage(body)

	url := fmt.Sprintf("http://%s%s", upstream, path)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(framedBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/grpc-web+json")
	req.Header.Set("Accept", "application/grpc-web+json")
	req.Header.Set("X-Grpc-Web", "1")

	return req, nil
}

// frameGRPCMessage frames a message in gRPC-Web format.
// Format: 1 byte flags + 4 bytes length + message
func frameGRPCMessage(msg []byte) []byte {
	frame := make([]byte, 5+len(msg))
	frame[0] = 0 // Data frame (not compressed)
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg)))
	copy(frame[5:], msg)
	return frame
}

// parseGRPCWebResponse parses a gRPC-Web response.
func (t *Transcoder) parseGRPCWebResponse(resp *http.Response) ([]byte, int, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	// Check for trailers-only response
	if len(body) == 0 {
		status := 0
		if s := resp.Header.Get("Grpc-Status"); s != "" {
			fmt.Sscanf(s, "%d", &status)
		}
		return nil, status, nil
	}

	// Parse framed response
	messages, trailers, err := parseGRPCFrames(body)
	if err != nil {
		return nil, 0, err
	}

	// Get gRPC status from trailers
	status := 0
	if s, ok := trailers["grpc-status"]; ok {
		fmt.Sscanf(s, "%d", &status)
	}

	// Return first message (for unary)
	if len(messages) > 0 {
		return messages[0], status, nil
	}

	return nil, status, nil
}

// parseGRPCFrames parses gRPC-Web frames from response body.
func parseGRPCFrames(body []byte) ([][]byte, map[string]string, error) {
	var messages [][]byte
	trailers := make(map[string]string)

	offset := 0
	for offset < len(body) {
		if offset+5 > len(body) {
			break
		}

		flags := body[offset]
		length := binary.BigEndian.Uint32(body[offset+1 : offset+5])
		offset += 5

		if offset+int(length) > len(body) {
			break
		}

		data := body[offset : offset+int(length)]
		offset += int(length)

		if flags&0x80 != 0 {
			// Trailer frame
			parseTrailers(data, trailers)
		} else {
			// Data frame
			messages = append(messages, data)
		}
	}

	return messages, trailers, nil
}

// parseTrailers parses gRPC trailers from a trailer frame.
func parseTrailers(data []byte, trailers map[string]string) {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if parts := strings.SplitN(line, ": ", 2); len(parts) == 2 {
			trailers[strings.ToLower(parts[0])] = parts[1]
		}
	}
}

// streamGRPCWebResponse streams gRPC-Web frames as SSE events.
func (t *Transcoder) streamGRPCWebResponse(w http.ResponseWriter, flusher http.Flusher, body io.Reader) error {
	// Buffer for reading frames
	header := make([]byte, 5)

	for {
		// Read frame header
		_, err := io.ReadFull(body, header)
		if err == io.EOF {
			// Send done event
			fmt.Fprintf(w, "event: done\ndata: {}\n\n")
			flusher.Flush()
			return nil
		}
		if err != nil {
			return err
		}

		flags := header[0]
		length := binary.BigEndian.Uint32(header[1:5])

		// Read frame data
		data := make([]byte, length)
		if _, err := io.ReadFull(body, data); err != nil {
			return err
		}

		if flags&0x80 != 0 {
			// Trailer frame - parse and send as event
			trailers := make(map[string]string)
			parseTrailers(data, trailers)
			trailerJSON, _ := json.Marshal(trailers)
			fmt.Fprintf(w, "event: trailers\ndata: %s\n\n", trailerJSON)
		} else {
			// Data frame - send as message event
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
		}
		flusher.Flush()
	}
}

// grpcStatusToHTTP maps gRPC status codes to HTTP status codes.
func grpcStatusToHTTP(grpcStatus int) int {
	switch grpcStatus {
	case 0: // OK
		return http.StatusOK
	case 1: // CANCELLED
		return http.StatusRequestTimeout
	case 2: // UNKNOWN
		return http.StatusInternalServerError
	case 3: // INVALID_ARGUMENT
		return http.StatusBadRequest
	case 4: // DEADLINE_EXCEEDED
		return http.StatusGatewayTimeout
	case 5: // NOT_FOUND
		return http.StatusNotFound
	case 6: // ALREADY_EXISTS
		return http.StatusConflict
	case 7: // PERMISSION_DENIED
		return http.StatusForbidden
	case 8: // RESOURCE_EXHAUSTED
		return http.StatusTooManyRequests
	case 9: // FAILED_PRECONDITION
		return http.StatusPreconditionFailed
	case 10: // ABORTED
		return http.StatusConflict
	case 11: // OUT_OF_RANGE
		return http.StatusBadRequest
	case 12: // UNIMPLEMENTED
		return http.StatusNotImplemented
	case 13: // INTERNAL
		return http.StatusInternalServerError
	case 14: // UNAVAILABLE
		return http.StatusServiceUnavailable
	case 15: // DATA_LOSS
		return http.StatusInternalServerError
	case 16: // UNAUTHENTICATED
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

// isForwardableHeader checks if a header should be forwarded.
func isForwardableHeader(key string) bool {
	key = strings.ToLower(key)
	// Don't forward hop-by-hop headers
	switch key {
	case "connection", "keep-alive", "transfer-encoding", "te",
		"trailer", "upgrade", "content-length", "content-type":
		return false
	}
	return true
}

// HTTPRule defines HTTP mapping for a gRPC method (google.api.http annotation style).
type HTTPRule struct {
	// Pattern is one of: GET, POST, PUT, DELETE, PATCH
	Get    string `json:"get,omitempty" yaml:"get,omitempty"`
	Post   string `json:"post,omitempty" yaml:"post,omitempty"`
	Put    string `json:"put,omitempty" yaml:"put,omitempty"`
	Delete string `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch  string `json:"patch,omitempty" yaml:"patch,omitempty"`
	// Body field name or "*" for whole message
	Body string `json:"body,omitempty" yaml:"body,omitempty"`
	// ResponseBody field name for response
	ResponseBody string `json:"response_body,omitempty" yaml:"response_body,omitempty"`
}

// BuildMethodFromHTTPRule creates a MethodDescriptor from an HTTPRule.
func BuildMethodFromHTTPRule(name string, rule HTTPRule) *MethodDescriptor {
	m := &MethodDescriptor{
		Name:       name,
		BodyField:  rule.Body,
		PathParams: make(map[string]string),
	}

	// Determine HTTP method and path
	switch {
	case rule.Get != "":
		m.HTTPMethod = "GET"
		m.HTTPPath = rule.Get
	case rule.Post != "":
		m.HTTPMethod = "POST"
		m.HTTPPath = rule.Post
	case rule.Put != "":
		m.HTTPMethod = "PUT"
		m.HTTPPath = rule.Put
	case rule.Delete != "":
		m.HTTPMethod = "DELETE"
		m.HTTPPath = rule.Delete
	case rule.Patch != "":
		m.HTTPMethod = "PATCH"
		m.HTTPPath = rule.Patch
	}

	// Extract path parameters
	if m.HTTPPath != "" {
		parts := strings.Split(m.HTTPPath, "/")
		for _, part := range parts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				param := part[1 : len(part)-1]
				// Handle nested field syntax {user.id}
				m.PathParams[param] = strings.ReplaceAll(param, ".", ".")
			}
		}
	}

	return m
}

// Reflection provides dynamic service discovery.
type Reflection struct {
	transcoder *Transcoder
	clients    map[string]*reflectionClient
	mu         sync.RWMutex
}

type reflectionClient struct {
	address  string
	services []string
}

// NewReflection creates a reflection-based transcoder.
func NewReflection(cfg Config) *Reflection {
	return &Reflection{
		transcoder: New(cfg),
		clients:    make(map[string]*reflectionClient),
	}
}

// DiscoverServices discovers services from a gRPC server using reflection.
func (r *Reflection) DiscoverServices(address string) error {
	// This would use gRPC reflection protocol to discover services
	// For now, this is a placeholder that would be implemented with
	// grpc.reflection.v1alpha.ServerReflection
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clients[address] = &reflectionClient{
		address: address,
	}

	return nil
}

// Handler returns the HTTP handler.
func (r *Reflection) Handler() http.Handler {
	return r.transcoder.Handler()
}

// Base64 helpers for gRPC-Web text format.

// encodeBase64 encodes bytes to base64 for gRPC-Web text format.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 string for gRPC-Web text format.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
