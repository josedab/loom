package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// GatewayHandler provides HTTP handling for GraphQL requests.
type GatewayHandler struct {
	gateway  *Gateway
	upstream string
	client   *http.Client
	stats    *GatewayStatsCollector
	logger   *slog.Logger
}

// GatewayHandlerConfig configures the GraphQL handler.
type GatewayHandlerConfig struct {
	// Gateway is the GraphQL gateway instance.
	Gateway *Gateway
	// Upstream is the GraphQL backend URL.
	Upstream string
	// Client is the HTTP client for upstream requests.
	Client *http.Client
	// Logger for handler events.
	Logger *slog.Logger
}

// NewGatewayHandler creates a new GraphQL HTTP handler.
func NewGatewayHandler(config GatewayHandlerConfig) *GatewayHandler {
	if config.Client == nil {
		config.Client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	var apqCache *APQCache
	if config.Gateway != nil {
		apqCache = config.Gateway.apqCache
	}

	return &GatewayHandler{
		gateway:  config.Gateway,
		upstream: config.Upstream,
		client:   config.Client,
		stats:    NewGatewayStatsCollector(apqCache),
		logger:   config.Logger,
	}
}

// ServeHTTP handles GraphQL HTTP requests.
func (h *GatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.stats.RecordRequest()

	// Handle batch requests first (before body is consumed)
	if batch, ok := h.parseBatchRequest(r); ok {
		h.handleBatch(w, r, batch)
		return
	}

	// Parse the request
	req, err := h.parseRequest(r)
	if err != nil {
		h.stats.RecordError()
		h.writeError(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Process through gateway
	ctx := r.Context()
	processedReq, analysis, err := h.gateway.ProcessRequest(ctx, req)
	if err != nil {
		h.handleProcessError(w, err, analysis)
		return
	}

	// Record operation types
	for _, op := range analysis.Operations {
		h.stats.RecordOperation(op)
	}

	// Forward to upstream
	resp, err := h.forwardRequest(ctx, processedReq)
	if err != nil {
		h.stats.RecordError()
		h.logger.Error("upstream request failed", "error", err)
		h.writeError(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *GatewayHandler) parseRequest(r *http.Request) (*GatewayRequest, error) {
	var req GatewayRequest

	switch r.Method {
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
		} else if strings.Contains(contentType, "application/graphql") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read body: %w", err)
			}
			req.Query = string(body)
		} else {
			// Try JSON anyway
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, fmt.Errorf("unsupported content type: %s", contentType)
			}
		}

	case http.MethodGet:
		req.Query = r.URL.Query().Get("query")
		req.OperationName = r.URL.Query().Get("operationName")

		if variables := r.URL.Query().Get("variables"); variables != "" {
			if err := json.Unmarshal([]byte(variables), &req.Variables); err != nil {
				return nil, fmt.Errorf("invalid variables JSON: %w", err)
			}
		}

		if extensions := r.URL.Query().Get("extensions"); extensions != "" {
			if err := json.Unmarshal([]byte(extensions), &req.Extensions); err != nil {
				return nil, fmt.Errorf("invalid extensions JSON: %w", err)
			}
		}

	default:
		return nil, fmt.Errorf("method not allowed: %s", r.Method)
	}

	return &req, nil
}

// GatewayBatchRequest represents a batched GraphQL request.
type GatewayBatchRequest struct {
	Requests []GatewayRequest
}

// GatewayResponse represents a GraphQL response.
type GatewayResponse struct {
	Data       interface{}             `json:"data,omitempty"`
	Errors     []GatewayResponseError  `json:"errors,omitempty"`
	Extensions *json.RawMessage        `json:"extensions,omitempty"`
}

// GatewayResponseError represents a GraphQL error.
type GatewayResponseError struct {
	Message    string                 `json:"message"`
	Locations  []GatewayLocation      `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GatewayLocation represents a location in the GraphQL document.
type GatewayLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

func (h *GatewayHandler) parseBatchRequest(r *http.Request) (*GatewayBatchRequest, bool) {
	if r.Method != http.MethodPost {
		return nil, false
	}

	// Check if this looks like a batch request
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, false
	}

	// Read and restore body for later parsing
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Try to parse as array
	var requests []GatewayRequest
	if err := json.Unmarshal(body, &requests); err == nil && len(requests) > 1 {
		return &GatewayBatchRequest{Requests: requests}, true
	}

	// Reset body for regular parsing
	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil, false
}

func (h *GatewayHandler) handleBatch(w http.ResponseWriter, r *http.Request, batch *GatewayBatchRequest) {
	responses := make([]GatewayResponse, len(batch.Requests))
	ctx := r.Context()

	for i, req := range batch.Requests {
		reqCopy := req
		processedReq, analysis, err := h.gateway.ProcessRequest(ctx, &reqCopy)
		if err != nil {
			responses[i] = GatewayResponse{
				Errors: []GatewayResponseError{{Message: err.Error()}},
			}
			continue
		}

		for _, op := range analysis.Operations {
			h.stats.RecordOperation(op)
		}

		resp, err := h.forwardRequest(ctx, processedReq)
		if err != nil {
			responses[i] = GatewayResponse{
				Errors: []GatewayResponseError{{Message: "upstream error"}},
			}
			continue
		}

		responses[i] = *resp
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responses)
}

func (h *GatewayHandler) handleProcessError(w http.ResponseWriter, err error, analysis *QueryAnalysis) {
	h.stats.RecordError()

	status := http.StatusBadRequest
	var reason string

	switch {
	case err == ErrQueryTooDeep:
		h.stats.RecordBlocked("depth")
		reason = fmt.Sprintf("query depth %d exceeds maximum allowed", analysis.Depth)
	case err == ErrQueryTooComplex:
		h.stats.RecordBlocked("complexity")
		reason = fmt.Sprintf("query complexity %d exceeds maximum allowed", analysis.Complexity)
	case err == ErrIntrospectionBlock:
		h.stats.RecordBlocked("introspection")
		reason = "introspection queries are disabled"
	case err == ErrQueryNotFound:
		reason = "persisted query not found"
		h.stats.RecordAPQMiss()
	case err == ErrFieldNotAllowed:
		status = http.StatusForbidden
		reason = err.Error()
	default:
		reason = err.Error()
	}

	h.logger.Warn("query blocked",
		"reason", reason,
		"error", err,
	)

	h.writeGraphQLError(w, reason, status)
}

func (h *GatewayHandler) forwardRequest(ctx context.Context, req *GatewayRequest) (*GatewayResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.upstream, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	var graphqlResp GatewayResponse
	if err := json.NewDecoder(resp.Body).Decode(&graphqlResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &graphqlResp, nil
}

func (h *GatewayHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (h *GatewayHandler) writeGraphQLError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(GatewayResponse{
		Errors: []GatewayResponseError{{Message: message}},
	})
}

// GetStats returns handler statistics.
func (h *GatewayHandler) GetStats() GatewayStats {
	return h.stats.GetStats()
}

// GatewayMiddleware provides GraphQL middleware for existing handlers.
type GatewayMiddleware struct {
	gateway *Gateway
	stats   *GatewayStatsCollector
	logger  *slog.Logger
}

// GatewayMiddlewareConfig configures the GraphQL middleware.
type GatewayMiddlewareConfig struct {
	// Gateway is the GraphQL gateway instance.
	Gateway *Gateway
	// Logger for middleware events.
	Logger *slog.Logger
}

// NewGatewayMiddleware creates new GraphQL middleware.
func NewGatewayMiddleware(config GatewayMiddlewareConfig) *GatewayMiddleware {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	var apqCache *APQCache
	if config.Gateway != nil {
		apqCache = config.Gateway.apqCache
	}

	return &GatewayMiddleware{
		gateway: config.Gateway,
		stats:   NewGatewayStatsCollector(apqCache),
		logger:  config.Logger,
	}
}

// Handler returns an HTTP middleware that validates GraphQL requests.
func (m *GatewayMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.stats.RecordRequest()

		// Only process POST requests to GraphQL endpoints
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			m.stats.RecordError()
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		// Parse request
		var req GatewayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			// Not a GraphQL request, pass through
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}

		// Process through gateway
		ctx := r.Context()
		_, analysis, err := m.gateway.ProcessRequest(ctx, &req)
		if err != nil {
			m.handleError(w, err, analysis)
			return
		}

		// Record operations
		for _, op := range analysis.Operations {
			m.stats.RecordOperation(op)
		}

		// Store analysis in context for downstream handlers
		ctx = context.WithValue(ctx, graphqlAnalysisKey, analysis)

		// Restore body and continue
		r.Body = io.NopCloser(bytes.NewReader(body))
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func (m *GatewayMiddleware) handleError(w http.ResponseWriter, err error, analysis *QueryAnalysis) {
	m.stats.RecordError()

	status := http.StatusBadRequest
	var message string

	switch {
	case err == ErrQueryTooDeep:
		m.stats.RecordBlocked("depth")
		if analysis != nil {
			message = fmt.Sprintf("query depth %d exceeds maximum allowed", analysis.Depth)
		} else {
			message = "query exceeds maximum depth"
		}
	case err == ErrQueryTooComplex:
		m.stats.RecordBlocked("complexity")
		if analysis != nil {
			message = fmt.Sprintf("query complexity %d exceeds maximum allowed", analysis.Complexity)
		} else {
			message = "query exceeds maximum complexity"
		}
	case err == ErrIntrospectionBlock:
		m.stats.RecordBlocked("introspection")
		message = "introspection queries are disabled"
	case err == ErrFieldNotAllowed:
		status = http.StatusForbidden
		message = err.Error()
	default:
		message = err.Error()
	}

	m.logger.Warn("GraphQL request blocked",
		"reason", message,
		"error", err,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(GatewayResponse{
		Errors: []GatewayResponseError{{Message: message}},
	})
}

// GetStats returns middleware statistics.
func (m *GatewayMiddleware) GetStats() GatewayStats {
	return m.stats.GetStats()
}

type contextKey string

const graphqlAnalysisKey contextKey = "graphql_analysis"

// GetAnalysisFromContext retrieves the query analysis from the context.
func GetAnalysisFromContext(ctx context.Context) *QueryAnalysis {
	if analysis, ok := ctx.Value(graphqlAnalysisKey).(*QueryAnalysis); ok {
		return analysis
	}
	return nil
}

// GatewayAdminHandler provides admin API for the GraphQL gateway.
type GatewayAdminHandler struct {
	gateway *Gateway
	handler *GatewayHandler
	logger  *slog.Logger
}

// NewGatewayAdminHandler creates a new admin handler.
func NewGatewayAdminHandler(gateway *Gateway, handler *GatewayHandler, logger *slog.Logger) *GatewayAdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayAdminHandler{
		gateway: gateway,
		handler: handler,
		logger:  logger,
	}
}

// ServeHTTP handles admin API requests.
func (h *GatewayAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/graphql/admin")

	switch {
	case path == "/stats" || path == "/stats/":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/config" || path == "/config/":
		if r.Method == http.MethodGet {
			h.handleGetConfig(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/analyze" || path == "/analyze/":
		if r.Method == http.MethodPost {
			h.handleAnalyze(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		http.NotFound(w, r)
	}
}

func (h *GatewayAdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.handler.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *GatewayAdminHandler) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := struct {
		MaxDepth           int      `json:"max_depth"`
		MaxComplexity      int      `json:"max_complexity"`
		AllowIntrospection bool     `json:"allow_introspection"`
		EnableAPQ          bool     `json:"enable_apq"`
		BlockedFields      []string `json:"blocked_fields"`
	}{
		MaxDepth:           h.gateway.config.MaxDepth,
		MaxComplexity:      h.gateway.config.MaxComplexity,
		AllowIntrospection: h.gateway.config.AllowIntrospection,
		EnableAPQ:          h.gateway.config.EnableAPQ,
		BlockedFields:      h.gateway.config.BlockedFields,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (h *GatewayAdminHandler) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	analysis, err := h.gateway.analyzer.Analyze(req.Query)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Also check limits
	var violations []string
	if h.gateway.config.MaxDepth > 0 && analysis.Depth > h.gateway.config.MaxDepth {
		violations = append(violations, fmt.Sprintf("depth %d exceeds max %d", analysis.Depth, h.gateway.config.MaxDepth))
	}
	if h.gateway.config.MaxComplexity > 0 && analysis.Complexity > h.gateway.config.MaxComplexity {
		violations = append(violations, fmt.Sprintf("complexity %d exceeds max %d", analysis.Complexity, h.gateway.config.MaxComplexity))
	}

	response := struct {
		*QueryAnalysis
		Violations []string `json:"violations,omitempty"`
	}{
		QueryAnalysis: analysis,
		Violations:    violations,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GatewayWebSocketHandler handles GraphQL subscriptions over WebSocket.
type GatewayWebSocketHandler struct {
	gateway       *Gateway
	subscriptions map[string]*gatewaySubscription
	nextID        int64
	logger        *slog.Logger
}

type gatewaySubscription struct {
	id        string
	query     string
	variables map[string]interface{}
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewGatewayWebSocketHandler creates a new WebSocket handler for subscriptions.
func NewGatewayWebSocketHandler(gateway *Gateway, logger *slog.Logger) *GatewayWebSocketHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &GatewayWebSocketHandler{
		gateway:       gateway,
		subscriptions: make(map[string]*gatewaySubscription),
		logger:        logger,
	}
}

// HandleMessage handles a WebSocket message (graphql-ws protocol).
func (h *GatewayWebSocketHandler) HandleMessage(ctx context.Context, msgType string, payload json.RawMessage) (interface{}, error) {
	switch msgType {
	case "connection_init":
		return map[string]string{"type": "connection_ack"}, nil

	case "subscribe":
		var req struct {
			ID      string          `json:"id"`
			Payload GatewayRequest  `json:"payload"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}

		// Validate subscription
		_, analysis, err := h.gateway.ProcessRequest(ctx, &req.Payload)
		if err != nil {
			return map[string]interface{}{
				"type":    "error",
				"id":      req.ID,
				"payload": []GatewayResponseError{{Message: err.Error()}},
			}, nil
		}

		if !analysis.HasSubscription {
			return map[string]interface{}{
				"type":    "error",
				"id":      req.ID,
				"payload": []GatewayResponseError{{Message: "not a subscription query"}},
			}, nil
		}

		// Create subscription
		subCtx, cancel := context.WithCancel(ctx)
		sub := &gatewaySubscription{
			id:        req.ID,
			query:     req.Payload.Query,
			variables: req.Payload.Variables,
			ctx:       subCtx,
			cancel:    cancel,
		}
		h.subscriptions[req.ID] = sub

		h.logger.Debug("subscription created", "id", req.ID)

		return nil, nil

	case "complete":
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}

		if sub, ok := h.subscriptions[req.ID]; ok {
			sub.cancel()
			delete(h.subscriptions, req.ID)
			h.logger.Debug("subscription completed", "id", req.ID)
		}

		return nil, nil

	default:
		return nil, fmt.Errorf("unknown message type: %s", msgType)
	}
}

// GenerateSubscriptionID generates a unique subscription ID.
func (h *GatewayWebSocketHandler) GenerateSubscriptionID() string {
	id := atomic.AddInt64(&h.nextID, 1)
	return fmt.Sprintf("sub_%d", id)
}

// Close closes all subscriptions.
func (h *GatewayWebSocketHandler) Close() {
	for _, sub := range h.subscriptions {
		sub.cancel()
	}
	h.subscriptions = make(map[string]*gatewaySubscription)
}

// ParseGatewayBatchRequest parses a batch request from JSON.
func ParseGatewayBatchRequest(data []byte) (*GatewayBatchRequest, error) {
	// Try array first
	var requests []GatewayRequest
	if err := json.Unmarshal(data, &requests); err == nil {
		return &GatewayBatchRequest{Requests: requests}, nil
	}

	// Try single request
	var single GatewayRequest
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("invalid request format: %w", err)
	}

	return &GatewayBatchRequest{Requests: []GatewayRequest{single}}, nil
}
