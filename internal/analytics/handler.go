package analytics

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler provides HTTP API for analytics.
type Handler struct {
	pipeline *Pipeline
	logger   *slog.Logger
}

// NewHandler creates a new analytics handler.
func NewHandler(pipeline *Pipeline, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// ServeHTTP handles analytics API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/analytics")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" || path == "":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/stats":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/snapshot":
		if r.Method == http.MethodGet {
			h.handleSnapshot(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/query":
		if r.Method == http.MethodPost {
			h.handleQuery(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/history":
		if r.Method == http.MethodGet {
			h.handleHistory(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/paths":
		if r.Method == http.MethodGet {
			h.handlePaths(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/status-codes":
		if r.Method == http.MethodGet {
			h.handleStatusCodes(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/latency":
		if r.Method == http.MethodGet {
			h.handleLatency(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/reset":
		if r.Method == http.MethodPost {
			h.handleReset(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.pipeline.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot := h.pipeline.GetAggregator().Snapshot()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

func (h *Handler) handleQuery(w http.ResponseWriter, r *http.Request) {
	var query Query
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.pipeline.Query(query)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	limitStr := r.URL.Query().Get("limit")

	var start, end time.Time
	var limit int

	if startStr != "" {
		var err error
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			h.jsonError(w, "invalid start time", http.StatusBadRequest)
			return
		}
	}

	if endStr != "" {
		var err error
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			h.jsonError(w, "invalid end time", http.StatusBadRequest)
			return
		}
	}

	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil {
			h.jsonError(w, "invalid limit", http.StatusBadRequest)
			return
		}
	}

	snapshots, err := h.pipeline.storage.GetSnapshots(start, end, limit)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}

func (h *Handler) handlePaths(w http.ResponseWriter, r *http.Request) {
	snapshot := h.pipeline.GetAggregator().Snapshot()

	// Convert to sorted list
	type pathInfo struct {
		Path       string  `json:"path"`
		Count      int64   `json:"count"`
		ErrorCount int64   `json:"error_count"`
		ErrorRate  float64 `json:"error_rate"`
		AvgLatency float64 `json:"avg_latency_ms"`
		P95Latency float64 `json:"p95_latency_ms"`
		P99Latency float64 `json:"p99_latency_ms"`
		TotalBytes int64   `json:"total_bytes"`
	}

	paths := make([]pathInfo, 0, len(snapshot.PathMetrics))
	for path, pm := range snapshot.PathMetrics {
		errorRate := float64(0)
		if pm.Count > 0 {
			errorRate = float64(pm.ErrorCount) / float64(pm.Count) * 100
		}
		paths = append(paths, pathInfo{
			Path:       path,
			Count:      pm.Count,
			ErrorCount: pm.ErrorCount,
			ErrorRate:  errorRate,
			AvgLatency: pm.AvgLatency,
			P95Latency: pm.P95Latency,
			P99Latency: pm.P99Latency,
			TotalBytes: pm.TotalBytes,
		})
	}

	// Sort by count descending
	for i := 0; i < len(paths)-1; i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].Count > paths[i].Count {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(paths)
}

func (h *Handler) handleStatusCodes(w http.ResponseWriter, r *http.Request) {
	snapshot := h.pipeline.GetAggregator().Snapshot()

	type statusInfo struct {
		Code       int     `json:"code"`
		Count      int64   `json:"count"`
		Percentage float64 `json:"percentage"`
		Category   string  `json:"category"`
	}

	total := snapshot.TotalRequests
	statuses := make([]statusInfo, 0, len(snapshot.StatusCodes))

	for code, count := range snapshot.StatusCodes {
		pct := float64(0)
		if total > 0 {
			pct = float64(count) / float64(total) * 100
		}

		category := "unknown"
		switch {
		case code >= 100 && code < 200:
			category = "informational"
		case code >= 200 && code < 300:
			category = "success"
		case code >= 300 && code < 400:
			category = "redirection"
		case code >= 400 && code < 500:
			category = "client_error"
		case code >= 500:
			category = "server_error"
		}

		statuses = append(statuses, statusInfo{
			Code:       code,
			Count:      count,
			Percentage: pct,
			Category:   category,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

func (h *Handler) handleLatency(w http.ResponseWriter, r *http.Request) {
	snapshot := h.pipeline.GetAggregator().Snapshot()

	response := map[string]interface{}{
		"avg_ms": snapshot.AvgLatency,
		"p50_ms": snapshot.P50Latency,
		"p95_ms": snapshot.P95Latency,
		"p99_ms": snapshot.P99Latency,
		"by_path": make(map[string]map[string]float64),
	}

	byPath := response["by_path"].(map[string]map[string]float64)
	for path, pm := range snapshot.PathMetrics {
		byPath[path] = map[string]float64{
			"avg_ms": pm.AvgLatency,
			"p50_ms": pm.P50Latency,
			"p95_ms": pm.P95Latency,
			"p99_ms": pm.P99Latency,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleReset(w http.ResponseWriter, r *http.Request) {
	h.pipeline.GetAggregator().Reset()

	h.logger.Info("analytics reset")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "reset complete",
	})
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// SSEHandler provides Server-Sent Events for real-time analytics.
type SSEHandler struct {
	pipeline *StreamingPipeline
	logger   *slog.Logger
}

// NewSSEHandler creates a new SSE handler.
func NewSSEHandler(pipeline *StreamingPipeline, logger *slog.Logger) *SSEHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &SSEHandler{
		pipeline: pipeline,
		logger:   logger,
	}
}

// ServeHTTP handles SSE connections.
func (h *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Create subscriber
	sub := &sseSubscriber{
		w:       w,
		flusher: flusher,
		done:    r.Context().Done(),
	}

	h.pipeline.GetStream().Subscribe(sub)
	defer h.pipeline.GetStream().Unsubscribe(sub)

	h.logger.Debug("SSE client connected")

	// Keep connection alive until client disconnects
	<-r.Context().Done()

	h.logger.Debug("SSE client disconnected")
}

type sseSubscriber struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    <-chan struct{}
}

func (s *sseSubscriber) OnEvent(event *Event) {
	select {
	case <-s.done:
		return
	default:
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	s.w.Write([]byte("event: event\ndata: "))
	s.w.Write(data)
	s.w.Write([]byte("\n\n"))
	s.flusher.Flush()
}

func (s *sseSubscriber) OnSnapshot(snapshot *Snapshot) {
	select {
	case <-s.done:
		return
	default:
	}

	data, err := json.Marshal(snapshot)
	if err != nil {
		return
	}

	s.w.Write([]byte("event: snapshot\ndata: "))
	s.w.Write(data)
	s.w.Write([]byte("\n\n"))
	s.flusher.Flush()
}
