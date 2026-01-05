// Package timetravel provides API time-travel debugging capabilities.
package timetravel

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Recorder records HTTP request/response pairs for time-travel debugging.
type Recorder struct {
	// storage holds recorded events
	storage Storage
	// config for recording behavior
	config RecorderConfig
	// logger for events
	logger *slog.Logger
	// mu protects concurrent access
	mu sync.RWMutex
}

// RecorderConfig configures the recorder.
type RecorderConfig struct {
	// MaxBodySize limits recorded body size (default: 1MB)
	MaxBodySize int64
	// MaxEvents limits total stored events (default: 100000)
	MaxEvents int
	// RetentionPeriod how long to keep events (default: 24h)
	RetentionPeriod time.Duration
	// SampleRate percentage of requests to record (0-100, default: 100)
	SampleRate int
	// ExcludePaths patterns to exclude from recording
	ExcludePaths []string
	// ExcludeHeaders headers to redact
	ExcludeHeaders []string
	// CompressBody compress recorded bodies
	CompressBody bool
	// Logger for recorder events
	Logger *slog.Logger
}

// DefaultRecorderConfig returns sensible defaults.
func DefaultRecorderConfig() RecorderConfig {
	return RecorderConfig{
		MaxBodySize:     1024 * 1024,
		MaxEvents:       100000,
		RetentionPeriod: 24 * time.Hour,
		SampleRate:      100,
		ExcludeHeaders:  []string{"Authorization", "Cookie", "Set-Cookie"},
		CompressBody:    true,
	}
}

// Storage interface for event persistence.
type Storage interface {
	Store(event *Event) error
	Get(id string) (*Event, error)
	Query(opts QueryOptions) ([]*Event, error)
	Delete(id string) error
	Cleanup(before time.Time) error
	Close() error
}

// Event represents a recorded HTTP request/response pair.
type Event struct {
	// ID is a unique identifier
	ID string `json:"id"`
	// Timestamp when the request was received
	Timestamp time.Time `json:"timestamp"`
	// Duration of the request
	Duration time.Duration `json:"duration"`
	// Request details
	Request RequestRecord `json:"request"`
	// Response details
	Response ResponseRecord `json:"response"`
	// TraceID for distributed tracing correlation
	TraceID string `json:"trace_id,omitempty"`
	// SpanID for distributed tracing
	SpanID string `json:"span_id,omitempty"`
	// RouteID identifies the matched route
	RouteID string `json:"route_id,omitempty"`
	// Tags for filtering
	Tags map[string]string `json:"tags,omitempty"`
	// Error if the request failed
	Error string `json:"error,omitempty"`
}

// RequestRecord holds recorded request details.
type RequestRecord struct {
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Host        string              `json:"host"`
	Headers     map[string][]string `json:"headers"`
	Body        []byte              `json:"body,omitempty"`
	BodyHash    string              `json:"body_hash,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	Size        int64               `json:"size"`
}

// ResponseRecord holds recorded response details.
type ResponseRecord struct {
	StatusCode  int                 `json:"status_code"`
	Headers     map[string][]string `json:"headers"`
	Body        []byte              `json:"body,omitempty"`
	BodyHash    string              `json:"body_hash,omitempty"`
	ContentType string              `json:"content_type,omitempty"`
	Size        int64               `json:"size"`
}

// QueryOptions for querying recorded events.
type QueryOptions struct {
	// StartTime filters events after this time
	StartTime time.Time
	// EndTime filters events before this time
	EndTime time.Time
	// Method filters by HTTP method
	Method string
	// Path filters by URL path (prefix match)
	Path string
	// StatusCode filters by response status
	StatusCode int
	// TraceID filters by trace ID
	TraceID string
	// RouteID filters by route
	RouteID string
	// Tags filters by tags
	Tags map[string]string
	// Limit max results
	Limit int
	// Offset for pagination
	Offset int
	// OrderBy field to order by
	OrderBy string
	// OrderDesc descending order
	OrderDesc bool
}

// NewRecorder creates a new recorder.
func NewRecorder(storage Storage, config RecorderConfig) *Recorder {
	if config.MaxBodySize == 0 {
		config.MaxBodySize = 1024 * 1024
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = 100000
	}
	if config.RetentionPeriod == 0 {
		config.RetentionPeriod = 24 * time.Hour
	}
	if config.SampleRate == 0 {
		config.SampleRate = 100
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	r := &Recorder{
		storage: storage,
		config:  config,
		logger:  config.Logger,
	}

	// Start cleanup goroutine
	go r.cleanupLoop()

	return r
}

// Record records a request/response pair.
func (r *Recorder) Record(event *Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Apply compression if configured
	if r.config.CompressBody {
		event.Request.Body = compressBody(event.Request.Body)
		event.Response.Body = compressBody(event.Response.Body)
	}

	return r.storage.Store(event)
}

// Query queries recorded events.
func (r *Recorder) Query(opts QueryOptions) ([]*Event, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	events, err := r.storage.Query(opts)
	if err != nil {
		return nil, err
	}

	// Decompress bodies if needed
	if r.config.CompressBody {
		for _, e := range events {
			e.Request.Body = decompressBody(e.Request.Body)
			e.Response.Body = decompressBody(e.Response.Body)
		}
	}

	return events, nil
}

// Get retrieves a single event by ID.
func (r *Recorder) Get(id string) (*Event, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	event, err := r.storage.Get(id)
	if err != nil {
		return nil, err
	}

	if r.config.CompressBody && event != nil {
		event.Request.Body = decompressBody(event.Request.Body)
		event.Response.Body = decompressBody(event.Response.Body)
	}

	return event, nil
}

// Delete removes an event.
func (r *Recorder) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.storage.Delete(id)
}

// cleanupLoop periodically removes old events.
func (r *Recorder) cleanupLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-r.config.RetentionPeriod)
		if err := r.storage.Cleanup(cutoff); err != nil {
			r.logger.Error("cleanup failed", "error", err)
		}
	}
}

// Close closes the recorder.
func (r *Recorder) Close() error {
	return r.storage.Close()
}

// compressBody compresses body data.
func compressBody(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()

	return buf.Bytes()
}

// decompressBody decompresses body data.
func decompressBody(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data // Return as-is if not compressed
	}
	defer gz.Close()

	result, err := io.ReadAll(gz)
	if err != nil {
		return data
	}

	return result
}

// hashBody creates a SHA256 hash of body content.
func hashBody(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// MemoryStorage implements in-memory storage.
type MemoryStorage struct {
	events   map[string]*Event
	order    []string // Ordered by timestamp
	maxSize  int
	mu       sync.RWMutex
}

// NewMemoryStorage creates an in-memory storage.
func NewMemoryStorage(maxSize int) *MemoryStorage {
	if maxSize == 0 {
		maxSize = 100000
	}
	return &MemoryStorage{
		events:  make(map[string]*Event),
		order:   make([]string, 0),
		maxSize: maxSize,
	}
}

// Store stores an event.
func (s *MemoryStorage) Store(event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check capacity
	if len(s.events) >= s.maxSize {
		// Remove oldest
		if len(s.order) > 0 {
			oldest := s.order[0]
			delete(s.events, oldest)
			s.order = s.order[1:]
		}
	}

	s.events[event.ID] = event
	s.order = append(s.order, event.ID)

	return nil
}

// Get retrieves an event by ID.
func (s *MemoryStorage) Get(id string) (*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	event, ok := s.events[id]
	if !ok {
		return nil, fmt.Errorf("event not found: %s", id)
	}

	return event, nil
}

// Query queries events with filtering.
func (s *MemoryStorage) Query(opts QueryOptions) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Event

	for _, event := range s.events {
		if matchesQuery(event, opts) {
			results = append(results, event)
		}
	}

	// Sort
	sortEvents(results, opts.OrderBy, opts.OrderDesc)

	// Pagination
	if opts.Offset > 0 {
		if opts.Offset >= len(results) {
			return []*Event{}, nil
		}
		results = results[opts.Offset:]
	}

	if opts.Limit > 0 && len(results) > opts.Limit {
		results = results[:opts.Limit]
	}

	return results, nil
}

// Delete removes an event.
func (s *MemoryStorage) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.events, id)

	// Remove from order
	for i, eid := range s.order {
		if eid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}

	return nil
}

// Cleanup removes events before a timestamp.
func (s *MemoryStorage) Cleanup(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []string
	for id, event := range s.events {
		if event.Timestamp.Before(before) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		delete(s.events, id)
	}

	// Rebuild order
	newOrder := make([]string, 0, len(s.order)-len(toDelete))
	for _, id := range s.order {
		if _, ok := s.events[id]; ok {
			newOrder = append(newOrder, id)
		}
	}
	s.order = newOrder

	return nil
}

// Close closes the storage.
func (s *MemoryStorage) Close() error {
	return nil
}

// matchesQuery checks if an event matches query options.
func matchesQuery(event *Event, opts QueryOptions) bool {
	if !opts.StartTime.IsZero() && event.Timestamp.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && event.Timestamp.After(opts.EndTime) {
		return false
	}
	if opts.Method != "" && event.Request.Method != opts.Method {
		return false
	}
	if opts.Path != "" && !matchPath(event.Request.URL, opts.Path) {
		return false
	}
	if opts.StatusCode != 0 && event.Response.StatusCode != opts.StatusCode {
		return false
	}
	if opts.TraceID != "" && event.TraceID != opts.TraceID {
		return false
	}
	if opts.RouteID != "" && event.RouteID != opts.RouteID {
		return false
	}
	for k, v := range opts.Tags {
		if event.Tags[k] != v {
			return false
		}
	}
	return true
}

// matchPath matches a URL against a path prefix.
func matchPath(url, path string) bool {
	return len(url) >= len(path) && url[:len(path)] == path
}

// sortEvents sorts events by the specified field.
func sortEvents(events []*Event, field string, desc bool) {
	sort.Slice(events, func(i, j int) bool {
		var less bool
		switch field {
		case "duration":
			less = events[i].Duration < events[j].Duration
		case "status":
			less = events[i].Response.StatusCode < events[j].Response.StatusCode
		default:
			less = events[i].Timestamp.Before(events[j].Timestamp)
		}
		if desc {
			return !less
		}
		return less
	})
}

// Replay represents a request replay session.
type Replay struct {
	recorder *Recorder
	events   []*Event
	current  int
	mu       sync.RWMutex
}

// NewReplay creates a replay session from recorded events.
func NewReplay(recorder *Recorder, opts QueryOptions) (*Replay, error) {
	events, err := recorder.Query(opts)
	if err != nil {
		return nil, err
	}

	return &Replay{
		recorder: recorder,
		events:   events,
		current:  0,
	}, nil
}

// Next returns the next event in the replay.
func (r *Replay) Next() *Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.current >= len(r.events) {
		return nil
	}

	event := r.events[r.current]
	r.current++
	return event
}

// Previous returns the previous event.
func (r *Replay) Previous() *Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.current <= 0 {
		return nil
	}

	r.current--
	return r.events[r.current]
}

// Seek moves to a specific position.
func (r *Replay) Seek(pos int) *Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pos < 0 || pos >= len(r.events) {
		return nil
	}

	r.current = pos
	return r.events[r.current]
}

// SeekToTime moves to the event nearest to a timestamp.
func (r *Replay) SeekToTime(t time.Time) *Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	closestIdx := 0
	closestDiff := time.Duration(1<<63 - 1)

	for i, event := range r.events {
		diff := event.Timestamp.Sub(t)
		if diff < 0 {
			diff = -diff
		}
		if diff < closestDiff {
			closestDiff = diff
			closestIdx = i
		}
	}

	r.current = closestIdx
	if closestIdx < len(r.events) {
		return r.events[closestIdx]
	}
	return nil
}

// Current returns the current event without moving.
func (r *Replay) Current() *Event {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.current >= len(r.events) {
		return nil
	}
	return r.events[r.current]
}

// Count returns total events in the replay.
func (r *Replay) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.events)
}

// Position returns current position.
func (r *Replay) Position() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Diff represents a diff between two events.
type Diff struct {
	// Fields that changed
	Changes []Change `json:"changes"`
}

// Change represents a single field change.
type Change struct {
	Path     string      `json:"path"`
	Type     string      `json:"type"` // added, removed, modified
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value,omitempty"`
}

// DiffEvents computes the difference between two events.
func DiffEvents(a, b *Event) *Diff {
	diff := &Diff{}

	// Compare request
	if a.Request.Method != b.Request.Method {
		diff.Changes = append(diff.Changes, Change{
			Path:     "request.method",
			Type:     "modified",
			OldValue: a.Request.Method,
			NewValue: b.Request.Method,
		})
	}

	if a.Request.URL != b.Request.URL {
		diff.Changes = append(diff.Changes, Change{
			Path:     "request.url",
			Type:     "modified",
			OldValue: a.Request.URL,
			NewValue: b.Request.URL,
		})
	}

	// Compare request headers
	diffHeaders("request.headers", a.Request.Headers, b.Request.Headers, diff)

	// Compare response status
	if a.Response.StatusCode != b.Response.StatusCode {
		diff.Changes = append(diff.Changes, Change{
			Path:     "response.status_code",
			Type:     "modified",
			OldValue: a.Response.StatusCode,
			NewValue: b.Response.StatusCode,
		})
	}

	// Compare response headers
	diffHeaders("response.headers", a.Response.Headers, b.Response.Headers, diff)

	// Compare bodies if they have hashes
	if a.Request.BodyHash != b.Request.BodyHash {
		diff.Changes = append(diff.Changes, Change{
			Path:     "request.body",
			Type:     "modified",
			OldValue: a.Request.BodyHash,
			NewValue: b.Request.BodyHash,
		})
	}

	if a.Response.BodyHash != b.Response.BodyHash {
		diff.Changes = append(diff.Changes, Change{
			Path:     "response.body",
			Type:     "modified",
			OldValue: a.Response.BodyHash,
			NewValue: b.Response.BodyHash,
		})
	}

	return diff
}

// diffHeaders compares two header maps.
func diffHeaders(prefix string, a, b map[string][]string, diff *Diff) {
	for key, aValues := range a {
		if bValues, ok := b[key]; ok {
			if !equalStringSlices(aValues, bValues) {
				diff.Changes = append(diff.Changes, Change{
					Path:     prefix + "." + key,
					Type:     "modified",
					OldValue: aValues,
					NewValue: bValues,
				})
			}
		} else {
			diff.Changes = append(diff.Changes, Change{
				Path:     prefix + "." + key,
				Type:     "removed",
				OldValue: aValues,
			})
		}
	}

	for key, bValues := range b {
		if _, ok := a[key]; !ok {
			diff.Changes = append(diff.Changes, Change{
				Path:     prefix + "." + key,
				Type:     "added",
				NewValue: bValues,
			})
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// APIHandler returns an HTTP handler for the time-travel API.
func (r *Recorder) APIHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/events", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		opts := QueryOptions{
			Limit: 100,
		}

		// Parse query params
		q := req.URL.Query()
		if v := q.Get("start"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				opts.StartTime = t
			}
		}
		if v := q.Get("end"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				opts.EndTime = t
			}
		}
		opts.Method = q.Get("method")
		opts.Path = q.Get("path")
		opts.TraceID = q.Get("trace_id")
		opts.RouteID = q.Get("route_id")

		events, err := r.Query(opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	mux.HandleFunc("/events/", func(w http.ResponseWriter, req *http.Request) {
		id := req.URL.Path[len("/events/"):]
		if id == "" {
			http.Error(w, "Event ID required", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "GET":
			event, err := r.Get(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(event)

		case "DELETE":
			if err := r.Delete(id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/replay", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var opts QueryOptions
		if err := json.NewDecoder(req.Body).Decode(&opts); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		replay, err := NewReplay(r, opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count": replay.Count(),
		})
	})

	mux.HandleFunc("/diff", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		q := req.URL.Query()
		id1 := q.Get("a")
		id2 := q.Get("b")

		if id1 == "" || id2 == "" {
			http.Error(w, "Both 'a' and 'b' event IDs required", http.StatusBadRequest)
			return
		}

		event1, err := r.Get(id1)
		if err != nil {
			http.Error(w, "Event A not found", http.StatusNotFound)
			return
		}

		event2, err := r.Get(id2)
		if err != nil {
			http.Error(w, "Event B not found", http.StatusNotFound)
			return
		}

		diff := DiffEvents(event1, event2)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(diff)
	})

	return mux
}

// Replayer can replay recorded requests against a target.
type Replayer struct {
	client *http.Client
	logger *slog.Logger
}

// NewReplayer creates a new replayer.
func NewReplayer(timeout time.Duration, logger *slog.Logger) *Replayer {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Replayer{
		client: &http.Client{Timeout: timeout},
		logger: logger,
	}
}

// ReplayResult holds the result of replaying a request.
type ReplayResult struct {
	Original  *Event         `json:"original"`
	Replayed  *Event         `json:"replayed"`
	Diff      *Diff          `json:"diff"`
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
}

// ReplayRequest replays a recorded request against a target.
func (r *Replayer) ReplayRequest(ctx context.Context, event *Event, targetURL string) (*ReplayResult, error) {
	result := &ReplayResult{
		Original: event,
	}

	// Build request
	body := bytes.NewReader(event.Request.Body)
	req, err := http.NewRequestWithContext(ctx, event.Request.Method, targetURL+event.Request.URL, body)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	// Copy headers (excluding hop-by-hop)
	for key, values := range event.Request.Headers {
		if !isHopByHop(key) {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}

	// Execute request
	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	// Read response
	respBody, _ := io.ReadAll(resp.Body)

	// Build replayed event
	result.Replayed = &Event{
		Timestamp: time.Now(),
		Duration:  duration,
		Request:   event.Request,
		Response: ResponseRecord{
			StatusCode:  resp.StatusCode,
			Headers:     resp.Header,
			Body:        respBody,
			BodyHash:    hashBody(respBody),
			ContentType: resp.Header.Get("Content-Type"),
			Size:        int64(len(respBody)),
		},
	}

	// Compute diff
	result.Diff = DiffEvents(event, result.Replayed)
	result.Success = len(result.Diff.Changes) == 0 || result.Replayed.Response.StatusCode == event.Response.StatusCode

	return result, nil
}

func isHopByHop(header string) bool {
	switch header {
	case "Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade":
		return true
	}
	return false
}
