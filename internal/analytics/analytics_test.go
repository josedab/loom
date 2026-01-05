package analytics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewPipeline(t *testing.T) {
	p := NewPipeline(PipelineConfig{})

	if p == nil {
		t.Fatal("expected pipeline to be created")
	}
	if p.config.BufferSize != 10000 {
		t.Errorf("BufferSize = %d, want 10000", p.config.BufferSize)
	}
	if p.config.FlushInterval != time.Minute {
		t.Errorf("FlushInterval = %v, want 1m", p.config.FlushInterval)
	}
}

func TestPipeline_Record(t *testing.T) {
	p := NewPipeline(PipelineConfig{
		BufferSize: 100,
	})
	p.Start()
	defer p.Stop()

	event := &Event{
		Type:       EventTypeResponse,
		Method:     "GET",
		Path:       "/api/users",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
		BytesSent:  1024,
	}

	p.Record(event)

	// Give time for processing
	time.Sleep(50 * time.Millisecond)

	stats := p.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", stats.TotalRequests)
	}
}

func TestAggregator_Record(t *testing.T) {
	a := NewAggregator()

	events := []*Event{
		{Type: EventTypeResponse, Path: "/api/users", StatusCode: 200, Duration: 100 * time.Millisecond, BytesSent: 100},
		{Type: EventTypeResponse, Path: "/api/users", StatusCode: 200, Duration: 200 * time.Millisecond, BytesSent: 200},
		{Type: EventTypeResponse, Path: "/api/items", StatusCode: 500, Duration: 50 * time.Millisecond, BytesSent: 50},
	}

	for _, e := range events {
		a.Record(e)
	}

	snapshot := a.Snapshot()

	if snapshot.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3", snapshot.TotalRequests)
	}
	if snapshot.TotalErrors != 1 {
		t.Errorf("TotalErrors = %d, want 1", snapshot.TotalErrors)
	}
	if snapshot.TotalBytes != 350 {
		t.Errorf("TotalBytes = %d, want 350", snapshot.TotalBytes)
	}

	// Check status codes
	if snapshot.StatusCodes[200] != 2 {
		t.Errorf("StatusCodes[200] = %d, want 2", snapshot.StatusCodes[200])
	}
	if snapshot.StatusCodes[500] != 1 {
		t.Errorf("StatusCodes[500] = %d, want 1", snapshot.StatusCodes[500])
	}

	// Check path metrics
	if pm, ok := snapshot.PathMetrics["/api/users"]; !ok {
		t.Error("expected /api/users in path metrics")
	} else if pm.Count != 2 {
		t.Errorf("/api/users count = %d, want 2", pm.Count)
	}
}

func TestAggregator_Percentiles(t *testing.T) {
	a := NewAggregator()

	// Add 100 events with known latencies
	for i := 1; i <= 100; i++ {
		a.Record(&Event{
			Type:       EventTypeResponse,
			Path:       "/api/test",
			StatusCode: 200,
			Duration:   time.Duration(i) * time.Millisecond,
		})
	}

	snapshot := a.Snapshot()

	// P50 should be around 50ms
	if snapshot.P50Latency < 49 || snapshot.P50Latency > 51 {
		t.Errorf("P50Latency = %v, want ~50ms", snapshot.P50Latency)
	}

	// P95 should be around 95ms
	if snapshot.P95Latency < 94 || snapshot.P95Latency > 96 {
		t.Errorf("P95Latency = %v, want ~95ms", snapshot.P95Latency)
	}

	// P99 should be around 99ms
	if snapshot.P99Latency < 98 || snapshot.P99Latency > 100 {
		t.Errorf("P99Latency = %v, want ~99ms", snapshot.P99Latency)
	}
}

func TestAggregator_Reset(t *testing.T) {
	a := NewAggregator()

	a.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
	})

	a.Reset()

	snapshot := a.Snapshot()
	if snapshot.TotalRequests != 0 {
		t.Errorf("TotalRequests after reset = %d, want 0", snapshot.TotalRequests)
	}
}

func TestMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage(MemoryStorageConfig{
		MaxSnapshots: 10,
	})

	// Store snapshots
	for i := 0; i < 15; i++ {
		snapshot := &Snapshot{
			Timestamp:     time.Now().Add(time.Duration(i) * time.Minute),
			TotalRequests: int64(i + 1),
		}
		storage.Store(snapshot)
	}

	// Should only have last 10
	snapshots, err := storage.GetSnapshots(time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Errorf("GetSnapshots() error = %v", err)
	}
	if len(snapshots) != 10 {
		t.Errorf("len(snapshots) = %d, want 10", len(snapshots))
	}

	// First should be the 6th (0-indexed: 5th which is i=5, requests=6)
	if snapshots[0].TotalRequests != 6 {
		t.Errorf("First snapshot TotalRequests = %d, want 6", snapshots[0].TotalRequests)
	}
}

func TestMemoryStorage_Query(t *testing.T) {
	storage := NewMemoryStorage(MemoryStorageConfig{})

	now := time.Now()
	storage.Store(&Snapshot{
		Timestamp:     now.Add(-2 * time.Hour),
		TotalRequests: 100,
		TotalErrors:   10,
		StatusCodes:   map[int]int64{200: 90, 500: 10},
		PathMetrics: map[string]*PathMetrics{
			"/api/users": {Count: 50},
			"/api/items": {Count: 50},
		},
	})
	storage.Store(&Snapshot{
		Timestamp:     now.Add(-1 * time.Hour),
		TotalRequests: 200,
		TotalErrors:   20,
		StatusCodes:   map[int]int64{200: 180, 500: 20},
		PathMetrics: map[string]*PathMetrics{
			"/api/users": {Count: 100},
			"/api/items": {Count: 100},
		},
	})

	// Query all
	result, err := storage.Query(Query{})
	if err != nil {
		t.Errorf("Query() error = %v", err)
	}

	if result.TotalRequests != 300 {
		t.Errorf("TotalRequests = %d, want 300", result.TotalRequests)
	}
	if result.TotalErrors != 30 {
		t.Errorf("TotalErrors = %d, want 30", result.TotalErrors)
	}

	// Query with path filter
	result, err = storage.Query(Query{
		Paths: []string{"/api/users"},
	})
	if err != nil {
		t.Errorf("Query() error = %v", err)
	}

	if result.ByPath["/api/users"] == nil {
		t.Error("expected /api/users in result")
	}
	if result.ByPath["/api/items"] != nil {
		t.Error("expected /api/items to be filtered out")
	}
}

func TestCollector(t *testing.T) {
	p := NewPipeline(PipelineConfig{
		BufferSize: 100,
	})
	p.Start()
	defer p.Stop()

	collector := NewCollector(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("User-Agent", "TestClient/1.0")
	req.Header.Set("X-Forwarded-For", "192.168.1.1")

	collector.CollectResponse(req, http.StatusOK, 1024, 100*time.Millisecond, "users-route", "backend1")

	// Give time for processing
	time.Sleep(50 * time.Millisecond)

	stats := p.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", stats.TotalRequests)
	}
}

func TestCollector_ErrorResponse(t *testing.T) {
	p := NewPipeline(PipelineConfig{
		BufferSize: 100,
	})
	p.Start()
	defer p.Stop()

	collector := NewCollector(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	collector.CollectResponse(req, http.StatusInternalServerError, 0, 50*time.Millisecond, "", "")

	time.Sleep(50 * time.Millisecond)

	stats := p.GetStats()
	if stats.TotalErrors != 1 {
		t.Errorf("TotalErrors = %d, want 1", stats.TotalErrors)
	}
}

func TestMiddleware(t *testing.T) {
	p := NewPipeline(PipelineConfig{
		BufferSize: 100,
	})
	p.Start()
	defer p.Stop()

	collector := NewCollector(p, nil)

	handler := Middleware(collector, func(r *http.Request) (string, string) {
		return "test-route", "test-upstream"
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	time.Sleep(50 * time.Millisecond)

	stats := p.GetStats()
	if stats.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", stats.TotalRequests)
	}
}

func TestHandler_Stats(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	// Record some events
	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/users",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
	})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/analytics/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var stats Stats
	json.NewDecoder(rec.Body).Decode(&stats)

	if stats.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", stats.TotalRequests)
	}
}

func TestHandler_Snapshot(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
		Duration:   50 * time.Millisecond,
	})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/analytics/snapshot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var snapshot Snapshot
	json.NewDecoder(rec.Body).Decode(&snapshot)

	if snapshot.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", snapshot.TotalRequests)
	}
}

func TestHandler_Query(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	// Flush to storage first
	p.GetAggregator().Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
	})
	p.flush()

	h := NewHandler(p, nil)

	queryBody := `{"paths": ["/api/test"]}`
	req := httptest.NewRequest(http.MethodPost, "/analytics/query", strings.NewReader(queryBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandler_Paths(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/users",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
	})
	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/items",
		StatusCode: 200,
		Duration:   50 * time.Millisecond,
	})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/analytics/paths", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var paths []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&paths)

	if len(paths) != 2 {
		t.Errorf("len(paths) = %d, want 2", len(paths))
	}
}

func TestHandler_StatusCodes(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	p.Record(&Event{Type: EventTypeResponse, Path: "/test", StatusCode: 200})
	p.Record(&Event{Type: EventTypeResponse, Path: "/test", StatusCode: 200})
	p.Record(&Event{Type: EventTypeResponse, Path: "/test", StatusCode: 404})
	p.Record(&Event{Type: EventTypeResponse, Path: "/test", StatusCode: 500})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/analytics/status-codes", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var statuses []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&statuses)

	// Should have 3 unique status codes
	if len(statuses) != 3 {
		t.Errorf("len(statuses) = %d, want 3", len(statuses))
	}
}

func TestHandler_Latency(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
	})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	req := httptest.NewRequest(http.MethodGet, "/analytics/latency", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	var latency map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&latency)

	if latency["avg_ms"] == nil {
		t.Error("expected avg_ms in response")
	}
	if latency["by_path"] == nil {
		t.Error("expected by_path in response")
	}
}

func TestHandler_Reset(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	p.Record(&Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
	})

	time.Sleep(50 * time.Millisecond)

	h := NewHandler(p, nil)

	// Reset
	req := httptest.NewRequest(http.MethodPost, "/analytics/reset", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Reset status = %d, want 200", rec.Code)
	}

	// Verify reset
	stats := p.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("TotalRequests after reset = %d, want 0", stats.TotalRequests)
	}
}

func TestStream(t *testing.T) {
	stream := NewStream()

	received := make(chan *Event, 1)
	sub := &testSubscriber{eventCh: received}

	stream.Subscribe(sub)

	event := &Event{
		Type: EventTypeResponse,
		Path: "/test",
	}
	stream.PublishEvent(event)

	select {
	case e := <-received:
		if e.Path != "/test" {
			t.Errorf("Path = %v, want /test", e.Path)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("event not received")
	}

	stream.Unsubscribe(sub)

	// After unsubscribe, should not receive
	stream.PublishEvent(event)
	select {
	case <-received:
		t.Error("should not receive after unsubscribe")
	case <-time.After(50 * time.Millisecond):
		// OK
	}
}

type testSubscriber struct {
	eventCh    chan *Event
	snapshotCh chan *Snapshot
}

func (s *testSubscriber) OnEvent(event *Event) {
	if s.eventCh != nil {
		s.eventCh <- event
	}
}

func (s *testSubscriber) OnSnapshot(snapshot *Snapshot) {
	if s.snapshotCh != nil {
		s.snapshotCh <- snapshot
	}
}

func TestStreamingPipeline(t *testing.T) {
	p := NewStreamingPipeline(PipelineConfig{
		BufferSize: 100,
	})
	p.Start()
	defer p.Stop()

	received := make(chan *Event, 1)
	sub := &testSubscriber{eventCh: received}
	p.GetStream().Subscribe(sub)

	event := &Event{
		Type:       EventTypeResponse,
		Path:       "/api/test",
		StatusCode: 200,
	}
	p.Record(event)

	select {
	case e := <-received:
		if e.Path != "/api/test" {
			t.Errorf("Path = %v, want /api/test", e.Path)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("event not received in stream")
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteAddr string
		want     string
	}{
		{
			name:       "X-Forwarded-For",
			headers:    map[string]string{"X-Forwarded-For": "192.168.1.1, 10.0.0.1"},
			remoteAddr: "127.0.0.1:1234",
			want:       "192.168.1.1",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "10.0.0.1"},
			remoteAddr: "127.0.0.1:1234",
			want:       "10.0.0.1",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "127.0.0.1:1234",
			want:       "127.0.0.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := getClientIP(req)
			if got != tt.want {
				t.Errorf("getClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPercentile(t *testing.T) {
	// Empty slice
	if p := percentile([]time.Duration{}, 50); p != 0 {
		t.Errorf("percentile(empty, 50) = %v, want 0", p)
	}

	// Single element
	sorted := []time.Duration{100 * time.Millisecond}
	if p := percentile(sorted, 50); p != 100*time.Millisecond {
		t.Errorf("percentile(single, 50) = %v, want 100ms", p)
	}

	// Multiple elements
	sorted = []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
		60 * time.Millisecond,
		70 * time.Millisecond,
		80 * time.Millisecond,
		90 * time.Millisecond,
		100 * time.Millisecond,
	}

	p50 := percentile(sorted, 50)
	if p50 != 50*time.Millisecond {
		t.Errorf("P50 = %v, want 50ms", p50)
	}

	p90 := percentile(sorted, 90)
	if p90 != 90*time.Millisecond {
		t.Errorf("P90 = %v, want 90ms", p90)
	}
}

func TestContainsString(t *testing.T) {
	slice := []string{"a", "b", "c"}

	if !containsString(slice, "b") {
		t.Error("expected to find 'b'")
	}
	if containsString(slice, "d") {
		t.Error("expected not to find 'd'")
	}
}

func TestPipeline_GetStats_TopPaths(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	p.Start()
	defer p.Stop()

	// Record events for multiple paths
	for i := 0; i < 100; i++ {
		p.Record(&Event{Type: EventTypeResponse, Path: "/api/users", StatusCode: 200, Duration: time.Millisecond})
	}
	for i := 0; i < 50; i++ {
		p.Record(&Event{Type: EventTypeResponse, Path: "/api/items", StatusCode: 200, Duration: time.Millisecond})
	}
	for i := 0; i < 25; i++ {
		p.Record(&Event{Type: EventTypeResponse, Path: "/api/orders", StatusCode: 200, Duration: time.Millisecond})
	}

	time.Sleep(100 * time.Millisecond)

	stats := p.GetStats()

	if len(stats.TopPaths) < 3 {
		t.Errorf("TopPaths count = %d, want >= 3", len(stats.TopPaths))
	}

	// First should be /api/users with most requests
	if stats.TopPaths[0].Path != "/api/users" {
		t.Errorf("TopPaths[0].Path = %v, want /api/users", stats.TopPaths[0].Path)
	}
	if stats.TopPaths[0].Count != 100 {
		t.Errorf("TopPaths[0].Count = %d, want 100", stats.TopPaths[0].Count)
	}
}

func TestEvent_Types(t *testing.T) {
	if EventTypeRequest != "request" {
		t.Errorf("EventTypeRequest = %v", EventTypeRequest)
	}
	if EventTypeResponse != "response" {
		t.Errorf("EventTypeResponse = %v", EventTypeResponse)
	}
	if EventTypeError != "error" {
		t.Errorf("EventTypeError = %v", EventTypeError)
	}
}
