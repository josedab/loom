package timetravel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMemoryStorage(t *testing.T) {
	storage := NewMemoryStorage(100)

	// Test Store and Get
	event := &Event{
		ID:        "test-1",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
		Request: RequestRecord{
			Method: "GET",
			URL:    "/api/users",
		},
		Response: ResponseRecord{
			StatusCode: 200,
		},
	}

	if err := storage.Store(event); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	retrieved, err := storage.Get("test-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.ID != event.ID {
		t.Errorf("expected ID %s, got %s", event.ID, retrieved.ID)
	}
	if retrieved.Request.Method != "GET" {
		t.Errorf("expected method GET, got %s", retrieved.Request.Method)
	}
}

func TestMemoryStorageQuery(t *testing.T) {
	storage := NewMemoryStorage(100)

	now := time.Now()

	// Store multiple events
	events := []*Event{
		{ID: "1", Timestamp: now.Add(-3 * time.Hour), Request: RequestRecord{Method: "GET", URL: "/api/users"}, Response: ResponseRecord{StatusCode: 200}},
		{ID: "2", Timestamp: now.Add(-2 * time.Hour), Request: RequestRecord{Method: "POST", URL: "/api/users"}, Response: ResponseRecord{StatusCode: 201}},
		{ID: "3", Timestamp: now.Add(-1 * time.Hour), Request: RequestRecord{Method: "GET", URL: "/api/posts"}, Response: ResponseRecord{StatusCode: 200}},
		{ID: "4", Timestamp: now, Request: RequestRecord{Method: "GET", URL: "/api/users/123"}, Response: ResponseRecord{StatusCode: 404}},
	}

	for _, e := range events {
		storage.Store(e)
	}

	tests := []struct {
		name    string
		opts    QueryOptions
		wantLen int
	}{
		{
			name:    "all events",
			opts:    QueryOptions{},
			wantLen: 4,
		},
		{
			name:    "filter by method",
			opts:    QueryOptions{Method: "GET"},
			wantLen: 3,
		},
		{
			name:    "filter by path",
			opts:    QueryOptions{Path: "/api/users"},
			wantLen: 3,
		},
		{
			name:    "filter by status",
			opts:    QueryOptions{StatusCode: 200},
			wantLen: 2,
		},
		{
			name:    "filter by time range",
			opts:    QueryOptions{StartTime: now.Add(-2*time.Hour - 30*time.Minute), EndTime: now.Add(-30 * time.Minute)},
			wantLen: 2,
		},
		{
			name:    "with limit",
			opts:    QueryOptions{Limit: 2},
			wantLen: 2,
		},
		{
			name:    "with offset",
			opts:    QueryOptions{Offset: 2},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := storage.Query(tt.opts)
			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}
			if len(results) != tt.wantLen {
				t.Errorf("expected %d results, got %d", tt.wantLen, len(results))
			}
		})
	}
}

func TestMemoryStorageDelete(t *testing.T) {
	storage := NewMemoryStorage(100)

	event := &Event{ID: "to-delete", Timestamp: time.Now()}
	storage.Store(event)

	if err := storage.Delete("to-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := storage.Get("to-delete")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestMemoryStorageCleanup(t *testing.T) {
	storage := NewMemoryStorage(100)

	now := time.Now()
	storage.Store(&Event{ID: "old", Timestamp: now.Add(-48 * time.Hour)})
	storage.Store(&Event{ID: "new", Timestamp: now})

	if err := storage.Cleanup(now.Add(-24 * time.Hour)); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	results, _ := storage.Query(QueryOptions{})
	if len(results) != 1 {
		t.Errorf("expected 1 event after cleanup, got %d", len(results))
	}

	if results[0].ID != "new" {
		t.Errorf("expected 'new' event to remain")
	}
}

func TestMemoryStorageMaxSize(t *testing.T) {
	storage := NewMemoryStorage(3)

	for i := 0; i < 5; i++ {
		storage.Store(&Event{ID: string(rune('a' + i)), Timestamp: time.Now()})
	}

	results, _ := storage.Query(QueryOptions{})
	if len(results) != 3 {
		t.Errorf("expected 3 events (max size), got %d", len(results))
	}
}

func TestRecorderWithCompression(t *testing.T) {
	storage := NewMemoryStorage(100)
	config := RecorderConfig{
		CompressBody: true,
	}

	recorder := NewRecorder(storage, config)
	defer recorder.Close()

	originalBody := []byte(`{"message": "hello world", "data": [1, 2, 3, 4, 5]}`)

	event := &Event{
		ID:        "test-compress",
		Timestamp: time.Now(),
		Request: RequestRecord{
			Method: "POST",
			URL:    "/api/test",
			Body:   originalBody,
		},
		Response: ResponseRecord{
			StatusCode: 200,
			Body:       originalBody,
		},
	}

	if err := recorder.Record(event); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// Retrieve and verify decompression
	retrieved, err := recorder.Get("test-compress")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved.Request.Body) != string(originalBody) {
		t.Errorf("request body mismatch after decompression")
	}
	if string(retrieved.Response.Body) != string(originalBody) {
		t.Errorf("response body mismatch after decompression")
	}
}

func TestRecorderQuery(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	now := time.Now()
	for i := 0; i < 5; i++ {
		recorder.Record(&Event{
			ID:        string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Request:   RequestRecord{Method: "GET", URL: "/api/test"},
			Response:  ResponseRecord{StatusCode: 200},
		})
	}

	results, err := recorder.Query(QueryOptions{Limit: 3})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestReplay(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	now := time.Now()
	for i := 0; i < 5; i++ {
		recorder.Record(&Event{
			ID:        string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Request:   RequestRecord{Method: "GET"},
			Response:  ResponseRecord{StatusCode: 200},
		})
	}

	replay, err := NewReplay(recorder, QueryOptions{})
	if err != nil {
		t.Fatalf("NewReplay failed: %v", err)
	}

	if replay.Count() != 5 {
		t.Errorf("expected 5 events, got %d", replay.Count())
	}

	// Test Next
	for i := 0; i < 5; i++ {
		event := replay.Next()
		if event == nil {
			t.Fatalf("expected event at position %d", i)
		}
	}

	// Next should return nil at end
	if event := replay.Next(); event != nil {
		t.Error("expected nil at end")
	}

	// Test Previous
	event := replay.Previous()
	if event == nil {
		t.Error("expected event from Previous")
	}

	// Test Seek
	event = replay.Seek(2)
	if event == nil {
		t.Error("expected event from Seek")
	}
	if replay.Position() != 2 {
		t.Errorf("expected position 2, got %d", replay.Position())
	}

	// Test invalid Seek
	if replay.Seek(-1) != nil {
		t.Error("expected nil for invalid seek")
	}
	if replay.Seek(100) != nil {
		t.Error("expected nil for out of bounds seek")
	}
}

func TestReplaySeekToTime(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		recorder.Record(&Event{
			ID:        string(rune('a' + i)),
			Timestamp: base.Add(time.Duration(i) * time.Hour),
			Request:   RequestRecord{Method: "GET"},
			Response:  ResponseRecord{StatusCode: 200},
		})
	}

	replay, _ := NewReplay(recorder, QueryOptions{})

	// Seek to middle
	target := base.Add(2*time.Hour + 30*time.Minute)
	event := replay.SeekToTime(target)
	if event == nil {
		t.Fatal("expected event from SeekToTime")
	}

	// Should find closest event (index 2 or 3)
	pos := replay.Position()
	if pos < 2 || pos > 3 {
		t.Errorf("expected position 2 or 3, got %d", pos)
	}
}

func TestDiffEvents(t *testing.T) {
	eventA := &Event{
		Request: RequestRecord{
			Method:  "GET",
			URL:     "/api/users",
			Headers: map[string][]string{"X-Custom": {"value1"}},
		},
		Response: ResponseRecord{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			BodyHash:   "hash1",
		},
	}

	eventB := &Event{
		Request: RequestRecord{
			Method:  "POST",
			URL:     "/api/users/new",
			Headers: map[string][]string{"X-Custom": {"value2"}, "X-New": {"new"}},
		},
		Response: ResponseRecord{
			StatusCode: 201,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			BodyHash:   "hash2",
		},
	}

	diff := DiffEvents(eventA, eventB)

	if len(diff.Changes) == 0 {
		t.Fatal("expected changes in diff")
	}

	// Check for expected changes
	changes := make(map[string]Change)
	for _, c := range diff.Changes {
		changes[c.Path] = c
	}

	if _, ok := changes["request.method"]; !ok {
		t.Error("expected method change")
	}
	if _, ok := changes["request.url"]; !ok {
		t.Error("expected url change")
	}
	if _, ok := changes["response.status_code"]; !ok {
		t.Error("expected status change")
	}
	if _, ok := changes["request.headers.X-New"]; !ok {
		t.Error("expected X-New header addition")
	}
}

func TestDiffEventsNoChanges(t *testing.T) {
	event := &Event{
		Request: RequestRecord{
			Method:  "GET",
			URL:     "/api/test",
			Headers: map[string][]string{"Accept": {"application/json"}},
		},
		Response: ResponseRecord{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
		},
	}

	diff := DiffEvents(event, event)

	if len(diff.Changes) != 0 {
		t.Errorf("expected no changes, got %d", len(diff.Changes))
	}
}

func TestAPIHandlerListEvents(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	recorder.Record(&Event{
		ID:        "test-1",
		Timestamp: time.Now(),
		Request:   RequestRecord{Method: "GET", URL: "/api/test"},
		Response:  ResponseRecord{StatusCode: 200},
	})

	handler := recorder.APIHandler()

	req := httptest.NewRequest("GET", "/events", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var events []*Event
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestAPIHandlerGetEvent(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	recorder.Record(&Event{
		ID:        "test-get",
		Timestamp: time.Now(),
		Request:   RequestRecord{Method: "GET"},
		Response:  ResponseRecord{StatusCode: 200},
	})

	handler := recorder.APIHandler()

	req := httptest.NewRequest("GET", "/events/test-get", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var event Event
	if err := json.NewDecoder(rec.Body).Decode(&event); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if event.ID != "test-get" {
		t.Errorf("expected ID 'test-get', got %q", event.ID)
	}
}

func TestAPIHandlerDeleteEvent(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	recorder.Record(&Event{
		ID:        "to-delete",
		Timestamp: time.Now(),
	})

	handler := recorder.APIHandler()

	req := httptest.NewRequest("DELETE", "/events/to-delete", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}

	// Verify deleted
	req = httptest.NewRequest("GET", "/events/to-delete", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", rec.Code)
	}
}

func TestAPIHandlerDiff(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	recorder.Record(&Event{
		ID:       "event-a",
		Request:  RequestRecord{Method: "GET", URL: "/old"},
		Response: ResponseRecord{StatusCode: 200},
	})
	recorder.Record(&Event{
		ID:       "event-b",
		Request:  RequestRecord{Method: "GET", URL: "/new"},
		Response: ResponseRecord{StatusCode: 201},
	})

	handler := recorder.APIHandler()

	req := httptest.NewRequest("GET", "/diff?a=event-a&b=event-b", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var diff Diff
	if err := json.NewDecoder(rec.Body).Decode(&diff); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(diff.Changes) == 0 {
		t.Error("expected changes in diff")
	}
}

func TestAPIHandlerReplay(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	for i := 0; i < 5; i++ {
		recorder.Record(&Event{
			ID:        string(rune('a' + i)),
			Timestamp: time.Now(),
			Request:   RequestRecord{Method: "GET"},
			Response:  ResponseRecord{StatusCode: 200},
		})
	}

	handler := recorder.APIHandler()

	body := bytes.NewBufferString(`{"limit": 10}`)
	req := httptest.NewRequest("POST", "/replay", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if result["count"].(float64) != 5 {
		t.Errorf("expected count 5, got %v", result["count"])
	}
}

func TestReplayer(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "replayed"}`))
	}))
	defer server.Close()

	replayer := NewReplayer(5*time.Second, nil)

	event := &Event{
		ID: "replay-test",
		Request: RequestRecord{
			Method: "GET",
			URL:    "/api/test",
			Headers: map[string][]string{
				"Accept": {"application/json"},
			},
		},
		Response: ResponseRecord{
			StatusCode: 200,
			Body:       []byte(`{"status": "original"}`),
			BodyHash:   hashBody([]byte(`{"status": "original"}`)),
		},
	}

	result, err := replayer.ReplayRequest(context.Background(), event, server.URL)
	if err != nil {
		t.Fatalf("ReplayRequest failed: %v", err)
	}

	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}

	if result.Replayed == nil {
		t.Fatal("expected replayed event")
	}

	if result.Replayed.Response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Replayed.Response.StatusCode)
	}

	// Should have diff in body
	if result.Diff == nil {
		t.Fatal("expected diff")
	}
}

func TestReplayerError(t *testing.T) {
	replayer := NewReplayer(100*time.Millisecond, nil)

	event := &Event{
		ID: "error-test",
		Request: RequestRecord{
			Method: "GET",
			URL:    "/api/test",
		},
		Response: ResponseRecord{StatusCode: 200},
	}

	// Use invalid URL
	result, err := replayer.ReplayRequest(context.Background(), event, "http://invalid-host-that-does-not-exist:12345")
	if err != nil {
		t.Fatalf("ReplayRequest should not return error, got: %v", err)
	}

	if result.Error == "" {
		t.Error("expected error in result")
	}
}

func TestCompressDecompress(t *testing.T) {
	original := []byte("Hello, World! This is a test message for compression.")

	compressed := compressBody(original)
	if len(compressed) == 0 {
		t.Fatal("compression returned empty")
	}

	decompressed := decompressBody(compressed)
	if string(decompressed) != string(original) {
		t.Errorf("decompressed mismatch: got %q", decompressed)
	}
}

func TestCompressEmptyBody(t *testing.T) {
	result := compressBody(nil)
	if len(result) != 0 {
		t.Error("expected empty result for nil input")
	}

	result = compressBody([]byte{})
	if len(result) != 0 {
		t.Error("expected empty result for empty input")
	}
}

func TestHashBody(t *testing.T) {
	hash1 := hashBody([]byte("test"))
	hash2 := hashBody([]byte("test"))
	hash3 := hashBody([]byte("different"))

	if hash1 != hash2 {
		t.Error("same input should produce same hash")
	}

	if hash1 == hash3 {
		t.Error("different input should produce different hash")
	}

	if len(hash1) != 64 {
		t.Errorf("expected 64 char hash, got %d", len(hash1))
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		url     string
		path    string
		matches bool
	}{
		{"/api/users", "/api", true},
		{"/api/users/123", "/api/users", true},
		{"/other/path", "/api", false},
		{"/api", "/api/users", false},
	}

	for _, tt := range tests {
		result := matchPath(tt.url, tt.path)
		if result != tt.matches {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.url, tt.path, result, tt.matches)
		}
	}
}

func TestSortEvents(t *testing.T) {
	now := time.Now()
	events := []*Event{
		{Timestamp: now.Add(2 * time.Hour), Duration: 100 * time.Millisecond, Response: ResponseRecord{StatusCode: 200}},
		{Timestamp: now, Duration: 300 * time.Millisecond, Response: ResponseRecord{StatusCode: 500}},
		{Timestamp: now.Add(1 * time.Hour), Duration: 200 * time.Millisecond, Response: ResponseRecord{StatusCode: 404}},
	}

	// Sort by timestamp ascending
	sortEvents(events, "timestamp", false)
	if !events[0].Timestamp.Equal(now) {
		t.Error("expected earliest event first")
	}

	// Sort by timestamp descending
	sortEvents(events, "timestamp", true)
	if !events[0].Timestamp.Equal(now.Add(2 * time.Hour)) {
		t.Error("expected latest event first")
	}

	// Sort by duration
	sortEvents(events, "duration", false)
	if events[0].Duration != 100*time.Millisecond {
		t.Error("expected shortest duration first")
	}

	// Sort by status
	sortEvents(events, "status", false)
	if events[0].Response.StatusCode != 200 {
		t.Error("expected lowest status first")
	}
}

func TestDefaultRecorderConfig(t *testing.T) {
	cfg := DefaultRecorderConfig()

	if cfg.MaxBodySize != 1024*1024 {
		t.Errorf("expected MaxBodySize 1MB, got %d", cfg.MaxBodySize)
	}
	if cfg.MaxEvents != 100000 {
		t.Errorf("expected MaxEvents 100000, got %d", cfg.MaxEvents)
	}
	if cfg.RetentionPeriod != 24*time.Hour {
		t.Errorf("expected 24h retention, got %v", cfg.RetentionPeriod)
	}
	if cfg.SampleRate != 100 {
		t.Errorf("expected SampleRate 100, got %d", cfg.SampleRate)
	}
	if !cfg.CompressBody {
		t.Error("expected CompressBody true")
	}
}

func TestIsHopByHop(t *testing.T) {
	hopByHop := []string{"Connection", "Keep-Alive", "Transfer-Encoding", "TE", "Trailer", "Upgrade"}
	notHopByHop := []string{"Content-Type", "Accept", "Authorization", "X-Custom"}

	for _, h := range hopByHop {
		if !isHopByHop(h) {
			t.Errorf("expected %s to be hop-by-hop", h)
		}
	}

	for _, h := range notHopByHop {
		if isHopByHop(h) {
			t.Errorf("expected %s to NOT be hop-by-hop", h)
		}
	}
}

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		a, b   []string
		expect bool
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{}, []string{}, true},
		{nil, nil, true},
	}

	for _, tt := range tests {
		result := equalStringSlices(tt.a, tt.b)
		if result != tt.expect {
			t.Errorf("equalStringSlices(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expect)
		}
	}
}

func TestAPIHandlerMethodNotAllowed(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	handler := recorder.APIHandler()

	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/events"},
		{"PUT", "/events/test"},
		{"GET", "/replay"},
		{"POST", "/diff"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d", tt.method, tt.path, rec.Code)
		}
	}
}

func TestAPIHandlerDiffMissingParams(t *testing.T) {
	storage := NewMemoryStorage(100)
	recorder := NewRecorder(storage, RecorderConfig{})
	defer recorder.Close()

	handler := recorder.APIHandler()

	tests := []struct {
		query string
	}{
		{""},
		{"a=event1"},
		{"b=event2"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/diff?"+tt.query, nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: expected 400, got %d", tt.query, rec.Code)
		}
	}
}
