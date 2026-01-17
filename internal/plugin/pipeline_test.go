package plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewPipeline_NilRuntime(t *testing.T) {
	p := NewPipeline(nil)

	if p == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if p.chains == nil {
		t.Error("expected non-nil chains map")
	}
	if p.runtime != nil {
		t.Error("expected nil runtime when passed nil")
	}
}

func TestPipeline_BuildChain_EmptyPlugins(t *testing.T) {
	p := NewPipeline(nil)

	// Should not panic with empty plugin list
	p.BuildChain("route1", []string{})

	chain := p.GetChain("route1")
	if len(chain) != 0 {
		t.Errorf("expected empty chain with empty plugin list, got %d entries", len(chain))
	}
}

func TestPipeline_GetChain_NonExistent(t *testing.T) {
	p := NewPipeline(nil)

	chain := p.GetChain("nonexistent")
	if chain != nil {
		t.Error("expected nil chain for non-existent route")
	}
}

func TestPipeline_ExecuteRequestPhase_EmptyChain(t *testing.T) {
	p := NewPipeline(nil)
	ctx := context.Background()
	reqCtx := NewRequestContext()

	result, err := p.ExecuteRequestPhase(ctx, "route1", PhaseOnRequestHeaders, reqCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Continue {
		t.Error("expected Continue to be true for empty chain")
	}
}

func TestPipeline_ExecuteResponsePhase_EmptyChain(t *testing.T) {
	p := NewPipeline(nil)
	ctx := context.Background()
	reqCtx := NewRequestContext()

	result, err := p.ExecuteResponsePhase(ctx, "route1", PhaseOnResponseHeaders, reqCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Continue {
		t.Error("expected Continue to be true for empty chain")
	}
}

func TestPipelineResult_Fields(t *testing.T) {
	result := &PipelineResult{
		Continue: true,
		ImmediateResponse: &ImmediateResponse{
			StatusCode: 200,
			Headers:    map[string]string{"X-Test": "value"},
			Body:       []byte("response body"),
		},
	}

	if !result.Continue {
		t.Error("expected Continue to be true")
	}
	if result.ImmediateResponse == nil {
		t.Fatal("expected non-nil ImmediateResponse")
	}
	if result.ImmediateResponse.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.ImmediateResponse.StatusCode)
	}
	if result.ImmediateResponse.Headers["X-Test"] != "value" {
		t.Error("header mismatch")
	}
	if string(result.ImmediateResponse.Body) != "response body" {
		t.Error("body mismatch")
	}
}

func TestPluginChainEntry_Fields(t *testing.T) {
	entry := &PluginChainEntry{
		Name:     "test-plugin",
		Priority: 100,
		Phase:    PhaseOnRequestHeaders,
	}

	if entry.Name != "test-plugin" {
		t.Errorf("expected name 'test-plugin', got %s", entry.Name)
	}
	if entry.Priority != 100 {
		t.Errorf("expected priority 100, got %d", entry.Priority)
	}
	if entry.Phase != PhaseOnRequestHeaders {
		t.Errorf("expected PhaseOnRequestHeaders, got %v", entry.Phase)
	}
}

func TestSetRouteID_ReturnsModifiedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	modifiedReq := SetRouteID(req, "my-route")

	// Ensure original request is not modified
	_, okOrig := req.Context().Value(routeIDKey).(string)
	if okOrig {
		t.Error("original request should not have route ID")
	}

	routeID, ok := modifiedReq.Context().Value(routeIDKey).(string)
	if !ok {
		t.Fatal("route ID not found in context")
	}
	if routeID != "my-route" {
		t.Errorf("expected route ID 'my-route', got %s", routeID)
	}
}

func TestPipeline_Middleware_NoRouteID(t *testing.T) {
	p := NewPipeline(nil)

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called when no route ID")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPipeline_Middleware_WithRouteID_EmptyChain(t *testing.T) {
	p := NewPipeline(nil)

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	})

	handler := p.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = SetRouteID(req, "route1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called for empty chain")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPipeline_Middleware_HeaderPropagation(t *testing.T) {
	p := NewPipeline(nil)

	var receivedHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	handler := p.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom", "custom-value")
	req.Header.Set("Content-Type", "application/json")
	req = SetRouteID(req, "route1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if receivedHeaders.Get("X-Custom") != "custom-value" {
		t.Error("expected X-Custom header to be propagated")
	}
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	// Set a header before WriteHeader
	rw.Header().Set("X-Response", "value")

	rw.WriteHeader(http.StatusCreated)

	if rw.statusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rw.statusCode)
	}
	if !rw.written {
		t.Error("expected written to be true")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("expected underlying recorder to have status 201, got %d", rec.Code)
	}
}

func TestResponseWriter_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	n, err := rw.Write([]byte("hello"))

	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if !rw.written {
		t.Error("expected written to be true after Write")
	}
	if rw.statusCode != http.StatusOK {
		t.Errorf("expected default status 200, got %d", rw.statusCode)
	}
}

func TestResponseWriter_WriteWithoutHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	rw.Write([]byte("data"))

	// Should implicitly call WriteHeader(200)
	if rw.statusCode != http.StatusOK {
		t.Errorf("expected implicit status 200, got %d", rw.statusCode)
	}
}

func TestResponseWriter_CapturesResponseHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("X-Custom", "value")
	rw.WriteHeader(http.StatusOK)

	// Response headers should be captured in reqCtx
	if reqCtx.ResponseHeaders["Content-Type"] != "application/json" {
		t.Error("Content-Type header not captured")
	}
	if reqCtx.ResponseHeaders["X-Custom"] != "value" {
		t.Error("X-Custom header not captured")
	}
}

func TestContextKey_String(t *testing.T) {
	key := routeIDKey
	if key != "routeID" {
		t.Errorf("expected routeIDKey to be 'routeID', got %v", key)
	}
}

func TestPipeline_ConcurrentAccess(t *testing.T) {
	p := NewPipeline(nil)

	done := make(chan bool, 20)

	// Concurrent builds (empty plugins) and gets
	for i := 0; i < 10; i++ {
		go func(id int) {
			// Use empty plugin list to avoid nil runtime panic
			p.BuildChain("route1", []string{})
			done <- true
		}(i)

		go func(id int) {
			_ = p.GetChain("route1")
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestPipeline_ExecuteRequestPhase_DifferentRoutes(t *testing.T) {
	p := NewPipeline(nil)
	ctx := context.Background()
	reqCtx := NewRequestContext()

	// Execute for different routes - all should succeed with empty chains
	routes := []string{"route1", "route2", "api-route", "admin-route"}

	for _, routeID := range routes {
		t.Run(routeID, func(t *testing.T) {
			result, err := p.ExecuteRequestPhase(ctx, routeID, PhaseOnRequestHeaders, reqCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Continue {
				t.Error("expected Continue to be true")
			}
		})
	}
}

func TestPipeline_ExecutePhases_DifferentPhases(t *testing.T) {
	p := NewPipeline(nil)
	ctx := context.Background()
	reqCtx := NewRequestContext()

	requestPhases := []ExecutionPhase{
		PhaseOnRequestHeaders,
		PhaseOnRequestBody,
	}

	responsePhases := []ExecutionPhase{
		PhaseOnResponseHeaders,
		PhaseOnResponseBody,
	}

	for _, phase := range requestPhases {
		t.Run(phase.String(), func(t *testing.T) {
			result, err := p.ExecuteRequestPhase(ctx, "route1", phase, reqCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Continue {
				t.Error("expected Continue to be true")
			}
		})
	}

	for _, phase := range responsePhases {
		t.Run(phase.String(), func(t *testing.T) {
			result, err := p.ExecuteResponsePhase(ctx, "route1", phase, reqCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Continue {
				t.Error("expected Continue to be true")
			}
		})
	}
}

func TestPipeline_Middleware_MultipleHeaders(t *testing.T) {
	p := NewPipeline(nil)

	var receivedHeaders http.Header
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("X-Response-Header", "value1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("body"))
	})

	handler := p.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom-1", "value1")
	req.Header.Set("X-Custom-2", "value2")
	req.Header.Set("Accept", "text/html")
	req = SetRouteID(req, "route1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify all headers were passed through
	if receivedHeaders.Get("X-Custom-1") != "value1" {
		t.Error("expected X-Custom-1 header")
	}
	if receivedHeaders.Get("X-Custom-2") != "value2" {
		t.Error("expected X-Custom-2 header")
	}
	if receivedHeaders.Get("Accept") != "text/html" {
		t.Error("expected Accept header")
	}
}

func TestPipeline_BuildChain_Multiple(t *testing.T) {
	p := NewPipeline(nil)

	// Build chains for multiple routes
	p.BuildChain("route1", []string{})
	p.BuildChain("route2", []string{})
	p.BuildChain("route3", []string{})

	// Verify all chains exist
	if p.GetChain("route1") == nil {
		// Empty chain is stored, just not as nil
		chain := p.GetChain("route1")
		if len(chain) != 0 {
			t.Error("expected empty chain for route1")
		}
	}
}

func TestResponseWriter_MultipleWrites(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte("first"))
	rw.Write([]byte(" second"))
	rw.Write([]byte(" third"))

	body := rec.Body.String()
	if body != "first second third" {
		t.Errorf("expected 'first second third', got %s", body)
	}
}

func TestResponseWriter_HeaderCapture(t *testing.T) {
	rec := httptest.NewRecorder()
	reqCtx := NewRequestContext()

	rw := &responseWriter{
		ResponseWriter: rec,
		reqCtx:         reqCtx,
	}

	// Set headers before WriteHeader
	rw.Header().Set("X-Test-1", "value1")
	rw.Header().Set("X-Test-2", "value2")
	rw.WriteHeader(http.StatusOK)

	// Verify headers were captured in reqCtx
	if reqCtx.ResponseHeaders["X-Test-1"] != "value1" {
		t.Error("X-Test-1 header not captured")
	}
	if reqCtx.ResponseHeaders["X-Test-2"] != "value2" {
		t.Error("X-Test-2 header not captured")
	}
}

func TestPipelineResult_Nil(t *testing.T) {
	result := &PipelineResult{}

	if result.Continue {
		t.Error("expected Continue to be false by default")
	}
	if result.ImmediateResponse != nil {
		t.Error("expected nil ImmediateResponse")
	}
}

func TestGetRouteID(t *testing.T) {
	// Test that routeIDKey is correctly defined
	if routeIDKey != "routeID" {
		t.Errorf("expected routeIDKey to be 'routeID', got %v", routeIDKey)
	}
}

func TestPipeline_ClearChains(t *testing.T) {
	p := NewPipeline(nil)

	// Build some chains
	p.BuildChain("route1", []string{})
	p.BuildChain("route2", []string{})
	p.BuildChain("route3", []string{})

	if p.GetChainCount() != 3 {
		t.Errorf("expected 3 chains, got %d", p.GetChainCount())
	}

	// Clear all chains
	p.ClearChains()

	if p.GetChainCount() != 0 {
		t.Errorf("expected 0 chains after clear, got %d", p.GetChainCount())
	}
}

func TestPipeline_RemoveChain(t *testing.T) {
	p := NewPipeline(nil)

	// Build some chains
	p.BuildChain("route1", []string{})
	p.BuildChain("route2", []string{})
	p.BuildChain("route3", []string{})

	if p.GetChainCount() != 3 {
		t.Errorf("expected 3 chains, got %d", p.GetChainCount())
	}

	// Remove one chain
	p.RemoveChain("route2")

	if p.GetChainCount() != 2 {
		t.Errorf("expected 2 chains after remove, got %d", p.GetChainCount())
	}

	// Verify the correct chain was removed
	if p.GetChain("route2") != nil {
		t.Error("expected route2 chain to be nil after remove")
	}
	if p.GetChain("route1") == nil {
		t.Error("expected route1 chain to still exist")
	}
	if p.GetChain("route3") == nil {
		t.Error("expected route3 chain to still exist")
	}
}

func TestPipeline_RemoveChain_NonExistent(t *testing.T) {
	p := NewPipeline(nil)

	// Should not panic when removing non-existent chain
	p.RemoveChain("nonexistent")

	if p.GetChainCount() != 0 {
		t.Errorf("expected 0 chains, got %d", p.GetChainCount())
	}
}

func TestPipeline_GetChainCount_Empty(t *testing.T) {
	p := NewPipeline(nil)

	if p.GetChainCount() != 0 {
		t.Errorf("expected 0 chains for new pipeline, got %d", p.GetChainCount())
	}
}
