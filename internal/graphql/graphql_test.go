package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewGateway(t *testing.T) {
	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)

	if gw == nil {
		t.Fatal("expected gateway to be created")
	}
	if gw.analyzer == nil {
		t.Error("expected analyzer to be created")
	}
	if gw.apqCache == nil {
		t.Error("expected APQ cache to be created when EnableAPQ is true")
	}
}

func TestQueryAnalyzer_Analyze(t *testing.T) {
	config := DefaultGatewayConfig()
	analyzer := NewQueryAnalyzer(config)

	tests := []struct {
		name            string
		query           string
		expectedDepth   int
		hasQuery        bool
		hasMutation     bool
		isIntrospection bool
	}{
		{
			name: "simple query",
			query: `
				query {
					user {
						id
						name
					}
				}
			`,
			expectedDepth: 2,
			hasQuery:      true,
		},
		{
			name: "nested query",
			query: `
				query {
					user {
						posts {
							comments {
								author {
									name
								}
							}
						}
					}
				}
			`,
			expectedDepth: 5,
			hasQuery:      true,
		},
		{
			name: "mutation",
			query: `
				mutation {
					createUser(name: "test") {
						id
					}
				}
			`,
			expectedDepth: 2,
			hasMutation:   true,
		},
		{
			name: "introspection",
			query: `
				query {
					__schema {
						types {
							name
						}
					}
				}
			`,
			expectedDepth:   3,
			hasQuery:        true,
			isIntrospection: true,
		},
		{
			name: "implicit query",
			query: `
				{
					user {
						id
					}
				}
			`,
			expectedDepth: 2,
			hasQuery:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := analyzer.Analyze(tt.query)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if analysis.Depth != tt.expectedDepth {
				t.Errorf("depth = %d, want %d", analysis.Depth, tt.expectedDepth)
			}
			if analysis.HasQuery != tt.hasQuery {
				t.Errorf("hasQuery = %v, want %v", analysis.HasQuery, tt.hasQuery)
			}
			if analysis.HasMutation != tt.hasMutation {
				t.Errorf("hasMutation = %v, want %v", analysis.HasMutation, tt.hasMutation)
			}
			if analysis.IsIntrospection != tt.isIntrospection {
				t.Errorf("isIntrospection = %v, want %v", analysis.IsIntrospection, tt.isIntrospection)
			}
		})
	}
}

func TestQueryAnalyzer_ExtractFields(t *testing.T) {
	config := DefaultGatewayConfig()
	analyzer := NewQueryAnalyzer(config)

	query := `
		query {
			user {
				id
				name
				posts {
					title
				}
			}
		}
	`

	analysis, err := analyzer.Analyze(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(analysis.Fields) == 0 {
		t.Error("expected fields to be extracted")
	}
}

func TestQueryAnalyzer_Complexity(t *testing.T) {
	config := DefaultGatewayConfig()
	config.FieldComplexity = map[string]int{
		"posts": 10,
		"users": 5,
	}
	config.DefaultFieldComplexity = 1

	analyzer := NewQueryAnalyzer(config)

	query := `
		query {
			user {
				id
				name
			}
		}
	`

	analysis, err := analyzer.Analyze(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if analysis.Complexity <= 0 {
		t.Error("expected complexity to be calculated")
	}
}

func TestGateway_ProcessRequest_DepthLimit(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxDepth = 3

	gw := NewGateway(config, nil)

	tests := []struct {
		name        string
		query       string
		expectError bool
	}{
		{
			name: "within limit",
			query: `
				query {
					user {
						id
					}
				}
			`,
			expectError: false,
		},
		{
			name: "exceeds limit",
			query: `
				query {
					user {
						posts {
							comments {
								id
							}
						}
					}
				}
			`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GatewayRequest{Query: tt.query}
			_, _, err := gw.ProcessRequest(context.Background(), req)

			if tt.expectError && err != ErrQueryTooDeep {
				t.Errorf("expected ErrQueryTooDeep, got %v", err)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGateway_ProcessRequest_ComplexityLimit(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxComplexity = 5
	config.DefaultFieldComplexity = 2

	gw := NewGateway(config, nil)

	tests := []struct {
		name        string
		query       string
		expectError bool
	}{
		{
			name: "within limit",
			query: `
				query {
					user {
						id
					}
				}
			`,
			expectError: false,
		},
		{
			name: "exceeds limit",
			query: `
				query {
					user {
						id
						name
						email
						posts {
							title
						}
					}
				}
			`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GatewayRequest{Query: tt.query}
			_, _, err := gw.ProcessRequest(context.Background(), req)

			if tt.expectError && err != ErrQueryTooComplex {
				t.Errorf("expected ErrQueryTooComplex, got %v", err)
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGateway_ProcessRequest_IntrospectionBlock(t *testing.T) {
	config := DefaultGatewayConfig()
	config.AllowIntrospection = false

	gw := NewGateway(config, nil)

	req := &GatewayRequest{
		Query: `
			query {
				__schema {
					types {
						name
					}
				}
			}
		`,
	}

	_, _, err := gw.ProcessRequest(context.Background(), req)
	if err != ErrIntrospectionBlock {
		t.Errorf("expected ErrIntrospectionBlock, got %v", err)
	}
}

func TestGateway_ProcessRequest_BlockedFields(t *testing.T) {
	config := DefaultGatewayConfig()
	config.BlockedFields = []string{"secretField", "admin.*"}

	gw := NewGateway(config, nil)

	tests := []struct {
		name        string
		query       string
		expectError bool
	}{
		{
			name: "allowed field",
			query: `
				query {
					user {
						id
					}
				}
			`,
			expectError: false,
		},
		{
			name: "blocked field",
			query: `
				query {
					secretField
				}
			`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GatewayRequest{Query: tt.query}
			_, _, err := gw.ProcessRequest(context.Background(), req)

			if tt.expectError && err == nil {
				t.Error("expected error for blocked field")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAPQCache(t *testing.T) {
	cache := NewAPQCache(100, time.Hour)

	// Test set and get
	hash := "abc123"
	query := "query { user { id } }"

	cache.Set(hash, query)

	got, found := cache.Get(hash)
	if !found {
		t.Error("expected to find cached query")
	}
	if got != query {
		t.Errorf("got %q, want %q", got, query)
	}

	// Test miss
	_, found = cache.Get("nonexistent")
	if found {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestAPQCache_Expiration(t *testing.T) {
	cache := NewAPQCache(100, 10*time.Millisecond)

	hash := "abc123"
	query := "query { user { id } }"

	cache.Set(hash, query)

	// Should find immediately
	_, found := cache.Get(hash)
	if !found {
		t.Error("expected to find cached query")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should not find after expiration
	_, found = cache.Get(hash)
	if found {
		t.Error("expected cache miss after expiration")
	}
}

func TestAPQCache_Eviction(t *testing.T) {
	cache := NewAPQCache(3, time.Hour)

	// Fill cache
	cache.Set("1", "query1")
	cache.Set("2", "query2")
	cache.Set("3", "query3")

	if cache.Size() != 3 {
		t.Errorf("cache size = %d, want 3", cache.Size())
	}

	// Add one more, should evict oldest
	cache.Set("4", "query4")

	if cache.Size() != 3 {
		t.Errorf("cache size = %d, want 3", cache.Size())
	}
}

func TestGateway_APQ(t *testing.T) {
	config := DefaultGatewayConfig()
	config.EnableAPQ = true

	gw := NewGateway(config, nil)

	query := "query { user { id } }"
	hash := "d6d41a61e5d1b6f43db14f7b9df4c5d3e3e0b2c5f6a8d9e1c2b3a4f5e6d7c8b9" // fake hash

	// First request with query - stores in cache
	req := &GatewayRequest{
		Query: query,
		Extensions: &GatewayExtensions{
			PersistedQuery: &PersistedQueryExtension{
				Version:    1,
				SHA256Hash: hash,
			},
		},
	}

	// This will fail because hash doesn't match
	_, _, err := gw.ProcessRequest(context.Background(), req)
	if err != ErrInvalidQuery {
		t.Errorf("expected ErrInvalidQuery for mismatched hash, got %v", err)
	}
}

func TestRoleBasedAuthorizer(t *testing.T) {
	roleExtractor := func(ctx context.Context) []string {
		if roles, ok := ctx.Value("roles").([]string); ok {
			return roles
		}
		return nil
	}

	auth := NewRoleBasedAuthorizer(roleExtractor)
	auth.AddFieldRole("admin.*", "admin")
	auth.AddFieldRole("user.email", "user", "admin")

	tests := []struct {
		name      string
		field     string
		roles     []string
		canAccess bool
	}{
		{
			name:      "admin accessing admin field",
			field:     "admin.users",
			roles:     []string{"admin"},
			canAccess: true,
		},
		{
			name:      "user accessing admin field",
			field:     "admin.users",
			roles:     []string{"user"},
			canAccess: false,
		},
		{
			name:      "user accessing user.email",
			field:     "user.email",
			roles:     []string{"user"},
			canAccess: true,
		},
		{
			name:      "no role accessing public field",
			field:     "public.data",
			roles:     nil,
			canAccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.roles != nil {
				ctx = context.WithValue(ctx, "roles", tt.roles)
			}

			got := auth.CanAccessField(ctx, tt.field)
			if got != tt.canAccess {
				t.Errorf("CanAccessField(%q) = %v, want %v", tt.field, got, tt.canAccess)
			}
		})
	}
}

func TestGatewaySchemaCache(t *testing.T) {
	cache := NewGatewaySchemaCache()

	schema := &GatewaySchema{
		Name:      "test",
		SDL:       "type Query { test: String }",
		UpdatedAt: time.Now(),
	}

	cache.Set("test", schema)

	got, found := cache.Get("test")
	if !found {
		t.Error("expected to find schema")
	}
	if got.Name != "test" {
		t.Errorf("schema name = %q, want %q", got.Name, "test")
	}

	cache.Delete("test")
	_, found = cache.Get("test")
	if found {
		t.Error("expected schema to be deleted")
	}
}

func TestGatewayHandler_ServeHTTP(t *testing.T) {
	// Create mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GatewayResponse{
			Data: map[string]interface{}{
				"user": map[string]interface{}{
					"id":   "1",
					"name": "Test User",
				},
			},
		})
	}))
	defer upstream.Close()

	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)

	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: upstream.URL,
	})

	// Test POST request
	body := `{"query": "query { user { id name } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp GatewayResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data == nil {
		t.Error("expected data in response")
	}
}

func TestGatewayHandler_ServeHTTP_GET(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GatewayResponse{
			Data: map[string]interface{}{"test": "value"},
		})
	}))
	defer upstream.Close()

	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)

	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: upstream.URL,
	})

	req := httptest.NewRequest(http.MethodGet, "/graphql?query=query{test}", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGatewayHandler_ServeHTTP_DepthError(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxDepth = 2

	gw := NewGateway(config, nil)

	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: "http://localhost:8080",
	})

	body := `{"query": "query { user { posts { comments { id } } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp GatewayResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Errors) == 0 {
		t.Error("expected errors in response")
	}
}

func TestGatewayHandler_BatchRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GatewayResponse{
			Data: map[string]interface{}{"test": "value"},
		})
	}))
	defer upstream.Close()

	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)

	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: upstream.URL,
	})

	body := `[{"query": "query { a }"}, {"query": "query { b }"}]`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []GatewayResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp) != 2 {
		t.Errorf("response count = %d, want 2", len(resp))
	}
}

func TestGatewayMiddleware(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxDepth = 3

	gw := NewGateway(config, nil)
	mw := NewGatewayMiddleware(GatewayMiddlewareConfig{Gateway: gw})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(next)

	// Valid query - should pass through
	body := `{"query": "query { user { id } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
}

func TestGatewayMiddleware_BlocksDeepQuery(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxDepth = 2

	gw := NewGateway(config, nil)
	mw := NewGatewayMiddleware(GatewayMiddlewareConfig{Gateway: gw})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := mw.Handler(next)

	body := `{"query": "query { user { posts { comments { id } } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("expected next handler to NOT be called for deep query")
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGatewayAdminHandler_Stats(t *testing.T) {
	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)
	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: "http://localhost",
	})

	admin := NewGatewayAdminHandler(gw, handler, nil)

	req := httptest.NewRequest(http.MethodGet, "/graphql/admin/stats", nil)
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var stats GatewayStats
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
}

func TestGatewayAdminHandler_Config(t *testing.T) {
	config := DefaultGatewayConfig()
	config.MaxDepth = 5
	config.MaxComplexity = 100

	gw := NewGateway(config, nil)
	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: "http://localhost",
	})

	admin := NewGatewayAdminHandler(gw, handler, nil)

	req := httptest.NewRequest(http.MethodGet, "/graphql/admin/config", nil)
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGatewayAdminHandler_Analyze(t *testing.T) {
	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)
	handler := NewGatewayHandler(GatewayHandlerConfig{
		Gateway:  gw,
		Upstream: "http://localhost",
	})

	admin := NewGatewayAdminHandler(gw, handler, nil)

	body := `{"query": "query { user { id posts { title } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql/admin/analyze", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGatewayStatsCollector(t *testing.T) {
	collector := NewGatewayStatsCollector(nil)

	collector.RecordRequest()
	collector.RecordRequest()
	collector.RecordError()
	collector.RecordBlocked("depth")
	collector.RecordOperation("query")
	collector.RecordOperation("query")
	collector.RecordOperation("mutation")

	stats := collector.GetStats()

	if stats.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", stats.TotalRequests)
	}
	if stats.TotalErrors != 1 {
		t.Errorf("TotalErrors = %d, want 1", stats.TotalErrors)
	}
	if stats.DepthViolations != 1 {
		t.Errorf("DepthViolations = %d, want 1", stats.DepthViolations)
	}
	if stats.OperationCounts["query"] != 2 {
		t.Errorf("query count = %d, want 2", stats.OperationCounts["query"])
	}
	if stats.OperationCounts["mutation"] != 1 {
		t.Errorf("mutation count = %d, want 1", stats.OperationCounts["mutation"])
	}
}

func TestFederatedGateway(t *testing.T) {
	config := DefaultGatewayConfig()
	fg := NewFederatedGateway(config, nil)

	// Add services
	fg.AddService(&ServiceDefinition{
		Name: "users",
		URL:  "http://users:8080/graphql",
		SDL:  "type Query { user(id: ID!): User }",
	})

	fg.AddService(&ServiceDefinition{
		Name: "posts",
		URL:  "http://posts:8080/graphql",
		SDL:  "type Query { posts: [Post] }",
	})

	services := fg.GetServices()
	if len(services) != 2 {
		t.Errorf("service count = %d, want 2", len(services))
	}

	// Test routing (simplified)
	req := &GatewayRequest{Query: "query { users { id } }"}
	serviceName, err := fg.RouteQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should route to users service
	if serviceName != "users" {
		t.Errorf("routed to %q, want %q", serviceName, "users")
	}

	// Remove service
	fg.RemoveService("users")
	services = fg.GetServices()
	if len(services) != 1 {
		t.Errorf("service count = %d, want 1", len(services))
	}
}

func TestParseGatewayBatchRequest(t *testing.T) {
	// Test batch array
	data := []byte(`[{"query": "query { a }"}, {"query": "query { b }"}]`)
	batch, err := ParseGatewayBatchRequest(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(batch.Requests) != 2 {
		t.Errorf("request count = %d, want 2", len(batch.Requests))
	}

	// Test single request
	data = []byte(`{"query": "query { a }"}`)
	batch, err = ParseGatewayBatchRequest(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(batch.Requests) != 1 {
		t.Errorf("request count = %d, want 1", len(batch.Requests))
	}
}

func TestQueryAnalyzer_RemoveComments(t *testing.T) {
	query := `
		# This is a comment
		query {
			user { # inline comment
				id
			}
		}
	`

	config := DefaultGatewayConfig()
	analyzer := NewQueryAnalyzer(config)

	analysis, err := analyzer.Analyze(query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !analysis.HasQuery {
		t.Error("expected HasQuery to be true")
	}
}

func TestMatchField(t *testing.T) {
	tests := []struct {
		field   string
		pattern string
		match   bool
	}{
		{"user", "user", true},
		{"user", "admin", false},
		{"admin.users", "admin.*", true},
		{"admin.settings", "admin.*", true},
		{"user.settings", "admin.*", false},
		{"anything", "*", true},
	}

	for _, tt := range tests {
		t.Run(tt.field+"/"+tt.pattern, func(t *testing.T) {
			got := matchField(tt.field, tt.pattern)
			if got != tt.match {
				t.Errorf("matchField(%q, %q) = %v, want %v", tt.field, tt.pattern, got, tt.match)
			}
		})
	}
}

func TestGatewayWebSocketHandler(t *testing.T) {
	config := DefaultGatewayConfig()
	gw := NewGateway(config, nil)

	wsHandler := NewGatewayWebSocketHandler(gw, nil)

	// Test connection_init
	resp, err := wsHandler.HandleMessage(context.Background(), "connection_init", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respMap, ok := resp.(map[string]string)
	if !ok {
		t.Fatal("expected map response")
	}
	if respMap["type"] != "connection_ack" {
		t.Errorf("type = %q, want %q", respMap["type"], "connection_ack")
	}

	// Test cleanup
	wsHandler.Close()
}

func TestGetAnalysisFromContext(t *testing.T) {
	analysis := &QueryAnalysis{
		Depth:      5,
		Complexity: 10,
	}

	ctx := context.WithValue(context.Background(), graphqlAnalysisKey, analysis)

	got := GetAnalysisFromContext(ctx)
	if got == nil {
		t.Fatal("expected analysis from context")
	}
	if got.Depth != 5 {
		t.Errorf("Depth = %d, want 5", got.Depth)
	}

	// Test missing
	got = GetAnalysisFromContext(context.Background())
	if got != nil {
		t.Error("expected nil for missing analysis")
	}
}
