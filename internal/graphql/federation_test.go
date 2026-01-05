package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
		opType  string
		hasSels bool
	}{
		{
			name:    "simple query",
			query:   "{ users { id name } }",
			opType:  "query",
			hasSels: true,
		},
		{
			name:    "explicit query",
			query:   "query GetUsers { users { id } }",
			opType:  "query",
			hasSels: true,
		},
		{
			name:    "mutation",
			query:   "mutation CreateUser { createUser(name: \"test\") { id } }",
			opType:  "mutation",
			hasSels: true,
		},
		{
			name:    "no selection set",
			query:   "query",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := ParseQuery(tt.query)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(doc.Operations) != 1 {
				t.Errorf("expected 1 operation, got %d", len(doc.Operations))
				return
			}

			op := doc.Operations[0]
			if op.Type != tt.opType {
				t.Errorf("expected operation type %q, got %q", tt.opType, op.Type)
			}

			if tt.hasSels && len(op.SelectionSet) == 0 {
				t.Error("expected selections")
			}
		})
	}
}

func TestParseSelection(t *testing.T) {
	tests := []struct {
		input string
		name  string
		alias string
		args  map[string]interface{}
	}{
		{
			input: "users",
			name:  "users",
		},
		{
			input: "allUsers: users",
			name:  "users",
			alias: "allUsers",
		},
		{
			input: "user(id: 123)",
			name:  "user",
			args:  map[string]interface{}{"id": float64(123)},
		},
		{
			input: `user(name: "test")`,
			name:  "user",
			args:  map[string]interface{}{"name": "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sel := parseSelection(tt.input)
			if sel == nil {
				t.Fatal("expected selection")
			}

			if sel.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, sel.Name)
			}
			if sel.Alias != tt.alias {
				t.Errorf("expected alias %q, got %q", tt.alias, sel.Alias)
			}

			for k, v := range tt.args {
				if sel.Arguments[k] != v {
					t.Errorf("expected arg %s=%v, got %v", k, v, sel.Arguments[k])
				}
			}
		})
	}
}

func TestParseSchemaTypes(t *testing.T) {
	sdl := `
type User @key(fields: "id") {
  id: ID!
  name: String
  email: String @external
}

type Query {
  users: [User]
  user(id: ID!): User
}
`

	types, err := parseSchemaTypes(sdl, "users-service")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(types) != 2 {
		t.Errorf("expected 2 types, got %d", len(types))
	}

	userType := types["User"]
	if userType == nil {
		t.Fatal("expected User type")
	}

	if len(userType.KeyFields) != 1 || userType.KeyFields[0] != "id" {
		t.Errorf("expected key field 'id', got %v", userType.KeyFields)
	}

	if userType.Owner != "users-service" {
		t.Errorf("expected owner 'users-service', got %q", userType.Owner)
	}

	// Check external field
	found := false
	for _, f := range userType.ExternalFields {
		if f == "email" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'email' in external fields")
	}
}

func TestExtractDirective(t *testing.T) {
	tests := []struct {
		line      string
		directive string
		expected  string
	}{
		{`type User @key(fields: "id")`, "@key", `fields: "id"`},
		{`email: String @external`, "@external", ""},
		{`name: String @requires(fields: "id")`, "@requires", `fields: "id"`},
		{`type Product`, "@key", ""},
	}

	for _, tt := range tests {
		result := extractDirective(tt.line, tt.directive)
		if result != tt.expected {
			t.Errorf("extractDirective(%q, %q) = %q, want %q",
				tt.line, tt.directive, result, tt.expected)
		}
	}
}

func TestExtractFieldsFromDirective(t *testing.T) {
	tests := []struct {
		arg      string
		expected []string
	}{
		{`fields: "id"`, []string{"id"}},
		{`fields: "id name"`, []string{"id", "name"}},
		{`"id"`, []string{"id"}},
	}

	for _, tt := range tests {
		result := extractFieldsFromDirective(tt.arg)
		if len(result) != len(tt.expected) {
			t.Errorf("extractFieldsFromDirective(%q) = %v, want %v",
				tt.arg, result, tt.expected)
			continue
		}
		for i, f := range result {
			if f != tt.expected[i] {
				t.Errorf("extractFieldsFromDirective(%q)[%d] = %q, want %q",
					tt.arg, i, f, tt.expected[i])
			}
		}
	}
}

func TestMergeTypeDefinitions(t *testing.T) {
	existing := &TypeDefinition{
		Name:      "User",
		KeyFields: []string{"id"},
		Fields: map[string]*FieldDefinition{
			"id":   {Name: "id", Type: "ID!"},
			"name": {Name: "name", Type: "String"},
		},
	}

	new := &TypeDefinition{
		Name:      "User",
		KeyFields: []string{"email"},
		Fields: map[string]*FieldDefinition{
			"email": {Name: "email", Type: "String"},
			"posts": {Name: "posts", Type: "[Post]"},
		},
	}

	mergeTypeDefinitions(existing, new)

	// Check merged fields
	if len(existing.Fields) != 4 {
		t.Errorf("expected 4 fields, got %d", len(existing.Fields))
	}

	if _, ok := existing.Fields["posts"]; !ok {
		t.Error("expected 'posts' field to be merged")
	}

	// Check merged key fields
	if len(existing.KeyFields) != 2 {
		t.Errorf("expected 2 key fields, got %d", len(existing.KeyFields))
	}
}

func TestBuildSubgraphQuery(t *testing.T) {
	sel := &Selection{
		Name:      "users",
		Arguments: map[string]interface{}{"limit": float64(10)},
		SelectionSet: []*Selection{
			{Name: "id"},
			{Name: "name"},
		},
	}

	query := buildSubgraphQuery(sel)

	if !strings.Contains(query, "users") {
		t.Error("expected query to contain 'users'")
	}
	if !strings.Contains(query, "limit") {
		t.Error("expected query to contain 'limit'")
	}
	if !strings.Contains(query, "id") {
		t.Error("expected query to contain 'id'")
	}
}

func TestQueryPlanner(t *testing.T) {
	schema := &Schema{
		Types: map[string]*TypeDefinition{
			"Query": {
				Name: "Query",
				Fields: map[string]*FieldDefinition{
					"users": {Name: "users", Type: "[User]"},
				},
			},
		},
		QueryType: "Query",
	}

	subgraphs := map[string]*Subgraph{
		"users-service": {
			Name: "users-service",
			URL:  "http://localhost:4001/graphql",
			Types: map[string]*TypeDefinition{
				"Query": {
					Name: "Query",
					Fields: map[string]*FieldDefinition{
						"users": {Name: "users", Type: "[User]"},
					},
				},
			},
		},
	}

	planner := NewQueryPlanner(schema, subgraphs)

	doc, _ := ParseQuery("{ users { id name } }")
	plan, err := planner.Plan(doc, "", nil)
	if err != nil {
		t.Fatalf("planning error: %v", err)
	}

	if len(plan.Fetches) == 0 {
		t.Error("expected at least one fetch")
	}

	if plan.Fetches[0].Subgraph != "users-service" {
		t.Errorf("expected subgraph 'users-service', got %q", plan.Fetches[0].Subgraph)
	}
}

func TestExecutor(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GraphQLResponse{
			Data: map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "1", "name": "Alice"},
					{"id": "2", "name": "Bob"},
				},
			},
		})
	}))
	defer server.Close()

	subgraphs := map[string]*Subgraph{
		"users": {
			Name: "users",
			URL:  server.URL,
		},
	}

	executor := NewExecutor(subgraphs, http.DefaultClient, nil)

	plan := &QueryPlan{
		Fetches: []*FetchOperation{
			{
				Subgraph: "users",
				Query:    "{ users { id name } }",
			},
		},
	}

	result, errs := executor.Execute(context.Background(), plan)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	data, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	users, ok := data["users"]
	if !ok {
		t.Fatal("expected 'users' in result")
	}

	userList, ok := users.([]interface{})
	if !ok {
		t.Fatal("expected users to be a list")
	}

	if len(userList) != 2 {
		t.Errorf("expected 2 users, got %d", len(userList))
	}
}

func TestFederationHandler(t *testing.T) {
	// Create test subgraph server
	subgraphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GraphQLResponse{
			Data: map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "1", "name": "Alice"},
				},
			},
		})
	}))
	defer subgraphServer.Close()

	// Create federation gateway
	federation, err := New(Config{
		Subgraphs: []Subgraph{
			{
				Name: "users",
				URL:  subgraphServer.URL,
				Schema: `
type User @key(fields: "id") {
  id: ID!
  name: String
}

type Query {
  users: [User]
}
`,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create federation: %v", err)
	}

	// Test query
	reqBody := `{"query": "{ users { id name } }"}`
	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	federation.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp GraphQLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Errors) > 0 {
		t.Errorf("unexpected errors: %v", resp.Errors)
	}

	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatal("expected map data")
	}

	if _, ok := data["users"]; !ok {
		t.Error("expected 'users' in response")
	}
}

func TestParseArguments(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]interface{}
	}{
		{
			input:    `id: 123`,
			expected: map[string]interface{}{"id": float64(123)},
		},
		{
			input:    `name: "test"`,
			expected: map[string]interface{}{"name": "test"},
		},
		{
			input:    `active: true`,
			expected: map[string]interface{}{"active": true},
		},
		{
			input:    `id: $userId`,
			expected: map[string]interface{}{"id": "$userId"},
		},
	}

	for _, tt := range tests {
		result := parseArguments(tt.input)
		for k, v := range tt.expected {
			if result[k] != v {
				t.Errorf("parseArguments(%q)[%s] = %v, want %v",
					tt.input, k, result[k], v)
			}
		}
	}
}

func TestGraphQLError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeGraphQLError(rec, "test error", http.StatusBadRequest)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}

	var resp GraphQLResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if len(resp.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(resp.Errors))
	}

	if resp.Errors[0].Message != "test error" {
		t.Errorf("expected message 'test error', got %q", resp.Errors[0].Message)
	}
}

func TestFederationRegisterSubgraph(t *testing.T) {
	federation, _ := New(Config{})

	err := federation.RegisterSubgraph(&Subgraph{
		Name: "products",
		URL:  "http://localhost:4002/graphql",
		Schema: `
type Product {
  id: ID!
  name: String
}
`,
	})

	if err != nil {
		t.Fatalf("register error: %v", err)
	}

	if len(federation.subgraphs) != 1 {
		t.Errorf("expected 1 subgraph, got %d", len(federation.subgraphs))
	}

	if _, ok := federation.subgraphs["products"]; !ok {
		t.Error("expected 'products' subgraph")
	}
}

func TestIntrospection(t *testing.T) {
	federation, _ := New(Config{})

	req := httptest.NewRequest("GET", "/graphql", nil)
	rec := httptest.NewRecorder()

	federation.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if _, ok := resp["data"]; !ok {
		t.Error("expected 'data' in response")
	}
}
