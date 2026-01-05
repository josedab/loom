package openapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// Sample OpenAPI spec for testing
const testSpec = `{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0"
  },
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "summary": "List users",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "schema": {
              "type": "integer",
              "minimum": 1,
              "maximum": 100
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/User"
                  }
                },
                "example": [{"id": "1", "name": "Test User"}]
              }
            }
          }
        }
      },
      "post": {
        "operationId": "createUser",
        "summary": "Create user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/CreateUser"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/User"
                }
              }
            }
          }
        }
      }
    },
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "summary": "Get user by ID",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/User"
                }
              }
            }
          }
        }
      },
      "delete": {
        "operationId": "deleteUser",
        "deprecated": true,
        "responses": {
          "204": {
            "description": "Deleted"
          }
        }
      }
    },
    "/health": {
      "get": {
        "operationId": "healthCheck",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "User": {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
          "id": {
            "type": "string"
          },
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100
          },
          "email": {
            "type": "string",
            "format": "email"
          },
          "age": {
            "type": "integer",
            "minimum": 0,
            "maximum": 150
          }
        }
      },
      "CreateUser": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100
          },
          "email": {
            "type": "string",
            "format": "email"
          }
        }
      }
    }
  }
}`

const testSpecYAML = `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /ping:
    get:
      operationId: ping
      responses:
        "200":
          description: Pong
`

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		check   func(*testing.T, *Spec)
	}{
		{
			name:    "parse JSON spec",
			input:   []byte(testSpec),
			wantErr: false,
			check: func(t *testing.T, spec *Spec) {
				if spec.OpenAPI != "3.0.0" {
					t.Errorf("expected openapi 3.0.0, got %s", spec.OpenAPI)
				}
				if spec.Info.Title != "Test API" {
					t.Errorf("expected title 'Test API', got %s", spec.Info.Title)
				}
				if len(spec.Paths) != 3 {
					t.Errorf("expected 3 paths, got %d", len(spec.Paths))
				}
			},
		},
		{
			name:    "parse YAML spec",
			input:   []byte(testSpecYAML),
			wantErr: false,
			check: func(t *testing.T, spec *Spec) {
				if spec.Info.Title != "Test API" {
					t.Errorf("expected title 'Test API', got %s", spec.Info.Title)
				}
				if _, ok := spec.Paths["/ping"]; !ok {
					t.Error("expected /ping path")
				}
			},
		},
		{
			name:    "invalid spec",
			input:   []byte("not valid yaml or json {{{"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && spec != nil {
				tt.check(t, spec)
			}
		})
	}
}

func TestParseReader(t *testing.T) {
	reader := bytes.NewReader([]byte(testSpec))
	spec, err := ParseReader(reader)
	if err != nil {
		t.Fatalf("ParseReader() error = %v", err)
	}
	if spec.Info.Title != "Test API" {
		t.Errorf("expected title 'Test API', got %s", spec.Info.Title)
	}
}

func TestGenerateRoutes(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	routes := spec.GenerateRoutes()

	if len(routes) != 5 {
		t.Errorf("expected 5 routes, got %d", len(routes))
	}

	// Check for specific routes
	found := make(map[string]bool)
	for _, route := range routes {
		key := route.Method + " " + route.Path
		found[key] = true
	}

	expected := []string{
		"GET /users",
		"POST /users",
		"GET /users/{id}",
		"DELETE /users/{id}",
		"GET /health",
	}

	for _, e := range expected {
		if !found[e] {
			t.Errorf("expected route %s not found", e)
		}
	}
}

func TestValidator(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name       string
		method     string
		path       string
		wantValid  bool
		wantParams map[string]string
	}{
		{
			name:      "valid GET /users",
			method:    "GET",
			path:      "/users",
			wantValid: true,
		},
		{
			name:      "valid GET /users/{id}",
			method:    "GET",
			path:      "/users/123",
			wantValid: true,
			wantParams: map[string]string{
				"id": "123",
			},
		},
		{
			name:      "unknown path",
			method:    "GET",
			path:      "/unknown",
			wantValid: false,
		},
		{
			name:      "wrong method",
			method:    "PUT",
			path:      "/users",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			result := validator.ValidateRequest(req)

			if result.Valid != tt.wantValid {
				t.Errorf("ValidateRequest() valid = %v, want %v, errors = %v",
					result.Valid, tt.wantValid, result.Errors)
			}

			for k, v := range tt.wantParams {
				if result.Params[k] != v {
					t.Errorf("expected param %s=%s, got %s", k, v, result.Params[k])
				}
			}
		})
	}
}

func TestValidatorQueryParams(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name      string
		path      string
		wantValid bool
	}{
		{
			name:      "valid limit",
			path:      "/users?limit=10",
			wantValid: true,
		},
		{
			name:      "limit too low",
			path:      "/users?limit=0",
			wantValid: false,
		},
		{
			name:      "limit too high",
			path:      "/users?limit=200",
			wantValid: false,
		},
		{
			name:      "invalid limit type",
			path:      "/users?limit=abc",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			result := validator.ValidateRequest(req)

			if result.Valid != tt.wantValid {
				t.Errorf("ValidateRequest() valid = %v, want %v, errors = %v",
					result.Valid, tt.wantValid, result.Errors)
			}
		})
	}
}

func TestValidatorRequiredBody(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name      string
		body      string
		wantValid bool
	}{
		{
			name:      "with body",
			body:      `{"name": "Test"}`,
			wantValid: true,
		},
		{
			name:      "without body",
			body:      "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			}
			req := httptest.NewRequest("POST", "/users", body)
			if tt.body != "" {
				req.ContentLength = int64(len(tt.body))
			}

			result := validator.ValidateRequest(req)

			if result.Valid != tt.wantValid {
				t.Errorf("ValidateRequest() valid = %v, want %v, errors = %v",
					result.Valid, tt.wantValid, result.Errors)
			}
		})
	}
}

func TestValidateJSON(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name       string
		schemaRef  string
		json       string
		wantErrors int
	}{
		{
			name:       "valid user",
			schemaRef:  "#/components/schemas/User",
			json:       `{"id": "1", "name": "Test User"}`,
			wantErrors: 0,
		},
		{
			name:       "missing required field",
			schemaRef:  "#/components/schemas/User",
			json:       `{"id": "1"}`,
			wantErrors: 1,
		},
		{
			name:       "name too short",
			schemaRef:  "#/components/schemas/User",
			json:       `{"id": "1", "name": ""}`,
			wantErrors: 1,
		},
		{
			name:       "invalid json",
			schemaRef:  "#/components/schemas/User",
			json:       `{invalid}`,
			wantErrors: 1,
		},
		{
			name:       "valid create user",
			schemaRef:  "#/components/schemas/CreateUser",
			json:       `{"name": "Test"}`,
			wantErrors: 0,
		},
		{
			name:       "age out of range",
			schemaRef:  "#/components/schemas/User",
			json:       `{"id": "1", "name": "Test", "age": 200}`,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := validator.resolveRef(tt.schemaRef)
			if schema == nil {
				t.Fatal("schema not found")
			}

			errors := validator.ValidateJSON([]byte(tt.json), schema)

			if len(errors) != tt.wantErrors {
				t.Errorf("ValidateJSON() errors = %d, want %d, errors = %v",
					len(errors), tt.wantErrors, errors)
			}
		})
	}
}

func TestMockGenerator(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	tests := []struct {
		name       string
		path       string
		method     string
		wantStatus int
		wantErr    bool
	}{
		{
			name:       "mock GET /users",
			path:       "/users",
			method:     "GET",
			wantStatus: 200,
		},
		{
			name:       "mock POST /users",
			path:       "/users",
			method:     "POST",
			wantStatus: 201,
		},
		{
			name:    "unknown path",
			path:    "/unknown",
			method:  "GET",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, body, err := gen.GenerateMock(tt.path, tt.method)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateMock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if status != tt.wantStatus {
					t.Errorf("GenerateMock() status = %d, want %d", status, tt.wantStatus)
				}
				if body == nil || len(body) == 0 {
					t.Error("expected non-empty body")
				}
			}
		})
	}
}

func TestMockGeneratorSchema(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	// Test schema-based mock generation
	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"name": {Type: "string"},
			"age":  {Type: "integer"},
			"tags": {
				Type:  "array",
				Items: &Schema{Type: "string"},
			},
		},
	}

	value := gen.generateValue(schema)
	obj, ok := value.(map[string]interface{})
	if !ok {
		t.Fatal("expected object")
	}

	if _, ok := obj["name"]; !ok {
		t.Error("expected 'name' property")
	}
	if _, ok := obj["age"]; !ok {
		t.Error("expected 'age' property")
	}
	if _, ok := obj["tags"]; !ok {
		t.Error("expected 'tags' property")
	}
}

func TestValidationMiddleware(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	middleware := ValidationMiddleware(MiddlewareConfig{
		Validator:       validator,
		ValidateRequest: true,
	})

	wrappedHandler := middleware(handler)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{
			name:       "valid request",
			method:     "GET",
			path:       "/users",
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid path",
			method:     "GET",
			path:       "/unknown",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestValidationMiddlewareBodyValidation(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read body to verify it's still available
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			t.Error("body should be restored after validation")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := ValidationMiddleware(MiddlewareConfig{
		Validator:       validator,
		ValidateRequest: true,
		ValidateBody:    true,
	})

	wrappedHandler := middleware(handler)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "valid body",
			body:       `{"name": "Test User"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing required field",
			body:       `{"email": "test@example.com"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/users", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = int64(len(tt.body))
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d, body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestValidationMiddlewareCustomErrorHandler(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	customHandlerCalled := false

	middleware := ValidationMiddleware(MiddlewareConfig{
		Validator:       validator,
		ValidateRequest: true,
		OnValidationError: func(w http.ResponseWriter, r *http.Request, result *ValidationResult) {
			customHandlerCalled = true
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte("custom error"))
		},
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/unknown", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !customHandlerCalled {
		t.Error("custom error handler should be called")
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnprocessableEntity)
	}
}

func TestMockMiddleware(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("real response"))
	})

	middleware := MockMiddleware(MockMiddlewareConfig{
		Generator: gen,
	})

	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/users", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Mock-Response") != "true" {
		t.Error("expected mock response header")
	}
}

func TestMockMiddlewareWithHeader(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("real response"))
	})

	middleware := MockMiddleware(MockMiddlewareConfig{
		Generator:  gen,
		MockHeader: "X-Mock",
	})

	wrappedHandler := middleware(handler)

	// Without header - should get real response
	req := httptest.NewRequest("GET", "/users", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Body.String() != "real response" {
		t.Error("expected real response without mock header")
	}

	// With header - should get mock response
	req = httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("X-Mock", "true")
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Header().Get("X-Mock-Response") != "true" {
		t.Error("expected mock response with mock header")
	}
}

func TestRouter(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	router := NewRouter(spec)

	// Register handlers
	router.RegisterHandlerFunc("/users", "GET", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("list users"))
	})

	router.RegisterHandlerFunc("/users/{id}", "GET", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("get user"))
	})

	tests := []struct {
		name     string
		method   string
		path     string
		wantBody string
		wantCode int
	}{
		{
			name:     "exact match",
			method:   "GET",
			path:     "/users",
			wantBody: "list users",
			wantCode: http.StatusOK,
		},
		{
			name:     "pattern match",
			method:   "GET",
			path:     "/users/123",
			wantBody: "get user",
			wantCode: http.StatusOK,
		},
		{
			name:     "not found",
			method:   "GET",
			path:     "/unknown",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("got body %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestRouterRegisterByOperationID(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	router := NewRouter(spec)

	called := false
	router.RegisterByOperationID("listUsers", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/users", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if !called {
		t.Error("handler should be called")
	}
}

func TestRouterGetRoutes(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	router := NewRouter(spec)

	routes := router.GetRoutes()
	if len(routes) != 5 {
		t.Errorf("expected 5 routes, got %d", len(routes))
	}
}

func TestSpecLoader(t *testing.T) {
	// Create temp spec file
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")

	if err := os.WriteFile(specPath, []byte(testSpec), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewSpecLoader(specPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	if loader.Spec().Info.Title != "Test API" {
		t.Error("spec not loaded correctly")
	}
	if loader.Validator() == nil {
		t.Error("validator should be created")
	}
	if loader.MockGenerator() == nil {
		t.Error("mock generator should be created")
	}
}

func TestSpecLoaderReload(t *testing.T) {
	// Create temp spec file
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")

	if err := os.WriteFile(specPath, []byte(testSpec), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewSpecLoader(specPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Update spec file
	updatedSpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Updated API", "version": "2.0.0"},
		"paths": {}
	}`
	if err := os.WriteFile(specPath, []byte(updatedSpec), 0644); err != nil {
		t.Fatal(err)
	}

	// Reload
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}

	if loader.Spec().Info.Title != "Updated API" {
		t.Error("spec not reloaded correctly")
	}
}

func TestSpecLoaderWatchAndReload(t *testing.T) {
	// Create temp spec file
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")

	if err := os.WriteFile(specPath, []byte(testSpec), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewSpecLoader(specPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go loader.WatchAndReload(done, 50*time.Millisecond)
	defer close(done)

	// Wait for initial load
	time.Sleep(100 * time.Millisecond)

	// Update spec file
	updatedSpec := `{
		"openapi": "3.0.0",
		"info": {"title": "Watched API", "version": "3.0.0"},
		"paths": {}
	}`
	if err := os.WriteFile(specPath, []byte(updatedSpec), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for reload
	time.Sleep(200 * time.Millisecond)

	if loader.Spec().Info.Title != "Watched API" {
		t.Error("spec not reloaded by watcher")
	}
}

func TestHandler(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	handler := NewHandler(spec, nil)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{
			name:       "get spec",
			method:     "GET",
			path:       "/openapi",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get routes",
			method:     "GET",
			path:       "/openapi/routes",
			wantStatus: http.StatusOK,
		},
		{
			name:       "not found",
			method:     "GET",
			path:       "/openapi/unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandlerValidate(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	handler := NewHandler(spec, nil)

	tests := []struct {
		name       string
		schema     string
		body       string
		wantStatus int
		wantValid  bool
	}{
		{
			name:       "valid user",
			schema:     "User",
			body:       `{"id": "1", "name": "Test"}`,
			wantStatus: http.StatusOK,
			wantValid:  true,
		},
		{
			name:       "invalid user",
			schema:     "User",
			body:       `{"id": "1"}`,
			wantStatus: http.StatusOK,
			wantValid:  false,
		},
		{
			name:       "schema not found",
			schema:     "Unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/openapi/validate?schema="+tt.schema,
				bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				var result struct {
					Valid bool `json:"valid"`
				}
				json.Unmarshal(rec.Body.Bytes(), &result)
				if result.Valid != tt.wantValid {
					t.Errorf("got valid %v, want %v", result.Valid, tt.wantValid)
				}
			}
		})
	}
}

func TestHandlerMock(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	handler := NewHandler(spec, nil)

	tests := []struct {
		name       string
		path       string
		method     string
		wantStatus int
	}{
		{
			name:       "valid mock",
			path:       "/users",
			method:     "GET",
			wantStatus: http.StatusOK,
		},
		{
			name:       "unknown path",
			path:       "/unknown",
			method:     "GET",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "missing params",
			path:       "",
			method:     "",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/openapi/mock"
			if tt.path != "" || tt.method != "" {
				url += "?path=" + tt.path + "&method=" + tt.method
			}
			req := httptest.NewRequest("GET", url, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d, body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestValidateString(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	minLen := 2
	maxLen := 10
	schema := &Schema{
		Type:      "string",
		MinLength: &minLen,
		MaxLength: &maxLen,
		Pattern:   "^[a-z]+$",
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", "hello", false},
		{"too short", "a", true},
		{"too long", "verylongstring", true},
		{"invalid pattern", "Hello123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateString(tt.value, schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnum(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	schema := &Schema{
		Type: "string",
		Enum: []interface{}{"active", "inactive", "pending"},
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid enum value", "active", false},
		{"invalid enum value", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateString(tt.value, schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNumber(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	min := 1.0
	max := 100.0
	schema := &Schema{
		Type:    "number",
		Minimum: &min,
		Maximum: &max,
	}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", "50", false},
		{"minimum", "1", false},
		{"maximum", "100", false},
		{"below minimum", "0", true},
		{"above maximum", "101", true},
		{"invalid number", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateNumber(tt.value, schema)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNumber() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBoolean(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"true", "true", false},
		{"false", "false", false},
		{"invalid", "yes", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateBoolean(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBoolean() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateJSONArray(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	minItems := 1
	maxItems := 3
	schema := &Schema{
		Type:     "array",
		MinItems: &minItems,
		MaxItems: &maxItems,
		Items:    &Schema{Type: "string"},
	}

	tests := []struct {
		name       string
		json       string
		wantErrors int
	}{
		{"valid array", `["a", "b"]`, 0},
		{"empty array", `[]`, 1},
		{"too many items", `["a", "b", "c", "d"]`, 1},
		{"invalid item type", `["a", 123]`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateJSON([]byte(tt.json), schema)
			if len(errors) != tt.wantErrors {
				t.Errorf("ValidateJSON() errors = %d, want %d, errors = %v",
					len(errors), tt.wantErrors, errors)
			}
		})
	}
}

func TestValidateNullable(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	validator := NewValidator(spec)

	tests := []struct {
		name       string
		schema     *Schema
		json       string
		wantErrors int
	}{
		{
			name:       "nullable with null",
			schema:     &Schema{Type: "string", Nullable: true},
			json:       `null`,
			wantErrors: 0,
		},
		{
			name:       "non-nullable with null",
			schema:     &Schema{Type: "string", Nullable: false},
			json:       `null`,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateJSON([]byte(tt.json), tt.schema)
			if len(errors) != tt.wantErrors {
				t.Errorf("ValidateJSON() errors = %d, want %d, errors = %v",
					len(errors), tt.wantErrors, errors)
			}
		})
	}
}

func TestMockGeneratorFormats(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	tests := []struct {
		name     string
		schema   *Schema
		expected interface{}
	}{
		{
			name:     "date-time",
			schema:   &Schema{Type: "string", Format: "date-time"},
			expected: "2024-01-01T00:00:00Z",
		},
		{
			name:     "date",
			schema:   &Schema{Type: "string", Format: "date"},
			expected: "2024-01-01",
		},
		{
			name:     "email",
			schema:   &Schema{Type: "string", Format: "email"},
			expected: "user@example.com",
		},
		{
			name:     "uuid",
			schema:   &Schema{Type: "string", Format: "uuid"},
			expected: "00000000-0000-0000-0000-000000000000",
		},
		{
			name:     "integer",
			schema:   &Schema{Type: "integer"},
			expected: 0,
		},
		{
			name:     "number",
			schema:   &Schema{Type: "number"},
			expected: 0.0,
		},
		{
			name:     "boolean",
			schema:   &Schema{Type: "boolean"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := gen.generateValue(tt.schema)
			if value != tt.expected {
				t.Errorf("generateValue() = %v, want %v", value, tt.expected)
			}
		})
	}
}

func TestMockGeneratorDefault(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	schema := &Schema{
		Type:    "string",
		Default: "default_value",
	}

	value := gen.generateValue(schema)
	if value != "default_value" {
		t.Errorf("expected default value, got %v", value)
	}
}

func TestMockGeneratorEnum(t *testing.T) {
	spec, _ := Parse([]byte(testSpec))
	gen := NewMockGenerator(spec)

	schema := &Schema{
		Type: "string",
		Enum: []interface{}{"first", "second", "third"},
	}

	value := gen.generateValue(schema)
	if value != "first" {
		t.Errorf("expected first enum value, got %v", value)
	}
}

func TestPathToRegex(t *testing.T) {
	tests := []struct {
		path    string
		testURL string
		match   bool
	}{
		{"/users", "/users", true},
		{"/users", "/users/123", false},
		{"/users/{id}", "/users/123", true},
		{"/users/{id}", "/users/abc", true},
		{"/users/{id}/posts/{postId}", "/users/1/posts/2", true},
		{"/api/v1/users", "/api/v2/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+" -> "+tt.testURL, func(t *testing.T) {
			pattern := pathToRegex(tt.path)
			re, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("invalid regex: %v", err)
			}

			matched := re.MatchString(tt.testURL)
			if matched != tt.match {
				t.Errorf("pathToRegex(%q) matching %q = %v, want %v",
					tt.path, tt.testURL, matched, tt.match)
			}
		})
	}
}

func TestFindBodySchema(t *testing.T) {
	schema := &Schema{Type: "object"}
	body := &RequestBody{
		Content: map[string]MediaType{
			"application/json": {Schema: schema},
		},
	}

	tests := []struct {
		name        string
		contentType string
		wantNil     bool
	}{
		{"exact match", "application/json", false},
		{"with charset", "application/json; charset=utf-8", false},
		{"unknown type fallback", "text/plain", false},
		{"nil body", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBody := body
			if tt.wantNil && tt.name == "nil body" {
				testBody = nil
			}

			result := findBodySchema(testBody, tt.contentType)
			if (result == nil) != tt.wantNil {
				t.Errorf("findBodySchema() nil = %v, wantNil %v", result == nil, tt.wantNil)
			}
		})
	}
}
