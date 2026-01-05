package validation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidator_ValidateString(t *testing.T) {
	v := New(Config{})

	tests := []struct {
		name     string
		data     interface{}
		schema   *Schema
		wantErr  bool
		errCount int
	}{
		{
			name: "valid string",
			data: "hello",
			schema: &Schema{
				Type: "string",
			},
			wantErr: false,
		},
		{
			name: "string too short",
			data: "hi",
			schema: &Schema{
				Type:      "string",
				MinLength: intPtr(5),
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "string too long",
			data: "hello world",
			schema: &Schema{
				Type:      "string",
				MaxLength: intPtr(5),
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "pattern match",
			data: "test@example.com",
			schema: &Schema{
				Type:    "string",
				Pattern: `^[a-z]+@[a-z]+\.[a-z]+$`,
			},
			wantErr: false,
		},
		{
			name: "pattern no match",
			data: "invalid-email",
			schema: &Schema{
				Type:    "string",
				Pattern: `^[a-z]+@[a-z]+\.[a-z]+$`,
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "email format valid",
			data: "test@example.com",
			schema: &Schema{
				Type:   "string",
				Format: "email",
			},
			wantErr: false,
		},
		{
			name: "email format invalid",
			data: "not-an-email",
			schema: &Schema{
				Type:   "string",
				Format: "email",
			},
			wantErr:  true,
			errCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.data, tt.schema)
			if tt.wantErr && result.Valid {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass, got errors: %v", result.Errors)
			}
			if tt.errCount > 0 && len(result.Errors) != tt.errCount {
				t.Errorf("expected %d errors, got %d", tt.errCount, len(result.Errors))
			}
		})
	}
}

func TestValidator_ValidateNumber(t *testing.T) {
	v := New(Config{})

	tests := []struct {
		name    string
		data    interface{}
		schema  *Schema
		wantErr bool
	}{
		{
			name: "valid number",
			data: 42.5,
			schema: &Schema{
				Type: "number",
			},
			wantErr: false,
		},
		{
			name: "number below minimum",
			data: 5.0,
			schema: &Schema{
				Type:    "number",
				Minimum: float64Ptr(10),
			},
			wantErr: true,
		},
		{
			name: "number above maximum",
			data: 100.0,
			schema: &Schema{
				Type:    "number",
				Maximum: float64Ptr(50),
			},
			wantErr: true,
		},
		{
			name: "integer type",
			data: 42.0,
			schema: &Schema{
				Type: "integer",
			},
			wantErr: false,
		},
		{
			name: "not an integer",
			data: 42.5,
			schema: &Schema{
				Type: "integer",
			},
			wantErr: true,
		},
		{
			name: "multiple of",
			data: 15.0,
			schema: &Schema{
				Type:       "number",
				MultipleOf: float64Ptr(5),
			},
			wantErr: false,
		},
		{
			name: "not multiple of",
			data: 17.0,
			schema: &Schema{
				Type:       "number",
				MultipleOf: float64Ptr(5),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.data, tt.schema)
			if tt.wantErr && result.Valid {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidator_ValidateArray(t *testing.T) {
	v := New(Config{})

	tests := []struct {
		name    string
		data    interface{}
		schema  *Schema
		wantErr bool
	}{
		{
			name: "valid array",
			data: []interface{}{"a", "b", "c"},
			schema: &Schema{
				Type:  "array",
				Items: &Schema{Type: "string"},
			},
			wantErr: false,
		},
		{
			name: "array too short",
			data: []interface{}{"a"},
			schema: &Schema{
				Type:     "array",
				MinItems: intPtr(2),
			},
			wantErr: true,
		},
		{
			name: "array too long",
			data: []interface{}{"a", "b", "c", "d"},
			schema: &Schema{
				Type:     "array",
				MaxItems: intPtr(3),
			},
			wantErr: true,
		},
		{
			name: "unique items valid",
			data: []interface{}{"a", "b", "c"},
			schema: &Schema{
				Type:        "array",
				UniqueItems: true,
			},
			wantErr: false,
		},
		{
			name: "unique items invalid",
			data: []interface{}{"a", "b", "a"},
			schema: &Schema{
				Type:        "array",
				UniqueItems: true,
			},
			wantErr: true,
		},
		{
			name: "invalid item type",
			data: []interface{}{"a", 123, "c"},
			schema: &Schema{
				Type:  "array",
				Items: &Schema{Type: "string"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.data, tt.schema)
			if tt.wantErr && result.Valid {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidator_ValidateObject(t *testing.T) {
	v := New(Config{})

	tests := []struct {
		name    string
		data    interface{}
		schema  *Schema
		wantErr bool
	}{
		{
			name: "valid object",
			data: map[string]interface{}{
				"name": "John",
				"age":  30.0,
			},
			schema: &Schema{
				Type: "object",
				Properties: map[string]*Schema{
					"name": {Type: "string"},
					"age":  {Type: "number"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing required property",
			data: map[string]interface{}{
				"name": "John",
			},
			schema: &Schema{
				Type: "object",
				Properties: map[string]*Schema{
					"name": {Type: "string"},
					"age":  {Type: "number"},
				},
				Required: []string{"name", "age"},
			},
			wantErr: true,
		},
		{
			name: "additional properties not allowed",
			data: map[string]interface{}{
				"name":  "John",
				"extra": "value",
			},
			schema: &Schema{
				Type: "object",
				Properties: map[string]*Schema{
					"name": {Type: "string"},
				},
				AdditionalProperties: false,
			},
			wantErr: true,
		},
		{
			name: "nested object valid",
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			schema: &Schema{
				Type: "object",
				Properties: map[string]*Schema{
					"user": {
						Type: "object",
						Properties: map[string]*Schema{
							"name": {Type: "string"},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.Validate(tt.data, tt.schema)
			if tt.wantErr && result.Valid {
				t.Error("expected validation to fail")
			}
			if !tt.wantErr && !result.Valid {
				t.Errorf("expected validation to pass, got errors: %v", result.Errors)
			}
		})
	}
}

func TestValidator_Enum(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		Enum: []interface{}{"red", "green", "blue"},
	}

	result := v.Validate("red", schema)
	if !result.Valid {
		t.Error("expected 'red' to be valid")
	}

	result = v.Validate("yellow", schema)
	if result.Valid {
		t.Error("expected 'yellow' to be invalid")
	}
}

func TestValidator_Const(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		Const: "fixed",
	}

	result := v.Validate("fixed", schema)
	if !result.Valid {
		t.Error("expected 'fixed' to be valid")
	}

	result = v.Validate("other", schema)
	if result.Valid {
		t.Error("expected 'other' to be invalid")
	}
}

func TestValidator_Nullable(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		Type:     "string",
		Nullable: true,
	}

	result := v.Validate(nil, schema)
	if !result.Valid {
		t.Error("expected null to be valid for nullable schema")
	}

	nonNullableSchema := &Schema{
		Type: "string",
	}

	result = v.Validate(nil, nonNullableSchema)
	if result.Valid {
		t.Error("expected null to be invalid for non-nullable schema")
	}
}

func TestValidator_AllOf(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		AllOf: []*Schema{
			{Type: "object", Properties: map[string]*Schema{"a": {Type: "string"}}},
			{Type: "object", Properties: map[string]*Schema{"b": {Type: "number"}}},
		},
	}

	result := v.Validate(map[string]interface{}{"a": "hello", "b": 42.0}, schema)
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}

	result = v.Validate(map[string]interface{}{"a": 123, "b": 42.0}, schema)
	if result.Valid {
		t.Error("expected invalid when first schema fails")
	}
}

func TestValidator_AnyOf(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		AnyOf: []*Schema{
			{Type: "string"},
			{Type: "number"},
		},
	}

	result := v.Validate("hello", schema)
	if !result.Valid {
		t.Error("expected string to match anyOf")
	}

	result = v.Validate(42.0, schema)
	if !result.Valid {
		t.Error("expected number to match anyOf")
	}

	result = v.Validate(true, schema)
	if result.Valid {
		t.Error("expected boolean to fail anyOf")
	}
}

func TestValidator_OneOf(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		OneOf: []*Schema{
			{Type: "string", MinLength: intPtr(5)},
			{Type: "string", MaxLength: intPtr(3)},
		},
	}

	result := v.Validate("hello", schema)
	if !result.Valid {
		t.Error("expected 'hello' to match exactly one schema")
	}

	// "hi" matches second schema only
	result = v.Validate("hi", schema)
	if !result.Valid {
		t.Error("expected 'hi' to match exactly one schema")
	}

	// "test" matches neither (4 chars)
	result = v.Validate("test", schema)
	if result.Valid {
		t.Error("expected 'test' to match none or more than one")
	}
}

func TestValidator_Not(t *testing.T) {
	v := New(Config{})

	schema := &Schema{
		Not: &Schema{Type: "string"},
	}

	result := v.Validate(42.0, schema)
	if !result.Valid {
		t.Error("expected number to pass 'not string'")
	}

	result = v.Validate("hello", schema)
	if result.Valid {
		t.Error("expected string to fail 'not string'")
	}
}

func TestValidator_ValidateRequest(t *testing.T) {
	config := Config{
		RequestMode: ModeStrict,
		Schemas: map[string]*RouteSchema{
			"test": {
				RequestSchema: &Schema{
					Type: "object",
					Properties: map[string]*Schema{
						"name": {Type: "string"},
						"age":  {Type: "integer"},
					},
					Required: []string{"name"},
				},
				QuerySchema: &Schema{
					Type: "object",
					Properties: map[string]*Schema{
						"page": {Type: "string"},
					},
				},
			},
		},
	}

	v := New(config)

	// Valid request
	body := `{"name": "John", "age": 30}`
	req := httptest.NewRequest(http.MethodPost, "/test?page=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := v.ValidateRequest(context.Background(), "test", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid, got errors: %v", result.Errors)
	}

	// Invalid request - missing required field
	body = `{"age": 30}`
	req = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	result, err = v.ValidateRequest(context.Background(), "test", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Error("expected invalid due to missing required field")
	}
}

func TestMiddleware(t *testing.T) {
	config := Config{
		RequestMode: ModeStrict,
		Schemas: map[string]*RouteSchema{
			"test": {
				RequestSchema: &Schema{
					Type: "object",
					Properties: map[string]*Schema{
						"name": {Type: "string"},
					},
					Required: []string{"name"},
				},
			},
		},
	}

	v := New(config)

	mw := Middleware(MiddlewareConfig{
		Validator:   v,
		RouteIDFunc: func(r *http.Request) string { return "test" },
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	})

	handler := mw(next)

	// Valid request
	body := `{"name": "John"}`
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// Invalid request
	body = `{"age": 30}`
	req = httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}

	var errResp ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != "validation_error" {
		t.Errorf("expected validation_error, got %s", errResp.Error)
	}
}

func TestMiddleware_WarnMode(t *testing.T) {
	config := Config{
		RequestMode: ModeWarn,
		Schemas: map[string]*RouteSchema{
			"test": {
				RequestSchema: &Schema{
					Type:     "object",
					Required: []string{"name"},
				},
			},
		},
	}

	v := New(config)

	nextCalled := false
	mw := Middleware(MiddlewareConfig{
		Validator:   v,
		RouteIDFunc: func(r *http.Request) string { return "test" },
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(next)

	// Invalid request should still proceed in warn mode
	body := `{"age": 30}`
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("expected next handler to be called in warn mode")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 in warn mode, got %d", rec.Code)
	}
}

func TestSchemaBuilder(t *testing.T) {
	schema := NewSchemaBuilder().
		Type("object").
		Required("name", "email").
		Property("name", &Schema{Type: "string", MinLength: intPtr(1)}).
		Property("email", &Schema{Type: "string", Format: "email"}).
		Property("age", &Schema{Type: "integer", Minimum: float64Ptr(0)}).
		Build()

	if schema.Type != "object" {
		t.Errorf("expected type object, got %s", schema.Type)
	}
	if len(schema.Required) != 2 {
		t.Errorf("expected 2 required, got %d", len(schema.Required))
	}
	if len(schema.Properties) != 3 {
		t.Errorf("expected 3 properties, got %d", len(schema.Properties))
	}
}

func TestSchemaHelpers(t *testing.T) {
	str := StringSchema()
	if str.Type != "string" {
		t.Error("StringSchema should have type string")
	}

	num := NumberSchema()
	if num.Type != "number" {
		t.Error("NumberSchema should have type number")
	}

	arr := ArraySchema(StringSchema())
	if arr.Type != "array" {
		t.Error("ArraySchema should have type array")
	}
	if arr.Items.Type != "string" {
		t.Error("ArraySchema items should be string")
	}

	obj := ObjectSchema(map[string]*Schema{"id": IntegerSchema()}, "id")
	if obj.Type != "object" {
		t.Error("ObjectSchema should have type object")
	}
	if len(obj.Required) != 1 {
		t.Error("ObjectSchema should have 1 required field")
	}
}

func TestFormatValidation(t *testing.T) {
	tests := []struct {
		value  string
		format string
		valid  bool
	}{
		{"test@example.com", "email", true},
		{"not-email", "email", false},
		{"https://example.com", "uri", true},
		{"not-uri", "uri", false},
		{"550e8400-e29b-41d4-a716-446655440000", "uuid", true},
		{"not-uuid", "uuid", false},
		{"2024-01-15", "date", true},
		{"01-15-2024", "date", false},
		{"192.168.1.1", "ipv4", true},
		{"999.999.999.999", "ipv4", false},
		{"example.com", "hostname", true},
	}

	for _, tt := range tests {
		t.Run(tt.format+":"+tt.value, func(t *testing.T) {
			result := validateFormat(tt.value, tt.format)
			if result != tt.valid {
				t.Errorf("validateFormat(%q, %q) = %v, want %v", tt.value, tt.format, result, tt.valid)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	config := Config{
		RequestMode: ModeStrict,
		UseDefaults: true,
		Schemas: map[string]*RouteSchema{
			"test": {
				RequestSchema: &Schema{
					Type: "object",
					Properties: map[string]*Schema{
						"name":  {Type: "string"},
						"count": {Type: "integer", Default: float64(1)},
					},
				},
			},
		},
	}

	v := New(config)

	body := `{"name": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	_, err := v.ValidateRequest(context.Background(), "test", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read the modified body
	var newBody bytes.Buffer
	newBody.ReadFrom(req.Body)

	var data map[string]interface{}
	if err := json.Unmarshal(newBody.Bytes(), &data); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if _, exists := data["count"]; !exists {
		t.Error("expected default value to be applied")
	}
}

func TestRemoveAdditional(t *testing.T) {
	config := Config{
		RequestMode:      ModeStrict,
		RemoveAdditional: true,
		Schemas: map[string]*RouteSchema{
			"test": {
				RequestSchema: &Schema{
					Type: "object",
					Properties: map[string]*Schema{
						"name": {Type: "string"},
					},
					AdditionalProperties: false,
				},
			},
		},
	}

	v := New(config)

	body := `{"name": "test", "extra": "value"}`
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	_, err := v.ValidateRequest(context.Background(), "test", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read the modified body
	var newBody bytes.Buffer
	newBody.ReadFrom(req.Body)

	var data map[string]interface{}
	if err := json.Unmarshal(newBody.Bytes(), &data); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if _, exists := data["extra"]; exists {
		t.Error("expected extra property to be removed")
	}
}

func TestOpenAPILoader(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"paths": {
			"/users": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"}
									},
									"required": ["name"]
								}
							}
						}
					},
					"responses": {
						"200": {
							"content": {
								"application/json": {
									"schema": {
										"type": "object",
										"properties": {
											"id": {"type": "integer"}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}`

	loader, err := NewOpenAPILoader([]byte(spec))
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	schemas, err := loader.LoadSchemas()
	if err != nil {
		t.Fatalf("failed to load schemas: %v", err)
	}

	routeSchema, exists := schemas["post:/users"]
	if !exists {
		t.Fatal("expected schema for post:/users")
	}

	if routeSchema.RequestSchema == nil {
		t.Error("expected request schema")
	}

	if routeSchema.ResponseSchemas == nil || routeSchema.ResponseSchemas[200] == nil {
		t.Error("expected response schema for 200")
	}
}

func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}
