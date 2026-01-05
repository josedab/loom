// Package validation provides JSON Schema validation for API requests and responses.
package validation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Mode determines how validation failures are handled.
type Mode string

const (
	// ModeStrict rejects requests/responses that fail validation.
	ModeStrict Mode = "strict"
	// ModeWarn logs validation failures but allows the request to proceed.
	ModeWarn Mode = "warn"
	// ModeSkip disables validation.
	ModeSkip Mode = "skip"
)

// Config contains validator configuration.
type Config struct {
	// RequestMode determines how request validation failures are handled.
	RequestMode Mode `json:"request_mode" yaml:"request_mode"`
	// ResponseMode determines how response validation failures are handled.
	ResponseMode Mode `json:"response_mode" yaml:"response_mode"`
	// Schemas maps route IDs to their schemas.
	Schemas map[string]*RouteSchema `json:"schemas" yaml:"schemas"`
	// DefaultSchema is used when no route-specific schema exists.
	DefaultSchema *Schema `json:"default_schema,omitempty" yaml:"default_schema,omitempty"`
	// CoerceTypes attempts to coerce types before validation.
	CoerceTypes bool `json:"coerce_types" yaml:"coerce_types"`
	// RemoveAdditional removes properties not in schema.
	RemoveAdditional bool `json:"remove_additional" yaml:"remove_additional"`
	// UseDefaults applies default values from schema.
	UseDefaults bool `json:"use_defaults" yaml:"use_defaults"`
}

// RouteSchema contains schemas for a specific route.
type RouteSchema struct {
	// RequestSchema validates request bodies.
	RequestSchema *Schema `json:"request_schema,omitempty" yaml:"request_schema,omitempty"`
	// ResponseSchemas maps status codes to response schemas.
	ResponseSchemas map[int]*Schema `json:"response_schemas,omitempty" yaml:"response_schemas,omitempty"`
	// QuerySchema validates query parameters.
	QuerySchema *Schema `json:"query_schema,omitempty" yaml:"query_schema,omitempty"`
	// HeaderSchema validates request headers.
	HeaderSchema *Schema `json:"header_schema,omitempty" yaml:"header_schema,omitempty"`
	// PathSchema validates path parameters.
	PathSchema *Schema `json:"path_schema,omitempty" yaml:"path_schema,omitempty"`
}

// Schema represents a JSON Schema definition.
type Schema struct {
	// Type of the value (string, number, integer, boolean, array, object, null).
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// Properties for object types.
	Properties map[string]*Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	// Required lists required properties.
	Required []string `json:"required,omitempty" yaml:"required,omitempty"`
	// Items schema for array types.
	Items *Schema `json:"items,omitempty" yaml:"items,omitempty"`
	// AdditionalProperties controls extra properties (bool or schema).
	AdditionalProperties interface{} `json:"additionalProperties,omitempty" yaml:"additionalProperties,omitempty"`
	// MinLength for strings.
	MinLength *int `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	// MaxLength for strings.
	MaxLength *int `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	// Pattern regex for strings.
	Pattern string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	// Format for strings (email, uri, date, etc.).
	Format string `json:"format,omitempty" yaml:"format,omitempty"`
	// Minimum for numbers.
	Minimum *float64 `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	// Maximum for numbers.
	Maximum *float64 `json:"maximum,omitempty" yaml:"maximum,omitempty"`
	// ExclusiveMinimum for numbers.
	ExclusiveMinimum *float64 `json:"exclusiveMinimum,omitempty" yaml:"exclusiveMinimum,omitempty"`
	// ExclusiveMaximum for numbers.
	ExclusiveMaximum *float64 `json:"exclusiveMaximum,omitempty" yaml:"exclusiveMaximum,omitempty"`
	// MultipleOf for numbers.
	MultipleOf *float64 `json:"multipleOf,omitempty" yaml:"multipleOf,omitempty"`
	// MinItems for arrays.
	MinItems *int `json:"minItems,omitempty" yaml:"minItems,omitempty"`
	// MaxItems for arrays.
	MaxItems *int `json:"maxItems,omitempty" yaml:"maxItems,omitempty"`
	// UniqueItems for arrays.
	UniqueItems bool `json:"uniqueItems,omitempty" yaml:"uniqueItems,omitempty"`
	// Enum lists allowed values.
	Enum []interface{} `json:"enum,omitempty" yaml:"enum,omitempty"`
	// Const specifies a constant value.
	Const interface{} `json:"const,omitempty" yaml:"const,omitempty"`
	// Default value.
	Default interface{} `json:"default,omitempty" yaml:"default,omitempty"`
	// Nullable allows null values.
	Nullable bool `json:"nullable,omitempty" yaml:"nullable,omitempty"`
	// Description for documentation.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// OneOf validates against exactly one schema.
	OneOf []*Schema `json:"oneOf,omitempty" yaml:"oneOf,omitempty"`
	// AnyOf validates against at least one schema.
	AnyOf []*Schema `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	// AllOf validates against all schemas.
	AllOf []*Schema `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	// Not validates that the schema does NOT match.
	Not *Schema `json:"not,omitempty" yaml:"not,omitempty"`
	// If/Then/Else for conditional validation.
	If   *Schema `json:"if,omitempty" yaml:"if,omitempty"`
	Then *Schema `json:"then,omitempty" yaml:"then,omitempty"`
	Else *Schema `json:"else,omitempty" yaml:"else,omitempty"`

	// Compiled regex pattern (internal use).
	compiledPattern *regexp.Regexp
}

// ValidationError represents a validation failure.
type ValidationError struct {
	// Path to the invalid value (JSONPath-like).
	Path string `json:"path"`
	// Message describing the error.
	Message string `json:"message"`
	// Value that failed validation.
	Value interface{} `json:"value,omitempty"`
	// SchemaPath in the schema that was violated.
	SchemaPath string `json:"schemaPath,omitempty"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

// ValidationResult contains the outcome of validation.
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors,omitempty"`
}

// Validator performs JSON Schema validation.
type Validator struct {
	config  Config
	schemas sync.Map // cache for compiled schemas
	mu      sync.RWMutex
}

// New creates a new Validator.
func New(config Config) *Validator {
	return &Validator{
		config: config,
	}
}

// ValidateRequest validates an HTTP request.
func (v *Validator) ValidateRequest(ctx context.Context, routeID string, r *http.Request) (*ValidationResult, error) {
	v.mu.RLock()
	mode := v.config.RequestMode
	schemas := v.config.Schemas
	v.mu.RUnlock()

	if mode == ModeSkip {
		return &ValidationResult{Valid: true}, nil
	}

	routeSchema, ok := schemas[routeID]
	if !ok {
		return &ValidationResult{Valid: true}, nil
	}

	result := &ValidationResult{Valid: true}

	// Validate query parameters
	if routeSchema.QuerySchema != nil {
		queryData := make(map[string]interface{})
		for key, values := range r.URL.Query() {
			if len(values) == 1 {
				queryData[key] = values[0]
			} else {
				queryData[key] = values
			}
		}
		queryResult := v.Validate(queryData, routeSchema.QuerySchema)
		if !queryResult.Valid {
			result.Valid = false
			for _, err := range queryResult.Errors {
				err.Path = "query." + err.Path
				result.Errors = append(result.Errors, err)
			}
		}
	}

	// Validate headers
	if routeSchema.HeaderSchema != nil {
		headerData := make(map[string]interface{})
		for key, values := range r.Header {
			if len(values) == 1 {
				headerData[key] = values[0]
			} else {
				headerData[key] = values
			}
		}
		headerResult := v.Validate(headerData, routeSchema.HeaderSchema)
		if !headerResult.Valid {
			result.Valid = false
			for _, err := range headerResult.Errors {
				err.Path = "header." + err.Path
				result.Errors = append(result.Errors, err)
			}
		}
	}

	// Validate request body
	if routeSchema.RequestSchema != nil && r.Body != nil && r.ContentLength > 0 {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    "body",
				Message: "invalid JSON: " + err.Error(),
			})
		} else {
			bodyResult := v.Validate(data, routeSchema.RequestSchema)
			if !bodyResult.Valid {
				result.Valid = false
				for _, err := range bodyResult.Errors {
					err.Path = "body." + err.Path
					result.Errors = append(result.Errors, err)
				}
			}

			// Apply defaults and coercion if needed
			if v.config.UseDefaults || v.config.CoerceTypes || v.config.RemoveAdditional {
				modified, changed := v.applySchemaModifications(data, routeSchema.RequestSchema)
				if changed {
					newBody, _ := json.Marshal(modified)
					r.Body = io.NopCloser(bytes.NewReader(newBody))
					r.ContentLength = int64(len(newBody))
				}
			}
		}
	}

	return result, nil
}

// ValidateResponse validates an HTTP response.
func (v *Validator) ValidateResponse(ctx context.Context, routeID string, resp *http.Response) (*ValidationResult, error) {
	v.mu.RLock()
	mode := v.config.ResponseMode
	schemas := v.config.Schemas
	v.mu.RUnlock()

	if mode == ModeSkip {
		return &ValidationResult{Valid: true}, nil
	}

	routeSchema, ok := schemas[routeID]
	if !ok {
		return &ValidationResult{Valid: true}, nil
	}

	result := &ValidationResult{Valid: true}

	// Get schema for this status code
	var schema *Schema
	if routeSchema.ResponseSchemas != nil {
		schema = routeSchema.ResponseSchemas[resp.StatusCode]
		if schema == nil {
			// Try default response schema
			schema = routeSchema.ResponseSchemas[0]
		}
	}

	if schema == nil {
		return result, nil
	}

	// Validate response body
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read body: %w", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))

		if len(body) > 0 {
			var data interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, &ValidationError{
					Path:    "body",
					Message: "invalid JSON: " + err.Error(),
				})
			} else {
				bodyResult := v.Validate(data, schema)
				if !bodyResult.Valid {
					result.Valid = false
					for _, err := range bodyResult.Errors {
						err.Path = "body." + err.Path
						result.Errors = append(result.Errors, err)
					}
				}
			}
		}
	}

	return result, nil
}

// Validate validates data against a schema.
func (v *Validator) Validate(data interface{}, schema *Schema) *ValidationResult {
	result := &ValidationResult{Valid: true}
	v.validateValue(data, schema, "$", result)
	return result
}

func (v *Validator) validateValue(data interface{}, schema *Schema, path string, result *ValidationResult) {
	if schema == nil {
		return
	}

	// Handle null
	if data == nil {
		if schema.Nullable {
			return
		}
		if schema.Type != "" && schema.Type != "null" {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: "value cannot be null",
				Value:   data,
			})
		}
		return
	}

	// Check const
	if schema.Const != nil {
		if !equalValues(data, schema.Const) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value must be %v", schema.Const),
				Value:   data,
			})
			return
		}
	}

	// Check enum
	if len(schema.Enum) > 0 {
		found := false
		for _, allowed := range schema.Enum {
			if equalValues(data, allowed) {
				found = true
				break
			}
		}
		if !found {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value must be one of: %v", schema.Enum),
				Value:   data,
			})
		}
	}

	// Validate type
	if schema.Type != "" {
		if !v.validateType(data, schema.Type, path, result) {
			return
		}
	}

	// Type-specific validation
	switch d := data.(type) {
	case string:
		v.validateString(d, schema, path, result)
	case float64:
		v.validateNumber(d, schema, path, result)
	case bool:
		// No additional validation for booleans
	case []interface{}:
		v.validateArray(d, schema, path, result)
	case map[string]interface{}:
		v.validateObject(d, schema, path, result)
	}

	// Composite validations
	if len(schema.AllOf) > 0 {
		for i, subSchema := range schema.AllOf {
			subResult := &ValidationResult{Valid: true}
			v.validateValue(data, subSchema, path, subResult)
			if !subResult.Valid {
				result.Valid = false
				for _, err := range subResult.Errors {
					err.SchemaPath = fmt.Sprintf("allOf[%d]", i)
					result.Errors = append(result.Errors, err)
				}
			}
		}
	}

	if len(schema.AnyOf) > 0 {
		anyValid := false
		for _, subSchema := range schema.AnyOf {
			subResult := &ValidationResult{Valid: true}
			v.validateValue(data, subSchema, path, subResult)
			if subResult.Valid {
				anyValid = true
				break
			}
		}
		if !anyValid {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: "value does not match any of the allowed schemas",
				Value:   data,
			})
		}
	}

	if len(schema.OneOf) > 0 {
		matchCount := 0
		for _, subSchema := range schema.OneOf {
			subResult := &ValidationResult{Valid: true}
			v.validateValue(data, subSchema, path, subResult)
			if subResult.Valid {
				matchCount++
			}
		}
		if matchCount != 1 {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value must match exactly one schema, matched %d", matchCount),
				Value:   data,
			})
		}
	}

	if schema.Not != nil {
		subResult := &ValidationResult{Valid: true}
		v.validateValue(data, schema.Not, path, subResult)
		if subResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: "value must NOT match the schema",
				Value:   data,
			})
		}
	}

	// If/Then/Else
	if schema.If != nil {
		ifResult := &ValidationResult{Valid: true}
		v.validateValue(data, schema.If, path, ifResult)

		if ifResult.Valid && schema.Then != nil {
			v.validateValue(data, schema.Then, path, result)
		} else if !ifResult.Valid && schema.Else != nil {
			v.validateValue(data, schema.Else, path, result)
		}
	}
}

func (v *Validator) validateType(data interface{}, expectedType, path string, result *ValidationResult) bool {
	actualType := getJSONType(data)

	// Handle multiple types (e.g., ["string", "null"])
	types := strings.Split(expectedType, ",")
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == actualType {
			return true
		}
		// Special case: integer is also a number
		if t == "number" && actualType == "integer" {
			return true
		}
		if t == "integer" && actualType == "number" {
			if num, ok := data.(float64); ok && num == float64(int64(num)) {
				return true
			}
		}
	}

	result.Valid = false
	result.Errors = append(result.Errors, &ValidationError{
		Path:    path,
		Message: fmt.Sprintf("expected type %s but got %s", expectedType, actualType),
		Value:   data,
	})
	return false
}

func (v *Validator) validateString(s string, schema *Schema, path string, result *ValidationResult) {
	if schema.MinLength != nil && len(s) < *schema.MinLength {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("string length %d is less than minimum %d", len(s), *schema.MinLength),
			Value:   s,
		})
	}

	if schema.MaxLength != nil && len(s) > *schema.MaxLength {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("string length %d exceeds maximum %d", len(s), *schema.MaxLength),
			Value:   s,
		})
	}

	if schema.Pattern != "" {
		if schema.compiledPattern == nil {
			var err error
			schema.compiledPattern, err = regexp.Compile(schema.Pattern)
			if err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, &ValidationError{
					Path:    path,
					Message: "invalid pattern in schema: " + err.Error(),
				})
				return
			}
		}
		if !schema.compiledPattern.MatchString(s) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string does not match pattern %s", schema.Pattern),
				Value:   s,
			})
		}
	}

	if schema.Format != "" {
		if !validateFormat(s, schema.Format) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string does not match format %s", schema.Format),
				Value:   s,
			})
		}
	}
}

func (v *Validator) validateNumber(n float64, schema *Schema, path string, result *ValidationResult) {
	if schema.Minimum != nil && n < *schema.Minimum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v is less than minimum %v", n, *schema.Minimum),
			Value:   n,
		})
	}

	if schema.Maximum != nil && n > *schema.Maximum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v exceeds maximum %v", n, *schema.Maximum),
			Value:   n,
		})
	}

	if schema.ExclusiveMinimum != nil && n <= *schema.ExclusiveMinimum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v must be greater than %v", n, *schema.ExclusiveMinimum),
			Value:   n,
		})
	}

	if schema.ExclusiveMaximum != nil && n >= *schema.ExclusiveMaximum {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v must be less than %v", n, *schema.ExclusiveMaximum),
			Value:   n,
		})
	}

	if schema.MultipleOf != nil && *schema.MultipleOf != 0 {
		quotient := n / *schema.MultipleOf
		if quotient != float64(int64(quotient)) {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value %v is not a multiple of %v", n, *schema.MultipleOf),
				Value:   n,
			})
		}
	}
}

func (v *Validator) validateArray(arr []interface{}, schema *Schema, path string, result *ValidationResult) {
	if schema.MinItems != nil && len(arr) < *schema.MinItems {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("array length %d is less than minimum %d", len(arr), *schema.MinItems),
		})
	}

	if schema.MaxItems != nil && len(arr) > *schema.MaxItems {
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("array length %d exceeds maximum %d", len(arr), *schema.MaxItems),
		})
	}

	if schema.UniqueItems {
		seen := make(map[string]bool)
		for i, item := range arr {
			key := fmt.Sprintf("%v", item)
			if seen[key] {
				result.Valid = false
				result.Errors = append(result.Errors, &ValidationError{
					Path:    path,
					Message: fmt.Sprintf("duplicate item at index %d", i),
					Value:   item,
				})
				break
			}
			seen[key] = true
		}
	}

	if schema.Items != nil {
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			v.validateValue(item, schema.Items, itemPath, result)
		}
	}
}

func (v *Validator) validateObject(obj map[string]interface{}, schema *Schema, path string, result *ValidationResult) {
	// Check required properties
	for _, required := range schema.Required {
		if _, exists := obj[required]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, &ValidationError{
				Path:    path + "." + required,
				Message: "required property is missing",
			})
		}
	}

	// Validate properties
	for key, value := range obj {
		propPath := path + "." + key

		if propSchema, exists := schema.Properties[key]; exists {
			v.validateValue(value, propSchema, propPath, result)
		} else {
			// Check additional properties
			switch ap := schema.AdditionalProperties.(type) {
			case bool:
				if !ap {
					result.Valid = false
					result.Errors = append(result.Errors, &ValidationError{
						Path:    propPath,
						Message: "additional property not allowed",
						Value:   value,
					})
				}
			case *Schema:
				v.validateValue(value, ap, propPath, result)
			case map[string]interface{}:
				// Convert map to schema
				schemaBytes, _ := json.Marshal(ap)
				var additionalSchema Schema
				if json.Unmarshal(schemaBytes, &additionalSchema) == nil {
					v.validateValue(value, &additionalSchema, propPath, result)
				}
			}
		}
	}
}

func (v *Validator) applySchemaModifications(data interface{}, schema *Schema) (interface{}, bool) {
	changed := false

	switch d := data.(type) {
	case map[string]interface{}:
		// Apply defaults
		if v.config.UseDefaults && schema.Properties != nil {
			for key, propSchema := range schema.Properties {
				if _, exists := d[key]; !exists && propSchema.Default != nil {
					d[key] = propSchema.Default
					changed = true
				}
			}
		}

		// Remove additional properties
		if v.config.RemoveAdditional && schema.Properties != nil {
			if ap, ok := schema.AdditionalProperties.(bool); ok && !ap {
				for key := range d {
					if _, exists := schema.Properties[key]; !exists {
						delete(d, key)
						changed = true
					}
				}
			}
		}

		// Recurse into properties
		if schema.Properties != nil {
			for key, propSchema := range schema.Properties {
				if val, exists := d[key]; exists {
					newVal, c := v.applySchemaModifications(val, propSchema)
					if c {
						d[key] = newVal
						changed = true
					}
				}
			}
		}

	case []interface{}:
		if schema.Items != nil {
			for i, item := range d {
				newItem, c := v.applySchemaModifications(item, schema.Items)
				if c {
					d[i] = newItem
					changed = true
				}
			}
		}
	}

	return data, changed
}

// UpdateConfig updates the validator configuration.
func (v *Validator) UpdateConfig(config Config) {
	v.mu.Lock()
	v.config = config
	v.mu.Unlock()
}

// AddRouteSchema adds a schema for a route.
func (v *Validator) AddRouteSchema(routeID string, schema *RouteSchema) {
	v.mu.Lock()
	if v.config.Schemas == nil {
		v.config.Schemas = make(map[string]*RouteSchema)
	}
	v.config.Schemas[routeID] = schema
	v.mu.Unlock()
}

// Helper functions

func getJSONType(data interface{}) string {
	switch data.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		num := data.(float64)
		if num == float64(int64(num)) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

func equalValues(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func validateFormat(s, format string) bool {
	switch format {
	case "email":
		// Basic email validation
		return strings.Contains(s, "@") && strings.Contains(s, ".")
	case "uri", "url":
		return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
	case "uuid":
		uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
		return uuidRegex.MatchString(s)
	case "date":
		dateRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
		return dateRegex.MatchString(s)
	case "date-time":
		// ISO 8601 format
		dateTimeRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
		return dateTimeRegex.MatchString(s)
	case "time":
		timeRegex := regexp.MustCompile(`^\d{2}:\d{2}:\d{2}`)
		return timeRegex.MatchString(s)
	case "ipv4":
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return false
		}
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return false
			}
		}
		return true
	case "ipv6":
		return strings.Contains(s, ":")
	case "hostname":
		hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
		return hostnameRegex.MatchString(s)
	default:
		// Unknown formats pass by default
		return true
	}
}

// SchemaBuilder provides a fluent interface for building schemas.
type SchemaBuilder struct {
	schema *Schema
}

// NewSchemaBuilder creates a new schema builder.
func NewSchemaBuilder() *SchemaBuilder {
	return &SchemaBuilder{
		schema: &Schema{},
	}
}

// Type sets the schema type.
func (b *SchemaBuilder) Type(t string) *SchemaBuilder {
	b.schema.Type = t
	return b
}

// Required adds required properties.
func (b *SchemaBuilder) Required(props ...string) *SchemaBuilder {
	b.schema.Required = append(b.schema.Required, props...)
	return b
}

// Property adds a property schema.
func (b *SchemaBuilder) Property(name string, propSchema *Schema) *SchemaBuilder {
	if b.schema.Properties == nil {
		b.schema.Properties = make(map[string]*Schema)
	}
	b.schema.Properties[name] = propSchema
	return b
}

// Items sets the items schema for arrays.
func (b *SchemaBuilder) Items(itemSchema *Schema) *SchemaBuilder {
	b.schema.Items = itemSchema
	return b
}

// MinLength sets minimum string length.
func (b *SchemaBuilder) MinLength(n int) *SchemaBuilder {
	b.schema.MinLength = &n
	return b
}

// MaxLength sets maximum string length.
func (b *SchemaBuilder) MaxLength(n int) *SchemaBuilder {
	b.schema.MaxLength = &n
	return b
}

// Pattern sets the pattern for strings.
func (b *SchemaBuilder) Pattern(p string) *SchemaBuilder {
	b.schema.Pattern = p
	return b
}

// Format sets the format for strings.
func (b *SchemaBuilder) Format(f string) *SchemaBuilder {
	b.schema.Format = f
	return b
}

// Minimum sets minimum for numbers.
func (b *SchemaBuilder) Minimum(n float64) *SchemaBuilder {
	b.schema.Minimum = &n
	return b
}

// Maximum sets maximum for numbers.
func (b *SchemaBuilder) Maximum(n float64) *SchemaBuilder {
	b.schema.Maximum = &n
	return b
}

// Enum sets allowed values.
func (b *SchemaBuilder) Enum(values ...interface{}) *SchemaBuilder {
	b.schema.Enum = values
	return b
}

// Default sets the default value.
func (b *SchemaBuilder) Default(v interface{}) *SchemaBuilder {
	b.schema.Default = v
	return b
}

// Nullable allows null values.
func (b *SchemaBuilder) Nullable() *SchemaBuilder {
	b.schema.Nullable = true
	return b
}

// Build returns the completed schema.
func (b *SchemaBuilder) Build() *Schema {
	return b.schema
}

// Common schema helpers

// StringSchema creates a string schema.
func StringSchema() *Schema {
	return &Schema{Type: "string"}
}

// IntegerSchema creates an integer schema.
func IntegerSchema() *Schema {
	return &Schema{Type: "integer"}
}

// NumberSchema creates a number schema.
func NumberSchema() *Schema {
	return &Schema{Type: "number"}
}

// BooleanSchema creates a boolean schema.
func BooleanSchema() *Schema {
	return &Schema{Type: "boolean"}
}

// ArraySchema creates an array schema with item type.
func ArraySchema(items *Schema) *Schema {
	return &Schema{Type: "array", Items: items}
}

// ObjectSchema creates an object schema with properties.
func ObjectSchema(properties map[string]*Schema, required ...string) *Schema {
	return &Schema{
		Type:       "object",
		Properties: properties,
		Required:   required,
	}
}
