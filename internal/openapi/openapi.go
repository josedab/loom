// Package openapi provides OpenAPI specification integration for the gateway.
package openapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Spec represents a parsed OpenAPI specification.
type Spec struct {
	OpenAPI    string                `json:"openapi" yaml:"openapi"`
	Info       Info                  `json:"info" yaml:"info"`
	Servers    []Server              `json:"servers,omitempty" yaml:"servers,omitempty"`
	Paths      map[string]*PathItem  `json:"paths" yaml:"paths"`
	Components *Components           `json:"components,omitempty" yaml:"components,omitempty"`
	Security   []SecurityRequirement `json:"security,omitempty" yaml:"security,omitempty"`
	Tags       []Tag                 `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// Info contains API metadata.
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string `json:"version" yaml:"version"`
}

// Server represents a server URL.
type Server struct {
	URL         string                    `json:"url" yaml:"url"`
	Description string                    `json:"description,omitempty" yaml:"description,omitempty"`
	Variables   map[string]ServerVariable `json:"variables,omitempty" yaml:"variables,omitempty"`
}

// ServerVariable represents a server URL variable.
type ServerVariable struct {
	Default     string   `json:"default" yaml:"default"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Enum        []string `json:"enum,omitempty" yaml:"enum,omitempty"`
}

// PathItem represents operations on a path.
type PathItem struct {
	Ref         string     `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Summary     string     `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Get         *Operation `json:"get,omitempty" yaml:"get,omitempty"`
	Put         *Operation `json:"put,omitempty" yaml:"put,omitempty"`
	Post        *Operation `json:"post,omitempty" yaml:"post,omitempty"`
	Delete      *Operation `json:"delete,omitempty" yaml:"delete,omitempty"`
	Options     *Operation `json:"options,omitempty" yaml:"options,omitempty"`
	Head        *Operation `json:"head,omitempty" yaml:"head,omitempty"`
	Patch       *Operation `json:"patch,omitempty" yaml:"patch,omitempty"`
	Trace       *Operation `json:"trace,omitempty" yaml:"trace,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// Operation represents a single API operation.
type Operation struct {
	OperationID string              `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Summary     string              `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string            `json:"tags,omitempty" yaml:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses" yaml:"responses"`
	Security    []SecurityRequirement `json:"security,omitempty" yaml:"security,omitempty"`
	Deprecated  bool                `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

// Parameter represents an operation parameter.
type Parameter struct {
	Ref         string  `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Name        string  `json:"name,omitempty" yaml:"name,omitempty"`
	In          string  `json:"in,omitempty" yaml:"in,omitempty"` // query, header, path, cookie
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool    `json:"required,omitempty" yaml:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Style       string  `json:"style,omitempty" yaml:"style,omitempty"`
	Explode     bool    `json:"explode,omitempty" yaml:"explode,omitempty"`
}

// RequestBody represents a request body.
type RequestBody struct {
	Ref         string               `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Description string               `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
	Required    bool                 `json:"required,omitempty" yaml:"required,omitempty"`
}

// Response represents an API response.
type Response struct {
	Ref         string               `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Description string               `json:"description,omitempty" yaml:"description,omitempty"`
	Headers     map[string]Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
}

// MediaType represents a media type.
type MediaType struct {
	Schema   *Schema             `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example  interface{}         `json:"example,omitempty" yaml:"example,omitempty"`
	Examples map[string]Example  `json:"examples,omitempty" yaml:"examples,omitempty"`
}

// Header represents a response header.
type Header struct {
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// Example represents an example value.
type Example struct {
	Summary     string      `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Value       interface{} `json:"value,omitempty" yaml:"value,omitempty"`
}

// Schema represents a JSON Schema.
type Schema struct {
	Ref                  string             `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	Type                 string             `json:"type,omitempty" yaml:"type,omitempty"`
	Format               string             `json:"format,omitempty" yaml:"format,omitempty"`
	Title                string             `json:"title,omitempty" yaml:"title,omitempty"`
	Description          string             `json:"description,omitempty" yaml:"description,omitempty"`
	Default              interface{}        `json:"default,omitempty" yaml:"default,omitempty"`
	Enum                 []interface{}      `json:"enum,omitempty" yaml:"enum,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Required             []string           `json:"required,omitempty" yaml:"required,omitempty"`
	Items                *Schema            `json:"items,omitempty" yaml:"items,omitempty"`
	AdditionalProperties interface{}        `json:"additionalProperties,omitempty" yaml:"additionalProperties,omitempty"`
	Minimum              *float64           `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	Maximum              *float64           `json:"maximum,omitempty" yaml:"maximum,omitempty"`
	MinLength            *int               `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	Pattern              string             `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	MinItems             *int               `json:"minItems,omitempty" yaml:"minItems,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty" yaml:"maxItems,omitempty"`
	UniqueItems          bool               `json:"uniqueItems,omitempty" yaml:"uniqueItems,omitempty"`
	AllOf                []*Schema          `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	OneOf                []*Schema          `json:"oneOf,omitempty" yaml:"oneOf,omitempty"`
	AnyOf                []*Schema          `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	Not                  *Schema            `json:"not,omitempty" yaml:"not,omitempty"`
	Nullable             bool               `json:"nullable,omitempty" yaml:"nullable,omitempty"`
	ReadOnly             bool               `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	WriteOnly            bool               `json:"writeOnly,omitempty" yaml:"writeOnly,omitempty"`
}

// Components contains reusable components.
type Components struct {
	Schemas         map[string]*Schema         `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	Responses       map[string]Response        `json:"responses,omitempty" yaml:"responses,omitempty"`
	Parameters      map[string]Parameter       `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBodies   map[string]RequestBody     `json:"requestBodies,omitempty" yaml:"requestBodies,omitempty"`
	Headers         map[string]Header          `json:"headers,omitempty" yaml:"headers,omitempty"`
	SecuritySchemes map[string]SecurityScheme  `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

// SecurityScheme represents a security scheme.
type SecurityScheme struct {
	Type             string     `json:"type" yaml:"type"`
	Description      string     `json:"description,omitempty" yaml:"description,omitempty"`
	Name             string     `json:"name,omitempty" yaml:"name,omitempty"`
	In               string     `json:"in,omitempty" yaml:"in,omitempty"`
	Scheme           string     `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat     string     `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	Flows            *OAuthFlows `json:"flows,omitempty" yaml:"flows,omitempty"`
	OpenIDConnectURL string     `json:"openIdConnectUrl,omitempty" yaml:"openIdConnectUrl,omitempty"`
}

// OAuthFlows represents OAuth2 flows.
type OAuthFlows struct {
	Implicit          *OAuthFlow `json:"implicit,omitempty" yaml:"implicit,omitempty"`
	Password          *OAuthFlow `json:"password,omitempty" yaml:"password,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty" yaml:"clientCredentials,omitempty"`
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty" yaml:"authorizationCode,omitempty"`
}

// OAuthFlow represents a single OAuth2 flow.
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty" yaml:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty" yaml:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes" yaml:"scopes"`
}

// SecurityRequirement maps security scheme names to required scopes.
type SecurityRequirement map[string][]string

// Tag represents an API tag.
type Tag struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Parse parses an OpenAPI specification from bytes.
func Parse(data []byte) (*Spec, error) {
	var spec Spec

	// Try JSON first
	if err := json.Unmarshal(data, &spec); err == nil {
		return &spec, nil
	}

	// Try YAML
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	return &spec, nil
}

// ParseReader parses an OpenAPI specification from a reader.
func ParseReader(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Route represents a generated route from OpenAPI.
type Route struct {
	Path        string
	Method      string
	OperationID string
	Summary     string
	Tags        []string
	Parameters  []Parameter
	RequestBody *RequestBody
	Responses   map[string]Response
	Security    []SecurityRequirement
	Deprecated  bool
}

// GenerateRoutes generates routes from the OpenAPI spec.
func (s *Spec) GenerateRoutes() []Route {
	var routes []Route

	for path, item := range s.Paths {
		if item == nil {
			continue
		}

		// Collect path-level parameters
		pathParams := item.Parameters

		operations := map[string]*Operation{
			"GET":     item.Get,
			"POST":    item.Post,
			"PUT":     item.Put,
			"DELETE":  item.Delete,
			"PATCH":   item.Patch,
			"OPTIONS": item.Options,
			"HEAD":    item.Head,
		}

		for method, op := range operations {
			if op == nil {
				continue
			}

			// Merge path and operation parameters
			params := append([]Parameter{}, pathParams...)
			params = append(params, op.Parameters...)

			route := Route{
				Path:        path,
				Method:      method,
				OperationID: op.OperationID,
				Summary:     op.Summary,
				Tags:        op.Tags,
				Parameters:  params,
				RequestBody: op.RequestBody,
				Responses:   op.Responses,
				Security:    op.Security,
				Deprecated:  op.Deprecated,
			}

			routes = append(routes, route)
		}
	}

	return routes
}

// Validator validates requests against an OpenAPI spec.
type Validator struct {
	spec          *Spec
	routes        map[string]map[string]*Route // path -> method -> route
	pathMatchers  map[string]*regexp.Regexp
	resolvedCache sync.Map // Cache resolved $ref schemas
}

// NewValidator creates a new validator for the spec.
func NewValidator(spec *Spec) *Validator {
	v := &Validator{
		spec:         spec,
		routes:       make(map[string]map[string]*Route),
		pathMatchers: make(map[string]*regexp.Regexp),
	}

	routes := spec.GenerateRoutes()
	for i := range routes {
		route := &routes[i]
		if v.routes[route.Path] == nil {
			v.routes[route.Path] = make(map[string]*Route)
		}
		v.routes[route.Path][route.Method] = route

		// Create path matcher regex
		pattern := pathToRegex(route.Path)
		v.pathMatchers[route.Path] = regexp.MustCompile(pattern)
	}

	return v
}

// pathToRegex converts OpenAPI path to regex pattern.
func pathToRegex(path string) string {
	// Replace {param} with named capture groups first, then escape the rest
	re := regexp.MustCompile(`\{([^}]+)\}`)
	// Replace path params with placeholders
	parts := re.Split(path, -1)
	matches := re.FindAllStringSubmatch(path, -1)

	var result strings.Builder
	result.WriteString("^")
	for i, part := range parts {
		result.WriteString(regexp.QuoteMeta(part))
		if i < len(matches) {
			result.WriteString("(?P<")
			result.WriteString(matches[i][1])
			result.WriteString(">[^/]+)")
		}
	}
	result.WriteString("$")
	return result.String()
}

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult contains the result of validation.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
	Route  *Route            `json:"-"`
	Params map[string]string `json:"params,omitempty"`
}

// ValidateRequest validates an HTTP request against the spec.
func (v *Validator) ValidateRequest(r *http.Request) *ValidationResult {
	result := &ValidationResult{Valid: true, Params: make(map[string]string)}

	// Find matching route
	route, params := v.findRoute(r.URL.Path, r.Method)
	if route == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "path",
			Message: fmt.Sprintf("no route found for %s %s", r.Method, r.URL.Path),
		})
		return result
	}

	result.Route = route
	result.Params = params

	// Validate parameters
	for _, param := range route.Parameters {
		if err := v.validateParameter(r, param, params); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, *err)
		}
	}

	// Validate request body
	if route.RequestBody != nil && route.RequestBody.Required {
		if r.Body == nil || r.ContentLength == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "body",
				Message: "request body is required",
			})
		}
	}

	return result
}

// findRoute finds a matching route for a path and method.
func (v *Validator) findRoute(path, method string) (*Route, map[string]string) {
	for routePath, matcher := range v.pathMatchers {
		if matches := matcher.FindStringSubmatch(path); matches != nil {
			if methods, ok := v.routes[routePath]; ok {
				if route, ok := methods[method]; ok {
					// Extract path parameters
					params := make(map[string]string)
					names := matcher.SubexpNames()
					for i, name := range names {
						if name != "" && i < len(matches) {
							params[name] = matches[i]
						}
					}
					return route, params
				}
			}
		}
	}
	return nil, nil
}

// validateParameter validates a single parameter.
func (v *Validator) validateParameter(r *http.Request, param Parameter, pathParams map[string]string) *ValidationError {
	var value string
	var found bool

	switch param.In {
	case "path":
		value, found = pathParams[param.Name]
	case "query":
		value = r.URL.Query().Get(param.Name)
		found = r.URL.Query().Has(param.Name)
	case "header":
		value = r.Header.Get(param.Name)
		found = value != ""
	case "cookie":
		if cookie, err := r.Cookie(param.Name); err == nil {
			value = cookie.Value
			found = true
		}
	}

	// Check required
	if param.Required && !found {
		return &ValidationError{
			Field:   fmt.Sprintf("%s.%s", param.In, param.Name),
			Message: "parameter is required",
		}
	}

	// Validate against schema if present
	if found && param.Schema != nil {
		if err := v.validateValue(value, param.Schema); err != nil {
			return &ValidationError{
				Field:   fmt.Sprintf("%s.%s", param.In, param.Name),
				Message: err.Error(),
				Value:   value,
			}
		}
	}

	return nil
}

// validateValue validates a value against a schema.
func (v *Validator) validateValue(value string, schema *Schema) error {
	if schema == nil {
		return nil
	}

	// Resolve $ref if present
	if schema.Ref != "" {
		resolved := v.resolveRef(schema.Ref)
		if resolved != nil {
			schema = resolved
		}
	}

	switch schema.Type {
	case "string":
		return v.validateString(value, schema)
	case "integer":
		return v.validateInteger(value, schema)
	case "number":
		return v.validateNumber(value, schema)
	case "boolean":
		return v.validateBoolean(value)
	}

	return nil
}

// validateString validates a string value.
func (v *Validator) validateString(value string, schema *Schema) error {
	if schema.MinLength != nil && len(value) < *schema.MinLength {
		return fmt.Errorf("string too short (min: %d)", *schema.MinLength)
	}
	if schema.MaxLength != nil && len(value) > *schema.MaxLength {
		return fmt.Errorf("string too long (max: %d)", *schema.MaxLength)
	}
	if schema.Pattern != "" {
		if matched, _ := regexp.MatchString(schema.Pattern, value); !matched {
			return fmt.Errorf("string does not match pattern: %s", schema.Pattern)
		}
	}
	if len(schema.Enum) > 0 {
		found := false
		for _, e := range schema.Enum {
			if fmt.Sprint(e) == value {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("value must be one of: %v", schema.Enum)
		}
	}
	return nil
}

// validateInteger validates an integer value.
func (v *Validator) validateInteger(value string, schema *Schema) error {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("not a valid integer")
	}
	if schema.Minimum != nil && float64(n) < *schema.Minimum {
		return fmt.Errorf("value too small (min: %v)", *schema.Minimum)
	}
	if schema.Maximum != nil && float64(n) > *schema.Maximum {
		return fmt.Errorf("value too large (max: %v)", *schema.Maximum)
	}
	return nil
}

// validateNumber validates a number value.
func (v *Validator) validateNumber(value string, schema *Schema) error {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("not a valid number")
	}
	if schema.Minimum != nil && n < *schema.Minimum {
		return fmt.Errorf("value too small (min: %v)", *schema.Minimum)
	}
	if schema.Maximum != nil && n > *schema.Maximum {
		return fmt.Errorf("value too large (max: %v)", *schema.Maximum)
	}
	return nil
}

// validateBoolean validates a boolean value.
func (v *Validator) validateBoolean(value string) error {
	if value != "true" && value != "false" {
		return fmt.Errorf("not a valid boolean")
	}
	return nil
}

// resolveRef resolves a $ref reference.
func (v *Validator) resolveRef(ref string) *Schema {
	// Check cache
	if cached, ok := v.resolvedCache.Load(ref); ok {
		return cached.(*Schema)
	}

	// Parse reference path: #/components/schemas/Name
	if !strings.HasPrefix(ref, "#/components/schemas/") {
		return nil
	}

	name := strings.TrimPrefix(ref, "#/components/schemas/")
	if v.spec.Components != nil && v.spec.Components.Schemas != nil {
		if schema, ok := v.spec.Components.Schemas[name]; ok {
			v.resolvedCache.Store(ref, schema)
			return schema
		}
	}

	return nil
}

// ValidateJSON validates a JSON body against a schema.
func (v *Validator) ValidateJSON(body []byte, schema *Schema) []ValidationError {
	if schema == nil {
		return nil
	}

	// Resolve $ref
	if schema.Ref != "" {
		if resolved := v.resolveRef(schema.Ref); resolved != nil {
			schema = resolved
		}
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return []ValidationError{{Field: "body", Message: "invalid JSON: " + err.Error()}}
	}

	var errors []ValidationError
	v.validateJSONValue("", data, schema, &errors)
	return errors
}

// validateJSONValue validates a JSON value against a schema.
func (v *Validator) validateJSONValue(path string, value interface{}, schema *Schema, errors *[]ValidationError) {
	if schema == nil {
		return
	}

	// Resolve $ref
	if schema.Ref != "" {
		if resolved := v.resolveRef(schema.Ref); resolved != nil {
			schema = resolved
		}
	}

	// Handle nullable
	if value == nil {
		if !schema.Nullable {
			*errors = append(*errors, ValidationError{
				Field:   path,
				Message: "null value not allowed",
			})
		}
		return
	}

	switch schema.Type {
	case "object":
		v.validateJSONObject(path, value, schema, errors)
	case "array":
		v.validateJSONArray(path, value, schema, errors)
	case "string":
		if str, ok := value.(string); ok {
			if err := v.validateString(str, schema); err != nil {
				*errors = append(*errors, ValidationError{Field: path, Message: err.Error(), Value: value})
			}
		} else {
			*errors = append(*errors, ValidationError{Field: path, Message: "expected string", Value: value})
		}
	case "integer", "number":
		if num, ok := value.(float64); ok {
			if schema.Minimum != nil && num < *schema.Minimum {
				*errors = append(*errors, ValidationError{Field: path, Message: fmt.Sprintf("value too small (min: %v)", *schema.Minimum), Value: value})
			}
			if schema.Maximum != nil && num > *schema.Maximum {
				*errors = append(*errors, ValidationError{Field: path, Message: fmt.Sprintf("value too large (max: %v)", *schema.Maximum), Value: value})
			}
		} else {
			*errors = append(*errors, ValidationError{Field: path, Message: "expected number", Value: value})
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			*errors = append(*errors, ValidationError{Field: path, Message: "expected boolean", Value: value})
		}
	}
}

// validateJSONObject validates a JSON object.
func (v *Validator) validateJSONObject(path string, value interface{}, schema *Schema, errors *[]ValidationError) {
	obj, ok := value.(map[string]interface{})
	if !ok {
		*errors = append(*errors, ValidationError{Field: path, Message: "expected object"})
		return
	}

	// Check required properties
	for _, req := range schema.Required {
		if _, ok := obj[req]; !ok {
			fieldPath := path + "." + req
			if path == "" {
				fieldPath = req
			}
			*errors = append(*errors, ValidationError{Field: fieldPath, Message: "required property missing"})
		}
	}

	// Validate properties
	for propName, propSchema := range schema.Properties {
		if propValue, ok := obj[propName]; ok {
			fieldPath := path + "." + propName
			if path == "" {
				fieldPath = propName
			}
			v.validateJSONValue(fieldPath, propValue, propSchema, errors)
		}
	}
}

// validateJSONArray validates a JSON array.
func (v *Validator) validateJSONArray(path string, value interface{}, schema *Schema, errors *[]ValidationError) {
	arr, ok := value.([]interface{})
	if !ok {
		*errors = append(*errors, ValidationError{Field: path, Message: "expected array"})
		return
	}

	// Check length constraints
	if schema.MinItems != nil && len(arr) < *schema.MinItems {
		*errors = append(*errors, ValidationError{Field: path, Message: fmt.Sprintf("array too short (min: %d)", *schema.MinItems)})
	}
	if schema.MaxItems != nil && len(arr) > *schema.MaxItems {
		*errors = append(*errors, ValidationError{Field: path, Message: fmt.Sprintf("array too long (max: %d)", *schema.MaxItems)})
	}

	// Validate items
	if schema.Items != nil {
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			v.validateJSONValue(itemPath, item, schema.Items, errors)
		}
	}
}

// MockGenerator generates mock responses from the spec.
type MockGenerator struct {
	spec *Spec
}

// NewMockGenerator creates a new mock generator.
func NewMockGenerator(spec *Spec) *MockGenerator {
	return &MockGenerator{spec: spec}
}

// GenerateMock generates a mock response for an operation.
func (g *MockGenerator) GenerateMock(path, method string) (int, map[string]string, []byte, error) {
	routes := g.spec.GenerateRoutes()

	for _, route := range routes {
		if route.Path == path && route.Method == method {
			// Find successful response (2xx)
			for code, resp := range route.Responses {
				statusCode, _ := strconv.Atoi(code)
				if statusCode >= 200 && statusCode < 300 {
					headers := make(map[string]string)
					var body []byte

					// Get content
					for contentType, media := range resp.Content {
						headers["Content-Type"] = contentType
						if media.Example != nil {
							body, _ = json.Marshal(media.Example)
						} else if media.Schema != nil {
							body = g.generateFromSchema(media.Schema)
						}
						break
					}

					return statusCode, headers, body, nil
				}
			}
		}
	}

	return 0, nil, nil, fmt.Errorf("no mock available for %s %s", method, path)
}

// generateFromSchema generates mock data from a schema.
func (g *MockGenerator) generateFromSchema(schema *Schema) []byte {
	value := g.generateValue(schema)
	data, _ := json.Marshal(value)
	return data
}

// generateValue generates a value from a schema.
func (g *MockGenerator) generateValue(schema *Schema) interface{} {
	if schema == nil {
		return nil
	}

	// Resolve $ref
	if schema.Ref != "" {
		name := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
		if g.spec.Components != nil && g.spec.Components.Schemas != nil {
			if resolved := g.spec.Components.Schemas[name]; resolved != nil {
				schema = resolved
			}
		}
	}

	// Use default if available
	if schema.Default != nil {
		return schema.Default
	}

	// Use first enum value if available
	if len(schema.Enum) > 0 {
		return schema.Enum[0]
	}

	switch schema.Type {
	case "string":
		if schema.Format == "date-time" {
			return "2024-01-01T00:00:00Z"
		}
		if schema.Format == "date" {
			return "2024-01-01"
		}
		if schema.Format == "email" {
			return "user@example.com"
		}
		if schema.Format == "uuid" {
			return "00000000-0000-0000-0000-000000000000"
		}
		return "string"
	case "integer":
		return 0
	case "number":
		return 0.0
	case "boolean":
		return false
	case "array":
		if schema.Items != nil {
			return []interface{}{g.generateValue(schema.Items)}
		}
		return []interface{}{}
	case "object":
		obj := make(map[string]interface{})
		for name, prop := range schema.Properties {
			obj[name] = g.generateValue(prop)
		}
		return obj
	}

	return nil
}
