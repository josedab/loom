package validation

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// MiddlewareConfig configures the validation middleware.
type MiddlewareConfig struct {
	// Validator is the validation engine.
	Validator *Validator
	// RouteIDFunc extracts the route ID from the request.
	RouteIDFunc func(*http.Request) string
	// Logger for validation events.
	Logger *slog.Logger
	// OnRequestError is called when request validation fails (optional).
	OnRequestError func(w http.ResponseWriter, r *http.Request, result *ValidationResult)
	// OnResponseError is called when response validation fails (optional).
	OnResponseError func(result *ValidationResult)
}

// ErrorResponse is the default error response format.
type ErrorResponse struct {
	Error   string             `json:"error"`
	Message string             `json:"message"`
	Details []*ValidationError `json:"details,omitempty"`
}

// Middleware returns HTTP middleware that validates requests and responses.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.OnRequestError == nil {
		cfg.OnRequestError = defaultRequestErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Validator == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Get route ID
			routeID := ""
			if cfg.RouteIDFunc != nil {
				routeID = cfg.RouteIDFunc(r)
			}

			// Validate request
			ctx := r.Context()
			result, err := cfg.Validator.ValidateRequest(ctx, routeID, r)
			if err != nil {
				cfg.Logger.Error("request validation error", "error", err)
				http.Error(w, "validation error", http.StatusInternalServerError)
				return
			}

			if !result.Valid {
				cfg.Validator.mu.RLock()
				mode := cfg.Validator.config.RequestMode
				cfg.Validator.mu.RUnlock()

				if mode == ModeStrict {
					cfg.Logger.Warn("request validation failed",
						"route", routeID,
						"errors", len(result.Errors))
					cfg.OnRequestError(w, r, result)
					return
				}

				if mode == ModeWarn {
					cfg.Logger.Warn("request validation failed (warning mode)",
						"route", routeID,
						"errors", len(result.Errors))
				}
			}

			// Create response recorder for response validation
			rec := &validationRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Call next handler
			next.ServeHTTP(rec, r)

			// Validate response if needed
			cfg.Validator.mu.RLock()
			respMode := cfg.Validator.config.ResponseMode
			cfg.Validator.mu.RUnlock()

			if respMode != ModeSkip && rec.body != nil {
				resp := &http.Response{
					StatusCode: rec.statusCode,
					Body:       nil, // Not needed for validation
				}

				// Create a simple response object for validation
				var respData interface{}
				if json.Unmarshal(rec.body, &respData) == nil {
					respResult := cfg.Validator.Validate(respData, nil)

					if !respResult.Valid {
						if respMode == ModeWarn {
							cfg.Logger.Warn("response validation failed (warning mode)",
								"route", routeID,
								"status", resp.StatusCode,
								"errors", len(respResult.Errors))
						}
						if cfg.OnResponseError != nil {
							cfg.OnResponseError(respResult)
						}
					}
				}
			}

			// Write the response
			rec.flush(w)
		})
	}
}

func defaultRequestErrorHandler(w http.ResponseWriter, r *http.Request, result *ValidationResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	resp := ErrorResponse{
		Error:   "validation_error",
		Message: "Request validation failed",
		Details: result.Errors,
	}

	json.NewEncoder(w).Encode(resp)
}

// validationRecorder captures the response for validation.
type validationRecorder struct {
	http.ResponseWriter
	statusCode  int
	body        []byte
	wroteHeader bool
}

func (r *validationRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.statusCode = code
	r.wroteHeader = true
}

func (r *validationRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

func (r *validationRecorder) flush(w http.ResponseWriter) {
	w.WriteHeader(r.statusCode)
	if r.body != nil {
		w.Write(r.body)
	}
}

// OpenAPILoader loads schemas from an OpenAPI specification.
type OpenAPILoader struct {
	spec map[string]interface{}
}

// NewOpenAPILoader creates a loader from OpenAPI JSON.
func NewOpenAPILoader(specJSON []byte) (*OpenAPILoader, error) {
	var spec map[string]interface{}
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return nil, err
	}
	return &OpenAPILoader{spec: spec}, nil
}

// LoadSchemas extracts schemas from the OpenAPI spec.
func (l *OpenAPILoader) LoadSchemas() (map[string]*RouteSchema, error) {
	schemas := make(map[string]*RouteSchema)

	paths, ok := l.spec["paths"].(map[string]interface{})
	if !ok {
		return schemas, nil
	}

	for path, pathItem := range paths {
		pathObj, ok := pathItem.(map[string]interface{})
		if !ok {
			continue
		}

		for method, operation := range pathObj {
			if method == "parameters" || method == "summary" || method == "description" {
				continue
			}

			opObj, ok := operation.(map[string]interface{})
			if !ok {
				continue
			}

			routeID := method + ":" + path
			routeSchema := &RouteSchema{
				ResponseSchemas: make(map[int]*Schema),
			}

			// Extract request body schema
			if requestBody, ok := opObj["requestBody"].(map[string]interface{}); ok {
				if content, ok := requestBody["content"].(map[string]interface{}); ok {
					if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
						if schemaObj, ok := jsonContent["schema"].(map[string]interface{}); ok {
							schema := l.convertSchema(schemaObj)
							routeSchema.RequestSchema = schema
						}
					}
				}
			}

			// Extract response schemas
			if responses, ok := opObj["responses"].(map[string]interface{}); ok {
				for statusStr, response := range responses {
					var statusCode int
					if statusStr == "default" {
						statusCode = 0
					} else {
						code, err := json.Number(statusStr).Int64()
						if err != nil {
							continue
						}
						statusCode = int(code)
					}

					respObj, ok := response.(map[string]interface{})
					if !ok {
						continue
					}

					if content, ok := respObj["content"].(map[string]interface{}); ok {
						if jsonContent, ok := content["application/json"].(map[string]interface{}); ok {
							if schemaObj, ok := jsonContent["schema"].(map[string]interface{}); ok {
								schema := l.convertSchema(schemaObj)
								routeSchema.ResponseSchemas[statusCode] = schema
							}
						}
					}
				}
			}

			// Extract query parameters schema
			if params, ok := opObj["parameters"].([]interface{}); ok {
				queryProps := make(map[string]*Schema)
				var queryRequired []string

				for _, param := range params {
					paramObj, ok := param.(map[string]interface{})
					if !ok {
						continue
					}

					in, _ := paramObj["in"].(string)
					name, _ := paramObj["name"].(string)

					if in != "query" || name == "" {
						continue
					}

					if schemaObj, ok := paramObj["schema"].(map[string]interface{}); ok {
						queryProps[name] = l.convertSchema(schemaObj)
					}

					if required, ok := paramObj["required"].(bool); ok && required {
						queryRequired = append(queryRequired, name)
					}
				}

				if len(queryProps) > 0 {
					routeSchema.QuerySchema = &Schema{
						Type:       "object",
						Properties: queryProps,
						Required:   queryRequired,
					}
				}
			}

			schemas[routeID] = routeSchema
		}
	}

	return schemas, nil
}

func (l *OpenAPILoader) convertSchema(obj map[string]interface{}) *Schema {
	schemaBytes, err := json.Marshal(obj)
	if err != nil {
		return nil
	}

	var schema Schema
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		return nil
	}

	// Recursively resolve $ref references
	if ref, ok := obj["$ref"].(string); ok {
		resolved := l.resolveRef(ref)
		if resolved != nil {
			return resolved
		}
	}

	return &schema
}

func (l *OpenAPILoader) resolveRef(ref string) *Schema {
	// Handle #/components/schemas/Name references
	if len(ref) > 2 && ref[0] == '#' && ref[1] == '/' {
		parts := []string{}
		for _, p := range ref[2:] {
			if p == '/' {
				parts = append(parts, "")
			} else if len(parts) > 0 {
				parts[len(parts)-1] += string(p)
			} else {
				parts = append(parts, string(p))
			}
		}

		current := interface{}(l.spec)
		for _, part := range parts {
			if m, ok := current.(map[string]interface{}); ok {
				current = m[part]
			} else {
				return nil
			}
		}

		if schemaObj, ok := current.(map[string]interface{}); ok {
			return l.convertSchema(schemaObj)
		}
	}

	return nil
}

// ValidatorStats contains validation statistics.
type ValidatorStats struct {
	RequestsValidated  int64
	ResponsesValidated int64
	RequestsFailed     int64
	ResponsesFailed    int64
}

// StatsCollector collects validation statistics.
type StatsCollector struct {
	stats ValidatorStats
}

// NewStatsCollector creates a new stats collector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// RecordRequestValidation records a request validation.
func (s *StatsCollector) RecordRequestValidation(valid bool) {
	s.stats.RequestsValidated++
	if !valid {
		s.stats.RequestsFailed++
	}
}

// RecordResponseValidation records a response validation.
func (s *StatsCollector) RecordResponseValidation(valid bool) {
	s.stats.ResponsesValidated++
	if !valid {
		s.stats.ResponsesFailed++
	}
}

// GetStats returns current statistics.
func (s *StatsCollector) GetStats() ValidatorStats {
	return s.stats
}
