package transform

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// MiddlewareConfig configures the transformation middleware.
type MiddlewareConfig struct {
	// Transformer is the transformation engine
	Transformer *Transformer
	// MaxBodySize is the maximum body size to transform (default: 10MB)
	MaxBodySize int64
	// RouteIDFunc extracts the route ID (for route-specific transforms)
	RouteIDFunc func(*http.Request) string
	// PathParamsFunc extracts path parameters from the request
	PathParamsFunc func(*http.Request) map[string]string
	// Logger for transformation events
	Logger *slog.Logger
}

// DefaultMiddlewareConfig returns sensible defaults.
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		MaxBodySize: 10 * 1024 * 1024, // 10MB
	}
}

// Middleware returns HTTP middleware that applies transformations.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 10 * 1024 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Transformer == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Build transformation context from request
			ctx := &Context{
				Headers:     r.Header.Clone(),
				Method:      r.Method,
				Path:        r.URL.Path,
				QueryParams: r.URL.Query(),
				Variables:   make(map[string]interface{}),
			}

			// Extract path parameters if function provided
			if cfg.PathParamsFunc != nil {
				ctx.PathParams = cfg.PathParamsFunc(r)
			}

			// Read and parse body if present
			var originalBody []byte
			if r.Body != nil && r.ContentLength > 0 && r.ContentLength <= cfg.MaxBodySize {
				var err error
				originalBody, err = io.ReadAll(io.LimitReader(r.Body, cfg.MaxBodySize))
				if err != nil {
					cfg.Logger.Debug("failed to read body for transformation", "error", err)
					next.ServeHTTP(w, r)
					return
				}

				// Parse JSON body
				if isJSON(r.Header.Get("Content-Type")) && len(originalBody) > 0 {
					if err := ctx.UnmarshalBody(originalBody); err != nil {
						cfg.Logger.Debug("failed to parse JSON body", "error", err)
						// Still allow pass-through with original body
						r.Body = io.NopCloser(bytes.NewReader(originalBody))
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			// Apply request transformations
			if err := cfg.Transformer.TransformRequest(ctx); err != nil {
				cfg.Logger.Error("request transformation failed", "error", err)
				// Continue with original request on error
				if originalBody != nil {
					r.Body = io.NopCloser(bytes.NewReader(originalBody))
				}
				next.ServeHTTP(w, r)
				return
			}

			// Update request with transformed values
			applyRequestTransforms(r, ctx, originalBody)

			// Create response recorder to capture response for transformation
			rec := &transformRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
				headers:        make(http.Header),
			}

			// Call next handler
			next.ServeHTTP(rec, r)

			// Build response context
			respCtx := &Context{
				Headers:     rec.headers,
				Method:      r.Method,
				Path:        r.URL.Path,
				StatusCode:  rec.statusCode,
				QueryParams: r.URL.Query(),
				PathParams:  ctx.PathParams,
				Variables:   ctx.Variables, // Share variables between req/resp
			}

			// Parse response body if JSON
			responseBody := rec.body.Bytes()
			if isJSON(rec.headers.Get("Content-Type")) && len(responseBody) > 0 {
				if err := respCtx.UnmarshalBody(responseBody); err != nil {
					cfg.Logger.Debug("failed to parse response JSON", "error", err)
					// Write original response
					writeResponse(w, rec.statusCode, rec.headers, responseBody)
					return
				}
			}

			// Apply response transformations
			if err := cfg.Transformer.TransformResponse(respCtx); err != nil {
				cfg.Logger.Error("response transformation failed", "error", err)
				// Write original response on error
				writeResponse(w, rec.statusCode, rec.headers, responseBody)
				return
			}

			// Write transformed response
			applyResponseTransforms(w, respCtx, rec, responseBody)
		})
	}
}

// applyRequestTransforms updates the request with transformed values.
func applyRequestTransforms(r *http.Request, ctx *Context, originalBody []byte) {
	// Update headers
	for key, values := range ctx.Headers {
		r.Header.Del(key)
		for _, v := range values {
			r.Header.Add(key, v)
		}
	}

	// Remove deleted headers
	for key := range r.Header {
		if _, exists := ctx.Headers[key]; !exists {
			r.Header.Del(key)
		}
	}

	// Update query parameters
	q := r.URL.Query()
	for key := range q {
		q.Del(key)
	}
	for key, values := range ctx.QueryParams {
		for _, v := range values {
			q.Add(key, v)
		}
	}
	r.URL.RawQuery = q.Encode()

	// Update body if it was JSON and we have transformed body
	if ctx.Body != nil {
		newBody, err := ctx.MarshalBody()
		if err == nil {
			r.Body = io.NopCloser(bytes.NewReader(newBody))
			r.ContentLength = int64(len(newBody))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(originalBody))
		}
	} else if originalBody != nil {
		r.Body = io.NopCloser(bytes.NewReader(originalBody))
	}
}

// applyResponseTransforms writes the transformed response.
func applyResponseTransforms(w http.ResponseWriter, ctx *Context, rec *transformRecorder, originalBody []byte) {
	// Copy transformed headers
	for key, values := range ctx.Headers {
		w.Header().Del(key)
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// Serialize transformed body if JSON was parsed
	var finalBody []byte
	if ctx.Body != nil {
		var err error
		finalBody, err = ctx.MarshalBody()
		if err != nil {
			finalBody = originalBody
		}
	} else {
		finalBody = originalBody
	}

	// Update Content-Length if body changed
	if len(finalBody) != len(originalBody) {
		w.Header().Del("Content-Length")
	}

	// Use transformed status code
	statusCode := ctx.StatusCode
	if statusCode == 0 {
		statusCode = rec.statusCode
	}

	w.WriteHeader(statusCode)
	w.Write(finalBody)
}

// writeResponse writes an unmodified response.
func writeResponse(w http.ResponseWriter, statusCode int, headers http.Header, body []byte) {
	for key, values := range headers {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(statusCode)
	w.Write(body)
}

// transformRecorder captures the response for transformation.
type transformRecorder struct {
	http.ResponseWriter
	statusCode    int
	body          *bytes.Buffer
	headers       http.Header
	wroteHeader   bool
}

func (r *transformRecorder) Header() http.Header {
	return r.headers
}

func (r *transformRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.statusCode = code
	r.wroteHeader = true
}

func (r *transformRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}

// isJSON checks if a content type is JSON.
func isJSON(contentType string) bool {
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "+json")
}

// ChainedTransformer allows applying multiple transformers in sequence.
type ChainedTransformer struct {
	transformers []*Transformer
}

// NewChainedTransformer creates a chained transformer.
func NewChainedTransformer(transformers ...*Transformer) *ChainedTransformer {
	return &ChainedTransformer{transformers: transformers}
}

// TransformRequest applies all transformers' request transforms.
func (c *ChainedTransformer) TransformRequest(ctx *Context) error {
	for _, t := range c.transformers {
		if err := t.TransformRequest(ctx); err != nil {
			return err
		}
	}
	return nil
}

// TransformResponse applies all transformers' response transforms.
func (c *ChainedTransformer) TransformResponse(ctx *Context) error {
	for _, t := range c.transformers {
		if err := t.TransformResponse(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RuleBuilder provides a fluent interface for building transformation rules.
type RuleBuilder struct {
	rule Rule
}

// NewRule starts building a new transformation rule.
func NewRule(name string) *RuleBuilder {
	return &RuleBuilder{
		rule: Rule{Name: name},
	}
}

// MatchPaths adds path patterns to match.
func (b *RuleBuilder) MatchPaths(paths ...string) *RuleBuilder {
	b.rule.Match.Paths = append(b.rule.Match.Paths, paths...)
	return b
}

// MatchMethods adds methods to match.
func (b *RuleBuilder) MatchMethods(methods ...string) *RuleBuilder {
	b.rule.Match.Methods = append(b.rule.Match.Methods, methods...)
	return b
}

// MatchHeader adds a header requirement.
func (b *RuleBuilder) MatchHeader(key, value string) *RuleBuilder {
	if b.rule.Match.Headers == nil {
		b.rule.Match.Headers = make(map[string]string)
	}
	b.rule.Match.Headers[key] = value
	return b
}

// OnRequest adds a request transformation operation.
func (b *RuleBuilder) OnRequest(op Operation) *RuleBuilder {
	b.rule.Request = append(b.rule.Request, op)
	return b
}

// OnResponse adds a response transformation operation.
func (b *RuleBuilder) OnResponse(op Operation) *RuleBuilder {
	b.rule.Response = append(b.rule.Response, op)
	return b
}

// SetRequestHeader adds an operation to set a request header.
func (b *RuleBuilder) SetRequestHeader(key, value string) *RuleBuilder {
	return b.OnRequest(Operation{
		Type:   "set",
		Target: "headers." + key,
		Value:  value,
	})
}

// SetResponseHeader adds an operation to set a response header.
func (b *RuleBuilder) SetResponseHeader(key, value string) *RuleBuilder {
	return b.OnResponse(Operation{
		Type:   "set",
		Target: "headers." + key,
		Value:  value,
	})
}

// DeleteRequestHeader adds an operation to delete a request header.
func (b *RuleBuilder) DeleteRequestHeader(key string) *RuleBuilder {
	return b.OnRequest(Operation{
		Type:   "delete",
		Target: "headers." + key,
	})
}

// CopyField adds an operation to copy a field.
func (b *RuleBuilder) CopyField(source, target string) *RuleBuilder {
	return b.OnRequest(Operation{
		Type:   "copy",
		Source: source,
		Target: target,
	})
}

// MapField adds an operation to map a field value.
func (b *RuleBuilder) MapField(source, target string, mapping map[string]interface{}) *RuleBuilder {
	return b.OnRequest(Operation{
		Type:    "map",
		Source:  source,
		Target:  target,
		Mapping: mapping,
	})
}

// Build returns the completed rule.
func (b *RuleBuilder) Build() Rule {
	return b.rule
}

// Common transformation operations as helper functions.

// SetOp creates a set operation.
func SetOp(target string, value interface{}) Operation {
	return Operation{Type: "set", Target: target, Value: value}
}

// DeleteOp creates a delete operation.
func DeleteOp(target string) Operation {
	return Operation{Type: "delete", Target: target}
}

// CopyOp creates a copy operation.
func CopyOp(source, target string) Operation {
	return Operation{Type: "copy", Source: source, Target: target}
}

// RenameOp creates a rename operation.
func RenameOp(source, target string) Operation {
	return Operation{Type: "rename", Source: source, Target: target}
}

// MapOp creates a map operation.
func MapOp(source, target string, mapping map[string]interface{}) Operation {
	return Operation{Type: "map", Source: source, Target: target, Mapping: mapping}
}

// TemplateOp creates a template operation.
func TemplateOp(target, template string) Operation {
	return Operation{Type: "template", Target: target, Template: template}
}

// ExtractOp creates an extract operation.
func ExtractOp(source, target, pattern string) Operation {
	return Operation{Type: "extract", Source: source, Target: target, Value: pattern}
}

// ConditionalOp wraps an operation with a condition.
func ConditionalOp(condition string, op Operation) Operation {
	op.Condition = condition
	return op
}
