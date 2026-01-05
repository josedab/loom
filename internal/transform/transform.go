// Package transform provides a DSL for request/response transformations.
package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// Operation represents a single transformation operation.
type Operation struct {
	// Type of operation: set, delete, rename, copy, map, template, extract
	Type string `json:"type" yaml:"type"`
	// Source path for the value (JSONPath-like syntax)
	Source string `json:"source,omitempty" yaml:"source,omitempty"`
	// Target path where to apply the result
	Target string `json:"target,omitempty" yaml:"target,omitempty"`
	// Value for set operations (can be template)
	Value interface{} `json:"value,omitempty" yaml:"value,omitempty"`
	// Condition to apply this operation (CEL expression)
	Condition string `json:"condition,omitempty" yaml:"condition,omitempty"`
	// Template for template operations
	Template string `json:"template,omitempty" yaml:"template,omitempty"`
	// Mapping for map operations
	Mapping map[string]interface{} `json:"mapping,omitempty" yaml:"mapping,omitempty"`
}

// Rule represents a transformation rule with multiple operations.
type Rule struct {
	// Name identifies the rule
	Name string `json:"name" yaml:"name"`
	// Match criteria for when to apply this rule
	Match Match `json:"match,omitempty" yaml:"match,omitempty"`
	// Operations to apply in order
	Request  []Operation `json:"request,omitempty" yaml:"request,omitempty"`
	Response []Operation `json:"response,omitempty" yaml:"response,omitempty"`
}

// Match specifies when a rule should be applied.
type Match struct {
	// Path patterns (glob-style)
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	// Methods to match (GET, POST, etc.)
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	// Headers that must be present
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

// Context provides data available during transformations.
type Context struct {
	// Headers of the request/response
	Headers map[string][]string
	// Body as parsed JSON (if applicable)
	Body map[string]interface{}
	// Path parameters extracted from URL
	PathParams map[string]string
	// Query parameters
	QueryParams map[string][]string
	// Status code (for responses)
	StatusCode int
	// Method of the request
	Method string
	// Path of the request
	Path string
	// Custom variables set during transformation
	Variables map[string]interface{}
}

// Transformer applies transformation rules.
type Transformer struct {
	rules     []Rule
	templates map[string]*template.Template
}

// New creates a new Transformer with the given rules.
func New(rules []Rule) (*Transformer, error) {
	t := &Transformer{
		rules:     rules,
		templates: make(map[string]*template.Template),
	}

	// Pre-compile templates
	for i, rule := range rules {
		for j, op := range rule.Request {
			if op.Template != "" {
				tmpl, err := template.New(fmt.Sprintf("req_%d_%d", i, j)).
					Funcs(templateFuncs()).
					Parse(op.Template)
				if err != nil {
					return nil, fmt.Errorf("parsing template for rule %s: %w", rule.Name, err)
				}
				t.templates[fmt.Sprintf("req_%d_%d", i, j)] = tmpl
			}
		}
		for j, op := range rule.Response {
			if op.Template != "" {
				tmpl, err := template.New(fmt.Sprintf("resp_%d_%d", i, j)).
					Funcs(templateFuncs()).
					Parse(op.Template)
				if err != nil {
					return nil, fmt.Errorf("parsing template for rule %s: %w", rule.Name, err)
				}
				t.templates[fmt.Sprintf("resp_%d_%d", i, j)] = tmpl
			}
		}
	}

	return t, nil
}

// TransformRequest applies request transformations.
func (t *Transformer) TransformRequest(ctx *Context) error {
	for i, rule := range t.rules {
		if !t.matchesRule(ctx, rule.Match) {
			continue
		}
		for j, op := range rule.Request {
			if err := t.applyOperation(ctx, op, fmt.Sprintf("req_%d_%d", i, j)); err != nil {
				return fmt.Errorf("rule %s op %d: %w", rule.Name, j, err)
			}
		}
	}
	return nil
}

// TransformResponse applies response transformations.
func (t *Transformer) TransformResponse(ctx *Context) error {
	for i, rule := range t.rules {
		if !t.matchesRule(ctx, rule.Match) {
			continue
		}
		for j, op := range rule.Response {
			if err := t.applyOperation(ctx, op, fmt.Sprintf("resp_%d_%d", i, j)); err != nil {
				return fmt.Errorf("rule %s op %d: %w", rule.Name, j, err)
			}
		}
	}
	return nil
}

// matchesRule checks if the context matches the rule's criteria.
func (t *Transformer) matchesRule(ctx *Context, match Match) bool {
	// Check path patterns
	if len(match.Paths) > 0 {
		matched := false
		for _, pattern := range match.Paths {
			if matchPath(ctx.Path, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check methods
	if len(match.Methods) > 0 {
		matched := false
		for _, method := range match.Methods {
			if strings.EqualFold(ctx.Method, method) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check headers
	for key, value := range match.Headers {
		headerValues := ctx.Headers[key]
		if len(headerValues) == 0 {
			return false
		}
		if value != "" && value != "*" {
			found := false
			for _, hv := range headerValues {
				if hv == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// applyOperation executes a single transformation operation.
func (t *Transformer) applyOperation(ctx *Context, op Operation, tmplKey string) error {
	// Check condition if present
	if op.Condition != "" {
		match, err := evaluateCondition(ctx, op.Condition)
		if err != nil {
			return fmt.Errorf("evaluating condition: %w", err)
		}
		if !match {
			return nil
		}
	}

	switch op.Type {
	case "set":
		return t.opSet(ctx, op, tmplKey)
	case "delete":
		return t.opDelete(ctx, op)
	case "rename":
		return t.opRename(ctx, op)
	case "copy":
		return t.opCopy(ctx, op)
	case "map":
		return t.opMap(ctx, op)
	case "template":
		return t.opTemplate(ctx, op, tmplKey)
	case "extract":
		return t.opExtract(ctx, op)
	case "merge":
		return t.opMerge(ctx, op)
	default:
		return fmt.Errorf("unknown operation type: %s", op.Type)
	}
}

// opSet sets a value at the target path.
func (t *Transformer) opSet(ctx *Context, op Operation, tmplKey string) error {
	value := op.Value

	// If value is a template string, process it
	if strVal, ok := value.(string); ok && strings.Contains(strVal, "{{") {
		result, err := t.processTemplate(ctx, strVal, tmplKey)
		if err != nil {
			return err
		}
		value = result
	}

	return setPath(ctx, op.Target, value)
}

// opDelete removes a value at the target path.
func (t *Transformer) opDelete(ctx *Context, op Operation) error {
	return deletePath(ctx, op.Target)
}

// opRename moves a value from source to target.
func (t *Transformer) opRename(ctx *Context, op Operation) error {
	value, err := getPath(ctx, op.Source)
	if err != nil {
		return nil // Source doesn't exist, nothing to rename
	}

	if err := setPath(ctx, op.Target, value); err != nil {
		return err
	}

	return deletePath(ctx, op.Source)
}

// opCopy copies a value from source to target.
func (t *Transformer) opCopy(ctx *Context, op Operation) error {
	value, err := getPath(ctx, op.Source)
	if err != nil {
		return nil // Source doesn't exist, nothing to copy
	}

	return setPath(ctx, op.Target, value)
}

// opMap maps a source value using a mapping table.
func (t *Transformer) opMap(ctx *Context, op Operation) error {
	value, err := getPath(ctx, op.Source)
	if err != nil {
		return nil // Source doesn't exist
	}

	key := fmt.Sprintf("%v", value)
	if mapped, ok := op.Mapping[key]; ok {
		return setPath(ctx, op.Target, mapped)
	}

	// Check for default
	if def, ok := op.Mapping["_default"]; ok {
		return setPath(ctx, op.Target, def)
	}

	return nil
}

// opTemplate applies a Go template.
func (t *Transformer) opTemplate(ctx *Context, op Operation, tmplKey string) error {
	tmpl, ok := t.templates[tmplKey]
	if !ok {
		return fmt.Errorf("template not found: %s", tmplKey)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	return setPath(ctx, op.Target, buf.String())
}

// opExtract extracts a value using a regex.
func (t *Transformer) opExtract(ctx *Context, op Operation) error {
	value, err := getPath(ctx, op.Source)
	if err != nil {
		return nil
	}

	strVal, ok := value.(string)
	if !ok {
		return nil
	}

	pattern, ok := op.Value.(string)
	if !ok {
		return fmt.Errorf("extract requires string pattern")
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}

	matches := re.FindStringSubmatch(strVal)
	if len(matches) > 1 {
		return setPath(ctx, op.Target, matches[1])
	} else if len(matches) == 1 {
		return setPath(ctx, op.Target, matches[0])
	}

	return nil
}

// opMerge merges source object into target.
func (t *Transformer) opMerge(ctx *Context, op Operation) error {
	source, err := getPath(ctx, op.Source)
	if err != nil {
		return nil
	}

	sourceMap, ok := source.(map[string]interface{})
	if !ok {
		return nil
	}

	target, _ := getPath(ctx, op.Target)
	targetMap, ok := target.(map[string]interface{})
	if !ok {
		targetMap = make(map[string]interface{})
	}

	for k, v := range sourceMap {
		targetMap[k] = v
	}

	return setPath(ctx, op.Target, targetMap)
}

// processTemplate processes an inline template string.
func (t *Transformer) processTemplate(ctx *Context, tmplStr string, key string) (string, error) {
	tmpl, err := template.New(key + "_inline").Funcs(templateFuncs()).Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// Path operations using JSONPath-like syntax.

// getPath retrieves a value from the context using a path.
// Paths: "body.field.nested", "headers.Content-Type", "query.page"
func getPath(ctx *Context, path string) (interface{}, error) {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty path")
	}

	var root interface{}
	remainder := ""

	switch parts[0] {
	case "body":
		root = ctx.Body
		if len(parts) > 1 {
			remainder = parts[1]
		}
	case "headers":
		if len(parts) < 2 {
			return ctx.Headers, nil
		}
		values := ctx.Headers[parts[1]]
		if len(values) == 0 {
			return nil, fmt.Errorf("header not found: %s", parts[1])
		}
		return values[0], nil
	case "query":
		if len(parts) < 2 {
			return ctx.QueryParams, nil
		}
		values := ctx.QueryParams[parts[1]]
		if len(values) == 0 {
			return nil, fmt.Errorf("query param not found: %s", parts[1])
		}
		return values[0], nil
	case "path":
		if len(parts) < 2 {
			return ctx.Path, nil
		}
		value, ok := ctx.PathParams[parts[1]]
		if !ok {
			return nil, fmt.Errorf("path param not found: %s", parts[1])
		}
		return value, nil
	case "var":
		if len(parts) < 2 {
			return ctx.Variables, nil
		}
		value, ok := ctx.Variables[parts[1]]
		if !ok {
			return nil, fmt.Errorf("variable not found: %s", parts[1])
		}
		return value, nil
	case "status":
		return ctx.StatusCode, nil
	case "method":
		return ctx.Method, nil
	default:
		return nil, fmt.Errorf("unknown path root: %s", parts[0])
	}

	if remainder == "" {
		return root, nil
	}

	return getNestedValue(root, remainder)
}

// getNestedValue retrieves a nested value from a map/slice.
func getNestedValue(data interface{}, path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, fmt.Errorf("key not found: %s", part)
			}
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", part)
			}
			if idx < 0 || idx >= len(v) {
				return nil, fmt.Errorf("index out of bounds: %d", idx)
			}
			current = v[idx]
		default:
			return nil, fmt.Errorf("cannot traverse into %T", current)
		}
	}

	return current, nil
}

// setPath sets a value in the context at the given path.
func setPath(ctx *Context, path string, value interface{}) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}

	switch parts[0] {
	case "body":
		if len(parts) == 1 {
			if m, ok := value.(map[string]interface{}); ok {
				ctx.Body = m
			}
			return nil
		}
		if ctx.Body == nil {
			ctx.Body = make(map[string]interface{})
		}
		return setNestedValue(ctx.Body, parts[1], value)
	case "headers":
		if len(parts) < 2 {
			return fmt.Errorf("header path requires header name")
		}
		if ctx.Headers == nil {
			ctx.Headers = make(map[string][]string)
		}
		ctx.Headers[parts[1]] = []string{fmt.Sprintf("%v", value)}
		return nil
	case "query":
		if len(parts) < 2 {
			return fmt.Errorf("query path requires param name")
		}
		if ctx.QueryParams == nil {
			ctx.QueryParams = make(map[string][]string)
		}
		ctx.QueryParams[parts[1]] = []string{fmt.Sprintf("%v", value)}
		return nil
	case "var":
		if len(parts) < 2 {
			return fmt.Errorf("var path requires variable name")
		}
		if ctx.Variables == nil {
			ctx.Variables = make(map[string]interface{})
		}
		ctx.Variables[parts[1]] = value
		return nil
	case "status":
		if code, ok := value.(int); ok {
			ctx.StatusCode = code
		} else if codeStr, ok := value.(string); ok {
			if code, err := strconv.Atoi(codeStr); err == nil {
				ctx.StatusCode = code
			}
		}
		return nil
	default:
		return fmt.Errorf("cannot set path root: %s", parts[0])
	}
}

// setNestedValue sets a nested value in a map.
func setNestedValue(data map[string]interface{}, path string, value interface{}) error {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts[:len(parts)-1] {
		next, ok := current[part]
		if !ok {
			// Create intermediate maps
			newMap := make(map[string]interface{})
			current[part] = newMap
			current = newMap
		} else {
			nextMap, ok := next.(map[string]interface{})
			if !ok {
				return fmt.Errorf("cannot traverse through %T at %s", next, strings.Join(parts[:i+1], "."))
			}
			current = nextMap
		}
	}

	current[parts[len(parts)-1]] = value
	return nil
}

// deletePath removes a value from the context.
func deletePath(ctx *Context, path string) error {
	parts := strings.SplitN(path, ".", 2)
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}

	switch parts[0] {
	case "body":
		if len(parts) == 1 {
			ctx.Body = nil
			return nil
		}
		return deleteNestedValue(ctx.Body, parts[1])
	case "headers":
		if len(parts) < 2 {
			return fmt.Errorf("header path requires header name")
		}
		delete(ctx.Headers, parts[1])
		return nil
	case "query":
		if len(parts) < 2 {
			return fmt.Errorf("query path requires param name")
		}
		delete(ctx.QueryParams, parts[1])
		return nil
	case "var":
		if len(parts) < 2 {
			return fmt.Errorf("var path requires variable name")
		}
		delete(ctx.Variables, parts[1])
		return nil
	default:
		return fmt.Errorf("cannot delete path root: %s", parts[0])
	}
}

// deleteNestedValue removes a nested value from a map.
func deleteNestedValue(data map[string]interface{}, path string) error {
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part]
		if !ok {
			return nil // Path doesn't exist
		}
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil // Can't traverse
		}
		current = nextMap
	}

	delete(current, parts[len(parts)-1])
	return nil
}

// matchPath matches a path against a glob pattern.
func matchPath(path, pattern string) bool {
	// Simple glob matching
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}

// evaluateCondition evaluates a simple condition expression.
// Supports: "body.field == value", "headers.X-Test exists", "status >= 400"
func evaluateCondition(ctx *Context, condition string) (bool, error) {
	condition = strings.TrimSpace(condition)

	// Check for "not exists" first (more specific)
	if strings.HasSuffix(condition, " not exists") {
		path := strings.TrimSuffix(condition, " not exists")
		_, err := getPath(ctx, strings.TrimSpace(path))
		return err != nil, nil
	}

	// Check for "exists"
	if strings.HasSuffix(condition, " exists") {
		path := strings.TrimSuffix(condition, " exists")
		_, err := getPath(ctx, strings.TrimSpace(path))
		return err == nil, nil
	}

	// Parse comparison operators
	operators := []string{"==", "!=", ">=", "<=", ">", "<", "contains", "matches"}
	for _, op := range operators {
		if strings.Contains(condition, " "+op+" ") {
			parts := strings.SplitN(condition, " "+op+" ", 2)
			if len(parts) != 2 {
				continue
			}

			leftPath := strings.TrimSpace(parts[0])
			rightVal := strings.TrimSpace(parts[1])

			left, err := getPath(ctx, leftPath)
			if err != nil {
				return false, nil // Path doesn't exist, condition fails
			}

			return compareValues(left, rightVal, op)
		}
	}

	return false, fmt.Errorf("invalid condition: %s", condition)
}

// compareValues compares two values with an operator.
func compareValues(left interface{}, right string, op string) (bool, error) {
	// Handle string comparison
	leftStr := fmt.Sprintf("%v", left)
	right = strings.Trim(right, `"'`)

	switch op {
	case "==":
		return leftStr == right, nil
	case "!=":
		return leftStr != right, nil
	case "contains":
		return strings.Contains(leftStr, right), nil
	case "matches":
		re, err := regexp.Compile(right)
		if err != nil {
			return false, err
		}
		return re.MatchString(leftStr), nil
	}

	// Numeric comparisons
	leftNum, err1 := strconv.ParseFloat(leftStr, 64)
	rightNum, err2 := strconv.ParseFloat(right, 64)
	if err1 != nil || err2 != nil {
		return false, nil // Non-numeric comparison
	}

	switch op {
	case ">":
		return leftNum > rightNum, nil
	case "<":
		return leftNum < rightNum, nil
	case ">=":
		return leftNum >= rightNum, nil
	case "<=":
		return leftNum <= rightNum, nil
	}

	return false, nil
}

// Template functions available in transformations.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"json": func(v interface{}) string {
			b, _ := json.Marshal(v)
			return string(b)
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"trim":  strings.TrimSpace,
		"split": strings.Split,
		"join":  strings.Join,
		"default": func(def, val interface{}) interface{} {
			if val == nil || val == "" {
				return def
			}
			return val
		},
		"concat": func(vals ...string) string {
			return strings.Join(vals, "")
		},
		"replace": strings.ReplaceAll,
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"toInt": func(s string) int {
			i, _ := strconv.Atoi(s)
			return i
		},
		"toString": func(v interface{}) string {
			return fmt.Sprintf("%v", v)
		},
	}
}

// MarshalBody serializes the Body map to JSON bytes.
func (ctx *Context) MarshalBody() ([]byte, error) {
	if ctx.Body == nil {
		return nil, nil
	}
	return json.Marshal(ctx.Body)
}

// UnmarshalBody parses JSON bytes into the Body map.
func (ctx *Context) UnmarshalBody(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &ctx.Body)
}
