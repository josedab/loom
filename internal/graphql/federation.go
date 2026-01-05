// Package graphql provides GraphQL Federation gateway functionality.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Federation implements a GraphQL Federation gateway.
type Federation struct {
	// subgraphs is a map of service name to subgraph configuration
	subgraphs map[string]*Subgraph
	// schema is the composed supergraph schema
	schema *Schema
	// planner generates query plans
	planner *QueryPlanner
	// executor executes query plans
	executor *Executor
	// httpClient for subgraph requests
	httpClient *http.Client
	// logger for federation events
	logger *slog.Logger
	mu     sync.RWMutex
}

// Subgraph represents a federated GraphQL subgraph.
type Subgraph struct {
	// Name identifies the subgraph
	Name string `json:"name" yaml:"name"`
	// URL is the GraphQL endpoint
	URL string `json:"url" yaml:"url"`
	// Schema is the subgraph's SDL
	Schema string `json:"schema,omitempty" yaml:"schema,omitempty"`
	// Types maps type names to their entity definitions
	Types map[string]*TypeDefinition `json:"-"`
	// Headers to include in requests
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	// Timeout for requests
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// TypeDefinition describes a GraphQL type in a subgraph.
type TypeDefinition struct {
	// Name of the type
	Name string
	// KeyFields for entity resolution (@key directive)
	KeyFields []string
	// Extends indicates this type extends another subgraph's type
	Extends bool
	// ExternalFields are fields from other subgraphs
	ExternalFields []string
	// ProvidedFields are fields provided when resolving the entity
	ProvidedFields []string
	// Fields defined in this subgraph
	Fields map[string]*FieldDefinition
	// Subgraph that owns this type
	Owner string
}

// FieldDefinition describes a GraphQL field.
type FieldDefinition struct {
	Name       string
	Type       string
	Arguments  []ArgumentDefinition
	External   bool
	Requires   []string
	Provides   []string
	Deprecated string
}

// ArgumentDefinition describes a GraphQL argument.
type ArgumentDefinition struct {
	Name    string
	Type    string
	Default interface{}
}

// Schema represents the composed supergraph schema.
type Schema struct {
	// Types maps type names to definitions
	Types map[string]*TypeDefinition
	// QueryType is the name of the query type
	QueryType string
	// MutationType is the name of the mutation type
	MutationType string
	// SubscriptionType is the name of the subscription type
	SubscriptionType string
	// Subgraphs contributing to this schema
	Subgraphs []string
}

// Config configures the federation gateway.
type Config struct {
	// Subgraphs to federate
	Subgraphs []Subgraph `json:"subgraphs" yaml:"subgraphs"`
	// Timeout for subgraph requests
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// Logger for events
	Logger *slog.Logger
}

// New creates a new Federation gateway.
func New(cfg Config) (*Federation, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	f := &Federation{
		subgraphs: make(map[string]*Subgraph),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: cfg.Logger,
	}

	// Register subgraphs
	for i := range cfg.Subgraphs {
		sg := &cfg.Subgraphs[i]
		if sg.Timeout == 0 {
			sg.Timeout = cfg.Timeout
		}
		sg.Types = make(map[string]*TypeDefinition)
		f.subgraphs[sg.Name] = sg
	}

	// Compose schema
	schema, err := f.composeSchema()
	if err != nil {
		return nil, fmt.Errorf("composing schema: %w", err)
	}
	f.schema = schema

	// Create planner and executor
	f.planner = NewQueryPlanner(f.schema, f.subgraphs)
	f.executor = NewExecutor(f.subgraphs, f.httpClient, f.logger)

	return f, nil
}

// RegisterSubgraph adds or updates a subgraph.
func (f *Federation) RegisterSubgraph(sg *Subgraph) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if sg.Types == nil {
		sg.Types = make(map[string]*TypeDefinition)
	}

	f.subgraphs[sg.Name] = sg

	// Recompose schema
	schema, err := f.composeSchema()
	if err != nil {
		return fmt.Errorf("recomposing schema: %w", err)
	}
	f.schema = schema
	f.planner = NewQueryPlanner(f.schema, f.subgraphs)

	return nil
}

// Handler returns an HTTP handler for the federation gateway.
func (f *Federation) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// Introspection or playground
			f.handleIntrospection(w, r)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse GraphQL request
		var req GraphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.logger.Debug("failed to parse request", "error", err)
			writeGraphQLError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Execute query
		result := f.Execute(r.Context(), req)

		// Write response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// Execute executes a GraphQL query.
func (f *Federation) Execute(ctx context.Context, req GraphQLRequest) *GraphQLResponse {
	// Parse the query
	doc, err := ParseQuery(req.Query)
	if err != nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: fmt.Sprintf("Parse error: %v", err)}},
		}
	}

	// Generate query plan
	plan, err := f.planner.Plan(doc, req.OperationName, req.Variables)
	if err != nil {
		return &GraphQLResponse{
			Errors: []GraphQLError{{Message: fmt.Sprintf("Planning error: %v", err)}},
		}
	}

	// Execute the plan
	data, errs := f.executor.Execute(ctx, plan)

	return &GraphQLResponse{
		Data:   data,
		Errors: errs,
	}
}

// composeSchema merges all subgraph schemas into a supergraph.
func (f *Federation) composeSchema() (*Schema, error) {
	schema := &Schema{
		Types:     make(map[string]*TypeDefinition),
		QueryType: "Query",
		Subgraphs: make([]string, 0, len(f.subgraphs)),
	}

	for name, sg := range f.subgraphs {
		schema.Subgraphs = append(schema.Subgraphs, name)

		// Parse and merge subgraph schema
		types, err := parseSchemaTypes(sg.Schema, name)
		if err != nil {
			f.logger.Debug("failed to parse subgraph schema", "subgraph", name, "error", err)
			// Continue with other subgraphs
			continue
		}

		for typeName, typeDef := range types {
			sg.Types[typeName] = typeDef

			if existing, ok := schema.Types[typeName]; ok {
				// Merge type definitions
				mergeTypeDefinitions(existing, typeDef)
			} else {
				schema.Types[typeName] = typeDef
			}
		}
	}

	return schema, nil
}

// parseSchemaTypes parses a GraphQL SDL and extracts type definitions.
func parseSchemaTypes(sdl string, owner string) (map[string]*TypeDefinition, error) {
	types := make(map[string]*TypeDefinition)

	if sdl == "" {
		return types, nil
	}

	// Simple SDL parser - in production, use a proper GraphQL parser
	lines := strings.Split(sdl, "\n")
	var currentType *TypeDefinition
	inType := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "extend type ") {
			// Extract type name
			extends := strings.HasPrefix(line, "extend ")
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			nameIdx := 1
			if extends {
				nameIdx = 2
			}
			typeName := parts[nameIdx]

			currentType = &TypeDefinition{
				Name:    typeName,
				Fields:  make(map[string]*FieldDefinition),
				Owner:   owner,
				Extends: extends,
			}

			// Extract key fields from @key directive
			if keyMatch := extractDirective(line, "@key"); keyMatch != "" {
				currentType.KeyFields = extractFieldsFromDirective(keyMatch)
			}

			types[typeName] = currentType
			inType = true
		} else if inType && line == "}" {
			inType = false
			currentType = nil
		} else if inType && currentType != nil && line != "" && !strings.HasPrefix(line, "#") {
			// Parse field
			field := parseField(line)
			if field != nil {
				currentType.Fields[field.Name] = field
				if field.External {
					currentType.ExternalFields = append(currentType.ExternalFields, field.Name)
				}
			}
		}
	}

	return types, nil
}

// parseField parses a GraphQL field definition.
func parseField(line string) *FieldDefinition {
	// Skip directives-only lines
	if strings.HasPrefix(line, "@") {
		return nil
	}

	// Extract field name and type
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return nil
	}

	name := strings.TrimSpace(parts[0])
	// Remove arguments
	if idx := strings.Index(name, "("); idx != -1 {
		name = strings.TrimSpace(name[:idx])
	}

	typePart := strings.TrimSpace(parts[1])
	// Remove directives
	if idx := strings.Index(typePart, "@"); idx != -1 {
		typePart = strings.TrimSpace(typePart[:idx])
	}

	field := &FieldDefinition{
		Name: name,
		Type: typePart,
	}

	// Check for @external directive
	if strings.Contains(line, "@external") {
		field.External = true
	}

	// Extract @requires
	if req := extractDirective(line, "@requires"); req != "" {
		field.Requires = extractFieldsFromDirective(req)
	}

	// Extract @provides
	if prov := extractDirective(line, "@provides"); prov != "" {
		field.Provides = extractFieldsFromDirective(prov)
	}

	return field
}

// extractDirective extracts a directive value from a line.
func extractDirective(line, directive string) string {
	idx := strings.Index(line, directive)
	if idx == -1 {
		return ""
	}

	// Find opening paren
	start := strings.Index(line[idx:], "(")
	if start == -1 {
		return ""
	}
	start += idx + 1

	// Find closing paren
	end := strings.Index(line[start:], ")")
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(line[start : start+end])
}

// extractFieldsFromDirective extracts field names from a directive argument.
func extractFieldsFromDirective(arg string) []string {
	// Handle: fields: "id name" or just "id name"
	arg = strings.TrimPrefix(arg, "fields:")
	arg = strings.Trim(arg, " \"'")
	return strings.Fields(arg)
}

// mergeTypeDefinitions merges two type definitions.
func mergeTypeDefinitions(existing, new *TypeDefinition) {
	// Merge fields
	for name, field := range new.Fields {
		if _, ok := existing.Fields[name]; !ok {
			existing.Fields[name] = field
		}
	}

	// Merge key fields
	for _, key := range new.KeyFields {
		found := false
		for _, existingKey := range existing.KeyFields {
			if key == existingKey {
				found = true
				break
			}
		}
		if !found {
			existing.KeyFields = append(existing.KeyFields, key)
		}
	}
}

func (f *Federation) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	// Return a simple schema for introspection
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"__schema": map[string]interface{}{
				"queryType":        map[string]string{"name": "Query"},
				"mutationType":     nil,
				"subscriptionType": nil,
				"types":            []interface{}{},
				"directives":       []interface{}{},
			},
		},
	})
}

// GraphQLRequest represents a GraphQL request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response.
type GraphQLResponse struct {
	Data   interface{}    `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message    string        `json:"message"`
	Locations  []Location    `json:"locations,omitempty"`
	Path       []interface{} `json:"path,omitempty"`
	Extensions interface{}   `json:"extensions,omitempty"`
}

// Location represents a location in a GraphQL document.
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// writeGraphQLError writes a GraphQL error response.
func writeGraphQLError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(GraphQLResponse{
		Errors: []GraphQLError{{Message: message}},
	})
}

// Document represents a parsed GraphQL document.
type Document struct {
	Operations []*Operation
	Fragments  map[string]*Fragment
}

// Operation represents a GraphQL operation.
type Operation struct {
	Type          string // query, mutation, subscription
	Name          string
	SelectionSet  []*Selection
	Variables     []*VariableDefinition
	VariableTypes map[string]string
}

// Selection represents a field selection.
type Selection struct {
	Name         string
	Alias        string
	Arguments    map[string]interface{}
	SelectionSet []*Selection
	// For inline fragments
	TypeCondition string
	// For fragment spreads
	FragmentName string
}

// Fragment represents a GraphQL fragment.
type Fragment struct {
	Name          string
	TypeCondition string
	SelectionSet  []*Selection
}

// VariableDefinition represents a variable definition.
type VariableDefinition struct {
	Name    string
	Type    string
	Default interface{}
}

// ParseQuery parses a GraphQL query string into a Document.
func ParseQuery(query string) (*Document, error) {
	doc := &Document{
		Fragments: make(map[string]*Fragment),
	}

	// Simple parser - in production use a proper GraphQL parser
	query = strings.TrimSpace(query)

	// Find operation type
	opType := "query"
	if strings.HasPrefix(query, "mutation") {
		opType = "mutation"
	} else if strings.HasPrefix(query, "subscription") {
		opType = "subscription"
	}

	op := &Operation{
		Type:          opType,
		VariableTypes: make(map[string]string),
	}

	// Extract selection set (simplified)
	start := strings.Index(query, "{")
	if start == -1 {
		return nil, fmt.Errorf("no selection set found")
	}

	selectionStr := query[start:]
	selections, err := parseSelections(selectionStr)
	if err != nil {
		return nil, err
	}
	op.SelectionSet = selections

	doc.Operations = append(doc.Operations, op)

	return doc, nil
}

// parseSelections parses a selection set string.
func parseSelections(str string) ([]*Selection, error) {
	var selections []*Selection

	str = strings.TrimSpace(str)
	if !strings.HasPrefix(str, "{") || !strings.HasSuffix(str, "}") {
		return nil, fmt.Errorf("invalid selection set")
	}

	str = strings.TrimPrefix(str, "{")
	str = strings.TrimSuffix(str, "}")
	str = strings.TrimSpace(str)

	// Simple field extraction
	depth := 0
	current := ""

	for _, ch := range str {
		switch ch {
		case '{':
			depth++
			current += string(ch)
		case '}':
			depth--
			current += string(ch)
		case '\n', ' ':
			if depth > 0 {
				current += string(ch)
			} else if current != "" {
				sel := parseSelection(strings.TrimSpace(current))
				if sel != nil {
					selections = append(selections, sel)
				}
				current = ""
			}
		default:
			current += string(ch)
		}
	}

	if current != "" {
		sel := parseSelection(strings.TrimSpace(current))
		if sel != nil {
			selections = append(selections, sel)
		}
	}

	return selections, nil
}

// parseSelection parses a single selection.
func parseSelection(str string) *Selection {
	if str == "" {
		return nil
	}

	sel := &Selection{
		Arguments: make(map[string]interface{}),
	}

	// Check for nested selection set
	if idx := strings.Index(str, "{"); idx != -1 {
		nestedStr := str[idx:]
		str = strings.TrimSpace(str[:idx])

		nested, _ := parseSelections(nestedStr)
		sel.SelectionSet = nested
	}

	// Check for arguments
	if idx := strings.Index(str, "("); idx != -1 {
		endIdx := strings.Index(str, ")")
		if endIdx > idx {
			argsStr := str[idx+1 : endIdx]
			sel.Arguments = parseArguments(argsStr)
			str = strings.TrimSpace(str[:idx])
		}
	}

	// Check for alias
	if idx := strings.Index(str, ":"); idx != -1 {
		sel.Alias = strings.TrimSpace(str[:idx])
		str = strings.TrimSpace(str[idx+1:])
	}

	sel.Name = str

	return sel
}

// parseArguments parses argument string into a map.
func parseArguments(str string) map[string]interface{} {
	args := make(map[string]interface{})

	// Simple key: value parsing
	parts := strings.Split(str, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])

			// Handle variable references
			if strings.HasPrefix(val, "$") {
				args[key] = val
			} else if val == "true" {
				args[key] = true
			} else if val == "false" {
				args[key] = false
			} else if strings.HasPrefix(val, "\"") {
				args[key] = strings.Trim(val, "\"")
			} else {
				// Try to parse as number
				var num float64
				if _, err := fmt.Sscanf(val, "%f", &num); err == nil {
					args[key] = num
				} else {
					args[key] = val
				}
			}
		}
	}

	return args
}

// QueryPlanner generates execution plans for GraphQL queries.
type QueryPlanner struct {
	schema    *Schema
	subgraphs map[string]*Subgraph
}

// QueryPlan represents an execution plan for a GraphQL query.
type QueryPlan struct {
	// Fetch operations to execute
	Fetches []*FetchOperation
	// Parallel indicates if fetches can run in parallel
	Parallel bool
}

// FetchOperation represents a fetch to a single subgraph.
type FetchOperation struct {
	// Subgraph to fetch from
	Subgraph string
	// Query to send to the subgraph
	Query string
	// Variables for the query
	Variables map[string]interface{}
	// Path where to merge the result
	Path []string
	// Requires entities from a previous fetch
	Requires *EntityRequirement
	// Provides fields for later fetches
	Provides []string
}

// EntityRequirement specifies required entity data from a previous fetch.
type EntityRequirement struct {
	// Type of entity
	Type string
	// Fields needed for entity resolution
	KeyFields []string
}

// NewQueryPlanner creates a new query planner.
func NewQueryPlanner(schema *Schema, subgraphs map[string]*Subgraph) *QueryPlanner {
	return &QueryPlanner{
		schema:    schema,
		subgraphs: subgraphs,
	}
}

// Plan generates an execution plan for a GraphQL document.
func (p *QueryPlanner) Plan(doc *Document, opName string, variables map[string]interface{}) (*QueryPlan, error) {
	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("no operations in document")
	}

	op := doc.Operations[0]
	if opName != "" {
		for _, o := range doc.Operations {
			if o.Name == opName {
				op = o
				break
			}
		}
	}

	plan := &QueryPlan{
		Parallel: true,
	}

	// For each root field, determine which subgraph can resolve it
	for _, sel := range op.SelectionSet {
		fetch := p.planSelection(sel, "Query", variables)
		if fetch != nil {
			plan.Fetches = append(plan.Fetches, fetch)
		}
	}

	return plan, nil
}

// planSelection plans a single selection.
func (p *QueryPlanner) planSelection(sel *Selection, parentType string, variables map[string]interface{}) *FetchOperation {
	// Find which subgraph has this field
	for name, sg := range p.subgraphs {
		if typeDef, ok := sg.Types[parentType]; ok {
			if _, hasField := typeDef.Fields[sel.Name]; hasField {
				// Build query for this subgraph
				query := buildSubgraphQuery(sel)

				return &FetchOperation{
					Subgraph:  name,
					Query:     query,
					Variables: variables,
					Path:      []string{sel.Alias},
				}
			}
		}
	}

	// Field not found in any subgraph - use first available
	for name := range p.subgraphs {
		query := buildSubgraphQuery(sel)
		return &FetchOperation{
			Subgraph:  name,
			Query:     query,
			Variables: variables,
		}
	}

	return nil
}

// buildSubgraphQuery builds a GraphQL query string for a selection.
func buildSubgraphQuery(sel *Selection) string {
	var buf bytes.Buffer
	buf.WriteString("{ ")
	writeSelection(&buf, sel)
	buf.WriteString(" }")
	return buf.String()
}

func writeSelection(buf *bytes.Buffer, sel *Selection) {
	if sel.Alias != "" {
		buf.WriteString(sel.Alias)
		buf.WriteString(": ")
	}
	buf.WriteString(sel.Name)

	if len(sel.Arguments) > 0 {
		buf.WriteString("(")
		first := true
		for k, v := range sel.Arguments {
			if !first {
				buf.WriteString(", ")
			}
			first = false
			buf.WriteString(k)
			buf.WriteString(": ")
			writeValue(buf, v)
		}
		buf.WriteString(")")
	}

	if len(sel.SelectionSet) > 0 {
		buf.WriteString(" { ")
		for i, child := range sel.SelectionSet {
			if i > 0 {
				buf.WriteString(" ")
			}
			writeSelection(buf, child)
		}
		buf.WriteString(" }")
	}
}

func writeValue(buf *bytes.Buffer, v interface{}) {
	switch val := v.(type) {
	case string:
		if strings.HasPrefix(val, "$") {
			buf.WriteString(val)
		} else {
			buf.WriteString(`"`)
			buf.WriteString(val)
			buf.WriteString(`"`)
		}
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	default:
		buf.WriteString(fmt.Sprintf("%v", val))
	}
}

// Executor executes query plans against subgraphs.
type Executor struct {
	subgraphs  map[string]*Subgraph
	httpClient *http.Client
	logger     *slog.Logger
}

// NewExecutor creates a new query executor.
func NewExecutor(subgraphs map[string]*Subgraph, client *http.Client, logger *slog.Logger) *Executor {
	return &Executor{
		subgraphs:  subgraphs,
		httpClient: client,
		logger:     logger,
	}
}

// Execute executes a query plan.
func (e *Executor) Execute(ctx context.Context, plan *QueryPlan) (interface{}, []GraphQLError) {
	if len(plan.Fetches) == 0 {
		return nil, nil
	}

	var errs []GraphQLError

	if plan.Parallel && len(plan.Fetches) > 1 {
		return e.executeParallel(ctx, plan.Fetches)
	}

	// Sequential execution
	result := make(map[string]interface{})

	for _, fetch := range plan.Fetches {
		data, fetchErrs := e.executeFetch(ctx, fetch)
		errs = append(errs, fetchErrs...)

		// Merge result
		if data != nil {
			for k, v := range data {
				result[k] = v
			}
		}
	}

	return result, errs
}

// executeParallel executes fetches in parallel.
func (e *Executor) executeParallel(ctx context.Context, fetches []*FetchOperation) (interface{}, []GraphQLError) {
	type fetchResult struct {
		data map[string]interface{}
		errs []GraphQLError
	}

	results := make(chan fetchResult, len(fetches))

	for _, fetch := range fetches {
		go func(f *FetchOperation) {
			data, errs := e.executeFetch(ctx, f)
			results <- fetchResult{data: data, errs: errs}
		}(fetch)
	}

	merged := make(map[string]interface{})
	var allErrs []GraphQLError

	for i := 0; i < len(fetches); i++ {
		result := <-results
		allErrs = append(allErrs, result.errs...)

		if result.data != nil {
			for k, v := range result.data {
				merged[k] = v
			}
		}
	}

	return merged, allErrs
}

// executeFetch executes a single fetch operation.
func (e *Executor) executeFetch(ctx context.Context, fetch *FetchOperation) (map[string]interface{}, []GraphQLError) {
	sg, ok := e.subgraphs[fetch.Subgraph]
	if !ok {
		return nil, []GraphQLError{{Message: fmt.Sprintf("unknown subgraph: %s", fetch.Subgraph)}}
	}

	// Build request
	reqBody := GraphQLRequest{
		Query:     fetch.Query,
		Variables: fetch.Variables,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, []GraphQLError{{Message: fmt.Sprintf("marshal error: %v", err)}}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", sg.URL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, []GraphQLError{{Message: fmt.Sprintf("request error: %v", err)}}
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range sg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, []GraphQLError{{Message: fmt.Sprintf("fetch error: %v", err)}}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, []GraphQLError{{Message: fmt.Sprintf("read error: %v", err)}}
	}

	var result GraphQLResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, []GraphQLError{{Message: fmt.Sprintf("parse error: %v", err)}}
	}

	data, _ := result.Data.(map[string]interface{})

	return data, result.Errors
}
