// Package graphql provides GraphQL gateway capabilities including query analysis,
// depth limiting, complexity analysis, and schema management.
package graphql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrQueryTooDeep       = errors.New("query exceeds maximum depth")
	ErrQueryTooComplex    = errors.New("query exceeds maximum complexity")
	ErrQueryNotFound      = errors.New("persisted query not found")
	ErrInvalidQuery       = errors.New("invalid GraphQL query")
	ErrSchemaNotFound     = errors.New("schema not found")
	ErrFieldNotAllowed    = errors.New("field access not allowed")
	ErrIntrospectionBlock = errors.New("introspection queries are disabled")
)

// GatewayRequest represents a GraphQL request for the gateway.
type GatewayRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	Extensions    *GatewayExtensions     `json:"extensions,omitempty"`
}

// GatewayExtensions contains GraphQL request extensions.
type GatewayExtensions struct {
	PersistedQuery *PersistedQueryExtension `json:"persistedQuery,omitempty"`
}

// PersistedQueryExtension for Automatic Persisted Queries (APQ).
type PersistedQueryExtension struct {
	Version    int    `json:"version"`
	SHA256Hash string `json:"sha256Hash"`
}

// QueryAnalysis contains the results of analyzing a GraphQL query.
type QueryAnalysis struct {
	Depth           int
	Complexity      int
	Fields          []string
	Operations      []string
	Fragments       []string
	HasMutation     bool
	HasQuery        bool
	HasSubscription bool
	IsIntrospection bool
}

// GatewayConfig configures the GraphQL gateway.
type GatewayConfig struct {
	// MaxDepth is the maximum allowed query depth (0 = unlimited).
	MaxDepth int
	// MaxComplexity is the maximum allowed query complexity (0 = unlimited).
	MaxComplexity int
	// AllowIntrospection enables/disables introspection queries.
	AllowIntrospection bool
	// EnableAPQ enables Automatic Persisted Queries.
	EnableAPQ bool
	// APQCacheSize is the number of persisted queries to cache.
	APQCacheSize int
	// APQCacheTTL is how long to cache persisted queries.
	APQCacheTTL time.Duration
	// FieldComplexity maps field names to their complexity cost.
	FieldComplexity map[string]int
	// DefaultFieldComplexity is the default complexity for unlisted fields.
	DefaultFieldComplexity int
	// BlockedFields are fields that cannot be queried.
	BlockedFields []string
	// RateLimitPerOperation enables per-operation rate limiting.
	RateLimitPerOperation bool
	// Upstreams maps schema names to their upstream URLs.
	Upstreams map[string]string
}

// DefaultGatewayConfig returns a default GraphQL configuration.
func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		MaxDepth:               10,
		MaxComplexity:          1000,
		AllowIntrospection:     true,
		EnableAPQ:              true,
		APQCacheSize:           10000,
		APQCacheTTL:            24 * time.Hour,
		DefaultFieldComplexity: 1,
		FieldComplexity:        make(map[string]int),
		BlockedFields:          []string{},
		Upstreams:              make(map[string]string),
	}
}

// Gateway provides GraphQL gateway functionality.
type Gateway struct {
	config       GatewayConfig
	analyzer     *QueryAnalyzer
	apqCache     *APQCache
	schemaCache  *GatewaySchemaCache
	authorizer   FieldAuthorizer
	logger       *slog.Logger
	mu           sync.RWMutex
}

// NewGateway creates a new GraphQL gateway.
func NewGateway(config GatewayConfig, logger *slog.Logger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}

	g := &Gateway{
		config:      config,
		analyzer:    NewQueryAnalyzer(config),
		schemaCache: NewGatewaySchemaCache(),
		logger:      logger,
	}

	if config.EnableAPQ {
		g.apqCache = NewAPQCache(config.APQCacheSize, config.APQCacheTTL)
	}

	return g
}

// SetAuthorizer sets the field-level authorizer.
func (g *Gateway) SetAuthorizer(auth FieldAuthorizer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.authorizer = auth
}

// ProcessRequest processes a GraphQL request.
func (g *Gateway) ProcessRequest(ctx context.Context, req *GatewayRequest) (*GatewayRequest, *QueryAnalysis, error) {
	// Handle APQ
	if g.config.EnableAPQ && req.Extensions != nil && req.Extensions.PersistedQuery != nil {
		processedReq, err := g.handleAPQ(req)
		if err != nil {
			return nil, nil, err
		}
		req = processedReq
	}

	if req.Query == "" {
		return nil, nil, ErrInvalidQuery
	}

	// Analyze the query
	analysis, err := g.analyzer.Analyze(req.Query)
	if err != nil {
		return nil, nil, fmt.Errorf("query analysis failed: %w", err)
	}

	// Check introspection
	if analysis.IsIntrospection && !g.config.AllowIntrospection {
		return nil, nil, ErrIntrospectionBlock
	}

	// Check depth
	if g.config.MaxDepth > 0 && analysis.Depth > g.config.MaxDepth {
		return nil, analysis, ErrQueryTooDeep
	}

	// Check complexity
	if g.config.MaxComplexity > 0 && analysis.Complexity > g.config.MaxComplexity {
		return nil, analysis, ErrQueryTooComplex
	}

	// Check blocked fields
	for _, field := range analysis.Fields {
		for _, blocked := range g.config.BlockedFields {
			if matchField(field, blocked) {
				return nil, analysis, fmt.Errorf("%w: %s", ErrFieldNotAllowed, field)
			}
		}
	}

	// Check field authorization
	g.mu.RLock()
	authorizer := g.authorizer
	g.mu.RUnlock()

	if authorizer != nil {
		for _, field := range analysis.Fields {
			if !authorizer.CanAccessField(ctx, field) {
				return nil, analysis, fmt.Errorf("%w: %s", ErrFieldNotAllowed, field)
			}
		}
	}

	return req, analysis, nil
}

func (g *Gateway) handleAPQ(req *GatewayRequest) (*GatewayRequest, error) {
	ext := req.Extensions.PersistedQuery

	if req.Query == "" {
		// Try to get from cache
		query, found := g.apqCache.Get(ext.SHA256Hash)
		if !found {
			return nil, ErrQueryNotFound
		}
		req.Query = query
		return req, nil
	}

	// Verify hash matches
	hash := sha256.Sum256([]byte(req.Query))
	hashStr := hex.EncodeToString(hash[:])
	if hashStr != ext.SHA256Hash {
		return nil, ErrInvalidQuery
	}

	// Store in cache
	g.apqCache.Set(ext.SHA256Hash, req.Query)

	return req, nil
}

// QueryAnalyzer analyzes GraphQL queries.
type QueryAnalyzer struct {
	config           GatewayConfig
	fieldPattern     *regexp.Regexp
	fragmentPattern  *regexp.Regexp
	operationPattern *regexp.Regexp
}

// NewQueryAnalyzer creates a new query analyzer.
func NewQueryAnalyzer(config GatewayConfig) *QueryAnalyzer {
	return &QueryAnalyzer{
		config:           config,
		fieldPattern:     regexp.MustCompile(`(\w+)\s*(?:\([^)]*\))?\s*\{`),
		fragmentPattern:  regexp.MustCompile(`fragment\s+(\w+)\s+on\s+(\w+)`),
		operationPattern: regexp.MustCompile(`(query|mutation|subscription)\s*(\w*)`),
	}
}

// Analyze analyzes a GraphQL query and returns analysis results.
func (a *QueryAnalyzer) Analyze(query string) (*QueryAnalysis, error) {
	analysis := &QueryAnalysis{
		Fields:     []string{},
		Operations: []string{},
		Fragments:  []string{},
	}

	// Remove comments
	query = removeComments(query)

	// Detect operations
	opMatches := a.operationPattern.FindAllStringSubmatch(query, -1)
	for _, match := range opMatches {
		if len(match) >= 2 {
			opType := match[1]
			analysis.Operations = append(analysis.Operations, opType)
			switch opType {
			case "query":
				analysis.HasQuery = true
			case "mutation":
				analysis.HasMutation = true
			case "subscription":
				analysis.HasSubscription = true
			}
		}
	}

	// If no explicit operation, it's a query
	if len(analysis.Operations) == 0 && strings.Contains(query, "{") {
		analysis.HasQuery = true
	}

	// Detect fragments
	fragMatches := a.fragmentPattern.FindAllStringSubmatch(query, -1)
	for _, match := range fragMatches {
		if len(match) >= 2 {
			analysis.Fragments = append(analysis.Fragments, match[1])
		}
	}

	// Calculate depth and extract fields
	analysis.Depth = calculateDepth(query)
	analysis.Fields = extractFields(query)
	analysis.Complexity = a.calculateComplexity(analysis.Fields)

	// Check for introspection
	analysis.IsIntrospection = isIntrospectionQuery(query)

	return analysis, nil
}

func (a *QueryAnalyzer) calculateComplexity(fields []string) int {
	complexity := 0
	for _, field := range fields {
		if cost, ok := a.config.FieldComplexity[field]; ok {
			complexity += cost
		} else {
			complexity += a.config.DefaultFieldComplexity
		}
	}
	return complexity
}

func removeComments(query string) string {
	// Remove single-line comments
	lines := strings.Split(query, "\n")
	var result []string
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

func calculateDepth(query string) int {
	maxDepth := 0
	currentDepth := 0

	for _, char := range query {
		switch char {
		case '{':
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		case '}':
			currentDepth--
		}
	}

	return maxDepth
}

func extractFields(query string) []string {
	fields := []string{}

	// Track the path for nested fields
	var path []string

	tokens := tokenize(query)
	for i, token := range tokens {
		switch token {
		case "{":
			// depth increased handled in next iteration
		case "}":
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		default:
			if isFieldName(token) && (i+1 >= len(tokens) || tokens[i+1] == "{" || tokens[i+1] == "}" || isFieldName(tokens[i+1])) {
				fullPath := token
				if len(path) > 0 {
					fullPath = strings.Join(append(path, token), ".")
				}
				fields = append(fields, fullPath)

				// If next token is {, add to path
				if i+1 < len(tokens) && tokens[i+1] == "{" {
					path = append(path, token)
				}
			}
		}
	}

	return fields
}

func tokenize(query string) []string {
	var tokens []string
	var current strings.Builder

	for _, char := range query {
		switch char {
		case '{', '}', '(', ')', ':', ',', '\n', '\r', '\t', ' ':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			if char == '{' || char == '}' {
				tokens = append(tokens, string(char))
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

func isFieldName(token string) bool {
	if token == "" || token == "{" || token == "}" {
		return false
	}
	// Skip keywords
	keywords := []string{"query", "mutation", "subscription", "fragment", "on", "true", "false", "null"}
	for _, kw := range keywords {
		if token == kw {
			return false
		}
	}
	// Skip if starts with $
	if strings.HasPrefix(token, "$") {
		return false
	}
	// Must start with letter or underscore
	if len(token) > 0 {
		first := token[0]
		return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_'
	}
	return false
}

func isIntrospectionQuery(query string) bool {
	introspectionFields := []string{"__schema", "__type", "__typename"}
	queryLower := strings.ToLower(query)
	for _, field := range introspectionFields {
		if strings.Contains(queryLower, strings.ToLower(field)) {
			return true
		}
	}
	return false
}

func matchField(field, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		return strings.HasPrefix(field, prefix+".")
	}
	return field == pattern
}

// APQCache caches persisted queries.
type APQCache struct {
	cache   map[string]*apqEntry
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type apqEntry struct {
	query     string
	expiresAt time.Time
}

// NewAPQCache creates a new APQ cache.
func NewAPQCache(maxSize int, ttl time.Duration) *APQCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	cache := &APQCache{
		cache:   make(map[string]*apqEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a query from the cache.
func (c *APQCache) Get(hash string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[hash]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.query, true
}

// Set stores a query in the cache.
func (c *APQCache) Set(hash, query string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[hash] = &apqEntry{
		query:     query,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *APQCache) evictOldest() {
	var oldestHash string
	var oldestTime time.Time

	for hash, entry := range c.cache {
		if oldestHash == "" || entry.expiresAt.Before(oldestTime) {
			oldestHash = hash
			oldestTime = entry.expiresAt
		}
	}

	if oldestHash != "" {
		delete(c.cache, oldestHash)
	}
}

func (c *APQCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for hash, entry := range c.cache {
			if now.After(entry.expiresAt) {
				delete(c.cache, hash)
			}
		}
		c.mu.Unlock()
	}
}

// Size returns the number of cached queries.
func (c *APQCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// GatewaySchemaCache caches GraphQL schemas.
type GatewaySchemaCache struct {
	schemas map[string]*GatewaySchema
	mu      sync.RWMutex
}

// GatewaySchema represents a GraphQL schema in the gateway.
type GatewaySchema struct {
	Name      string
	SDL       string
	Types     map[string]*GatewayTypeDef
	UpdatedAt time.Time
}

// GatewayTypeDef represents a GraphQL type definition in the gateway.
type GatewayTypeDef struct {
	Name   string
	Kind   string // OBJECT, INTERFACE, UNION, ENUM, INPUT_OBJECT, SCALAR
	Fields map[string]*GatewayFieldDef
}

// GatewayFieldDef represents a GraphQL field definition in the gateway.
type GatewayFieldDef struct {
	Name       string
	Type       string
	Args       []GatewayArgDef
	Complexity int
}

// GatewayArgDef represents a GraphQL argument definition in the gateway.
type GatewayArgDef struct {
	Name string
	Type string
}

// NewGatewaySchemaCache creates a new schema cache.
func NewGatewaySchemaCache() *GatewaySchemaCache {
	return &GatewaySchemaCache{
		schemas: make(map[string]*GatewaySchema),
	}
}

// Get retrieves a schema from the cache.
func (c *GatewaySchemaCache) Get(name string) (*GatewaySchema, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	schema, ok := c.schemas[name]
	return schema, ok
}

// Set stores a schema in the cache.
func (c *GatewaySchemaCache) Set(name string, schema *GatewaySchema) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.schemas[name] = schema
}

// Delete removes a schema from the cache.
func (c *GatewaySchemaCache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.schemas, name)
}

// FieldAuthorizer checks if a field can be accessed.
type FieldAuthorizer interface {
	CanAccessField(ctx context.Context, field string) bool
}

// RoleBasedAuthorizer provides role-based field authorization.
type RoleBasedAuthorizer struct {
	// FieldRoles maps field patterns to required roles.
	FieldRoles map[string][]string
	// RoleExtractor extracts roles from the context.
	RoleExtractor func(ctx context.Context) []string
}

// NewRoleBasedAuthorizer creates a new role-based authorizer.
func NewRoleBasedAuthorizer(roleExtractor func(ctx context.Context) []string) *RoleBasedAuthorizer {
	return &RoleBasedAuthorizer{
		FieldRoles:    make(map[string][]string),
		RoleExtractor: roleExtractor,
	}
}

// AddFieldRole adds a role requirement for a field pattern.
func (a *RoleBasedAuthorizer) AddFieldRole(fieldPattern string, roles ...string) {
	a.FieldRoles[fieldPattern] = append(a.FieldRoles[fieldPattern], roles...)
}

// CanAccessField checks if the current user can access the field.
func (a *RoleBasedAuthorizer) CanAccessField(ctx context.Context, field string) bool {
	// Check if field requires any roles
	var requiredRoles []string
	for pattern, roles := range a.FieldRoles {
		if matchField(field, pattern) {
			requiredRoles = append(requiredRoles, roles...)
		}
	}

	// If no roles required, allow access
	if len(requiredRoles) == 0 {
		return true
	}

	// Get user's roles
	userRoles := a.RoleExtractor(ctx)

	// Check if user has any required role
	for _, required := range requiredRoles {
		for _, userRole := range userRoles {
			if required == userRole {
				return true
			}
		}
	}

	return false
}

// QueryBatcher batches multiple GraphQL queries.
type QueryBatcher struct {
	maxBatchSize int
	timeout      time.Duration
}

// NewQueryBatcher creates a new query batcher.
func NewQueryBatcher(maxBatchSize int, timeout time.Duration) *QueryBatcher {
	if maxBatchSize <= 0 {
		maxBatchSize = 10
	}
	if timeout <= 0 {
		timeout = 10 * time.Millisecond
	}
	return &QueryBatcher{
		maxBatchSize: maxBatchSize,
		timeout:      timeout,
	}
}

// GatewayStats contains GraphQL gateway statistics.
type GatewayStats struct {
	TotalRequests        int64            `json:"total_requests"`
	TotalErrors          int64            `json:"total_errors"`
	QueriesBlocked       int64            `json:"queries_blocked"`
	DepthViolations      int64            `json:"depth_violations"`
	ComplexityViolations int64            `json:"complexity_violations"`
	APQHits              int64            `json:"apq_hits"`
	APQMisses            int64            `json:"apq_misses"`
	APQCacheSize         int              `json:"apq_cache_size"`
	OperationCounts      map[string]int64 `json:"operation_counts"`
}

// GatewayStatsCollector collects GraphQL statistics.
type GatewayStatsCollector struct {
	totalRequests        int64
	totalErrors          int64
	queriesBlocked       int64
	depthViolations      int64
	complexityViolations int64
	apqHits              int64
	apqMisses            int64
	operationCounts      map[string]*int64
	apqCache             *APQCache
	mu                   sync.RWMutex
}

// NewGatewayStatsCollector creates a new stats collector.
func NewGatewayStatsCollector(apqCache *APQCache) *GatewayStatsCollector {
	return &GatewayStatsCollector{
		operationCounts: make(map[string]*int64),
		apqCache:        apqCache,
	}
}

// RecordRequest records a request.
func (s *GatewayStatsCollector) RecordRequest() {
	s.mu.Lock()
	s.totalRequests++
	s.mu.Unlock()
}

// RecordError records an error.
func (s *GatewayStatsCollector) RecordError() {
	s.mu.Lock()
	s.totalErrors++
	s.mu.Unlock()
}

// RecordBlocked records a blocked query.
func (s *GatewayStatsCollector) RecordBlocked(reason string) {
	s.mu.Lock()
	s.queriesBlocked++
	switch reason {
	case "depth":
		s.depthViolations++
	case "complexity":
		s.complexityViolations++
	}
	s.mu.Unlock()
}

// RecordAPQHit records an APQ cache hit.
func (s *GatewayStatsCollector) RecordAPQHit() {
	s.mu.Lock()
	s.apqHits++
	s.mu.Unlock()
}

// RecordAPQMiss records an APQ cache miss.
func (s *GatewayStatsCollector) RecordAPQMiss() {
	s.mu.Lock()
	s.apqMisses++
	s.mu.Unlock()
}

// RecordOperation records an operation type.
func (s *GatewayStatsCollector) RecordOperation(opType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.operationCounts[opType] == nil {
		var count int64
		s.operationCounts[opType] = &count
	}
	*s.operationCounts[opType]++
}

// GetStats returns current statistics.
func (s *GatewayStatsCollector) GetStats() GatewayStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := GatewayStats{
		TotalRequests:        s.totalRequests,
		TotalErrors:          s.totalErrors,
		QueriesBlocked:       s.queriesBlocked,
		DepthViolations:      s.depthViolations,
		ComplexityViolations: s.complexityViolations,
		APQHits:              s.apqHits,
		APQMisses:            s.apqMisses,
		OperationCounts:      make(map[string]int64),
	}

	if s.apqCache != nil {
		stats.APQCacheSize = s.apqCache.Size()
	}

	for op, count := range s.operationCounts {
		if count != nil {
			stats.OperationCounts[op] = *count
		}
	}

	return stats
}

// ServiceDefinition represents a federated service for the gateway.
type ServiceDefinition struct {
	Name string
	URL  string
	SDL  string
}

// FederatedGateway manages multiple GraphQL services.
type FederatedGateway struct {
	services map[string]*ServiceDefinition
	gateway  *Gateway
	logger   *slog.Logger
	mu       sync.RWMutex
}

// NewFederatedGateway creates a new federated gateway.
func NewFederatedGateway(config GatewayConfig, logger *slog.Logger) *FederatedGateway {
	return &FederatedGateway{
		services: make(map[string]*ServiceDefinition),
		gateway:  NewGateway(config, logger),
		logger:   logger,
	}
}

// AddService adds a service to the federation.
func (f *FederatedGateway) AddService(service *ServiceDefinition) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.services[service.Name] = service
}

// RemoveService removes a service from the federation.
func (f *FederatedGateway) RemoveService(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.services, name)
}

// GetServices returns all registered services.
func (f *FederatedGateway) GetServices() []*ServiceDefinition {
	f.mu.RLock()
	defer f.mu.RUnlock()

	services := make([]*ServiceDefinition, 0, len(f.services))
	for _, svc := range f.services {
		services = append(services, svc)
	}
	return services
}

// RouteQuery determines which service should handle a query.
func (f *FederatedGateway) RouteQuery(ctx context.Context, req *GatewayRequest) (string, error) {
	// Analyze the query to determine routing
	_, analysis, err := f.gateway.ProcessRequest(ctx, req)
	if err != nil {
		return "", err
	}

	// Simple routing based on root field
	if len(analysis.Fields) > 0 {
		rootField := analysis.Fields[0]
		if idx := strings.Index(rootField, "."); idx > 0 {
			rootField = rootField[:idx]
		}

		f.mu.RLock()
		defer f.mu.RUnlock()

		// Check if any service owns this field
		for name := range f.services {
			// In a real implementation, we'd check the service's schema
			// For now, route based on service name matching field prefix
			if strings.HasPrefix(strings.ToLower(rootField), strings.ToLower(name)) {
				return name, nil
			}
		}
	}

	// Default to first service if no match
	f.mu.RLock()
	defer f.mu.RUnlock()
	for name := range f.services {
		return name, nil
	}

	return "", ErrSchemaNotFound
}

// GetGateway returns the underlying gateway.
func (f *FederatedGateway) GetGateway() *Gateway {
	return f.gateway
}
