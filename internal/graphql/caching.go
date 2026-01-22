// Package graphql provides smart caching for GraphQL queries.
package graphql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CacheConfig configures GraphQL caching.
type CacheConfig struct {
	// Enabled turns caching on/off.
	Enabled bool
	// MaxSize is the maximum number of cached responses.
	MaxSize int
	// DefaultTTL is the default cache TTL.
	DefaultTTL time.Duration
	// StaleWhileRevalidate allows serving stale content while revalidating.
	StaleWhileRevalidate time.Duration
	// EnableNormalization enables entity-based normalized caching.
	EnableNormalization bool
	// EnableFieldLevelCache enables per-field caching.
	EnableFieldLevelCache bool
	// TypePolicies defines caching policies per GraphQL type.
	TypePolicies map[string]TypeCachePolicy
	// FieldPolicies defines caching policies per field.
	FieldPolicies map[string]FieldCachePolicy
	// ExcludedOperations are operation names that should never be cached.
	ExcludedOperations []string
	// ExcludedTypes are types that should never be cached.
	ExcludedTypes []string
	// Logger for cache events.
	Logger *slog.Logger
}

// TypeCachePolicy defines caching policy for a GraphQL type.
type TypeCachePolicy struct {
	// KeyFields are fields used to generate the cache key (e.g., ["id"]).
	KeyFields []string
	// TTL is the cache TTL for this type.
	TTL time.Duration
	// Merge defines how to merge incoming data with cached data.
	Merge MergeStrategy
}

// FieldCachePolicy defines caching policy for a GraphQL field.
type FieldCachePolicy struct {
	// TTL is the cache TTL for this field.
	TTL time.Duration
	// KeyArgs are argument names used in the cache key.
	KeyArgs []string
	// Read is a custom read function for transforming cached data.
	Read func(existing interface{}) interface{}
	// Merge defines how to merge incoming data with cached data.
	Merge MergeStrategy
}

// MergeStrategy defines how to merge cached data.
type MergeStrategy string

const (
	MergeReplace  MergeStrategy = "replace"
	MergeMerge    MergeStrategy = "merge"
	MergeAppend   MergeStrategy = "append"
	MergePrepend  MergeStrategy = "prepend"
)

// ResponseCache caches GraphQL responses.
type ResponseCache struct {
	config      CacheConfig
	entries     map[string]*CacheEntry
	entityStore *EntityStore
	stats       *CacheStats
	mu          sync.RWMutex
	logger      *slog.Logger
	stopCh      chan struct{}
}

// CacheEntry represents a cached response.
type CacheEntry struct {
	Key         string                 `json:"key"`
	Query       string                 `json:"query"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Response    *GatewayResponse       `json:"response"`
	Entities    []EntityRef            `json:"entities,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	StaleAt     time.Time              `json:"stale_at"`
	HitCount    int64                  `json:"hit_count"`
	LastAccess  time.Time              `json:"last_access"`
	Revalidating bool                  `json:"-"`
}

// EntityRef references a cached entity.
type EntityRef struct {
	TypeName string `json:"typename"`
	ID       string `json:"id"`
}

// EntityStore stores normalized entity data.
type EntityStore struct {
	entities map[string]*EntityEntry
	watchers map[string][]chan EntityUpdate
	mu       sync.RWMutex
}

// EntityEntry represents a cached entity.
type EntityEntry struct {
	TypeName   string                 `json:"typename"`
	ID         string                 `json:"id"`
	Data       map[string]interface{} `json:"data"`
	UpdatedAt  time.Time              `json:"updated_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
	References []string               `json:"references"` // Cache keys that reference this entity
}

// EntityUpdate represents an entity change notification.
type EntityUpdate struct {
	TypeName  string
	ID        string
	Operation string // "update", "delete", "invalidate"
	Data      map[string]interface{}
}

// CacheStats contains cache statistics.
type CacheStats struct {
	hits           int64
	misses         int64
	staleHits      int64
	evictions      int64
	invalidations  int64
	revalidations  int64
	entryCount     int64
	entityCount    int64
	bytesUsed      int64
}

// NewResponseCache creates a new GraphQL response cache.
func NewResponseCache(config CacheConfig) *ResponseCache {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxSize == 0 {
		config.MaxSize = 10000
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 5 * time.Minute
	}

	cache := &ResponseCache{
		config:  config,
		entries: make(map[string]*CacheEntry),
		stats:   &CacheStats{},
		logger:  config.Logger,
		stopCh:  make(chan struct{}),
	}

	if config.EnableNormalization {
		cache.entityStore = NewEntityStore()
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache
}

// Get retrieves a cached response.
func (c *ResponseCache) Get(ctx context.Context, req *GatewayRequest) (*GatewayResponse, CacheStatus) {
	if !c.config.Enabled {
		return nil, CacheStatusDisabled
	}

	// Check if this operation should be cached
	if c.isExcluded(req) {
		return nil, CacheStatusBypass
	}

	key := c.generateKey(req)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		atomic.AddInt64(&c.stats.misses, 1)
		return nil, CacheStatusMiss
	}

	now := time.Now()

	// Check if expired
	if now.After(entry.ExpiresAt) {
		atomic.AddInt64(&c.stats.misses, 1)
		return nil, CacheStatusMiss
	}

	// Update stats
	atomic.AddInt64(&entry.HitCount, 1)
	entry.LastAccess = now

	// Check if stale (but still valid)
	if now.After(entry.StaleAt) {
		atomic.AddInt64(&c.stats.staleHits, 1)

		// Trigger background revalidation if not already revalidating
		if c.config.StaleWhileRevalidate > 0 && !entry.Revalidating {
			go c.revalidate(ctx, key, req)
		}

		return entry.Response, CacheStatusStale
	}

	atomic.AddInt64(&c.stats.hits, 1)
	return entry.Response, CacheStatusHit
}

// Set caches a response.
func (c *ResponseCache) Set(ctx context.Context, req *GatewayRequest, resp *GatewayResponse) {
	if !c.config.Enabled {
		return
	}

	// Don't cache errors
	if len(resp.Errors) > 0 {
		return
	}

	// Check if excluded
	if c.isExcluded(req) {
		return
	}

	key := c.generateKey(req)
	ttl := c.getTTL(req)
	now := time.Now()

	entry := &CacheEntry{
		Key:        key,
		Query:      req.Query,
		Variables:  req.Variables,
		Response:   resp,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		StaleAt:    now.Add(ttl - c.config.StaleWhileRevalidate),
		LastAccess: now,
	}

	// Extract and store entities if normalization is enabled
	if c.config.EnableNormalization && c.entityStore != nil {
		entities := c.extractEntities(resp.Data)
		entry.Entities = entities
		c.storeEntities(key, entities, resp.Data)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.config.MaxSize {
		c.evictLRU()
	}

	c.entries[key] = entry
	atomic.StoreInt64(&c.stats.entryCount, int64(len(c.entries)))

	c.logger.Debug("cached GraphQL response",
		"key", key,
		"ttl", ttl,
	)
}

// Invalidate invalidates cache entries.
func (c *ResponseCache) Invalidate(pattern string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for key := range c.entries {
		if matchCacheKey(key, pattern) {
			delete(c.entries, key)
			count++
		}
	}

	atomic.AddInt64(&c.stats.invalidations, int64(count))
	atomic.StoreInt64(&c.stats.entryCount, int64(len(c.entries)))

	c.logger.Info("invalidated cache entries",
		"pattern", pattern,
		"count", count,
	)

	return count
}

// InvalidateEntity invalidates all cache entries referencing an entity.
func (c *ResponseCache) InvalidateEntity(typeName, id string) int {
	if c.entityStore == nil {
		return 0
	}

	entityKey := fmt.Sprintf("%s:%s", typeName, id)

	c.entityStore.mu.RLock()
	entity, ok := c.entityStore.entities[entityKey]
	c.entityStore.mu.RUnlock()

	if !ok {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for _, cacheKey := range entity.References {
		if _, exists := c.entries[cacheKey]; exists {
			delete(c.entries, cacheKey)
			count++
		}
	}

	// Remove entity
	c.entityStore.mu.Lock()
	delete(c.entityStore.entities, entityKey)
	c.entityStore.mu.Unlock()

	atomic.AddInt64(&c.stats.invalidations, int64(count))

	c.logger.Info("invalidated entity and references",
		"type", typeName,
		"id", id,
		"count", count,
	)

	return count
}

// InvalidateType invalidates all cache entries for a type.
func (c *ResponseCache) InvalidateType(typeName string) int {
	if c.entityStore == nil {
		return 0
	}

	c.entityStore.mu.RLock()
	var keysToInvalidate []string
	for _, entity := range c.entityStore.entities {
		if entity.TypeName == typeName {
			keysToInvalidate = append(keysToInvalidate, entity.References...)
		}
	}
	c.entityStore.mu.RUnlock()

	c.mu.Lock()
	count := 0
	for _, cacheKey := range keysToInvalidate {
		if _, exists := c.entries[cacheKey]; exists {
			delete(c.entries, cacheKey)
			count++
		}
	}
	atomic.StoreInt64(&c.stats.entryCount, int64(len(c.entries)))
	c.mu.Unlock()

	// Remove entities of this type
	c.entityStore.mu.Lock()
	for key, entity := range c.entityStore.entities {
		if entity.TypeName == typeName {
			delete(c.entityStore.entities, key)
		}
	}
	atomic.StoreInt64(&c.stats.entityCount, int64(len(c.entityStore.entities)))
	c.entityStore.mu.Unlock()

	atomic.AddInt64(&c.stats.invalidations, int64(count))

	c.logger.Info("invalidated type cache",
		"type", typeName,
		"count", count,
	)

	return count
}

// UpdateEntity updates a cached entity and marks related cache entries as stale.
func (c *ResponseCache) UpdateEntity(typeName, id string, data map[string]interface{}) {
	if c.entityStore == nil {
		return
	}

	entityKey := fmt.Sprintf("%s:%s", typeName, id)

	c.entityStore.mu.Lock()
	if entity, ok := c.entityStore.entities[entityKey]; ok {
		// Merge data
		for k, v := range data {
			entity.Data[k] = v
		}
		entity.UpdatedAt = time.Now()
	} else {
		c.entityStore.entities[entityKey] = &EntityEntry{
			TypeName:  typeName,
			ID:        id,
			Data:      data,
			UpdatedAt: time.Now(),
			ExpiresAt: time.Now().Add(c.config.DefaultTTL),
		}
	}
	c.entityStore.mu.Unlock()

	// Notify watchers
	c.entityStore.notifyWatchers(EntityUpdate{
		TypeName:  typeName,
		ID:        id,
		Operation: "update",
		Data:      data,
	})
}

// generateKey generates a cache key for a request.
func (c *ResponseCache) generateKey(req *GatewayRequest) string {
	// Normalize the query (remove whitespace, sort fields)
	normalizedQuery := normalizeQuery(req.Query)

	// Build key components
	var keyParts []string
	keyParts = append(keyParts, normalizedQuery)

	if req.OperationName != "" {
		keyParts = append(keyParts, req.OperationName)
	}

	// Sort and include variables
	if len(req.Variables) > 0 {
		varsJSON, _ := json.Marshal(sortedVariables(req.Variables))
		keyParts = append(keyParts, string(varsJSON))
	}

	// Hash the key
	combined := strings.Join(keyParts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes
}

// getTTL determines the TTL for a request.
func (c *ResponseCache) getTTL(req *GatewayRequest) time.Duration {
	// Check type policies
	for typeName, policy := range c.config.TypePolicies {
		if strings.Contains(req.Query, typeName) && policy.TTL > 0 {
			return policy.TTL
		}
	}

	// Check field policies
	for fieldName, policy := range c.config.FieldPolicies {
		if strings.Contains(req.Query, fieldName) && policy.TTL > 0 {
			return policy.TTL
		}
	}

	return c.config.DefaultTTL
}

// isExcluded checks if a request should not be cached.
func (c *ResponseCache) isExcluded(req *GatewayRequest) bool {
	// Don't cache mutations
	if strings.Contains(strings.ToLower(req.Query), "mutation") {
		return true
	}

	// Don't cache subscriptions
	if strings.Contains(strings.ToLower(req.Query), "subscription") {
		return true
	}

	// Check excluded operations
	for _, op := range c.config.ExcludedOperations {
		if req.OperationName == op {
			return true
		}
	}

	// Check excluded types
	for _, t := range c.config.ExcludedTypes {
		if strings.Contains(req.Query, t) {
			return true
		}
	}

	return false
}

// extractEntities extracts entity references from response data.
func (c *ResponseCache) extractEntities(data interface{}) []EntityRef {
	var entities []EntityRef
	c.walkData(data, func(obj map[string]interface{}) {
		typename, hasType := obj["__typename"].(string)
		id, hasID := obj["id"].(string)
		if hasType && hasID {
			entities = append(entities, EntityRef{
				TypeName: typename,
				ID:       id,
			})
		}
	})
	return entities
}

// walkData recursively walks through response data.
func (c *ResponseCache) walkData(data interface{}, fn func(map[string]interface{})) {
	switch v := data.(type) {
	case map[string]interface{}:
		fn(v)
		for _, value := range v {
			c.walkData(value, fn)
		}
	case []interface{}:
		for _, item := range v {
			c.walkData(item, fn)
		}
	}
}

// storeEntities stores extracted entities in the entity store.
func (c *ResponseCache) storeEntities(cacheKey string, refs []EntityRef, data interface{}) {
	if c.entityStore == nil {
		return
	}

	c.entityStore.mu.Lock()
	defer c.entityStore.mu.Unlock()

	for _, ref := range refs {
		entityKey := fmt.Sprintf("%s:%s", ref.TypeName, ref.ID)

		if entry, ok := c.entityStore.entities[entityKey]; ok {
			// Add reference
			entry.References = appendUnique(entry.References, cacheKey)
		} else {
			// Create new entity entry
			c.entityStore.entities[entityKey] = &EntityEntry{
				TypeName:   ref.TypeName,
				ID:         ref.ID,
				UpdatedAt:  time.Now(),
				ExpiresAt:  time.Now().Add(c.config.DefaultTTL),
				References: []string{cacheKey},
			}
		}
	}

	atomic.StoreInt64(&c.stats.entityCount, int64(len(c.entityStore.entities)))
}

// revalidate revalidates a stale cache entry in the background.
func (c *ResponseCache) revalidate(ctx context.Context, key string, req *GatewayRequest) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok || entry.Revalidating {
		c.mu.Unlock()
		return
	}
	entry.Revalidating = true
	c.mu.Unlock()

	atomic.AddInt64(&c.stats.revalidations, 1)

	c.logger.Debug("revalidating cache entry", "key", key)

	// Note: In a real implementation, this would make an upstream request
	// For now, we just mark as revalidated
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		entry.Revalidating = false
	}
	c.mu.Unlock()
}

// evictLRU evicts the least recently used entry.
func (c *ResponseCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.LastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccess
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		atomic.AddInt64(&c.stats.evictions, 1)
	}
}

// cleanupLoop periodically removes expired entries.
func (c *ResponseCache) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired entries.
func (c *ResponseCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}

	atomic.StoreInt64(&c.stats.entryCount, int64(len(c.entries)))
}

// Stop stops the cache.
func (c *ResponseCache) Stop() {
	close(c.stopCh)
}

// Stats returns cache statistics.
func (c *ResponseCache) Stats() CacheStatsSnapshot {
	return CacheStatsSnapshot{
		Hits:          atomic.LoadInt64(&c.stats.hits),
		Misses:        atomic.LoadInt64(&c.stats.misses),
		StaleHits:     atomic.LoadInt64(&c.stats.staleHits),
		Evictions:     atomic.LoadInt64(&c.stats.evictions),
		Invalidations: atomic.LoadInt64(&c.stats.invalidations),
		Revalidations: atomic.LoadInt64(&c.stats.revalidations),
		EntryCount:    atomic.LoadInt64(&c.stats.entryCount),
		EntityCount:   atomic.LoadInt64(&c.stats.entityCount),
	}
}

// CacheStatsSnapshot is a snapshot of cache statistics.
type CacheStatsSnapshot struct {
	Hits          int64 `json:"hits"`
	Misses        int64 `json:"misses"`
	StaleHits     int64 `json:"stale_hits"`
	Evictions     int64 `json:"evictions"`
	Invalidations int64 `json:"invalidations"`
	Revalidations int64 `json:"revalidations"`
	EntryCount    int64 `json:"entry_count"`
	EntityCount   int64 `json:"entity_count"`
	HitRate       float64 `json:"hit_rate"`
}

// CacheStatus indicates the cache lookup result.
type CacheStatus string

const (
	CacheStatusHit      CacheStatus = "hit"
	CacheStatusMiss     CacheStatus = "miss"
	CacheStatusStale    CacheStatus = "stale"
	CacheStatusBypass   CacheStatus = "bypass"
	CacheStatusDisabled CacheStatus = "disabled"
)

// NewEntityStore creates a new entity store.
func NewEntityStore() *EntityStore {
	return &EntityStore{
		entities: make(map[string]*EntityEntry),
		watchers: make(map[string][]chan EntityUpdate),
	}
}

// Watch watches for updates to an entity.
func (s *EntityStore) Watch(typeName, id string) <-chan EntityUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", typeName, id)
	ch := make(chan EntityUpdate, 10)
	s.watchers[key] = append(s.watchers[key], ch)

	return ch
}

// Unwatch stops watching an entity.
func (s *EntityStore) Unwatch(typeName, id string, ch <-chan EntityUpdate) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", typeName, id)
	watchers := s.watchers[key]

	for i, w := range watchers {
		if w == ch {
			s.watchers[key] = append(watchers[:i], watchers[i+1:]...)
			close(w)
			break
		}
	}
}

// notifyWatchers notifies all watchers of an update.
func (s *EntityStore) notifyWatchers(update EntityUpdate) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", update.TypeName, update.ID)
	for _, ch := range s.watchers[key] {
		select {
		case ch <- update:
		default:
			// Drop if channel is full
		}
	}

	// Also notify type-level watchers
	typeKey := fmt.Sprintf("%s:*", update.TypeName)
	for _, ch := range s.watchers[typeKey] {
		select {
		case ch <- update:
		default:
		}
	}
}

// Get retrieves an entity from the store.
func (s *EntityStore) Get(typeName, id string) (map[string]interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", typeName, id)
	entry, ok := s.entities[key]
	if !ok {
		return nil, false
	}

	return entry.Data, true
}

// CachingMiddleware provides caching middleware for GraphQL handlers.
type CachingMiddleware struct {
	cache   *ResponseCache
	gateway *Gateway
	logger  *slog.Logger
}

// CachingMiddlewareConfig configures the caching middleware.
type CachingMiddlewareConfig struct {
	Cache   *ResponseCache
	Gateway *Gateway
	Logger  *slog.Logger
}

// NewCachingMiddleware creates new caching middleware.
func NewCachingMiddleware(config CachingMiddlewareConfig) *CachingMiddleware {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &CachingMiddleware{
		cache:   config.Cache,
		gateway: config.Gateway,
		logger:  config.Logger,
	}
}

// Handler wraps an HTTP handler with caching.
func (m *CachingMiddleware) Handler(next func(context.Context, *GatewayRequest) (*GatewayResponse, error)) func(context.Context, *GatewayRequest) (*GatewayResponse, error) {
	return func(ctx context.Context, req *GatewayRequest) (*GatewayResponse, error) {
		// Try cache first
		if resp, status := m.cache.Get(ctx, req); status == CacheStatusHit || status == CacheStatusStale {
			m.logger.Debug("cache hit",
				"status", status,
				"operation", req.OperationName,
			)
			return resp, nil
		}

		// Execute the request
		resp, err := next(ctx, req)
		if err != nil {
			return resp, err
		}

		// Cache the response
		m.cache.Set(ctx, req, resp)

		return resp, nil
	}
}

// QueryNormalizer normalizes GraphQL queries for caching.
type QueryNormalizer struct {
	// SortFields sorts fields alphabetically within selection sets.
	SortFields bool
	// RemoveAliases removes field aliases.
	RemoveAliases bool
	// RemoveComments removes comments.
	RemoveComments bool
	// CollapseWhitespace collapses whitespace.
	CollapseWhitespace bool
}

// NewQueryNormalizer creates a new query normalizer.
func NewQueryNormalizer() *QueryNormalizer {
	return &QueryNormalizer{
		SortFields:         true,
		RemoveComments:     true,
		CollapseWhitespace: true,
	}
}

// Normalize normalizes a GraphQL query.
func (n *QueryNormalizer) Normalize(query string) string {
	// Remove comments
	if n.RemoveComments {
		query = removeGraphQLComments(query)
	}

	// Collapse whitespace
	if n.CollapseWhitespace {
		query = collapseWhitespace(query)
	}

	// Sort fields (basic implementation)
	if n.SortFields {
		query = sortSelectionSets(query)
	}

	return strings.TrimSpace(query)
}

// normalizeQuery normalizes a query for cache key generation.
func normalizeQuery(query string) string {
	normalizer := NewQueryNormalizer()
	return normalizer.Normalize(query)
}

// removeGraphQLComments removes GraphQL comments from a query.
func removeGraphQLComments(query string) string {
	var result strings.Builder
	lines := strings.Split(query, "\n")

	for _, line := range lines {
		// Find # outside of strings
		inString := false
		for i, char := range line {
			if char == '"' && (i == 0 || line[i-1] != '\\') {
				inString = !inString
			}
			if char == '#' && !inString {
				line = line[:i]
				break
			}
		}
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}

// collapseWhitespace collapses multiple whitespace characters.
func collapseWhitespace(query string) string {
	var result strings.Builder
	var lastWasSpace bool
	inString := false

	for _, char := range query {
		if char == '"' {
			inString = !inString
		}

		if inString {
			result.WriteRune(char)
			continue
		}

		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			if !lastWasSpace {
				result.WriteRune(' ')
				lastWasSpace = true
			}
		} else {
			result.WriteRune(char)
			lastWasSpace = false
		}
	}

	return result.String()
}

// sortSelectionSets sorts fields within selection sets (basic implementation).
func sortSelectionSets(query string) string {
	// This is a simplified implementation
	// A full implementation would use a proper GraphQL parser
	return query
}

// sortedVariables returns variables sorted by key for consistent hashing.
func sortedVariables(vars map[string]interface{}) map[string]interface{} {
	if vars == nil {
		return nil
	}

	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sorted := make(map[string]interface{}, len(vars))
	for _, k := range keys {
		sorted[k] = vars[k]
	}
	return sorted
}

// matchCacheKey checks if a cache key matches a pattern.
func matchCacheKey(key, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(key, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(key, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(key, pattern[:len(pattern)-1])
	}
	return key == pattern
}

// appendUnique appends an item to a slice if not already present.
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// CacheControl parses and represents cache control directives.
type CacheControl struct {
	MaxAge               int
	SMaxAge              int
	NoCache              bool
	NoStore              bool
	MustRevalidate       bool
	StaleWhileRevalidate int
	Private              bool
	Public               bool
}

// ParseCacheControl parses a Cache-Control header value.
func ParseCacheControl(header string) *CacheControl {
	cc := &CacheControl{}
	directives := strings.Split(header, ",")

	for _, directive := range directives {
		directive = strings.TrimSpace(strings.ToLower(directive))

		if strings.HasPrefix(directive, "max-age=") {
			fmt.Sscanf(directive, "max-age=%d", &cc.MaxAge)
		} else if strings.HasPrefix(directive, "s-maxage=") {
			fmt.Sscanf(directive, "s-maxage=%d", &cc.SMaxAge)
		} else if strings.HasPrefix(directive, "stale-while-revalidate=") {
			fmt.Sscanf(directive, "stale-while-revalidate=%d", &cc.StaleWhileRevalidate)
		} else {
			switch directive {
			case "no-cache":
				cc.NoCache = true
			case "no-store":
				cc.NoStore = true
			case "must-revalidate":
				cc.MustRevalidate = true
			case "private":
				cc.Private = true
			case "public":
				cc.Public = true
			}
		}
	}

	return cc
}

// ShouldCache determines if a response should be cached based on cache control.
func (cc *CacheControl) ShouldCache() bool {
	if cc.NoStore || cc.NoCache || cc.Private {
		return false
	}
	return cc.MaxAge > 0 || cc.SMaxAge > 0
}

// TTL returns the TTL based on cache control directives.
func (cc *CacheControl) TTL() time.Duration {
	if cc.SMaxAge > 0 {
		return time.Duration(cc.SMaxAge) * time.Second
	}
	if cc.MaxAge > 0 {
		return time.Duration(cc.MaxAge) * time.Second
	}
	return 0
}
