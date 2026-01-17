// Package router provides radix tree based request routing.
package router

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josedab/loom/internal/config"
)

// Common errors for route operations.
var (
	ErrRouteNotFound      = errors.New("route not found")
	ErrRouteAlreadyExists = errors.New("route already exists")
)

// Route defines a routing rule.
type Route struct {
	ID          string
	Host        string
	Path        string
	Methods     []string
	Headers     map[string]string
	QueryParams map[string]string
	Upstream    string
	Plugins     []string
	StripPrefix bool
	Timeout     time.Duration
	Priority    int
	Metadata    map[string]string
}

// routeSnapshot is an immutable snapshot of the routing table.
// Used for lock-free reads via atomic.Value.
type routeSnapshot struct {
	trees  map[string]*radixNode
	routes []*Route
}

// Router handles request routing with radix tree.
// Uses copy-on-write semantics for lock-free Match operations.
type Router struct {
	snapshot atomic.Value // *routeSnapshot - lock-free reads
	mu       sync.Mutex   // Only protects writes (Configure)
	notFound atomic.Value // http.Handler - lock-free reads
}

// radixNode is a node in the radix tree.
type radixNode struct {
	path     string
	children []*radixNode
	route    *Route
	routes   []*Route   // multiple routes for same path (different hosts)
	wildcard bool       // matches rest of path (*)
	param    bool       // path parameter (:id)
	paramKey string     // parameter name
}

// MatchResult contains the result of a route match.
type MatchResult struct {
	Route  *Route
	Params map[string]string
}

// New creates a new router.
func New() *Router {
	r := &Router{}
	// Initialize empty snapshot
	r.snapshot.Store(&routeSnapshot{
		trees:  make(map[string]*radixNode),
		routes: make([]*Route, 0),
	})
	// Initialize default not found handler
	r.notFound.Store(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	return r
}

// getSnapshot returns the current routing snapshot for lock-free reads.
func (r *Router) getSnapshot() *routeSnapshot {
	return r.snapshot.Load().(*routeSnapshot)
}

// Configure sets up routes from configuration.
// Uses copy-on-write: builds a new snapshot and atomically swaps it.
func (r *Router) Configure(configs []config.RouteConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build new snapshot (copy-on-write)
	newSnapshot := &routeSnapshot{
		trees:  make(map[string]*radixNode),
		routes: make([]*Route, 0, len(configs)),
	}

	for _, cfg := range configs {
		route := &Route{
			ID:          cfg.ID,
			Host:        cfg.Host,
			Path:        cfg.Path,
			Methods:     cfg.Methods,
			Headers:     cfg.Headers,
			QueryParams: cfg.QueryParams,
			Upstream:    cfg.Upstream,
			Plugins:     cfg.Plugins,
			StripPrefix: cfg.StripPrefix,
			Priority:    cfg.Priority,
			Timeout:     config.ParseDuration(cfg.Timeout, 30*time.Second),
		}

		if len(route.Methods) == 0 {
			route.Methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		}

		if err := r.addRouteToSnapshot(newSnapshot, route); err != nil {
			return err
		}
	}

	// Atomically publish the new snapshot
	r.snapshot.Store(newSnapshot)
	return nil
}

// addRouteToSnapshot adds a route to a snapshot (used during Configure).
func (r *Router) addRouteToSnapshot(snap *routeSnapshot, route *Route) error {
	for _, method := range route.Methods {
		tree, ok := snap.trees[method]
		if !ok {
			tree = &radixNode{}
			snap.trees[method] = tree
		}

		insertRoute(tree, route.Path, route)
	}

	snap.routes = append(snap.routes, route)

	// Sort by priority (higher first)
	sort.Slice(snap.routes, func(i, j int) bool {
		return snap.routes[i].Priority > snap.routes[j].Priority
	})

	return nil
}

// insertRoute inserts a route into the radix tree.
// This is a standalone function used during snapshot building.
func insertRoute(node *radixNode, path string, route *Route) {
	// Handle empty path
	if path == "" {
		if route != nil {
			node.routes = append(node.routes, route)
			if node.route == nil {
				node.route = route
			}
		}
		return
	}

	// Handle wildcards
	if strings.HasSuffix(path, "/*") {
		basePath := strings.TrimSuffix(path, "/*")
		insertRoute(node, basePath, nil)

		// Find or create the base node
		baseNode := findOrCreateNode(node, basePath)

		// Look for existing wildcard node
		for _, child := range baseNode.children {
			if child.wildcard {
				child.routes = append(child.routes, route)
				return
			}
		}

		baseNode.children = append(baseNode.children, &radixNode{
			path:     "*",
			wildcard: true,
			route:    route,
			routes:   []*Route{route},
		})
		return
	}

	// Handle path parameters (:param)
	if idx := strings.Index(path, ":"); idx != -1 {
		prefix := path[:idx]
		rest := path[idx:]

		// Find end of parameter
		endIdx := strings.IndexByte(rest[1:], '/')
		var paramName, suffix string
		if endIdx == -1 {
			paramName = rest[1:]
			suffix = ""
		} else {
			paramName = rest[1 : endIdx+1]
			suffix = rest[endIdx+1:]
		}

		// Insert prefix
		if prefix != "" {
			node = findOrCreateNode(node, prefix)
		}

		// Create parameter node
		paramNode := &radixNode{
			path:     ":" + paramName,
			param:    true,
			paramKey: paramName,
		}

		// Check if param node exists
		var existingParam *radixNode
		for _, child := range node.children {
			if child.param && child.paramKey == paramName {
				existingParam = child
				break
			}
		}

		if existingParam != nil {
			paramNode = existingParam
		} else {
			node.children = append(node.children, paramNode)
		}

		// Continue with suffix
		if suffix != "" {
			insertRoute(paramNode, suffix, route)
		} else {
			paramNode.routes = append(paramNode.routes, route)
			if paramNode.route == nil {
				paramNode.route = route
			}
		}
		return
	}

	// Regular path insertion
	targetNode := findOrCreateNode(node, path)
	targetNode.routes = append(targetNode.routes, route)
	if targetNode.route == nil {
		targetNode.route = route
	}
}

// findOrCreateNode finds or creates a node for the given path.
// This is a standalone function used during snapshot building.
func findOrCreateNode(node *radixNode, path string) *radixNode {
	if path == "" {
		return node
	}

	for _, child := range node.children {
		if child.param || child.wildcard {
			continue
		}

		// Find common prefix
		common := commonPrefix(child.path, path)
		if common == "" {
			continue
		}

		if common == child.path {
			// Descend into child
			return findOrCreateNode(child, path[len(common):])
		}

		// Split the child node
		newChild := &radixNode{
			path:     child.path[len(common):],
			children: child.children,
			route:    child.route,
		}
		child.path = common
		child.children = []*radixNode{newChild}
		child.route = nil

		if len(path) > len(common) {
			return findOrCreateNode(child, path[len(common):])
		}
		return child
	}

	// Create new child
	newNode := &radixNode{path: path}
	node.children = append(node.children, newNode)
	return newNode
}

// commonPrefix returns the common prefix of two strings.
func commonPrefix(a, b string) string {
	maxLen := len(a)
	if len(b) < maxLen {
		maxLen = len(b)
	}

	i := 0
	for i < maxLen && a[i] == b[i] {
		i++
	}
	return a[:i]
}

// Match finds the route for a request.
// This is lock-free using atomic.Value for snapshot access.
func (r *Router) Match(req *http.Request) *MatchResult {
	// Lock-free snapshot access
	snap := r.getSnapshot()

	tree, ok := snap.trees[req.Method]
	if !ok {
		return nil
	}

	params := make(map[string]string)
	routes := matchPathRoutes(tree, req.URL.Path, params)

	if len(routes) == 0 {
		return nil
	}

	// Find matching route based on host/headers/query params
	for _, route := range routes {
		if matchRoute(route, req) {
			return &MatchResult{
				Route:  route,
				Params: params,
			}
		}
	}

	return nil
}

// matchPathRoutes traverses the radix tree to find all matching routes.
// This is a standalone function for use with lock-free snapshot access.
func matchPathRoutes(node *radixNode, path string, params map[string]string) []*Route {
	if len(path) == 0 {
		return node.routes
	}

	// Try exact match first
	for _, child := range node.children {
		if child.param || child.wildcard {
			continue
		}

		if strings.HasPrefix(path, child.path) {
			if routes := matchPathRoutes(child, path[len(child.path):], params); len(routes) > 0 {
				return routes
			}
		}
	}

	// Try parameter match
	for _, child := range node.children {
		if !child.param {
			continue
		}

		// Find end of segment
		end := strings.IndexByte(path, '/')
		if end == -1 {
			end = len(path)
		}

		params[child.paramKey] = path[:end]
		if routes := matchPathRoutes(child, path[end:], params); len(routes) > 0 {
			return routes
		}
		delete(params, child.paramKey)
	}

	// Try wildcard match
	for _, child := range node.children {
		if !child.wildcard {
			continue
		}

		params["*"] = path
		return child.routes
	}

	return nil
}

// matchRoute checks additional route criteria.
// This is a standalone function for use with lock-free snapshot access.
func matchRoute(route *Route, req *http.Request) bool {
	// Check host
	if route.Host != "" {
		host := req.Host
		if idx := strings.IndexByte(host, ':'); idx != -1 {
			host = host[:idx]
		}
		if route.Host != host {
			return false
		}
	}

	// Check required headers
	for key, value := range route.Headers {
		if req.Header.Get(key) != value {
			return false
		}
	}

	// Check required query params
	query := req.URL.Query()
	for key, value := range route.QueryParams {
		if query.Get(key) != value {
			return false
		}
	}

	return true
}

// GetRoutes returns all configured routes.
// This is lock-free using atomic.Value for snapshot access.
func (r *Router) GetRoutes() []*Route {
	snap := r.getSnapshot()
	routes := make([]*Route, len(snap.routes))
	copy(routes, snap.routes)
	return routes
}

// GetRoute returns a route by ID.
// This is lock-free using atomic.Value for snapshot access.
func (r *Router) GetRoute(id string) (*Route, bool) {
	snap := r.getSnapshot()
	for _, route := range snap.routes {
		if route.ID == id {
			return route, true
		}
	}
	return nil, false
}

// AddRoute adds a new route dynamically.
// Uses copy-on-write: builds a new snapshot and atomically swaps it.
func (r *Router) AddRoute(cfg config.RouteConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldSnap := r.getSnapshot()

	// Check if route already exists
	for _, route := range oldSnap.routes {
		if route.ID == cfg.ID {
			return ErrRouteAlreadyExists
		}
	}

	// Build new snapshot with existing routes plus the new one
	newSnapshot := &routeSnapshot{
		trees:  make(map[string]*radixNode),
		routes: make([]*Route, 0, len(oldSnap.routes)+1),
	}

	// Copy existing routes
	for _, route := range oldSnap.routes {
		if err := r.addRouteToSnapshot(newSnapshot, route); err != nil {
			return err
		}
	}

	// Add new route
	route := &Route{
		ID:          cfg.ID,
		Host:        cfg.Host,
		Path:        cfg.Path,
		Methods:     cfg.Methods,
		Headers:     cfg.Headers,
		QueryParams: cfg.QueryParams,
		Upstream:    cfg.Upstream,
		Plugins:     cfg.Plugins,
		StripPrefix: cfg.StripPrefix,
		Priority:    cfg.Priority,
		Timeout:     config.ParseDuration(cfg.Timeout, 30*time.Second),
	}

	if len(route.Methods) == 0 {
		route.Methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	}

	if err := r.addRouteToSnapshot(newSnapshot, route); err != nil {
		return err
	}

	// Atomically publish the new snapshot
	r.snapshot.Store(newSnapshot)
	return nil
}

// UpdateRoute updates an existing route.
// Uses copy-on-write: builds a new snapshot and atomically swaps it.
func (r *Router) UpdateRoute(id string, cfg config.RouteConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldSnap := r.getSnapshot()

	// Check if route exists
	found := false
	for _, route := range oldSnap.routes {
		if route.ID == id {
			found = true
			break
		}
	}
	if !found {
		return ErrRouteNotFound
	}

	// Build new snapshot with updated route
	newSnapshot := &routeSnapshot{
		trees:  make(map[string]*radixNode),
		routes: make([]*Route, 0, len(oldSnap.routes)),
	}

	for _, oldRoute := range oldSnap.routes {
		if oldRoute.ID == id {
			// Add updated route
			route := &Route{
				ID:          cfg.ID,
				Host:        cfg.Host,
				Path:        cfg.Path,
				Methods:     cfg.Methods,
				Headers:     cfg.Headers,
				QueryParams: cfg.QueryParams,
				Upstream:    cfg.Upstream,
				Plugins:     cfg.Plugins,
				StripPrefix: cfg.StripPrefix,
				Priority:    cfg.Priority,
				Timeout:     config.ParseDuration(cfg.Timeout, 30*time.Second),
			}

			if len(route.Methods) == 0 {
				route.Methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
			}

			if err := r.addRouteToSnapshot(newSnapshot, route); err != nil {
				return err
			}
		} else {
			// Copy existing route
			if err := r.addRouteToSnapshot(newSnapshot, oldRoute); err != nil {
				return err
			}
		}
	}

	// Atomically publish the new snapshot
	r.snapshot.Store(newSnapshot)
	return nil
}

// DeleteRoute removes a route by ID.
// Uses copy-on-write: builds a new snapshot and atomically swaps it.
func (r *Router) DeleteRoute(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldSnap := r.getSnapshot()

	// Check if route exists
	found := false
	for _, route := range oldSnap.routes {
		if route.ID == id {
			found = true
			break
		}
	}
	if !found {
		return ErrRouteNotFound
	}

	// Build new snapshot without the deleted route
	newSnapshot := &routeSnapshot{
		trees:  make(map[string]*radixNode),
		routes: make([]*Route, 0, len(oldSnap.routes)-1),
	}

	for _, oldRoute := range oldSnap.routes {
		if oldRoute.ID != id {
			if err := r.addRouteToSnapshot(newSnapshot, oldRoute); err != nil {
				return err
			}
		}
	}

	// Atomically publish the new snapshot
	r.snapshot.Store(newSnapshot)
	return nil
}

// SetNotFoundHandler sets the handler for unmatched requests.
// Uses atomic.Value for lock-free reads.
func (r *Router) SetNotFoundHandler(handler http.Handler) {
	r.notFound.Store(handler)
}

// NotFoundHandler returns the not found handler.
// This is lock-free using atomic.Value.
func (r *Router) NotFoundHandler() http.Handler {
	return r.notFound.Load().(http.Handler)
}
