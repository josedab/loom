// Package gatewayapi provides Kubernetes Gateway API conformance for Loom.
package gatewayapi

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// FilterChain represents a chain of filters to apply to requests/responses.
type FilterChain struct {
	filters       []HTTPRouteFilter
	matchedPrefix string // The prefix that was matched for ReplacePrefixMatch operations
}

// NewFilterChain creates a new filter chain from HTTPRoute filters.
func NewFilterChain(filters []HTTPRouteFilter) *FilterChain {
	return &FilterChain{filters: filters}
}

// SetMatchedPrefix sets the matched prefix for ReplacePrefixMatch operations.
func (fc *FilterChain) SetMatchedPrefix(prefix string) {
	fc.matchedPrefix = prefix
}

// ProcessRequest applies request filters and returns whether to continue processing.
// Returns the modified request, a redirect response (if applicable), and whether to continue.
func (fc *FilterChain) ProcessRequest(r *http.Request) (*http.Request, *RedirectResponse, bool) {
	for _, filter := range fc.filters {
		switch filter.Type {
		case FilterTypeRequestHeaderModifier:
			if filter.RequestHeaderModifier != nil {
				r = applyRequestHeaderModifier(r, filter.RequestHeaderModifier)
			}

		case FilterTypeURLRewrite:
			if filter.URLRewrite != nil {
				r = applyURLRewrite(r, filter.URLRewrite, fc.matchedPrefix)
			}

		case FilterTypeRequestRedirect:
			if filter.RequestRedirect != nil {
				redirect := applyRequestRedirect(r, filter.RequestRedirect)
				return r, redirect, false
			}
		}
	}
	return r, nil, true
}

// ProcessResponse applies response filters.
func (fc *FilterChain) ProcessResponse(w http.ResponseWriter) {
	for _, filter := range fc.filters {
		switch filter.Type {
		case FilterTypeResponseHeaderModifier:
			if filter.ResponseHeaderModifier != nil {
				applyResponseHeaderModifier(w, filter.ResponseHeaderModifier)
			}
		}
	}
}

// RedirectResponse represents a redirect response to send.
type RedirectResponse struct {
	StatusCode int
	Location   string
}

// applyRequestHeaderModifier modifies request headers.
func applyRequestHeaderModifier(r *http.Request, modifier *HTTPHeaderFilter) *http.Request {
	// Clone the request to avoid modifying the original
	r2 := r.Clone(r.Context())

	// Set headers (replace existing)
	for _, h := range modifier.Set {
		r2.Header.Set(h.Name, h.Value)
	}

	// Add headers (append to existing)
	for _, h := range modifier.Add {
		r2.Header.Add(h.Name, h.Value)
	}

	// Remove headers
	for _, name := range modifier.Remove {
		r2.Header.Del(name)
	}

	return r2
}

// applyResponseHeaderModifier modifies response headers.
func applyResponseHeaderModifier(w http.ResponseWriter, modifier *HTTPHeaderFilter) {
	// Set headers (replace existing)
	for _, h := range modifier.Set {
		w.Header().Set(h.Name, h.Value)
	}

	// Add headers (append to existing)
	for _, h := range modifier.Add {
		w.Header().Add(h.Name, h.Value)
	}

	// Remove headers
	for _, name := range modifier.Remove {
		w.Header().Del(name)
	}
}

// applyURLRewrite rewrites the request URL.
func applyURLRewrite(r *http.Request, rewrite *HTTPURLRewriteFilter, matchedPrefix string) *http.Request {
	r2 := r.Clone(r.Context())

	// Rewrite hostname
	if rewrite.Hostname != nil {
		r2.Host = *rewrite.Hostname
		r2.URL.Host = *rewrite.Hostname
	}

	// Rewrite path
	if rewrite.Path != nil {
		r2.URL.Path = applyPathModifier(r2.URL.Path, rewrite.Path, matchedPrefix)
	}

	return r2
}

// applyPathModifier applies a path modification.
func applyPathModifier(originalPath string, modifier *HTTPPathModifier, matchedPrefix string) string {
	switch modifier.Type {
	case PathModifierReplaceFullPath:
		if modifier.ReplaceFullPath != nil {
			return *modifier.ReplaceFullPath
		}

	case PathModifierReplacePrefixMatch:
		if modifier.ReplacePrefixMatch != nil {
			// Replace the matched prefix with the replacement
			replacement := *modifier.ReplacePrefixMatch
			if strings.HasPrefix(originalPath, matchedPrefix) {
				suffix := strings.TrimPrefix(originalPath, matchedPrefix)
				// Ensure proper path joining
				if replacement == "/" {
					return "/" + strings.TrimPrefix(suffix, "/")
				}
				replacement = strings.TrimSuffix(replacement, "/")
				suffix = strings.TrimPrefix(suffix, "/")
				if suffix == "" {
					return replacement
				}
				return replacement + "/" + suffix
			}
		}
	}

	return originalPath
}

// applyRequestRedirect generates a redirect response.
func applyRequestRedirect(r *http.Request, redirect *HTTPRequestRedirectFilter) *RedirectResponse {
	// Build redirect URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if redirect.Scheme != nil {
		scheme = *redirect.Scheme
	}

	hostname := r.Host
	if redirect.Hostname != nil {
		hostname = *redirect.Hostname
	}

	// Handle port
	if redirect.Port != nil {
		// Remove existing port from hostname
		if colonIdx := strings.LastIndex(hostname, ":"); colonIdx != -1 {
			hostname = hostname[:colonIdx]
		}
		hostname = hostname + ":" + strconv.Itoa(int(*redirect.Port))
	}

	path := r.URL.Path
	if redirect.Path != nil {
		path = applyPathModifier(r.URL.Path, redirect.Path, r.URL.Path)
	}

	// Build the redirect URL
	redirectURL := &url.URL{
		Scheme:   scheme,
		Host:     hostname,
		Path:     path,
		RawQuery: r.URL.RawQuery,
	}

	statusCode := http.StatusFound // 302 by default
	if redirect.StatusCode != nil {
		statusCode = *redirect.StatusCode
	}

	return &RedirectResponse{
		StatusCode: statusCode,
		Location:   redirectURL.String(),
	}
}

// FilterMiddleware creates HTTP middleware for applying Gateway API filters.
type FilterMiddleware struct {
	controller *Controller
}

// NewFilterMiddleware creates a new filter middleware.
func NewFilterMiddleware(controller *Controller) *FilterMiddleware {
	return &FilterMiddleware{controller: controller}
}

// Handler returns an HTTP handler that applies filters.
func (fm *FilterMiddleware) Handler(routeMatch *RouteMatch) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create filter chain from route match
			chain := NewFilterChain(routeMatch.Filters)

			// Process request filters
			modifiedReq, redirect, continueProcessing := chain.ProcessRequest(r)
			if !continueProcessing {
				// Send redirect response
				if redirect != nil {
					w.Header().Set("Location", redirect.Location)
					w.WriteHeader(redirect.StatusCode)
				}
				return
			}

			// Create a response writer wrapper to capture and modify response headers
			rw := &filterResponseWriter{
				ResponseWriter: w,
				chain:          chain,
				headerWritten:  false,
			}

			// Call next handler with modified request
			next.ServeHTTP(rw, modifiedReq)
		})
	}
}

// filterResponseWriter wraps http.ResponseWriter to apply response filters.
type filterResponseWriter struct {
	http.ResponseWriter
	chain         *FilterChain
	headerWritten bool
}

// WriteHeader applies response filters before writing the status code.
func (rw *filterResponseWriter) WriteHeader(statusCode int) {
	if !rw.headerWritten {
		rw.chain.ProcessResponse(rw.ResponseWriter)
		rw.headerWritten = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers are processed before writing body.
func (rw *filterResponseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.chain.ProcessResponse(rw.ResponseWriter)
		rw.headerWritten = true
	}
	return rw.ResponseWriter.Write(b)
}

// PathMatcher provides enhanced path matching capabilities.
type PathMatcher struct {
	pathType PathMatchType
	value    string
	regex    *regexp.Regexp
}

// NewPathMatcher creates a new path matcher.
func NewPathMatcher(pathMatch *HTTPPathMatch) (*PathMatcher, error) {
	if pathMatch == nil || pathMatch.Value == nil {
		return &PathMatcher{
			pathType: PathMatchPathPrefix,
			value:    "/",
		}, nil
	}

	pm := &PathMatcher{
		value: *pathMatch.Value,
	}

	if pathMatch.Type != nil {
		pm.pathType = *pathMatch.Type
	} else {
		pm.pathType = PathMatchPathPrefix
	}

	// Compile regex if needed
	if pm.pathType == PathMatchRegularExpression {
		re, err := regexp.Compile(pm.value)
		if err != nil {
			return nil, err
		}
		pm.regex = re
	}

	return pm, nil
}

// Match checks if a path matches.
func (pm *PathMatcher) Match(path string) bool {
	switch pm.pathType {
	case PathMatchExact:
		return path == pm.value

	case PathMatchPathPrefix:
		if pm.value == "/" {
			return true
		}
		// Ensure proper prefix matching (don't match /foobar for prefix /foo)
		if path == pm.value {
			return true
		}
		if strings.HasPrefix(path, pm.value) {
			// Check that the next character is / or end of string
			remainder := path[len(pm.value):]
			return len(remainder) == 0 || remainder[0] == '/'
		}
		return false

	case PathMatchRegularExpression:
		if pm.regex != nil {
			return pm.regex.MatchString(path)
		}
		return false

	default:
		return false
	}
}

// MatchedPrefix returns the matched prefix for ReplacePrefixMatch operations.
func (pm *PathMatcher) MatchedPrefix() string {
	if pm.pathType == PathMatchPathPrefix {
		return pm.value
	}
	return ""
}

// HeaderMatcher provides header matching capabilities.
type HeaderMatcher struct {
	name      string
	matchType HeaderMatchType
	value     string
	regex     *regexp.Regexp
}

// NewHeaderMatcher creates a new header matcher.
func NewHeaderMatcher(headerMatch *HTTPHeaderMatch) (*HeaderMatcher, error) {
	hm := &HeaderMatcher{
		name:  headerMatch.Name,
		value: headerMatch.Value,
	}

	if headerMatch.Type != nil {
		hm.matchType = *headerMatch.Type
	} else {
		hm.matchType = HeaderMatchExact
	}

	if hm.matchType == HeaderMatchRegularExpression {
		re, err := regexp.Compile(hm.value)
		if err != nil {
			return nil, err
		}
		hm.regex = re
	}

	return hm, nil
}

// Match checks if a header value matches.
func (hm *HeaderMatcher) Match(headerValue string) bool {
	switch hm.matchType {
	case HeaderMatchExact:
		return headerValue == hm.value

	case HeaderMatchRegularExpression:
		if hm.regex != nil {
			return hm.regex.MatchString(headerValue)
		}
		return false

	default:
		return false
	}
}

// QueryParamMatcher provides query parameter matching capabilities.
type QueryParamMatcher struct {
	name      string
	matchType QueryParamMatchType
	value     string
	regex     *regexp.Regexp
}

// NewQueryParamMatcher creates a new query parameter matcher.
func NewQueryParamMatcher(qpMatch *HTTPQueryParamMatch) (*QueryParamMatcher, error) {
	qm := &QueryParamMatcher{
		name:  qpMatch.Name,
		value: qpMatch.Value,
	}

	if qpMatch.Type != nil {
		qm.matchType = *qpMatch.Type
	} else {
		qm.matchType = QueryParamMatchExact
	}

	if qm.matchType == QueryParamMatchRegularExpression {
		re, err := regexp.Compile(qm.value)
		if err != nil {
			return nil, err
		}
		qm.regex = re
	}

	return qm, nil
}

// Match checks if a query parameter value matches.
func (qm *QueryParamMatcher) Match(paramValue string) bool {
	switch qm.matchType {
	case QueryParamMatchExact:
		return paramValue == qm.value

	case QueryParamMatchRegularExpression:
		if qm.regex != nil {
			return qm.regex.MatchString(paramValue)
		}
		return false

	default:
		return false
	}
}

// TrafficSplitter handles weighted traffic splitting across backends.
type TrafficSplitter struct {
	backends []weightedBackend
	total    int32
}

type weightedBackend struct {
	ref    HTTPBackendRef
	weight int32
}

// NewTrafficSplitter creates a traffic splitter from backend refs.
func NewTrafficSplitter(backends []HTTPBackendRef) *TrafficSplitter {
	ts := &TrafficSplitter{
		backends: make([]weightedBackend, 0, len(backends)),
	}

	for _, b := range backends {
		weight := int32(1) // Default weight
		if b.Weight != nil {
			weight = *b.Weight
		}
		ts.backends = append(ts.backends, weightedBackend{
			ref:    b,
			weight: weight,
		})
		ts.total += weight
	}

	return ts
}

// Select chooses a backend based on weighted random selection.
// The random value should be in range [0, total weight).
func (ts *TrafficSplitter) Select(randomValue int32) *HTTPBackendRef {
	if len(ts.backends) == 0 {
		return nil
	}

	if ts.total == 0 {
		// All weights are 0, return first backend
		return &ts.backends[0].ref
	}

	// Normalize random value to be within range
	randomValue = randomValue % ts.total
	if randomValue < 0 {
		randomValue += ts.total
	}

	var cumulative int32
	for _, b := range ts.backends {
		cumulative += b.weight
		if randomValue < cumulative {
			ref := b.ref
			return &ref
		}
	}

	// Fallback to last backend
	return &ts.backends[len(ts.backends)-1].ref
}

// TotalWeight returns the total weight of all backends.
func (ts *TrafficSplitter) TotalWeight() int32 {
	return ts.total
}

// BackendCount returns the number of backends.
func (ts *TrafficSplitter) BackendCount() int {
	return len(ts.backends)
}
