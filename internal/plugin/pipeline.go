// Package plugin provides the plugin execution pipeline.
package plugin

import (
	"context"
	"net/http"
	"sort"
	"sync"
)

// Pipeline manages plugin execution order and chaining.
type Pipeline struct {
	runtime *Runtime
	chains  map[string][]*PluginChainEntry // route ID -> plugin chain
	mu      sync.RWMutex
}

// PluginChainEntry represents a plugin in the chain.
type PluginChainEntry struct {
	Name     string
	Priority int
	Phase    ExecutionPhase
}

// NewPipeline creates a new plugin pipeline.
func NewPipeline(runtime *Runtime) *Pipeline {
	return &Pipeline{
		runtime: runtime,
		chains:  make(map[string][]*PluginChainEntry),
	}
}

// BuildChain builds a plugin chain for a route.
func (p *Pipeline) BuildChain(routeID string, pluginNames []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	chain := make([]*PluginChainEntry, 0, len(pluginNames))

	for _, name := range pluginNames {
		plugin, ok := p.runtime.GetPlugin(name)
		if !ok {
			continue
		}

		chain = append(chain, &PluginChainEntry{
			Name:     name,
			Priority: plugin.Config.Priority,
			Phase:    plugin.Config.Phase,
		})
	}

	// Sort by priority (higher first)
	sort.Slice(chain, func(i, j int) bool {
		return chain[i].Priority > chain[j].Priority
	})

	p.chains[routeID] = chain
}

// GetChain returns the plugin chain for a route.
func (p *Pipeline) GetChain(routeID string) []*PluginChainEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.chains[routeID]
}

// ExecuteRequestPhase executes all request phase plugins.
func (p *Pipeline) ExecuteRequestPhase(
	ctx context.Context,
	routeID string,
	phase ExecutionPhase,
	reqCtx *RequestContext,
) (*PipelineResult, error) {
	chain := p.GetChain(routeID)
	if len(chain) == 0 {
		return &PipelineResult{Continue: true}, nil
	}

	result := &PipelineResult{Continue: true}

	for _, entry := range chain {
		if entry.Phase != phase {
			continue
		}

		resp, err := p.runtime.ExecutePlugin(ctx, entry.Name, phase, reqCtx)
		if err != nil {
			return nil, err
		}

		switch resp.Action {
		case ActionPause:
			result.Continue = false
			result.ImmediateResponse = resp.ImmediateResponse
			return result, nil
		case ActionEndStream:
			result.Continue = false
			return result, nil
		}
	}

	return result, nil
}

// ExecuteResponsePhase executes all response phase plugins.
func (p *Pipeline) ExecuteResponsePhase(
	ctx context.Context,
	routeID string,
	phase ExecutionPhase,
	reqCtx *RequestContext,
) (*PipelineResult, error) {
	chain := p.GetChain(routeID)
	if len(chain) == 0 {
		return &PipelineResult{Continue: true}, nil
	}

	result := &PipelineResult{Continue: true}

	// Execute in reverse order for response phases
	for i := len(chain) - 1; i >= 0; i-- {
		entry := chain[i]
		if entry.Phase != phase {
			continue
		}

		resp, err := p.runtime.ExecutePlugin(ctx, entry.Name, phase, reqCtx)
		if err != nil {
			return nil, err
		}

		switch resp.Action {
		case ActionPause:
			result.Continue = false
			result.ImmediateResponse = resp.ImmediateResponse
			return result, nil
		case ActionEndStream:
			result.Continue = false
			return result, nil
		}
	}

	return result, nil
}

// PipelineResult contains the result of pipeline execution.
type PipelineResult struct {
	Continue          bool
	ImmediateResponse *ImmediateResponse
}

// Middleware returns an HTTP middleware for the plugin pipeline.
func (p *Pipeline) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get route ID from context
			routeID, ok := r.Context().Value(routeIDKey).(string)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Create request context
			reqCtx := NewRequestContext()
			for k, v := range r.Header {
				if len(v) > 0 {
					reqCtx.RequestHeaders[k] = v[0]
				}
			}

			// Execute request headers phase
			result, err := p.ExecuteRequestPhase(
				r.Context(),
				routeID,
				PhaseOnRequestHeaders,
				reqCtx,
			)
			if err != nil {
				http.Error(w, "Plugin error", http.StatusInternalServerError)
				return
			}

			if !result.Continue {
				if result.ImmediateResponse != nil {
					for k, v := range result.ImmediateResponse.Headers {
						w.Header().Set(k, v)
					}
					w.WriteHeader(result.ImmediateResponse.StatusCode)
					w.Write(result.ImmediateResponse.Body)
					return
				}
				return
			}

			// Apply modified headers
			for k, v := range reqCtx.RequestHeaders {
				r.Header.Set(k, v)
			}

			// Create response wrapper to capture response
			rw := &responseWriter{
				ResponseWriter: w,
				reqCtx:         reqCtx,
			}

			// Continue to next handler
			next.ServeHTTP(rw, r)

			// Execute log phase
			_, _ = p.ExecuteRequestPhase(
				r.Context(),
				routeID,
				PhaseOnLog,
				reqCtx,
			)
		})
	}
}

type contextKey string

const routeIDKey contextKey = "routeID"

// SetRouteID sets the route ID in the request context.
func SetRouteID(r *http.Request, routeID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), routeIDKey, routeID))
}

// responseWriter wraps http.ResponseWriter to capture response.
type responseWriter struct {
	http.ResponseWriter
	reqCtx     *RequestContext
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.written = true

	// Capture response headers
	for k, v := range rw.Header() {
		if len(v) > 0 {
			rw.reqCtx.ResponseHeaders[k] = v[0]
		}
	}

	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}
