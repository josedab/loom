package edge

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// MiddlewareConfig configures the edge function middleware.
type MiddlewareConfig struct {
	// Runtime is the edge function runtime
	Runtime *Runtime
	// Logger for middleware events
	Logger *slog.Logger
	// OnError is called when a function execution fails
	OnError func(err error, fn *Function, r *http.Request)
}

// Middleware returns HTTP middleware that executes edge functions.
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find matching functions
			functions := cfg.Runtime.MatchFunctions(r)
			if len(functions) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Execute each matching function
			for _, fn := range functions {
				execCtx := &ExecutionContext{
					Request:        r,
					ResponseWriter: w,
					Vars:           make(map[string]string),
					Env:            fn.Env,
					Data:           make(map[string]interface{}),
				}

				result, err := cfg.Runtime.Execute(r.Context(), fn.ID, execCtx)
				if err != nil {
					cfg.Logger.Error("edge function execution failed",
						"function", fn.ID,
						"error", err)
					if cfg.OnError != nil {
						cfg.OnError(err, fn, r)
					}
					continue
				}

				if result.Error != nil {
					cfg.Logger.Error("edge function returned error",
						"function", fn.ID,
						"error", result.Error)
					if cfg.OnError != nil {
						cfg.OnError(result.Error, fn, r)
					}
					continue
				}

				// If function returned a response, write it
				if result.Response {
					for k, v := range result.Headers {
						w.Header().Set(k, v)
					}
					if result.StatusCode > 0 {
						w.WriteHeader(result.StatusCode)
					}
					if len(result.Body) > 0 {
						w.Write(result.Body)
					}
					return
				}

				// If function modified the request, use the modified version
				if result.ModifiedRequest != nil {
					r = result.ModifiedRequest
				}

				cfg.Logger.Debug("edge function executed",
					"function", fn.ID,
					"duration", result.Duration)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Handler returns an HTTP handler that executes a specific function.
func Handler(runtime *Runtime, functionID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		execCtx := &ExecutionContext{
			Request:        r,
			ResponseWriter: w,
			Vars:           make(map[string]string),
			Data:           make(map[string]interface{}),
		}

		fn := runtime.GetFunction(functionID)
		if fn != nil {
			execCtx.Env = fn.Env
		}

		result, err := runtime.Execute(r.Context(), functionID, execCtx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		// Write response
		for k, v := range result.Headers {
			w.Header().Set(k, v)
		}

		if result.StatusCode > 0 {
			w.WriteHeader(result.StatusCode)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if len(result.Body) > 0 {
			w.Write(result.Body)
		}
	})
}

// APIHandler returns an HTTP handler for the edge functions management API.
func (r *Runtime) APIHandler() http.Handler {
	mux := http.NewServeMux()

	// List functions
	mux.HandleFunc("/functions", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET":
			functions := r.ListFunctions()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(functions)

		case "POST":
			var fn Function
			if err := json.NewDecoder(req.Body).Decode(&fn); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := r.RegisterFunction(&fn); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(fn)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Get/update/delete function
	mux.HandleFunc("/functions/", func(w http.ResponseWriter, req *http.Request) {
		id := req.URL.Path[len("/functions/"):]
		if id == "" {
			http.Error(w, "Function ID required", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "GET":
			fn := r.GetFunction(id)
			if fn == nil {
				http.Error(w, "Function not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(fn)

		case "PUT":
			var fn Function
			if err := json.NewDecoder(req.Body).Decode(&fn); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fn.ID = id

			if err := r.RegisterFunction(&fn); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(fn)

		case "DELETE":
			r.UnregisterFunction(id)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Execute function
	mux.HandleFunc("/execute/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := req.URL.Path[len("/execute/"):]
		if id == "" {
			http.Error(w, "Function ID required", http.StatusBadRequest)
			return
		}

		// Parse execution context from body
		var execData struct {
			Request struct {
				Method  string              `json:"method"`
				URL     string              `json:"url"`
				Headers map[string][]string `json:"headers"`
				Body    string              `json:"body"`
			} `json:"request"`
			Vars map[string]string      `json:"vars"`
			Data map[string]interface{} `json:"data"`
		}

		if err := json.NewDecoder(req.Body).Decode(&execData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Build mock request
		mockReq, _ := http.NewRequest(
			execData.Request.Method,
			execData.Request.URL,
			bytes.NewBufferString(execData.Request.Body),
		)
		for k, v := range execData.Request.Headers {
			mockReq.Header[k] = v
		}

		fn := r.GetFunction(id)
		execCtx := &ExecutionContext{
			Request: mockReq,
			Vars:    execData.Vars,
			Data:    execData.Data,
		}
		if fn != nil {
			execCtx.Env = fn.Env
		}

		result, err := r.Execute(req.Context(), id, execCtx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Get runtime stats
	mux.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Stats())
	})

	return mux
}

// ResponseCapture captures response for edge function post-processing.
type ResponseCapture struct {
	http.ResponseWriter
	StatusCode int
	Body       bytes.Buffer
	Headers    http.Header
}

// NewResponseCapture creates a new response capture.
func NewResponseCapture(w http.ResponseWriter) *ResponseCapture {
	return &ResponseCapture{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
		Headers:        make(http.Header),
	}
}

// WriteHeader captures the status code.
func (c *ResponseCapture) WriteHeader(code int) {
	c.StatusCode = code
	// Copy headers before they're written
	for k, v := range c.ResponseWriter.Header() {
		c.Headers[k] = v
	}
}

// Write captures the response body.
func (c *ResponseCapture) Write(b []byte) (int, error) {
	return c.Body.Write(b)
}

// Flush implements http.Flusher.
func (c *ResponseCapture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// PostProcessMiddleware returns middleware that runs edge functions after the response.
func PostProcessMiddleware(cfg MiddlewareConfig, functionIDs ...string) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Capture the response
			capture := NewResponseCapture(w)

			// Execute the upstream handler
			next.ServeHTTP(capture, r)

			// Build response data for edge function
			responseData := map[string]interface{}{
				"status":  capture.StatusCode,
				"headers": capture.Headers,
				"body":    capture.Body.String(),
			}

			// Execute post-processing functions
			for _, fnID := range functionIDs {
				fn := cfg.Runtime.GetFunction(fnID)
				if fn == nil || !fn.Enabled {
					continue
				}

				execCtx := &ExecutionContext{
					Request: r,
					Vars:    make(map[string]string),
					Env:     fn.Env,
					Data: map[string]interface{}{
						"response": responseData,
					},
				}

				result, err := cfg.Runtime.Execute(r.Context(), fnID, execCtx)
				if err != nil {
					cfg.Logger.Error("post-process function failed",
						"function", fnID,
						"error", err)
					continue
				}

				// If function modified the response, update capture
				if result.Response {
					if result.StatusCode > 0 {
						capture.StatusCode = result.StatusCode
					}
					for k, v := range result.Headers {
						capture.Headers.Set(k, v)
					}
					if len(result.Body) > 0 {
						capture.Body.Reset()
						capture.Body.Write(result.Body)
					}
				}
			}

			// Write the final response
			for k, v := range capture.Headers {
				for _, val := range v {
					w.Header().Add(k, val)
				}
			}
			w.WriteHeader(capture.StatusCode)
			io.Copy(w, &capture.Body)
		})
	}
}

// FunctionBuilder provides a fluent API for building edge functions.
type FunctionBuilder struct {
	function *Function
}

// NewFunction creates a new function builder.
func NewFunction(id string) *FunctionBuilder {
	return &FunctionBuilder{
		function: &Function{
			ID:      id,
			Enabled: true,
			Type:    FunctionTypeScript,
			Env:     make(map[string]string),
		},
	}
}

// Name sets the function name.
func (b *FunctionBuilder) Name(name string) *FunctionBuilder {
	b.function.Name = name
	return b
}

// Description sets the function description.
func (b *FunctionBuilder) Description(desc string) *FunctionBuilder {
	b.function.Description = desc
	return b
}

// Type sets the function type.
func (b *FunctionBuilder) Type(t FunctionType) *FunctionBuilder {
	b.function.Type = t
	return b
}

// Code sets the function code.
func (b *FunctionBuilder) Code(code string) *FunctionBuilder {
	b.function.Code = code
	return b
}

// WASM sets the WASM module.
func (b *FunctionBuilder) WASM(module []byte) *FunctionBuilder {
	b.function.Type = FunctionTypeWASM
	b.function.WASMModule = module
	return b
}

// WASMPath sets the path to the WASM file.
func (b *FunctionBuilder) WASMPath(path string) *FunctionBuilder {
	b.function.Type = FunctionTypeWASM
	b.function.WASMPath = path
	return b
}

// OnPath adds a path trigger.
func (b *FunctionBuilder) OnPath(path string, methods ...string) *FunctionBuilder {
	trigger := Trigger{
		Type:    TriggerTypePath,
		Path:    path,
		Methods: methods,
	}
	b.function.Triggers = append(b.function.Triggers, trigger)
	return b
}

// OnEvent adds an event trigger.
func (b *FunctionBuilder) OnEvent(event string) *FunctionBuilder {
	trigger := Trigger{
		Type:  TriggerTypeEvent,
		Event: event,
	}
	b.function.Triggers = append(b.function.Triggers, trigger)
	return b
}

// OnSchedule adds a schedule trigger.
func (b *FunctionBuilder) OnSchedule(cron string) *FunctionBuilder {
	trigger := Trigger{
		Type:     TriggerTypeSchedule,
		Schedule: cron,
	}
	b.function.Triggers = append(b.function.Triggers, trigger)
	return b
}

// Env sets an environment variable.
func (b *FunctionBuilder) Env(key, value string) *FunctionBuilder {
	b.function.Env[key] = value
	return b
}

// Timeout sets the execution timeout.
func (b *FunctionBuilder) Timeout(d time.Duration) *FunctionBuilder {
	b.function.Timeout = d
	return b
}

// Enable enables the function.
func (b *FunctionBuilder) Enable() *FunctionBuilder {
	b.function.Enabled = true
	return b
}

// Disable disables the function.
func (b *FunctionBuilder) Disable() *FunctionBuilder {
	b.function.Enabled = false
	return b
}

// Build returns the built function.
func (b *FunctionBuilder) Build() *Function {
	return b.function
}
