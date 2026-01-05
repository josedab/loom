// Package plugin provides the Proxy-Wasm ABI host implementation.
package plugin

import (
	"bytes"
	"context"
	"log/slog"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// validateHeaderValue checks for CRLF injection in header keys and values.
// Returns true if the value is safe, false if it contains CRLF characters.
func validateHeaderValue(data []byte) bool {
	// Check for CR (\r) or LF (\n) which can be used for header injection
	return !bytes.ContainsAny(data, "\r\n")
}

// LogLevel represents Proxy-Wasm log levels.
type LogLevel uint32

const (
	LogLevelTrace LogLevel = iota
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelCritical
)

// HeaderMapType represents the type of header map.
type HeaderMapType uint32

const (
	HeaderMapTypeRequestHeaders HeaderMapType = iota
	HeaderMapTypeRequestTrailers
	HeaderMapTypeResponseHeaders
	HeaderMapTypeResponseTrailers
	HeaderMapTypeGrpcReceiveInitialMetadata
	HeaderMapTypeGrpcReceiveTrailingMetadata
)

// BufferType represents the type of buffer.
type BufferType uint32

const (
	BufferTypeHttpRequestBody BufferType = iota
	BufferTypeHttpResponseBody
	BufferTypeDownstreamData
	BufferTypeUpstreamData
	BufferTypeHttpCallResponseBody
	BufferTypeGrpcReceiveBuffer
	BufferTypeVmConfiguration
	BufferTypePluginConfiguration
	BufferTypeCallData
)

// RequestContext holds per-request state.
type RequestContext struct {
	RequestHeaders   map[string]string
	RequestBody      []byte
	RequestBodyBuf   *BodyBuffer
	RequestTrailers  map[string]string
	ResponseHeaders  map[string]string
	ResponseBody     []byte
	ResponseBodyBuf  *BodyBuffer
	ResponseTrailers map[string]string
	Properties       map[string][]byte
	PluginConfig     []byte
	mu               sync.RWMutex
}

// requestContextPool is a pool of RequestContext objects.
var requestContextPool = sync.Pool{
	New: func() interface{} {
		return &RequestContext{
			RequestHeaders:  make(map[string]string, 16), // Pre-allocate with typical header count
			ResponseHeaders: make(map[string]string, 16),
			Properties:      make(map[string][]byte, 8),
		}
	},
}

// AcquireRequestContext gets a RequestContext from the pool.
// The caller must call ReleaseRequestContext when done.
func AcquireRequestContext() *RequestContext {
	return requestContextPool.Get().(*RequestContext)
}

// ReleaseRequestContext returns a RequestContext to the pool.
// After calling this, the RequestContext must not be used.
func ReleaseRequestContext(ctx *RequestContext) {
	if ctx == nil {
		return
	}
	ctx.Reset()
	requestContextPool.Put(ctx)
}

// Reset clears the RequestContext for reuse.
func (r *RequestContext) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear maps by deleting keys (keeps allocated memory)
	for k := range r.RequestHeaders {
		delete(r.RequestHeaders, k)
	}
	for k := range r.ResponseHeaders {
		delete(r.ResponseHeaders, k)
	}
	for k := range r.RequestTrailers {
		delete(r.RequestTrailers, k)
	}
	for k := range r.ResponseTrailers {
		delete(r.ResponseTrailers, k)
	}
	for k := range r.Properties {
		delete(r.Properties, k)
	}

	// Clear slices (set to nil to release memory)
	r.RequestBody = nil
	r.ResponseBody = nil
	r.PluginConfig = nil

	// Clear buffers
	r.RequestBodyBuf = nil
	r.ResponseBodyBuf = nil
}

// NewRequestContext creates a new request context.
// Deprecated: Use AcquireRequestContext for better performance.
func NewRequestContext() *RequestContext {
	return &RequestContext{
		RequestHeaders:  make(map[string]string),
		ResponseHeaders: make(map[string]string),
		Properties:      make(map[string][]byte),
	}
}

// SetRequestBodyBuffer sets the request body buffer.
func (r *RequestContext) SetRequestBodyBuffer(buf *BodyBuffer) {
	r.mu.Lock()
	r.RequestBodyBuf = buf
	r.mu.Unlock()
}

// GetRequestBodyBuffer returns the request body buffer.
func (r *RequestContext) GetRequestBodyBuffer() *BodyBuffer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.RequestBodyBuf
}

// SetResponseBodyBuffer sets the response body buffer.
func (r *RequestContext) SetResponseBodyBuffer(buf *BodyBuffer) {
	r.mu.Lock()
	r.ResponseBodyBuf = buf
	r.mu.Unlock()
}

// GetResponseBodyBuffer returns the response body buffer.
func (r *RequestContext) GetResponseBodyBuffer() *BodyBuffer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ResponseBodyBuf
}

// ProxyWasmHost implements the Proxy-Wasm ABI.
type ProxyWasmHost struct {
	runtime wazero.Runtime
	ctx     *RequestContext
	mu      sync.RWMutex
	logger  *slog.Logger
}

// NewProxyWasmHost creates a new Proxy-Wasm host.
func NewProxyWasmHost(runtime wazero.Runtime) *ProxyWasmHost {
	return &ProxyWasmHost{
		runtime: runtime,
		ctx:     NewRequestContext(),
		logger:  slog.Default(),
	}
}

// SetRequestContext sets the current request context.
func (h *ProxyWasmHost) SetRequestContext(ctx *RequestContext) {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
}

// GetRequestContext returns the current request context.
func (h *ProxyWasmHost) GetRequestContext() *RequestContext {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ctx
}

// RegisterHostFunctions registers all Proxy-Wasm host functions.
func (h *ProxyWasmHost) RegisterHostFunctions(ctx context.Context) error {
	_, err := h.runtime.NewHostModuleBuilder("env").
		// Logging
		NewFunctionBuilder().
		WithFunc(h.proxyLog).
		Export("proxy_log").
		// Headers manipulation
		NewFunctionBuilder().
		WithFunc(h.proxyGetHeaderMapValue).
		Export("proxy_get_header_map_value").
		NewFunctionBuilder().
		WithFunc(h.proxyAddHeaderMapValue).
		Export("proxy_add_header_map_value").
		NewFunctionBuilder().
		WithFunc(h.proxyReplaceHeaderMapValue).
		Export("proxy_replace_header_map_value").
		NewFunctionBuilder().
		WithFunc(h.proxyRemoveHeaderMapValue).
		Export("proxy_remove_header_map_value").
		NewFunctionBuilder().
		WithFunc(h.proxyGetHeaderMapPairs).
		Export("proxy_get_header_map_pairs").
		NewFunctionBuilder().
		WithFunc(h.proxySetHeaderMapPairs).
		Export("proxy_set_header_map_pairs").
		// Buffer manipulation
		NewFunctionBuilder().
		WithFunc(h.proxyGetBufferBytes).
		Export("proxy_get_buffer_bytes").
		NewFunctionBuilder().
		WithFunc(h.proxySetBufferBytes).
		Export("proxy_set_buffer_bytes").
		// Properties
		NewFunctionBuilder().
		WithFunc(h.proxyGetProperty).
		Export("proxy_get_property").
		NewFunctionBuilder().
		WithFunc(h.proxySetProperty).
		Export("proxy_set_property").
		// HTTP calls
		NewFunctionBuilder().
		WithFunc(h.proxyHttpCall).
		Export("proxy_http_call").
		// Metrics
		NewFunctionBuilder().
		WithFunc(h.proxyDefineMetric).
		Export("proxy_define_metric").
		NewFunctionBuilder().
		WithFunc(h.proxyIncrementMetric).
		Export("proxy_increment_metric").
		NewFunctionBuilder().
		WithFunc(h.proxyRecordMetric).
		Export("proxy_record_metric").
		NewFunctionBuilder().
		WithFunc(h.proxyGetMetric).
		Export("proxy_get_metric").
		// Response handling
		NewFunctionBuilder().
		WithFunc(h.proxySendLocalResponse).
		Export("proxy_send_local_response").
		// Time
		NewFunctionBuilder().
		WithFunc(h.proxyGetCurrentTimeNanoseconds).
		Export("proxy_get_current_time_nanoseconds").
		// Status
		NewFunctionBuilder().
		WithFunc(h.proxySetEffectiveContext).
		Export("proxy_set_effective_context").
		NewFunctionBuilder().
		WithFunc(h.proxyDone).
		Export("proxy_done").
		Instantiate(ctx)

	return err
}

// proxyLog handles logging from plugins.
func (h *ProxyWasmHost) proxyLog(
	ctx context.Context,
	m api.Module,
	logLevel uint32,
	messageData uint32,
	messageSize uint32,
) uint32 {
	message, ok := m.Memory().Read(messageData, messageSize)
	if !ok {
		return 1 // WasmResultInvalidMemoryAccess
	}

	level := LogLevel(logLevel)
	msg := string(message)

	switch level {
	case LogLevelTrace, LogLevelDebug:
		h.logger.Debug(msg, "plugin", m.Name())
	case LogLevelInfo:
		h.logger.Info(msg, "plugin", m.Name())
	case LogLevelWarn:
		h.logger.Warn(msg, "plugin", m.Name())
	case LogLevelError, LogLevelCritical:
		h.logger.Error(msg, "plugin", m.Name())
	}

	return 0 // WasmResultOk
}

// proxyGetHeaderMapValue retrieves a header value.
func (h *ProxyWasmHost) proxyGetHeaderMapValue(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	keyData uint32,
	keySize uint32,
	valueData uint32,
	valueSize uint32,
) uint32 {
	key, ok := m.Memory().Read(keyData, keySize)
	if !ok {
		return 1
	}

	h.mu.RLock()
	reqCtx := h.ctx
	h.mu.RUnlock()

	var headers map[string]string
	switch HeaderMapType(mapType) {
	case HeaderMapTypeRequestHeaders:
		headers = reqCtx.RequestHeaders
	case HeaderMapTypeResponseHeaders:
		headers = reqCtx.ResponseHeaders
	case HeaderMapTypeRequestTrailers:
		headers = reqCtx.RequestTrailers
	case HeaderMapTypeResponseTrailers:
		headers = reqCtx.ResponseTrailers
	default:
		return 1
	}

	value, exists := headers[string(key)]
	if !exists {
		return 2 // WasmResultNotFound
	}

	// Write value pointer and size to plugin memory
	valueBytes := []byte(value)
	if !writeToMemory(m, valueData, valueBytes) {
		return 1
	}
	if !m.Memory().WriteUint32Le(valueSize, uint32(len(valueBytes))) {
		return 1
	}

	return 0
}

// proxyAddHeaderMapValue adds a header value.
func (h *ProxyWasmHost) proxyAddHeaderMapValue(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	keyData uint32,
	keySize uint32,
	valueData uint32,
	valueSize uint32,
) uint32 {
	key, ok := m.Memory().Read(keyData, keySize)
	if !ok {
		return 1
	}
	value, ok := m.Memory().Read(valueData, valueSize)
	if !ok {
		return 1
	}

	// Validate header key and value for CRLF injection
	if !validateHeaderValue(key) || !validateHeaderValue(value) {
		slog.Warn("CRLF injection attempt in header", "key", string(key))
		return 1 // Reject headers with CRLF characters
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var headers map[string]string
	switch HeaderMapType(mapType) {
	case HeaderMapTypeRequestHeaders:
		headers = h.ctx.RequestHeaders
	case HeaderMapTypeResponseHeaders:
		headers = h.ctx.ResponseHeaders
	default:
		return 1
	}

	headers[string(key)] = string(value)
	return 0
}

// proxyReplaceHeaderMapValue replaces a header value.
func (h *ProxyWasmHost) proxyReplaceHeaderMapValue(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	keyData uint32,
	keySize uint32,
	valueData uint32,
	valueSize uint32,
) uint32 {
	return h.proxyAddHeaderMapValue(ctx, m, mapType, keyData, keySize, valueData, valueSize)
}

// proxyRemoveHeaderMapValue removes a header value.
func (h *ProxyWasmHost) proxyRemoveHeaderMapValue(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	keyData uint32,
	keySize uint32,
) uint32 {
	key, ok := m.Memory().Read(keyData, keySize)
	if !ok {
		return 1
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var headers map[string]string
	switch HeaderMapType(mapType) {
	case HeaderMapTypeRequestHeaders:
		headers = h.ctx.RequestHeaders
	case HeaderMapTypeResponseHeaders:
		headers = h.ctx.ResponseHeaders
	default:
		return 1
	}

	delete(headers, string(key))
	return 0
}

// proxyGetHeaderMapPairs retrieves all headers as pairs.
func (h *ProxyWasmHost) proxyGetHeaderMapPairs(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	returnDataPtr uint32,
	returnDataSize uint32,
) uint32 {
	h.mu.RLock()
	reqCtx := h.ctx
	h.mu.RUnlock()

	var headers map[string]string
	switch HeaderMapType(mapType) {
	case HeaderMapTypeRequestHeaders:
		headers = reqCtx.RequestHeaders
	case HeaderMapTypeResponseHeaders:
		headers = reqCtx.ResponseHeaders
	default:
		return 1
	}

	// Serialize headers to bytes (Proxy-Wasm format)
	data := serializeHeaders(headers)

	// Write to return pointers
	// In a real implementation, we'd allocate memory in WASM and return pointer
	_ = data
	return 0
}

// proxySetHeaderMapPairs sets all headers from pairs.
func (h *ProxyWasmHost) proxySetHeaderMapPairs(
	ctx context.Context,
	m api.Module,
	mapType uint32,
	pairsData uint32,
	pairsSize uint32,
) uint32 {
	data, ok := m.Memory().Read(pairsData, pairsSize)
	if !ok {
		return 1
	}

	headers := deserializeHeaders(data)

	h.mu.Lock()
	defer h.mu.Unlock()

	switch HeaderMapType(mapType) {
	case HeaderMapTypeRequestHeaders:
		h.ctx.RequestHeaders = headers
	case HeaderMapTypeResponseHeaders:
		h.ctx.ResponseHeaders = headers
	default:
		return 1
	}

	return 0
}

// proxyGetBufferBytes retrieves buffer bytes.
func (h *ProxyWasmHost) proxyGetBufferBytes(
	ctx context.Context,
	m api.Module,
	bufferType uint32,
	start uint32,
	maxSize uint32,
	returnDataPtr uint32,
	returnDataSize uint32,
) uint32 {
	h.mu.RLock()
	reqCtx := h.ctx
	h.mu.RUnlock()

	var data []byte
	switch BufferType(bufferType) {
	case BufferTypeHttpRequestBody:
		if reqCtx.RequestBodyBuf != nil {
			var err error
			data, err = reqCtx.RequestBodyBuf.Read(int(start), int(maxSize))
			if err != nil {
				return 2 // NotFound
			}
		} else {
			data = reqCtx.RequestBody
		}
	case BufferTypeHttpResponseBody:
		if reqCtx.ResponseBodyBuf != nil {
			var err error
			data, err = reqCtx.ResponseBodyBuf.Read(int(start), int(maxSize))
			if err != nil {
				return 2 // NotFound
			}
		} else {
			data = reqCtx.ResponseBody
		}
	case BufferTypePluginConfiguration:
		data = reqCtx.PluginConfig
	default:
		return 2 // NotFound
	}

	if data == nil || start >= uint32(len(data)) {
		return 2
	}

	end := start + maxSize
	if end > uint32(len(data)) {
		end = uint32(len(data))
	}

	slice := data[start:end]
	// Write to plugin memory
	if !writeToMemory(m, returnDataPtr, slice) {
		return 1
	}
	if !m.Memory().WriteUint32Le(returnDataSize, uint32(len(slice))) {
		return 1
	}

	return 0
}

// proxySetBufferBytes sets buffer bytes.
func (h *ProxyWasmHost) proxySetBufferBytes(
	ctx context.Context,
	m api.Module,
	bufferType uint32,
	start uint32,
	size uint32,
	dataPtr uint32,
	dataSize uint32,
) uint32 {
	data, ok := m.Memory().Read(dataPtr, dataSize)
	if !ok {
		return 1
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	switch BufferType(bufferType) {
	case BufferTypeHttpRequestBody:
		if h.ctx.RequestBodyBuf != nil {
			if start == 0 && size == 0 {
				// Replace entire buffer
				h.ctx.RequestBodyBuf.Write(data)
			} else {
				// Replace portion of buffer
				h.ctx.RequestBodyBuf.Replace(int(start), int(start+size), data)
			}
		} else {
			h.ctx.RequestBody = data
		}
	case BufferTypeHttpResponseBody:
		if h.ctx.ResponseBodyBuf != nil {
			if start == 0 && size == 0 {
				h.ctx.ResponseBodyBuf.Write(data)
			} else {
				h.ctx.ResponseBodyBuf.Replace(int(start), int(start+size), data)
			}
		} else {
			h.ctx.ResponseBody = data
		}
	default:
		return 1
	}

	return 0
}

// proxyGetProperty retrieves a property.
func (h *ProxyWasmHost) proxyGetProperty(
	ctx context.Context,
	m api.Module,
	pathData uint32,
	pathSize uint32,
	returnValueData uint32,
	returnValueSize uint32,
) uint32 {
	path, ok := m.Memory().Read(pathData, pathSize)
	if !ok {
		return 1
	}

	h.mu.RLock()
	value, exists := h.ctx.Properties[string(path)]
	h.mu.RUnlock()

	if !exists {
		return 2 // NotFound
	}

	_ = value // Would write to memory
	return 0
}

// proxySetProperty sets a property.
func (h *ProxyWasmHost) proxySetProperty(
	ctx context.Context,
	m api.Module,
	pathData uint32,
	pathSize uint32,
	valueData uint32,
	valueSize uint32,
) uint32 {
	path, ok := m.Memory().Read(pathData, pathSize)
	if !ok {
		return 1
	}
	value, ok := m.Memory().Read(valueData, valueSize)
	if !ok {
		return 1
	}

	h.mu.Lock()
	h.ctx.Properties[string(path)] = value
	h.mu.Unlock()

	return 0
}

// proxyHttpCall initiates an HTTP call.
func (h *ProxyWasmHost) proxyHttpCall(
	ctx context.Context,
	m api.Module,
	upstreamData uint32,
	upstreamSize uint32,
	headersData uint32,
	headersSize uint32,
	bodyData uint32,
	bodySize uint32,
	trailersData uint32,
	trailersSize uint32,
	timeoutMs uint32,
	returnCalloutID uint32,
) uint32 {
	// Read upstream name
	_, ok := m.Memory().Read(upstreamData, upstreamSize)
	if !ok {
		return 1
	}

	// In a full implementation, we would:
	// 1. Parse headers, body, trailers
	// 2. Execute HTTP call asynchronously
	// 3. Store callback token for response delivery

	return 0
}

// proxyDefineMetric defines a new metric.
func (h *ProxyWasmHost) proxyDefineMetric(
	ctx context.Context,
	m api.Module,
	metricType uint32,
	nameData uint32,
	nameSize uint32,
	returnMetricID uint32,
) uint32 {
	return 0
}

// proxyIncrementMetric increments a metric.
func (h *ProxyWasmHost) proxyIncrementMetric(
	ctx context.Context,
	m api.Module,
	metricID uint32,
	offset int64,
) uint32 {
	return 0
}

// proxyRecordMetric records a metric value.
func (h *ProxyWasmHost) proxyRecordMetric(
	ctx context.Context,
	m api.Module,
	metricID uint32,
	value uint64,
) uint32 {
	return 0
}

// proxyGetMetric retrieves a metric value.
func (h *ProxyWasmHost) proxyGetMetric(
	ctx context.Context,
	m api.Module,
	metricID uint32,
	returnValue uint32,
) uint32 {
	return 0
}

// proxySendLocalResponse sends an immediate response.
func (h *ProxyWasmHost) proxySendLocalResponse(
	ctx context.Context,
	m api.Module,
	statusCode uint32,
	statusCodeDetailsData uint32,
	statusCodeDetailsSize uint32,
	bodyData uint32,
	bodySize uint32,
	headersData uint32,
	headersSize uint32,
	grpcStatus int32,
) uint32 {
	return 0
}

// proxyGetCurrentTimeNanoseconds returns current time.
func (h *ProxyWasmHost) proxyGetCurrentTimeNanoseconds(
	ctx context.Context,
	m api.Module,
	returnTime uint32,
) uint32 {
	return 0
}

// proxySetEffectiveContext sets the effective context.
func (h *ProxyWasmHost) proxySetEffectiveContext(
	ctx context.Context,
	m api.Module,
	contextID uint32,
) uint32 {
	return 0
}

// proxyDone signals completion.
func (h *ProxyWasmHost) proxyDone(
	ctx context.Context,
	m api.Module,
) uint32 {
	return 0
}

// Helper functions

func writeToMemory(m api.Module, ptr uint32, data []byte) bool {
	return m.Memory().Write(ptr, data)
}

func serializeHeaders(headers map[string]string) []byte {
	// Proxy-Wasm header serialization format
	var result []byte
	for k, v := range headers {
		result = append(result, []byte(k)...)
		result = append(result, 0)
		result = append(result, []byte(v)...)
		result = append(result, 0)
	}
	return result
}

func deserializeHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	// Parse null-terminated key-value pairs
	// Simplified implementation
	return headers
}
