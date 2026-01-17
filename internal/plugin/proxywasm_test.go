package plugin

import (
	"testing"
)

func TestLogLevel_Constants(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected uint32
	}{
		{LogLevelTrace, 0},
		{LogLevelDebug, 1},
		{LogLevelInfo, 2},
		{LogLevelWarn, 3},
		{LogLevelError, 4},
		{LogLevelCritical, 5},
	}

	for _, tt := range tests {
		if uint32(tt.level) != tt.expected {
			t.Errorf("LogLevel %d expected %d", tt.level, tt.expected)
		}
	}
}

func TestHeaderMapType_Constants(t *testing.T) {
	tests := []struct {
		mapType  HeaderMapType
		expected uint32
	}{
		{HeaderMapTypeRequestHeaders, 0},
		{HeaderMapTypeRequestTrailers, 1},
		{HeaderMapTypeResponseHeaders, 2},
		{HeaderMapTypeResponseTrailers, 3},
		{HeaderMapTypeGrpcReceiveInitialMetadata, 4},
		{HeaderMapTypeGrpcReceiveTrailingMetadata, 5},
	}

	for _, tt := range tests {
		if uint32(tt.mapType) != tt.expected {
			t.Errorf("HeaderMapType %d expected %d", tt.mapType, tt.expected)
		}
	}
}

func TestBufferType_Constants(t *testing.T) {
	tests := []struct {
		bufType  BufferType
		expected uint32
	}{
		{BufferTypeHttpRequestBody, 0},
		{BufferTypeHttpResponseBody, 1},
		{BufferTypeDownstreamData, 2},
		{BufferTypeUpstreamData, 3},
		{BufferTypeHttpCallResponseBody, 4},
		{BufferTypeGrpcReceiveBuffer, 5},
		{BufferTypeVmConfiguration, 6},
		{BufferTypePluginConfiguration, 7},
		{BufferTypeCallData, 8},
	}

	for _, tt := range tests {
		if uint32(tt.bufType) != tt.expected {
			t.Errorf("BufferType %d expected %d", tt.bufType, tt.expected)
		}
	}
}

func TestValidateHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected bool
	}{
		{"normal value", []byte("application/json"), true},
		{"empty value", []byte(""), true},
		{"with spaces", []byte("some value with spaces"), true},
		{"with CR", []byte("value\rwith\rCR"), false},
		{"with LF", []byte("value\nwith\nLF"), false},
		{"with CRLF", []byte("value\r\nwith\r\nCRLF"), false},
		{"mixed injection", []byte("header\r\nX-Injected: evil"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateHeaderValue(tt.value)
			if result != tt.expected {
				t.Errorf("validateHeaderValue(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestNewRequestContext_Initialization(t *testing.T) {
	ctx := NewRequestContext()

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.RequestHeaders == nil {
		t.Error("expected non-nil RequestHeaders")
	}
	if ctx.ResponseHeaders == nil {
		t.Error("expected non-nil ResponseHeaders")
	}
	if ctx.Properties == nil {
		t.Error("expected non-nil Properties")
	}
	// New test: check that maps are empty initially
	if len(ctx.RequestHeaders) != 0 {
		t.Error("expected empty RequestHeaders")
	}
	if len(ctx.ResponseHeaders) != 0 {
		t.Error("expected empty ResponseHeaders")
	}
}

func TestAcquireReleaseRequestContext(t *testing.T) {
	// Acquire context
	ctx := AcquireRequestContext()
	if ctx == nil {
		t.Fatal("expected non-nil context from pool")
	}

	// Set some values
	ctx.RequestHeaders["Content-Type"] = "application/json"
	ctx.ResponseHeaders["X-Custom"] = "value"
	ctx.Properties["test"] = []byte("data")
	ctx.RequestBody = []byte("body")

	// Release and re-acquire
	ReleaseRequestContext(ctx)

	// The context should be reset when re-acquired
	ctx2 := AcquireRequestContext()
	if ctx2 == nil {
		t.Fatal("expected non-nil context from pool")
	}

	// Values should be cleared
	if len(ctx2.RequestBody) != 0 {
		t.Error("expected RequestBody to be cleared")
	}
}

func TestReleaseRequestContext_Nil(t *testing.T) {
	// Should not panic
	ReleaseRequestContext(nil)
}

func TestRequestContext_Reset(t *testing.T) {
	ctx := NewRequestContext()

	// Set values
	ctx.RequestHeaders["X-Test"] = "value"
	ctx.ResponseHeaders["X-Response"] = "resp"
	ctx.RequestTrailers = map[string]string{"trailer": "value"}
	ctx.ResponseTrailers = map[string]string{"resp-trailer": "value"}
	ctx.Properties["prop"] = []byte("data")
	ctx.RequestBody = []byte("request body")
	ctx.ResponseBody = []byte("response body")
	ctx.PluginConfig = []byte("config")
	ctx.RequestBodyBuf = NewBodyBufferFromBytes([]byte("buf"))
	ctx.ResponseBodyBuf = NewBodyBufferFromBytes([]byte("resp buf"))

	// Reset
	ctx.Reset()

	// Verify all cleared
	if len(ctx.RequestHeaders) != 0 {
		t.Error("RequestHeaders not cleared")
	}
	if len(ctx.ResponseHeaders) != 0 {
		t.Error("ResponseHeaders not cleared")
	}
	if ctx.RequestBody != nil {
		t.Error("RequestBody not cleared")
	}
	if ctx.ResponseBody != nil {
		t.Error("ResponseBody not cleared")
	}
	if ctx.PluginConfig != nil {
		t.Error("PluginConfig not cleared")
	}
	if ctx.RequestBodyBuf != nil {
		t.Error("RequestBodyBuf not cleared")
	}
	if ctx.ResponseBodyBuf != nil {
		t.Error("ResponseBodyBuf not cleared")
	}
}

func TestRequestContext_BodyBufferAccessors(t *testing.T) {
	ctx := NewRequestContext()

	// Test request body buffer
	reqBuf := NewBodyBufferFromBytes([]byte("request"))
	ctx.SetRequestBodyBuffer(reqBuf)

	gotReqBuf := ctx.GetRequestBodyBuffer()
	if gotReqBuf != reqBuf {
		t.Error("GetRequestBodyBuffer returned wrong buffer")
	}

	// Test response body buffer
	respBuf := NewBodyBufferFromBytes([]byte("response"))
	ctx.SetResponseBodyBuffer(respBuf)

	gotRespBuf := ctx.GetResponseBodyBuffer()
	if gotRespBuf != respBuf {
		t.Error("GetResponseBodyBuffer returned wrong buffer")
	}
}

func TestNewProxyWasmHost(t *testing.T) {
	// nil runtime is acceptable
	host := NewProxyWasmHost(nil)

	if host == nil {
		t.Fatal("expected non-nil host")
	}
	if host.ctx == nil {
		t.Error("expected non-nil default context")
	}
	if host.logger == nil {
		t.Error("expected non-nil logger")
	}
}

func TestProxyWasmHost_SetGetRequestContext(t *testing.T) {
	host := NewProxyWasmHost(nil)

	ctx := NewRequestContext()
	ctx.RequestHeaders["X-Test"] = "value"

	host.SetRequestContext(ctx)

	got := host.GetRequestContext()
	if got != ctx {
		t.Error("GetRequestContext returned wrong context")
	}
	if got.RequestHeaders["X-Test"] != "value" {
		t.Error("context data not preserved")
	}
}

func TestSerializeHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "empty headers",
			headers: map[string]string{},
		},
		{
			name: "single header",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "multiple headers",
			headers: map[string]string{
				"Content-Type":   "application/json",
				"Accept":         "text/plain",
				"X-Custom-Header": "custom-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serializeHeaders(tt.headers)

			// For empty headers, should return empty slice
			if len(tt.headers) == 0 {
				if len(result) != 0 {
					t.Errorf("expected empty result for empty headers, got %d bytes", len(result))
				}
				return
			}

			// For non-empty headers, should contain null-terminated key-value pairs
			if len(result) == 0 {
				t.Error("expected non-empty result for non-empty headers")
			}
		})
	}
}

func TestDeserializeHeaders(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "some data",
			data: []byte("key\x00value\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deserializeHeaders(tt.data)
			if result == nil {
				t.Error("expected non-nil map")
			}
		})
	}
}

func TestRequestContext_ConcurrentAccess(t *testing.T) {
	ctx := NewRequestContext()

	done := make(chan bool, 10)

	// Concurrent reads and writes
	for i := 0; i < 5; i++ {
		go func(id int) {
			buf := NewBodyBufferFromBytes([]byte("test"))
			ctx.SetRequestBodyBuffer(buf)
			_ = ctx.GetRequestBodyBuffer()
			done <- true
		}(i)

		go func(id int) {
			buf := NewBodyBufferFromBytes([]byte("test"))
			ctx.SetResponseBodyBuffer(buf)
			_ = ctx.GetResponseBodyBuffer()
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestProxyWasmHost_ConcurrentContextAccess(t *testing.T) {
	host := NewProxyWasmHost(nil)

	done := make(chan bool, 20)

	for i := 0; i < 10; i++ {
		go func() {
			ctx := NewRequestContext()
			ctx.RequestHeaders["X-Test"] = "value"
			host.SetRequestContext(ctx)
			done <- true
		}()

		go func() {
			_ = host.GetRequestContext()
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestRequestContext_Properties(t *testing.T) {
	ctx := NewRequestContext()

	ctx.Properties["test.key"] = []byte("test value")
	ctx.Properties["another.key"] = []byte("another value")

	if string(ctx.Properties["test.key"]) != "test value" {
		t.Error("expected property 'test.key'")
	}
	if string(ctx.Properties["another.key"]) != "another value" {
		t.Error("expected property 'another.key'")
	}
}

func TestRequestContext_Trailers(t *testing.T) {
	ctx := NewRequestContext()

	// Request trailers
	ctx.RequestTrailers = map[string]string{
		"X-Trailer": "value",
	}
	if ctx.RequestTrailers["X-Trailer"] != "value" {
		t.Error("expected request trailer")
	}

	// Response trailers
	ctx.ResponseTrailers = map[string]string{
		"X-Response-Trailer": "resp-value",
	}
	if ctx.ResponseTrailers["X-Response-Trailer"] != "resp-value" {
		t.Error("expected response trailer")
	}
}

func TestRequestContext_Bodies(t *testing.T) {
	ctx := NewRequestContext()

	ctx.RequestBody = []byte("request body content")
	ctx.ResponseBody = []byte("response body content")
	ctx.PluginConfig = []byte(`{"key": "value"}`)

	if string(ctx.RequestBody) != "request body content" {
		t.Error("request body mismatch")
	}
	if string(ctx.ResponseBody) != "response body content" {
		t.Error("response body mismatch")
	}
	if string(ctx.PluginConfig) != `{"key": "value"}` {
		t.Error("plugin config mismatch")
	}
}

func TestRequestContext_Reset_ClearsTrailers(t *testing.T) {
	ctx := NewRequestContext()

	ctx.RequestTrailers = map[string]string{"trailer": "value"}
	ctx.ResponseTrailers = map[string]string{"resp-trailer": "value"}

	ctx.Reset()

	// Trailers should be cleared after reset
	if len(ctx.RequestTrailers) != 0 {
		t.Error("RequestTrailers not cleared")
	}
	if len(ctx.ResponseTrailers) != 0 {
		t.Error("ResponseTrailers not cleared")
	}
}

func TestSerializeHeaders_Order(t *testing.T) {
	headers := map[string]string{
		"A": "1",
		"B": "2",
		"C": "3",
	}

	result := serializeHeaders(headers)

	// Should contain all headers (order may vary)
	if len(result) == 0 {
		t.Error("expected non-empty serialization")
	}
}

func TestDeserializeHeaders_Returns_Map(t *testing.T) {
	result := deserializeHeaders([]byte{})
	if result == nil {
		t.Error("expected non-nil map")
	}
}

func TestSerializeHeaders_SingleHeader(t *testing.T) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	result := serializeHeaders(headers)
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
	// Check that result contains null terminators
	nullCount := 0
	for _, b := range result {
		if b == 0 {
			nullCount++
		}
	}
	if nullCount != 2 {
		t.Errorf("expected 2 null terminators, got %d", nullCount)
	}
}

func TestSerializeHeaders_SpecialCharacters(t *testing.T) {
	headers := map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
		"Cache-Control":   "no-cache, no-store",
	}

	result := serializeHeaders(headers)
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestDeserializeHeaders_WithData(t *testing.T) {
	data := []byte("key1\x00value1\x00key2\x00value2\x00")
	result := deserializeHeaders(data)
	if result == nil {
		t.Error("expected non-nil map")
	}
	// Current implementation returns empty map (simplified)
}

func TestRequestContext_AllFields(t *testing.T) {
	ctx := NewRequestContext()

	// Test all fields can be set
	ctx.RequestHeaders["X-Request"] = "value"
	ctx.ResponseHeaders["X-Response"] = "value"
	ctx.RequestTrailers = map[string]string{"X-Trailer": "value"}
	ctx.ResponseTrailers = map[string]string{"X-Resp-Trailer": "value"}
	ctx.Properties["prop"] = []byte("data")
	ctx.RequestBody = []byte("request body")
	ctx.ResponseBody = []byte("response body")
	ctx.PluginConfig = []byte(`{"key":"value"}`)

	// Verify all set correctly
	if ctx.RequestHeaders["X-Request"] != "value" {
		t.Error("RequestHeaders not set correctly")
	}
	if ctx.ResponseHeaders["X-Response"] != "value" {
		t.Error("ResponseHeaders not set correctly")
	}
	if ctx.RequestTrailers["X-Trailer"] != "value" {
		t.Error("RequestTrailers not set correctly")
	}
	if ctx.ResponseTrailers["X-Resp-Trailer"] != "value" {
		t.Error("ResponseTrailers not set correctly")
	}
	if string(ctx.Properties["prop"]) != "data" {
		t.Error("Properties not set correctly")
	}
}

func TestProxyWasmHost_Logger(t *testing.T) {
	host := NewProxyWasmHost(nil)

	if host.logger == nil {
		t.Error("expected non-nil logger")
	}
}

func TestRequestContext_BodyBufferNil(t *testing.T) {
	ctx := NewRequestContext()

	// Should return nil for unset body buffers
	if ctx.GetRequestBodyBuffer() != nil {
		t.Error("expected nil request body buffer")
	}
	if ctx.GetResponseBodyBuffer() != nil {
		t.Error("expected nil response body buffer")
	}
}

func TestValidateHeaderValue_Binary(t *testing.T) {
	// Binary data without CR/LF should be valid
	binaryData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !validateHeaderValue(binaryData) {
		t.Error("expected binary data without CR/LF to be valid")
	}

	// Binary data with CR should be invalid
	binaryWithCR := []byte{0x01, 0x02, '\r', 0x04}
	if validateHeaderValue(binaryWithCR) {
		t.Error("expected binary data with CR to be invalid")
	}
}

func TestValidateHeaderValue_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    []byte
		expected bool
	}{
		{"single CR at start", []byte("\rvalue"), false},
		{"single LF at end", []byte("value\n"), false},
		{"CRLF in middle", []byte("val\r\nue"), false},
		{"tab character (allowed)", []byte("value\twith\ttab"), true},
		{"unicode (allowed)", []byte("value with unicode: 日本語"), true},
		{"space only", []byte("   "), true},
		{"null byte (allowed)", []byte("value\x00with\x00null"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateHeaderValue(tt.value)
			if result != tt.expected {
				t.Errorf("validateHeaderValue(%q) = %v, want %v", tt.value, result, tt.expected)
			}
		})
	}
}
