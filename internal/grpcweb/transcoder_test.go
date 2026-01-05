package grpcweb

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		params  map[string]string
		match   bool
	}{
		{"/api/users", "/api/users", map[string]string{}, true},
		{"/api/users/123", "/api/users/{id}", map[string]string{"id": "123"}, true},
		{"/api/users/123/posts/456", "/api/users/{user_id}/posts/{post_id}",
			map[string]string{"user_id": "123", "post_id": "456"}, true},
		{"/api/users", "/api/posts", nil, false},
		{"/api/users/123", "/api/users", nil, false},
	}

	for _, tt := range tests {
		result := matchPath(tt.path, tt.pattern)
		if tt.match {
			if result == nil {
				t.Errorf("matchPath(%q, %q) expected match", tt.path, tt.pattern)
				continue
			}
			for k, v := range tt.params {
				if result[k] != v {
					t.Errorf("matchPath(%q, %q) param %s = %q, want %q",
						tt.path, tt.pattern, k, result[k], v)
				}
			}
		} else if result != nil {
			t.Errorf("matchPath(%q, %q) expected no match", tt.path, tt.pattern)
		}
	}
}

func TestGRPCStatusToHTTP(t *testing.T) {
	tests := []struct {
		grpcStatus int
		httpStatus int
	}{
		{0, http.StatusOK},
		{3, http.StatusBadRequest},
		{5, http.StatusNotFound},
		{7, http.StatusForbidden},
		{12, http.StatusNotImplemented},
		{14, http.StatusServiceUnavailable},
		{16, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		result := grpcStatusToHTTP(tt.grpcStatus)
		if result != tt.httpStatus {
			t.Errorf("grpcStatusToHTTP(%d) = %d, want %d", tt.grpcStatus, result, tt.httpStatus)
		}
	}
}

func TestFrameGRPCMessage(t *testing.T) {
	msg := []byte(`{"name":"test"}`)
	framed := frameGRPCMessage(msg)

	// Check frame header
	if framed[0] != 0 {
		t.Errorf("expected flags = 0, got %d", framed[0])
	}

	length := binary.BigEndian.Uint32(framed[1:5])
	if int(length) != len(msg) {
		t.Errorf("expected length %d, got %d", len(msg), length)
	}

	// Check message content
	if string(framed[5:]) != string(msg) {
		t.Errorf("message mismatch: got %q", framed[5:])
	}
}

func TestParseGRPCFrames(t *testing.T) {
	// Build test data with data frame and trailer frame
	msg := []byte(`{"result":"ok"}`)
	trailers := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")

	// Data frame
	dataFrame := frameGRPCMessage(msg)

	// Trailer frame (flags = 0x80)
	trailerFrame := make([]byte, 5+len(trailers))
	trailerFrame[0] = 0x80
	binary.BigEndian.PutUint32(trailerFrame[1:5], uint32(len(trailers)))
	copy(trailerFrame[5:], trailers)

	body := append(dataFrame, trailerFrame...)

	messages, parsedTrailers, err := parseGRPCFrames(body)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(messages))
	}
	if string(messages[0]) != string(msg) {
		t.Errorf("message mismatch: got %q", messages[0])
	}

	if parsedTrailers["grpc-status"] != "0" {
		t.Errorf("expected grpc-status 0, got %q", parsedTrailers["grpc-status"])
	}
}

func TestSetNestedField(t *testing.T) {
	tests := []struct {
		field    string
		value    interface{}
		expected map[string]interface{}
	}{
		{
			"name",
			"test",
			map[string]interface{}{"name": "test"},
		},
		{
			"user.name",
			"john",
			map[string]interface{}{"user": map[string]interface{}{"name": "john"}},
		},
		{
			"user.address.city",
			"NYC",
			map[string]interface{}{"user": map[string]interface{}{"address": map[string]interface{}{"city": "NYC"}}},
		},
	}

	for _, tt := range tests {
		msg := make(map[string]interface{})
		setNestedField(msg, tt.field, tt.value)

		expected, _ := json.Marshal(tt.expected)
		actual, _ := json.Marshal(msg)
		if string(actual) != string(expected) {
			t.Errorf("setNestedField(%q) = %s, want %s", tt.field, actual, expected)
		}
	}
}

func TestBuildMethodFromHTTPRule(t *testing.T) {
	rule := HTTPRule{
		Get:  "/api/users/{user_id}",
		Body: "",
	}

	method := BuildMethodFromHTTPRule("GetUser", rule)

	if method.Name != "GetUser" {
		t.Errorf("expected name 'GetUser', got %q", method.Name)
	}
	if method.HTTPMethod != "GET" {
		t.Errorf("expected GET method, got %q", method.HTTPMethod)
	}
	if method.HTTPPath != "/api/users/{user_id}" {
		t.Errorf("wrong path: %q", method.HTTPPath)
	}
	if _, ok := method.PathParams["user_id"]; !ok {
		t.Error("expected user_id path param")
	}
}

func TestTranscoderNew(t *testing.T) {
	cfg := Config{
		Services: []ServiceDescriptor{
			{
				Name: "test.UserService",
				Methods: map[string]*MethodDescriptor{
					"GetUser": {
						Name:       "GetUser",
						HTTPPath:   "/api/users/{id}",
						HTTPMethod: "GET",
						PathParams: map[string]string{"id": "id"},
					},
				},
			},
		},
		DefaultUpstream: "localhost:9000",
	}

	transcoder := New(cfg)

	if len(transcoder.services) != 1 {
		t.Errorf("expected 1 service, got %d", len(transcoder.services))
	}
	if transcoder.upstreams["_default"] != "localhost:9000" {
		t.Error("expected default upstream")
	}
}

func TestTranscoderMatchRequest(t *testing.T) {
	transcoder := New(Config{
		Services: []ServiceDescriptor{
			{
				Name: "test.UserService",
				Methods: map[string]*MethodDescriptor{
					"GetUser": {
						Name:       "GetUser",
						HTTPPath:   "/api/users/{id}",
						HTTPMethod: "GET",
						PathParams: map[string]string{"id": "id"},
					},
					"CreateUser": {
						Name:       "CreateUser",
						HTTPPath:   "/api/users",
						HTTPMethod: "POST",
					},
				},
			},
		},
	})

	tests := []struct {
		method      string
		path        string
		expectMatch bool
		expectName  string
	}{
		{"GET", "/api/users/123", true, "GetUser"},
		{"POST", "/api/users", true, "CreateUser"},
		{"GET", "/api/posts", false, ""},
		{"PUT", "/api/users/123", false, ""}, // Wrong method
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		svc, method, _ := transcoder.matchRequest(req)

		if tt.expectMatch {
			if method == nil {
				t.Errorf("%s %s: expected match", tt.method, tt.path)
				continue
			}
			if method.Name != tt.expectName {
				t.Errorf("%s %s: expected %s, got %s", tt.method, tt.path, tt.expectName, method.Name)
			}
			if svc == nil {
				t.Errorf("%s %s: expected service", tt.method, tt.path)
			}
		} else if method != nil {
			t.Errorf("%s %s: expected no match", tt.method, tt.path)
		}
	}
}

func TestTranscoderBuildGRPCRequest(t *testing.T) {
	transcoder := New(Config{})

	method := &MethodDescriptor{
		Name:       "GetUser",
		HTTPPath:   "/api/users/{id}",
		HTTPMethod: "GET",
		PathParams: map[string]string{"id": "user_id"},
		QueryParams: []string{"include"},
	}

	body := bytes.NewBufferString(`{"extra":"data"}`)
	req := httptest.NewRequest("GET", "/api/users/123?include=posts", body)
	req.Header.Set("Content-Type", "application/json")

	pathParams := map[string]string{"id": "123"}

	grpcReq, err := transcoder.buildGRPCRequest(req, method, pathParams)
	if err != nil {
		t.Fatalf("buildGRPCRequest failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(grpcReq, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Check path param was mapped
	if result["user_id"] != "123" {
		t.Errorf("expected user_id=123, got %v", result["user_id"])
	}

	// Check query param
	if result["include"] != "posts" {
		t.Errorf("expected include=posts, got %v", result["include"])
	}

	// Check body merged
	if result["extra"] != "data" {
		t.Errorf("expected extra=data, got %v", result["extra"])
	}
}

func TestIsForwardableHeader(t *testing.T) {
	tests := []struct {
		header     string
		forwardable bool
	}{
		{"Authorization", true},
		{"X-Custom", true},
		{"Content-Type", false},
		{"Connection", false},
		{"Keep-Alive", false},
	}

	for _, tt := range tests {
		result := isForwardableHeader(tt.header)
		if result != tt.forwardable {
			t.Errorf("isForwardableHeader(%q) = %v, want %v", tt.header, result, tt.forwardable)
		}
	}
}

func TestJSONFieldMapper(t *testing.T) {
	mapper := &JSONFieldMapper{
		CamelCase: true,
		FieldMappings: map[string]string{
			"user_id": "userId",
		},
	}

	input := []byte(`{"user_id": "123", "first_name": "John", "nested": {"last_name": "Doe"}}`)
	output, err := mapper.MapFields(input)
	if err != nil {
		t.Fatalf("MapFields failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if _, ok := result["userId"]; !ok {
		t.Error("expected userId field")
	}
	if _, ok := result["firstName"]; !ok {
		t.Error("expected firstName field (camelCase)")
	}

	nested := result["nested"].(map[string]interface{})
	if _, ok := nested["lastName"]; !ok {
		t.Error("expected nested lastName field")
	}
}

func TestSnakeToCamel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"user_id", "userId"},
		{"first_name", "firstName"},
		{"simple", "simple"},
		{"a_b_c", "aBC"},
	}

	for _, tt := range tests {
		result := snakeToCamel(tt.input)
		if result != tt.expected {
			t.Errorf("snakeToCamel(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCamelToSnake(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"userId", "user_id"},
		{"firstName", "first_name"},
		{"simple", "simple"},
	}

	for _, tt := range tests {
		result := camelToSnake(tt.input)
		if result != tt.expected {
			t.Errorf("camelToSnake(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestConvertTimestamp(t *testing.T) {
	data := map[string]interface{}{
		"seconds": float64(1609459200),
		"nanos":   float64(0),
	}

	result := ConvertTimestamp(data)

	// Should be 2021-01-01T00:00:00Z
	expected := time.Unix(1609459200, 0).Format(time.RFC3339Nano)
	if result != expected {
		t.Errorf("ConvertTimestamp = %q, want %q", result, expected)
	}
}

func TestConvertDuration(t *testing.T) {
	data := map[string]interface{}{
		"seconds": float64(90),
		"nanos":   float64(500000000),
	}

	result := ConvertDuration(data)

	expected := "1m30.5s"
	if result != expected {
		t.Errorf("ConvertDuration = %q, want %q", result, expected)
	}
}

func TestMiddlewareShouldTranscode(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		expected bool
	}{
		{"/api/users", []string{"/api"}, true},
		{"/other/path", []string{"/api"}, false},
		{"/anything", []string{}, true}, // Empty patterns match all
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		result := shouldTranscode(req, tt.patterns)
		if result != tt.expected {
			t.Errorf("shouldTranscode(%q, %v) = %v, want %v",
				tt.path, tt.patterns, result, tt.expected)
		}
	}
}

func TestIsGRPCWeb(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/grpc-web", true},
		{"application/grpc-web+proto", true},
		{"application/grpc-web+json", true},
		{"application/grpc-web-text", true},
		{"application/json", false},
		{"text/plain", false},
	}

	for _, tt := range tests {
		result := isGRPCWeb(tt.contentType)
		if result != tt.expected {
			t.Errorf("isGRPCWeb(%q) = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()

	addCORSHeaders(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
		t.Error("expected origin to match request origin")
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Allow-Methods header")
	}
	if rec.Header().Get("Access-Control-Expose-Headers") == "" {
		t.Error("expected Expose-Headers header")
	}
}
