// Package aigateway provides AI/LLM gateway capabilities including token counting,
// multi-provider routing, semantic caching, and streaming support.
package aigateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Provider represents an LLM provider (OpenAI, Anthropic, etc.)
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderAzure     Provider = "azure"
	ProviderLocal     Provider = "local"
	ProviderUnknown   Provider = "unknown"
)

// ProviderConfig configures an LLM provider endpoint.
type ProviderConfig struct {
	Name       string            `yaml:"name" json:"name"`
	Provider   Provider          `yaml:"provider" json:"provider"`
	Endpoint   string            `yaml:"endpoint" json:"endpoint"`
	APIKey     string            `yaml:"api_key" json:"api_key,omitempty"`
	OrgID      string            `yaml:"org_id" json:"org_id,omitempty"`
	Model      string            `yaml:"model" json:"model,omitempty"`
	Weight     int               `yaml:"weight" json:"weight,omitempty"`
	Priority   int               `yaml:"priority" json:"priority,omitempty"`
	MaxTokens  int               `yaml:"max_tokens" json:"max_tokens,omitempty"`
	CostPer1K  float64           `yaml:"cost_per_1k" json:"cost_per_1k,omitempty"`
	Headers    map[string]string `yaml:"headers" json:"headers,omitempty"`
	RateLimit  int               `yaml:"rate_limit" json:"rate_limit,omitempty"`
	Timeout    time.Duration     `yaml:"timeout" json:"timeout,omitempty"`
	HealthPath string            `yaml:"health_path" json:"health_path,omitempty"`
}

// ProviderEndpoint represents a configured provider with health status.
type ProviderEndpoint struct {
	Config        ProviderConfig
	healthy       atomic.Bool
	activeReqs    atomic.Int64
	totalTokens   atomic.Int64
	totalRequests atomic.Int64
	lastError     atomic.Value // string
	lastCheck     atomic.Value // time.Time
	rateLimiter   *TokenBucketLimiter
}

// NewProviderEndpoint creates a new provider endpoint.
func NewProviderEndpoint(cfg ProviderConfig) *ProviderEndpoint {
	pe := &ProviderEndpoint{
		Config: cfg,
	}
	pe.healthy.Store(true)
	pe.lastCheck.Store(time.Now())

	if cfg.RateLimit > 0 {
		pe.rateLimiter = NewTokenBucketLimiter(cfg.RateLimit, cfg.RateLimit*2)
	}

	return pe
}

// IsHealthy returns whether the provider is healthy.
func (pe *ProviderEndpoint) IsHealthy() bool {
	return pe.healthy.Load()
}

// SetHealthy sets the health status.
func (pe *ProviderEndpoint) SetHealthy(healthy bool) {
	pe.healthy.Store(healthy)
	pe.lastCheck.Store(time.Now())
}

// RecordRequest records a request with token count.
func (pe *ProviderEndpoint) RecordRequest(tokens int) {
	pe.totalRequests.Add(1)
	pe.totalTokens.Add(int64(tokens))
}

// Stats returns provider statistics.
func (pe *ProviderEndpoint) Stats() ProviderStats {
	var lastErr string
	if v := pe.lastError.Load(); v != nil {
		lastErr = v.(string)
	}
	var lastCheck time.Time
	if v := pe.lastCheck.Load(); v != nil {
		lastCheck = v.(time.Time)
	}

	return ProviderStats{
		Name:          pe.Config.Name,
		Provider:      pe.Config.Provider,
		Healthy:       pe.healthy.Load(),
		ActiveReqs:    pe.activeReqs.Load(),
		TotalTokens:   pe.totalTokens.Load(),
		TotalRequests: pe.totalRequests.Load(),
		LastError:     lastErr,
		LastCheck:     lastCheck,
	}
}

// ProviderStats contains provider statistics.
type ProviderStats struct {
	Name          string    `json:"name"`
	Provider      Provider  `json:"provider"`
	Healthy       bool      `json:"healthy"`
	ActiveReqs    int64     `json:"active_requests"`
	TotalTokens   int64     `json:"total_tokens"`
	TotalRequests int64     `json:"total_requests"`
	LastError     string    `json:"last_error,omitempty"`
	LastCheck     time.Time `json:"last_check"`
}

// TokenBucketLimiter provides simple token bucket rate limiting.
type TokenBucketLimiter struct {
	rate       float64
	burst      int
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucketLimiter creates a new token bucket limiter.
func NewTokenBucketLimiter(rate int, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		rate:       float64(rate),
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed.
func (l *TokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.lastUpdate = now

	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	if l.tokens >= 1 {
		l.tokens--
		return true
	}

	return false
}

// DetectProvider detects the provider from request headers and path.
func DetectProvider(r *http.Request) Provider {
	// Check Authorization header patterns
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer sk-") {
		return ProviderOpenAI
	}
	if strings.HasPrefix(auth, "Bearer ant-") {
		return ProviderAnthropic
	}

	// Check for Anthropic version header
	if r.Header.Get("anthropic-version") != "" {
		return ProviderAnthropic
	}

	// Check for OpenAI organization header
	if r.Header.Get("OpenAI-Organization") != "" {
		return ProviderOpenAI
	}

	// Check path patterns
	path := r.URL.Path
	if strings.Contains(path, "/v1/chat/completions") ||
		strings.Contains(path, "/v1/completions") ||
		strings.Contains(path, "/v1/embeddings") {
		return ProviderOpenAI
	}
	if strings.Contains(path, "/v1/messages") ||
		strings.Contains(path, "/v1/complete") {
		return ProviderAnthropic
	}

	// Check host
	host := r.Host
	if strings.Contains(host, "openai") {
		return ProviderOpenAI
	}
	if strings.Contains(host, "anthropic") {
		return ProviderAnthropic
	}
	if strings.Contains(host, "azure") {
		return ProviderAzure
	}

	return ProviderUnknown
}

// LLMRequest represents a parsed LLM request.
type LLMRequest struct {
	Provider      Provider          `json:"provider"`
	Model         string            `json:"model"`
	Messages      []Message         `json:"messages,omitempty"`
	Prompt        string            `json:"prompt,omitempty"`
	MaxTokens     int               `json:"max_tokens,omitempty"`
	Temperature   float64           `json:"temperature,omitempty"`
	Stream        bool              `json:"stream"`
	SystemPrompt  string            `json:"system,omitempty"`
	StopSequences []string          `json:"stop,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	RawBody       []byte            `json:"-"`
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// LLMResponse represents a parsed LLM response.
type LLMResponse struct {
	Provider     Provider `json:"provider"`
	Model        string   `json:"model"`
	Content      string   `json:"content"`
	InputTokens  int      `json:"input_tokens"`
	OutputTokens int      `json:"output_tokens"`
	TotalTokens  int      `json:"total_tokens"`
	FinishReason string   `json:"finish_reason"`
	Cached       bool     `json:"cached"`
	Latency      int64    `json:"latency_ms"`
	RawBody      []byte   `json:"-"`
}

// ParseRequest parses an LLM request from an HTTP request.
func ParseRequest(r *http.Request) (*LLMRequest, error) {
	if r.Body == nil {
		return nil, errors.New("empty request body")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	provider := DetectProvider(r)
	req := &LLMRequest{
		Provider: provider,
		RawBody:  body,
	}

	switch provider {
	case ProviderOpenAI, ProviderAzure:
		if err := parseOpenAIRequest(body, req); err != nil {
			return nil, err
		}
	case ProviderAnthropic:
		if err := parseAnthropicRequest(body, req); err != nil {
			return nil, err
		}
	default:
		// Try OpenAI format as default
		if err := parseOpenAIRequest(body, req); err != nil {
			// If that fails, try Anthropic
			if err := parseAnthropicRequest(body, req); err != nil {
				return nil, errors.New("unable to parse request format")
			}
		}
	}

	return req, nil
}

// parseOpenAIRequest parses an OpenAI-format request.
func parseOpenAIRequest(body []byte, req *LLMRequest) error {
	var data struct {
		Model       string    `json:"model"`
		Messages    []Message `json:"messages"`
		Prompt      string    `json:"prompt"`
		MaxTokens   int       `json:"max_tokens"`
		Temperature float64   `json:"temperature"`
		Stream      bool      `json:"stream"`
		Stop        []string  `json:"stop"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("parsing OpenAI request: %w", err)
	}

	req.Model = data.Model
	req.Messages = data.Messages
	req.Prompt = data.Prompt
	req.MaxTokens = data.MaxTokens
	req.Temperature = data.Temperature
	req.Stream = data.Stream
	req.StopSequences = data.Stop

	// Extract system message if present
	for _, msg := range data.Messages {
		if msg.Role == "system" {
			req.SystemPrompt = msg.Content
			break
		}
	}

	return nil
}

// parseAnthropicRequest parses an Anthropic-format request.
func parseAnthropicRequest(body []byte, req *LLMRequest) error {
	var data struct {
		Model     string    `json:"model"`
		Messages  []Message `json:"messages"`
		System    string    `json:"system"`
		MaxTokens int       `json:"max_tokens"`
		Stream    bool      `json:"stream"`
		Stop      []string  `json:"stop_sequences"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("parsing Anthropic request: %w", err)
	}

	req.Model = data.Model
	req.Messages = data.Messages
	req.SystemPrompt = data.System
	req.MaxTokens = data.MaxTokens
	req.Stream = data.Stream
	req.StopSequences = data.Stop

	return nil
}

// ParseResponse parses an LLM response.
func ParseResponse(body []byte, provider Provider) (*LLMResponse, error) {
	resp := &LLMResponse{
		Provider: provider,
		RawBody:  body,
	}

	switch provider {
	case ProviderOpenAI, ProviderAzure:
		if err := parseOpenAIResponse(body, resp); err != nil {
			return nil, err
		}
	case ProviderAnthropic:
		if err := parseAnthropicResponse(body, resp); err != nil {
			return nil, err
		}
	default:
		// Try OpenAI format as default
		if err := parseOpenAIResponse(body, resp); err != nil {
			if err := parseAnthropicResponse(body, resp); err != nil {
				return nil, errors.New("unable to parse response format")
			}
		}
	}

	return resp, nil
}

// parseOpenAIResponse parses an OpenAI-format response.
func parseOpenAIResponse(body []byte, resp *LLMResponse) error {
	var data struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text         string `json:"text"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("parsing OpenAI response: %w", err)
	}

	resp.Model = data.Model
	if len(data.Choices) > 0 {
		if data.Choices[0].Message.Content != "" {
			resp.Content = data.Choices[0].Message.Content
		} else {
			resp.Content = data.Choices[0].Text
		}
		resp.FinishReason = data.Choices[0].FinishReason
	}
	resp.InputTokens = data.Usage.PromptTokens
	resp.OutputTokens = data.Usage.CompletionTokens
	resp.TotalTokens = data.Usage.TotalTokens

	return nil
}

// parseAnthropicResponse parses an Anthropic-format response.
func parseAnthropicResponse(body []byte, resp *LLMResponse) error {
	var data struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("parsing Anthropic response: %w", err)
	}

	resp.Model = data.Model
	for _, c := range data.Content {
		if c.Type == "text" {
			resp.Content += c.Text
		}
	}
	resp.FinishReason = data.StopReason
	resp.InputTokens = data.Usage.InputTokens
	resp.OutputTokens = data.Usage.OutputTokens
	resp.TotalTokens = resp.InputTokens + resp.OutputTokens

	return nil
}

// StreamEvent represents a Server-Sent Event for streaming responses.
type StreamEvent struct {
	Event string `json:"event,omitempty"`
	Data  string `json:"data"`
	ID    string `json:"id,omitempty"`
	Retry int    `json:"retry,omitempty"`
}

// StreamParser parses SSE streams from LLM providers.
type StreamParser struct {
	provider Provider
	reader   *bufio.Reader
	buffer   bytes.Buffer
}

// NewStreamParser creates a new stream parser.
func NewStreamParser(r io.Reader, provider Provider) *StreamParser {
	return &StreamParser{
		provider: provider,
		reader:   bufio.NewReader(r),
	}
}

// Next returns the next event from the stream.
func (sp *StreamParser) Next() (*StreamEvent, error) {
	event := &StreamEvent{}

	for {
		line, err := sp.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && sp.buffer.Len() > 0 {
				// Process remaining buffer
				event.Data = sp.buffer.String()
				sp.buffer.Reset()
				return event, nil
			}
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			// Empty line = end of event
			if sp.buffer.Len() > 0 {
				event.Data = sp.buffer.String()
				sp.buffer.Reset()
				return event, nil
			}
			continue
		}

		if strings.HasPrefix(line, ":") {
			// Comment, ignore
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		field := line[:colonIdx]
		value := strings.TrimPrefix(line[colonIdx+1:], " ")

		switch field {
		case "event":
			event.Event = value
		case "data":
			if sp.buffer.Len() > 0 {
				sp.buffer.WriteString("\n")
			}
			sp.buffer.WriteString(value)
		case "id":
			event.ID = value
		case "retry":
			// Parse retry value (ignore errors)
			fmt.Sscanf(value, "%d", &event.Retry)
		}
	}
}

// ExtractStreamContent extracts content from a stream event.
func ExtractStreamContent(event *StreamEvent, provider Provider) (string, bool) {
	if event.Data == "[DONE]" {
		return "", true // Stream complete
	}

	switch provider {
	case ProviderOpenAI, ProviderAzure:
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(event.Data), &chunk); err != nil {
			return "", false
		}
		if len(chunk.Choices) > 0 {
			if chunk.Choices[0].FinishReason != "" {
				return "", true
			}
			return chunk.Choices[0].Delta.Content, false
		}

	case ProviderAnthropic:
		// Anthropic uses different event types
		if event.Event == "content_block_delta" {
			var delta struct {
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
			}
			if err := json.Unmarshal([]byte(event.Data), &delta); err != nil {
				return "", false
			}
			return delta.Delta.Text, false
		}
		if event.Event == "message_stop" {
			return "", true
		}
	}

	return "", false
}

// StreamResponseWriter wraps an http.ResponseWriter for streaming.
type StreamResponseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// NewStreamResponseWriter creates a new stream response writer.
func NewStreamResponseWriter(w http.ResponseWriter) (*StreamResponseWriter, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, errors.New("streaming not supported")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	return &StreamResponseWriter{
		w:       w,
		flusher: flusher,
	}, nil
}

// WriteEvent writes an SSE event.
func (sw *StreamResponseWriter) WriteEvent(event *StreamEvent) error {
	if event.Event != "" {
		fmt.Fprintf(sw.w, "event: %s\n", event.Event)
	}
	if event.ID != "" {
		fmt.Fprintf(sw.w, "id: %s\n", event.ID)
	}
	if event.Retry > 0 {
		fmt.Fprintf(sw.w, "retry: %d\n", event.Retry)
	}

	// Handle multi-line data
	lines := strings.Split(event.Data, "\n")
	for _, line := range lines {
		fmt.Fprintf(sw.w, "data: %s\n", line)
	}
	fmt.Fprint(sw.w, "\n")

	sw.flusher.Flush()
	return nil
}

// WriteData writes a data-only event.
func (sw *StreamResponseWriter) WriteData(data string) error {
	return sw.WriteEvent(&StreamEvent{Data: data})
}

// Close sends the final [DONE] event.
func (sw *StreamResponseWriter) Close() error {
	return sw.WriteData("[DONE]")
}

// PromptInjectionDetector detects potential prompt injection attempts.
type PromptInjectionDetector struct {
	patterns []*regexp.Regexp
}

// NewPromptInjectionDetector creates a new prompt injection detector.
func NewPromptInjectionDetector() *PromptInjectionDetector {
	patterns := []string{
		`(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|text)`,
		`(?i)disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|text)`,
		`(?i)forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|text)`,
		`(?i)new\s+instructions?:`,
		`(?i)system\s*:\s*you\s+are`,
		`(?i)\[system\]`,
		`(?i)<\|im_start\|>`,
		`(?i)jailbreak`,
		`(?i)do\s+anything\s+now`,
		`(?i)developer\s+mode`,
		`(?i)pretend\s+(you\s+are|to\s+be)`,
		`(?i)act\s+as\s+(if|though)`,
		`(?i)roleplay\s+as`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}

	return &PromptInjectionDetector{patterns: compiled}
}

// Detect checks for prompt injection patterns.
func (d *PromptInjectionDetector) Detect(text string) (bool, string) {
	for _, re := range d.patterns {
		if match := re.FindString(text); match != "" {
			return true, match
		}
	}
	return false, ""
}

// DetectRequest checks an entire LLM request for prompt injection.
func (d *PromptInjectionDetector) DetectRequest(req *LLMRequest) (bool, string) {
	// Check prompt
	if detected, match := d.Detect(req.Prompt); detected {
		return true, match
	}

	// Check messages
	for _, msg := range req.Messages {
		if msg.Role != "system" { // Don't flag system messages
			if detected, match := d.Detect(msg.Content); detected {
				return true, match
			}
		}
	}

	return false, ""
}

// RequestContext holds context for an LLM request through the gateway.
type RequestContext struct {
	ID            string
	StartTime     time.Time
	Provider      Provider
	Model         string
	InputTokens   int
	OutputTokens  int
	Cached        bool
	CacheKey      string
	SelectedIndex int // Selected provider index
	Retries       int
	Error         error
}

// NewRequestContext creates a new request context.
func NewRequestContext() *RequestContext {
	return &RequestContext{
		ID:        generateRequestID(),
		StartTime: time.Now(),
	}
}

// Duration returns the request duration.
func (rc *RequestContext) Duration() time.Duration {
	return time.Since(rc.StartTime)
}

// generateRequestID generates a unique request ID.
func generateRequestID() string {
	return fmt.Sprintf("llm-%d", time.Now().UnixNano())
}
