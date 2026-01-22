// Package aigateway provides AI/LLM gateway capabilities.
package aigateway

import (
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// Tokenizer interface for counting tokens.
type Tokenizer interface {
	Count(text string) int
	CountMessages(messages []Message) int
	Name() string
}

// TokenizerRegistry manages tokenizers for different models.
type TokenizerRegistry struct {
	tokenizers map[string]Tokenizer
	defaults   map[Provider]Tokenizer
	mu         sync.RWMutex
}

// NewTokenizerRegistry creates a new tokenizer registry with default tokenizers.
func NewTokenizerRegistry() *TokenizerRegistry {
	registry := &TokenizerRegistry{
		tokenizers: make(map[string]Tokenizer),
		defaults:   make(map[Provider]Tokenizer),
	}

	// Register default tokenizers
	cl100k := NewCL100KTokenizer()
	claude := NewClaudeTokenizer()
	simple := NewSimpleTokenizer()

	// OpenAI models use cl100k_base
	registry.tokenizers["gpt-4"] = cl100k
	registry.tokenizers["gpt-4-turbo"] = cl100k
	registry.tokenizers["gpt-4-turbo-preview"] = cl100k
	registry.tokenizers["gpt-4o"] = cl100k
	registry.tokenizers["gpt-4o-mini"] = cl100k
	registry.tokenizers["gpt-3.5-turbo"] = cl100k
	registry.tokenizers["text-embedding-ada-002"] = cl100k
	registry.tokenizers["text-embedding-3-small"] = cl100k
	registry.tokenizers["text-embedding-3-large"] = cl100k

	// Anthropic models
	registry.tokenizers["claude-3-opus"] = claude
	registry.tokenizers["claude-3-sonnet"] = claude
	registry.tokenizers["claude-3-haiku"] = claude
	registry.tokenizers["claude-3-5-sonnet"] = claude
	registry.tokenizers["claude-3-5-haiku"] = claude
	registry.tokenizers["claude-2"] = claude
	registry.tokenizers["claude-2.1"] = claude

	// Set provider defaults
	registry.defaults[ProviderOpenAI] = cl100k
	registry.defaults[ProviderAzure] = cl100k
	registry.defaults[ProviderAnthropic] = claude
	registry.defaults[ProviderLocal] = simple
	registry.defaults[ProviderUnknown] = simple

	return registry
}

// Get returns the tokenizer for a model.
func (r *TokenizerRegistry) Get(model string) Tokenizer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match
	if t, ok := r.tokenizers[model]; ok {
		return t
	}

	// Prefix match for versioned models
	modelLower := strings.ToLower(model)
	for prefix, t := range r.tokenizers {
		if strings.HasPrefix(modelLower, strings.ToLower(prefix)) {
			return t
		}
	}

	// Return simple tokenizer as fallback
	return r.defaults[ProviderUnknown]
}

// GetForProvider returns the default tokenizer for a provider.
func (r *TokenizerRegistry) GetForProvider(provider Provider) Tokenizer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if t, ok := r.defaults[provider]; ok {
		return t
	}
	return r.defaults[ProviderUnknown]
}

// Register registers a tokenizer for a model.
func (r *TokenizerRegistry) Register(model string, tokenizer Tokenizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokenizers[model] = tokenizer
}

// CL100KTokenizer approximates OpenAI's cl100k_base tokenizer.
// This is used by GPT-4, GPT-3.5-turbo, and text-embedding models.
type CL100KTokenizer struct {
	// Token patterns ordered by priority
	patterns []*regexp.Regexp
}

// NewCL100KTokenizer creates a new cl100k_base approximation tokenizer.
func NewCL100KTokenizer() *CL100KTokenizer {
	// Patterns that approximate cl100k_base tokenization
	// These are simplified and won't be 100% accurate but are close enough
	patterns := []string{
		// Contractions and possessives
		`'(?:s|t|re|ve|m|ll|d|em)`,
		// Numbers
		`\d{1,3}(?:,\d{3})*(?:\.\d+)?`,
		`\d+`,
		// Words with special handling for capitalization
		`[A-Z][a-z]+`,
		`[A-Z]+`,
		`[a-z]+`,
		// Punctuation groups
		`[.!?]+`,
		`[,;:]+`,
		// Special tokens
		`\s+`,
		// Individual characters as fallback
		`.`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}

	return &CL100KTokenizer{patterns: compiled}
}

// Name returns the tokenizer name.
func (t *CL100KTokenizer) Name() string {
	return "cl100k_base"
}

// Count counts tokens in text using cl100k_base approximation.
func (t *CL100KTokenizer) Count(text string) int {
	if text == "" {
		return 0
	}

	// Base count: approximately 1 token per 4 characters for English
	// Adjust based on content characteristics
	baseCount := len(text) / 4
	if baseCount == 0 {
		baseCount = 1
	}

	// Count special patterns that affect tokenization
	tokens := 0
	remaining := text

	for len(remaining) > 0 {
		matched := false
		for _, re := range t.patterns {
			if loc := re.FindStringIndex(remaining); loc != nil && loc[0] == 0 {
				match := remaining[loc[0]:loc[1]]
				tokens += t.estimateTokens(match)
				remaining = remaining[loc[1]:]
				matched = true
				break
			}
		}
		if !matched {
			// Single character fallback
			_, size := utf8.DecodeRuneInString(remaining)
			tokens++
			remaining = remaining[size:]
		}
	}

	return tokens
}

// estimateTokens estimates tokens for a matched pattern.
func (t *CL100KTokenizer) estimateTokens(match string) int {
	// Whitespace is typically 1 token
	if strings.TrimSpace(match) == "" {
		return 1
	}

	// Short words/tokens are usually 1 token
	if len(match) <= 4 {
		return 1
	}

	// Longer words are approximately 1 token per 4 chars
	return (len(match) + 3) / 4
}

// CountMessages counts tokens for chat messages including special tokens.
func (t *CL100KTokenizer) CountMessages(messages []Message) int {
	tokens := 0

	// Each message has overhead tokens
	// <|im_start|>{role}\n{content}<|im_end|>\n
	// Approximately 4 tokens overhead per message
	for _, msg := range messages {
		tokens += 4 // Message framing overhead
		tokens += t.Count(msg.Role)
		tokens += t.Count(msg.Content)
	}

	// Add 3 tokens for assistant priming
	tokens += 3

	return tokens
}

// ClaudeTokenizer approximates Anthropic's tokenizer.
type ClaudeTokenizer struct {
	wordPattern *regexp.Regexp
}

// NewClaudeTokenizer creates a new Claude tokenizer approximation.
func NewClaudeTokenizer() *ClaudeTokenizer {
	return &ClaudeTokenizer{
		wordPattern: regexp.MustCompile(`\S+|\s+`),
	}
}

// Name returns the tokenizer name.
func (t *ClaudeTokenizer) Name() string {
	return "claude"
}

// Count counts tokens in text using Claude approximation.
// Claude uses a similar BPE approach but with different vocabulary.
func (t *ClaudeTokenizer) Count(text string) int {
	if text == "" {
		return 0
	}

	// Claude tokenization is roughly similar to cl100k but slightly different
	// Approximately 1 token per 3.5 characters for English text
	matches := t.wordPattern.FindAllString(text, -1)
	tokens := 0

	for _, match := range matches {
		if strings.TrimSpace(match) == "" {
			// Whitespace
			tokens += 1
		} else if len(match) <= 3 {
			tokens += 1
		} else {
			// Approximate BPE: longer words split into subwords
			tokens += (len(match) + 2) / 3
		}
	}

	if tokens == 0 {
		tokens = 1
	}

	return tokens
}

// CountMessages counts tokens for Claude messages.
func (t *ClaudeTokenizer) CountMessages(messages []Message) int {
	tokens := 0

	// Claude message format overhead
	// Human: {content}\n\nAssistant: {content}
	for _, msg := range messages {
		tokens += 3 // Role prefix overhead
		tokens += t.Count(msg.Content)
		tokens += 2 // Newline overhead
	}

	return tokens
}

// SimpleTokenizer provides a simple word-based token count.
// Used as fallback for unknown models.
type SimpleTokenizer struct {
	wordPattern *regexp.Regexp
}

// NewSimpleTokenizer creates a new simple tokenizer.
func NewSimpleTokenizer() *SimpleTokenizer {
	return &SimpleTokenizer{
		wordPattern: regexp.MustCompile(`\S+`),
	}
}

// Name returns the tokenizer name.
func (t *SimpleTokenizer) Name() string {
	return "simple"
}

// Count counts tokens using simple word splitting.
// Approximately 1.3 tokens per word.
func (t *SimpleTokenizer) Count(text string) int {
	if text == "" {
		return 0
	}

	words := t.wordPattern.FindAllString(text, -1)
	// Apply 1.3x multiplier to account for subword tokenization
	tokens := (len(words) * 13) / 10
	if tokens == 0 {
		tokens = 1
	}
	return tokens
}

// CountMessages counts tokens for messages.
func (t *SimpleTokenizer) CountMessages(messages []Message) int {
	tokens := 0
	for _, msg := range messages {
		tokens += 2 // Role overhead
		tokens += t.Count(msg.Content)
	}
	return tokens
}

// TokenCounter provides high-level token counting for LLM requests.
type TokenCounter struct {
	registry *TokenizerRegistry
}

// NewTokenCounter creates a new token counter.
func NewTokenCounter() *TokenCounter {
	return &TokenCounter{
		registry: NewTokenizerRegistry(),
	}
}

// CountRequest counts tokens in an LLM request.
func (tc *TokenCounter) CountRequest(req *LLMRequest) TokenCount {
	var tokenizer Tokenizer
	if req.Model != "" {
		tokenizer = tc.registry.Get(req.Model)
	} else {
		tokenizer = tc.registry.GetForProvider(req.Provider)
	}

	count := TokenCount{
		Tokenizer: tokenizer.Name(),
	}

	// Count prompt tokens
	if req.Prompt != "" {
		count.PromptTokens = tokenizer.Count(req.Prompt)
	}

	// Count message tokens
	if len(req.Messages) > 0 {
		if msgTokenizer, ok := tokenizer.(interface{ CountMessages([]Message) int }); ok {
			count.PromptTokens += msgTokenizer.CountMessages(req.Messages)
		} else {
			// Fallback to summing individual messages
			for _, msg := range req.Messages {
				count.PromptTokens += tokenizer.Count(msg.Content) + 2 // +2 for role
			}
		}
	}

	// Count system prompt
	if req.SystemPrompt != "" && !hasSystemMessage(req.Messages) {
		count.PromptTokens += tokenizer.Count(req.SystemPrompt) + 2
	}

	// Estimate completion tokens based on max_tokens
	if req.MaxTokens > 0 {
		count.MaxCompletionTokens = req.MaxTokens
	} else {
		// Default estimate
		count.MaxCompletionTokens = 1000
	}

	count.TotalPromptTokens = count.PromptTokens

	return count
}

// hasSystemMessage checks if messages already contain a system message.
func hasSystemMessage(messages []Message) bool {
	for _, msg := range messages {
		if msg.Role == "system" {
			return true
		}
	}
	return false
}

// CountResponse counts tokens in an LLM response.
func (tc *TokenCounter) CountResponse(resp *LLMResponse) TokenCount {
	var tokenizer Tokenizer
	if resp.Model != "" {
		tokenizer = tc.registry.Get(resp.Model)
	} else {
		tokenizer = tc.registry.GetForProvider(resp.Provider)
	}

	count := TokenCount{
		Tokenizer: tokenizer.Name(),
	}

	// Use provided counts if available
	if resp.InputTokens > 0 {
		count.PromptTokens = resp.InputTokens
	}
	if resp.OutputTokens > 0 {
		count.CompletionTokens = resp.OutputTokens
	} else if resp.Content != "" {
		// Count content tokens
		count.CompletionTokens = tokenizer.Count(resp.Content)
	}

	if resp.TotalTokens > 0 {
		count.TotalPromptTokens = resp.TotalTokens
	} else {
		count.TotalPromptTokens = count.PromptTokens + count.CompletionTokens
	}

	return count
}

// CountText counts tokens in plain text.
func (tc *TokenCounter) CountText(text string, model string) int {
	tokenizer := tc.registry.Get(model)
	return tokenizer.Count(text)
}

// TokenCount holds token counts for a request or response.
type TokenCount struct {
	Tokenizer           string `json:"tokenizer"`
	PromptTokens        int    `json:"prompt_tokens"`
	CompletionTokens    int    `json:"completion_tokens"`
	MaxCompletionTokens int    `json:"max_completion_tokens,omitempty"`
	TotalPromptTokens   int    `json:"total_tokens"`
}

// EstimatedCost calculates estimated cost based on token counts.
func (tc TokenCount) EstimatedCost(inputCostPer1K, outputCostPer1K float64) float64 {
	inputCost := float64(tc.PromptTokens) / 1000.0 * inputCostPer1K
	outputCost := float64(tc.CompletionTokens) / 1000.0 * outputCostPer1K
	return inputCost + outputCost
}
