package aigateway

import (
	"testing"
)

func TestCL100KTokenizer_Count(t *testing.T) {
	tokenizer := NewCL100KTokenizer()

	tests := []struct {
		name     string
		text     string
		minCount int
		maxCount int
	}{
		{
			name:     "empty string",
			text:     "",
			minCount: 0,
			maxCount: 0,
		},
		{
			name:     "single word",
			text:     "hello",
			minCount: 1,
			maxCount: 2,
		},
		{
			name:     "simple sentence",
			text:     "Hello, world!",
			minCount: 2,
			maxCount: 10,
		},
		{
			name:     "longer text",
			text:     "The quick brown fox jumps over the lazy dog.",
			minCount: 8,
			maxCount: 25,
		},
		{
			name:     "code snippet",
			text:     "func main() { fmt.Println(\"Hello\") }",
			minCount: 8,
			maxCount: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := tokenizer.Count(tt.text)
			if count < tt.minCount || count > tt.maxCount {
				t.Errorf("Count(%q) = %d, want between %d and %d",
					tt.text, count, tt.minCount, tt.maxCount)
			}
		})
	}
}

func TestCL100KTokenizer_CountMessages(t *testing.T) {
	tokenizer := NewCL100KTokenizer()

	messages := []Message{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "Hello!"},
		{Role: "assistant", Content: "Hi there! How can I help you?"},
	}

	count := tokenizer.CountMessages(messages)
	if count < 15 || count > 60 {
		t.Errorf("CountMessages() = %d, want between 15 and 60", count)
	}
}

func TestClaudeTokenizer_Count(t *testing.T) {
	tokenizer := NewClaudeTokenizer()

	tests := []struct {
		name     string
		text     string
		minCount int
		maxCount int
	}{
		{
			name:     "empty string",
			text:     "",
			minCount: 0,
			maxCount: 0,
		},
		{
			name:     "single word",
			text:     "hello",
			minCount: 1,
			maxCount: 2,
		},
		{
			name:     "simple sentence",
			text:     "Hello, world!",
			minCount: 2,
			maxCount: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := tokenizer.Count(tt.text)
			if count < tt.minCount || count > tt.maxCount {
				t.Errorf("Count(%q) = %d, want between %d and %d",
					tt.text, count, tt.minCount, tt.maxCount)
			}
		})
	}
}

func TestTokenizerRegistry_Get(t *testing.T) {
	registry := NewTokenizerRegistry()

	tests := []struct {
		name          string
		model         string
		expectedName  string
	}{
		{
			name:         "gpt-4",
			model:        "gpt-4",
			expectedName: "cl100k_base",
		},
		{
			name:         "gpt-4-turbo",
			model:        "gpt-4-turbo",
			expectedName: "cl100k_base",
		},
		{
			name:         "claude-3-opus",
			model:        "claude-3-opus",
			expectedName: "claude",
		},
		{
			name:         "unknown model",
			model:        "unknown-model",
			expectedName: "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := registry.Get(tt.model)
			if tokenizer.Name() != tt.expectedName {
				t.Errorf("Get(%q).Name() = %q, want %q",
					tt.model, tokenizer.Name(), tt.expectedName)
			}
		})
	}
}

func TestTokenCounter_CountRequest(t *testing.T) {
	counter := NewTokenCounter()

	req := &LLMRequest{
		Model:   "gpt-4",
		Messages: []Message{
			{Role: "user", Content: "What is the capital of France?"},
		},
		MaxTokens: 100,
	}

	count := counter.CountRequest(req)

	if count.PromptTokens <= 0 {
		t.Errorf("CountRequest() PromptTokens = %d, want > 0", count.PromptTokens)
	}
	if count.MaxCompletionTokens != 100 {
		t.Errorf("CountRequest() MaxCompletionTokens = %d, want 100", count.MaxCompletionTokens)
	}
	if count.Tokenizer != "cl100k_base" {
		t.Errorf("CountRequest() Tokenizer = %q, want cl100k_base", count.Tokenizer)
	}
}

func TestTokenCount_EstimatedCost(t *testing.T) {
	count := TokenCount{
		PromptTokens:     1000,
		CompletionTokens: 500,
	}

	// GPT-4 pricing example: $0.03/1K input, $0.06/1K output
	cost := count.EstimatedCost(0.03, 0.06)
	expected := (1000.0/1000.0)*0.03 + (500.0/1000.0)*0.06 // $0.06

	if cost < 0.059 || cost > 0.061 {
		t.Errorf("EstimatedCost() = %f, want approximately %f", cost, expected)
	}
}

func BenchmarkCL100KTokenizer_Count(b *testing.B) {
	tokenizer := NewCL100KTokenizer()
	text := "The quick brown fox jumps over the lazy dog. This is a longer text to benchmark tokenization performance."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokenizer.Count(text)
	}
}

func BenchmarkClaudeTokenizer_Count(b *testing.B) {
	tokenizer := NewClaudeTokenizer()
	text := "The quick brown fox jumps over the lazy dog. This is a longer text to benchmark tokenization performance."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokenizer.Count(text)
	}
}
