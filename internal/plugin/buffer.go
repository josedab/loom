// Package plugin provides body buffering for WASM plugins.
package plugin

import (
	"bytes"
	"io"
	"sync"
)

// BodyBuffer provides buffered access to request/response bodies.
// It allows plugins to read, modify, and replace body content.
type BodyBuffer struct {
	data       []byte
	reader     io.Reader
	written    bool
	streaming  bool
	maxSize    int64
	mu         sync.RWMutex
	chunks     [][]byte
	endOfBody  bool
}

// BodyBufferConfig configures body buffering behavior.
type BodyBufferConfig struct {
	MaxSize       int64 // Maximum buffer size (0 = unlimited)
	EnableStream  bool  // Enable streaming mode for large bodies
	ChunkSize     int   // Chunk size for streaming (default 64KB)
}

// DefaultBodyBufferConfig returns default body buffer configuration.
func DefaultBodyBufferConfig() BodyBufferConfig {
	return BodyBufferConfig{
		MaxSize:      10 * 1024 * 1024, // 10MB default
		EnableStream: true,
		ChunkSize:    64 * 1024, // 64KB chunks
	}
}

// NewBodyBuffer creates a new body buffer.
func NewBodyBuffer(r io.Reader, cfg BodyBufferConfig) *BodyBuffer {
	return &BodyBuffer{
		reader:    r,
		maxSize:   cfg.MaxSize,
		streaming: cfg.EnableStream,
	}
}

// NewBodyBufferFromBytes creates a body buffer from existing data.
func NewBodyBufferFromBytes(data []byte) *BodyBuffer {
	return &BodyBuffer{
		data:      data,
		written:   true,
		endOfBody: true,
	}
}

// Read reads buffered body data.
func (b *BodyBuffer) Read(start, length int) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.written {
		return nil, ErrBodyNotBuffered
	}

	dataLen := len(b.data)
	if start >= dataLen {
		return nil, nil
	}

	end := start + length
	if end > dataLen {
		end = dataLen
	}

	result := make([]byte, end-start)
	copy(result, b.data[start:end])
	return result, nil
}

// ReadAll reads the entire buffered body.
func (b *BodyBuffer) ReadAll() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.written {
		return b.data, nil
	}

	// Buffer the entire body from reader
	if b.reader == nil {
		b.written = true
		b.endOfBody = true
		return nil, nil
	}

	var buf bytes.Buffer
	if b.maxSize > 0 {
		limited := io.LimitReader(b.reader, b.maxSize)
		_, err := io.Copy(&buf, limited)
		if err != nil {
			return nil, err
		}
	} else {
		_, err := io.Copy(&buf, b.reader)
		if err != nil {
			return nil, err
		}
	}

	b.data = buf.Bytes()
	b.written = true
	b.endOfBody = true

	return b.data, nil
}

// Write replaces the body content.
func (b *BodyBuffer) Write(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = make([]byte, len(data))
	copy(b.data, data)
	b.written = true
}

// Append appends data to the body.
func (b *BodyBuffer) Append(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = append(b.data, data...)
	b.written = true
}

// Prepend prepends data to the body.
func (b *BodyBuffer) Prepend(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	newData := make([]byte, len(data)+len(b.data))
	copy(newData, data)
	copy(newData[len(data):], b.data)
	b.data = newData
	b.written = true
}

// Replace replaces a portion of the body.
func (b *BodyBuffer) Replace(start, end int, replacement []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.written {
		return ErrBodyNotBuffered
	}

	dataLen := len(b.data)
	if start < 0 || start > dataLen || end < start || end > dataLen {
		return ErrInvalidRange
	}

	newLen := dataLen - (end - start) + len(replacement)
	newData := make([]byte, newLen)
	copy(newData, b.data[:start])
	copy(newData[start:], replacement)
	copy(newData[start+len(replacement):], b.data[end:])
	b.data = newData

	return nil
}

// Size returns the current buffer size.
func (b *BodyBuffer) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.data)
}

// IsBuffered returns whether the body has been buffered.
func (b *BodyBuffer) IsBuffered() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.written
}

// IsEndOfBody returns whether the entire body has been received.
func (b *BodyBuffer) IsEndOfBody() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.endOfBody
}

// SetEndOfBody marks the body as complete.
func (b *BodyBuffer) SetEndOfBody(eob bool) {
	b.mu.Lock()
	b.endOfBody = eob
	b.mu.Unlock()
}

// AsReader returns the buffer as an io.Reader.
func (b *BodyBuffer) AsReader() io.Reader {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return bytes.NewReader(b.data)
}

// Reset resets the buffer.
func (b *BodyBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = nil
	b.written = false
	b.endOfBody = false
	b.chunks = nil
}

// AddChunk adds a chunk in streaming mode.
func (b *BodyBuffer) AddChunk(chunk []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	chunkCopy := make([]byte, len(chunk))
	copy(chunkCopy, chunk)
	b.chunks = append(b.chunks, chunkCopy)
}

// GetChunks returns all chunks in streaming mode.
func (b *BodyBuffer) GetChunks() [][]byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.chunks
}

// ConsolidateChunks merges all chunks into a single buffer.
func (b *BodyBuffer) ConsolidateChunks() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.chunks) == 0 {
		return
	}

	totalSize := 0
	for _, chunk := range b.chunks {
		totalSize += len(chunk)
	}

	b.data = make([]byte, totalSize)
	offset := 0
	for _, chunk := range b.chunks {
		copy(b.data[offset:], chunk)
		offset += len(chunk)
	}

	b.chunks = nil
	b.written = true
}

// BodyBufferError represents body buffer errors.
type BodyBufferError string

func (e BodyBufferError) Error() string { return string(e) }

const (
	ErrBodyNotBuffered = BodyBufferError("body not buffered")
	ErrInvalidRange    = BodyBufferError("invalid range")
	ErrBufferTooLarge  = BodyBufferError("buffer exceeds maximum size")
)

// StreamingBodyReader wraps a body reader for streaming processing.
type StreamingBodyReader struct {
	reader    io.ReadCloser
	buffer    *BodyBuffer
	onChunk   func([]byte) ([]byte, error)
	chunkSize int
}

// NewStreamingBodyReader creates a streaming body reader.
func NewStreamingBodyReader(r io.ReadCloser, chunkSize int, onChunk func([]byte) ([]byte, error)) *StreamingBodyReader {
	if chunkSize <= 0 {
		chunkSize = 64 * 1024 // 64KB default
	}
	return &StreamingBodyReader{
		reader:    r,
		buffer:    &BodyBuffer{},
		onChunk:   onChunk,
		chunkSize: chunkSize,
	}
}

// Read implements io.Reader with chunk processing.
func (s *StreamingBodyReader) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if n > 0 && s.onChunk != nil {
		processed, procErr := s.onChunk(p[:n])
		if procErr != nil {
			return 0, procErr
		}
		if len(processed) != n {
			copy(p, processed)
			n = len(processed)
		}
	}
	return n, err
}

// Close closes the underlying reader.
func (s *StreamingBodyReader) Close() error {
	return s.reader.Close()
}

// Buffer returns the underlying buffer.
func (s *StreamingBodyReader) Buffer() *BodyBuffer {
	return s.buffer
}

// BufferedResponseWriter wraps http.ResponseWriter to buffer response body.
type BufferedResponseWriter struct {
	buffer     *BodyBuffer
	statusCode int
	headers    map[string][]string
	headerSent bool
}

// NewBufferedResponseWriter creates a buffered response writer.
func NewBufferedResponseWriter() *BufferedResponseWriter {
	return &BufferedResponseWriter{
		buffer:     &BodyBuffer{data: make([]byte, 0)},
		statusCode: 200,
		headers:    make(map[string][]string),
	}
}

// Header returns the header map.
func (w *BufferedResponseWriter) Header() map[string][]string {
	return w.headers
}

// WriteHeader sets the status code.
func (w *BufferedResponseWriter) WriteHeader(statusCode int) {
	if !w.headerSent {
		w.statusCode = statusCode
		w.headerSent = true
	}
}

// Write writes data to the buffer.
func (w *BufferedResponseWriter) Write(data []byte) (int, error) {
	if !w.headerSent {
		w.WriteHeader(200)
	}
	w.buffer.Append(data)
	return len(data), nil
}

// StatusCode returns the status code.
func (w *BufferedResponseWriter) StatusCode() int {
	return w.statusCode
}

// Body returns the buffered body.
func (w *BufferedResponseWriter) Body() []byte {
	data, _ := w.buffer.ReadAll()
	return data
}

// Buffer returns the underlying buffer.
func (w *BufferedResponseWriter) Buffer() *BodyBuffer {
	return w.buffer
}
