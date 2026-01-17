package plugin

import (
	"io"
	"strings"
	"testing"
)

func TestDefaultBodyBufferConfig(t *testing.T) {
	cfg := DefaultBodyBufferConfig()

	if cfg.MaxSize != 10*1024*1024 {
		t.Errorf("expected MaxSize 10MB, got %d", cfg.MaxSize)
	}
	if !cfg.EnableStream {
		t.Error("expected EnableStream to be true")
	}
	if cfg.ChunkSize != 64*1024 {
		t.Errorf("expected ChunkSize 64KB, got %d", cfg.ChunkSize)
	}
}

func TestNewBodyBuffer(t *testing.T) {
	reader := strings.NewReader("test data")
	cfg := DefaultBodyBufferConfig()

	buf := NewBodyBuffer(reader, cfg)
	if buf == nil {
		t.Fatal("expected non-nil buffer")
	}
	if buf.maxSize != cfg.MaxSize {
		t.Errorf("expected maxSize %d, got %d", cfg.MaxSize, buf.maxSize)
	}
	if buf.streaming != cfg.EnableStream {
		t.Error("streaming mismatch")
	}
}

func TestNewBodyBufferFromBytes(t *testing.T) {
	data := []byte("hello world")
	buf := NewBodyBufferFromBytes(data)

	if buf == nil {
		t.Fatal("expected non-nil buffer")
	}
	if !buf.written {
		t.Error("expected written to be true")
	}
	if !buf.endOfBody {
		t.Error("expected endOfBody to be true")
	}
	if string(buf.data) != "hello world" {
		t.Error("data mismatch")
	}
}

func TestBodyBuffer_ReadAll(t *testing.T) {
	reader := strings.NewReader("test data for reading")
	cfg := DefaultBodyBufferConfig()
	buf := NewBodyBuffer(reader, cfg)

	data, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(data) != "test data for reading" {
		t.Errorf("expected 'test data for reading', got %s", string(data))
	}

	// Second call should return cached data
	data2, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("second ReadAll failed: %v", err)
	}
	if string(data2) != "test data for reading" {
		t.Error("cached data mismatch")
	}
}

func TestBodyBuffer_ReadAll_NilReader(t *testing.T) {
	cfg := DefaultBodyBufferConfig()
	buf := NewBodyBuffer(nil, cfg)

	data, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if data != nil {
		t.Errorf("expected nil data, got %v", data)
	}
	if !buf.written {
		t.Error("expected written to be true")
	}
}

func TestBodyBuffer_Read(t *testing.T) {
	data := []byte("hello world")
	buf := NewBodyBufferFromBytes(data)

	// Read portion
	result, err := buf.Read(0, 5)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(result) != "hello" {
		t.Errorf("expected 'hello', got %s", string(result))
	}

	// Read from middle
	result, err = buf.Read(6, 5)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(result) != "world" {
		t.Errorf("expected 'world', got %s", string(result))
	}

	// Read beyond end
	result, err = buf.Read(6, 100)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(result) != "world" {
		t.Errorf("expected 'world', got %s", string(result))
	}
}

func TestBodyBuffer_Read_NotBuffered(t *testing.T) {
	cfg := DefaultBodyBufferConfig()
	buf := NewBodyBuffer(strings.NewReader("data"), cfg)

	_, err := buf.Read(0, 5)
	if err != ErrBodyNotBuffered {
		t.Errorf("expected ErrBodyNotBuffered, got %v", err)
	}
}

func TestBodyBuffer_Read_StartBeyondLength(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	result, err := buf.Read(100, 5)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil for start beyond length, got %v", result)
	}
}

func TestBodyBuffer_Write(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("original"))

	buf.Write([]byte("new data"))

	data, _ := buf.ReadAll()
	if string(data) != "new data" {
		t.Errorf("expected 'new data', got %s", string(data))
	}
}

func TestBodyBuffer_Append(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	buf.Append([]byte(" world"))

	data, _ := buf.ReadAll()
	if string(data) != "hello world" {
		t.Errorf("expected 'hello world', got %s", string(data))
	}
}

func TestBodyBuffer_Prepend(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("world"))

	buf.Prepend([]byte("hello "))

	data, _ := buf.ReadAll()
	if string(data) != "hello world" {
		t.Errorf("expected 'hello world', got %s", string(data))
	}
}

func TestBodyBuffer_Replace(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello world"))

	err := buf.Replace(6, 11, []byte("there"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	data, _ := buf.ReadAll()
	if string(data) != "hello there" {
		t.Errorf("expected 'hello there', got %s", string(data))
	}
}

func TestBodyBuffer_Replace_InvalidRange(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	err := buf.Replace(-1, 5, []byte("x"))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange for negative start, got %v", err)
	}

	err = buf.Replace(10, 5, []byte("x"))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange for start > len, got %v", err)
	}

	err = buf.Replace(2, 1, []byte("x"))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange for end < start, got %v", err)
	}
}

func TestBodyBuffer_Replace_NotBuffered(t *testing.T) {
	cfg := DefaultBodyBufferConfig()
	buf := NewBodyBuffer(strings.NewReader("data"), cfg)

	err := buf.Replace(0, 1, []byte("x"))
	if err != ErrBodyNotBuffered {
		t.Errorf("expected ErrBodyNotBuffered, got %v", err)
	}
}

func TestBodyBuffer_Size(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	if buf.Size() != 5 {
		t.Errorf("expected size 5, got %d", buf.Size())
	}

	buf.Append([]byte(" world"))
	if buf.Size() != 11 {
		t.Errorf("expected size 11, got %d", buf.Size())
	}
}

func TestBodyBuffer_IsBuffered(t *testing.T) {
	cfg := DefaultBodyBufferConfig()
	buf := NewBodyBuffer(strings.NewReader("data"), cfg)

	if buf.IsBuffered() {
		t.Error("expected IsBuffered to be false before ReadAll")
	}

	buf.ReadAll()

	if !buf.IsBuffered() {
		t.Error("expected IsBuffered to be true after ReadAll")
	}
}

func TestBodyBuffer_IsEndOfBody(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("data"))

	if !buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be true for bytes buffer")
	}

	buf.SetEndOfBody(false)
	if buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be false after SetEndOfBody(false)")
	}
}

func TestBodyBuffer_AsReader(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	reader := buf.AsReader()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %s", string(data))
	}
}

func TestBodyBuffer_Reset(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))
	buf.AddChunk([]byte("chunk"))

	buf.Reset()

	if buf.IsBuffered() {
		t.Error("expected IsBuffered to be false after Reset")
	}
	if buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be false after Reset")
	}
	if buf.Size() != 0 {
		t.Errorf("expected size 0 after Reset, got %d", buf.Size())
	}
}

func TestBodyBuffer_Chunks(t *testing.T) {
	buf := &BodyBuffer{}

	buf.AddChunk([]byte("chunk1"))
	buf.AddChunk([]byte("chunk2"))
	buf.AddChunk([]byte("chunk3"))

	chunks := buf.GetChunks()
	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(chunks))
	}

	buf.ConsolidateChunks()

	data, _ := buf.ReadAll()
	if string(data) != "chunk1chunk2chunk3" {
		t.Errorf("expected 'chunk1chunk2chunk3', got %s", string(data))
	}

	// Chunks should be cleared after consolidation
	chunks = buf.GetChunks()
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks after consolidation, got %d", len(chunks))
	}
}

func TestBodyBuffer_ConsolidateChunks_Empty(t *testing.T) {
	buf := &BodyBuffer{}
	buf.ConsolidateChunks() // Should not panic
}

func TestBodyBufferError(t *testing.T) {
	err := ErrBodyNotBuffered
	if err.Error() != "body not buffered" {
		t.Errorf("expected 'body not buffered', got %s", err.Error())
	}

	err = ErrInvalidRange
	if err.Error() != "invalid range" {
		t.Errorf("expected 'invalid range', got %s", err.Error())
	}

	err = ErrBufferTooLarge
	if err.Error() != "buffer exceeds maximum size" {
		t.Errorf("expected 'buffer exceeds maximum size', got %s", err.Error())
	}
}

func TestNewStreamingBodyReader(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("streaming data"))

	sbr := NewStreamingBodyReader(reader, 1024, nil)
	if sbr == nil {
		t.Fatal("expected non-nil StreamingBodyReader")
	}

	if sbr.chunkSize != 1024 {
		t.Errorf("expected chunkSize 1024, got %d", sbr.chunkSize)
	}
}

func TestNewStreamingBodyReader_DefaultChunkSize(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("data"))

	sbr := NewStreamingBodyReader(reader, 0, nil)

	if sbr.chunkSize != 64*1024 {
		t.Errorf("expected default chunkSize 64KB, got %d", sbr.chunkSize)
	}
}

func TestStreamingBodyReader_Read(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("hello world"))

	var processedChunks []string
	onChunk := func(data []byte) ([]byte, error) {
		processedChunks = append(processedChunks, string(data))
		return data, nil
	}

	sbr := NewStreamingBodyReader(reader, 1024, onChunk)

	buf := make([]byte, 11)
	n, err := sbr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 11 {
		t.Errorf("expected 11 bytes, got %d", n)
	}

	if len(processedChunks) != 1 {
		t.Errorf("expected 1 processed chunk, got %d", len(processedChunks))
	}
}

func TestStreamingBodyReader_Close(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("data"))
	sbr := NewStreamingBodyReader(reader, 1024, nil)

	err := sbr.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestStreamingBodyReader_Buffer(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("data"))
	sbr := NewStreamingBodyReader(reader, 1024, nil)

	buf := sbr.Buffer()
	if buf == nil {
		t.Error("expected non-nil buffer")
	}
}

func TestNewBufferedResponseWriter(t *testing.T) {
	brw := NewBufferedResponseWriter()

	if brw == nil {
		t.Fatal("expected non-nil BufferedResponseWriter")
	}
	if brw.statusCode != 200 {
		t.Errorf("expected status code 200, got %d", brw.statusCode)
	}
	if brw.headers == nil {
		t.Error("expected non-nil headers")
	}
}

func TestBufferedResponseWriter_Header(t *testing.T) {
	brw := NewBufferedResponseWriter()

	headers := brw.Header()
	if headers == nil {
		t.Fatal("expected non-nil headers")
	}

	headers["Content-Type"] = []string{"application/json"}
	if brw.headers["Content-Type"][0] != "application/json" {
		t.Error("header not set correctly")
	}
}

func TestBufferedResponseWriter_WriteHeader(t *testing.T) {
	brw := NewBufferedResponseWriter()

	brw.WriteHeader(201)
	if brw.statusCode != 201 {
		t.Errorf("expected status code 201, got %d", brw.statusCode)
	}
	if !brw.headerSent {
		t.Error("expected headerSent to be true")
	}

	// Second call should be ignored
	brw.WriteHeader(404)
	if brw.statusCode != 201 {
		t.Errorf("expected status code to remain 201, got %d", brw.statusCode)
	}
}

func TestBufferedResponseWriter_Write(t *testing.T) {
	brw := NewBufferedResponseWriter()

	n, err := brw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}

	n, err = brw.Write([]byte(" world"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 6 {
		t.Errorf("expected 6 bytes written, got %d", n)
	}

	body := brw.Body()
	if string(body) != "hello world" {
		t.Errorf("expected 'hello world', got %s", string(body))
	}
}

func TestBufferedResponseWriter_StatusCode(t *testing.T) {
	brw := NewBufferedResponseWriter()

	brw.WriteHeader(500)
	if brw.StatusCode() != 500 {
		t.Errorf("expected status code 500, got %d", brw.StatusCode())
	}
}

func TestBufferedResponseWriter_Buffer(t *testing.T) {
	brw := NewBufferedResponseWriter()
	brw.Write([]byte("data"))

	buf := brw.Buffer()
	if buf == nil {
		t.Error("expected non-nil buffer")
	}
	if buf.Size() != 4 {
		t.Errorf("expected buffer size 4, got %d", buf.Size())
	}
}

func TestBodyBuffer_Read_AfterAppend(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))
	buf.Append([]byte(" world"))

	result, err := buf.Read(0, 11)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("expected 'hello world', got %s", string(result))
	}
}

func TestBodyBuffer_Read_AfterPrepend(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("world"))
	buf.Prepend([]byte("hello "))

	result, err := buf.Read(0, 11)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(result) != "hello world" {
		t.Errorf("expected 'hello world', got %s", string(result))
	}
}

func TestBodyBuffer_Replace_AtEnd(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello world"))

	// Replace "world" with "everyone"
	err := buf.Replace(6, 11, []byte("everyone"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	data, _ := buf.ReadAll()
	if string(data) != "hello everyone" {
		t.Errorf("expected 'hello everyone', got %s", string(data))
	}
}

func TestBodyBuffer_Replace_Expand(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hi"))

	err := buf.Replace(0, 2, []byte("hello world"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	if buf.Size() != 11 {
		t.Errorf("expected size 11, got %d", buf.Size())
	}
}

func TestBodyBuffer_Replace_Shrink(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello world"))

	err := buf.Replace(0, 11, []byte("hi"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	if buf.Size() != 2 {
		t.Errorf("expected size 2, got %d", buf.Size())
	}
}

func TestBodyBuffer_Multiple_Operations(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("start"))

	buf.Append([]byte(" middle"))
	buf.Prepend([]byte("prefix "))
	buf.Append([]byte(" end"))

	data, _ := buf.ReadAll()
	if string(data) != "prefix start middle end" {
		t.Errorf("expected 'prefix start middle end', got %s", string(data))
	}
}

func TestStreamingBodyReader_WithTransformation(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("hello"))

	var processed []byte
	onChunk := func(data []byte) ([]byte, error) {
		// Just record what was processed (returns same data since same length)
		processed = make([]byte, len(data))
		copy(processed, data)
		return processed, nil
	}

	sbr := NewStreamingBodyReader(reader, 1024, onChunk)

	buf := make([]byte, 10)
	n, err := sbr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 5 {
		t.Errorf("expected 5 bytes read, got %d", n)
	}
	if string(processed) != "hello" {
		t.Errorf("onChunk should have been called with 'hello', got %s", string(processed))
	}
}

func TestStreamingBodyReader_WithLengthChange(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("hello"))

	onChunk := func(data []byte) ([]byte, error) {
		// Double the data to trigger copy back
		return append(data, data...), nil
	}

	sbr := NewStreamingBodyReader(reader, 1024, onChunk)

	buf := make([]byte, 20)
	n, err := sbr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 10 {
		t.Errorf("expected 10 bytes (doubled), got %d", n)
	}
	if string(buf[:n]) != "hellohello" {
		t.Errorf("expected 'hellohello', got %s", string(buf[:n]))
	}
}

func TestBufferedResponseWriter_MultipleWrites(t *testing.T) {
	brw := NewBufferedResponseWriter()

	brw.Write([]byte("first "))
	brw.Write([]byte("second "))
	brw.Write([]byte("third"))

	body := brw.Body()
	if string(body) != "first second third" {
		t.Errorf("expected 'first second third', got %s", string(body))
	}
}

func TestBufferedResponseWriter_HeadersBeforeWrite(t *testing.T) {
	brw := NewBufferedResponseWriter()

	brw.Header()["X-Custom"] = []string{"value"}
	brw.Header()["Content-Type"] = []string{"text/plain"}

	brw.WriteHeader(202)

	if brw.StatusCode() != 202 {
		t.Errorf("expected status 202, got %d", brw.StatusCode())
	}
	if brw.Header()["X-Custom"][0] != "value" {
		t.Error("expected X-Custom header")
	}
}

func TestBodyBuffer_Size_AfterOperations(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("test"))

	if buf.Size() != 4 {
		t.Errorf("initial size should be 4, got %d", buf.Size())
	}

	buf.Append([]byte("12345"))
	if buf.Size() != 9 {
		t.Errorf("after append size should be 9, got %d", buf.Size())
	}

	buf.Write([]byte("new"))
	if buf.Size() != 3 {
		t.Errorf("after write size should be 3, got %d", buf.Size())
	}

	buf.Reset()
	if buf.Size() != 0 {
		t.Errorf("after reset size should be 0, got %d", buf.Size())
	}
}

func TestBodyBuffer_AsReader_MultipleTimes(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("test data"))

	reader1 := buf.AsReader()
	data1, _ := io.ReadAll(reader1)

	reader2 := buf.AsReader()
	data2, _ := io.ReadAll(reader2)

	if string(data1) != string(data2) {
		t.Error("AsReader should return same data each time")
	}
}

func TestStreamingBodyReader_OnChunkError(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("hello"))

	onChunk := func(data []byte) ([]byte, error) {
		return nil, io.ErrUnexpectedEOF
	}

	sbr := NewStreamingBodyReader(reader, 1024, onChunk)

	buf := make([]byte, 10)
	_, err := sbr.Read(buf)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestBodyBuffer_ReadAll_EmptyBuffer(t *testing.T) {
	buf := &BodyBuffer{}

	data, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestBodyBuffer_Write_Empty(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("original"))
	buf.Write([]byte{})

	data, _ := buf.ReadAll()
	if len(data) != 0 {
		t.Errorf("expected empty data after writing empty, got %d bytes", len(data))
	}
}

func TestBodyBuffer_Append_ToEmpty(t *testing.T) {
	buf := &BodyBuffer{}
	buf.Append([]byte("added"))

	data, _ := buf.ReadAll()
	if string(data) != "added" {
		t.Errorf("expected 'added', got %s", string(data))
	}
}

func TestBodyBuffer_Prepend_ToEmpty(t *testing.T) {
	buf := &BodyBuffer{}
	buf.Prepend([]byte("prepended"))

	data, _ := buf.ReadAll()
	if string(data) != "prepended" {
		t.Errorf("expected 'prepended', got %s", string(data))
	}
}

func TestBodyBufferConfig_Defaults(t *testing.T) {
	cfg := DefaultBodyBufferConfig()

	if cfg.MaxSize != 10*1024*1024 {
		t.Errorf("expected MaxSize 10MB, got %d", cfg.MaxSize)
	}
	if !cfg.EnableStream {
		t.Error("expected EnableStream to be true")
	}
	if cfg.ChunkSize != 64*1024 {
		t.Errorf("expected ChunkSize 64KB, got %d", cfg.ChunkSize)
	}
}

func TestNewBodyBuffer_WithConfig(t *testing.T) {
	reader := strings.NewReader("test content")
	cfg := BodyBufferConfig{
		MaxSize:      1024,
		ChunkSize:    256,
		EnableStream: true,
	}

	buf := NewBodyBuffer(reader, cfg)

	if buf.maxSize != 1024 {
		t.Errorf("expected maxSize 1024, got %d", buf.maxSize)
	}
	if !buf.streaming {
		t.Error("expected streaming to be true")
	}

	// Verify buffer was created correctly
	if buf == nil {
		t.Error("expected non-nil buffer")
	}
}

func TestBufferedResponseWriter_FullFlow(t *testing.T) {
	brw := NewBufferedResponseWriter()
	brw.WriteHeader(201)
	brw.Write([]byte("data"))

	// Verify data was written
	if brw.StatusCode() != 201 {
		t.Errorf("expected status 201, got %d", brw.StatusCode())
	}
	body := brw.Body()
	if string(body) != "data" {
		t.Errorf("expected 'data', got %s", string(body))
	}
}

func TestBodyBuffer_ConcurrentOperations(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("initial"))

	done := make(chan bool, 20)

	for i := 0; i < 10; i++ {
		go func() {
			_, _ = buf.ReadAll()
			done <- true
		}()

		go func() {
			_ = buf.Size()
			_ = buf.IsBuffered()
			_ = buf.IsEndOfBody()
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestBodyBuffer_ReadAll_WithMaxSize(t *testing.T) {
	// Create a reader with more data than maxSize
	reader := strings.NewReader("this is a long string that exceeds max size")
	cfg := BodyBufferConfig{
		MaxSize:      10, // Only allow 10 bytes
		EnableStream: false,
	}
	buf := NewBodyBuffer(reader, cfg)

	data, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Should only read up to maxSize bytes
	if len(data) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(data))
	}
	if string(data) != "this is a " {
		t.Errorf("expected 'this is a ', got %s", string(data))
	}
}

func TestBodyBuffer_ReadAll_NoMaxSize(t *testing.T) {
	reader := strings.NewReader("unlimited read")
	cfg := BodyBufferConfig{
		MaxSize:      0, // No limit
		EnableStream: false,
	}
	buf := NewBodyBuffer(reader, cfg)

	data, err := buf.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(data) != "unlimited read" {
		t.Errorf("expected 'unlimited read', got %s", string(data))
	}
}

type errorReader struct{}

func (e errorReader) Read(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestBodyBuffer_ReadAll_ReaderError(t *testing.T) {
	cfg := BodyBufferConfig{
		MaxSize: 0, // No limit
	}
	buf := NewBodyBuffer(errorReader{}, cfg)

	_, err := buf.ReadAll()
	if err != io.ErrClosedPipe {
		t.Errorf("expected ErrClosedPipe, got %v", err)
	}
}

func TestBodyBuffer_ReadAll_ReaderError_WithLimit(t *testing.T) {
	cfg := BodyBufferConfig{
		MaxSize: 100, // With limit
	}
	buf := NewBodyBuffer(errorReader{}, cfg)

	_, err := buf.ReadAll()
	if err != io.ErrClosedPipe {
		t.Errorf("expected ErrClosedPipe, got %v", err)
	}
}

func TestBodyBuffer_SetEndOfBody(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("data"))

	if !buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be true initially")
	}

	buf.SetEndOfBody(false)
	if buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be false after setting to false")
	}

	buf.SetEndOfBody(true)
	if !buf.IsEndOfBody() {
		t.Error("expected IsEndOfBody to be true after setting to true")
	}
}

func TestBodyBuffer_Replace_EndEqualToLength(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	// Replace entire buffer
	err := buf.Replace(0, 5, []byte("world"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	data, _ := buf.ReadAll()
	if string(data) != "world" {
		t.Errorf("expected 'world', got %s", string(data))
	}
}

func TestBodyBuffer_Replace_EndGreaterThanLength(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello"))

	// End > dataLen is an error
	err := buf.Replace(0, 100, []byte("x"))
	if err != ErrInvalidRange {
		t.Errorf("expected ErrInvalidRange for end > dataLen, got %v", err)
	}
}

func TestBodyBuffer_Replace_MiddleSameSize(t *testing.T) {
	buf := NewBodyBufferFromBytes([]byte("hello world"))

	// Replace "lo wo" with "XXXXX"
	err := buf.Replace(3, 8, []byte("XXXXX"))
	if err != nil {
		t.Fatalf("Replace failed: %v", err)
	}

	data, _ := buf.ReadAll()
	if string(data) != "helXXXXXrld" {
		t.Errorf("expected 'helXXXXXrld', got %s", string(data))
	}
}

func TestStreamingBodyReader_NoOnChunk(t *testing.T) {
	reader := io.NopCloser(strings.NewReader("data"))
	sbr := NewStreamingBodyReader(reader, 1024, nil)

	buf := make([]byte, 10)
	n, err := sbr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}

	if n != 4 {
		t.Errorf("expected 4 bytes, got %d", n)
	}
	if string(buf[:n]) != "data" {
		t.Errorf("expected 'data', got %s", string(buf[:n]))
	}
}

func TestStreamingBodyReader_EOF(t *testing.T) {
	reader := io.NopCloser(strings.NewReader(""))
	sbr := NewStreamingBodyReader(reader, 1024, nil)

	buf := make([]byte, 10)
	n, err := sbr.Read(buf)
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
}

func TestBufferedResponseWriter_WriteImplicitHeaders(t *testing.T) {
	brw := NewBufferedResponseWriter()

	// Write without explicit WriteHeader
	brw.Write([]byte("body"))

	// Headers should be sent with default 200
	if !brw.headerSent {
		t.Error("expected headerSent to be true after Write")
	}
	if brw.StatusCode() != 200 {
		t.Errorf("expected default status 200, got %d", brw.StatusCode())
	}
}

func TestBufferedResponseWriter_EmptyWrite(t *testing.T) {
	brw := NewBufferedResponseWriter()

	n, err := brw.Write([]byte{})
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written, got %d", n)
	}
}

func TestBodyBuffer_Chunks_Operations(t *testing.T) {
	buf := &BodyBuffer{}

	// Add chunks
	buf.AddChunk([]byte("a"))
	buf.AddChunk([]byte("b"))

	// Check chunks count
	chunks := buf.GetChunks()
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(chunks))
	}

	// Check individual chunk contents
	if string(chunks[0]) != "a" {
		t.Errorf("expected first chunk 'a', got %s", string(chunks[0]))
	}
	if string(chunks[1]) != "b" {
		t.Errorf("expected second chunk 'b', got %s", string(chunks[1]))
	}
}

func TestBodyBuffer_ConsolidateChunks_WithData(t *testing.T) {
	// ConsolidateChunks replaces data with chunks (doesn't preserve existing data)
	buf := &BodyBuffer{}
	buf.AddChunk([]byte("chunk1"))
	buf.AddChunk([]byte("chunk2"))

	buf.ConsolidateChunks()

	data, _ := buf.ReadAll()
	if string(data) != "chunk1chunk2" {
		t.Errorf("expected 'chunk1chunk2', got %s", string(data))
	}
}
