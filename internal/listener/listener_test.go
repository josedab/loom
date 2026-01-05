package listener

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/josedab/loom/internal/config"
)

func TestNewManager(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}

	if m.listeners == nil {
		t.Error("expected initialized listeners map")
	}

	if m.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestConfigure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "http", Address: ":0", Protocol: "http"},
		{Name: "h2c", Address: ":0", Protocol: "h2c"},
	}

	err := m.Configure(configs)
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if m.ListenerCount() != 2 {
		t.Errorf("expected 2 listeners, got %d", m.ListenerCount())
	}
}

func TestConfigureWithInvalidTLS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{
			Name:     "https",
			Address:  ":0",
			Protocol: "https",
			TLS: &config.TLSConfig{
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
		},
	}

	err := m.Configure(configs)
	if err == nil {
		t.Error("expected error for invalid TLS cert paths")
	}
}

func TestGetListener(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "http", Address: ":0", Protocol: "http"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	// Get existing listener
	l, ok := m.GetListener("http")
	if !ok {
		t.Error("expected to find listener 'http'")
	}
	if l == nil {
		t.Error("expected non-nil listener")
	}
	if l.Name != "http" {
		t.Errorf("expected name 'http', got %s", l.Name)
	}
	if l.Protocol != ProtocolHTTP {
		t.Errorf("expected protocol 'http', got %s", l.Protocol)
	}

	// Get non-existing listener
	_, ok = m.GetListener("nonexistent")
	if ok {
		t.Error("expected not to find listener 'nonexistent'")
	}
}

func TestListenerCount(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	if m.ListenerCount() != 0 {
		t.Errorf("expected 0 listeners, got %d", m.ListenerCount())
	}

	configs := []config.ListenerConfig{
		{Name: "http1", Address: ":0", Protocol: "http"},
		{Name: "http2", Address: ":0", Protocol: "http"},
		{Name: "http3", Address: ":0", Protocol: "http"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if m.ListenerCount() != 3 {
		t.Errorf("expected 3 listeners, got %d", m.ListenerCount())
	}
}

func TestProtocolConstants(t *testing.T) {
	if ProtocolHTTP != "http" {
		t.Errorf("expected ProtocolHTTP to be 'http', got %s", ProtocolHTTP)
	}
	if ProtocolHTTPS != "https" {
		t.Errorf("expected ProtocolHTTPS to be 'https', got %s", ProtocolHTTPS)
	}
	if ProtocolH2C != "h2c" {
		t.Errorf("expected ProtocolH2C to be 'h2c', got %s", ProtocolH2C)
	}
	if ProtocolHTTP3 != "http3" {
		t.Errorf("expected ProtocolHTTP3 to be 'http3', got %s", ProtocolHTTP3)
	}
	if ProtocolGRPC != "grpc" {
		t.Errorf("expected ProtocolGRPC to be 'grpc', got %s", ProtocolGRPC)
	}
	if ProtocolGRPCS != "grpcs" {
		t.Errorf("expected ProtocolGRPCS to be 'grpcs', got %s", ProtocolGRPCS)
	}
}

func TestListenerStruct(t *testing.T) {
	l := &Listener{
		Name:     "test",
		Address:  ":8080",
		Protocol: ProtocolHTTP,
	}

	if l.Name != "test" {
		t.Errorf("expected name 'test', got %s", l.Name)
	}
	if l.Address != ":8080" {
		t.Errorf("expected address ':8080', got %s", l.Address)
	}
	if l.Protocol != ProtocolHTTP {
		t.Errorf("expected protocol 'http', got %s", l.Protocol)
	}
}

func TestStartAndShutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "http", Address: "127.0.0.1:0", Protocol: "http"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- m.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(200 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := m.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestShutdownWithoutStart(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "http", Address: ":0", Protocol: "http"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	// Shutdown without starting should not error
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := m.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown without start failed: %v", err)
	}
}

func TestStartH2C(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "h2c", Address: "127.0.0.1:0", Protocol: "h2c"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start in background
	go func() {
		m.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(200 * time.Millisecond)

	// Shutdown
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	m.Shutdown(shutdownCtx)
}

func TestStartGRPC(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "grpc", Address: "127.0.0.1:0", Protocol: "grpc"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start in background
	go func() {
		m.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(200 * time.Millisecond)

	// Shutdown
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	m.Shutdown(shutdownCtx)
}

func TestStartUnsupportedProtocol(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	// Manually add listener with unsupported protocol
	m.listeners["unsupported"] = &Listener{
		Name:     "unsupported",
		Address:  ":0",
		Protocol: Protocol("unknown"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := m.Start(ctx)
	if err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestMultipleListeners(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := NewManager(handler)

	configs := []config.ListenerConfig{
		{Name: "http1", Address: "127.0.0.1:0", Protocol: "http"},
		{Name: "http2", Address: "127.0.0.1:0", Protocol: "http"},
		{Name: "h2c", Address: "127.0.0.1:0", Protocol: "h2c"},
	}

	if err := m.Configure(configs); err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if m.ListenerCount() != 3 {
		t.Errorf("expected 3 listeners, got %d", m.ListenerCount())
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start in background
	go func() {
		m.Start(ctx)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Verify all listeners are set up
	for _, name := range []string{"http1", "http2", "h2c"} {
		if _, ok := m.GetListener(name); !ok {
			t.Errorf("expected to find listener %s", name)
		}
	}

	// Shutdown
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	m.Shutdown(shutdownCtx)
}
