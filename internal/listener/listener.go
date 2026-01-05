// Package listener provides HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and gRPC listener management.
package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/josedab/loom/internal/config"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

// Protocol represents a listener protocol type.
type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolH2C   Protocol = "h2c"
	ProtocolHTTP3 Protocol = "http3" // HTTP/3 over QUIC
	ProtocolGRPC  Protocol = "grpc"
	ProtocolGRPCS Protocol = "grpcs"
)

// Listener represents a single listener endpoint.
type Listener struct {
	Name        string
	Address     string
	Protocol    Protocol
	TLSConfig   *tls.Config
	httpServer  *http.Server
	http3Server *http3.Server
	grpcServer  *grpc.Server
	listener    net.Listener
}

// Manager handles all incoming connections.
type Manager struct {
	listeners map[string]*Listener
	handler   http.Handler
	mu        sync.RWMutex
}

// NewManager creates a new listener manager.
func NewManager(handler http.Handler) *Manager {
	return &Manager{
		listeners: make(map[string]*Listener),
		handler:   handler,
	}
}

// Configure sets up listeners from configuration.
func (m *Manager) Configure(configs []config.ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cfg := range configs {
		var tlsCfg *tls.Config
		if cfg.TLS != nil {
			cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
			if err != nil {
				return fmt.Errorf("loading TLS for %s: %w", cfg.Name, err)
			}
			tlsCfg = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		}

		m.listeners[cfg.Name] = &Listener{
			Name:      cfg.Name,
			Address:   cfg.Address,
			Protocol:  Protocol(cfg.Protocol),
			TLSConfig: tlsCfg,
		}
	}

	return nil
}

// Start initializes all configured listeners.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var wg sync.WaitGroup
	errCh := make(chan error, len(m.listeners))

	for name, listener := range m.listeners {
		wg.Add(1)
		go func(name string, l *Listener) {
			defer wg.Done()
			if err := m.startListener(ctx, l); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("listener %s: %w", name, err)
			}
		}(name, listener)
	}

	// Wait briefly for any immediate startup errors
	select {
	case err := <-errCh:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// startListener starts a single listener.
func (m *Manager) startListener(ctx context.Context, l *Listener) error {
	var err error

	switch l.Protocol {
	case ProtocolHTTP, ProtocolH2C:
		return m.startHTTPListener(ctx, l)
	case ProtocolHTTPS:
		return m.startHTTPSListener(ctx, l)
	case ProtocolHTTP3:
		return m.startHTTP3Listener(ctx, l)
	case ProtocolGRPC:
		return m.startGRPCListener(ctx, l, false)
	case ProtocolGRPCS:
		return m.startGRPCListener(ctx, l, true)
	default:
		err = fmt.Errorf("unsupported protocol: %s", l.Protocol)
	}

	return err
}

// startHTTPListener starts an HTTP/1.1 or h2c listener.
func (m *Manager) startHTTPListener(ctx context.Context, l *Listener) error {
	var handler http.Handler = m.handler

	// Support HTTP/2 cleartext (h2c) for internal traffic
	if l.Protocol == ProtocolH2C {
		h2s := &http2.Server{}
		handler = h2c.NewHandler(m.handler, h2s)
	}

	l.httpServer = &http.Server{
		Addr:              l.Address,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	listener, err := net.Listen("tcp", l.Address)
	if err != nil {
		return fmt.Errorf("binding to %s: %w", l.Address, err)
	}
	l.listener = listener

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		l.httpServer.Shutdown(shutdownCtx)
	}()

	return l.httpServer.Serve(listener)
}

// startHTTPSListener starts an HTTPS listener with TLS.
func (m *Manager) startHTTPSListener(ctx context.Context, l *Listener) error {
	l.httpServer = &http.Server{
		Addr:              l.Address,
		Handler:           m.handler,
		TLSConfig:         l.TLSConfig,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(l.httpServer, &http2.Server{}); err != nil {
		return fmt.Errorf("configuring HTTP/2: %w", err)
	}

	listener, err := tls.Listen("tcp", l.Address, l.TLSConfig)
	if err != nil {
		return fmt.Errorf("binding TLS to %s: %w", l.Address, err)
	}
	l.listener = listener

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		l.httpServer.Shutdown(shutdownCtx)
	}()

	return l.httpServer.Serve(listener)
}

// startHTTP3Listener starts an HTTP/3 (QUIC) listener.
// HTTP/3 runs over UDP using QUIC protocol, providing:
// - 0-RTT connection establishment
// - Improved multiplexing without head-of-line blocking
// - Connection migration (seamless network switches)
// - Built-in encryption via TLS 1.3
func (m *Manager) startHTTP3Listener(ctx context.Context, l *Listener) error {
	if l.TLSConfig == nil {
		return fmt.Errorf("HTTP/3 requires TLS configuration")
	}

	// Clone TLS config and ensure HTTP/3 ALPN is set
	tlsConfig := l.TLSConfig.Clone()
	tlsConfig.NextProtos = []string{"h3", "h3-29"} // HTTP/3 ALPN tokens

	l.http3Server = &http3.Server{
		Addr:      l.Address,
		Handler:   m.handler,
		TLSConfig: tlsConfig,
	}

	slog.Info("starting HTTP/3 (QUIC) listener",
		"address", l.Address,
		"protocol", "h3")

	go func() {
		<-ctx.Done()
		slog.Info("shutting down HTTP/3 listener", "address", l.Address)
		if err := l.http3Server.Close(); err != nil {
			slog.Error("error closing HTTP/3 server", "error", err)
		}
	}()

	return l.http3Server.ListenAndServe()
}

// startGRPCListener starts a gRPC listener.
func (m *Manager) startGRPCListener(ctx context.Context, l *Listener, useTLS bool) error {
	var opts []grpc.ServerOption

	if useTLS {
		creds := grpc.Creds(nil) // Would use credentials.NewTLS(l.TLSConfig)
		opts = append(opts, creds)
	}

	l.grpcServer = grpc.NewServer(opts...)

	var listener net.Listener
	var err error

	if useTLS && l.TLSConfig != nil {
		listener, err = tls.Listen("tcp", l.Address, l.TLSConfig)
	} else {
		listener, err = net.Listen("tcp", l.Address)
	}
	if err != nil {
		return fmt.Errorf("binding to %s: %w", l.Address, err)
	}
	l.listener = listener

	go func() {
		<-ctx.Done()
		l.grpcServer.GracefulStop()
	}()

	return l.grpcServer.Serve(listener)
}

// Shutdown gracefully stops all listeners.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, l := range m.listeners {
		wg.Add(1)
		go func(l *Listener) {
			defer wg.Done()
			if l.httpServer != nil {
				l.httpServer.Shutdown(ctx)
			}
			if l.http3Server != nil {
				l.http3Server.Close()
			}
			if l.grpcServer != nil {
				l.grpcServer.GracefulStop()
			}
		}(l)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetListener returns a listener by name.
func (m *Manager) GetListener(name string) (*Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.listeners[name]
	return l, ok
}

// ListenerCount returns the number of configured listeners.
func (m *Manager) ListenerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners)
}
