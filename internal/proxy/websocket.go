// Package proxy provides WebSocket proxying support.
package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocketHandler handles WebSocket upgrade and proxying.
type WebSocketHandler struct {
	dialer *net.Dialer
}

// NewWebSocketHandler creates a new WebSocket handler.
func NewWebSocketHandler() *WebSocketHandler {
	return &WebSocketHandler{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// IsWebSocket checks if the request is a WebSocket upgrade.
func IsWebSocket(r *http.Request) bool {
	connection := r.Header.Get("Connection")
	upgrade := r.Header.Get("Upgrade")

	return strings.Contains(strings.ToLower(connection), "upgrade") &&
		strings.EqualFold(upgrade, "websocket")
}

// Proxy proxies a WebSocket connection to the upstream.
func (h *WebSocketHandler) Proxy(w http.ResponseWriter, r *http.Request, upstreamAddr string) error {
	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return nil
	}

	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	// Connect to upstream
	upstreamConn, err := h.dialer.Dial("tcp", upstreamAddr)
	if err != nil {
		return err
	}
	defer upstreamConn.Close()

	// Forward the upgrade request to upstream
	if err := r.Write(upstreamConn); err != nil {
		return err
	}

	// Flush any buffered data from client
	if clientRW.Reader.Buffered() > 0 {
		buffered := make([]byte, clientRW.Reader.Buffered())
		clientRW.Read(buffered)
		upstreamConn.Write(buffered)
	}

	// Bidirectional copy with proper cleanup
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel to signal when first copy completes
	done := make(chan struct{})

	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientConn)
		// Signal that one direction is done
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
		// Signal that one direction is done
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	// Wait for first copy to complete, then close connections to unblock the other
	<-done

	// Close connections to ensure both goroutines can complete
	// This prevents goroutine leaks by unblocking any pending reads
	clientConn.Close()
	upstreamConn.Close()

	// Wait for both goroutines to complete
	wg.Wait()

	return nil
}

// WebSocketMiddleware adds WebSocket support to a handler.
func WebSocketMiddleware(wsHandler *WebSocketHandler, getUpstream func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsWebSocket(r) {
				upstreamAddr := getUpstream(r)
				if upstreamAddr == "" {
					http.Error(w, "No upstream for WebSocket", http.StatusBadGateway)
					return
				}

				if err := wsHandler.Proxy(w, r, upstreamAddr); err != nil {
					// Connection already hijacked, can't write error response
					return
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WebSocketReverseProxy provides a more sophisticated WebSocket proxy.
type WebSocketReverseProxy struct {
	Director  func(*http.Request)
	Transport http.RoundTripper
}

// ServeHTTP handles the WebSocket proxy.
func (p *WebSocketReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !IsWebSocket(r) {
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}

	// Modify request
	outReq := r.Clone(r.Context())
	if p.Director != nil {
		p.Director(outReq)
	}

	// Get target host
	targetHost := outReq.URL.Host
	if targetHost == "" {
		targetHost = outReq.Host
	}

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", targetHost, 30*time.Second)
	if err != nil {
		return
	}
	defer backendConn.Close()

	// Send upgrade request
	outReq.Write(backendConn)

	// Bidirectional copy
	done := make(chan struct{})

	go func() {
		io.Copy(backendConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, backendConn)
		done <- struct{}{}
	}()

	<-done
}
