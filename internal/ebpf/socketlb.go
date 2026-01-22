// Package ebpf provides eBPF-based acceleration for Loom.
package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SocketLBManager manages socket-level load balancing using eBPF.
// This attaches to socket operations to perform load balancing at the socket layer,
// bypassing kernel network stack for improved performance.
type SocketLBManager struct {
	config   Config
	logger   *slog.Logger
	stats    *Stats
	loaded   atomic.Bool

	// Connection tracking
	connTrack  map[string]*TrackedConnection
	connMu     sync.RWMutex
	connTicker *time.Ticker

	// Services and backends
	services map[string]*SocketService
	svcMu    sync.RWMutex

	// Event handlers
	eventHandlers []EventHandler
	handlerMu     sync.RWMutex
}

// SocketService represents a service for socket-level LB.
type SocketService struct {
	VIP        net.IP
	Port       uint16
	Protocol   string // "tcp" or "udp"
	Backends   []*SocketBackend
	LBMethod   LBMethod
	Affinity   AffinityConfig
	rrCounter  atomic.Uint64
}

// SocketBackend represents a backend for socket LB.
type SocketBackend struct {
	IP          net.IP
	Port        uint16
	Weight      uint32
	Healthy     atomic.Bool
	Connections atomic.Int64
	BytesSent   atomic.Uint64
	BytesRecv   atomic.Uint64
}

// AffinityConfig defines session affinity settings.
type AffinityConfig struct {
	Enabled    bool
	Type       AffinityType
	TimeoutSec uint32
}

// AffinityType defines the type of session affinity.
type AffinityType uint8

const (
	AffinityNone AffinityType = iota
	AffinityClientIP
	AffinityCookie
)

// TrackedConnection represents a tracked connection.
type TrackedConnection struct {
	SrcIP       net.IP
	SrcPort     uint16
	DstIP       net.IP
	DstPort     uint16
	BackendIP   net.IP
	BackendPort uint16
	Protocol    string
	State       ConnectionState
	CreatedAt   time.Time
	LastSeen    time.Time
	BytesSent   uint64
	BytesRecv   uint64
}

// NewSocketLBManager creates a new socket-level load balancer.
func NewSocketLBManager(config Config, logger *slog.Logger) *SocketLBManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &SocketLBManager{
		config:    config,
		logger:    logger,
		stats:     NewStats(),
		connTrack: make(map[string]*TrackedConnection),
		services:  make(map[string]*SocketService),
	}
}

// Load loads the socket LB eBPF programs.
func (m *SocketLBManager) Load() error {
	if m.loaded.Load() {
		return ErrAlreadyLoaded
	}

	m.logger.Info("Loading socket LB eBPF programs")

	// In a real implementation, this would load:
	// - cgroup/connect4 program for connect() interception
	// - cgroup/sendmsg4 program for UDP steering
	// - cgroup/recvmsg4 program for reply handling

	m.loaded.Store(true)
	m.logger.Info("Socket LB programs loaded")
	return nil
}

// Unload unloads the socket LB programs.
func (m *SocketLBManager) Unload() error {
	if !m.loaded.Load() {
		return nil
	}

	if m.connTicker != nil {
		m.connTicker.Stop()
	}

	m.loaded.Store(false)
	m.logger.Info("Socket LB programs unloaded")
	return nil
}

// IsLoaded returns whether the programs are loaded.
func (m *SocketLBManager) IsLoaded() bool {
	return m.loaded.Load()
}

// AddService adds a service for socket-level load balancing.
func (m *SocketLBManager) AddService(vip net.IP, port uint16, protocol string, lbMethod LBMethod) error {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()

	key := serviceKey(vip, port, protocol)
	if _, exists := m.services[key]; exists {
		return ErrServiceExists
	}

	m.services[key] = &SocketService{
		VIP:      vip,
		Port:     port,
		Protocol: protocol,
		LBMethod: lbMethod,
		Backends: make([]*SocketBackend, 0),
	}

	m.logger.Info("Service added to socket LB",
		"vip", vip.String(),
		"port", port,
		"protocol", protocol)

	return nil
}

// RemoveService removes a service.
func (m *SocketLBManager) RemoveService(vip net.IP, port uint16, protocol string) error {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()

	key := serviceKey(vip, port, protocol)
	delete(m.services, key)

	m.logger.Info("Service removed from socket LB",
		"vip", vip.String(),
		"port", port,
		"protocol", protocol)

	return nil
}

// AddBackend adds a backend to a service.
func (m *SocketLBManager) AddBackend(vip net.IP, port uint16, protocol string, backendIP net.IP, backendPort uint16, weight uint32) error {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()

	key := serviceKey(vip, port, protocol)
	svc, exists := m.services[key]
	if !exists {
		return ErrMapNotFound
	}

	// Check for duplicate
	for _, b := range svc.Backends {
		if b.IP.Equal(backendIP) && b.Port == backendPort {
			return ErrBackendExists
		}
	}

	backend := &SocketBackend{
		IP:     backendIP,
		Port:   backendPort,
		Weight: weight,
	}
	backend.Healthy.Store(true)

	svc.Backends = append(svc.Backends, backend)

	m.logger.Info("Backend added to socket LB",
		"vip", vip.String(),
		"port", port,
		"backend", fmt.Sprintf("%s:%d", backendIP, backendPort))

	return nil
}

// RemoveBackend removes a backend from a service.
func (m *SocketLBManager) RemoveBackend(vip net.IP, port uint16, protocol string, backendIP net.IP, backendPort uint16) error {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()

	key := serviceKey(vip, port, protocol)
	svc, exists := m.services[key]
	if !exists {
		return ErrMapNotFound
	}

	found := -1
	for i, b := range svc.Backends {
		if b.IP.Equal(backendIP) && b.Port == backendPort {
			found = i
			break
		}
	}

	if found < 0 {
		return ErrBackendNotFound
	}

	svc.Backends = append(svc.Backends[:found], svc.Backends[found+1:]...)

	m.logger.Info("Backend removed from socket LB",
		"vip", vip.String(),
		"port", port,
		"backend", fmt.Sprintf("%s:%d", backendIP, backendPort))

	return nil
}

// SetBackendHealth sets the health status of a backend.
func (m *SocketLBManager) SetBackendHealth(vip net.IP, port uint16, protocol string, backendIP net.IP, backendPort uint16, healthy bool) error {
	m.svcMu.RLock()
	defer m.svcMu.RUnlock()

	key := serviceKey(vip, port, protocol)
	svc, exists := m.services[key]
	if !exists {
		return ErrMapNotFound
	}

	for _, b := range svc.Backends {
		if b.IP.Equal(backendIP) && b.Port == backendPort {
			b.Healthy.Store(healthy)
			return nil
		}
	}

	return ErrBackendNotFound
}

// SetAffinity configures session affinity for a service.
func (m *SocketLBManager) SetAffinity(vip net.IP, port uint16, protocol string, affinity AffinityConfig) error {
	m.svcMu.Lock()
	defer m.svcMu.Unlock()

	key := serviceKey(vip, port, protocol)
	svc, exists := m.services[key]
	if !exists {
		return ErrMapNotFound
	}

	svc.Affinity = affinity
	return nil
}

// Connect handles a connection request and returns the selected backend.
func (m *SocketLBManager) Connect(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol string) (*SocketBackend, error) {
	m.stats.Update("connections", 1)

	// Check for existing connection (for affinity)
	connKey := connectionKey(srcIP, srcPort, dstIP, dstPort, protocol)
	m.connMu.RLock()
	if conn, exists := m.connTrack[connKey]; exists {
		m.connMu.RUnlock()
		conn.LastSeen = time.Now()
		// Find the backend
		m.svcMu.RLock()
		defer m.svcMu.RUnlock()
		svcKey := serviceKey(dstIP, dstPort, protocol)
		if svc, ok := m.services[svcKey]; ok {
			for _, b := range svc.Backends {
				if b.IP.Equal(conn.BackendIP) && b.Port == conn.BackendPort {
					return b, nil
				}
			}
		}
	}
	m.connMu.RUnlock()

	// Select a backend
	m.svcMu.RLock()
	key := serviceKey(dstIP, dstPort, protocol)
	svc, exists := m.services[key]
	m.svcMu.RUnlock()

	if !exists {
		return nil, ErrMapNotFound
	}

	// Get healthy backends
	healthy := m.getHealthyBackends(svc)
	if len(healthy) == 0 {
		return nil, ErrBackendNotFound
	}

	// Check affinity
	if svc.Affinity.Enabled && svc.Affinity.Type == AffinityClientIP {
		backend := m.selectByAffinity(srcIP, healthy)
		if backend != nil {
			m.trackConnection(srcIP, srcPort, dstIP, dstPort, backend.IP, backend.Port, protocol)
			backend.Connections.Add(1)
			m.stats.Update("lb_decisions", 1)
			return backend, nil
		}
	}

	// Select based on LB method
	var backend *SocketBackend
	switch svc.LBMethod {
	case LBMethodRoundRobin:
		idx := svc.rrCounter.Add(1) % uint64(len(healthy))
		backend = healthy[idx]
	case LBMethodLeastConn:
		backend = m.selectLeastConnections(healthy)
	case LBMethodWeighted:
		backend = m.selectWeightedBackend(healthy)
	case LBMethodIPHash:
		hash := hashIP(srcIP)
		backend = healthy[hash%uint32(len(healthy))]
	default:
		idx := svc.rrCounter.Add(1) % uint64(len(healthy))
		backend = healthy[idx]
	}

	m.trackConnection(srcIP, srcPort, dstIP, dstPort, backend.IP, backend.Port, protocol)
	backend.Connections.Add(1)
	m.stats.Update("lb_decisions", 1)

	return backend, nil
}

// Disconnect handles a connection close.
func (m *SocketLBManager) Disconnect(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol string) error {
	connKey := connectionKey(srcIP, srcPort, dstIP, dstPort, protocol)

	m.connMu.Lock()
	conn, exists := m.connTrack[connKey]
	if exists {
		conn.State = ConnStateClosed

		// Update backend connection count
		m.svcMu.RLock()
		svcKey := serviceKey(dstIP, dstPort, protocol)
		if svc, ok := m.services[svcKey]; ok {
			for _, b := range svc.Backends {
				if b.IP.Equal(conn.BackendIP) && b.Port == conn.BackendPort {
					b.Connections.Add(-1)
					break
				}
			}
		}
		m.svcMu.RUnlock()

		// Remove from tracking after some delay (for affinity)
		delete(m.connTrack, connKey)
	}
	m.connMu.Unlock()

	return nil
}

// getHealthyBackends returns backends that are healthy.
func (m *SocketLBManager) getHealthyBackends(svc *SocketService) []*SocketBackend {
	healthy := make([]*SocketBackend, 0, len(svc.Backends))
	for _, b := range svc.Backends {
		if b.Healthy.Load() {
			healthy = append(healthy, b)
		}
	}
	// Fall back to all backends if none are healthy
	if len(healthy) == 0 {
		return svc.Backends
	}
	return healthy
}

// selectLeastConnections selects the backend with fewest connections.
func (m *SocketLBManager) selectLeastConnections(backends []*SocketBackend) *SocketBackend {
	var selected *SocketBackend
	minConns := int64(1<<62 - 1)

	for _, b := range backends {
		conns := b.Connections.Load()
		if conns < minConns {
			minConns = conns
			selected = b
		}
	}

	return selected
}

// selectWeightedBackend selects a backend based on weight.
func (m *SocketLBManager) selectWeightedBackend(backends []*SocketBackend) *SocketBackend {
	var totalWeight uint32
	for _, b := range backends {
		totalWeight += b.Weight
	}
	if totalWeight == 0 {
		return backends[0]
	}

	rnd := uint32(time.Now().UnixNano() % int64(totalWeight))
	var cumulative uint32
	for _, b := range backends {
		cumulative += b.Weight
		if rnd < cumulative {
			return b
		}
	}
	return backends[len(backends)-1]
}

// selectByAffinity selects a backend based on client IP affinity.
func (m *SocketLBManager) selectByAffinity(clientIP net.IP, backends []*SocketBackend) *SocketBackend {
	hash := hashIP(clientIP)
	return backends[hash%uint32(len(backends))]
}

// trackConnection adds a connection to the tracking table.
func (m *SocketLBManager) trackConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, backendIP net.IP, backendPort uint16, protocol string) {
	connKey := connectionKey(srcIP, srcPort, dstIP, dstPort, protocol)

	m.connMu.Lock()
	defer m.connMu.Unlock()

	m.connTrack[connKey] = &TrackedConnection{
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		BackendIP:   backendIP,
		BackendPort: backendPort,
		Protocol:    protocol,
		State:       ConnStateNew,
		CreatedAt:   time.Now(),
		LastSeen:    time.Now(),
	}

	m.stats.Update("active", 1)
}

// OnEvent adds an event handler.
func (m *SocketLBManager) OnEvent(handler EventHandler) {
	m.handlerMu.Lock()
	defer m.handlerMu.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// emitEvent emits an event to all handlers.
func (m *SocketLBManager) emitEvent(event Event) {
	m.handlerMu.RLock()
	handlers := m.eventHandlers
	m.handlerMu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}

// Stats returns current statistics.
func (m *SocketLBManager) Stats() Stats {
	return m.stats.Snapshot()
}

// GetConnectionCount returns the number of tracked connections.
func (m *SocketLBManager) GetConnectionCount() int {
	m.connMu.RLock()
	defer m.connMu.RUnlock()
	return len(m.connTrack)
}

// GetServiceCount returns the number of configured services.
func (m *SocketLBManager) GetServiceCount() int {
	m.svcMu.RLock()
	defer m.svcMu.RUnlock()
	return len(m.services)
}

// Run starts the socket LB manager.
func (m *SocketLBManager) Run(ctx context.Context) error {
	if err := m.Load(); err != nil && err != ErrAlreadyLoaded {
		return err
	}

	// Start connection cleanup ticker
	m.connTicker = time.NewTicker(30 * time.Second)
	go m.cleanupLoop(ctx)

	m.logger.Info("Socket LB manager started")

	<-ctx.Done()

	m.Unload()
	m.logger.Info("Socket LB manager stopped")
	return nil
}

// cleanupLoop periodically cleans up stale connections.
func (m *SocketLBManager) cleanupLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.connTicker.C:
			m.cleanupStaleConnections()
		}
	}
}

// cleanupStaleConnections removes old tracked connections.
func (m *SocketLBManager) cleanupStaleConnections() {
	threshold := time.Now().Add(-5 * time.Minute)

	m.connMu.Lock()
	defer m.connMu.Unlock()

	for key, conn := range m.connTrack {
		if conn.LastSeen.Before(threshold) || conn.State == ConnStateClosed {
			delete(m.connTrack, key)
			m.stats.Update("active", ^uint64(0)) // Decrement
		}
	}
}

// Helper functions

func serviceKey(vip net.IP, port uint16, protocol string) string {
	return fmt.Sprintf("%s:%d/%s", vip.String(), port, protocol)
}

func connectionKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol string) string {
	return fmt.Sprintf("%s:%d->%s:%d/%s", srcIP.String(), srcPort, dstIP.String(), dstPort, protocol)
}
