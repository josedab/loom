// Package ebpf provides eBPF-based acceleration for Loom.
package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors
var (
	ErrNotSupported   = errors.New("eBPF not supported on this platform")
	ErrNotLoaded      = errors.New("eBPF program not loaded")
	ErrAlreadyLoaded  = errors.New("eBPF program already loaded")
	ErrInvalidConfig  = errors.New("invalid eBPF configuration")
	ErrMapNotFound    = errors.New("eBPF map not found")
	ErrServiceExists  = errors.New("service already exists")
	ErrBackendExists  = errors.New("backend already exists")
	ErrBackendNotFound = errors.New("backend not found")
)

// XDPManager manages XDP programs for connection steering.
type XDPManager struct {
	config   Config
	logger   *slog.Logger
	stats    *Stats
	loaded   atomic.Bool
	attached atomic.Bool

	// Service configuration (simulated without actual eBPF)
	services map[string]*Service
	backends map[string][]Backend
	mu       sync.RWMutex

	// Callbacks
	onPacket func(pkt *PacketInfo)
}

// PacketInfo contains information about a processed packet.
type PacketInfo struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Action     XDPAction
	BackendIP  net.IP
	BackendPort uint16
	Timestamp  time.Time
}

// NewXDPManager creates a new XDP manager.
func NewXDPManager(config Config, logger *slog.Logger) *XDPManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &XDPManager{
		config:   config,
		logger:   logger,
		stats:    NewStats(),
		services: make(map[string]*Service),
		backends: make(map[string][]Backend),
	}
}

// Load loads and verifies the XDP program.
func (m *XDPManager) Load() error {
	if m.loaded.Load() {
		return ErrAlreadyLoaded
	}

	m.logger.Info("Loading XDP program",
		"interface", m.config.Interface,
		"mode", m.config.XDPMode)

	// In a real implementation, this would:
	// 1. Load compiled eBPF object file
	// 2. Verify the program
	// 3. Initialize maps

	// For now, we simulate the loading process
	m.loaded.Store(true)
	m.logger.Info("XDP program loaded successfully")
	return nil
}

// Attach attaches the XDP program to the configured interface.
func (m *XDPManager) Attach() error {
	if !m.loaded.Load() {
		return ErrNotLoaded
	}
	if m.attached.Load() {
		return nil // Already attached
	}

	m.logger.Info("Attaching XDP program",
		"interface", m.config.Interface,
		"mode", m.config.XDPMode)

	// In a real implementation, this would attach to the interface
	m.attached.Store(true)
	m.logger.Info("XDP program attached successfully")
	return nil
}

// Detach detaches the XDP program from the interface.
func (m *XDPManager) Detach() error {
	if !m.attached.Load() {
		return nil
	}

	m.logger.Info("Detaching XDP program", "interface", m.config.Interface)
	m.attached.Store(false)
	return nil
}

// Unload unloads the XDP program.
func (m *XDPManager) Unload() error {
	if m.attached.Load() {
		if err := m.Detach(); err != nil {
			return err
		}
	}

	m.loaded.Store(false)
	m.logger.Info("XDP program unloaded")
	return nil
}

// IsLoaded returns whether the XDP program is loaded.
func (m *XDPManager) IsLoaded() bool {
	return m.loaded.Load()
}

// IsAttached returns whether the XDP program is attached.
func (m *XDPManager) IsAttached() bool {
	return m.attached.Load()
}

// AddService adds a service to the XDP steering table.
func (m *XDPManager) AddService(svc *Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", svc.VIP.String(), svc.Port)
	if _, exists := m.services[key]; exists {
		return ErrServiceExists
	}

	m.services[key] = svc
	m.backends[key] = svc.Backends

	m.logger.Info("Service added to XDP",
		"vip", svc.VIP.String(),
		"port", svc.Port,
		"backends", len(svc.Backends))

	return nil
}

// UpdateService updates an existing service.
func (m *XDPManager) UpdateService(svc *Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", svc.VIP.String(), svc.Port)
	m.services[key] = svc
	m.backends[key] = svc.Backends

	m.logger.Info("Service updated in XDP",
		"vip", svc.VIP.String(),
		"port", svc.Port,
		"backends", len(svc.Backends))

	return nil
}

// RemoveService removes a service from the XDP steering table.
func (m *XDPManager) RemoveService(vip net.IP, port uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	delete(m.services, key)
	delete(m.backends, key)

	m.logger.Info("Service removed from XDP", "vip", vip.String(), "port", port)
	return nil
}

// AddBackend adds a backend to a service.
func (m *XDPManager) AddBackend(vip net.IP, port uint16, backend Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	svc, exists := m.services[key]
	if !exists {
		return ErrMapNotFound
	}

	// Check for duplicates
	for _, b := range m.backends[key] {
		if b.IP.Equal(backend.IP) && b.Port == backend.Port {
			return ErrBackendExists
		}
	}

	m.backends[key] = append(m.backends[key], backend)
	svc.Backends = m.backends[key]

	m.logger.Info("Backend added to XDP",
		"vip", vip.String(),
		"port", port,
		"backend", fmt.Sprintf("%s:%d", backend.IP, backend.Port))

	return nil
}

// RemoveBackend removes a backend from a service.
func (m *XDPManager) RemoveBackend(vip net.IP, port uint16, backendIP net.IP, backendPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	backends, exists := m.backends[key]
	if !exists {
		return ErrMapNotFound
	}

	found := false
	newBackends := make([]Backend, 0, len(backends))
	for _, b := range backends {
		if b.IP.Equal(backendIP) && b.Port == backendPort {
			found = true
			continue
		}
		newBackends = append(newBackends, b)
	}

	if !found {
		return ErrBackendNotFound
	}

	m.backends[key] = newBackends
	if svc, ok := m.services[key]; ok {
		svc.Backends = newBackends
	}

	m.logger.Info("Backend removed from XDP",
		"vip", vip.String(),
		"port", port,
		"backend", fmt.Sprintf("%s:%d", backendIP, backendPort))

	return nil
}

// UpdateBackendHealth updates the health status of a backend.
func (m *XDPManager) UpdateBackendHealth(vip net.IP, port uint16, backendIP net.IP, backendPort uint16, healthy bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	backends, exists := m.backends[key]
	if !exists {
		return ErrMapNotFound
	}

	for i := range backends {
		if backends[i].IP.Equal(backendIP) && backends[i].Port == backendPort {
			backends[i].Healthy = healthy
			return nil
		}
	}

	return ErrBackendNotFound
}

// GetService returns a service by VIP and port.
func (m *XDPManager) GetService(vip net.IP, port uint16) (*Service, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	svc, exists := m.services[key]
	if !exists {
		return nil, ErrMapNotFound
	}

	return svc, nil
}

// ListServices returns all configured services.
func (m *XDPManager) ListServices() []*Service {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Service, 0, len(m.services))
	for _, svc := range m.services {
		result = append(result, svc)
	}
	return result
}

// SelectBackend selects a backend for a given connection using the configured LB method.
func (m *XDPManager) SelectBackend(vip net.IP, port uint16, srcIP net.IP, srcPort uint16) (*Backend, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", vip.String(), port)
	svc, exists := m.services[key]
	if !exists {
		return nil, ErrMapNotFound
	}

	backends := m.backends[key]
	if len(backends) == 0 {
		return nil, ErrBackendNotFound
	}

	// Filter healthy backends
	healthy := make([]Backend, 0, len(backends))
	for _, b := range backends {
		if b.Healthy {
			healthy = append(healthy, b)
		}
	}

	if len(healthy) == 0 {
		// Fall back to all backends if none are healthy
		healthy = backends
	}

	// Select based on LB method
	var selected *Backend
	switch svc.LBMethod {
	case LBMethodRoundRobin:
		selected = m.selectRoundRobin(key, healthy)
	case LBMethodLeastConn:
		selected = m.selectLeastConn(healthy)
	case LBMethodWeighted:
		selected = m.selectWeighted(healthy)
	case LBMethodIPHash:
		selected = m.selectIPHash(srcIP, healthy)
	case LBMethodMaglev:
		selected = m.selectMaglev(srcIP, srcPort, healthy)
	default:
		selected = m.selectRoundRobin(key, healthy)
	}

	m.stats.Update("lb_decisions", 1)
	return selected, nil
}

// Round robin selection (simplified)
func (m *XDPManager) selectRoundRobin(key string, backends []Backend) *Backend {
	// In production, this would use atomic counters per service
	idx := time.Now().UnixNano() % int64(len(backends))
	return &backends[idx]
}

// Least connections selection
func (m *XDPManager) selectLeastConn(backends []Backend) *Backend {
	// Simplified: would track connections in eBPF maps
	return &backends[0]
}

// Weighted selection
func (m *XDPManager) selectWeighted(backends []Backend) *Backend {
	var totalWeight uint32
	for _, b := range backends {
		totalWeight += b.Weight
	}
	if totalWeight == 0 {
		return &backends[0]
	}

	rnd := uint32(time.Now().UnixNano() % int64(totalWeight))
	var cumulative uint32
	for i := range backends {
		cumulative += backends[i].Weight
		if rnd < cumulative {
			return &backends[i]
		}
	}
	return &backends[len(backends)-1]
}

// IP hash selection for session affinity
func (m *XDPManager) selectIPHash(srcIP net.IP, backends []Backend) *Backend {
	hash := hashIP(srcIP)
	idx := hash % uint32(len(backends))
	return &backends[idx]
}

// Maglev consistent hashing
func (m *XDPManager) selectMaglev(srcIP net.IP, srcPort uint16, backends []Backend) *Backend {
	// Simplified maglev - in production would use full maglev lookup table
	hash := hashIP(srcIP) ^ uint32(srcPort)
	idx := hash % uint32(len(backends))
	return &backends[idx]
}

// Simple IP hash function
func hashIP(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	// FNV-1a hash
	hash := uint32(2166136261)
	for _, b := range ip4 {
		hash ^= uint32(b)
		hash *= 16777619
	}
	return hash
}

// OnPacket sets a callback for processed packets.
func (m *XDPManager) OnPacket(fn func(*PacketInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPacket = fn
}

// SimulatePacket simulates processing a packet through XDP.
// This is used for testing and when eBPF is not available.
func (m *XDPManager) SimulatePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) (*PacketInfo, error) {
	m.stats.Update("packets", 1)

	// Try to find a matching service
	backend, err := m.SelectBackend(dstIP, dstPort, srcIP, srcPort)

	pkt := &PacketInfo{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  proto,
		Timestamp: time.Now(),
	}

	if err != nil {
		// No matching service, pass the packet
		pkt.Action = XDPPass
		m.stats.Update("xdp_pass", 1)
	} else {
		// Redirect to backend
		pkt.Action = XDPRedirect
		pkt.BackendIP = backend.IP
		pkt.BackendPort = backend.Port
		m.stats.Update("xdp_redirect", 1)
	}

	// Invoke callback if set
	m.mu.RLock()
	fn := m.onPacket
	m.mu.RUnlock()
	if fn != nil {
		fn(pkt)
	}

	return pkt, nil
}

// Stats returns current XDP statistics.
func (m *XDPManager) Stats() Stats {
	return m.stats.Snapshot()
}

// Run starts the XDP manager event loop.
func (m *XDPManager) Run(ctx context.Context) error {
	if err := m.Load(); err != nil && err != ErrAlreadyLoaded {
		return err
	}

	if m.config.EnableXDP {
		if err := m.Attach(); err != nil {
			return err
		}
	}

	m.logger.Info("XDP manager started",
		"xdp_enabled", m.config.EnableXDP,
		"interface", m.config.Interface)

	// Wait for context cancellation
	<-ctx.Done()

	// Cleanup
	m.Unload()
	m.logger.Info("XDP manager stopped")
	return nil
}
