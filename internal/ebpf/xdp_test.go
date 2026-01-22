package ebpf

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestXDPManager_LoadUnload(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)

	// Load
	err := mgr.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !mgr.IsLoaded() {
		t.Error("IsLoaded() should return true after Load()")
	}

	// Load again should fail
	err = mgr.Load()
	if err != ErrAlreadyLoaded {
		t.Errorf("Load() second time should return ErrAlreadyLoaded, got %v", err)
	}

	// Unload
	err = mgr.Unload()
	if err != nil {
		t.Fatalf("Unload() error = %v", err)
	}
	if mgr.IsLoaded() {
		t.Error("IsLoaded() should return false after Unload()")
	}
}

func TestXDPManager_AttachDetach(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)

	// Attach before load should fail
	err := mgr.Attach()
	if err != ErrNotLoaded {
		t.Errorf("Attach() before Load() should return ErrNotLoaded, got %v", err)
	}

	// Load and attach
	mgr.Load()
	err = mgr.Attach()
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	if !mgr.IsAttached() {
		t.Error("IsAttached() should return true after Attach()")
	}

	// Detach
	err = mgr.Detach()
	if err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	if mgr.IsAttached() {
		t.Error("IsAttached() should return false after Detach()")
	}

	mgr.Unload()
}

func TestXDPManager_ServiceManagement(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true},
			{IP: net.ParseIP("192.168.1.2"), Port: 8080, Weight: 1, Healthy: true},
		},
	}

	// Add service
	err := mgr.AddService(svc)
	if err != nil {
		t.Fatalf("AddService() error = %v", err)
	}

	// Add duplicate should fail
	err = mgr.AddService(svc)
	if err != ErrServiceExists {
		t.Errorf("AddService() duplicate should return ErrServiceExists, got %v", err)
	}

	// Get service
	retrieved, err := mgr.GetService(vip, port)
	if err != nil {
		t.Fatalf("GetService() error = %v", err)
	}
	if len(retrieved.Backends) != 2 {
		t.Errorf("GetService() backends = %d, want 2", len(retrieved.Backends))
	}

	// List services
	services := mgr.ListServices()
	if len(services) != 1 {
		t.Errorf("ListServices() = %d, want 1", len(services))
	}

	// Remove service
	err = mgr.RemoveService(vip, port)
	if err != nil {
		t.Fatalf("RemoveService() error = %v", err)
	}

	// Get removed service should fail
	_, err = mgr.GetService(vip, port)
	if err != ErrMapNotFound {
		t.Errorf("GetService() after remove should return ErrMapNotFound, got %v", err)
	}
}

func TestXDPManager_BackendManagement(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{},
	}
	mgr.AddService(svc)

	// Add backend
	backend := Backend{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true}
	err := mgr.AddBackend(vip, port, backend)
	if err != nil {
		t.Fatalf("AddBackend() error = %v", err)
	}

	// Add duplicate backend should fail
	err = mgr.AddBackend(vip, port, backend)
	if err != ErrBackendExists {
		t.Errorf("AddBackend() duplicate should return ErrBackendExists, got %v", err)
	}

	// Update health
	err = mgr.UpdateBackendHealth(vip, port, backend.IP, backend.Port, false)
	if err != nil {
		t.Fatalf("UpdateBackendHealth() error = %v", err)
	}

	// Remove backend
	err = mgr.RemoveBackend(vip, port, backend.IP, backend.Port)
	if err != nil {
		t.Fatalf("RemoveBackend() error = %v", err)
	}

	// Remove non-existent backend should fail
	err = mgr.RemoveBackend(vip, port, backend.IP, backend.Port)
	if err != ErrBackendNotFound {
		t.Errorf("RemoveBackend() non-existent should return ErrBackendNotFound, got %v", err)
	}
}

func TestXDPManager_SelectBackend_RoundRobin(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true},
			{IP: net.ParseIP("192.168.1.2"), Port: 8080, Weight: 1, Healthy: true},
		},
	}
	mgr.AddService(svc)

	srcIP := net.ParseIP("10.0.0.100")

	// Select backends multiple times
	for i := 0; i < 10; i++ {
		backend, err := mgr.SelectBackend(vip, port, srcIP, uint16(1000+i))
		if err != nil {
			t.Fatalf("SelectBackend() error = %v", err)
		}
		if backend == nil {
			t.Fatal("SelectBackend() returned nil backend")
		}
	}

	// Verify stats updated
	stats := mgr.Stats()
	if stats.LBDecisions < 10 {
		t.Errorf("LBDecisions = %d, want >= 10", stats.LBDecisions)
	}
}

func TestXDPManager_SelectBackend_IPHash(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodIPHash,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true},
			{IP: net.ParseIP("192.168.1.2"), Port: 8080, Weight: 1, Healthy: true},
		},
	}
	mgr.AddService(svc)

	srcIP := net.ParseIP("10.0.0.100")

	// Same source IP should always select same backend
	var firstBackend *Backend
	for i := 0; i < 10; i++ {
		backend, err := mgr.SelectBackend(vip, port, srcIP, uint16(1000+i))
		if err != nil {
			t.Fatalf("SelectBackend() error = %v", err)
		}
		if firstBackend == nil {
			firstBackend = backend
		} else if !backend.IP.Equal(firstBackend.IP) || backend.Port != firstBackend.Port {
			t.Error("IPHash should always select same backend for same source IP")
		}
	}
}

func TestXDPManager_SelectBackend_Weighted(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodWeighted,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 90, Healthy: true},
			{IP: net.ParseIP("192.168.1.2"), Port: 8080, Weight: 10, Healthy: true},
		},
	}
	mgr.AddService(svc)

	srcIP := net.ParseIP("10.0.0.100")

	// Count selections over many iterations
	counts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		backend, _ := mgr.SelectBackend(vip, port, srcIP, uint16(1000+i))
		counts[backend.IP.String()]++
	}

	// Backend 1 should be selected significantly more often
	backend1Count := counts["192.168.1.1"]
	if backend1Count < 700 { // Should be ~90% = ~900
		t.Errorf("Weighted selection: backend1 selected %d times, expected more with 90%% weight", backend1Count)
	}
}

func TestXDPManager_SelectBackend_UnhealthyFallback(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: false}, // Unhealthy
			{IP: net.ParseIP("192.168.1.2"), Port: 8080, Weight: 1, Healthy: true},  // Healthy
		},
	}
	mgr.AddService(svc)

	srcIP := net.ParseIP("10.0.0.100")

	// Should only select healthy backend
	for i := 0; i < 10; i++ {
		backend, _ := mgr.SelectBackend(vip, port, srcIP, uint16(1000+i))
		if backend.IP.Equal(net.ParseIP("192.168.1.1")) {
			t.Error("Should not select unhealthy backend when healthy one is available")
		}
	}
}

func TestXDPManager_SimulatePacket(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	svc := &Service{
		VIP:      vip,
		Port:     port,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true},
		},
	}
	mgr.AddService(svc)

	// Simulate packet to service VIP
	pkt, err := mgr.SimulatePacket(
		net.ParseIP("10.0.0.100"),
		vip,
		12345,
		port,
		6, // TCP
	)
	if err != nil {
		t.Fatalf("SimulatePacket() error = %v", err)
	}

	if pkt.Action != XDPRedirect {
		t.Errorf("Action = %v, want XDPRedirect", pkt.Action)
	}
	if !pkt.BackendIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("BackendIP = %v, want 192.168.1.1", pkt.BackendIP)
	}
	if pkt.BackendPort != 8080 {
		t.Errorf("BackendPort = %d, want 8080", pkt.BackendPort)
	}

	// Verify stats
	stats := mgr.Stats()
	if stats.PacketsProcessed != 1 {
		t.Errorf("PacketsProcessed = %d, want 1", stats.PacketsProcessed)
	}
	if stats.XDPRedirects != 1 {
		t.Errorf("XDPRedirects = %d, want 1", stats.XDPRedirects)
	}

	// Simulate packet to unknown destination
	pkt2, _ := mgr.SimulatePacket(
		net.ParseIP("10.0.0.100"),
		net.ParseIP("10.0.0.99"), // Unknown
		12345,
		80,
		6,
	)
	if pkt2.Action != XDPPass {
		t.Errorf("Action for unknown dst = %v, want XDPPass", pkt2.Action)
	}
}

func TestXDPManager_OnPacket(t *testing.T) {
	config := DefaultConfig()
	mgr := NewXDPManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	svc := &Service{
		VIP:      vip,
		Port:     80,
		LBMethod: LBMethodRoundRobin,
		Backends: []Backend{
			{IP: net.ParseIP("192.168.1.1"), Port: 8080, Weight: 1, Healthy: true},
		},
	}
	mgr.AddService(svc)

	received := make(chan *PacketInfo, 1)
	mgr.OnPacket(func(pkt *PacketInfo) {
		received <- pkt
	})

	mgr.SimulatePacket(net.ParseIP("10.0.0.100"), vip, 12345, 80, 6)

	select {
	case pkt := <-received:
		if pkt == nil {
			t.Error("Received nil packet info")
		}
	case <-time.After(time.Second):
		t.Error("OnPacket callback not called")
	}
}

func TestXDPManager_Run(t *testing.T) {
	config := DefaultConfig()
	config.EnableXDP = false // Don't actually attach
	mgr := NewXDPManager(config, nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- mgr.Run(ctx)
	}()

	// Give it time to start
	time.Sleep(50 * time.Millisecond)

	if !mgr.IsLoaded() {
		t.Error("Manager should be loaded after Run()")
	}

	// Cancel and wait for shutdown
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Run() did not complete after cancel")
	}
}

func TestHashIP(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.1")

	hash1 := hashIP(ip1)
	hash2 := hashIP(ip2)
	hash3 := hashIP(ip3)

	// Same IP should produce same hash
	if hash1 != hash3 {
		t.Error("Same IP should produce same hash")
	}

	// Different IPs should (usually) produce different hashes
	if hash1 == hash2 {
		t.Error("Different IPs produced same hash")
	}
}
