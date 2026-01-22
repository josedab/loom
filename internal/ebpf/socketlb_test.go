package ebpf

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSocketLBManager_LoadUnload(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)

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

func TestSocketLBManager_ServiceManagement(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)

	// Add service
	err := mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	if err != nil {
		t.Fatalf("AddService() error = %v", err)
	}

	// Add duplicate should fail
	err = mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	if err != ErrServiceExists {
		t.Errorf("AddService() duplicate should return ErrServiceExists, got %v", err)
	}

	// Different protocol should work
	err = mgr.AddService(vip, port, "udp", LBMethodRoundRobin)
	if err != nil {
		t.Fatalf("AddService() UDP error = %v", err)
	}

	if mgr.GetServiceCount() != 2 {
		t.Errorf("GetServiceCount() = %d, want 2", mgr.GetServiceCount())
	}

	// Remove service
	err = mgr.RemoveService(vip, port, "tcp")
	if err != nil {
		t.Fatalf("RemoveService() error = %v", err)
	}

	if mgr.GetServiceCount() != 1 {
		t.Errorf("GetServiceCount() after remove = %d, want 1", mgr.GetServiceCount())
	}
}

func TestSocketLBManager_BackendManagement(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)

	// Add backend
	backendIP := net.ParseIP("192.168.1.1")
	backendPort := uint16(8080)
	err := mgr.AddBackend(vip, port, "tcp", backendIP, backendPort, 1)
	if err != nil {
		t.Fatalf("AddBackend() error = %v", err)
	}

	// Add duplicate should fail
	err = mgr.AddBackend(vip, port, "tcp", backendIP, backendPort, 1)
	if err != ErrBackendExists {
		t.Errorf("AddBackend() duplicate should return ErrBackendExists, got %v", err)
	}

	// Set health
	err = mgr.SetBackendHealth(vip, port, "tcp", backendIP, backendPort, false)
	if err != nil {
		t.Fatalf("SetBackendHealth() error = %v", err)
	}

	// Remove backend
	err = mgr.RemoveBackend(vip, port, "tcp", backendIP, backendPort)
	if err != nil {
		t.Fatalf("RemoveBackend() error = %v", err)
	}

	// Remove non-existent should fail
	err = mgr.RemoveBackend(vip, port, "tcp", backendIP, backendPort)
	if err != ErrBackendNotFound {
		t.Errorf("RemoveBackend() non-existent should return ErrBackendNotFound, got %v", err)
	}
}

func TestSocketLBManager_Connect_RoundRobin(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")

	// Connect multiple times
	counts := make(map[string]int)
	for i := 0; i < 100; i++ {
		backend, err := mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
		if err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
		counts[backend.IP.String()]++
	}

	// Should be roughly even distribution
	for ip, count := range counts {
		if count < 30 || count > 70 {
			t.Errorf("Round robin uneven: %s got %d connections", ip, count)
		}
	}

	// Verify connection count
	if mgr.GetConnectionCount() != 100 {
		t.Errorf("GetConnectionCount() = %d, want 100", mgr.GetConnectionCount())
	}
}

func TestSocketLBManager_Connect_LeastConn(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodLeastConn)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")

	// First connection
	backend1, _ := mgr.Connect(srcIP, 10000, vip, port, "tcp")
	if backend1 == nil {
		t.Fatal("Connect() returned nil backend")
	}

	// Second connection should go to least loaded
	backend2, _ := mgr.Connect(srcIP, 10001, vip, port, "tcp")
	if backend2 == nil {
		t.Fatal("Connect() returned nil backend")
	}
}

func TestSocketLBManager_Connect_Weighted(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodWeighted)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 90)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 10)

	srcIP := net.ParseIP("10.0.0.100")

	// Connect many times
	counts := make(map[string]int)
	for i := 0; i < 1000; i++ {
		backend, _ := mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
		counts[backend.IP.String()]++
	}

	// High weight backend should get more connections
	if counts["192.168.1.1"] < 700 {
		t.Errorf("Weighted: high-weight backend got %d, expected ~900", counts["192.168.1.1"])
	}
}

func TestSocketLBManager_Connect_IPHash(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodIPHash)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")

	// Same source should always get same backend
	var firstBackend *SocketBackend
	for i := 0; i < 10; i++ {
		backend, _ := mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
		if firstBackend == nil {
			firstBackend = backend
		} else if !backend.IP.Equal(firstBackend.IP) {
			t.Error("IPHash: same source got different backends")
		}
	}

	// Different source might get different backend
	srcIP2 := net.ParseIP("10.0.0.200")
	backend2, _ := mgr.Connect(srcIP2, 10000, vip, port, "tcp")
	if backend2 == nil {
		t.Fatal("Connect() returned nil for second source")
	}
}

func TestSocketLBManager_Affinity(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	mgr.SetAffinity(vip, port, "tcp", AffinityConfig{
		Enabled:    true,
		Type:       AffinityClientIP,
		TimeoutSec: 300,
	})
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")

	// With affinity, same client should get same backend
	var firstBackend *SocketBackend
	for i := 0; i < 10; i++ {
		backend, _ := mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
		if firstBackend == nil {
			firstBackend = backend
		} else if !backend.IP.Equal(firstBackend.IP) {
			t.Error("Affinity: same client got different backends")
		}
	}
}

func TestSocketLBManager_Disconnect(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")
	srcPort := uint16(10000)

	// Connect
	mgr.Connect(srcIP, srcPort, vip, port, "tcp")
	if mgr.GetConnectionCount() != 1 {
		t.Errorf("GetConnectionCount() after connect = %d, want 1", mgr.GetConnectionCount())
	}

	// Disconnect
	err := mgr.Disconnect(srcIP, srcPort, vip, port, "tcp")
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	if mgr.GetConnectionCount() != 0 {
		t.Errorf("GetConnectionCount() after disconnect = %d, want 0", mgr.GetConnectionCount())
	}
}

func TestSocketLBManager_UnhealthyBackends(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.2"), 8080, 1)

	// Mark first backend unhealthy
	mgr.SetBackendHealth(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, false)

	srcIP := net.ParseIP("10.0.0.100")

	// Should only select healthy backend
	for i := 0; i < 10; i++ {
		backend, _ := mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
		if backend.IP.Equal(net.ParseIP("192.168.1.1")) {
			t.Error("Should not select unhealthy backend")
		}
	}
}

func TestSocketLBManager_Stats(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	vip := net.ParseIP("10.0.0.1")
	port := uint16(80)
	mgr.AddService(vip, port, "tcp", LBMethodRoundRobin)
	mgr.AddBackend(vip, port, "tcp", net.ParseIP("192.168.1.1"), 8080, 1)

	srcIP := net.ParseIP("10.0.0.100")

	// Make some connections
	for i := 0; i < 5; i++ {
		mgr.Connect(srcIP, uint16(10000+i), vip, port, "tcp")
	}

	stats := mgr.Stats()
	if stats.Connections != 5 {
		t.Errorf("Connections = %d, want 5", stats.Connections)
	}
	if stats.LBDecisions != 5 {
		t.Errorf("LBDecisions = %d, want 5", stats.LBDecisions)
	}
}

func TestSocketLBManager_Run(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)

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

	// Cancel and wait
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

func TestSocketLBManager_OnEvent(t *testing.T) {
	config := DefaultConfig()
	mgr := NewSocketLBManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	received := make(chan Event, 1)
	mgr.OnEvent(func(e Event) {
		received <- e
	})

	// Emit an event
	mgr.emitEvent(Event{
		Type:      EventTypeConnection,
		Timestamp: uint64(time.Now().UnixNano()),
	})

	select {
	case e := <-received:
		if e.Type != EventTypeConnection {
			t.Errorf("Event type = %v, want EventTypeConnection", e.Type)
		}
	case <-time.After(time.Second):
		t.Error("OnEvent callback not called")
	}
}
