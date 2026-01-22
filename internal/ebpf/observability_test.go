package ebpf

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestObservabilityManager_LoadUnload(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)

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

func TestObservabilityManager_Counter(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Register counter
	c := mgr.RegisterCounter("test_counter", map[string]string{"env": "test"})
	if c == nil {
		t.Fatal("RegisterCounter() returned nil")
	}

	// Increment
	mgr.IncCounter("test_counter", map[string]string{"env": "test"})
	mgr.IncCounter("test_counter", map[string]string{"env": "test"})

	// Get value
	value := mgr.GetCounterValue("test_counter", map[string]string{"env": "test"})
	if value != 2 {
		t.Errorf("Counter value = %d, want 2", value)
	}

	// Add
	mgr.AddCounter("test_counter", map[string]string{"env": "test"}, 10)
	value = mgr.GetCounterValue("test_counter", map[string]string{"env": "test"})
	if value != 12 {
		t.Errorf("Counter value after Add = %d, want 12", value)
	}
}

func TestObservabilityManager_Gauge(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Register gauge
	g := mgr.RegisterGauge("test_gauge", nil)
	if g == nil {
		t.Fatal("RegisterGauge() returned nil")
	}

	// Set value
	mgr.SetGauge("test_gauge", nil, 100)
	value := mgr.GetGaugeValue("test_gauge", nil)
	if value != 100 {
		t.Errorf("Gauge value = %d, want 100", value)
	}

	// Increment
	mgr.IncGauge("test_gauge", nil)
	value = mgr.GetGaugeValue("test_gauge", nil)
	if value != 101 {
		t.Errorf("Gauge value after Inc = %d, want 101", value)
	}

	// Decrement
	mgr.DecGauge("test_gauge", nil)
	value = mgr.GetGaugeValue("test_gauge", nil)
	if value != 100 {
		t.Errorf("Gauge value after Dec = %d, want 100", value)
	}
}

func TestObservabilityManager_Histogram(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Register histogram
	h := mgr.RegisterHistogram("test_histogram", nil, []float64{1, 5, 10, 50, 100})
	if h == nil {
		t.Fatal("RegisterHistogram() returned nil")
	}

	// Observe values
	mgr.ObserveHistogram("test_histogram", nil, 0.5)  // bucket 0
	mgr.ObserveHistogram("test_histogram", nil, 3)    // bucket 1
	mgr.ObserveHistogram("test_histogram", nil, 7)    // bucket 2
	mgr.ObserveHistogram("test_histogram", nil, 25)   // bucket 3
	mgr.ObserveHistogram("test_histogram", nil, 75)   // bucket 4
	mgr.ObserveHistogram("test_histogram", nil, 200)  // bucket 5 (overflow)

	// Verify count
	if h.count.Load() != 6 {
		t.Errorf("Histogram count = %d, want 6", h.count.Load())
	}
}

func TestObservabilityManager_RecordRequest(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Record requests
	mgr.RecordRequest("service-a", 100*time.Millisecond, 1000, 2000, nil)
	mgr.RecordRequest("service-a", 200*time.Millisecond, 500, 1500, nil)

	// Get service metrics
	metrics := mgr.GetServiceMetrics("service-a")
	if metrics == nil {
		t.Fatal("GetServiceMetrics() returned nil")
	}

	if metrics.RequestsTotal != 2 {
		t.Errorf("RequestsTotal = %d, want 2", metrics.RequestsTotal)
	}
	if metrics.BytesSent != 1500 {
		t.Errorf("BytesSent = %d, want 1500", metrics.BytesSent)
	}
	if metrics.BytesReceived != 3500 {
		t.Errorf("BytesReceived = %d, want 3500", metrics.BytesReceived)
	}
	if metrics.AvgLatencyUs <= 0 {
		t.Error("AvgLatencyUs should be > 0")
	}
}

func TestObservabilityManager_RecordRequestWithError(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Record request with error
	mgr.RecordRequest("service-b", 50*time.Millisecond, 100, 0, ErrNotSupported)

	metrics := mgr.GetServiceMetrics("service-b")
	if metrics == nil {
		t.Fatal("GetServiceMetrics() returned nil")
	}

	if metrics.ErrorsTotal != 1 {
		t.Errorf("ErrorsTotal = %d, want 1", metrics.ErrorsTotal)
	}
}

func TestObservabilityManager_RecordConnection(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Connect
	mgr.RecordConnection("service-c", true)
	mgr.RecordConnection("service-c", true)

	metrics := mgr.GetServiceMetrics("service-c")
	if metrics.ActiveConns != 2 {
		t.Errorf("ActiveConns = %d, want 2", metrics.ActiveConns)
	}

	// Disconnect
	mgr.RecordConnection("service-c", false)
	metrics = mgr.GetServiceMetrics("service-c")
	if metrics.ActiveConns != 1 {
		t.Errorf("ActiveConns after disconnect = %d, want 1", metrics.ActiveConns)
	}
}

func TestObservabilityManager_RecordXDPEvent(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	mgr.RecordXDPEvent(XDPRedirect, 1500)
	mgr.RecordXDPEvent(XDPDrop, 100)
	mgr.RecordXDPEvent(XDPPass, 500)

	// Check counters
	packets := mgr.GetCounterValue("loom_xdp_packets_total", nil)
	if packets != 3 {
		t.Errorf("XDP packets = %d, want 3", packets)
	}

	redirects := mgr.GetCounterValue("loom_xdp_redirects_total", nil)
	if redirects != 1 {
		t.Errorf("XDP redirects = %d, want 1", redirects)
	}

	drops := mgr.GetCounterValue("loom_xdp_drops_total", nil)
	if drops != 1 {
		t.Errorf("XDP drops = %d, want 1", drops)
	}
}

func TestObservabilityManager_GetAllServiceMetrics(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Record for multiple services
	mgr.RecordRequest("service-a", 100*time.Millisecond, 100, 200, nil)
	mgr.RecordRequest("service-b", 200*time.Millisecond, 100, 200, nil)
	mgr.RecordRequest("service-c", 300*time.Millisecond, 100, 200, nil)

	all := mgr.GetAllServiceMetrics()
	if len(all) != 3 {
		t.Errorf("GetAllServiceMetrics() = %d services, want 3", len(all))
	}

	// Should be sorted by key
	if all[0].ServiceKey != "service-a" {
		t.Error("Services should be sorted by key")
	}
}

func TestObservabilityManager_ExportPrometheus(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Register and add some metrics
	mgr.RegisterCounter("test_requests_total", map[string]string{"method": "GET"})
	mgr.IncCounter("test_requests_total", map[string]string{"method": "GET"})
	mgr.RegisterGauge("test_connections", nil)
	mgr.SetGauge("test_connections", nil, 42)
	mgr.RegisterHistogram("test_duration", nil, []float64{0.1, 0.5, 1.0, 5.0})
	mgr.ObserveHistogram("test_duration", nil, 0.5)

	output := mgr.ExportPrometheus()

	// Check for counter
	if !strings.Contains(output, "test_requests_total") {
		t.Error("Prometheus output should contain counter")
	}

	// Check for gauge
	if !strings.Contains(output, "test_connections") {
		t.Error("Prometheus output should contain gauge")
	}

	// Check for histogram
	if !strings.Contains(output, "test_duration_bucket") {
		t.Error("Prometheus output should contain histogram buckets")
	}
	if !strings.Contains(output, "test_duration_sum") {
		t.Error("Prometheus output should contain histogram sum")
	}
	if !strings.Contains(output, "test_duration_count") {
		t.Error("Prometheus output should contain histogram count")
	}

	// Check for TYPE declarations
	if !strings.Contains(output, "# TYPE") {
		t.Error("Prometheus output should contain TYPE declarations")
	}
}

func TestObservabilityManager_OnEvent(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	received := make(chan Event, 1)
	mgr.OnEvent(func(e Event) {
		received <- e
	})

	// Emit event
	mgr.EmitEvent(Event{
		Type:      EventTypeRequest,
		Timestamp: uint64(time.Now().UnixNano()),
		Bytes:     1000,
	})

	select {
	case e := <-received:
		if e.Type != EventTypeRequest {
			t.Errorf("Event type = %v, want EventTypeRequest", e.Type)
		}
	case <-time.After(time.Second):
		t.Error("OnEvent callback not called")
	}
}

func TestObservabilityManager_DefaultMetrics(t *testing.T) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	// Verify default metrics exist
	defaultCounters := []string{
		"loom_requests_total",
		"loom_bytes_sent_total",
		"loom_bytes_received_total",
		"loom_connections_total",
		"loom_errors_total",
	}

	for _, name := range defaultCounters {
		// Should not panic when accessing
		_ = mgr.GetCounterValue(name, nil)
	}

	defaultGauges := []string{
		"loom_active_connections",
		"loom_backends_healthy",
		"loom_backends_total",
	}

	for _, name := range defaultGauges {
		_ = mgr.GetGaugeValue(name, nil)
	}
}

func TestObservabilityManager_Run(t *testing.T) {
	config := DefaultConfig()
	config.MetricsRingSize = 10
	mgr := NewObservabilityManager(config, nil)

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

func TestObservabilityManager_LatencyBuckets(t *testing.T) {
	buckets := DefaultLatencyBuckets()

	if len(buckets) == 0 {
		t.Fatal("DefaultLatencyBuckets() returned empty slice")
	}

	// Verify buckets are ordered
	for i := 1; i < len(buckets); i++ {
		if buckets[i].LowerBound < buckets[i-1].UpperBound {
			t.Error("Latency buckets not properly ordered")
		}
	}
}

func TestMetricKey(t *testing.T) {
	tests := []struct {
		name     string
		metric   string
		labels   map[string]string
		expected string
	}{
		{
			name:     "no labels",
			metric:   "test",
			labels:   nil,
			expected: "test",
		},
		{
			name:     "single label",
			metric:   "test",
			labels:   map[string]string{"env": "prod"},
			expected: "test_env_prod",
		},
		{
			name:     "multiple labels sorted",
			metric:   "test",
			labels:   map[string]string{"z": "3", "a": "1", "m": "2"},
			expected: "test_a_1_m_2_z_3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := metricKey(tt.metric, tt.labels)
			if result != tt.expected {
				t.Errorf("metricKey() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatLabels(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		expected string
	}{
		{
			name:     "no labels",
			labels:   nil,
			expected: "",
		},
		{
			name:     "single label",
			labels:   map[string]string{"env": "prod"},
			expected: `{env="prod"}`,
		},
		{
			name:     "multiple labels",
			labels:   map[string]string{"a": "1", "b": "2"},
			expected: `{a="1",b="2"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatLabels(tt.labels)
			if result != tt.expected {
				t.Errorf("formatLabels() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func BenchmarkObservabilityManager_IncCounter(b *testing.B) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.IncCounter("loom_requests_total", nil)
	}
}

func BenchmarkObservabilityManager_RecordRequest(b *testing.B) {
	config := DefaultConfig()
	mgr := NewObservabilityManager(config, nil)
	mgr.Load()
	defer mgr.Unload()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.RecordRequest("service-a", 100*time.Millisecond, 1000, 2000, nil)
	}
}
