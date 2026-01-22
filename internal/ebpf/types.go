// Package ebpf provides eBPF-based acceleration for Loom.
// It implements XDP connection steering, socket-level load balancing,
// and high-performance observability through eBPF programs.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// EndpointKey represents a backend endpoint in eBPF maps.
type EndpointKey struct {
	IP   [4]byte // IPv4 address in network byte order
	Port uint16  // Port in network byte order
	_    uint16  // Padding for alignment
}

// EndpointValue contains endpoint metadata.
type EndpointValue struct {
	Weight      uint32 // Relative weight for load balancing
	Connections uint32 // Current active connections
	Healthy     uint8  // 1 if healthy, 0 if not
	_           [3]byte // Padding
}

// ConnectionKey identifies a connection for tracking.
type ConnectionKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_       [3]byte // Padding
}

// ConnectionValue contains connection state.
type ConnectionValue struct {
	BackendIP   [4]byte
	BackendPort uint16
	State       uint8
	_           byte // Padding
	Timestamp   uint64
	BytesSent   uint64
	BytesRecv   uint64
}

// ConnectionState represents the state of a tracked connection.
type ConnectionState uint8

const (
	ConnStateNew ConnectionState = iota
	ConnStateEstablished
	ConnStateClosing
	ConnStateClosed
)

// ServiceKey identifies a service for load balancing.
type ServiceKey struct {
	IP   [4]byte
	Port uint16
	_    uint16 // Padding
}

// ServiceValue contains service configuration.
type ServiceValue struct {
	BackendCount uint32
	LBMethod     uint8 // Load balancing method
	_            [3]byte
}

// LBMethod defines the load balancing algorithm.
type LBMethod uint8

const (
	LBMethodRoundRobin LBMethod = iota
	LBMethodLeastConn
	LBMethodWeighted
	LBMethodIPHash
	LBMethodMaglev
)

// MetricsKey identifies a metric in eBPF maps.
type MetricsKey struct {
	Type     MetricType
	ServiceID uint32
}

// MetricType defines the type of metric.
type MetricType uint32

const (
	MetricTypePackets MetricType = iota
	MetricTypeBytes
	MetricTypeConnections
	MetricTypeErrors
	MetricTypeLatency
	MetricTypeDropped
)

// MetricsValue contains metric data.
type MetricsValue struct {
	Count     uint64
	ByteCount uint64
	MinValue  uint64
	MaxValue  uint64
	SumValue  uint64
}

// XDPAction defines XDP return codes.
type XDPAction int

const (
	XDPAbort XDPAction = iota
	XDPDrop
	XDPPass
	XDPTx
	XDPRedirect
)

// Config holds eBPF subsystem configuration.
type Config struct {
	// Enable XDP acceleration
	EnableXDP bool `yaml:"enable_xdp"`
	// Enable socket-level load balancing
	EnableSocketLB bool `yaml:"enable_socket_lb"`
	// Enable eBPF-based metrics
	EnableMetrics bool `yaml:"enable_metrics"`
	// Interface to attach XDP programs
	Interface string `yaml:"interface"`
	// XDP mode (native, offload, generic)
	XDPMode string `yaml:"xdp_mode"`
	// Connection tracking table size
	ConnTrackSize uint32 `yaml:"conntrack_size"`
	// Metrics ring buffer size
	MetricsRingSize uint32 `yaml:"metrics_ring_size"`
	// Path to compiled eBPF objects
	BPFObjectPath string `yaml:"bpf_object_path"`
}

// DefaultConfig returns default eBPF configuration.
func DefaultConfig() Config {
	return Config{
		EnableXDP:       false,
		EnableSocketLB:  false,
		EnableMetrics:   true,
		Interface:       "eth0",
		XDPMode:         "generic",
		ConnTrackSize:   65536,
		MetricsRingSize: 4096,
		BPFObjectPath:   "/usr/lib/loom/bpf",
	}
}

// Backend represents a backend server.
type Backend struct {
	IP      net.IP
	Port    uint16
	Weight  uint32
	Healthy bool
}

// Service represents a load-balanced service.
type Service struct {
	VIP      net.IP
	Port     uint16
	Backends []Backend
	LBMethod LBMethod
}

// ParseIP parses an IP address to the eBPF key format.
func ParseIP(ip net.IP) [4]byte {
	var result [4]byte
	ip4 := ip.To4()
	if ip4 != nil {
		copy(result[:], ip4)
	}
	return result
}

// IPToUint32 converts IP bytes to uint32.
func IPToUint32(ip [4]byte) uint32 {
	return binary.BigEndian.Uint32(ip[:])
}

// Uint32ToIP converts uint32 to IP bytes.
func Uint32ToIP(n uint32) [4]byte {
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], n)
	return ip
}

// PortToNetwork converts a port to network byte order.
func PortToNetwork(port uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], port)
	return binary.NativeEndian.Uint16(buf[:])
}

// NetworkToPort converts a port from network byte order.
func NetworkToPort(port uint16) uint16 {
	var buf [2]byte
	binary.NativeEndian.PutUint16(buf[:], port)
	return binary.BigEndian.Uint16(buf[:])
}

// LatencyBucket defines a latency histogram bucket.
type LatencyBucket struct {
	LowerBound time.Duration
	UpperBound time.Duration
	Count      uint64
}

// DefaultLatencyBuckets returns default latency histogram buckets.
func DefaultLatencyBuckets() []LatencyBucket {
	boundaries := []time.Duration{
		100 * time.Microsecond,
		500 * time.Microsecond,
		1 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
	}

	buckets := make([]LatencyBucket, len(boundaries)+1)
	var prev time.Duration
	for i, bound := range boundaries {
		buckets[i] = LatencyBucket{
			LowerBound: prev,
			UpperBound: bound,
		}
		prev = bound
	}
	buckets[len(boundaries)] = LatencyBucket{
		LowerBound: prev,
		UpperBound: time.Duration(1<<63 - 1), // Max duration
	}

	return buckets
}

// Stats contains eBPF subsystem statistics.
type Stats struct {
	PacketsProcessed uint64
	BytesProcessed   uint64
	Connections      uint64
	ActiveConns      uint64
	Drops            uint64
	Errors           uint64
	XDPPasses        uint64
	XDPDrops         uint64
	XDPRedirects     uint64
	LBDecisions      uint64
	mu               sync.RWMutex
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
	return &Stats{}
}

// Update atomically updates statistics.
func (s *Stats) Update(field string, delta uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch field {
	case "packets":
		s.PacketsProcessed += delta
	case "bytes":
		s.BytesProcessed += delta
	case "connections":
		s.Connections += delta
	case "active":
		s.ActiveConns += delta
	case "drops":
		s.Drops += delta
	case "errors":
		s.Errors += delta
	case "xdp_pass":
		s.XDPPasses += delta
	case "xdp_drop":
		s.XDPDrops += delta
	case "xdp_redirect":
		s.XDPRedirects += delta
	case "lb_decisions":
		s.LBDecisions += delta
	}
}

// Snapshot returns a copy of current statistics.
func (s *Stats) Snapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		PacketsProcessed: s.PacketsProcessed,
		BytesProcessed:   s.BytesProcessed,
		Connections:      s.Connections,
		ActiveConns:      s.ActiveConns,
		Drops:            s.Drops,
		Errors:           s.Errors,
		XDPPasses:        s.XDPPasses,
		XDPDrops:         s.XDPDrops,
		XDPRedirects:     s.XDPRedirects,
		LBDecisions:      s.LBDecisions,
	}
}

// String returns a string representation of stats.
func (s *Stats) String() string {
	snap := s.Snapshot()
	return fmt.Sprintf(
		"packets=%d bytes=%d conns=%d active=%d drops=%d errors=%d",
		snap.PacketsProcessed, snap.BytesProcessed, snap.Connections,
		snap.ActiveConns, snap.Drops, snap.Errors,
	)
}

// Event represents an eBPF event from the ring buffer.
type Event struct {
	Type      EventType
	Timestamp uint64
	SrcIP     [4]byte
	DstIP     [4]byte
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	Action    uint8
	Latency   uint64
	Bytes     uint64
}

// EventType defines the type of eBPF event.
type EventType uint8

const (
	EventTypeConnection EventType = iota
	EventTypeRequest
	EventTypeResponse
	EventTypeError
	EventTypeDrop
	EventTypeLatency
)

// EventHandler processes eBPF events.
type EventHandler func(Event)

// MapInfo contains information about an eBPF map.
type MapInfo struct {
	Name       string
	Type       string
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

// ProgramInfo contains information about an eBPF program.
type ProgramInfo struct {
	Name          string
	Type          string
	Tag           string
	InstructionCount uint32
	LoadedAt      time.Time
}
