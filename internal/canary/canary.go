// Package canary provides canary deployment and traffic splitting functionality.
package canary

import (
	"crypto/rand"
	"hash/fnv"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Target represents a deployment target with its weight.
type Target struct {
	Name     string  // Target identifier (e.g., "v1", "v2", "canary")
	Upstream string  // Upstream name to route to
	Weight   int     // Weight for traffic distribution (0-100)
	Headers  Headers // Additional headers to set for this target
}

// Headers are key-value pairs to add to requests.
type Headers map[string]string

// Deployment represents a canary deployment configuration.
type Deployment struct {
	ID          string
	RouteID     string    // The route this deployment applies to
	Targets     []Target  // Weighted targets
	Sticky      bool      // Enable sticky sessions via cookie
	StickyCookie string   // Cookie name for sticky sessions (default: "canary-session")
	StickyTTL   time.Duration // Cookie TTL
	HeaderMatch *HeaderMatch // Optional header-based routing override
	mu          sync.RWMutex
	metrics     *DeploymentMetrics
}

// HeaderMatch allows routing based on request headers.
type HeaderMatch struct {
	Header   string            // Header to check (e.g., "X-Canary")
	Values   map[string]string // Header value -> target name mapping
}

// DeploymentMetrics tracks traffic distribution metrics.
type DeploymentMetrics struct {
	RequestsTotal map[string]*uint64 // target -> request count
	ErrorsTotal   map[string]*uint64 // target -> error count
	mu            sync.RWMutex
}

// Manager manages canary deployments.
type Manager struct {
	deployments map[string]*Deployment // routeID -> deployment
	mu          sync.RWMutex
	logger      *slog.Logger
}

// NewManager creates a new canary deployment manager.
func NewManager() *Manager {
	return &Manager{
		deployments: make(map[string]*Deployment),
		logger:      slog.Default(),
	}
}

// Config for a canary deployment.
type Config struct {
	RouteID      string
	Targets      []Target
	Sticky       bool
	StickyCookie string
	StickyTTL    time.Duration
	HeaderMatch  *HeaderMatch
}

// CreateDeployment creates a new canary deployment.
func (m *Manager) CreateDeployment(cfg Config) (*Deployment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate total weight equals 100
	totalWeight := 0
	for _, t := range cfg.Targets {
		totalWeight += t.Weight
	}
	if totalWeight != 100 {
		// Normalize weights if they don't add up to 100
		for i := range cfg.Targets {
			cfg.Targets[i].Weight = cfg.Targets[i].Weight * 100 / totalWeight
		}
	}

	d := &Deployment{
		ID:          generateID(),
		RouteID:     cfg.RouteID,
		Targets:     cfg.Targets,
		Sticky:      cfg.Sticky,
		StickyCookie: cfg.StickyCookie,
		StickyTTL:   cfg.StickyTTL,
		HeaderMatch: cfg.HeaderMatch,
		metrics:     newDeploymentMetrics(cfg.Targets),
	}

	if d.StickyCookie == "" {
		d.StickyCookie = "canary-session"
	}
	if d.StickyTTL == 0 {
		d.StickyTTL = 24 * time.Hour
	}

	m.deployments[cfg.RouteID] = d
	m.logger.Info("created canary deployment",
		"route", cfg.RouteID,
		"targets", len(cfg.Targets))

	return d, nil
}

// GetDeployment returns the deployment for a route.
func (m *Manager) GetDeployment(routeID string) (*Deployment, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.deployments[routeID]
	return d, ok
}

// DeleteDeployment removes a canary deployment.
func (m *Manager) DeleteDeployment(routeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deployments, routeID)
}

// UpdateWeights updates the traffic distribution weights.
func (m *Manager) UpdateWeights(routeID string, weights map[string]int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.deployments[routeID]
	if !ok {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for i, target := range d.Targets {
		if w, ok := weights[target.Name]; ok {
			d.Targets[i].Weight = w
		}
	}

	// Normalize
	total := 0
	for _, t := range d.Targets {
		total += t.Weight
	}
	if total != 100 && total > 0 {
		for i := range d.Targets {
			d.Targets[i].Weight = d.Targets[i].Weight * 100 / total
		}
	}

	m.logger.Info("updated canary weights", "route", routeID, "weights", weights)
	return nil
}

// SelectTarget chooses a target based on the deployment rules.
func (d *Deployment) SelectTarget(r *http.Request) (*Target, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.Targets) == 0 {
		return nil, false
	}

	// Check header-based routing first (highest priority)
	if d.HeaderMatch != nil {
		headerVal := r.Header.Get(d.HeaderMatch.Header)
		if targetName, ok := d.HeaderMatch.Values[headerVal]; ok {
			for i := range d.Targets {
				if d.Targets[i].Name == targetName {
					return &d.Targets[i], true
				}
			}
		}
	}

	// Check sticky session
	if d.Sticky {
		if cookie, err := r.Cookie(d.StickyCookie); err == nil {
			for i := range d.Targets {
				if d.Targets[i].Name == cookie.Value {
					return &d.Targets[i], true
				}
			}
		}
	}

	// Weighted random selection
	return d.weightedSelect(r), true
}

// weightedSelect performs weighted random selection of a target.
func (d *Deployment) weightedSelect(r *http.Request) *Target {
	// Use consistent hashing for better distribution if no sticky session
	var seed int64
	if d.Sticky {
		// Use request characteristics for deterministic selection
		h := fnv.New64a()
		h.Write([]byte(r.RemoteAddr))
		h.Write([]byte(r.URL.Path))
		seed = int64(h.Sum64())
	} else {
		// Random selection
		n, _ := rand.Int(rand.Reader, big.NewInt(100))
		seed = n.Int64()
	}

	// Select based on weight
	roll := int(seed % 100)
	cumulative := 0
	for i := range d.Targets {
		cumulative += d.Targets[i].Weight
		if roll < cumulative {
			return &d.Targets[i]
		}
	}

	// Fallback to first target
	return &d.Targets[0]
}

// SetStickyCookie sets the sticky session cookie in the response.
func (d *Deployment) SetStickyCookie(w http.ResponseWriter, targetName string) {
	if !d.Sticky {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     d.StickyCookie,
		Value:    targetName,
		Path:     "/",
		MaxAge:   int(d.StickyTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// RecordRequest records a request to a target.
func (d *Deployment) RecordRequest(targetName string) {
	d.metrics.mu.RLock()
	if counter, ok := d.metrics.RequestsTotal[targetName]; ok {
		atomic.AddUint64(counter, 1)
	}
	d.metrics.mu.RUnlock()
}

// RecordError records an error for a target.
func (d *Deployment) RecordError(targetName string) {
	d.metrics.mu.RLock()
	if counter, ok := d.metrics.ErrorsTotal[targetName]; ok {
		atomic.AddUint64(counter, 1)
	}
	d.metrics.mu.RUnlock()
}

// GetMetrics returns the current deployment metrics.
func (d *Deployment) GetMetrics() map[string]TargetMetrics {
	d.metrics.mu.RLock()
	defer d.metrics.mu.RUnlock()

	result := make(map[string]TargetMetrics)
	for name, req := range d.metrics.RequestsTotal {
		result[name] = TargetMetrics{
			Requests: atomic.LoadUint64(req),
			Errors:   atomic.LoadUint64(d.metrics.ErrorsTotal[name]),
		}
	}
	return result
}

// TargetMetrics holds metrics for a single target.
type TargetMetrics struct {
	Requests uint64
	Errors   uint64
}

// newDeploymentMetrics initializes metrics for a deployment.
func newDeploymentMetrics(targets []Target) *DeploymentMetrics {
	dm := &DeploymentMetrics{
		RequestsTotal: make(map[string]*uint64),
		ErrorsTotal:   make(map[string]*uint64),
	}
	for _, t := range targets {
		reqCounter := uint64(0)
		errCounter := uint64(0)
		dm.RequestsTotal[t.Name] = &reqCounter
		dm.ErrorsTotal[t.Name] = &errCounter
	}
	return dm
}

// generateID generates a random deployment ID.
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return string([]byte("0123456789abcdef")[b[0]&0xf]) +
		string([]byte("0123456789abcdef")[b[1]&0xf]) +
		string([]byte("0123456789abcdef")[b[2]&0xf]) +
		string([]byte("0123456789abcdef")[b[3]&0xf]) +
		string([]byte("0123456789abcdef")[b[4]&0xf]) +
		string([]byte("0123456789abcdef")[b[5]&0xf]) +
		string([]byte("0123456789abcdef")[b[6]&0xf]) +
		string([]byte("0123456789abcdef")[b[7]&0xf])
}

// GetAllDeployments returns all active deployments.
func (m *Manager) GetAllDeployments() []*Deployment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Deployment, 0, len(m.deployments))
	for _, d := range m.deployments {
		result = append(result, d)
	}
	return result
}

// PromoteTarget promotes a target to 100% traffic (completes the canary).
func (m *Manager) PromoteTarget(routeID, targetName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	d, ok := m.deployments[routeID]
	if !ok {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for i := range d.Targets {
		if d.Targets[i].Name == targetName {
			d.Targets[i].Weight = 100
		} else {
			d.Targets[i].Weight = 0
		}
	}

	m.logger.Info("promoted canary target",
		"route", routeID,
		"target", targetName)
	return nil
}

// RollbackTarget rolls back to a target (sets it to 100% traffic).
func (m *Manager) RollbackTarget(routeID, targetName string) error {
	return m.PromoteTarget(routeID, targetName)
}
