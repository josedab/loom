// Package anomaly provides API anomaly detection capabilities.
package anomaly

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"
)

// RootCauseAnalyzer analyzes anomalies to identify root causes.
type RootCauseAnalyzer struct {
	config       RootCauseConfig
	detector     *Detector
	dependencies *DependencyGraph
	incidents    []*Incident
	mu           sync.RWMutex
}

// RootCauseConfig configures the root cause analyzer.
type RootCauseConfig struct {
	// CorrelationWindow is the time window for correlating related anomalies
	CorrelationWindow time.Duration
	// CascadeThreshold is the minimum correlation score to consider cascade
	CascadeThreshold float64
	// MaxIncidents is the maximum number of incidents to track
	MaxIncidents int
	// IncidentTimeout is how long an incident stays active
	IncidentTimeout time.Duration
}

// DefaultRootCauseConfig returns sensible defaults.
func DefaultRootCauseConfig() RootCauseConfig {
	return RootCauseConfig{
		CorrelationWindow: 5 * time.Minute,
		CascadeThreshold:  0.7,
		MaxIncidents:      100,
		IncidentTimeout:   30 * time.Minute,
	}
}

// NewRootCauseAnalyzer creates a new root cause analyzer.
func NewRootCauseAnalyzer(config RootCauseConfig, detector *Detector) *RootCauseAnalyzer {
	if config.CorrelationWindow == 0 {
		config.CorrelationWindow = 5 * time.Minute
	}
	if config.CascadeThreshold == 0 {
		config.CascadeThreshold = 0.7
	}
	if config.MaxIncidents == 0 {
		config.MaxIncidents = 100
	}
	if config.IncidentTimeout == 0 {
		config.IncidentTimeout = 30 * time.Minute
	}

	return &RootCauseAnalyzer{
		config:       config,
		detector:     detector,
		dependencies: NewDependencyGraph(),
		incidents:    make([]*Incident, 0),
	}
}

// DependencyGraph represents service dependencies.
type DependencyGraph struct {
	nodes map[string]*ServiceNode
	edges map[string][]*DependencyEdge
	mu    sync.RWMutex
}

// ServiceNode represents a service in the dependency graph.
type ServiceNode struct {
	Name         string
	Type         ServiceType
	Criticality  Criticality
	HealthStatus HealthStatus
	LastSeen     time.Time
	Metadata     map[string]string
}

// ServiceType identifies the type of service.
type ServiceType string

const (
	ServiceTypeAPI      ServiceType = "api"
	ServiceTypeDatabase ServiceType = "database"
	ServiceTypeCache    ServiceType = "cache"
	ServiceTypeQueue    ServiceType = "queue"
	ServiceTypeExternal ServiceType = "external"
)

// Criticality indicates how critical a service is.
type Criticality string

const (
	CriticalityHigh   Criticality = "high"
	CriticalityMedium Criticality = "medium"
	CriticalityLow    Criticality = "low"
)

// HealthStatus indicates the health of a service.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// DependencyEdge represents a dependency between services.
type DependencyEdge struct {
	From       string
	To         string
	Weight     float64 // Call frequency weight
	Latency    time.Duration
	ErrorRate  float64
	LastCalled time.Time
}

// NewDependencyGraph creates a new dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]*ServiceNode),
		edges: make(map[string][]*DependencyEdge),
	}
}

// AddService adds or updates a service node.
func (g *DependencyGraph) AddService(name string, svcType ServiceType, criticality Criticality) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[name]; !exists {
		g.nodes[name] = &ServiceNode{
			Name:         name,
			Type:         svcType,
			Criticality:  criticality,
			HealthStatus: HealthStatusUnknown,
			Metadata:     make(map[string]string),
		}
	}
	g.nodes[name].LastSeen = time.Now()
}

// AddDependency adds a dependency edge.
func (g *DependencyGraph) AddDependency(from, to string, latency time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Ensure nodes exist
	if _, exists := g.nodes[from]; !exists {
		g.nodes[from] = &ServiceNode{
			Name:         from,
			Type:         ServiceTypeAPI,
			Criticality:  CriticalityMedium,
			HealthStatus: HealthStatusUnknown,
			Metadata:     make(map[string]string),
			LastSeen:     time.Now(),
		}
	}
	if _, exists := g.nodes[to]; !exists {
		g.nodes[to] = &ServiceNode{
			Name:         to,
			Type:         ServiceTypeAPI,
			Criticality:  CriticalityMedium,
			HealthStatus: HealthStatusUnknown,
			Metadata:     make(map[string]string),
			LastSeen:     time.Now(),
		}
	}

	// Find or create edge
	edges := g.edges[from]
	var edge *DependencyEdge
	for _, e := range edges {
		if e.To == to {
			edge = e
			break
		}
	}

	if edge == nil {
		edge = &DependencyEdge{
			From: from,
			To:   to,
		}
		g.edges[from] = append(g.edges[from], edge)
	}

	// Update edge statistics
	edge.Weight++
	edge.Latency = time.Duration((float64(edge.Latency)*edge.Weight + float64(latency)) / (edge.Weight + 1))
	edge.LastCalled = time.Now()
}

// RecordError records an error on a dependency edge.
func (g *DependencyGraph) RecordError(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edges := g.edges[from]
	for _, edge := range edges {
		if edge.To == to {
			// Update error rate (exponential moving average)
			edge.ErrorRate = edge.ErrorRate*0.9 + 0.1
			return
		}
	}
}

// GetDependencies returns all dependencies of a service.
func (g *DependencyGraph) GetDependencies(service string) []*DependencyEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.edges[service]
}

// GetDependents returns services that depend on the given service.
func (g *DependencyGraph) GetDependents(service string) []*DependencyEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var dependents []*DependencyEdge
	for from, edges := range g.edges {
		for _, edge := range edges {
			if edge.To == service {
				dependents = append(dependents, &DependencyEdge{
					From:      from,
					To:        service,
					Weight:    edge.Weight,
					Latency:   edge.Latency,
					ErrorRate: edge.ErrorRate,
				})
			}
		}
	}
	return dependents
}

// UpdateHealth updates the health status of a service.
func (g *DependencyGraph) UpdateHealth(service string, status HealthStatus) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if node, exists := g.nodes[service]; exists {
		node.HealthStatus = status
		node.LastSeen = time.Now()
	}
}

// GetService returns a service node.
func (g *DependencyGraph) GetService(name string) *ServiceNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if node, exists := g.nodes[name]; exists {
		return node
	}
	return nil
}

// GetAllServices returns all services.
func (g *DependencyGraph) GetAllServices() []*ServiceNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	services := make([]*ServiceNode, 0, len(g.nodes))
	for _, node := range g.nodes {
		services = append(services, node)
	}
	return services
}

// Export exports the graph as a DOT format string for visualization.
func (g *DependencyGraph) Export() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result string
	result = "digraph dependencies {\n"
	result += "  rankdir=LR;\n"
	result += "  node [shape=box];\n"

	// Add nodes with colors based on health
	for name, node := range g.nodes {
		color := "white"
		switch node.HealthStatus {
		case HealthStatusHealthy:
			color = "green"
		case HealthStatusDegraded:
			color = "yellow"
		case HealthStatusUnhealthy:
			color = "red"
		}
		result += fmt.Sprintf("  \"%s\" [style=filled, fillcolor=%s, label=\"%s\\n(%s)\"];\n",
			name, color, name, node.Type)
	}

	// Add edges
	for _, edges := range g.edges {
		for _, edge := range edges {
			result += fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%.0f calls\\n%.2f%% err\"];\n",
				edge.From, edge.To, edge.Weight, edge.ErrorRate*100)
		}
	}

	result += "}\n"
	return result
}

// Incident represents a detected incident with root cause analysis.
type Incident struct {
	ID          string           `json:"id"`
	StartTime   time.Time        `json:"start_time"`
	EndTime     *time.Time       `json:"end_time,omitempty"`
	Status      IncidentStatus   `json:"status"`
	Severity    Severity         `json:"severity"`
	RootCauses  []*RootCause     `json:"root_causes"`
	AffectedSvcs []string        `json:"affected_services"`
	Alerts      []Alert          `json:"alerts"`
	Timeline    []*TimelineEvent `json:"timeline"`
	Impact      *ImpactAnalysis  `json:"impact"`
	mu          sync.RWMutex
}

// IncidentStatus represents the status of an incident.
type IncidentStatus string

const (
	IncidentStatusActive    IncidentStatus = "active"
	IncidentStatusMitigated IncidentStatus = "mitigated"
	IncidentStatusResolved  IncidentStatus = "resolved"
)

// RootCause represents a potential root cause.
type RootCause struct {
	Service     string    `json:"service"`
	Cause       string    `json:"cause"`
	Confidence  float64   `json:"confidence"`
	Evidence    []string  `json:"evidence"`
	FirstSeen   time.Time `json:"first_seen"`
	Correlation float64   `json:"correlation"`
}

// TimelineEvent represents an event in the incident timeline.
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Service     string    `json:"service"`
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
}

// ImpactAnalysis contains the impact analysis of an incident.
type ImpactAnalysis struct {
	TotalAffectedServices int              `json:"total_affected_services"`
	TotalAffectedUsers    int              `json:"total_affected_users"`
	ErrorRate             float64          `json:"error_rate"`
	LatencyIncrease       float64          `json:"latency_increase_percent"`
	ThroughputDecrease    float64          `json:"throughput_decrease_percent"`
	EstimatedRevenueLoss  float64          `json:"estimated_revenue_loss,omitempty"`
	CascadeDepth          int              `json:"cascade_depth"`
	ServiceImpact         map[string]float64 `json:"service_impact"`
}

// Analyze processes an alert and performs root cause analysis.
func (rca *RootCauseAnalyzer) Analyze(alert Alert) *Incident {
	rca.mu.Lock()
	defer rca.mu.Unlock()

	// Find or create incident for this alert
	incident := rca.findOrCreateIncident(alert)

	// Add alert to incident
	incident.mu.Lock()
	incident.Alerts = append(incident.Alerts, alert)
	incident.mu.Unlock()

	// Update timeline
	rca.addTimelineEvent(incident, &TimelineEvent{
		Timestamp:   alert.Timestamp,
		EventType:   string(alert.Type),
		Service:     alert.Route,
		Description: alert.Description,
		Severity:    alert.Severity,
	})

	// Analyze root causes
	rca.analyzeRootCauses(incident)

	// Update impact analysis
	rca.updateImpactAnalysis(incident)

	// Check for cascade failures
	rca.detectCascade(incident)

	return incident
}

// findOrCreateIncident finds an existing active incident or creates a new one.
func (rca *RootCauseAnalyzer) findOrCreateIncident(alert Alert) *Incident {
	now := time.Now()

	// Look for active incident within correlation window
	for _, inc := range rca.incidents {
		if inc.Status == IncidentStatusActive {
			if now.Sub(inc.StartTime) < rca.config.IncidentTimeout {
				// Check if alert is correlated
				for _, existingAlert := range inc.Alerts {
					if rca.isCorrelated(existingAlert, alert) {
						return inc
					}
				}
			}
		}
	}

	// Create new incident
	incident := &Incident{
		ID:           generateID(),
		StartTime:    alert.Timestamp,
		Status:       IncidentStatusActive,
		Severity:     alert.Severity,
		RootCauses:   make([]*RootCause, 0),
		AffectedSvcs: []string{alert.Route},
		Alerts:       make([]Alert, 0),
		Timeline:     make([]*TimelineEvent, 0),
		Impact:       &ImpactAnalysis{ServiceImpact: make(map[string]float64)},
	}

	rca.incidents = append(rca.incidents, incident)

	// Cleanup old incidents
	if len(rca.incidents) > rca.config.MaxIncidents {
		rca.incidents = rca.incidents[len(rca.incidents)-rca.config.MaxIncidents:]
	}

	return incident
}

// isCorrelated checks if two alerts are correlated.
func (rca *RootCauseAnalyzer) isCorrelated(a, b Alert) bool {
	// Time proximity
	timeDiff := a.Timestamp.Sub(b.Timestamp)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > rca.config.CorrelationWindow {
		return false
	}

	// Same route or dependent routes
	if a.Route == b.Route {
		return true
	}

	// Check dependency graph
	deps := rca.dependencies.GetDependencies(a.Route)
	for _, dep := range deps {
		if dep.To == b.Route {
			return true
		}
	}

	dependents := rca.dependencies.GetDependents(a.Route)
	for _, dep := range dependents {
		if dep.From == b.Route {
			return true
		}
	}

	// Similar anomaly type
	if a.Type == b.Type {
		return true
	}

	return false
}

// addTimelineEvent adds an event to the incident timeline.
func (rca *RootCauseAnalyzer) addTimelineEvent(incident *Incident, event *TimelineEvent) {
	incident.mu.Lock()
	defer incident.mu.Unlock()

	incident.Timeline = append(incident.Timeline, event)

	// Sort by timestamp
	sort.Slice(incident.Timeline, func(i, j int) bool {
		return incident.Timeline[i].Timestamp.Before(incident.Timeline[j].Timestamp)
	})
}

// analyzeRootCauses identifies potential root causes.
func (rca *RootCauseAnalyzer) analyzeRootCauses(incident *Incident) {
	incident.mu.Lock()
	defer incident.mu.Unlock()

	if len(incident.Alerts) == 0 {
		return
	}

	// Group alerts by service
	alertsByService := make(map[string][]Alert)
	for _, alert := range incident.Alerts {
		alertsByService[alert.Route] = append(alertsByService[alert.Route], alert)
	}

	// Find earliest alerts - likely root causes
	var earliestTime time.Time
	var earliestService string
	for service, alerts := range alertsByService {
		for _, alert := range alerts {
			if earliestTime.IsZero() || alert.Timestamp.Before(earliestTime) {
				earliestTime = alert.Timestamp
				earliestService = service
			}
		}
	}

	// Check if earliest service has dependencies that also failed
	rootCauses := make([]*RootCause, 0)

	// The service with earliest alert is likely root cause
	if earliestService != "" {
		confidence := rca.calculateConfidence(earliestService, incident)
		evidence := rca.gatherEvidence(earliestService, incident)

		rootCauses = append(rootCauses, &RootCause{
			Service:     earliestService,
			Cause:       rca.determineCause(alertsByService[earliestService]),
			Confidence:  confidence,
			Evidence:    evidence,
			FirstSeen:   earliestTime,
			Correlation: rca.calculateCorrelation(earliestService, incident),
		})
	}

	// Check for upstream dependencies as potential causes
	for service := range alertsByService {
		if service == earliestService {
			continue
		}

		// Check if this service depends on the earliest service
		deps := rca.dependencies.GetDependencies(service)
		for _, dep := range deps {
			if dep.To == earliestService {
				// This service's failure might be caused by earliestService
				continue
			}

			// Check if there's an upstream dependency that failed
			if _, hasAlerts := alertsByService[dep.To]; hasAlerts {
				rootCauses = append(rootCauses, &RootCause{
					Service:     dep.To,
					Cause:       "Upstream dependency failure",
					Confidence:  0.7,
					Evidence:    []string{fmt.Sprintf("%s depends on %s", service, dep.To)},
					FirstSeen:   earliestTime,
					Correlation: dep.ErrorRate,
				})
			}
		}
	}

	// Sort by confidence
	sort.Slice(rootCauses, func(i, j int) bool {
		return rootCauses[i].Confidence > rootCauses[j].Confidence
	})

	// Keep top root causes
	if len(rootCauses) > 5 {
		rootCauses = rootCauses[:5]
	}

	incident.RootCauses = rootCauses
}

// calculateConfidence calculates confidence score for a root cause.
func (rca *RootCauseAnalyzer) calculateConfidence(service string, incident *Incident) float64 {
	confidence := 0.5 // Base confidence

	// Higher confidence if it's the first service with alerts
	alerts := incident.Alerts
	if len(alerts) > 0 {
		firstAlert := alerts[0]
		for _, a := range alerts {
			if a.Timestamp.Before(firstAlert.Timestamp) {
				firstAlert = a
			}
		}
		if firstAlert.Route == service {
			confidence += 0.3
		}
	}

	// Higher confidence for high severity alerts
	for _, alert := range alerts {
		if alert.Route == service {
			switch alert.Severity {
			case SeverityCritical:
				confidence += 0.1
			case SeverityHigh:
				confidence += 0.05
			}
		}
	}

	// Higher confidence if many services depend on this one
	dependents := rca.dependencies.GetDependents(service)
	dependentRatio := float64(len(dependents)) / float64(len(incident.AffectedSvcs)+1)
	confidence += dependentRatio * 0.2

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// gatherEvidence gathers evidence for a root cause.
func (rca *RootCauseAnalyzer) gatherEvidence(service string, incident *Incident) []string {
	evidence := make([]string, 0)

	// Alert-based evidence
	alertCount := 0
	for _, alert := range incident.Alerts {
		if alert.Route == service {
			alertCount++
			evidence = append(evidence, fmt.Sprintf("%s: %s (severity: %s)",
				alert.Type, alert.Description, alert.Severity))
		}
	}

	if alertCount > 1 {
		evidence = append(evidence, fmt.Sprintf("%d alerts from this service", alertCount))
	}

	// Dependency-based evidence
	dependents := rca.dependencies.GetDependents(service)
	if len(dependents) > 0 {
		evidence = append(evidence, fmt.Sprintf("%d services depend on this service", len(dependents)))
	}

	// Timeline evidence
	for i, event := range incident.Timeline {
		if event.Service == service && i == 0 {
			evidence = append(evidence, "First service to show anomaly in timeline")
			break
		}
	}

	return evidence
}

// determineCause determines the likely cause from alerts.
func (rca *RootCauseAnalyzer) determineCause(alerts []Alert) string {
	if len(alerts) == 0 {
		return "Unknown"
	}

	// Count alert types
	typeCounts := make(map[AnomalyType]int)
	for _, alert := range alerts {
		typeCounts[alert.Type]++
	}

	// Find most common type
	var maxType AnomalyType
	maxCount := 0
	for t, count := range typeCounts {
		if count > maxCount {
			maxType = t
			maxCount = count
		}
	}

	switch maxType {
	case AnomalyTypeLatency:
		return "High latency - possible resource exhaustion or downstream dependency issue"
	case AnomalyTypeError:
		return "High error rate - possible service failure or bug"
	case AnomalyTypeRate:
		return "Unusual request rate - possible traffic spike or DDoS"
	case AnomalyTypePattern:
		return "Unusual traffic pattern - possible security issue or misconfiguration"
	default:
		return "Service degradation detected"
	}
}

// calculateCorrelation calculates correlation score for a service.
func (rca *RootCauseAnalyzer) calculateCorrelation(service string, incident *Incident) float64 {
	if len(incident.Alerts) == 0 {
		return 0
	}

	// Calculate temporal correlation
	serviceAlerts := 0
	for _, alert := range incident.Alerts {
		if alert.Route == service {
			serviceAlerts++
		}
	}

	correlation := float64(serviceAlerts) / float64(len(incident.Alerts))
	return correlation
}

// updateImpactAnalysis updates the impact analysis for an incident.
func (rca *RootCauseAnalyzer) updateImpactAnalysis(incident *Incident) {
	incident.mu.Lock()
	defer incident.mu.Unlock()

	// Count affected services
	affectedSet := make(map[string]struct{})
	for _, alert := range incident.Alerts {
		affectedSet[alert.Route] = struct{}{}
	}

	// Add transitive dependencies
	for service := range affectedSet {
		dependents := rca.dependencies.GetDependents(service)
		for _, dep := range dependents {
			affectedSet[dep.From] = struct{}{}
		}
	}

	// Update affected services list
	incident.AffectedSvcs = make([]string, 0, len(affectedSet))
	for service := range affectedSet {
		incident.AffectedSvcs = append(incident.AffectedSvcs, service)
	}

	incident.Impact.TotalAffectedServices = len(affectedSet)

	// Calculate error rate and latency impact
	var totalErrorDeviation, totalLatencyDeviation float64
	var errorCount, latencyCount int

	for _, alert := range incident.Alerts {
		if alert.Type == AnomalyTypeError {
			totalErrorDeviation += alert.Deviation
			errorCount++
		}
		if alert.Type == AnomalyTypeLatency {
			if alert.Expected > 0 {
				latencyIncrease := (alert.Value - alert.Expected) / alert.Expected * 100
				totalLatencyDeviation += latencyIncrease
				latencyCount++
			}
		}
	}

	if errorCount > 0 {
		incident.Impact.ErrorRate = totalErrorDeviation / float64(errorCount)
	}
	if latencyCount > 0 {
		incident.Impact.LatencyIncrease = totalLatencyDeviation / float64(latencyCount)
	}

	// Calculate cascade depth
	incident.Impact.CascadeDepth = rca.calculateCascadeDepth(incident)

	// Update per-service impact
	for _, alert := range incident.Alerts {
		impact := incident.Impact.ServiceImpact[alert.Route]
		switch alert.Severity {
		case SeverityCritical:
			impact += 1.0
		case SeverityHigh:
			impact += 0.7
		case SeverityMedium:
			impact += 0.4
		case SeverityLow:
			impact += 0.1
		}
		incident.Impact.ServiceImpact[alert.Route] = impact
	}

	// Update overall severity
	incident.Severity = rca.calculateOverallSeverity(incident)
}

// calculateCascadeDepth calculates the cascade failure depth.
func (rca *RootCauseAnalyzer) calculateCascadeDepth(incident *Incident) int {
	if len(incident.RootCauses) == 0 {
		return 0
	}

	rootService := incident.RootCauses[0].Service
	maxDepth := 0

	// BFS to find cascade depth
	visited := make(map[string]int)
	visited[rootService] = 0
	queue := []string{rootService}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		currentDepth := visited[current]

		dependents := rca.dependencies.GetDependents(current)
		for _, dep := range dependents {
			if _, seen := visited[dep.From]; !seen {
				// Only count if this service has alerts
				for _, alert := range incident.Alerts {
					if alert.Route == dep.From {
						visited[dep.From] = currentDepth + 1
						queue = append(queue, dep.From)
						if currentDepth+1 > maxDepth {
							maxDepth = currentDepth + 1
						}
						break
					}
				}
			}
		}
	}

	return maxDepth
}

// calculateOverallSeverity calculates the overall incident severity.
func (rca *RootCauseAnalyzer) calculateOverallSeverity(incident *Incident) Severity {
	if len(incident.Alerts) == 0 {
		return SeverityLow
	}

	// Score based on multiple factors
	score := 0.0

	// Factor 1: Highest alert severity
	for _, alert := range incident.Alerts {
		switch alert.Severity {
		case SeverityCritical:
			score = math.Max(score, 1.0)
		case SeverityHigh:
			score = math.Max(score, 0.7)
		case SeverityMedium:
			score = math.Max(score, 0.4)
		case SeverityLow:
			score = math.Max(score, 0.1)
		}
	}

	// Factor 2: Number of affected services
	affectedScore := float64(incident.Impact.TotalAffectedServices) / 10.0
	if affectedScore > 0.3 {
		affectedScore = 0.3
	}
	score += affectedScore

	// Factor 3: Cascade depth
	cascadeScore := float64(incident.Impact.CascadeDepth) * 0.1
	if cascadeScore > 0.2 {
		cascadeScore = 0.2
	}
	score += cascadeScore

	// Convert to severity
	if score >= 1.0 {
		return SeverityCritical
	}
	if score >= 0.7 {
		return SeverityHigh
	}
	if score >= 0.4 {
		return SeverityMedium
	}
	return SeverityLow
}

// detectCascade detects cascade failures.
func (rca *RootCauseAnalyzer) detectCascade(incident *Incident) {
	incident.mu.RLock()
	if len(incident.RootCauses) == 0 {
		incident.mu.RUnlock()
		return
	}

	rootService := incident.RootCauses[0].Service
	firstSeen := incident.RootCauses[0].FirstSeen
	alerts := make([]Alert, len(incident.Alerts))
	copy(alerts, incident.Alerts)
	incident.mu.RUnlock()

	// Check if dependent services are failing
	dependents := rca.dependencies.GetDependents(rootService)
	var cascadeEvents []*TimelineEvent
	cascadeCount := 0

	for _, dep := range dependents {
		for _, alert := range alerts {
			if alert.Route == dep.From && alert.Timestamp.After(firstSeen) {
				cascadeCount++
				// Collect cascade events to add later
				cascadeEvents = append(cascadeEvents, &TimelineEvent{
					Timestamp:   alert.Timestamp,
					EventType:   "cascade",
					Service:     dep.From,
					Description: fmt.Sprintf("Cascade failure from %s to %s", rootService, dep.From),
					Severity:    alert.Severity,
				})
			}
		}
	}

	// Add cascade events to timeline
	for _, event := range cascadeEvents {
		rca.addTimelineEvent(incident, event)
	}

	if cascadeCount > 0 {
		incident.mu.Lock()
		if len(incident.RootCauses) > 0 {
			incident.RootCauses[0].Evidence = append(incident.RootCauses[0].Evidence,
				fmt.Sprintf("Cascade detected: %d downstream services affected", cascadeCount))
		}
		incident.mu.Unlock()
	}
}

// GetActiveIncidents returns all active incidents.
func (rca *RootCauseAnalyzer) GetActiveIncidents() []*Incident {
	rca.mu.RLock()
	defer rca.mu.RUnlock()

	var active []*Incident
	for _, inc := range rca.incidents {
		if inc.Status == IncidentStatusActive {
			active = append(active, inc)
		}
	}
	return active
}

// GetIncident returns an incident by ID.
func (rca *RootCauseAnalyzer) GetIncident(id string) *Incident {
	rca.mu.RLock()
	defer rca.mu.RUnlock()

	for _, inc := range rca.incidents {
		if inc.ID == id {
			return inc
		}
	}
	return nil
}

// ResolveIncident marks an incident as resolved.
func (rca *RootCauseAnalyzer) ResolveIncident(id string) {
	rca.mu.Lock()
	defer rca.mu.Unlock()

	for _, inc := range rca.incidents {
		if inc.ID == id {
			inc.mu.Lock()
			inc.Status = IncidentStatusResolved
			now := time.Now()
			inc.EndTime = &now
			inc.mu.Unlock()
			return
		}
	}
}

// GetDependencyGraph returns the dependency graph.
func (rca *RootCauseAnalyzer) GetDependencyGraph() *DependencyGraph {
	return rca.dependencies
}

// APIHandler returns an HTTP handler for the root cause analysis API.
func (rca *RootCauseAnalyzer) APIHandler() http.Handler {
	mux := http.NewServeMux()

	// Get active incidents
	mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		incidents := rca.GetActiveIncidents()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(incidents)
	})

	// Get specific incident
	mux.HandleFunc("/incidents/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := r.URL.Path[len("/incidents/"):]
		incident := rca.GetIncident(id)
		if incident == nil {
			http.Error(w, "Incident not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(incident)
	})

	// Get dependency graph
	mux.HandleFunc("/dependencies", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		format := r.URL.Query().Get("format")
		if format == "dot" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(rca.dependencies.Export()))
			return
		}

		services := rca.dependencies.GetAllServices()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(services)
	})

	// Add service
	mux.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name        string      `json:"name"`
			Type        ServiceType `json:"type"`
			Criticality Criticality `json:"criticality"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rca.dependencies.AddService(req.Name, req.Type, req.Criticality)
		w.WriteHeader(http.StatusCreated)
	})

	// Add dependency
	mux.HandleFunc("/dependencies/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			From    string `json:"from"`
			To      string `json:"to"`
			Latency int64  `json:"latency_ms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rca.dependencies.AddDependency(req.From, req.To, time.Duration(req.Latency)*time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	})

	return mux
}
