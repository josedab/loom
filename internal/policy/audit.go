// Package policy provides audit logging and compliance tracking for policy decisions.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// AuditLevel represents the level of audit detail.
type AuditLevel string

const (
	AuditLevelNone     AuditLevel = "none"
	AuditLevelBasic    AuditLevel = "basic"
	AuditLevelDetailed AuditLevel = "detailed"
	AuditLevelFull     AuditLevel = "full"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	PolicyID      string                 `json:"policy_id"`
	PolicyVersion int                    `json:"policy_version,omitempty"`
	Decision      *Decision              `json:"decision"`
	Input         *AuditInput            `json:"input,omitempty"`
	Duration      time.Duration          `json:"duration_ns"`
	RequestID     string                 `json:"request_id,omitempty"`
	Source        string                 `json:"source,omitempty"`
	Labels        map[string]string      `json:"labels,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AuditInput is a sanitized version of Input for audit logging.
type AuditInput struct {
	Method     string              `json:"method,omitempty"`
	Path       string              `json:"path,omitempty"`
	Host       string              `json:"host,omitempty"`
	RemoteAddr string              `json:"remote_addr,omitempty"`
	UserID     string              `json:"user_id,omitempty"`
	Username   string              `json:"username,omitempty"`
	Roles      []string            `json:"roles,omitempty"`
	Groups     []string            `json:"groups,omitempty"`
	Resource   *AuditResourceInput `json:"resource,omitempty"`
}

// AuditResourceInput is a sanitized version of ResourceInput for audit logging.
type AuditResourceInput struct {
	Type   string            `json:"type,omitempty"`
	ID     string            `json:"id,omitempty"`
	Owner  string            `json:"owner,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// AuditLogger handles audit logging for policy decisions.
type AuditLogger struct {
	config       AuditLoggerConfig
	entries      []*AuditEntry
	writers      []AuditWriter
	hooks        []AuditHook
	idGenerator  func() string
	mu           sync.RWMutex
	entryChan    chan *AuditEntry
	stopCh       chan struct{}
	logger       *slog.Logger
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// Level determines how much detail to log.
	Level AuditLevel
	// MaxEntries is the maximum number of entries to keep in memory.
	MaxEntries int
	// BufferSize is the size of the async write buffer.
	BufferSize int
	// FlushInterval is how often to flush buffered entries.
	FlushInterval time.Duration
	// SanitizeInput determines if sensitive input data should be sanitized.
	SanitizeInput bool
	// IncludeInput determines if input should be included in audit entries.
	IncludeInput bool
	// StorageDir is the directory for persistent audit logs.
	StorageDir string
	// RetentionDays is how many days to retain audit logs.
	RetentionDays int
	// Logger for audit logger events.
	Logger *slog.Logger
}

// AuditWriter writes audit entries to a destination.
type AuditWriter interface {
	Write(entry *AuditEntry) error
	Flush() error
	Close() error
}

// AuditHook is called for each audit entry.
type AuditHook func(entry *AuditEntry)

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(cfg AuditLoggerConfig) *AuditLogger {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1000
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 30
	}

	al := &AuditLogger{
		config:      cfg,
		entries:     make([]*AuditEntry, 0),
		writers:     make([]AuditWriter, 0),
		hooks:       make([]AuditHook, 0),
		idGenerator: generateAuditID,
		entryChan:   make(chan *AuditEntry, cfg.BufferSize),
		stopCh:      make(chan struct{}),
		logger:      cfg.Logger,
	}

	// Create storage directory if specified
	if cfg.StorageDir != "" {
		if err := os.MkdirAll(cfg.StorageDir, 0755); err != nil {
			al.logger.Error("failed to create audit storage directory",
				"dir", cfg.StorageDir,
				"error", err,
			)
		}
	}

	// Start background processing
	go al.processLoop()

	return al
}

// AddWriter adds an audit writer.
func (al *AuditLogger) AddWriter(writer AuditWriter) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.writers = append(al.writers, writer)
}

// AddHook adds an audit hook.
func (al *AuditLogger) AddHook(hook AuditHook) {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.hooks = append(al.hooks, hook)
}

// Log logs a policy decision.
func (al *AuditLogger) Log(ctx context.Context, policyID string, input *Input, decision *Decision, duration time.Duration) {
	if al.config.Level == AuditLevelNone {
		return
	}

	entry := &AuditEntry{
		ID:        al.idGenerator(),
		Timestamp: time.Now(),
		PolicyID:  policyID,
		Decision:  decision,
		Duration:  duration,
	}

	// Add request ID from context if available
	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		entry.RequestID = requestID
	}

	// Add input based on level
	if al.config.IncludeInput && input != nil {
		entry.Input = al.sanitizeInput(input)
	}

	// Send to processing channel (non-blocking)
	select {
	case al.entryChan <- entry:
	default:
		al.logger.Warn("audit buffer full, dropping entry",
			"policy", policyID,
		)
	}
}

// LogWithVersion logs a policy decision with version information.
func (al *AuditLogger) LogWithVersion(ctx context.Context, policyID string, version int, input *Input, decision *Decision, duration time.Duration) {
	if al.config.Level == AuditLevelNone {
		return
	}

	entry := &AuditEntry{
		ID:            al.idGenerator(),
		Timestamp:     time.Now(),
		PolicyID:      policyID,
		PolicyVersion: version,
		Decision:      decision,
		Duration:      duration,
	}

	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		entry.RequestID = requestID
	}

	if al.config.IncludeInput && input != nil {
		entry.Input = al.sanitizeInput(input)
	}

	select {
	case al.entryChan <- entry:
	default:
		al.logger.Warn("audit buffer full, dropping entry",
			"policy", policyID,
			"version", version,
		)
	}
}

// LogPolicyChange logs a policy change event.
func (al *AuditLogger) LogPolicyChange(event PolicyChangeEvent, actor string) {
	entry := &AuditEntry{
		ID:            al.idGenerator(),
		Timestamp:     event.Timestamp,
		PolicyID:      event.PolicyID,
		PolicyVersion: event.Version,
		Source:        "policy_change",
		Labels: map[string]string{
			"change_type": string(event.Type),
			"actor":       actor,
		},
	}

	if event.Error != nil {
		entry.Labels["error"] = event.Error.Error()
	}

	select {
	case al.entryChan <- entry:
	default:
		al.logger.Warn("audit buffer full, dropping policy change entry",
			"policy", event.PolicyID,
		)
	}
}

// sanitizeInput creates a sanitized version of the input for logging.
func (al *AuditLogger) sanitizeInput(input *Input) *AuditInput {
	auditInput := &AuditInput{
		Method:     input.Request.Method,
		Path:       input.Request.Path,
		Host:       input.Request.Host,
		RemoteAddr: input.Request.RemoteAddr,
	}

	if input.User != nil {
		auditInput.UserID = input.User.ID
		auditInput.Username = input.User.Username
		auditInput.Roles = input.User.Roles
		auditInput.Groups = input.User.Groups
	}

	if input.Resource != nil {
		auditInput.Resource = &AuditResourceInput{
			Type:   input.Resource.Type,
			ID:     input.Resource.ID,
			Owner:  input.Resource.Owner,
			Labels: input.Resource.Labels,
		}
	}

	return auditInput
}

// processLoop processes audit entries in the background.
func (al *AuditLogger) processLoop() {
	flushTicker := time.NewTicker(al.config.FlushInterval)
	defer flushTicker.Stop()

	var buffer []*AuditEntry

	for {
		select {
		case <-al.stopCh:
			// Flush remaining entries
			al.flushBuffer(buffer)
			return

		case entry := <-al.entryChan:
			buffer = append(buffer, entry)
			al.addEntry(entry)

			// Call hooks
			al.mu.RLock()
			for _, hook := range al.hooks {
				go hook(entry)
			}
			al.mu.RUnlock()

			// Flush if buffer is large enough
			if len(buffer) >= al.config.BufferSize/2 {
				al.flushBuffer(buffer)
				buffer = nil
			}

		case <-flushTicker.C:
			if len(buffer) > 0 {
				al.flushBuffer(buffer)
				buffer = nil
			}
		}
	}
}

// addEntry adds an entry to the in-memory store.
func (al *AuditLogger) addEntry(entry *AuditEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.entries = append(al.entries, entry)

	// Trim if exceeding max
	if len(al.entries) > al.config.MaxEntries {
		al.entries = al.entries[len(al.entries)-al.config.MaxEntries:]
	}
}

// flushBuffer writes buffered entries to all writers.
func (al *AuditLogger) flushBuffer(entries []*AuditEntry) {
	if len(entries) == 0 {
		return
	}

	al.mu.RLock()
	writers := al.writers
	al.mu.RUnlock()

	for _, writer := range writers {
		for _, entry := range entries {
			if err := writer.Write(entry); err != nil {
				al.logger.Error("failed to write audit entry",
					"error", err,
				)
			}
		}
		if err := writer.Flush(); err != nil {
			al.logger.Error("failed to flush audit writer",
				"error", err,
			)
		}
	}

	// Persist to storage if configured
	if al.config.StorageDir != "" {
		al.persistEntries(entries)
	}
}

// persistEntries saves entries to the storage directory.
func (al *AuditLogger) persistEntries(entries []*AuditEntry) {
	if len(entries) == 0 {
		return
	}

	// Group by date
	byDate := make(map[string][]*AuditEntry)
	for _, entry := range entries {
		date := entry.Timestamp.Format("2006-01-02")
		byDate[date] = append(byDate[date], entry)
	}

	for date, dateEntries := range byDate {
		filename := filepath.Join(al.config.StorageDir, fmt.Sprintf("audit-%s.jsonl", date))

		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			al.logger.Error("failed to open audit file",
				"file", filename,
				"error", err,
			)
			continue
		}

		for _, entry := range dateEntries {
			data, err := json.Marshal(entry)
			if err != nil {
				al.logger.Error("failed to marshal audit entry", "error", err)
				continue
			}
			f.Write(data)
			f.Write([]byte("\n"))
		}

		f.Close()
	}
}

// Query queries audit entries.
func (al *AuditLogger) Query(filter AuditFilter) []*AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var results []*AuditEntry
	for _, entry := range al.entries {
		if filter.Matches(entry) {
			results = append(results, entry)
		}
	}

	// Sort by timestamp descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	// Apply limit
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results
}

// GetEntry retrieves a specific audit entry by ID.
func (al *AuditLogger) GetEntry(id string) *AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	for _, entry := range al.entries {
		if entry.ID == id {
			return entry
		}
	}
	return nil
}

// Stop stops the audit logger.
func (al *AuditLogger) Stop() error {
	close(al.stopCh)

	al.mu.Lock()
	defer al.mu.Unlock()

	for _, writer := range al.writers {
		writer.Close()
	}

	return nil
}

// AuditFilter filters audit entries.
type AuditFilter struct {
	PolicyID  string
	UserID    string
	StartTime time.Time
	EndTime   time.Time
	Allowed   *bool
	Path      string
	Method    string
	Limit     int
}

// Matches checks if an entry matches the filter.
func (f *AuditFilter) Matches(entry *AuditEntry) bool {
	if f.PolicyID != "" && entry.PolicyID != f.PolicyID {
		return false
	}
	if f.UserID != "" && (entry.Input == nil || entry.Input.UserID != f.UserID) {
		return false
	}
	if !f.StartTime.IsZero() && entry.Timestamp.Before(f.StartTime) {
		return false
	}
	if !f.EndTime.IsZero() && entry.Timestamp.After(f.EndTime) {
		return false
	}
	if f.Allowed != nil && entry.Decision != nil && entry.Decision.Allowed != *f.Allowed {
		return false
	}
	if f.Path != "" && (entry.Input == nil || entry.Input.Path != f.Path) {
		return false
	}
	if f.Method != "" && (entry.Input == nil || entry.Input.Method != f.Method) {
		return false
	}
	return true
}

// AuditStats contains audit statistics.
type AuditStats struct {
	TotalDecisions    int64              `json:"total_decisions"`
	AllowedDecisions  int64              `json:"allowed_decisions"`
	DeniedDecisions   int64              `json:"denied_decisions"`
	ByPolicy          map[string]int64   `json:"by_policy"`
	ByUser            map[string]int64   `json:"by_user"`
	ByPath            map[string]int64   `json:"by_path"`
	ByMethod          map[string]int64   `json:"by_method"`
	AverageLatency    time.Duration      `json:"average_latency_ns"`
	P99Latency        time.Duration      `json:"p99_latency_ns"`
	HourlyDistribution map[int]int64     `json:"hourly_distribution"`
}

// Stats computes statistics from audit entries.
func (al *AuditLogger) Stats(filter AuditFilter) *AuditStats {
	al.mu.RLock()
	defer al.mu.RUnlock()

	stats := &AuditStats{
		ByPolicy:           make(map[string]int64),
		ByUser:             make(map[string]int64),
		ByPath:             make(map[string]int64),
		ByMethod:           make(map[string]int64),
		HourlyDistribution: make(map[int]int64),
	}

	var latencies []time.Duration

	for _, entry := range al.entries {
		if !filter.Matches(entry) {
			continue
		}

		stats.TotalDecisions++
		if entry.Decision != nil {
			if entry.Decision.Allowed {
				stats.AllowedDecisions++
			} else {
				stats.DeniedDecisions++
			}
		}

		stats.ByPolicy[entry.PolicyID]++

		if entry.Input != nil {
			if entry.Input.UserID != "" {
				stats.ByUser[entry.Input.UserID]++
			}
			if entry.Input.Path != "" {
				stats.ByPath[entry.Input.Path]++
			}
			if entry.Input.Method != "" {
				stats.ByMethod[entry.Input.Method]++
			}
		}

		stats.HourlyDistribution[entry.Timestamp.Hour()]++
		latencies = append(latencies, entry.Duration)
	}

	// Calculate latency stats
	if len(latencies) > 0 {
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		stats.AverageLatency = total / time.Duration(len(latencies))

		// Sort for P99
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})
		p99Index := int(float64(len(latencies)) * 0.99)
		if p99Index >= len(latencies) {
			p99Index = len(latencies) - 1
		}
		stats.P99Latency = latencies[p99Index]
	}

	return stats
}

// ComplianceReport represents a compliance report.
type ComplianceReport struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	ReportPeriod     ReportPeriod            `json:"report_period"`
	Summary          ComplianceSummary       `json:"summary"`
	PolicyStats      []PolicyComplianceStats `json:"policy_stats"`
	ViolationSummary ViolationSummary        `json:"violation_summary"`
	Recommendations  []string                `json:"recommendations,omitempty"`
}

// ReportPeriod represents the time period for a report.
type ReportPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ComplianceSummary contains summary compliance metrics.
type ComplianceSummary struct {
	TotalRequests       int64   `json:"total_requests"`
	ComplianceRate      float64 `json:"compliance_rate"`
	DenialRate          float64 `json:"denial_rate"`
	PolicyCoverage      float64 `json:"policy_coverage"`
	AverageResponseTime float64 `json:"average_response_time_ms"`
}

// PolicyComplianceStats contains compliance stats for a single policy.
type PolicyComplianceStats struct {
	PolicyID       string  `json:"policy_id"`
	Evaluations    int64   `json:"evaluations"`
	Allowed        int64   `json:"allowed"`
	Denied         int64   `json:"denied"`
	Errors         int64   `json:"errors"`
	ComplianceRate float64 `json:"compliance_rate"`
}

// ViolationSummary summarizes policy violations.
type ViolationSummary struct {
	TotalViolations   int64                      `json:"total_violations"`
	ViolationsByType  map[string]int64           `json:"violations_by_type"`
	TopViolators      []ViolatorInfo             `json:"top_violators"`
	ViolationTrend    []ViolationTrendDataPoint  `json:"violation_trend"`
}

// ViolatorInfo contains information about a frequent violator.
type ViolatorInfo struct {
	UserID     string `json:"user_id"`
	Violations int64  `json:"violations"`
}

// ViolationTrendDataPoint represents a data point in the violation trend.
type ViolationTrendDataPoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Violations int64     `json:"violations"`
}

// ComplianceReporter generates compliance reports.
type ComplianceReporter struct {
	auditLogger *AuditLogger
	policyStore *PolicyStore
	logger      *slog.Logger
}

// NewComplianceReporter creates a new compliance reporter.
func NewComplianceReporter(auditLogger *AuditLogger, policyStore *PolicyStore, logger *slog.Logger) *ComplianceReporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &ComplianceReporter{
		auditLogger: auditLogger,
		policyStore: policyStore,
		logger:      logger,
	}
}

// GenerateReport generates a compliance report for the given period.
func (r *ComplianceReporter) GenerateReport(start, end time.Time) *ComplianceReport {
	filter := AuditFilter{
		StartTime: start,
		EndTime:   end,
	}
	entries := r.auditLogger.Query(filter)
	stats := r.auditLogger.Stats(filter)

	report := &ComplianceReport{
		GeneratedAt: time.Now(),
		ReportPeriod: ReportPeriod{
			Start: start,
			End:   end,
		},
	}

	// Calculate summary
	if stats.TotalDecisions > 0 {
		report.Summary = ComplianceSummary{
			TotalRequests:       stats.TotalDecisions,
			ComplianceRate:      float64(stats.AllowedDecisions) / float64(stats.TotalDecisions) * 100,
			DenialRate:          float64(stats.DeniedDecisions) / float64(stats.TotalDecisions) * 100,
			AverageResponseTime: float64(stats.AverageLatency) / float64(time.Millisecond),
		}
	}

	// Calculate policy coverage
	if r.policyStore != nil {
		totalPolicies := len(r.policyStore.List())
		usedPolicies := len(stats.ByPolicy)
		if totalPolicies > 0 {
			report.Summary.PolicyCoverage = float64(usedPolicies) / float64(totalPolicies) * 100
		}
	}

	// Policy stats
	for policyID, count := range stats.ByPolicy {
		pStats := PolicyComplianceStats{
			PolicyID:    policyID,
			Evaluations: count,
		}

		// Count allowed/denied for this policy
		for _, entry := range entries {
			if entry.PolicyID != policyID {
				continue
			}
			if entry.Decision != nil {
				if entry.Decision.Allowed {
					pStats.Allowed++
				} else {
					pStats.Denied++
				}
			}
		}

		if pStats.Evaluations > 0 {
			pStats.ComplianceRate = float64(pStats.Allowed) / float64(pStats.Evaluations) * 100
		}

		report.PolicyStats = append(report.PolicyStats, pStats)
	}

	// Sort by evaluations descending
	sort.Slice(report.PolicyStats, func(i, j int) bool {
		return report.PolicyStats[i].Evaluations > report.PolicyStats[j].Evaluations
	})

	// Violation summary
	report.ViolationSummary = r.calculateViolationSummary(entries)

	// Generate recommendations
	report.Recommendations = r.generateRecommendations(report)

	return report
}

// calculateViolationSummary calculates violation statistics.
func (r *ComplianceReporter) calculateViolationSummary(entries []*AuditEntry) ViolationSummary {
	summary := ViolationSummary{
		ViolationsByType: make(map[string]int64),
	}

	violatorCounts := make(map[string]int64)
	dailyViolations := make(map[string]int64)

	for _, entry := range entries {
		if entry.Decision == nil || entry.Decision.Allowed {
			continue
		}

		summary.TotalViolations++

		// By policy type
		summary.ViolationsByType[entry.PolicyID]++

		// By user
		if entry.Input != nil && entry.Input.UserID != "" {
			violatorCounts[entry.Input.UserID]++
		}

		// Daily trend
		day := entry.Timestamp.Format("2006-01-02")
		dailyViolations[day]++
	}

	// Top violators
	type violatorEntry struct {
		userID string
		count  int64
	}
	var violators []violatorEntry
	for userID, count := range violatorCounts {
		violators = append(violators, violatorEntry{userID, count})
	}
	sort.Slice(violators, func(i, j int) bool {
		return violators[i].count > violators[j].count
	})
	for i := 0; i < len(violators) && i < 10; i++ {
		summary.TopViolators = append(summary.TopViolators, ViolatorInfo{
			UserID:     violators[i].userID,
			Violations: violators[i].count,
		})
	}

	// Violation trend
	var days []string
	for day := range dailyViolations {
		days = append(days, day)
	}
	sort.Strings(days)
	for _, day := range days {
		ts, _ := time.Parse("2006-01-02", day)
		summary.ViolationTrend = append(summary.ViolationTrend, ViolationTrendDataPoint{
			Timestamp:  ts,
			Violations: dailyViolations[day],
		})
	}

	return summary
}

// generateRecommendations generates compliance recommendations based on the report.
func (r *ComplianceReporter) generateRecommendations(report *ComplianceReport) []string {
	var recommendations []string

	// High denial rate
	if report.Summary.DenialRate > 20 {
		recommendations = append(recommendations,
			fmt.Sprintf("High denial rate (%.1f%%) detected. Review policies for overly restrictive rules.", report.Summary.DenialRate))
	}

	// Low policy coverage
	if report.Summary.PolicyCoverage < 50 {
		recommendations = append(recommendations,
			fmt.Sprintf("Low policy coverage (%.1f%%). Consider adding policies for uncovered endpoints.", report.Summary.PolicyCoverage))
	}

	// High latency
	if report.Summary.AverageResponseTime > 10 {
		recommendations = append(recommendations,
			fmt.Sprintf("High average policy evaluation time (%.1fms). Consider optimizing complex policies.", report.Summary.AverageResponseTime))
	}

	// Frequent violators
	if len(report.ViolationSummary.TopViolators) > 0 {
		top := report.ViolationSummary.TopViolators[0]
		if top.Violations > 100 {
			recommendations = append(recommendations,
				fmt.Sprintf("User %s has %d violations. Consider reviewing their access patterns.", top.UserID, top.Violations))
		}
	}

	// Increasing violation trend
	if len(report.ViolationSummary.ViolationTrend) >= 2 {
		last := report.ViolationSummary.ViolationTrend[len(report.ViolationSummary.ViolationTrend)-1]
		prev := report.ViolationSummary.ViolationTrend[len(report.ViolationSummary.ViolationTrend)-2]
		if last.Violations > prev.Violations*2 {
			recommendations = append(recommendations,
				"Violation trend is increasing rapidly. Investigate recent policy or access changes.")
		}
	}

	return recommendations
}

// ExportReport exports a compliance report in the specified format.
func (r *ComplianceReporter) ExportReport(report *ComplianceReport, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// FileAuditWriter writes audit entries to a file.
type FileAuditWriter struct {
	file     *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
}

// NewFileAuditWriter creates a new file audit writer.
func NewFileAuditWriter(path string) (*FileAuditWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &FileAuditWriter{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// Write writes an audit entry.
func (w *FileAuditWriter) Write(entry *AuditEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(entry)
}

// Flush flushes the file.
func (w *FileAuditWriter) Flush() error {
	return w.file.Sync()
}

// Close closes the file.
func (w *FileAuditWriter) Close() error {
	return w.file.Close()
}

// Context key for request ID.
type contextKey string

const requestIDKey contextKey = "request_id"

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// generateAuditID generates a unique audit entry ID.
var auditIDCounter int64
var auditIDMu sync.Mutex

func generateAuditID() string {
	auditIDMu.Lock()
	auditIDCounter++
	id := auditIDCounter
	auditIDMu.Unlock()
	return fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), id)
}

// AuditedEngine wraps an Engine with audit logging.
type AuditedEngine struct {
	engine      *Engine
	auditLogger *AuditLogger
	store       *PolicyStore
}

// NewAuditedEngine creates a new audited engine.
func NewAuditedEngine(engine *Engine, auditLogger *AuditLogger, store *PolicyStore) *AuditedEngine {
	return &AuditedEngine{
		engine:      engine,
		auditLogger: auditLogger,
		store:       store,
	}
}

// Evaluate evaluates a policy and logs the decision.
func (ae *AuditedEngine) Evaluate(ctx context.Context, policy string, input *Input) (*Decision, error) {
	start := time.Now()
	decision, err := ae.engine.Evaluate(ctx, policy, input)
	duration := time.Since(start)

	if err == nil && ae.auditLogger != nil {
		var version int
		if ae.store != nil {
			if managed, err := ae.store.Get(policy); err == nil {
				version = managed.CurrentVersion
			}
		}
		if version > 0 {
			ae.auditLogger.LogWithVersion(ctx, policy, version, input, decision, duration)
		} else {
			ae.auditLogger.Log(ctx, policy, input, decision, duration)
		}
	}

	return decision, err
}
