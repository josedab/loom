// Package policy provides policy versioning and hot-reload capabilities.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// PolicyVersion represents a specific version of a policy.
type PolicyVersion struct {
	ID          string                 `json:"id" yaml:"id"`
	Version     int                    `json:"version" yaml:"version"`
	Content     string                 `json:"content" yaml:"content"`
	ContentHash string                 `json:"content_hash" yaml:"content_hash"`
	Type        PolicyType             `json:"type" yaml:"type"`
	Metadata    PolicyMetadata         `json:"metadata" yaml:"metadata"`
	CreatedAt   time.Time              `json:"created_at" yaml:"created_at"`
	CreatedBy   string                 `json:"created_by,omitempty" yaml:"created_by,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Tags        []string               `json:"tags,omitempty" yaml:"tags,omitempty"`
	Extra       map[string]interface{} `json:"-" yaml:"-"` // Extra fields for type-specific data
}

// PolicyType represents the type of policy (CEL, OPA, etc.).
type PolicyType string

const (
	PolicyTypeCEL    PolicyType = "cel"
	PolicyTypeOPA    PolicyType = "opa"
	PolicyTypeLocal  PolicyType = "local"
	PolicyTypeCustom PolicyType = "custom"
)

// PolicyMetadata contains metadata about a policy.
type PolicyMetadata struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Author      string `json:"author,omitempty" yaml:"author,omitempty"`
	Priority    int    `json:"priority,omitempty" yaml:"priority,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// PolicyStatus represents the status of a policy.
type PolicyStatus string

const (
	PolicyStatusActive     PolicyStatus = "active"
	PolicyStatusInactive   PolicyStatus = "inactive"
	PolicyStatusPending    PolicyStatus = "pending"
	PolicyStatusDeprecated PolicyStatus = "deprecated"
	PolicyStatusFailed     PolicyStatus = "failed"
)

// PolicyStore manages policy versions and persistence.
type PolicyStore struct {
	policies      map[string]*ManagedPolicy
	storageDir    string
	backupDir     string
	maxVersions   int
	logger        *slog.Logger
	mu            sync.RWMutex
	changeHooks   []PolicyChangeHook
	validationFn  PolicyValidationFunc
	notifications chan PolicyChangeEvent
}

// ManagedPolicy represents a policy with version history.
type ManagedPolicy struct {
	ID             string           `json:"id" yaml:"id"`
	CurrentVersion int              `json:"current_version" yaml:"current_version"`
	Versions       []*PolicyVersion `json:"versions" yaml:"versions"`
	Status         PolicyStatus     `json:"status" yaml:"status"`
	LoadedAt       time.Time        `json:"loaded_at" yaml:"loaded_at"`
	LastModified   time.Time        `json:"last_modified" yaml:"last_modified"`
}

// PolicyChangeHook is called when a policy changes.
type PolicyChangeHook func(event PolicyChangeEvent)

// PolicyChangeEvent represents a change to a policy.
type PolicyChangeEvent struct {
	Type      PolicyChangeType `json:"type"`
	PolicyID  string           `json:"policy_id"`
	Version   int              `json:"version"`
	OldStatus PolicyStatus     `json:"old_status,omitempty"`
	NewStatus PolicyStatus     `json:"new_status,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
	Error     error            `json:"error,omitempty"`
}

// PolicyChangeType represents the type of policy change.
type PolicyChangeType string

const (
	PolicyChangeCreated    PolicyChangeType = "created"
	PolicyChangeUpdated    PolicyChangeType = "updated"
	PolicyChangeDeleted    PolicyChangeType = "deleted"
	PolicyChangeRolledBack PolicyChangeType = "rolled_back"
	PolicyChangeActivated  PolicyChangeType = "activated"
	PolicyChangeDeactivated PolicyChangeType = "deactivated"
	PolicyChangeReloaded   PolicyChangeType = "reloaded"
)

// PolicyValidationFunc validates a policy before it's applied.
type PolicyValidationFunc func(policy *PolicyVersion) error

// PolicyStoreConfig configures the policy store.
type PolicyStoreConfig struct {
	StorageDir    string
	BackupDir     string
	MaxVersions   int
	Logger        *slog.Logger
	ValidationFn  PolicyValidationFunc
}

// NewPolicyStore creates a new policy store.
func NewPolicyStore(cfg PolicyStoreConfig) *PolicyStore {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxVersions == 0 {
		cfg.MaxVersions = 10
	}

	store := &PolicyStore{
		policies:      make(map[string]*ManagedPolicy),
		storageDir:    cfg.StorageDir,
		backupDir:     cfg.BackupDir,
		maxVersions:   cfg.MaxVersions,
		logger:        cfg.Logger,
		validationFn:  cfg.ValidationFn,
		notifications: make(chan PolicyChangeEvent, 100),
	}

	// Create storage directories if they don't exist
	if cfg.StorageDir != "" {
		os.MkdirAll(cfg.StorageDir, 0755)
	}
	if cfg.BackupDir != "" {
		os.MkdirAll(cfg.BackupDir, 0755)
	}

	return store
}

// RegisterChangeHook registers a callback for policy changes.
func (s *PolicyStore) RegisterChangeHook(hook PolicyChangeHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changeHooks = append(s.changeHooks, hook)
}

// Notifications returns the channel for policy change events.
func (s *PolicyStore) Notifications() <-chan PolicyChangeEvent {
	return s.notifications
}

// Create creates a new policy with the given content.
func (s *PolicyStore) Create(ctx context.Context, id string, policyType PolicyType, content string, metadata PolicyMetadata) (*PolicyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if policy already exists
	if _, exists := s.policies[id]; exists {
		return nil, fmt.Errorf("policy already exists: %s", id)
	}

	// Create version
	version := &PolicyVersion{
		ID:          id,
		Version:     1,
		Content:     content,
		ContentHash: s.hashContent(content),
		Type:        policyType,
		Metadata:    metadata,
		CreatedAt:   time.Now(),
	}

	// Validate if validation function is set
	if s.validationFn != nil {
		if err := s.validationFn(version); err != nil {
			return nil, fmt.Errorf("policy validation failed: %w", err)
		}
	}

	// Create managed policy
	managed := &ManagedPolicy{
		ID:             id,
		CurrentVersion: 1,
		Versions:       []*PolicyVersion{version},
		Status:         PolicyStatusActive,
		LoadedAt:       time.Now(),
		LastModified:   time.Now(),
	}

	s.policies[id] = managed

	// Persist to disk if storage is configured
	if s.storageDir != "" {
		if err := s.persistPolicy(managed); err != nil {
			s.logger.Error("failed to persist policy", "id", id, "error", err)
		}
	}

	// Emit event
	s.emitEvent(PolicyChangeEvent{
		Type:      PolicyChangeCreated,
		PolicyID:  id,
		Version:   1,
		NewStatus: PolicyStatusActive,
		Timestamp: time.Now(),
	})

	s.logger.Info("policy created",
		"id", id,
		"type", policyType,
		"version", 1,
	)

	return version, nil
}

// Update updates a policy with new content, creating a new version.
func (s *PolicyStore) Update(ctx context.Context, id string, content string, metadata *PolicyMetadata) (*PolicyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	managed, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}

	// Get current version
	currentVersion := s.getCurrentVersion(managed)
	if currentVersion == nil {
		return nil, fmt.Errorf("no current version for policy: %s", id)
	}

	// Check if content actually changed
	newHash := s.hashContent(content)
	if newHash == currentVersion.ContentHash {
		return currentVersion, nil // No change
	}

	// Create new version
	newVersionNum := managed.CurrentVersion + 1
	newMeta := currentVersion.Metadata
	if metadata != nil {
		newMeta = *metadata
	}

	version := &PolicyVersion{
		ID:          id,
		Version:     newVersionNum,
		Content:     content,
		ContentHash: newHash,
		Type:        currentVersion.Type,
		Metadata:    newMeta,
		CreatedAt:   time.Now(),
	}

	// Validate
	if s.validationFn != nil {
		if err := s.validationFn(version); err != nil {
			return nil, fmt.Errorf("policy validation failed: %w", err)
		}
	}

	// Add version
	managed.Versions = append(managed.Versions, version)
	managed.CurrentVersion = newVersionNum
	managed.LastModified = time.Now()

	// Prune old versions
	s.pruneVersions(managed)

	// Persist
	if s.storageDir != "" {
		if err := s.persistPolicy(managed); err != nil {
			s.logger.Error("failed to persist policy", "id", id, "error", err)
		}
	}

	// Emit event
	s.emitEvent(PolicyChangeEvent{
		Type:     PolicyChangeUpdated,
		PolicyID: id,
		Version:  newVersionNum,
		Timestamp: time.Now(),
	})

	s.logger.Info("policy updated",
		"id", id,
		"version", newVersionNum,
	)

	return version, nil
}

// Get retrieves a policy by ID.
func (s *PolicyStore) Get(id string) (*ManagedPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	managed, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}

	return managed, nil
}

// GetVersion retrieves a specific version of a policy.
func (s *PolicyStore) GetVersion(id string, version int) (*PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	managed, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}

	for _, v := range managed.Versions {
		if v.Version == version {
			return v, nil
		}
	}

	return nil, fmt.Errorf("version not found: %s v%d", id, version)
}

// GetCurrentVersion retrieves the current version of a policy.
func (s *PolicyStore) GetCurrentVersion(id string) (*PolicyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	managed, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}

	return s.getCurrentVersion(managed), nil
}

// List returns all managed policies.
func (s *PolicyStore) List() []*ManagedPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policies := make([]*ManagedPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}

	// Sort by ID
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].ID < policies[j].ID
	})

	return policies
}

// Delete deletes a policy.
func (s *PolicyStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	managed, exists := s.policies[id]
	if !exists {
		return fmt.Errorf("policy not found: %s", id)
	}

	// Backup before delete
	if s.backupDir != "" {
		if err := s.backupPolicy(managed); err != nil {
			s.logger.Error("failed to backup policy before delete", "id", id, "error", err)
		}
	}

	delete(s.policies, id)

	// Remove from disk
	if s.storageDir != "" {
		path := filepath.Join(s.storageDir, id+".yaml")
		os.Remove(path)
	}

	// Emit event
	s.emitEvent(PolicyChangeEvent{
		Type:      PolicyChangeDeleted,
		PolicyID:  id,
		OldStatus: managed.Status,
		Timestamp: time.Now(),
	})

	s.logger.Info("policy deleted", "id", id)

	return nil
}

// Rollback rolls back a policy to a previous version.
func (s *PolicyStore) Rollback(ctx context.Context, id string, targetVersion int) (*PolicyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	managed, exists := s.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}

	// Find target version
	var targetPolicyVersion *PolicyVersion
	for _, v := range managed.Versions {
		if v.Version == targetVersion {
			targetPolicyVersion = v
			break
		}
	}

	if targetPolicyVersion == nil {
		return nil, fmt.Errorf("version not found: %s v%d", id, targetVersion)
	}

	oldVersion := managed.CurrentVersion

	// Create new version based on the target
	newVersionNum := managed.CurrentVersion + 1
	version := &PolicyVersion{
		ID:          id,
		Version:     newVersionNum,
		Content:     targetPolicyVersion.Content,
		ContentHash: targetPolicyVersion.ContentHash,
		Type:        targetPolicyVersion.Type,
		Metadata:    targetPolicyVersion.Metadata,
		CreatedAt:   time.Now(),
		Annotations: map[string]string{
			"rollback_from": fmt.Sprintf("v%d", oldVersion),
			"rollback_to":   fmt.Sprintf("v%d", targetVersion),
		},
	}

	// Add version
	managed.Versions = append(managed.Versions, version)
	managed.CurrentVersion = newVersionNum
	managed.LastModified = time.Now()

	// Prune old versions
	s.pruneVersions(managed)

	// Persist
	if s.storageDir != "" {
		if err := s.persistPolicy(managed); err != nil {
			s.logger.Error("failed to persist policy", "id", id, "error", err)
		}
	}

	// Emit event
	s.emitEvent(PolicyChangeEvent{
		Type:     PolicyChangeRolledBack,
		PolicyID: id,
		Version:  newVersionNum,
		Timestamp: time.Now(),
	})

	s.logger.Info("policy rolled back",
		"id", id,
		"from_version", oldVersion,
		"to_version", targetVersion,
		"new_version", newVersionNum,
	)

	return version, nil
}

// SetStatus sets the status of a policy.
func (s *PolicyStore) SetStatus(id string, status PolicyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	managed, exists := s.policies[id]
	if !exists {
		return fmt.Errorf("policy not found: %s", id)
	}

	oldStatus := managed.Status
	managed.Status = status
	managed.LastModified = time.Now()

	// Persist
	if s.storageDir != "" {
		if err := s.persistPolicy(managed); err != nil {
			s.logger.Error("failed to persist policy", "id", id, "error", err)
		}
	}

	// Emit event
	eventType := PolicyChangeUpdated
	if status == PolicyStatusActive {
		eventType = PolicyChangeActivated
	} else if status == PolicyStatusInactive {
		eventType = PolicyChangeDeactivated
	}

	s.emitEvent(PolicyChangeEvent{
		Type:      eventType,
		PolicyID:  id,
		Version:   managed.CurrentVersion,
		OldStatus: oldStatus,
		NewStatus: status,
		Timestamp: time.Now(),
	})

	return nil
}

// getCurrentVersion returns the current version of a managed policy.
func (s *PolicyStore) getCurrentVersion(managed *ManagedPolicy) *PolicyVersion {
	for _, v := range managed.Versions {
		if v.Version == managed.CurrentVersion {
			return v
		}
	}
	return nil
}

// pruneVersions removes old versions beyond maxVersions.
func (s *PolicyStore) pruneVersions(managed *ManagedPolicy) {
	if len(managed.Versions) <= s.maxVersions {
		return
	}

	// Sort by version number
	sort.Slice(managed.Versions, func(i, j int) bool {
		return managed.Versions[i].Version < managed.Versions[j].Version
	})

	// Keep only the most recent maxVersions
	managed.Versions = managed.Versions[len(managed.Versions)-s.maxVersions:]
}

// hashContent computes a SHA-256 hash of the content.
func (s *PolicyStore) hashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// persistPolicy saves a policy to disk.
func (s *PolicyStore) persistPolicy(managed *ManagedPolicy) error {
	if s.storageDir == "" {
		return nil
	}

	path := filepath.Join(s.storageDir, managed.ID+".yaml")
	data, err := yaml.Marshal(managed)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// backupPolicy creates a backup of a policy.
func (s *PolicyStore) backupPolicy(managed *ManagedPolicy) error {
	if s.backupDir == "" {
		return nil
	}

	timestamp := time.Now().Format("20060102-150405")
	path := filepath.Join(s.backupDir, fmt.Sprintf("%s-%s.yaml", managed.ID, timestamp))

	data, err := yaml.Marshal(managed)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// LoadFromDisk loads all policies from the storage directory.
func (s *PolicyStore) LoadFromDisk() error {
	if s.storageDir == "" {
		return nil
	}

	entries, err := os.ReadDir(s.storageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read storage directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(s.storageDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			s.logger.Error("failed to read policy file", "path", path, "error", err)
			continue
		}

		var managed ManagedPolicy
		if err := yaml.Unmarshal(data, &managed); err != nil {
			s.logger.Error("failed to unmarshal policy", "path", path, "error", err)
			continue
		}

		s.mu.Lock()
		s.policies[managed.ID] = &managed
		s.mu.Unlock()

		s.logger.Info("loaded policy from disk",
			"id", managed.ID,
			"version", managed.CurrentVersion,
		)
	}

	return nil
}

// emitEvent emits a policy change event.
func (s *PolicyStore) emitEvent(event PolicyChangeEvent) {
	// Call hooks
	for _, hook := range s.changeHooks {
		go hook(event)
	}

	// Send to notification channel (non-blocking)
	select {
	case s.notifications <- event:
	default:
		s.logger.Warn("policy notification channel full, dropping event",
			"type", event.Type,
			"policy", event.PolicyID,
		)
	}
}

// HotReloader watches for policy file changes and reloads them.
type HotReloader struct {
	store         *PolicyStore
	engine        *Engine
	evaluator     Evaluator
	watchDir      string
	watcher       *fsnotify.Watcher
	debounceDelay time.Duration
	stopCh        chan struct{}
	logger        *slog.Logger
	mu            sync.Mutex

	// Pending changes for debouncing
	pending map[string]time.Time
}

// HotReloaderConfig configures the hot reloader.
type HotReloaderConfig struct {
	Store         *PolicyStore
	Engine        *Engine
	Evaluator     Evaluator
	WatchDir      string
	DebounceDelay time.Duration
	Logger        *slog.Logger
}

// NewHotReloader creates a new hot reloader.
func NewHotReloader(cfg HotReloaderConfig) (*HotReloader, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DebounceDelay == 0 {
		cfg.DebounceDelay = 500 * time.Millisecond
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add watch directory
	if err := watcher.Add(cfg.WatchDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch directory %s: %w", cfg.WatchDir, err)
	}

	return &HotReloader{
		store:         cfg.Store,
		engine:        cfg.Engine,
		evaluator:     cfg.Evaluator,
		watchDir:      cfg.WatchDir,
		watcher:       watcher,
		debounceDelay: cfg.DebounceDelay,
		stopCh:        make(chan struct{}),
		logger:        cfg.Logger,
		pending:       make(map[string]time.Time),
	}, nil
}

// Start starts the hot reloader.
func (r *HotReloader) Start() {
	go r.watchLoop()
	go r.processLoop()

	r.logger.Info("hot reloader started", "watch_dir", r.watchDir)
}

// Stop stops the hot reloader.
func (r *HotReloader) Stop() error {
	close(r.stopCh)
	return r.watcher.Close()
}

// watchLoop watches for file system events.
func (r *HotReloader) watchLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}

			if !r.isRelevantFile(event.Name) {
				continue
			}

			r.mu.Lock()
			r.pending[event.Name] = time.Now()
			r.mu.Unlock()

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Error("file watcher error", "error", err)
		}
	}
}

// processLoop processes pending file changes after debounce delay.
func (r *HotReloader) processLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.processPending()
		}
	}
}

// processPending processes files that have been stable for the debounce delay.
func (r *HotReloader) processPending() {
	r.mu.Lock()
	now := time.Now()
	toProcess := make([]string, 0)

	for path, lastChange := range r.pending {
		if now.Sub(lastChange) >= r.debounceDelay {
			toProcess = append(toProcess, path)
			delete(r.pending, path)
		}
	}
	r.mu.Unlock()

	for _, path := range toProcess {
		if err := r.reloadFile(path); err != nil {
			r.logger.Error("failed to reload policy file",
				"path", path,
				"error", err,
			)
		}
	}
}

// isRelevantFile checks if a file should trigger a reload.
func (r *HotReloader) isRelevantFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".rego"
}

// reloadFile reloads a policy from a file.
func (r *HotReloader) reloadFile(path string) error {
	r.logger.Info("reloading policy file", "path", path)

	// Check if file still exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		// File was deleted
		return r.handleDeletedFile(path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if info.IsDir() {
		return nil
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse based on extension
	ext := strings.ToLower(filepath.Ext(path))
	var policies []PolicyFileEntry

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &policies); err != nil {
			// Try single policy format
			var single PolicyFileEntry
			if err2 := yaml.Unmarshal(data, &single); err2 == nil {
				policies = []PolicyFileEntry{single}
			} else {
				return fmt.Errorf("failed to parse YAML: %w", err)
			}
		}
	case ".json":
		if err := json.Unmarshal(data, &policies); err != nil {
			var single PolicyFileEntry
			if err2 := json.Unmarshal(data, &single); err2 == nil {
				policies = []PolicyFileEntry{single}
			} else {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
		}
	case ".rego":
		// Rego files use filename as policy ID
		id := strings.TrimSuffix(filepath.Base(path), ext)
		policies = []PolicyFileEntry{{
			ID:      id,
			Type:    string(PolicyTypeOPA),
			Content: string(data),
			Enabled: true,
		}}
	default:
		return fmt.Errorf("unsupported file extension: %s", ext)
	}

	// Update policies
	for _, entry := range policies {
		if err := r.applyPolicy(entry); err != nil {
			r.logger.Error("failed to apply policy",
				"id", entry.ID,
				"error", err,
			)
		}
	}

	return nil
}

// handleDeletedFile handles a deleted policy file.
func (r *HotReloader) handleDeletedFile(path string) error {
	// Extract policy ID from filename
	id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	// Check if policy exists
	if _, err := r.store.Get(id); err != nil {
		return nil // Policy doesn't exist, nothing to do
	}

	// Mark as inactive rather than deleting
	if err := r.store.SetStatus(id, PolicyStatusInactive); err != nil {
		return fmt.Errorf("failed to deactivate policy: %w", err)
	}

	r.logger.Info("policy deactivated due to file deletion", "id", id)
	return nil
}

// applyPolicy applies a policy file entry.
func (r *HotReloader) applyPolicy(entry PolicyFileEntry) error {
	ctx := context.Background()

	// Validate the policy content first
	if err := r.validatePolicy(entry); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	// Check if policy exists
	existing, err := r.store.Get(entry.ID)
	if err != nil {
		// Create new policy
		metadata := PolicyMetadata{
			Name:        entry.Name,
			Description: entry.Description,
			Enabled:     entry.Enabled,
		}

		_, err = r.store.Create(ctx, entry.ID, PolicyType(entry.Type), entry.Content, metadata)
		if err != nil {
			return fmt.Errorf("failed to create policy: %w", err)
		}

		r.logger.Info("policy created from file",
			"id", entry.ID,
			"type", entry.Type,
		)
	} else {
		// Update existing policy
		metadata := PolicyMetadata{
			Name:        entry.Name,
			Description: entry.Description,
			Enabled:     entry.Enabled,
		}

		_, err = r.store.Update(ctx, entry.ID, entry.Content, &metadata)
		if err != nil {
			return fmt.Errorf("failed to update policy: %w", err)
		}

		// Update status if changed
		newStatus := PolicyStatusActive
		if !entry.Enabled {
			newStatus = PolicyStatusInactive
		}
		if existing.Status != newStatus {
			r.store.SetStatus(entry.ID, newStatus)
		}

		r.logger.Info("policy updated from file",
			"id", entry.ID,
			"type", entry.Type,
		)
	}

	// Apply to evaluator if CEL type
	if r.evaluator != nil && entry.Type == string(PolicyTypeCEL) {
		if celEval, ok := r.evaluator.(*CELEvaluator); ok {
			if err := celEval.AddPolicy(entry.ID, entry.Content); err != nil {
				return fmt.Errorf("failed to compile CEL policy: %w", err)
			}
		}
	}

	return nil
}

// validatePolicy validates a policy entry.
func (r *HotReloader) validatePolicy(entry PolicyFileEntry) error {
	if entry.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if entry.Content == "" {
		return fmt.Errorf("policy content is required")
	}

	// Type-specific validation
	switch PolicyType(entry.Type) {
	case PolicyTypeCEL:
		if r.evaluator != nil {
			if celEval, ok := r.evaluator.(*CELEvaluator); ok {
				if err := celEval.ValidateExpression(entry.Content); err != nil {
					return fmt.Errorf("invalid CEL expression: %w", err)
				}
			}
		}
	case PolicyTypeOPA:
		// OPA validation would require an OPA connection
		// For now, just check basic syntax
		if !strings.Contains(entry.Content, "package") {
			return fmt.Errorf("OPA policy must contain a package declaration")
		}
	}

	return nil
}

// PolicyFileEntry represents a policy entry in a file.
type PolicyFileEntry struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Type        string `json:"type" yaml:"type"`
	Content     string `json:"content" yaml:"content"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// Reload forces a reload of a specific policy file.
func (r *HotReloader) Reload(path string) error {
	return r.reloadFile(path)
}

// ReloadAll reloads all policy files in the watch directory.
func (r *HotReloader) ReloadAll() error {
	entries, err := os.ReadDir(r.watchDir)
	if err != nil {
		return fmt.Errorf("failed to read watch directory: %w", err)
	}

	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || !r.isRelevantFile(entry.Name()) {
			continue
		}

		path := filepath.Join(r.watchDir, entry.Name())
		if err := r.reloadFile(path); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", entry.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("reload errors: %v", errs)
	}

	return nil
}

// PolicyDiff represents the difference between two policy versions.
type PolicyDiff struct {
	PolicyID   string           `json:"policy_id"`
	OldVersion *PolicyVersion   `json:"old_version,omitempty"`
	NewVersion *PolicyVersion   `json:"new_version,omitempty"`
	Changes    []PolicyChange   `json:"changes"`
}

// PolicyChange represents a specific change in a policy.
type PolicyChange struct {
	Field    string `json:"field"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// DiffVersions compares two versions of a policy.
func (s *PolicyStore) DiffVersions(id string, v1, v2 int) (*PolicyDiff, error) {
	version1, err := s.GetVersion(id, v1)
	if err != nil {
		return nil, err
	}

	version2, err := s.GetVersion(id, v2)
	if err != nil {
		return nil, err
	}

	diff := &PolicyDiff{
		PolicyID:   id,
		OldVersion: version1,
		NewVersion: version2,
		Changes:    make([]PolicyChange, 0),
	}

	// Compare content
	if version1.Content != version2.Content {
		diff.Changes = append(diff.Changes, PolicyChange{
			Field:    "content",
			OldValue: version1.Content,
			NewValue: version2.Content,
		})
	}

	// Compare metadata
	if version1.Metadata.Name != version2.Metadata.Name {
		diff.Changes = append(diff.Changes, PolicyChange{
			Field:    "metadata.name",
			OldValue: version1.Metadata.Name,
			NewValue: version2.Metadata.Name,
		})
	}

	if version1.Metadata.Description != version2.Metadata.Description {
		diff.Changes = append(diff.Changes, PolicyChange{
			Field:    "metadata.description",
			OldValue: version1.Metadata.Description,
			NewValue: version2.Metadata.Description,
		})
	}

	if version1.Metadata.Enabled != version2.Metadata.Enabled {
		diff.Changes = append(diff.Changes, PolicyChange{
			Field:    "metadata.enabled",
			OldValue: fmt.Sprintf("%v", version1.Metadata.Enabled),
			NewValue: fmt.Sprintf("%v", version2.Metadata.Enabled),
		})
	}

	return diff, nil
}

// Export exports all policies to a single file.
func (s *PolicyStore) Export(format string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policies := make([]*ManagedPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}

	switch format {
	case "yaml":
		return yaml.Marshal(policies)
	case "json":
		return json.MarshalIndent(policies, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// Import imports policies from data.
func (s *PolicyStore) Import(ctx context.Context, data []byte, format string) error {
	var policies []*ManagedPolicy

	switch format {
	case "yaml":
		if err := yaml.Unmarshal(data, &policies); err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	case "json":
		if err := json.Unmarshal(data, &policies); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range policies {
		s.policies[p.ID] = p

		// Persist
		if s.storageDir != "" {
			if err := s.persistPolicy(p); err != nil {
				s.logger.Error("failed to persist imported policy", "id", p.ID, "error", err)
			}
		}

		s.emitEvent(PolicyChangeEvent{
			Type:      PolicyChangeCreated,
			PolicyID:  p.ID,
			Version:   p.CurrentVersion,
			NewStatus: p.Status,
			Timestamp: time.Now(),
		})
	}

	s.logger.Info("imported policies", "count", len(policies))

	return nil
}
