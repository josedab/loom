package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestPolicyStore_Create(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{
		MaxVersions: 5,
	})

	ctx := context.Background()
	metadata := PolicyMetadata{
		Name:        "test-policy",
		Description: "A test policy",
		Enabled:     true,
	}

	version, err := store.Create(ctx, "test", PolicyTypeCEL, "request.method == 'GET'", metadata)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if version.ID != "test" {
		t.Errorf("expected ID 'test', got %s", version.ID)
	}
	if version.Version != 1 {
		t.Errorf("expected version 1, got %d", version.Version)
	}
	if version.Content != "request.method == 'GET'" {
		t.Errorf("unexpected content: %s", version.Content)
	}
	if version.Type != PolicyTypeCEL {
		t.Errorf("expected type CEL, got %s", version.Type)
	}
	if version.ContentHash == "" {
		t.Error("content hash should not be empty")
	}

	// Verify policy exists
	managed, err := store.Get("test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if managed.CurrentVersion != 1 {
		t.Errorf("expected current version 1, got %d", managed.CurrentVersion)
	}
	if managed.Status != PolicyStatusActive {
		t.Errorf("expected status Active, got %s", managed.Status)
	}
}

func TestPolicyStore_CreateDuplicate(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, err := store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Try to create duplicate
	_, err = store.Create(ctx, "test", PolicyTypeCEL, "false", PolicyMetadata{})
	if err == nil {
		t.Error("expected error for duplicate policy")
	}
}

func TestPolicyStore_Update(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, err := store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{Name: "v1"})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update with new content
	version, err := store.Update(ctx, "test", "false", &PolicyMetadata{Name: "v2"})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if version.Version != 2 {
		t.Errorf("expected version 2, got %d", version.Version)
	}
	if version.Content != "false" {
		t.Errorf("expected content 'false', got %s", version.Content)
	}
	if version.Metadata.Name != "v2" {
		t.Errorf("expected metadata name 'v2', got %s", version.Metadata.Name)
	}

	// Verify current version updated
	managed, err := store.Get("test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if managed.CurrentVersion != 2 {
		t.Errorf("expected current version 2, got %d", managed.CurrentVersion)
	}
	if len(managed.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(managed.Versions))
	}
}

func TestPolicyStore_UpdateNoChange(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, err := store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update with same content
	version, err := store.Update(ctx, "test", "true", nil)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Should return same version without creating new one
	if version.Version != 1 {
		t.Errorf("expected version 1 (no change), got %d", version.Version)
	}

	managed, _ := store.Get("test")
	if len(managed.Versions) != 1 {
		t.Errorf("expected 1 version (no change), got %d", len(managed.Versions))
	}
}

func TestPolicyStore_GetVersion(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "v1-content", PolicyMetadata{})
	_, _ = store.Update(ctx, "test", "v2-content", nil)
	_, _ = store.Update(ctx, "test", "v3-content", nil)

	// Get specific version
	v2, err := store.GetVersion("test", 2)
	if err != nil {
		t.Fatalf("GetVersion failed: %v", err)
	}
	if v2.Content != "v2-content" {
		t.Errorf("expected v2-content, got %s", v2.Content)
	}

	// Get non-existent version
	_, err = store.GetVersion("test", 99)
	if err == nil {
		t.Error("expected error for non-existent version")
	}
}

func TestPolicyStore_GetCurrentVersion(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "v1", PolicyMetadata{})
	_, _ = store.Update(ctx, "test", "v2", nil)

	current, err := store.GetCurrentVersion("test")
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}
	if current.Version != 2 {
		t.Errorf("expected version 2, got %d", current.Version)
	}
	if current.Content != "v2" {
		t.Errorf("expected content 'v2', got %s", current.Content)
	}
}

func TestPolicyStore_List(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "policy-b", PolicyTypeCEL, "true", PolicyMetadata{})
	_, _ = store.Create(ctx, "policy-a", PolicyTypeCEL, "true", PolicyMetadata{})
	_, _ = store.Create(ctx, "policy-c", PolicyTypeCEL, "true", PolicyMetadata{})

	list := store.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(list))
	}

	// Should be sorted by ID
	if list[0].ID != "policy-a" || list[1].ID != "policy-b" || list[2].ID != "policy-c" {
		t.Error("policies not sorted correctly")
	}
}

func TestPolicyStore_Delete(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{})

	err := store.Delete("test")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = store.Get("test")
	if err == nil {
		t.Error("expected error for deleted policy")
	}
}

func TestPolicyStore_Rollback(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "v1-content", PolicyMetadata{Name: "v1"})
	_, _ = store.Update(ctx, "test", "v2-content", &PolicyMetadata{Name: "v2"})
	_, _ = store.Update(ctx, "test", "v3-content", &PolicyMetadata{Name: "v3"})

	// Rollback to version 1
	rolled, err := store.Rollback(ctx, "test", 1)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if rolled.Version != 4 {
		t.Errorf("expected new version 4, got %d", rolled.Version)
	}
	if rolled.Content != "v1-content" {
		t.Errorf("expected v1-content, got %s", rolled.Content)
	}
	if rolled.Metadata.Name != "v1" {
		t.Errorf("expected metadata name 'v1', got %s", rolled.Metadata.Name)
	}

	// Check rollback annotation
	if rolled.Annotations["rollback_from"] != "v3" {
		t.Errorf("expected rollback_from 'v3', got %s", rolled.Annotations["rollback_from"])
	}
	if rolled.Annotations["rollback_to"] != "v1" {
		t.Errorf("expected rollback_to 'v1', got %s", rolled.Annotations["rollback_to"])
	}
}

func TestPolicyStore_SetStatus(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{})

	// Deactivate
	err := store.SetStatus("test", PolicyStatusInactive)
	if err != nil {
		t.Fatalf("SetStatus failed: %v", err)
	}

	managed, _ := store.Get("test")
	if managed.Status != PolicyStatusInactive {
		t.Errorf("expected status Inactive, got %s", managed.Status)
	}

	// Reactivate
	err = store.SetStatus("test", PolicyStatusActive)
	if err != nil {
		t.Fatalf("SetStatus failed: %v", err)
	}

	managed, _ = store.Get("test")
	if managed.Status != PolicyStatusActive {
		t.Errorf("expected status Active, got %s", managed.Status)
	}
}

func TestPolicyStore_VersionPruning(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{
		MaxVersions: 3,
	})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "v1", PolicyMetadata{})
	_, _ = store.Update(ctx, "test", "v2", nil)
	_, _ = store.Update(ctx, "test", "v3", nil)
	_, _ = store.Update(ctx, "test", "v4", nil)
	_, _ = store.Update(ctx, "test", "v5", nil)

	managed, _ := store.Get("test")
	if len(managed.Versions) != 3 {
		t.Errorf("expected 3 versions (after pruning), got %d", len(managed.Versions))
	}

	// Should have versions 3, 4, 5 (most recent)
	for _, v := range managed.Versions {
		if v.Version < 3 {
			t.Errorf("old version %d should have been pruned", v.Version)
		}
	}
}

func TestPolicyStore_ChangeHooks(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	var mu sync.Mutex
	events := make([]PolicyChangeEvent, 0)
	store.RegisterChangeHook(func(event PolicyChangeEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	})

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "v1", PolicyMetadata{})
	_, _ = store.Update(ctx, "test", "v2", nil)
	_ = store.SetStatus("test", PolicyStatusInactive)
	_ = store.Delete("test")

	// Wait for async hooks
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	eventCount := len(events)
	mu.Unlock()

	if eventCount < 4 {
		t.Fatalf("expected at least 4 events, got %d", eventCount)
	}

	// Check that we have all expected event types (order may vary due to async)
	mu.Lock()
	eventTypes := make(map[PolicyChangeType]int)
	for _, e := range events {
		eventTypes[e.Type]++
	}
	mu.Unlock()

	if eventTypes[PolicyChangeCreated] == 0 {
		t.Error("expected at least one Created event")
	}
	if eventTypes[PolicyChangeUpdated] == 0 {
		t.Error("expected at least one Updated event")
	}
	if eventTypes[PolicyChangeDeleted] == 0 {
		t.Error("expected at least one Deleted event")
	}
}

func TestPolicyStore_Notifications(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	go func() {
		_, _ = store.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{})
	}()

	select {
	case event := <-store.Notifications():
		if event.Type != PolicyChangeCreated {
			t.Errorf("expected Created event, got %s", event.Type)
		}
		if event.PolicyID != "test" {
			t.Errorf("expected policy ID 'test', got %s", event.PolicyID)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for notification")
	}
}

func TestPolicyStore_Persistence(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "policy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create store with persistence
	store1 := NewPolicyStore(PolicyStoreConfig{
		StorageDir: tempDir,
	})

	ctx := context.Background()
	_, _ = store1.Create(ctx, "test", PolicyTypeCEL, "true", PolicyMetadata{Name: "Test Policy"})
	_, _ = store1.Update(ctx, "test", "false", nil)

	// Create new store and load from disk
	store2 := NewPolicyStore(PolicyStoreConfig{
		StorageDir: tempDir,
	})
	if err := store2.LoadFromDisk(); err != nil {
		t.Fatalf("LoadFromDisk failed: %v", err)
	}

	managed, err := store2.Get("test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if managed.CurrentVersion != 2 {
		t.Errorf("expected version 2, got %d", managed.CurrentVersion)
	}
	if len(managed.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(managed.Versions))
	}
}

func TestPolicyStore_DiffVersions(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "test", PolicyTypeCEL, "content-v1", PolicyMetadata{Name: "v1", Description: "First"})
	_, _ = store.Update(ctx, "test", "content-v2", &PolicyMetadata{Name: "v2", Description: "Second"})

	diff, err := store.DiffVersions("test", 1, 2)
	if err != nil {
		t.Fatalf("DiffVersions failed: %v", err)
	}

	if diff.PolicyID != "test" {
		t.Errorf("expected policy ID 'test', got %s", diff.PolicyID)
	}
	if len(diff.Changes) < 2 {
		t.Errorf("expected at least 2 changes, got %d", len(diff.Changes))
	}

	// Check for content change
	foundContent := false
	foundName := false
	for _, change := range diff.Changes {
		if change.Field == "content" {
			foundContent = true
			if change.OldValue != "content-v1" {
				t.Errorf("expected old content 'content-v1', got %s", change.OldValue)
			}
		}
		if change.Field == "metadata.name" {
			foundName = true
			if change.NewValue != "v2" {
				t.Errorf("expected new name 'v2', got %s", change.NewValue)
			}
		}
	}
	if !foundContent {
		t.Error("expected content change in diff")
	}
	if !foundName {
		t.Error("expected name change in diff")
	}
}

func TestPolicyStore_ExportImport(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	_, _ = store.Create(ctx, "policy1", PolicyTypeCEL, "true", PolicyMetadata{Name: "Policy 1"})
	_, _ = store.Create(ctx, "policy2", PolicyTypeCEL, "false", PolicyMetadata{Name: "Policy 2"})

	// Export as YAML
	data, err := store.Export("yaml")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Create new store and import
	store2 := NewPolicyStore(PolicyStoreConfig{})
	if err := store2.Import(ctx, data, "yaml"); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	list := store2.List()
	if len(list) != 2 {
		t.Errorf("expected 2 policies after import, got %d", len(list))
	}

	// Export as JSON
	data, err = store.Export("json")
	if err != nil {
		t.Fatalf("Export JSON failed: %v", err)
	}

	store3 := NewPolicyStore(PolicyStoreConfig{})
	if err := store3.Import(ctx, data, "json"); err != nil {
		t.Fatalf("Import JSON failed: %v", err)
	}

	if len(store3.List()) != 2 {
		t.Error("expected 2 policies after JSON import")
	}
}

func TestPolicyStore_Validation(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{
		ValidationFn: func(policy *PolicyVersion) error {
			if policy.Content == "invalid" {
				return fmt.Errorf("invalid policy content")
			}
			return nil
		},
	})
	ctx := context.Background()

	// Valid policy
	_, err := store.Create(ctx, "valid", PolicyTypeCEL, "true", PolicyMetadata{})
	if err != nil {
		t.Errorf("expected valid policy to be created: %v", err)
	}

	// Invalid policy
	_, err = store.Create(ctx, "invalid", PolicyTypeCEL, "invalid", PolicyMetadata{})
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestHotReloader_ReloadFile(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "hotreload-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:    store,
		WatchDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}
	defer reloader.Stop()

	// Create policy file
	policyFile := filepath.Join(tempDir, "test-policy.yaml")
	content := []PolicyFileEntry{{
		ID:      "test",
		Type:    "cel",
		Content: "request.method == 'GET'",
		Enabled: true,
	}}
	data, _ := yaml.Marshal(content)
	if err := os.WriteFile(policyFile, data, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Reload file
	if err := reloader.Reload(policyFile); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Verify policy was loaded
	managed, err := store.Get("test")
	if err != nil {
		t.Fatalf("policy not found: %v", err)
	}
	if managed.CurrentVersion != 1 {
		t.Errorf("expected version 1, got %d", managed.CurrentVersion)
	}
}

func TestHotReloader_ReloadAll(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-all-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:    store,
		WatchDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}
	defer reloader.Stop()

	// Create multiple policy files
	for i := 1; i <= 3; i++ {
		policyFile := filepath.Join(tempDir, fmt.Sprintf("policy-%d.yaml", i))
		content := []PolicyFileEntry{{
			ID:      fmt.Sprintf("policy-%d", i),
			Type:    "cel",
			Content: "true",
			Enabled: true,
		}}
		data, _ := yaml.Marshal(content)
		os.WriteFile(policyFile, data, 0644)
	}

	// Reload all
	if err := reloader.ReloadAll(); err != nil {
		t.Fatalf("ReloadAll failed: %v", err)
	}

	list := store.List()
	if len(list) != 3 {
		t.Errorf("expected 3 policies, got %d", len(list))
	}
}

func TestHotReloader_WatchEvents(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-watch-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:         store,
		WatchDir:      tempDir,
		DebounceDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}

	reloader.Start()
	defer reloader.Stop()

	// Create policy file
	policyFile := filepath.Join(tempDir, "watched.yaml")
	content := []PolicyFileEntry{{
		ID:      "watched",
		Type:    "cel",
		Content: "true",
		Enabled: true,
	}}
	data, _ := yaml.Marshal(content)

	if err := os.WriteFile(policyFile, data, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Wait for debounce and processing
	time.Sleep(500 * time.Millisecond)

	// Verify policy was loaded
	_, err = store.Get("watched")
	if err != nil {
		t.Fatalf("policy not found after watch event: %v", err)
	}
}

func TestHotReloader_UpdateExistingPolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-update-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:    store,
		WatchDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}
	defer reloader.Stop()

	policyFile := filepath.Join(tempDir, "update-test.yaml")

	// Create initial policy
	content1 := []PolicyFileEntry{{
		ID:      "update-test",
		Type:    "cel",
		Content: "v1-content",
		Enabled: true,
	}}
	data1, _ := yaml.Marshal(content1)
	os.WriteFile(policyFile, data1, 0644)
	reloader.Reload(policyFile)

	// Update policy
	content2 := []PolicyFileEntry{{
		ID:      "update-test",
		Type:    "cel",
		Content: "v2-content",
		Enabled: true,
	}}
	data2, _ := yaml.Marshal(content2)
	os.WriteFile(policyFile, data2, 0644)
	reloader.Reload(policyFile)

	// Verify update
	managed, _ := store.Get("update-test")
	if managed.CurrentVersion != 2 {
		t.Errorf("expected version 2, got %d", managed.CurrentVersion)
	}

	current, _ := store.GetCurrentVersion("update-test")
	if current.Content != "v2-content" {
		t.Errorf("expected v2-content, got %s", current.Content)
	}
}

func TestHotReloader_JSONFormat(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-json-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:    store,
		WatchDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}
	defer reloader.Stop()

	// Create JSON policy file
	policyFile := filepath.Join(tempDir, "json-policy.json")
	content := `[{"id": "json-test", "type": "cel", "content": "true", "enabled": true}]`
	os.WriteFile(policyFile, []byte(content), 0644)

	if err := reloader.Reload(policyFile); err != nil {
		t.Fatalf("Reload JSON failed: %v", err)
	}

	_, err = store.Get("json-test")
	if err != nil {
		t.Fatalf("JSON policy not loaded: %v", err)
	}
}

func TestHotReloader_FileDeleted(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-delete-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:         store,
		WatchDir:      tempDir,
		DebounceDelay: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}

	reloader.Start()
	defer reloader.Stop()

	// Create policy file
	policyFile := filepath.Join(tempDir, "to-delete.yaml")
	content := []PolicyFileEntry{{
		ID:      "to-delete",
		Type:    "cel",
		Content: "true",
		Enabled: true,
	}}
	data, _ := yaml.Marshal(content)
	os.WriteFile(policyFile, data, 0644)

	// Load it
	reloader.Reload(policyFile)

	managed, _ := store.Get("to-delete")
	if managed.Status != PolicyStatusActive {
		t.Errorf("expected Active status, got %s", managed.Status)
	}

	// Delete the file
	os.Remove(policyFile)

	// Handle the deletion
	reloader.handleDeletedFile(policyFile)

	// Should be deactivated, not deleted
	managed, err = store.Get("to-delete")
	if err != nil {
		t.Fatalf("policy should still exist: %v", err)
	}
	if managed.Status != PolicyStatusInactive {
		t.Errorf("expected Inactive status after deletion, got %s", managed.Status)
	}
}

func TestHotReloader_ValidationFailure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hotreload-valid-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewPolicyStore(PolicyStoreConfig{})

	reloader, err := NewHotReloader(HotReloaderConfig{
		Store:    store,
		WatchDir: tempDir,
	})
	if err != nil {
		t.Fatalf("NewHotReloader failed: %v", err)
	}
	defer reloader.Stop()

	// Create invalid policy file (missing ID)
	policyFile := filepath.Join(tempDir, "invalid.yaml")
	content := []PolicyFileEntry{{
		ID:      "",
		Type:    "cel",
		Content: "true",
	}}
	data, _ := yaml.Marshal(content)
	os.WriteFile(policyFile, data, 0644)

	err = reloader.Reload(policyFile)
	// Should not fail catastrophically, just log error
	// The invalid policy should not be in the store

	// Verify invalid policy was not loaded
	_, err = store.Get("")
	if err == nil {
		t.Error("invalid policy should not have been loaded")
	}
}

func TestPolicyStore_ContentHash(t *testing.T) {
	store := NewPolicyStore(PolicyStoreConfig{})
	ctx := context.Background()

	v1, _ := store.Create(ctx, "hash-test", PolicyTypeCEL, "content-a", PolicyMetadata{})
	v2, _ := store.Update(ctx, "hash-test", "content-b", nil)

	if v1.ContentHash == "" {
		t.Error("v1 should have content hash")
	}
	if v2.ContentHash == "" {
		t.Error("v2 should have content hash")
	}
	if v1.ContentHash == v2.ContentHash {
		t.Error("different content should have different hashes")
	}

	// Same content should have same hash
	v3, _ := store.Update(ctx, "hash-test", "content-a", nil)
	if v3.ContentHash != v1.ContentHash {
		t.Error("same content should have same hash")
	}
}

