package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStaticProvider(t *testing.T) {
	secrets := map[string]string{
		"api-key":      "secret123",
		"db-password":  "dbpass456",
		"app/config":   "configvalue",
	}

	p := NewStaticProvider(secrets)

	if p.Name() != "static" {
		t.Errorf("expected name 'static', got %s", p.Name())
	}

	ctx := context.Background()

	// Get existing secret
	secret, err := p.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "secret123" {
		t.Errorf("expected value 'secret123', got %s", secret.Value)
	}

	// Get non-existing secret
	_, err = p.Get(ctx, "non-existing")
	if err == nil {
		t.Error("expected error for non-existing secret")
	}

	// List secrets
	keys, err := p.List(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// List with prefix
	keys, err = p.List(ctx, "app/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key with prefix 'app/', got %d", len(keys))
	}

	// Set secret
	newSecret := &Secret{
		Key:   "new-secret",
		Value: "newvalue",
	}
	err = p.Set(ctx, newSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secret, err = p.Get(ctx, "new-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "newvalue" {
		t.Errorf("expected 'newvalue', got %s", secret.Value)
	}

	// Delete secret
	err = p.Delete(ctx, "new-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = p.Get(ctx, "new-secret")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestEnvProvider(t *testing.T) {
	p := NewEnvProvider("TEST_")

	ctx := context.Background()

	// Set an environment variable
	os.Setenv("TEST_API_KEY", "envvalue")
	defer os.Unsetenv("TEST_API_KEY")

	if p.Name() != "env" {
		t.Errorf("expected name 'env', got %s", p.Name())
	}

	// Get existing secret
	secret, err := p.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "envvalue" {
		t.Errorf("expected 'envvalue', got %s", secret.Value)
	}

	// Get non-existing secret
	_, err = p.Get(ctx, "non_existing")
	if err == nil {
		t.Error("expected error for non-existing env var")
	}

	// Set secret
	err = p.Set(ctx, &Secret{Key: "new_key", Value: "newval"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if os.Getenv("TEST_NEW_KEY") != "newval" {
		t.Error("environment variable not set correctly")
	}
	os.Unsetenv("TEST_NEW_KEY")
}

func TestFileProvider(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	p := NewFileProvider(tmpDir)

	if p.Name() != "file" {
		t.Errorf("expected name 'file', got %s", p.Name())
	}

	ctx := context.Background()

	// Create a secret file
	secretPath := filepath.Join(tmpDir, "api-key")
	os.WriteFile(secretPath, []byte("filevalue"), 0600)

	// Get existing secret
	secret, err := p.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "filevalue" {
		t.Errorf("expected 'filevalue', got %s", secret.Value)
	}

	// Get non-existing secret
	_, err = p.Get(ctx, "non-existing")
	if err == nil {
		t.Error("expected error for non-existing file")
	}

	// Set secret
	err = p.Set(ctx, &Secret{Key: "subdir/new-key", Value: "newval"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secret, err = p.Get(ctx, "subdir/new-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "newval" {
		t.Errorf("expected 'newval', got %s", secret.Value)
	}

	// List secrets
	keys, err := p.List(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) < 1 {
		t.Error("expected at least 1 key")
	}

	// Delete secret
	err = p.Delete(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = p.Get(ctx, "api-key")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestVaultProvider(t *testing.T) {
	// Create mock Vault server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Vault-Token")
		if token != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/api-key":
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"value": "vaultvalue",
					},
					"metadata": map[string]interface{}{
						"version":      1,
						"created_time": time.Now().Format(time.RFC3339),
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/not-found":
			w.WriteHeader(http.StatusNotFound)

		case r.Method == http.MethodPost && r.URL.Path == "/v1/secret/data/new-key":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodDelete && r.URL.Path == "/v1/secret/metadata/api-key":
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := NewVaultProvider(VaultConfig{
		Address: server.URL,
		Token:   "test-token",
	})

	if p.Name() != "vault" {
		t.Errorf("expected name 'vault', got %s", p.Name())
	}

	ctx := context.Background()

	// Get existing secret
	secret, err := p.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "vaultvalue" {
		t.Errorf("expected 'vaultvalue', got %s", secret.Value)
	}

	// Get non-existing secret
	_, err = p.Get(ctx, "not-found")
	if err == nil {
		t.Error("expected error for non-existing secret")
	}

	// Set secret
	err = p.Set(ctx, &Secret{Key: "new-key", Value: "newval"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Delete secret
	err = p.Delete(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManager(t *testing.T) {
	config := Config{
		DefaultProvider: "static",
		CacheTTL:        time.Minute,
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer m.Close()

	// Register static provider
	p := NewStaticProvider(map[string]string{
		"api-key": "secret123",
	})
	m.RegisterProvider(p)

	ctx := context.Background()

	// Get secret
	secret, err := m.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "secret123" {
		t.Errorf("expected 'secret123', got %s", secret.Value)
	}

	// Get from cache (second call)
	secret, err = m.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "secret123" {
		t.Errorf("expected cached value 'secret123', got %s", secret.Value)
	}

	// GetValue convenience method
	value, err := m.GetValue(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "secret123" {
		t.Errorf("expected 'secret123', got %s", value)
	}

	// Set secret
	err = m.Set(ctx, "new-key", "newvalue")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secret, err = m.Get(ctx, "new-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "newvalue" {
		t.Errorf("expected 'newvalue', got %s", secret.Value)
	}

	// Delete secret
	err = m.Delete(ctx, "new-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerWithProviderPrefix(t *testing.T) {
	config := Config{
		DefaultProvider: "static",
		CacheTTL:        time.Minute,
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer m.Close()

	// Register multiple providers
	staticProvider := NewStaticProvider(map[string]string{
		"api-key": "static-secret",
	})
	m.RegisterProvider(staticProvider)

	envProvider := NewEnvProvider("TEST_MGR_")
	m.RegisterProvider(envProvider)

	os.Setenv("TEST_MGR_API_KEY", "env-secret")
	defer os.Unsetenv("TEST_MGR_API_KEY")

	ctx := context.Background()

	// Get from default provider
	secret, err := m.Get(ctx, "api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "static-secret" {
		t.Errorf("expected 'static-secret', got %s", secret.Value)
	}

	// Get from specific provider
	secret, err = m.Get(ctx, "env:api_key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret.Value != "env-secret" {
		t.Errorf("expected 'env-secret', got %s", secret.Value)
	}
}

func TestSecretCache(t *testing.T) {
	cache := &secretCache{
		entries: make(map[string]*cacheEntry),
		ttl:     100 * time.Millisecond,
	}

	secret := &Secret{
		Key:   "test",
		Value: "cached",
	}

	// Set and get
	cache.set("test", secret)
	cached := cache.get("test")
	if cached == nil {
		t.Fatal("expected cached secret")
	}
	if cached.Value != "cached" {
		t.Errorf("expected 'cached', got %s", cached.Value)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)
	cached = cache.get("test")
	if cached != nil {
		t.Error("expected cache to expire")
	}

	// Delete
	cache.set("test2", secret)
	cache.delete("test2")
	cached = cache.get("test2")
	if cached != nil {
		t.Error("expected nil after delete")
	}
}

func TestSecretExpiration(t *testing.T) {
	expiry := time.Now().Add(-time.Hour)
	secret := &Secret{
		Key:       "expired",
		ExpiresAt: &expiry,
	}

	if !secret.IsExpired() {
		t.Error("expected secret to be expired")
	}

	future := time.Now().Add(time.Hour)
	secret.ExpiresAt = &future
	if secret.IsExpired() {
		t.Error("expected secret to not be expired")
	}

	secret.ExpiresAt = nil
	if secret.IsExpired() {
		t.Error("expected secret with nil expiry to not be expired")
	}
}

func TestRandomStringGenerator(t *testing.T) {
	gen := &RandomStringGenerator{
		Length:  16,
		Charset: "abc123",
	}

	ctx := context.Background()

	value1, err := gen.Generate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(value1) != 16 {
		t.Errorf("expected length 16, got %d", len(value1))
	}

	value2, err := gen.Generate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value1 == value2 {
		t.Error("expected different values")
	}

	// Verify charset
	for _, c := range value1 {
		if c != 'a' && c != 'b' && c != 'c' && c != '1' && c != '2' && c != '3' {
			t.Errorf("unexpected character: %c", c)
		}
	}
}

func TestUUIDGenerator(t *testing.T) {
	gen := &UUIDGenerator{}

	ctx := context.Background()

	uuid1, err := gen.Generate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if len(uuid1) != 36 {
		t.Errorf("expected length 36, got %d", len(uuid1))
	}

	if uuid1[8] != '-' || uuid1[13] != '-' || uuid1[18] != '-' || uuid1[23] != '-' {
		t.Error("invalid UUID format")
	}

	uuid2, err := gen.Generate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if uuid1 == uuid2 {
		t.Error("expected different UUIDs")
	}
}

func TestEncryption(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := []byte("secret data to encrypt")

	// Encrypt
	encrypted, err := Encrypt(data, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if string(encrypted) == string(data) {
		t.Error("encrypted data should differ from original")
	}

	// Decrypt
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(data) {
		t.Errorf("expected '%s', got '%s'", string(data), string(decrypted))
	}

	// Decryption with wrong key should fail
	wrongKey := make([]byte, 32)
	_, err = Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestRotationRule(t *testing.T) {
	config := Config{
		DefaultProvider:       "static",
		EnableRotation:        true,
		RotationCheckInterval: 50 * time.Millisecond,
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer m.Close()

	p := NewStaticProvider(map[string]string{
		"rotating-secret": "initial",
	})
	m.RegisterProvider(p)

	// Add rotation rule
	m.AddRotationRule(&RotationRule{
		Key:          "rotating-secret",
		Interval:     50 * time.Millisecond,
		Enabled:      true,
		LastRotation: time.Now().Add(-time.Hour), // Force immediate rotation
		Generator: &RandomStringGenerator{
			Length:  8,
			Charset: "abcdef",
		},
	})

	// Wait for rotation
	time.Sleep(150 * time.Millisecond)

	ctx := context.Background()
	secret, err := m.Get(ctx, "rotating-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if secret.Value == "initial" {
		t.Error("expected secret to be rotated")
	}

	// Remove rotation rule
	m.RemoveRotationRule("rotating-secret")
}

func TestManagerEncryptionKey(t *testing.T) {
	// Valid encryption key (32 bytes base64)
	validKey := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

	config := Config{
		EncryptionKey: validKey,
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m.Close()

	// Invalid encryption key
	config.EncryptionKey = "not-valid-base64"
	_, err = NewManager(config)
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Wrong key length
	config.EncryptionKey = "c2hvcnQ=" // "short" in base64
	_, err = NewManager(config)
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestProviderNotFound(t *testing.T) {
	config := Config{
		DefaultProvider: "nonexistent",
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer m.Close()

	ctx := context.Background()

	_, err = m.Get(ctx, "any-key")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

func TestEndpointHostPort(t *testing.T) {
	secret := &Secret{
		Key:   "test",
		Value: "value",
	}

	// Test that Secret struct is created properly
	if secret.Key != "test" || secret.Value != "value" {
		t.Error("secret fields not set correctly")
	}
}

func TestMustGetValuePanic(t *testing.T) {
	config := Config{
		DefaultProvider: "static",
	}

	m, err := NewManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer m.Close()

	p := NewStaticProvider(map[string]string{})
	m.RegisterProvider(p)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for missing secret")
		}
	}()

	ctx := context.Background()
	m.MustGetValue(ctx, "nonexistent")
}
