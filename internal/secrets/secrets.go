// Package secrets provides secret management with multiple backends.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Secret represents a secret value.
type Secret struct {
	// Key is the secret identifier.
	Key string `json:"key"`
	// Value is the secret value.
	Value string `json:"value"`
	// Version of the secret.
	Version int `json:"version"`
	// Metadata contains additional information.
	Metadata map[string]string `json:"metadata,omitempty"`
	// ExpiresAt is when the secret expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// CreatedAt is when the secret was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the secret was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// IsExpired checks if the secret has expired.
func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

// Provider is the interface for secret providers.
type Provider interface {
	// Name returns the provider name.
	Name() string
	// Get retrieves a secret by key.
	Get(ctx context.Context, key string) (*Secret, error)
	// List lists available secrets.
	List(ctx context.Context, prefix string) ([]string, error)
	// Set stores a secret.
	Set(ctx context.Context, secret *Secret) error
	// Delete removes a secret.
	Delete(ctx context.Context, key string) error
	// Watch watches for secret changes.
	Watch(ctx context.Context, key string, callback func(*Secret)) error
}

// Manager manages secrets across multiple providers.
type Manager struct {
	providers     map[string]Provider
	defaultProvider string
	cache         *secretCache
	encryptionKey []byte
	rotationRules map[string]*RotationRule
	mu            sync.RWMutex
	done          chan struct{}
}

// RotationRule defines when and how to rotate a secret.
type RotationRule struct {
	// Key is the secret key to rotate.
	Key string `json:"key"`
	// Interval is how often to rotate.
	Interval time.Duration `json:"interval"`
	// Generator generates new secret values.
	Generator SecretGenerator `json:"-"`
	// LastRotation tracks the last rotation time.
	LastRotation time.Time `json:"last_rotation"`
	// Enabled flag.
	Enabled bool `json:"enabled"`
}

// SecretGenerator generates secret values.
type SecretGenerator interface {
	Generate(ctx context.Context) (string, error)
}

// Config configures the secret manager.
type Config struct {
	// DefaultProvider is the default provider name.
	DefaultProvider string `json:"default_provider" yaml:"default_provider"`
	// CacheTTL is how long to cache secrets.
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
	// EncryptionKey for encrypting cached secrets (base64).
	EncryptionKey string `json:"encryption_key" yaml:"encryption_key"`
	// EnableRotation enables automatic secret rotation.
	EnableRotation bool `json:"enable_rotation" yaml:"enable_rotation"`
	// RotationCheckInterval is how often to check for rotation.
	RotationCheckInterval time.Duration `json:"rotation_check_interval" yaml:"rotation_check_interval"`
}

// NewManager creates a new secret manager.
func NewManager(config Config) (*Manager, error) {
	var encKey []byte
	if config.EncryptionKey != "" {
		var err error
		encKey, err = base64.StdEncoding.DecodeString(config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid encryption key: %w", err)
		}
		if len(encKey) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes (AES-256)")
		}
	}

	m := &Manager{
		providers:       make(map[string]Provider),
		defaultProvider: config.DefaultProvider,
		cache: &secretCache{
			entries: make(map[string]*cacheEntry),
			ttl:     config.CacheTTL,
		},
		encryptionKey: encKey,
		rotationRules: make(map[string]*RotationRule),
		done:          make(chan struct{}),
	}

	if config.EnableRotation {
		interval := config.RotationCheckInterval
		if interval == 0 {
			interval = time.Minute
		}
		go m.rotationLoop(interval)
	}

	return m, nil
}

// RegisterProvider registers a secret provider.
func (m *Manager) RegisterProvider(provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Name()] = provider
	if m.defaultProvider == "" {
		m.defaultProvider = provider.Name()
	}
}

// Get retrieves a secret.
func (m *Manager) Get(ctx context.Context, key string) (*Secret, error) {
	// Check cache first
	if secret := m.cache.get(key); secret != nil {
		return secret, nil
	}

	// Parse provider prefix (e.g., "vault:secret/data/api-key")
	providerName, secretKey := m.parseKey(key)

	m.mu.RLock()
	provider, ok := m.providers[providerName]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider not found: %s", providerName)
	}

	secret, err := provider.Get(ctx, secretKey)
	if err != nil {
		return nil, err
	}

	// Cache the secret
	m.cache.set(key, secret)

	return secret, nil
}

// Set stores a secret.
func (m *Manager) Set(ctx context.Context, key string, value string) error {
	providerName, secretKey := m.parseKey(key)

	m.mu.RLock()
	provider, ok := m.providers[providerName]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("provider not found: %s", providerName)
	}

	secret := &Secret{
		Key:       secretKey,
		Value:     value,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := provider.Set(ctx, secret); err != nil {
		return err
	}

	// Invalidate cache
	m.cache.delete(key)

	return nil
}

// Delete removes a secret.
func (m *Manager) Delete(ctx context.Context, key string) error {
	providerName, secretKey := m.parseKey(key)

	m.mu.RLock()
	provider, ok := m.providers[providerName]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("provider not found: %s", providerName)
	}

	if err := provider.Delete(ctx, secretKey); err != nil {
		return err
	}

	m.cache.delete(key)

	return nil
}

// AddRotationRule adds a secret rotation rule.
func (m *Manager) AddRotationRule(rule *RotationRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotationRules[rule.Key] = rule
}

// RemoveRotationRule removes a rotation rule.
func (m *Manager) RemoveRotationRule(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rotationRules, key)
}

func (m *Manager) parseKey(key string) (string, string) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return m.defaultProvider, key
}

func (m *Manager) rotationLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkRotations()
		case <-m.done:
			return
		}
	}
}

func (m *Manager) checkRotations() {
	m.mu.RLock()
	rules := make([]*RotationRule, 0, len(m.rotationRules))
	for _, rule := range m.rotationRules {
		rules = append(rules, rule)
	}
	m.mu.RUnlock()

	now := time.Now()
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if now.Sub(rule.LastRotation) >= rule.Interval {
			m.rotateSecret(rule)
		}
	}
}

func (m *Manager) rotateSecret(rule *RotationRule) {
	ctx := context.Background()

	if rule.Generator == nil {
		return
	}

	newValue, err := rule.Generator.Generate(ctx)
	if err != nil {
		return
	}

	if err := m.Set(ctx, rule.Key, newValue); err != nil {
		return
	}

	m.mu.Lock()
	rule.LastRotation = time.Now()
	m.mu.Unlock()
}

// Close shuts down the manager.
func (m *Manager) Close() error {
	close(m.done)
	return nil
}

// GetValue is a convenience method to get just the secret value.
func (m *Manager) GetValue(ctx context.Context, key string) (string, error) {
	secret, err := m.Get(ctx, key)
	if err != nil {
		return "", err
	}
	return secret.Value, nil
}

// MustGetValue panics if the secret cannot be retrieved.
func (m *Manager) MustGetValue(ctx context.Context, key string) string {
	value, err := m.GetValue(ctx, key)
	if err != nil {
		panic(err)
	}
	return value
}

// secretCache caches secrets in memory.
type secretCache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	mu      sync.RWMutex
}

type cacheEntry struct {
	secret    *Secret
	expiresAt time.Time
}

func (c *secretCache) get(key string) *Secret {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.secret
}

func (c *secretCache) set(key string, secret *Secret) {
	if c.ttl == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		secret:    secret,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *secretCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// VaultProvider implements HashiCorp Vault integration.
type VaultProvider struct {
	address   string
	token     string
	namespace string
	client    *http.Client
	mount     string
}

// VaultConfig configures the Vault provider.
type VaultConfig struct {
	Address   string `json:"address" yaml:"address"`
	Token     string `json:"token" yaml:"token"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Mount     string `json:"mount" yaml:"mount"`
}

// NewVaultProvider creates a new Vault provider.
func NewVaultProvider(config VaultConfig) *VaultProvider {
	if config.Mount == "" {
		config.Mount = "secret"
	}

	return &VaultProvider{
		address:   config.Address,
		token:     config.Token,
		namespace: config.Namespace,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		mount: config.Mount,
	}
}

func (p *VaultProvider) Name() string {
	return "vault"
}

func (p *VaultProvider) Get(ctx context.Context, key string) (*Secret, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.address, p.mount, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault error (%d): %s", resp.StatusCode, string(body))
	}

	var vaultResp struct {
		Data struct {
			Data     map[string]interface{} `json:"data"`
			Metadata struct {
				Version   int       `json:"version"`
				CreatedAt time.Time `json:"created_time"`
			} `json:"metadata"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	// Extract the value (assume single "value" key or first key)
	var value string
	if v, ok := vaultResp.Data.Data["value"]; ok {
		value = fmt.Sprintf("%v", v)
	} else {
		// Return all data as JSON
		data, _ := json.Marshal(vaultResp.Data.Data)
		value = string(data)
	}

	metadata := make(map[string]string)
	for k, v := range vaultResp.Data.Data {
		if k != "value" {
			metadata[k] = fmt.Sprintf("%v", v)
		}
	}

	return &Secret{
		Key:       key,
		Value:     value,
		Version:   vaultResp.Data.Metadata.Version,
		Metadata:  metadata,
		CreatedAt: vaultResp.Data.Metadata.CreatedAt,
		UpdatedAt: vaultResp.Data.Metadata.CreatedAt,
	}, nil
}

func (p *VaultProvider) List(ctx context.Context, prefix string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", p.address, p.mount, prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"?list=true", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var listResp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}

	return listResp.Data.Keys, nil
}

func (p *VaultProvider) Set(ctx context.Context, secret *Secret) error {
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.address, p.mount, secret.Key)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"value": secret.Value,
		},
	}

	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("X-Vault-Token", p.token)
	req.Header.Set("Content-Type", "application/json")
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (%d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (p *VaultProvider) Delete(ctx context.Context, key string) error {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", p.address, p.mount, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (p *VaultProvider) Watch(ctx context.Context, key string, callback func(*Secret)) error {
	// Vault doesn't have native watch, poll instead
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var lastVersion int

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			secret, err := p.Get(ctx, key)
			if err != nil {
				continue
			}
			if secret.Version != lastVersion {
				lastVersion = secret.Version
				callback(secret)
			}
		}
	}
}

// EnvProvider reads secrets from environment variables.
type EnvProvider struct {
	prefix string
}

// NewEnvProvider creates an environment variable provider.
func NewEnvProvider(prefix string) *EnvProvider {
	return &EnvProvider{prefix: prefix}
}

func (p *EnvProvider) Name() string {
	return "env"
}

func (p *EnvProvider) Get(ctx context.Context, key string) (*Secret, error) {
	envKey := p.prefix + strings.ToUpper(strings.ReplaceAll(key, "/", "_"))
	value := os.Getenv(envKey)
	if value == "" {
		return nil, fmt.Errorf("environment variable not found: %s", envKey)
	}

	return &Secret{
		Key:       key,
		Value:     value,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (p *EnvProvider) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	fullPrefix := p.prefix + strings.ToUpper(strings.ReplaceAll(prefix, "/", "_"))

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if strings.HasPrefix(parts[0], fullPrefix) {
			keys = append(keys, parts[0])
		}
	}

	return keys, nil
}

func (p *EnvProvider) Set(ctx context.Context, secret *Secret) error {
	envKey := p.prefix + strings.ToUpper(strings.ReplaceAll(secret.Key, "/", "_"))
	return os.Setenv(envKey, secret.Value)
}

func (p *EnvProvider) Delete(ctx context.Context, key string) error {
	envKey := p.prefix + strings.ToUpper(strings.ReplaceAll(key, "/", "_"))
	return os.Unsetenv(envKey)
}

func (p *EnvProvider) Watch(ctx context.Context, key string, callback func(*Secret)) error {
	return fmt.Errorf("watch not supported for environment provider")
}

// FileProvider reads secrets from files.
type FileProvider struct {
	baseDir string
}

// NewFileProvider creates a file-based provider.
func NewFileProvider(baseDir string) *FileProvider {
	return &FileProvider{baseDir: baseDir}
}

func (p *FileProvider) Name() string {
	return "file"
}

// validatePath ensures the path doesn't escape the base directory (path traversal protection).
func (p *FileProvider) validatePath(key string) (string, error) {
	// Clean the base directory and join with key
	cleanBase := filepath.Clean(p.baseDir)
	path := filepath.Join(cleanBase, key)

	// Clean the resulting path and verify it's still within base directory
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) && cleanPath != cleanBase {
		return "", fmt.Errorf("path traversal attempt detected: %s", key)
	}

	return cleanPath, nil
}

func (p *FileProvider) Get(ctx context.Context, key string) (*Secret, error) {
	path, err := p.validatePath(key)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("secret not found: %s", key)
		}
		return nil, err
	}

	info, _ := os.Stat(path)

	return &Secret{
		Key:       key,
		Value:     strings.TrimSpace(string(data)),
		CreatedAt: info.ModTime(),
		UpdatedAt: info.ModTime(),
	}, nil
}

func (p *FileProvider) List(ctx context.Context, prefix string) ([]string, error) {
	searchDir, err := p.validatePath(prefix)
	if err != nil {
		return nil, err
	}

	var keys []string
	err = filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(p.baseDir, path)
			keys = append(keys, rel)
		}
		return nil
	})

	return keys, err
}

func (p *FileProvider) Set(ctx context.Context, secret *Secret) error {
	path, err := p.validatePath(secret.Key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(secret.Value), 0600)
}

func (p *FileProvider) Delete(ctx context.Context, key string) error {
	path, err := p.validatePath(key)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func (p *FileProvider) Watch(ctx context.Context, key string, callback func(*Secret)) error {
	path, err := p.validatePath(key)
	if err != nil {
		return err
	}
	var lastMod time.Time

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastMod) {
				lastMod = info.ModTime()
				secret, err := p.Get(ctx, key)
				if err == nil {
					callback(secret)
				}
			}
		}
	}
}

// StaticProvider provides static secrets (useful for testing).
type StaticProvider struct {
	secrets map[string]*Secret
	mu      sync.RWMutex
}

// NewStaticProvider creates a static provider.
func NewStaticProvider(secrets map[string]string) *StaticProvider {
	p := &StaticProvider{
		secrets: make(map[string]*Secret),
	}

	for k, v := range secrets {
		p.secrets[k] = &Secret{
			Key:       k,
			Value:     v,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}

	return p
}

func (p *StaticProvider) Name() string {
	return "static"
}

func (p *StaticProvider) Get(ctx context.Context, key string) (*Secret, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	secret, ok := p.secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	return secret, nil
}

func (p *StaticProvider) List(ctx context.Context, prefix string) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var keys []string
	for k := range p.secrets {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}

	return keys, nil
}

func (p *StaticProvider) Set(ctx context.Context, secret *Secret) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.secrets[secret.Key] = secret
	return nil
}

func (p *StaticProvider) Delete(ctx context.Context, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.secrets, key)
	return nil
}

func (p *StaticProvider) Watch(ctx context.Context, key string, callback func(*Secret)) error {
	return fmt.Errorf("watch not supported for static provider")
}

// Encryption utilities

// Encrypt encrypts data with AES-256-GCM.
func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts AES-256-GCM encrypted data.
func Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Secret generators

// RandomStringGenerator generates random strings.
type RandomStringGenerator struct {
	Length  int
	Charset string
}

func (g *RandomStringGenerator) Generate(ctx context.Context) (string, error) {
	charset := g.Charset
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	}

	length := g.Length
	if length == 0 {
		length = 32
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b), nil
}

// UUIDGenerator generates UUIDs.
type UUIDGenerator struct{}

func (g *UUIDGenerator) Generate(ctx context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
