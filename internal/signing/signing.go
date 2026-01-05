// Package signing provides request signing and verification using HMAC and AWS SigV4.
package signing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrMissingSignature   = errors.New("missing signature")
	ErrExpiredSignature   = errors.New("signature has expired")
	ErrMissingCredentials = errors.New("missing credentials")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrReplayDetected     = errors.New("replay attack detected")
	ErrKeyNotFound        = errors.New("signing key not found")
)

// sanitizeHeaderValue removes CRLF characters from header values to prevent injection attacks.
func sanitizeHeaderValue(value string) string {
	// Replace CR and LF with spaces to prevent header injection
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

// SigningMethod represents the signature algorithm.
type SigningMethod string

const (
	// MethodHMACSHA256 uses HMAC-SHA256.
	MethodHMACSHA256 SigningMethod = "HMAC-SHA256"
	// MethodAWSSigV4 uses AWS Signature Version 4.
	MethodAWSSigV4 SigningMethod = "AWS4-HMAC-SHA256"
)

// Credentials holds signing credentials.
type Credentials struct {
	// ID is the access key ID or credential identifier.
	ID string `json:"id"`
	// Secret is the secret key.
	Secret string `json:"secret"`
	// Description of these credentials.
	Description string `json:"description,omitempty"`
	// Enabled indicates if these credentials are active.
	Enabled bool `json:"enabled"`
	// ExpiresAt is when these credentials expire.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// CreatedAt is when credentials were created.
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired returns true if the credentials have expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// KeyStore manages signing keys.
type KeyStore interface {
	// GetKey retrieves credentials by ID.
	GetKey(id string) (*Credentials, error)
	// AddKey adds new credentials.
	AddKey(creds *Credentials) error
	// RemoveKey removes credentials by ID.
	RemoveKey(id string) error
	// ListKeys returns all credential IDs.
	ListKeys() []string
}

// MemoryKeyStore is an in-memory key store.
type MemoryKeyStore struct {
	keys map[string]*Credentials
	mu   sync.RWMutex
}

// NewMemoryKeyStore creates a new in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]*Credentials),
	}
}

// GetKey retrieves credentials by ID.
func (s *MemoryKeyStore) GetKey(id string) (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, exists := s.keys[id]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return creds, nil
}

// AddKey adds new credentials.
func (s *MemoryKeyStore) AddKey(creds *Credentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	creds.CreatedAt = time.Now()
	s.keys[creds.ID] = creds

	return nil
}

// RemoveKey removes credentials by ID.
func (s *MemoryKeyStore) RemoveKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[id]; !exists {
		return ErrKeyNotFound
	}

	delete(s.keys, id)
	return nil
}

// ListKeys returns all credential IDs.
func (s *MemoryKeyStore) ListKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.keys))
	for k := range s.keys {
		keys = append(keys, k)
	}

	return keys
}

// HMACSigner signs requests using HMAC-SHA256.
type HMACSigner struct {
	keyStore  KeyStore
	keyID     string
	logger    *slog.Logger
	timestamp func() time.Time
}

// HMACSignerConfig configures the HMAC signer.
type HMACSignerConfig struct {
	// KeyStore for retrieving signing keys.
	KeyStore KeyStore
	// KeyID to use for signing.
	KeyID string
	// Logger for signing events.
	Logger *slog.Logger
}

// NewHMACSigner creates a new HMAC signer.
func NewHMACSigner(cfg HMACSignerConfig) *HMACSigner {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &HMACSigner{
		keyStore:  cfg.KeyStore,
		keyID:     cfg.KeyID,
		logger:    cfg.Logger,
		timestamp: time.Now,
	}
}

// Sign signs the request.
func (s *HMACSigner) Sign(r *http.Request) error {
	creds, err := s.keyStore.GetKey(s.keyID)
	if err != nil {
		return fmt.Errorf("getting key: %w", err)
	}

	if !creds.Enabled {
		return ErrInvalidCredentials
	}

	if creds.IsExpired() {
		return ErrExpiredSignature
	}

	// Read body
	body, err := readBody(r)
	if err != nil {
		return err
	}

	timestamp := s.timestamp().UTC().Format(time.RFC3339)

	// Create string to sign
	stringToSign := createHMACStringToSign(r.Method, r.URL, r.Header, body, timestamp)

	// Create signature
	signature := computeHMAC([]byte(stringToSign), []byte(creds.Secret))

	// Set headers
	r.Header.Set("X-Signature-Timestamp", timestamp)
	r.Header.Set("X-Signature-KeyID", s.keyID)
	r.Header.Set("X-Signature", signature)

	return nil
}

func createHMACStringToSign(method string, u *url.URL, headers http.Header, body []byte, timestamp string) string {
	var sb strings.Builder

	sb.WriteString(method)
	sb.WriteString("\n")
	sb.WriteString(u.Path)
	sb.WriteString("\n")
	sb.WriteString(u.RawQuery)
	sb.WriteString("\n")
	sb.WriteString(timestamp)
	sb.WriteString("\n")
	sb.WriteString(headers.Get("Content-Type"))
	sb.WriteString("\n")

	// Hash the body
	bodyHash := sha256.Sum256(body)
	sb.WriteString(hex.EncodeToString(bodyHash[:]))

	return sb.String()
}

func computeHMAC(message, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACVerifier verifies HMAC signatures.
type HMACVerifier struct {
	keyStore      KeyStore
	logger        *slog.Logger
	maxClockSkew  time.Duration
	nonceStore    NonceStore
	timestamp     func() time.Time
}

// HMACVerifierConfig configures the HMAC verifier.
type HMACVerifierConfig struct {
	// KeyStore for retrieving signing keys.
	KeyStore KeyStore
	// Logger for verification events.
	Logger *slog.Logger
	// MaxClockSkew is the maximum allowed time difference.
	MaxClockSkew time.Duration
	// NonceStore for replay protection.
	NonceStore NonceStore
}

// NewHMACVerifier creates a new HMAC verifier.
func NewHMACVerifier(cfg HMACVerifierConfig) *HMACVerifier {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}

	return &HMACVerifier{
		keyStore:     cfg.KeyStore,
		logger:       cfg.Logger,
		maxClockSkew: cfg.MaxClockSkew,
		nonceStore:   cfg.NonceStore,
		timestamp:    time.Now,
	}
}

// Verify verifies the request signature.
func (v *HMACVerifier) Verify(r *http.Request) error {
	signature := r.Header.Get("X-Signature")
	if signature == "" {
		return ErrMissingSignature
	}

	timestamp := r.Header.Get("X-Signature-Timestamp")
	if timestamp == "" {
		return ErrMissingSignature
	}

	keyID := r.Header.Get("X-Signature-KeyID")
	if keyID == "" {
		return ErrMissingCredentials
	}

	// Parse timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	// Check clock skew
	now := v.timestamp()
	if ts.Before(now.Add(-v.maxClockSkew)) || ts.After(now.Add(v.maxClockSkew)) {
		return ErrExpiredSignature
	}

	// Check for replay
	if v.nonceStore != nil {
		nonce := r.Header.Get("X-Signature-Nonce")
		if nonce != "" {
			if v.nonceStore.HasSeen(nonce) {
				return ErrReplayDetected
			}
			v.nonceStore.Mark(nonce, v.maxClockSkew*2)
		}
	}

	// Get credentials
	creds, err := v.keyStore.GetKey(keyID)
	if err != nil {
		return ErrInvalidCredentials
	}

	if !creds.Enabled {
		return ErrInvalidCredentials
	}

	if creds.IsExpired() {
		return ErrInvalidCredentials
	}

	// Read body
	body, err := readBody(r)
	if err != nil {
		return err
	}

	// Recreate string to sign
	stringToSign := createHMACStringToSign(r.Method, r.URL, r.Header, body, timestamp)

	// Compute expected signature
	expected := computeHMAC([]byte(stringToSign), []byte(creds.Secret))

	// Compare signatures
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrInvalidSignature
	}

	return nil
}

// NonceStore tracks used nonces for replay protection.
type NonceStore interface {
	// HasSeen returns true if the nonce was already used.
	HasSeen(nonce string) bool
	// Mark records a nonce with expiration.
	Mark(nonce string, ttl time.Duration)
}

// MemoryNonceStore is an in-memory nonce store.
type MemoryNonceStore struct {
	nonces map[string]time.Time
	mu     sync.RWMutex
}

// NewMemoryNonceStore creates a new memory nonce store.
func NewMemoryNonceStore() *MemoryNonceStore {
	store := &MemoryNonceStore{
		nonces: make(map[string]time.Time),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// HasSeen returns true if the nonce was already used.
func (s *MemoryNonceStore) HasSeen(nonce string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiry, exists := s.nonces[nonce]
	if !exists {
		return false
	}

	return time.Now().Before(expiry)
}

// Mark records a nonce with expiration.
func (s *MemoryNonceStore) Mark(nonce string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nonces[nonce] = time.Now().Add(ttl)
}

func (s *MemoryNonceStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for nonce, expiry := range s.nonces {
			if now.After(expiry) {
				delete(s.nonces, nonce)
			}
		}
		s.mu.Unlock()
	}
}

// AWS4Signer signs requests using AWS Signature Version 4.
type AWS4Signer struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	service         string
	logger          *slog.Logger
	timestamp       func() time.Time
}

// AWS4SignerConfig configures the AWS4 signer.
type AWS4SignerConfig struct {
	// AccessKeyID is the AWS access key ID.
	AccessKeyID string
	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string
	// Region is the AWS region.
	Region string
	// Service is the AWS service name.
	Service string
	// Logger for signing events.
	Logger *slog.Logger
}

// NewAWS4Signer creates a new AWS SigV4 signer.
func NewAWS4Signer(cfg AWS4SignerConfig) *AWS4Signer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &AWS4Signer{
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		region:          cfg.Region,
		service:         cfg.Service,
		logger:          cfg.Logger,
		timestamp:       time.Now,
	}
}

// Sign signs the request using AWS Signature Version 4.
func (s *AWS4Signer) Sign(r *http.Request) error {
	now := s.timestamp().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Read body
	body, err := readBody(r)
	if err != nil {
		return err
	}

	// Calculate payload hash
	payloadHash := sha256.Sum256(body)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	// Set required headers
	if r.Header.Get("Host") == "" {
		r.Header.Set("Host", r.Host)
	}
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadHashHex)

	// Create canonical request
	canonicalRequest, signedHeaders := s.createCanonicalRequest(r, payloadHashHex)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, s.region, s.service)
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hex.EncodeToString(canonicalRequestHash[:]),
	)

	// Calculate signing key
	signingKey := s.deriveSigningKey(dateStamp)

	// Calculate signature
	signature := computeHMAC([]byte(stringToSign), signingKey)

	// Create authorization header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)

	r.Header.Set("Authorization", authHeader)

	return nil
}

func (s *AWS4Signer) createCanonicalRequest(r *http.Request, payloadHash string) (string, string) {
	// Canonical URI
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string (sorted)
	params := r.URL.Query()
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalQueryString strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalQueryString.WriteString("&")
		}
		canonicalQueryString.WriteString(url.QueryEscape(k))
		canonicalQueryString.WriteString("=")
		canonicalQueryString.WriteString(url.QueryEscape(params.Get(k)))
	}

	// Canonical headers (sorted, lowercase)
	headerKeys := make([]string, 0)
	for k := range r.Header {
		headerKeys = append(headerKeys, strings.ToLower(k))
	}
	sort.Strings(headerKeys)

	var canonicalHeaders strings.Builder
	var signedHeaders []string
	for _, k := range headerKeys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteString(":")
		// Sanitize header value to prevent CRLF injection
		headerValue := sanitizeHeaderValue(strings.TrimSpace(r.Header.Get(k)))
		canonicalHeaders.WriteString(headerValue)
		canonicalHeaders.WriteString("\n")
		signedHeaders = append(signedHeaders, k)
	}

	signedHeadersStr := strings.Join(signedHeaders, ";")

	// Construct canonical request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		r.Method,
		canonicalURI,
		canonicalQueryString.String(),
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	)

	return canonicalRequest, signedHeadersStr
}

func (s *AWS4Signer) deriveSigningKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte(s.service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// AWS4Verifier verifies AWS Signature Version 4 signatures.
type AWS4Verifier struct {
	keyStore     KeyStore
	region       string
	service      string
	logger       *slog.Logger
	maxClockSkew time.Duration
	timestamp    func() time.Time
}

// AWS4VerifierConfig configures the AWS4 verifier.
type AWS4VerifierConfig struct {
	// KeyStore for retrieving signing keys.
	KeyStore KeyStore
	// Region is the AWS region.
	Region string
	// Service is the AWS service name.
	Service string
	// Logger for verification events.
	Logger *slog.Logger
	// MaxClockSkew is the maximum allowed time difference.
	MaxClockSkew time.Duration
}

// NewAWS4Verifier creates a new AWS SigV4 verifier.
func NewAWS4Verifier(cfg AWS4VerifierConfig) *AWS4Verifier {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}

	return &AWS4Verifier{
		keyStore:     cfg.KeyStore,
		region:       cfg.Region,
		service:      cfg.Service,
		logger:       cfg.Logger,
		maxClockSkew: cfg.MaxClockSkew,
		timestamp:    time.Now,
	}
}

// Verify verifies the AWS SigV4 signature.
func (v *AWS4Verifier) Verify(r *http.Request) error {
	// Parse Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ErrMissingSignature
	}

	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		return ErrInvalidSignature
	}

	// Parse auth header components
	credential, signedHeaders, signature, err := parseAWS4AuthHeader(authHeader)
	if err != nil {
		return err
	}

	// Parse credential
	accessKeyID, dateStamp, region, service, err := parseCredential(credential)
	if err != nil {
		return err
	}

	// Validate region and service
	if region != v.region || service != v.service {
		return ErrInvalidCredentials
	}

	// Get date from header
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return ErrMissingSignature
	}

	// Parse and validate timestamp
	ts, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}

	now := v.timestamp()
	if ts.Before(now.Add(-v.maxClockSkew)) || ts.After(now.Add(v.maxClockSkew)) {
		return ErrExpiredSignature
	}

	// Get credentials
	creds, err := v.keyStore.GetKey(accessKeyID)
	if err != nil {
		return ErrInvalidCredentials
	}

	if !creds.Enabled {
		return ErrInvalidCredentials
	}

	// Read body
	body, err := readBody(r)
	if err != nil {
		return err
	}

	// Calculate payload hash
	payloadHash := sha256.Sum256(body)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	// Create canonical request
	canonicalRequest := createAWS4CanonicalRequest(r, signedHeaders, payloadHashHex)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hex.EncodeToString(canonicalRequestHash[:]),
	)

	// Derive signing key
	kDate := hmacSHA256([]byte("AWS4"+creds.Secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// Calculate expected signature
	expected := computeHMAC([]byte(stringToSign), kSigning)

	// Compare signatures
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrInvalidSignature
	}

	return nil
}

func parseAWS4AuthHeader(header string) (credential, signedHeaders, signature string, err error) {
	// AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", "", "", ErrInvalidSignature
	}

	components := strings.Split(parts[1], ", ")
	for _, c := range components {
		kv := strings.SplitN(c, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "Credential":
			credential = kv[1]
		case "SignedHeaders":
			signedHeaders = kv[1]
		case "Signature":
			signature = kv[1]
		}
	}

	if credential == "" || signedHeaders == "" || signature == "" {
		return "", "", "", ErrInvalidSignature
	}

	return credential, signedHeaders, signature, nil
}

func parseCredential(credential string) (accessKeyID, dateStamp, region, service string, err error) {
	// ACCESS_KEY/YYYYMMDD/region/service/aws4_request
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return "", "", "", "", ErrInvalidCredentials
	}

	return parts[0], parts[1], parts[2], parts[3], nil
}

func createAWS4CanonicalRequest(r *http.Request, signedHeadersList, payloadHash string) string {
	// Canonical URI
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string (sorted)
	params := r.URL.Query()
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonicalQueryString strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalQueryString.WriteString("&")
		}
		canonicalQueryString.WriteString(url.QueryEscape(k))
		canonicalQueryString.WriteString("=")
		canonicalQueryString.WriteString(url.QueryEscape(params.Get(k)))
	}

	// Canonical headers (based on signed headers)
	signedHeaders := strings.Split(signedHeadersList, ";")
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(r.Header.Get(h)))
		canonicalHeaders.WriteString("\n")
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		r.Method,
		canonicalURI,
		canonicalQueryString.String(),
		canonicalHeaders.String(),
		signedHeadersList,
		payloadHash,
	)
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Restore body for further reading
	r.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// Stats holds signing statistics.
type Stats struct {
	TotalKeys     int            `json:"total_keys"`
	ActiveKeys    int            `json:"active_keys"`
	ExpiredKeys   int            `json:"expired_keys"`
	KeysByStatus  map[string]int `json:"keys_by_status"`
}

// GetStats returns key store statistics.
func GetStats(store KeyStore) *Stats {
	stats := &Stats{
		KeysByStatus: make(map[string]int),
	}

	keys := store.ListKeys()
	for _, id := range keys {
		stats.TotalKeys++
		creds, err := store.GetKey(id)
		if err != nil {
			continue
		}

		if creds.IsExpired() {
			stats.ExpiredKeys++
			stats.KeysByStatus["expired"]++
		} else if creds.Enabled {
			stats.ActiveKeys++
			stats.KeysByStatus["active"]++
		} else {
			stats.KeysByStatus["disabled"]++
		}
	}

	return stats
}
