package signing

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMemoryKeyStore(t *testing.T) {
	store := NewMemoryKeyStore()

	// Add key
	creds := &Credentials{
		ID:          "test-key",
		Secret:      "test-secret",
		Description: "Test key",
		Enabled:     true,
	}

	err := store.AddKey(creds)
	if err != nil {
		t.Errorf("AddKey() error = %v", err)
	}

	if creds.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	// Get key
	got, err := store.GetKey("test-key")
	if err != nil {
		t.Errorf("GetKey() error = %v", err)
	}
	if got.Secret != "test-secret" {
		t.Errorf("Secret = %v, want test-secret", got.Secret)
	}

	// Get non-existent key
	_, err = store.GetKey("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey() error = %v, want ErrKeyNotFound", err)
	}

	// List keys
	keys := store.ListKeys()
	if len(keys) != 1 {
		t.Errorf("len(ListKeys()) = %d, want 1", len(keys))
	}

	// Remove key
	err = store.RemoveKey("test-key")
	if err != nil {
		t.Errorf("RemoveKey() error = %v", err)
	}

	// Remove non-existent key
	err = store.RemoveKey("test-key")
	if err != ErrKeyNotFound {
		t.Errorf("RemoveKey() error = %v, want ErrKeyNotFound", err)
	}
}

func TestCredentials_IsExpired(t *testing.T) {
	// Not expired (no expiry)
	creds := &Credentials{}
	if creds.IsExpired() {
		t.Error("expected not expired when ExpiresAt is nil")
	}

	// Not expired (future)
	future := time.Now().Add(time.Hour)
	creds.ExpiresAt = &future
	if creds.IsExpired() {
		t.Error("expected not expired when ExpiresAt is in future")
	}

	// Expired (past)
	past := time.Now().Add(-time.Hour)
	creds.ExpiresAt = &past
	if !creds.IsExpired() {
		t.Error("expected expired when ExpiresAt is in past")
	}
}

func TestHMACSigner_Sign(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "test-key",
	})

	// Fixed timestamp for testing
	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	signer.timestamp = func() time.Time { return fixedTime }

	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"name":"test"}`))
	req.Header.Set("Content-Type", "application/json")

	err := signer.Sign(req)
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}

	// Check headers were set
	if req.Header.Get("X-Signature") == "" {
		t.Error("expected X-Signature header")
	}
	if req.Header.Get("X-Signature-Timestamp") == "" {
		t.Error("expected X-Signature-Timestamp header")
	}
	if req.Header.Get("X-Signature-KeyID") != "test-key" {
		t.Errorf("X-Signature-KeyID = %v, want test-key", req.Header.Get("X-Signature-KeyID"))
	}
}

func TestHMACSigner_Sign_DisabledKey(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "disabled-key",
		Secret:  "test-secret",
		Enabled: false,
	})

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "disabled-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	err := signer.Sign(req)
	if err != ErrInvalidCredentials {
		t.Errorf("Sign() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestHMACSigner_Sign_ExpiredKey(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:        "expired-key",
		Secret:    "test-secret",
		Enabled:   true,
		ExpiresAt: &past,
	})

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "expired-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	err := signer.Sign(req)
	if err != ErrExpiredSignature {
		t.Errorf("Sign() error = %v, want ErrExpiredSignature", err)
	}
}

func TestHMACVerifier_Verify(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	fixedTime := time.Now()

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "test-key",
	})
	signer.timestamp = func() time.Time { return fixedTime }

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore:     store,
		MaxClockSkew: 5 * time.Minute,
	})
	verifier.timestamp = func() time.Time { return fixedTime }

	// Create and sign request
	body := `{"name":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Create new request with same signature for verification
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	verifyReq.Header = req.Header.Clone()

	err = verifier.Verify(verifyReq)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

func TestHMACVerifier_Verify_MissingSignature(t *testing.T) {
	store := NewMemoryKeyStore()
	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore: store,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	err := verifier.Verify(req)
	if err != ErrMissingSignature {
		t.Errorf("Verify() error = %v, want ErrMissingSignature", err)
	}
}

func TestHMACVerifier_Verify_InvalidSignature(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore: store,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-Signature", "invalid-signature")
	req.Header.Set("X-Signature-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Signature-KeyID", "test-key")

	err := verifier.Verify(req)
	if err != ErrInvalidSignature {
		t.Errorf("Verify() error = %v, want ErrInvalidSignature", err)
	}
}

func TestHMACVerifier_Verify_ExpiredTimestamp(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore:     store,
		MaxClockSkew: 5 * time.Minute,
	})

	oldTime := time.Now().Add(-10 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-Signature", "some-signature")
	req.Header.Set("X-Signature-Timestamp", oldTime.UTC().Format(time.RFC3339))
	req.Header.Set("X-Signature-KeyID", "test-key")

	err := verifier.Verify(req)
	if err != ErrExpiredSignature {
		t.Errorf("Verify() error = %v, want ErrExpiredSignature", err)
	}
}

func TestMemoryNonceStore(t *testing.T) {
	store := NewMemoryNonceStore()

	// Should not have seen new nonce
	if store.HasSeen("nonce1") {
		t.Error("expected nonce to not be seen initially")
	}

	// Mark nonce
	store.Mark("nonce1", time.Minute)

	// Should have seen it now
	if !store.HasSeen("nonce1") {
		t.Error("expected nonce to be seen after marking")
	}
}

func TestHMACVerifier_ReplayProtection(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	nonceStore := NewMemoryNonceStore()
	fixedTime := time.Now()

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "test-key",
	})
	signer.timestamp = func() time.Time { return fixedTime }

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore:   store,
		NonceStore: nonceStore,
	})
	verifier.timestamp = func() time.Time { return fixedTime }

	// Sign and add nonce
	body := `{"test":"data"}`
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	signer.Sign(req)
	req.Header.Set("X-Signature-Nonce", "unique-nonce-123")

	// First verification should succeed
	verifyReq1 := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	verifyReq1.Header = req.Header.Clone()
	err := verifier.Verify(verifyReq1)
	if err != nil {
		t.Errorf("First verify error = %v", err)
	}

	// Second verification (replay) should fail
	verifyReq2 := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	verifyReq2.Header = req.Header.Clone()
	err = verifier.Verify(verifyReq2)
	if err != ErrReplayDetected {
		t.Errorf("Replay verify error = %v, want ErrReplayDetected", err)
	}
}

func TestAWS4Signer_Sign(t *testing.T) {
	signer := NewAWS4Signer(AWS4SignerConfig{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "execute-api",
	})

	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	signer.timestamp = func() time.Time { return fixedTime }

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/users?limit=10", nil)

	err := signer.Sign(req)
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}

	// Check headers
	if req.Header.Get("Authorization") == "" {
		t.Error("expected Authorization header")
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		t.Error("expected AWS4-HMAC-SHA256 prefix")
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("expected X-Amz-Date header")
	}
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Error("expected X-Amz-Content-Sha256 header")
	}
}

func TestAWS4Signer_Sign_WithBody(t *testing.T) {
	signer := NewAWS4Signer(AWS4SignerConfig{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "execute-api",
	})

	body := `{"name":"test","value":123}`
	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/items", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	err := signer.Sign(req)
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}

	// Verify body is still readable
	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	if buf.String() != body {
		t.Error("body should still be readable after signing")
	}
}

func TestAWS4Verifier_Verify(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "AKIAIOSFODNN7EXAMPLE",
		Secret:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Enabled: true,
	})

	fixedTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	signer := NewAWS4Signer(AWS4SignerConfig{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	signer.timestamp = func() time.Time { return fixedTime }

	verifier := NewAWS4Verifier(AWS4VerifierConfig{
		KeyStore: store,
		Region:   "us-east-1",
		Service:  "execute-api",
	})
	verifier.timestamp = func() time.Time { return fixedTime }

	// Sign request
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	err := signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify
	verifyReq := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	verifyReq.Header = req.Header.Clone()

	err = verifier.Verify(verifyReq)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

func TestAWS4Verifier_Verify_MissingAuth(t *testing.T) {
	store := NewMemoryKeyStore()
	verifier := NewAWS4Verifier(AWS4VerifierConfig{
		KeyStore: store,
		Region:   "us-east-1",
		Service:  "execute-api",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	err := verifier.Verify(req)
	if err != ErrMissingSignature {
		t.Errorf("Verify() error = %v, want ErrMissingSignature", err)
	}
}

func TestAWS4Verifier_Verify_WrongRegion(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "AKIAIOSFODNN7EXAMPLE",
		Secret:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Enabled: true,
	})

	fixedTime := time.Now()

	signer := NewAWS4Signer(AWS4SignerConfig{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-west-2", // Different region
		Service:         "execute-api",
	})
	signer.timestamp = func() time.Time { return fixedTime }

	verifier := NewAWS4Verifier(AWS4VerifierConfig{
		KeyStore: store,
		Region:   "us-east-1",
		Service:  "execute-api",
	})
	verifier.timestamp = func() time.Time { return fixedTime }

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	signer.Sign(req)

	verifyReq := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	verifyReq.Header = req.Header.Clone()

	err := verifier.Verify(verifyReq)
	if err != ErrInvalidCredentials {
		t.Errorf("Verify() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestParseAWS4AuthHeader(t *testing.T) {
	header := "AWS4-HMAC-SHA256 Credential=AKID/20240115/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123"

	credential, signedHeaders, signature, err := parseAWS4AuthHeader(header)
	if err != nil {
		t.Errorf("parseAWS4AuthHeader() error = %v", err)
	}

	if credential != "AKID/20240115/us-east-1/s3/aws4_request" {
		t.Errorf("credential = %v", credential)
	}
	if signedHeaders != "host;x-amz-date" {
		t.Errorf("signedHeaders = %v", signedHeaders)
	}
	if signature != "abc123" {
		t.Errorf("signature = %v", signature)
	}
}

func TestParseCredential(t *testing.T) {
	credential := "AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/execute-api/aws4_request"

	accessKey, dateStamp, region, service, err := parseCredential(credential)
	if err != nil {
		t.Errorf("parseCredential() error = %v", err)
	}

	if accessKey != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("accessKey = %v", accessKey)
	}
	if dateStamp != "20240115" {
		t.Errorf("dateStamp = %v", dateStamp)
	}
	if region != "us-east-1" {
		t.Errorf("region = %v", region)
	}
	if service != "execute-api" {
		t.Errorf("service = %v", service)
	}
}

func TestVerificationMiddleware(t *testing.T) {
	store := NewMemoryKeyStore()
	store.AddKey(&Credentials{
		ID:      "test-key",
		Secret:  "test-secret",
		Enabled: true,
	})

	fixedTime := time.Now()

	signer := NewHMACSigner(HMACSignerConfig{
		KeyStore: store,
		KeyID:    "test-key",
	})
	signer.timestamp = func() time.Time { return fixedTime }

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore: store,
	})
	verifier.timestamp = func() time.Time { return fixedTime }

	handler := VerificationMiddleware(VerificationMiddlewareConfig{
		HMACVerifier: verifier,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Signed request
	body := `{"test":"data"}`
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	signer.Sign(req)

	// Create verification request
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	verifyReq.Header = req.Header.Clone()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, verifyReq)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestVerificationMiddleware_MissingSignature(t *testing.T) {
	store := NewMemoryKeyStore()

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore: store,
	})

	handler := VerificationMiddleware(VerificationMiddlewareConfig{
		HMACVerifier: verifier,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVerificationMiddleware_SkipPaths(t *testing.T) {
	store := NewMemoryKeyStore()

	verifier := NewHMACVerifier(HMACVerifierConfig{
		KeyStore: store,
	})

	handler := VerificationMiddleware(VerificationMiddlewareConfig{
		HMACVerifier: verifier,
		SkipPaths:    []string{"/health", "/metrics/*"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		path   string
		status int
	}{
		{"/health", http.StatusOK},
		{"/metrics/cpu", http.StatusOK},
		{"/api/users", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != tt.status {
			t.Errorf("path %s: status = %d, want %d", tt.path, rec.Code, tt.status)
		}
	}
}

func TestHandler_CRUD(t *testing.T) {
	store := NewMemoryKeyStore()
	h := NewHandler(store, nil)

	// Create key
	createBody := `{"id": "test-key", "secret": "test-secret", "description": "Test", "enabled": true}`
	req := httptest.NewRequest(http.MethodPost, "/signing/keys", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Create status = %d, want 201", rec.Code)
	}

	// List keys
	req = httptest.NewRequest(http.MethodGet, "/signing/keys", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("List status = %d, want 200", rec.Code)
	}

	var keys []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&keys)
	if len(keys) != 1 {
		t.Errorf("len(keys) = %d, want 1", len(keys))
	}

	// Get key
	req = httptest.NewRequest(http.MethodGet, "/signing/keys/test-key", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Get status = %d, want 200", rec.Code)
	}

	// Delete key
	req = httptest.NewRequest(http.MethodDelete, "/signing/keys/test-key", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Delete status = %d, want 204", rec.Code)
	}

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/signing/keys/test-key", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Get deleted status = %d, want 404", rec.Code)
	}
}

func TestHandler_Stats(t *testing.T) {
	store := NewMemoryKeyStore()
	h := NewHandler(store, nil)

	// Add keys
	store.AddKey(&Credentials{ID: "key1", Secret: "s1", Enabled: true})
	store.AddKey(&Credentials{ID: "key2", Secret: "s2", Enabled: false})

	req := httptest.NewRequest(http.MethodGet, "/signing/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Stats status = %d, want 200", rec.Code)
	}

	var stats Stats
	json.NewDecoder(rec.Body).Decode(&stats)

	if stats.TotalKeys != 2 {
		t.Errorf("TotalKeys = %d, want 2", stats.TotalKeys)
	}
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, want 1", stats.ActiveKeys)
	}
}

func TestGetStats(t *testing.T) {
	store := NewMemoryKeyStore()

	past := time.Now().Add(-time.Hour)
	store.AddKey(&Credentials{ID: "active", Secret: "s", Enabled: true})
	store.AddKey(&Credentials{ID: "disabled", Secret: "s", Enabled: false})
	store.AddKey(&Credentials{ID: "expired", Secret: "s", Enabled: true, ExpiresAt: &past})

	stats := GetStats(store)

	if stats.TotalKeys != 3 {
		t.Errorf("TotalKeys = %d, want 3", stats.TotalKeys)
	}
	if stats.ActiveKeys != 1 {
		t.Errorf("ActiveKeys = %d, want 1", stats.ActiveKeys)
	}
	if stats.ExpiredKeys != 1 {
		t.Errorf("ExpiredKeys = %d, want 1", stats.ExpiredKeys)
	}
}

func TestComputeHMAC(t *testing.T) {
	message := []byte("test message")
	key := []byte("secret-key")

	sig1 := computeHMAC(message, key)
	sig2 := computeHMAC(message, key)

	if sig1 != sig2 {
		t.Error("same input should produce same signature")
	}

	sig3 := computeHMAC([]byte("different message"), key)
	if sig1 == sig3 {
		t.Error("different input should produce different signature")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "/anything", true},
		{"/health", "/health", true},
		{"/health", "/healthz", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", true},
		{"/api/*", "/other", false},
	}

	for _, tt := range tests {
		got := matchPath(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}
