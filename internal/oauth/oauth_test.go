package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAudience_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    Audience
		wantErr bool
	}{
		{
			name: "single string",
			json: `"api"`,
			want: Audience{"api"},
		},
		{
			name: "array",
			json: `["api", "backend"]`,
			want: Audience{"api", "backend"},
		},
		{
			name:    "invalid type",
			json:    `123`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var aud Audience
			err := json.Unmarshal([]byte(tt.json), &aud)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(aud) != len(tt.want) {
				t.Errorf("got %v, want %v", aud, tt.want)
			}
		})
	}
}

func TestAudience_Contains(t *testing.T) {
	aud := Audience{"api", "backend", "frontend"}

	if !aud.Contains("api") {
		t.Error("expected to contain 'api'")
	}
	if !aud.Contains("backend") {
		t.Error("expected to contain 'backend'")
	}
	if aud.Contains("unknown") {
		t.Error("expected not to contain 'unknown'")
	}
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "invalid format - no parts",
			token:   "invalidtoken",
			wantErr: true,
		},
		{
			name:    "invalid format - two parts",
			token:   "part1.part2",
			wantErr: true,
		},
		{
			name:    "invalid base64 header",
			token:   "!!!.eyJ0ZXN0IjoidmFsdWUifQ.sig",
			wantErr: true,
		},
		{
			name:    "invalid base64 claims",
			token:   "eyJhbGciOiJSUzI1NiJ9.!!!.sig",
			wantErr: true,
		},
		{
			name:  "valid token structure",
			token: createTestToken(t, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ParseToken(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token.Raw != tt.token {
				t.Error("raw token mismatch")
			}
		})
	}
}

func TestParseToken_Claims(t *testing.T) {
	token := createTestTokenWithClaims(t, map[string]interface{}{
		"iss":    "https://issuer.example.com",
		"sub":    "user123",
		"aud":    "api",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"name":   "John Doe",
		"email":  "john@example.com",
		"roles":  []string{"admin", "user"},
		"custom": "value",
	})

	parsed, err := ParseToken(token)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if parsed.Claims.Issuer != "https://issuer.example.com" {
		t.Errorf("issuer = %s, want https://issuer.example.com", parsed.Claims.Issuer)
	}
	if parsed.Claims.Subject != "user123" {
		t.Errorf("subject = %s, want user123", parsed.Claims.Subject)
	}
	if !parsed.Claims.Audience.Contains("api") {
		t.Error("expected audience to contain 'api'")
	}
	if parsed.Claims.Name != "John Doe" {
		t.Errorf("name = %s, want John Doe", parsed.Claims.Name)
	}
	if parsed.Claims.Email != "john@example.com" {
		t.Errorf("email = %s, want john@example.com", parsed.Claims.Email)
	}
	if v, ok := parsed.Claims.Custom["custom"]; !ok || v != "value" {
		t.Error("expected custom claim")
	}
}

func TestJWK_RSAPublicKey(t *testing.T) {
	// Generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk := JWK{
		KeyType: "RSA",
		KeyID:   "test-key",
		N:       base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
	}

	pubKey, err := jwk.RSAPublicKey()
	if err != nil {
		t.Fatalf("failed to convert JWK: %v", err)
	}

	if pubKey.N.Cmp(privateKey.N) != 0 {
		t.Error("modulus mismatch")
	}
	if pubKey.E != privateKey.E {
		t.Error("exponent mismatch")
	}
}

func TestJWK_RSAPublicKey_Errors(t *testing.T) {
	tests := []struct {
		name string
		jwk  JWK
	}{
		{
			name: "wrong key type",
			jwk:  JWK{KeyType: "EC"},
		},
		{
			name: "invalid modulus",
			jwk:  JWK{KeyType: "RSA", N: "!!!", E: "AQAB"},
		},
		{
			name: "invalid exponent",
			jwk:  JWK{KeyType: "RSA", N: "dGVzdA", E: "!!!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jwk.RSAPublicKey()
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNewProvider(t *testing.T) {
	provider := NewProvider(ProviderConfig{
		Name:      "test",
		Issuer:    "https://issuer.example.com",
		JWKSURI:   "https://issuer.example.com/.well-known/jwks.json",
		Audiences: []string{"api"},
	})

	if provider.Name != "test" {
		t.Errorf("name = %s, want test", provider.Name)
	}
	if provider.Issuer != "https://issuer.example.com" {
		t.Error("issuer mismatch")
	}
	if provider.httpClient == nil {
		t.Error("expected http client")
	}
	if provider.logger == nil {
		t.Error("expected logger")
	}
}

func TestProvider_FetchJWKS(t *testing.T) {
	// Create test JWKS server
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := JWKS{
		Keys: []JWK{
			{
				KeyType: "RSA",
				KeyID:   "test-key-1",
				Use:     "sig",
				N:       base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
				E:       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	provider := NewProvider(ProviderConfig{
		Issuer:  "https://test.example.com",
		JWKSURI: server.URL,
	})

	fetched, err := provider.FetchJWKS(context.Background())
	if err != nil {
		t.Fatalf("failed to fetch JWKS: %v", err)
	}

	if len(fetched.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(fetched.Keys))
	}
	if fetched.Keys[0].KeyID != "test-key-1" {
		t.Error("key ID mismatch")
	}
}

func TestProvider_GetKey(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := JWKS{
		Keys: []JWK{
			{KeyType: "RSA", KeyID: "key-1", N: base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())},
			{KeyType: "RSA", KeyID: "key-2", N: base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	provider := NewProvider(ProviderConfig{JWKSURI: server.URL})

	key, err := provider.GetKey(context.Background(), "key-1")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if key.KeyID != "key-1" {
		t.Error("key ID mismatch")
	}

	_, err = provider.GetKey(context.Background(), "unknown")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestNewValidator(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})

	if validator.providers == nil {
		t.Error("expected providers map")
	}
	if len(validator.config.AllowedAlgorithms) == 0 {
		t.Error("expected default algorithms")
	}
	if validator.config.ClockSkew == 0 {
		t.Error("expected default clock skew")
	}
}

func TestValidator_AddRemoveProvider(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})

	provider := NewProvider(ProviderConfig{
		Issuer: "https://test.example.com",
	})

	validator.AddProvider(provider)

	if validator.GetProvider("https://test.example.com") == nil {
		t.Error("expected provider to be added")
	}

	validator.RemoveProvider("https://test.example.com")

	if validator.GetProvider("https://test.example.com") != nil {
		t.Error("expected provider to be removed")
	}
}

func TestClaims_HasScope(t *testing.T) {
	claims := &Claims{
		Scope:  "read write",
		Scopes: []string{"admin"},
	}

	if !claims.HasScope("read") {
		t.Error("expected to have 'read' scope")
	}
	if !claims.HasScope("write") {
		t.Error("expected to have 'write' scope")
	}
	if !claims.HasScope("admin") {
		t.Error("expected to have 'admin' scope")
	}
	if claims.HasScope("delete") {
		t.Error("expected not to have 'delete' scope")
	}
}

func TestClaims_HasRole(t *testing.T) {
	claims := &Claims{
		Roles: []string{"admin", "user"},
	}

	if !claims.HasRole("admin") {
		t.Error("expected to have 'admin' role")
	}
	if !claims.HasRole("user") {
		t.Error("expected to have 'user' role")
	}
	if claims.HasRole("superadmin") {
		t.Error("expected not to have 'superadmin' role")
	}
}

func TestClaims_HasGroup(t *testing.T) {
	claims := &Claims{
		Groups: []string{"engineering", "devops"},
	}

	if !claims.HasGroup("engineering") {
		t.Error("expected to have 'engineering' group")
	}
	if claims.HasGroup("marketing") {
		t.Error("expected not to have 'marketing' group")
	}
}

func TestProvider_Discover(t *testing.T) {
	oidcConfig := OIDCConfig{
		Issuer:                "https://test.example.com",
		AuthorizationEndpoint: "https://test.example.com/authorize",
		TokenEndpoint:         "https://test.example.com/token",
		JWKSURI:               "https://test.example.com/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			json.NewEncoder(w).Encode(oidcConfig)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	provider := NewProvider(ProviderConfig{
		Issuer: server.URL,
	})

	config, err := provider.Discover(context.Background())
	if err != nil {
		t.Fatalf("failed to discover: %v", err)
	}

	if config.TokenEndpoint != oidcConfig.TokenEndpoint {
		t.Error("token endpoint mismatch")
	}
	if len(config.ScopesSupported) != 3 {
		t.Error("scopes mismatch")
	}
}

// Helper functions

func createTestToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	if claims == nil {
		claims = map[string]interface{}{
			"iss": "https://test.example.com",
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
	}
	return createTestTokenWithClaims(t, claims)
}

func createTestTokenWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create fake signature
	signingInput := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(h[:])

	return headerB64 + "." + claimsB64 + "." + signatureB64
}

func TestBearerTokenExtractor(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "valid bearer token",
			header: "Bearer eyJhbGciOiJSUzI1NiJ9.test.sig",
			want:   "eyJhbGciOiJSUzI1NiJ9.test.sig",
		},
		{
			name:   "lowercase bearer",
			header: "bearer token123",
			want:   "token123",
		},
		{
			name:   "no header",
			header: "",
			want:   "",
		},
		{
			name:   "wrong scheme",
			header: "Basic dXNlcjpwYXNz",
			want:   "",
		},
		{
			name:   "missing token",
			header: "Bearer",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}

			got := BearerTokenExtractor(r)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQueryTokenExtractor(t *testing.T) {
	extractor := QueryTokenExtractor("access_token")

	r := httptest.NewRequest("GET", "/?access_token=test123", nil)
	got := extractor(r)
	if got != "test123" {
		t.Errorf("got %q, want %q", got, "test123")
	}

	r = httptest.NewRequest("GET", "/", nil)
	got = extractor(r)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCookieTokenExtractor(t *testing.T) {
	extractor := CookieTokenExtractor("session")

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	got := extractor(r)
	if got != "cookie-token" {
		t.Errorf("got %q, want %q", got, "cookie-token")
	}

	r = httptest.NewRequest("GET", "/", nil)
	got = extractor(r)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestChainedTokenExtractor(t *testing.T) {
	extractor := ChainedTokenExtractor(
		BearerTokenExtractor,
		QueryTokenExtractor("token"),
		CookieTokenExtractor("auth"),
	)

	// Bearer header takes precedence
	r := httptest.NewRequest("GET", "/?token=query", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	got := extractor(r)
	if got != "header-token" {
		t.Errorf("got %q, want %q", got, "header-token")
	}

	// Falls back to query
	r = httptest.NewRequest("GET", "/?token=query-token", nil)
	got = extractor(r)
	if got != "query-token" {
		t.Errorf("got %q, want %q", got, "query-token")
	}

	// Falls back to cookie
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: "cookie-token"})
	got = extractor(r)
	if got != "cookie-token" {
		t.Errorf("got %q, want %q", got, "cookie-token")
	}

	// No token
	r = httptest.NewRequest("GET", "/", nil)
	got = extractor(r)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestMiddleware_SkipPaths(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})

	middleware := Middleware(MiddlewareConfig{
		Validator: validator,
		SkipPaths: []string{"/health", "/public/*"},
	})

	handlerCalled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		path       string
		wantCalled bool
	}{
		{"/health", true},
		{"/public/docs", true},
		{"/api/users", false}, // Not skipped, no token
	}

	for _, tt := range tests {
		handlerCalled = false
		r := httptest.NewRequest("GET", tt.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if tt.wantCalled != handlerCalled {
			t.Errorf("path %s: handler called = %v, want %v", tt.path, handlerCalled, tt.wantCalled)
		}
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})

	middleware := Middleware(MiddlewareConfig{
		Validator: validator,
	})

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/api/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestGetToken_FromContext(t *testing.T) {
	token := &Token{
		Claims: Claims{
			Subject: "user123",
		},
	}

	ctx := context.WithValue(context.Background(), tokenContextKey{}, token)

	got := GetToken(ctx)
	if got == nil {
		t.Fatal("expected token")
	}
	if got.Claims.Subject != "user123" {
		t.Error("subject mismatch")
	}

	claims := GetClaims(ctx)
	if claims == nil {
		t.Fatal("expected claims")
	}
	if claims.Subject != "user123" {
		t.Error("subject mismatch")
	}

	// Empty context
	got = GetToken(context.Background())
	if got != nil {
		t.Error("expected nil for empty context")
	}
}

func TestRequireScopes(t *testing.T) {
	middleware := RequireScopes("read", "write")

	token := &Token{
		Claims: Claims{
			Scope: "read write delete",
		},
	}

	handlerCalled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	// With required scopes
	r := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(r.Context(), tokenContextKey{}, token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r.WithContext(ctx))

	if !handlerCalled {
		t.Error("expected handler to be called")
	}

	// Missing scope
	token.Claims.Scope = "read"
	handlerCalled = false
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r.WithContext(ctx))

	if handlerCalled {
		t.Error("expected handler not to be called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRequireRoles(t *testing.T) {
	middleware := RequireRoles("admin")

	token := &Token{
		Claims: Claims{
			Roles: []string{"admin", "user"},
		},
	}

	handlerCalled := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	r := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(r.Context(), tokenContextKey{}, token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r.WithContext(ctx))

	if !handlerCalled {
		t.Error("expected handler to be called")
	}

	// Missing role
	token.Claims.Roles = []string{"user"}
	handlerCalled = false
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r.WithContext(ctx))

	if handlerCalled {
		t.Error("expected handler not to be called")
	}
}

func TestHandler_Validate(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})
	handler := NewHandler(validator, nil)

	// Invalid token (no provider)
	body := `{"token": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ1bmtub3duIn0.sig"}`
	r := httptest.NewRequest("POST", "/oauth/validate", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["valid"] != false {
		t.Error("expected valid=false")
	}
}

func TestHandler_UserInfo(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})
	handler := NewHandler(validator, nil)

	// No token in context
	r := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// With token
	token := &Token{
		Claims: Claims{
			Subject: "user123",
			Name:    "John Doe",
			Email:   "john@example.com",
			Roles:   []string{"admin"},
		},
	}
	ctx := context.WithValue(r.Context(), tokenContextKey{}, token)
	r = httptest.NewRequest("GET", "/oauth/userinfo", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r.WithContext(ctx))

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["sub"] != "user123" {
		t.Error("expected sub=user123")
	}
}

func TestHandler_ListProviders(t *testing.T) {
	validator := NewValidator(ValidatorConfig{})
	validator.AddProvider(NewProvider(ProviderConfig{
		Name:   "test",
		Issuer: "https://test.example.com",
	}))

	handler := NewHandler(validator, nil)

	r := httptest.NewRequest("GET", "/oauth/providers", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	var providers []map[string]string
	json.NewDecoder(w.Body).Decode(&providers)
	if len(providers) != 1 {
		t.Errorf("expected 1 provider, got %d", len(providers))
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "/any/path", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", true},
		{"/api/*", "/other", false},
		{"/health", "/health", true},
		{"/health", "/healthz", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchPath(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}
