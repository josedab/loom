// Package oauth provides OAuth 2.0 and OpenID Connect authentication.
package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrTokenMissing     = errors.New("token missing")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenInvalid     = errors.New("token invalid")
	ErrTokenNotYetValid = errors.New("token not yet valid")
	ErrIssuerMismatch   = errors.New("issuer mismatch")
	ErrAudienceMismatch = errors.New("audience mismatch")
	ErrKeyNotFound      = errors.New("signing key not found")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Token represents a parsed JWT token.
type Token struct {
	Raw       string
	Header    TokenHeader
	Claims    Claims
	Signature []byte
	Valid     bool
}

// TokenHeader represents JWT header.
type TokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// Claims represents JWT claims.
type Claims struct {
	// Standard claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`

	// OIDC claims
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`

	// Authorization claims
	Scope  string   `json:"scope,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`

	// Custom claims
	Custom map[string]interface{} `json:"-"`
}

// Audience handles both string and []string audience claims.
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*a = multi
		return nil
	}

	return errors.New("invalid audience format")
}

// Contains checks if audience contains a value.
func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`

	// RSA key components
	N string `json:"n"` // Modulus
	E string `json:"e"` // Exponent

	// EC key components
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`

	// Certificates
	X5C []string `json:"x5c,omitempty"`
	X5T string   `json:"x5t,omitempty"`
}

// RSAPublicKey converts JWK to RSA public key.
func (j *JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if j.KeyType != "RSA" {
		return nil, fmt.Errorf("key type is not RSA: %s", j.KeyType)
	}

	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// OIDCConfig represents OpenID Connect discovery configuration.
type OIDCConfig struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	ScopesSupported          []string `json:"scopes_supported"`
	ResponseTypesSupported   []string `json:"response_types_supported"`
	ClaimsSupported          []string `json:"claims_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// Provider represents an OAuth/OIDC provider.
type Provider struct {
	Name         string
	Issuer       string
	JWKSURI      string
	ClientID     string
	ClientSecret string
	Audiences    []string

	// Cached data
	oidcConfig *OIDCConfig
	jwks       *JWKS
	jwksMu     sync.RWMutex
	jwksExpiry time.Time

	httpClient *http.Client
	logger     *slog.Logger
}

// ProviderConfig configures a provider.
type ProviderConfig struct {
	Name         string
	Issuer       string
	JWKSURI      string // Optional if using OIDC discovery
	ClientID     string
	ClientSecret string
	Audiences    []string
	HTTPClient   *http.Client
	Logger       *slog.Logger
}

// NewProvider creates a new OAuth provider.
func NewProvider(cfg ProviderConfig) *Provider {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Provider{
		Name:         cfg.Name,
		Issuer:       cfg.Issuer,
		JWKSURI:      cfg.JWKSURI,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Audiences:    cfg.Audiences,
		httpClient:   cfg.HTTPClient,
		logger:       cfg.Logger,
	}
}

// Discover fetches OIDC configuration.
func (p *Provider) Discover(ctx context.Context) (*OIDCConfig, error) {
	if p.oidcConfig != nil {
		return p.oidcConfig, nil
	}

	discoveryURL := strings.TrimSuffix(p.Issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC config: %w", err)
	}

	p.oidcConfig = &config
	if p.JWKSURI == "" {
		p.JWKSURI = config.JWKSURI
	}

	p.logger.Info("OIDC discovery completed",
		"issuer", config.Issuer,
		"jwks_uri", config.JWKSURI,
	)

	return &config, nil
}

// FetchJWKS fetches the JSON Web Key Set.
func (p *Provider) FetchJWKS(ctx context.Context) (*JWKS, error) {
	p.jwksMu.RLock()
	if p.jwks != nil && time.Now().Before(p.jwksExpiry) {
		jwks := p.jwks
		p.jwksMu.RUnlock()
		return jwks, nil
	}
	p.jwksMu.RUnlock()

	// Need to fetch
	p.jwksMu.Lock()
	defer p.jwksMu.Unlock()

	// Double-check after acquiring write lock
	if p.jwks != nil && time.Now().Before(p.jwksExpiry) {
		return p.jwks, nil
	}

	jwksURI := p.JWKSURI
	if jwksURI == "" {
		// Try OIDC discovery
		config, err := p.Discover(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to discover JWKS URI: %w", err)
		}
		jwksURI = config.JWKSURI
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	p.jwks = &jwks
	p.jwksExpiry = time.Now().Add(time.Hour) // Cache for 1 hour

	p.logger.Info("JWKS fetched",
		"keys_count", len(jwks.Keys),
	)

	return &jwks, nil
}

// GetKey retrieves a key by ID.
func (p *Provider) GetKey(ctx context.Context, kid string) (*JWK, error) {
	jwks, err := p.FetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}

	// Key not found - try refetching
	p.jwksMu.Lock()
	p.jwksExpiry = time.Time{} // Force refresh
	p.jwksMu.Unlock()

	jwks, err = p.FetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}

	return nil, ErrKeyNotFound
}

// Validator validates JWT tokens.
type Validator struct {
	providers map[string]*Provider
	mu        sync.RWMutex
	config    ValidatorConfig
	logger    *slog.Logger
}

// ValidatorConfig configures the validator.
type ValidatorConfig struct {
	// RequiredClaims that must be present.
	RequiredClaims []string
	// AllowedAlgorithms limits which signing algorithms are accepted.
	AllowedAlgorithms []string
	// ClockSkew tolerance for time-based claims.
	ClockSkew time.Duration
	// Logger for validation events.
	Logger *slog.Logger
}

// NewValidator creates a new token validator.
func NewValidator(cfg ValidatorConfig) *Validator {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		cfg.AllowedAlgorithms = []string{"RS256", "RS384", "RS512"}
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = time.Minute
	}

	return &Validator{
		providers: make(map[string]*Provider),
		config:    cfg,
		logger:    cfg.Logger,
	}
}

// AddProvider adds an OAuth provider.
func (v *Validator) AddProvider(provider *Provider) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.providers[provider.Issuer] = provider
}

// RemoveProvider removes a provider.
func (v *Validator) RemoveProvider(issuer string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.providers, issuer)
}

// GetProvider returns a provider by issuer.
func (v *Validator) GetProvider(issuer string) *Provider {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.providers[issuer]
}

// ParseToken parses a JWT token without validation.
func ParseToken(tokenString string) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header TokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Parse custom claims
	var customClaims map[string]interface{}
	json.Unmarshal(claimsBytes, &customClaims)

	// Remove standard claims from custom
	standardClaims := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
		"name", "email", "email_verified", "picture", "locale",
		"scope", "scopes", "roles", "groups"}
	for _, c := range standardClaims {
		delete(customClaims, c)
	}
	claims.Custom = customClaims

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return &Token{
		Raw:       tokenString,
		Header:    header,
		Claims:    claims,
		Signature: signature,
	}, nil
}

// Validate validates a JWT token.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Token, error) {
	token, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Check algorithm
	allowed := false
	for _, alg := range v.config.AllowedAlgorithms {
		if token.Header.Algorithm == alg {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("algorithm %s not allowed", token.Header.Algorithm)
	}

	// Find provider for issuer
	v.mu.RLock()
	provider := v.providers[token.Claims.Issuer]
	v.mu.RUnlock()

	if provider == nil {
		return nil, fmt.Errorf("%w: unknown issuer %s", ErrIssuerMismatch, token.Claims.Issuer)
	}

	// Validate signature
	if err := v.validateSignature(ctx, token, provider); err != nil {
		return nil, err
	}

	// Validate time claims
	now := time.Now()

	if token.Claims.ExpiresAt > 0 {
		expTime := time.Unix(token.Claims.ExpiresAt, 0)
		if now.After(expTime.Add(v.config.ClockSkew)) {
			return nil, ErrTokenExpired
		}
	}

	if token.Claims.NotBefore > 0 {
		nbfTime := time.Unix(token.Claims.NotBefore, 0)
		if now.Before(nbfTime.Add(-v.config.ClockSkew)) {
			return nil, ErrTokenNotYetValid
		}
	}

	// Validate audience
	if len(provider.Audiences) > 0 {
		matched := false
		for _, aud := range provider.Audiences {
			if token.Claims.Audience.Contains(aud) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrAudienceMismatch
		}
	}

	// Check required claims
	for _, claim := range v.config.RequiredClaims {
		if !v.hasClaim(token, claim) {
			return nil, fmt.Errorf("missing required claim: %s", claim)
		}
	}

	token.Valid = true
	return token, nil
}

// validateSignature validates the token signature.
func (v *Validator) validateSignature(ctx context.Context, token *Token, provider *Provider) error {
	// Get signing key
	key, err := provider.GetKey(ctx, token.Header.KeyID)
	if err != nil {
		return fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse signature based on algorithm
	switch token.Header.Algorithm {
	case "RS256", "RS384", "RS512":
		return v.validateRSASignature(token, key)
	default:
		return fmt.Errorf("unsupported algorithm: %s", token.Header.Algorithm)
	}
}

// validateRSASignature validates RSA signature.
func (v *Validator) validateRSASignature(token *Token, key *JWK) error {
	pubKey, err := key.RSAPublicKey()
	if err != nil {
		return err
	}

	// Get hash algorithm
	var hashFunc func() hash.Hash
	var cryptoHash crypto.Hash

	switch token.Header.Algorithm {
	case "RS256":
		hashFunc = sha256.New
		cryptoHash = crypto.SHA256
	case "RS384":
		hashFunc = sha512.New384
		cryptoHash = crypto.SHA384
	case "RS512":
		hashFunc = sha512.New
		cryptoHash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", token.Header.Algorithm)
	}

	// Compute hash of signing input
	parts := strings.Split(token.Raw, ".")
	signingInput := parts[0] + "." + parts[1]

	h := hashFunc()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	// Verify signature
	err = rsa.VerifyPKCS1v15(pubKey, cryptoHash, hashed, token.Signature)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// hasClaim checks if a claim is present.
func (v *Validator) hasClaim(token *Token, claim string) bool {
	switch claim {
	case "iss":
		return token.Claims.Issuer != ""
	case "sub":
		return token.Claims.Subject != ""
	case "aud":
		return len(token.Claims.Audience) > 0
	case "exp":
		return token.Claims.ExpiresAt > 0
	case "email":
		return token.Claims.Email != ""
	default:
		_, ok := token.Claims.Custom[claim]
		return ok
	}
}

// TokenIntrospector introspects tokens with the authorization server.
type TokenIntrospector struct {
	provider   *Provider
	httpClient *http.Client
	logger     *slog.Logger
}

// IntrospectionResponse represents token introspection response.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
}

// NewTokenIntrospector creates a new introspector.
func NewTokenIntrospector(provider *Provider) *TokenIntrospector {
	return &TokenIntrospector{
		provider:   provider,
		httpClient: provider.httpClient,
		logger:     provider.logger,
	}
}

// Introspect checks if a token is active.
func (ti *TokenIntrospector) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	config, err := ti.provider.Discover(ctx)
	if err != nil {
		return nil, err
	}

	// Find introspection endpoint
	introspectURL := strings.TrimSuffix(config.TokenEndpoint, "/token") + "/introspect"

	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client credentials
	if ti.provider.ClientID != "" && ti.provider.ClientSecret != "" {
		req.SetBasicAuth(ti.provider.ClientID, ti.provider.ClientSecret)
	}

	resp, err := ti.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("introspection failed: %s", string(body))
	}

	var introspectResp IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		return nil, err
	}

	return &introspectResp, nil
}

// HasScope checks if token has a specific scope.
func (c *Claims) HasScope(scope string) bool {
	// Check scope string (space-separated)
	if c.Scope != "" {
		scopes := strings.Split(c.Scope, " ")
		for _, s := range scopes {
			if s == scope {
				return true
			}
		}
	}

	// Check scopes array
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}

	return false
}

// HasRole checks if token has a specific role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasGroup checks if token is in a specific group.
func (c *Claims) HasGroup(group string) bool {
	for _, g := range c.Groups {
		if g == group {
			return true
		}
	}
	return false
}
