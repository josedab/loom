package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestDefaultMTLSConfig(t *testing.T) {
	cfg := DefaultMTLSConfig()

	if !cfg.RequireClientCert {
		t.Error("expected RequireClientCert to be true")
	}
	if !cfg.ExtractIdentity {
		t.Error("expected ExtractIdentity to be true")
	}
	if len(cfg.ExcludedPaths) == 0 {
		t.Error("expected default excluded paths")
	}
}

func TestMTLSMiddleware_NoTLS(t *testing.T) {
	cfg := MTLSConfig{RequireClientCert: true}
	middleware := MTLSMiddleware(cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestMTLSMiddleware_NoTLS_NotRequired(t *testing.T) {
	cfg := MTLSConfig{RequireClientCert: false}
	middleware := MTLSMiddleware(cfg)

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestMTLSMiddleware_ExcludedPath(t *testing.T) {
	cfg := MTLSConfig{
		RequireClientCert: true,
		ExcludedPaths:     []string{"/health", "/api/public/*"},
	}
	middleware := MTLSMiddleware(cfg)

	called := false
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/health", true},
		{"/health/live", true},
		{"/api/public/data", true},
		{"/api/private", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tt.excluded {
				if !called {
					t.Error("expected handler to be called for excluded path")
				}
			} else {
				// Not excluded, should fail (no TLS)
				if rec.Code != http.StatusBadRequest {
					t.Errorf("expected status 400, got %d", rec.Code)
				}
			}
		})
	}
}

func TestMTLSMiddleware_NoCertificate(t *testing.T) {
	cfg := MTLSConfig{RequireClientCert: true}
	middleware := MTLSMiddleware(cfg)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: nil, // No verified chains
	}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestMTLSMiddleware_ValidCertificate(t *testing.T) {
	cert := createTestCertificate(t, "test-service", []string{"example.com"}, nil)

	cfg := MTLSConfig{
		RequireClientCert: true,
		ExtractIdentity:   true,
	}
	middleware := MTLSMiddleware(cfg)

	var identity *MTLSIdentity
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity = GetMTLSIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if identity == nil {
		t.Fatal("expected identity in context")
	}
	if identity.CommonName != "test-service" {
		t.Errorf("expected CN 'test-service', got '%s'", identity.CommonName)
	}
}

func TestMTLSMiddleware_AllowedCNs(t *testing.T) {
	tests := []struct {
		name        string
		certCN      string
		allowedCNs  []string
		expectAllow bool
	}{
		{"allowed CN", "service-a", []string{"service-a", "service-b"}, true},
		{"not allowed CN", "service-c", []string{"service-a", "service-b"}, false},
		{"no restriction", "any-service", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificate(t, tt.certCN, nil, nil)

			cfg := MTLSConfig{
				RequireClientCert: true,
				AllowedCNs:        tt.allowedCNs,
			}
			middleware := MTLSMiddleware(cfg)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tt.expectAllow && rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
			if !tt.expectAllow && rec.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", rec.Code)
			}
		})
	}
}

func TestMTLSMiddleware_AllowedOrgs(t *testing.T) {
	tests := []struct {
		name        string
		certOrgs    []string
		allowedOrgs []string
		expectAllow bool
	}{
		{"allowed org", []string{"Acme Inc"}, []string{"Acme Inc", "Other Corp"}, true},
		{"not allowed org", []string{"Unknown Inc"}, []string{"Acme Inc", "Other Corp"}, false},
		{"no restriction", []string{"Any Org"}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificateWithOrg(t, "test", tt.certOrgs, nil)

			cfg := MTLSConfig{
				RequireClientCert: true,
				AllowedOrgs:       tt.allowedOrgs,
			}
			middleware := MTLSMiddleware(cfg)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tt.expectAllow && rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
			if !tt.expectAllow && rec.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", rec.Code)
			}
		})
	}
}

func TestMTLSMiddleware_AllowedDNSSANs(t *testing.T) {
	tests := []struct {
		name          string
		certDNS       []string
		allowedDNS    []string
		expectAllow   bool
	}{
		{"exact match", []string{"api.example.com"}, []string{"api.example.com"}, true},
		{"wildcard match", []string{"api.example.com"}, []string{"*.example.com"}, true},
		{"no match", []string{"api.other.com"}, []string{"*.example.com"}, false},
		{"no restriction", []string{"any.domain.com"}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertificate(t, "test", tt.certDNS, nil)

			cfg := MTLSConfig{
				RequireClientCert: true,
				AllowedDNSSANs:    tt.allowedDNS,
			}
			middleware := MTLSMiddleware(cfg)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tt.expectAllow && rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
			if !tt.expectAllow && rec.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", rec.Code)
			}
		})
	}
}

func TestMTLSMiddleware_AllowedURISANs(t *testing.T) {
	tests := []struct {
		name        string
		certURIs    []string
		allowedURIs []string
		expectAllow bool
	}{
		{"exact SPIFFE match", []string{"spiffe://cluster.local/ns/default/sa/api"}, []string{"spiffe://cluster.local/ns/default/sa/api"}, true},
		{"wildcard SPIFFE match", []string{"spiffe://cluster.local/ns/default/sa/api"}, []string{"spiffe://cluster.local/*"}, true},
		{"no match", []string{"spiffe://other.local/ns/default/sa/api"}, []string{"spiffe://cluster.local/*"}, false},
		{"no restriction", []string{"spiffe://any.domain/path"}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uris := make([]*url.URL, 0, len(tt.certURIs))
			for _, u := range tt.certURIs {
				parsed, _ := url.Parse(u)
				uris = append(uris, parsed)
			}
			cert := createTestCertificateWithURIs(t, "test", uris)

			cfg := MTLSConfig{
				RequireClientCert: true,
				AllowedURISANs:    tt.allowedURIs,
			}
			middleware := MTLSMiddleware(cfg)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.TLS = &tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if tt.expectAllow && rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
			if !tt.expectAllow && rec.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", rec.Code)
			}
		})
	}
}

func TestGetMTLSIdentity_NoIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	identity := GetMTLSIdentity(req.Context())

	if identity != nil {
		t.Error("expected nil identity")
	}
}

func TestValidateSPIFFEID(t *testing.T) {
	tests := []struct {
		uri   string
		valid bool
	}{
		{"spiffe://cluster.local/ns/default/sa/api", true},
		{"spiffe://trust-domain/workload", true},
		{"spiffe://domain", true},
		{"spiffe://", false},
		{"spiffe:///", false},
		{"http://example.com", false},
		{"spiffe://domain:8080/path", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := ValidateSPIFFEID(tt.uri)
			if result != tt.valid {
				t.Errorf("ValidateSPIFFEID(%s) = %v, expected %v", tt.uri, result, tt.valid)
			}
		})
	}
}

func TestExtractSPIFFETrustDomain(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{"spiffe://cluster.local/ns/default/sa/api", "cluster.local"},
		{"spiffe://example.com/workload", "example.com"},
		{"spiffe://domain", "domain"},
		{"http://example.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := ExtractSPIFFETrustDomain(tt.uri)
			if result != tt.expected {
				t.Errorf("ExtractSPIFFETrustDomain(%s) = %s, expected %s", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestExtractSPIFFEWorkloadPath(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{"spiffe://cluster.local/ns/default/sa/api", "/ns/default/sa/api"},
		{"spiffe://example.com/workload", "/workload"},
		{"spiffe://domain", ""},
		{"http://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			result := ExtractSPIFFEWorkloadPath(tt.uri)
			if result != tt.expected {
				t.Errorf("ExtractSPIFFEWorkloadPath(%s) = %s, expected %s", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		str     string
		match   bool
	}{
		{"exact", "exact", true},
		{"exact", "different", false},
		{"prefix*", "prefix-suffix", true},
		{"prefix*", "other", false},
		{"*suffix", "prefix-suffix", true},
		{"*suffix", "other", false},
		{"pre*suf", "pre-middle-suf", true},
		{"pre*suf", "pre-suf", true},
		{"pre*suf", "presuf", true},
		{"pre*suf", "other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.str, func(t *testing.T) {
			result := matchWildcard(tt.pattern, tt.str)
			if result != tt.match {
				t.Errorf("matchWildcard(%s, %s) = %v, expected %v", tt.pattern, tt.str, result, tt.match)
			}
		})
	}
}

func TestMTLSIdentity_Fields(t *testing.T) {
	uris := []*url.URL{
		{Scheme: "spiffe", Host: "cluster.local", Path: "/ns/default/sa/api"},
	}
	cert := createTestCertificateWithAll(t, "test-cn", []string{"Org1"}, []string{"OU1"}, []string{"test.example.com"}, uris, []string{"test@example.com"})

	identity := extractMTLSIdentity(cert)

	if identity.CommonName != "test-cn" {
		t.Errorf("expected CN 'test-cn', got '%s'", identity.CommonName)
	}
	if len(identity.Organization) != 1 || identity.Organization[0] != "Org1" {
		t.Errorf("expected Organization ['Org1'], got %v", identity.Organization)
	}
	if len(identity.OrganizationalUnit) != 1 || identity.OrganizationalUnit[0] != "OU1" {
		t.Errorf("expected OU ['OU1'], got %v", identity.OrganizationalUnit)
	}
	if len(identity.DNSNames) != 1 || identity.DNSNames[0] != "test.example.com" {
		t.Errorf("expected DNSNames ['test.example.com'], got %v", identity.DNSNames)
	}
	if len(identity.URIs) != 1 || identity.URIs[0] != "spiffe://cluster.local/ns/default/sa/api" {
		t.Errorf("expected URIs, got %v", identity.URIs)
	}
	if len(identity.EmailAddresses) != 1 || identity.EmailAddresses[0] != "test@example.com" {
		t.Errorf("expected EmailAddresses ['test@example.com'], got %v", identity.EmailAddresses)
	}
	if identity.Certificate != cert {
		t.Error("expected certificate reference")
	}
}

// Helper functions to create test certificates

func createTestCertificate(t *testing.T, cn string, dnsNames []string, uris []*url.URL) *x509.Certificate {
	t.Helper()
	return createTestCertificateWithAll(t, cn, nil, nil, dnsNames, uris, nil)
}

func createTestCertificateWithOrg(t *testing.T, cn string, orgs []string, ous []string) *x509.Certificate {
	t.Helper()
	return createTestCertificateWithAll(t, cn, orgs, ous, nil, nil, nil)
}

func createTestCertificateWithURIs(t *testing.T, cn string, uris []*url.URL) *x509.Certificate {
	t.Helper()
	return createTestCertificateWithAll(t, cn, nil, nil, nil, uris, nil)
}

func createTestCertificateWithAll(t *testing.T, cn string, orgs []string, ous []string, dnsNames []string, uris []*url.URL, emails []string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       orgs,
			OrganizationalUnit: ous,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		URIs:                  uris,
		EmailAddresses:        emails,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
