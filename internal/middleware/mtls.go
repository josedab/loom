// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
)

// MTLSConfig configures mutual TLS authentication middleware.
type MTLSConfig struct {
	// RequireClientCert requires a valid client certificate.
	// If false, requests without certificates are allowed through.
	RequireClientCert bool

	// AllowedCNs is a list of allowed Common Names.
	// If empty, all valid certificates are allowed.
	AllowedCNs []string

	// AllowedOUs is a list of allowed Organizational Units.
	// If empty, all OUs are allowed.
	AllowedOUs []string

	// AllowedOrgs is a list of allowed Organizations.
	// If empty, all organizations are allowed.
	AllowedOrgs []string

	// AllowedDNSSANs is a list of allowed DNS Subject Alternative Names.
	// If empty, DNS SANs are not checked.
	AllowedDNSSANs []string

	// AllowedURISANs is a list of allowed URI Subject Alternative Names.
	// Supports wildcards like "spiffe://cluster.local/*".
	AllowedURISANs []string

	// ExcludedPaths are paths that don't require mTLS.
	ExcludedPaths []string

	// ExtractIdentity if true, extracts client identity to context.
	ExtractIdentity bool
}

// MTLSIdentity contains the client identity extracted from a certificate.
type MTLSIdentity struct {
	// CommonName is the certificate's Common Name.
	CommonName string

	// Organization is the certificate's Organization.
	Organization []string

	// OrganizationalUnit is the certificate's Organizational Unit.
	OrganizationalUnit []string

	// DNSNames are the DNS Subject Alternative Names.
	DNSNames []string

	// URIs are the URI Subject Alternative Names.
	URIs []string

	// EmailAddresses are email Subject Alternative Names.
	EmailAddresses []string

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// Issuer is the certificate issuer's Common Name.
	Issuer string

	// Certificate is the verified client certificate.
	Certificate *x509.Certificate
}

// MTLSIdentityContextKey is the context key for mTLS identity.
type MTLSIdentityContextKey struct{}

// DefaultMTLSConfig returns default mTLS configuration.
func DefaultMTLSConfig() MTLSConfig {
	return MTLSConfig{
		RequireClientCert: true,
		ExtractIdentity:   true,
		ExcludedPaths:     []string{"/health", "/healthz", "/ready"},
	}
}

// MTLSMiddleware provides mutual TLS authentication.
func MTLSMiddleware(cfg MTLSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			for _, path := range cfg.ExcludedPaths {
				if matchPath(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if TLS connection exists
			if r.TLS == nil {
				if cfg.RequireClientCert {
					http.Error(w, "TLS required", http.StatusBadRequest)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Check for verified client certificates
			if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
				if cfg.RequireClientCert {
					http.Error(w, "Client certificate required", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Get the client certificate (first cert in first verified chain)
			clientCert := r.TLS.VerifiedChains[0][0]

			// Validate Common Name
			if len(cfg.AllowedCNs) > 0 {
				if !containsString(cfg.AllowedCNs, clientCert.Subject.CommonName) {
					http.Error(w, fmt.Sprintf("Certificate CN '%s' not allowed", clientCert.Subject.CommonName), http.StatusForbidden)
					return
				}
			}

			// Validate Organization
			if len(cfg.AllowedOrgs) > 0 {
				found := false
				for _, org := range clientCert.Subject.Organization {
					if containsString(cfg.AllowedOrgs, org) {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Certificate organization not allowed", http.StatusForbidden)
					return
				}
			}

			// Validate Organizational Unit
			if len(cfg.AllowedOUs) > 0 {
				found := false
				for _, ou := range clientCert.Subject.OrganizationalUnit {
					if containsString(cfg.AllowedOUs, ou) {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Certificate organizational unit not allowed", http.StatusForbidden)
					return
				}
			}

			// Validate DNS SANs
			if len(cfg.AllowedDNSSANs) > 0 {
				found := false
				for _, dns := range clientCert.DNSNames {
					if matchWildcardString(cfg.AllowedDNSSANs, dns) {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Certificate DNS SAN not allowed", http.StatusForbidden)
					return
				}
			}

			// Validate URI SANs (commonly used for SPIFFE IDs)
			if len(cfg.AllowedURISANs) > 0 {
				found := false
				for _, uri := range clientCert.URIs {
					if matchWildcardString(cfg.AllowedURISANs, uri.String()) {
						found = true
						break
					}
				}
				if !found {
					http.Error(w, "Certificate URI SAN not allowed", http.StatusForbidden)
					return
				}
			}

			// Extract identity to context if enabled
			if cfg.ExtractIdentity {
				identity := extractMTLSIdentity(clientCert)
				ctx := context.WithValue(r.Context(), MTLSIdentityContextKey{}, identity)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetMTLSIdentity extracts mTLS identity from context.
func GetMTLSIdentity(ctx context.Context) *MTLSIdentity {
	if identity, ok := ctx.Value(MTLSIdentityContextKey{}).(*MTLSIdentity); ok {
		return identity
	}
	return nil
}

// extractMTLSIdentity creates an MTLSIdentity from a certificate.
func extractMTLSIdentity(cert *x509.Certificate) *MTLSIdentity {
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	return &MTLSIdentity{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		DNSNames:           cert.DNSNames,
		URIs:               uris,
		EmailAddresses:     cert.EmailAddresses,
		SerialNumber:       cert.SerialNumber.String(),
		Issuer:             cert.Issuer.CommonName,
		Certificate:        cert,
	}
}

// containsString checks if a slice contains a string (case-sensitive).
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// matchWildcardString checks if any pattern in the slice matches the string.
// Supports * as a wildcard for any characters.
func matchWildcardString(patterns []string, str string) bool {
	for _, pattern := range patterns {
		if matchWildcard(pattern, str) {
			return true
		}
	}
	return false
}

// matchWildcard matches a string against a pattern with * wildcard.
func matchWildcard(pattern, str string) bool {
	// Exact match
	if pattern == str {
		return true
	}

	// Handle trailing wildcard (most common case for SPIFFE)
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(str, prefix)
	}

	// Handle leading wildcard
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(str, suffix)
	}

	// Handle middle wildcard
	if idx := strings.Index(pattern, "*"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return strings.HasPrefix(str, prefix) && strings.HasSuffix(str, suffix)
	}

	return false
}

// matchPath checks if a request path matches an excluded path pattern.
func matchPath(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		return path == pattern[:len(pattern)-2] || strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	return path == pattern || strings.HasPrefix(path, pattern+"/")
}

// ValidateSPIFFEID validates that a URI SAN is a valid SPIFFE ID.
// SPIFFE IDs have the format: spiffe://<trust-domain>/<workload-path>
func ValidateSPIFFEID(uri string) bool {
	if !strings.HasPrefix(uri, "spiffe://") {
		return false
	}
	// Must have at least trust domain
	rest := strings.TrimPrefix(uri, "spiffe://")
	if rest == "" || rest == "/" {
		return false
	}
	// Trust domain cannot contain certain characters
	parts := strings.SplitN(rest, "/", 2)
	trustDomain := parts[0]
	if trustDomain == "" || strings.ContainsAny(trustDomain, ":@") {
		return false
	}
	return true
}

// ExtractSPIFFETrustDomain extracts the trust domain from a SPIFFE ID.
func ExtractSPIFFETrustDomain(spiffeID string) string {
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return ""
	}
	rest := strings.TrimPrefix(spiffeID, "spiffe://")
	parts := strings.SplitN(rest, "/", 2)
	return parts[0]
}

// ExtractSPIFFEWorkloadPath extracts the workload path from a SPIFFE ID.
func ExtractSPIFFEWorkloadPath(spiffeID string) string {
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return ""
	}
	rest := strings.TrimPrefix(spiffeID, "spiffe://")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	return "/" + parts[1]
}
