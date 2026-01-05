// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"net/http"
)

// SecurityHeadersConfig configures security headers.
type SecurityHeadersConfig struct {
	// HSTS settings
	HSTSEnabled           bool
	HSTSMaxAge            int
	HSTSIncludeSubDomains bool
	HSTSPreload           bool

	// Content Security Policy
	ContentSecurityPolicy string

	// Other security headers
	XContentTypeOptions   string // default: nosniff
	XFrameOptions         string // default: DENY
	XXSSProtection        string // default: 1; mode=block
	ReferrerPolicy        string // default: strict-origin-when-cross-origin
	PermissionsPolicy     string

	// Custom headers
	CustomHeaders map[string]string
}

// DefaultSecurityHeadersConfig returns default security headers configuration.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubDomains: true,
		HSTSPreload:           false,
		XContentTypeOptions:   "nosniff",
		XFrameOptions:         "DENY",
		XXSSProtection:        "1; mode=block",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}
}

// SecurityHeadersMiddleware adds security headers to responses.
func SecurityHeadersMiddleware(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// X-Content-Type-Options
			if cfg.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", cfg.XContentTypeOptions)
			}

			// X-Frame-Options
			if cfg.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", cfg.XFrameOptions)
			}

			// X-XSS-Protection
			if cfg.XXSSProtection != "" {
				w.Header().Set("X-XSS-Protection", cfg.XXSSProtection)
			}

			// Referrer-Policy
			if cfg.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
			}

			// Content-Security-Policy
			if cfg.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
			}

			// Permissions-Policy
			if cfg.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", cfg.PermissionsPolicy)
			}

			// HSTS (only for HTTPS)
			if cfg.HSTSEnabled && r.TLS != nil {
				hstsValue := "max-age=" + itoa(cfg.HSTSMaxAge)
				if cfg.HSTSIncludeSubDomains {
					hstsValue += "; includeSubDomains"
				}
				if cfg.HSTSPreload {
					hstsValue += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Custom headers
			for k, v := range cfg.CustomHeaders {
				w.Header().Set(k, v)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// itoa converts int to string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	neg := i < 0
	if neg {
		i = -i
	}

	var buf [20]byte
	pos := len(buf)

	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}

	if neg {
		pos--
		buf[pos] = '-'
	}

	return string(buf[pos:])
}
