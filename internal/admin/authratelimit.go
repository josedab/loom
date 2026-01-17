// Package admin provides the administrative API for the gateway.
package admin

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthRateLimitConfig configures authentication rate limiting.
type AuthRateLimitConfig struct {
	// MaxAttempts is the maximum number of auth attempts per window.
	// Default: 5
	MaxAttempts int

	// Window is the time window for rate limiting.
	// Default: 1 minute
	Window time.Duration

	// LockoutDuration is how long to lock out after max attempts exceeded.
	// Default: 15 minutes
	LockoutDuration time.Duration

	// CleanupInterval is how often to clean up old entries.
	// Default: 5 minutes
	CleanupInterval time.Duration

	// Enabled enables auth rate limiting.
	Enabled bool
}

// DefaultAuthRateLimitConfig returns sensible defaults for auth rate limiting.
func DefaultAuthRateLimitConfig() AuthRateLimitConfig {
	return AuthRateLimitConfig{
		MaxAttempts:     5,
		Window:          1 * time.Minute,
		LockoutDuration: 15 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		Enabled:         true,
	}
}

// authAttempt tracks authentication attempts for a client.
type authAttempt struct {
	attempts   int
	windowStart time.Time
	lockedUntil time.Time
}

// AuthRateLimiter rate limits authentication attempts per client IP.
type AuthRateLimiter struct {
	config   AuthRateLimitConfig
	attempts map[string]*authAttempt
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// NewAuthRateLimiter creates a new authentication rate limiter.
func NewAuthRateLimiter(cfg AuthRateLimitConfig) *AuthRateLimiter {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = 1 * time.Minute
	}
	if cfg.LockoutDuration <= 0 {
		cfg.LockoutDuration = 15 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}

	arl := &AuthRateLimiter{
		config:   cfg,
		attempts: make(map[string]*authAttempt),
		stopCh:   make(chan struct{}),
	}

	if cfg.Enabled {
		go arl.cleanup()
	}

	return arl
}

// CheckAllowed checks if an authentication attempt is allowed for the given IP.
// Returns true if allowed, false if rate limited.
func (arl *AuthRateLimiter) CheckAllowed(clientIP string) bool {
	if !arl.config.Enabled {
		return true
	}

	now := time.Now()

	arl.mu.RLock()
	attempt, exists := arl.attempts[clientIP]
	arl.mu.RUnlock()

	if !exists {
		return true
	}

	// Check if locked out
	if now.Before(attempt.lockedUntil) {
		return false
	}

	// If lockout has expired, allow access (RecordAttempt will reset)
	if !attempt.lockedUntil.IsZero() {
		return true
	}

	// Check if window has expired
	if now.Sub(attempt.windowStart) > arl.config.Window {
		return true
	}

	// Check if under limit
	return attempt.attempts < arl.config.MaxAttempts
}

// RecordAttempt records an authentication attempt.
// Returns true if the attempt is allowed, false if rate limited.
func (arl *AuthRateLimiter) RecordAttempt(clientIP string, success bool) bool {
	if !arl.config.Enabled {
		return true
	}

	now := time.Now()

	arl.mu.Lock()
	defer arl.mu.Unlock()

	attempt, exists := arl.attempts[clientIP]
	if !exists {
		attempt = &authAttempt{
			windowStart: now,
		}
		arl.attempts[clientIP] = attempt
	}

	// Check if locked out
	if now.Before(attempt.lockedUntil) {
		return false
	}

	// If lockout has expired, reset
	if !attempt.lockedUntil.IsZero() {
		attempt.attempts = 0
		attempt.windowStart = now
		attempt.lockedUntil = time.Time{}
	}

	// Check if window has expired, reset if so
	if now.Sub(attempt.windowStart) > arl.config.Window {
		attempt.attempts = 0
		attempt.windowStart = now
	}

	// If successful auth, reset the counter
	if success {
		attempt.attempts = 0
		attempt.windowStart = now
		return true
	}

	// Failed attempt
	attempt.attempts++

	// Check if we've reached max attempts - set lockout for future requests
	// The current attempt is still allowed (we passed the lockout check above)
	if attempt.attempts >= arl.config.MaxAttempts {
		attempt.lockedUntil = now.Add(arl.config.LockoutDuration)
	}

	return true
}

// RemainingAttempts returns the number of remaining auth attempts for the IP.
func (arl *AuthRateLimiter) RemainingAttempts(clientIP string) int {
	if !arl.config.Enabled {
		return arl.config.MaxAttempts
	}

	now := time.Now()

	arl.mu.RLock()
	defer arl.mu.RUnlock()

	attempt, exists := arl.attempts[clientIP]
	if !exists {
		return arl.config.MaxAttempts
	}

	// Check if locked out
	if now.Before(attempt.lockedUntil) {
		return 0
	}

	// Check if window has expired
	if now.Sub(attempt.windowStart) > arl.config.Window {
		return arl.config.MaxAttempts
	}

	remaining := arl.config.MaxAttempts - attempt.attempts
	if remaining < 0 {
		return 0
	}
	return remaining
}

// IsLockedOut checks if the IP is currently locked out.
func (arl *AuthRateLimiter) IsLockedOut(clientIP string) bool {
	if !arl.config.Enabled {
		return false
	}

	arl.mu.RLock()
	defer arl.mu.RUnlock()

	attempt, exists := arl.attempts[clientIP]
	if !exists {
		return false
	}

	return time.Now().Before(attempt.lockedUntil)
}

// LockoutRemaining returns how long until the lockout expires.
func (arl *AuthRateLimiter) LockoutRemaining(clientIP string) time.Duration {
	if !arl.config.Enabled {
		return 0
	}

	arl.mu.RLock()
	defer arl.mu.RUnlock()

	attempt, exists := arl.attempts[clientIP]
	if !exists {
		return 0
	}

	if time.Now().Before(attempt.lockedUntil) {
		return time.Until(attempt.lockedUntil)
	}
	return 0
}

// cleanup periodically removes expired entries.
func (arl *AuthRateLimiter) cleanup() {
	ticker := time.NewTicker(arl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-arl.stopCh:
			return
		case <-ticker.C:
			arl.doCleanup()
		}
	}
}

// doCleanup removes entries that are no longer needed.
func (arl *AuthRateLimiter) doCleanup() {
	now := time.Now()
	threshold := arl.config.Window * 2

	arl.mu.Lock()
	defer arl.mu.Unlock()

	for ip, attempt := range arl.attempts {
		// Remove if not locked out and window has long expired
		if now.After(attempt.lockedUntil) && now.Sub(attempt.windowStart) > threshold {
			delete(arl.attempts, ip)
		}
	}
}

// Stop stops the cleanup goroutine.
func (arl *AuthRateLimiter) Stop() {
	close(arl.stopCh)
}

// Stats returns current statistics.
func (arl *AuthRateLimiter) Stats() AuthRateLimiterStats {
	arl.mu.RLock()
	defer arl.mu.RUnlock()

	now := time.Now()
	lockedOut := 0
	for _, attempt := range arl.attempts {
		if now.Before(attempt.lockedUntil) {
			lockedOut++
		}
	}

	return AuthRateLimiterStats{
		TrackedIPs:    len(arl.attempts),
		LockedOutIPs:  lockedOut,
		MaxAttempts:   arl.config.MaxAttempts,
		WindowSeconds: int(arl.config.Window.Seconds()),
	}
}

// AuthRateLimiterStats contains rate limiter statistics.
type AuthRateLimiterStats struct {
	TrackedIPs    int
	LockedOutIPs  int
	MaxAttempts   int
	WindowSeconds int
}

// getClientIP extracts the client IP from the request.
func getAuthClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
