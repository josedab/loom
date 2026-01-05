// Package middleware provides built-in HTTP middleware components.
package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting.
type RateLimiter struct {
	rate       float64 // tokens per second
	burst      int     // maximum bucket size
	buckets    map[string]*bucket
	mu         sync.RWMutex
	keyFunc    KeyFunc
	cleanupInt time.Duration
	stopCh     chan struct{}
}

// KeyFunc extracts the rate limit key from a request.
type KeyFunc func(*http.Request) string

// bucket represents a token bucket for a single key.
type bucket struct {
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// RateLimiterConfig configures the rate limiter.
type RateLimiterConfig struct {
	Rate            float64       // Requests per second
	Burst           int           // Maximum burst size
	KeyFunc         KeyFunc       // Function to extract key (default: client IP)
	CleanupInterval time.Duration // Interval to clean up old buckets
	TrustedProxies  []string      // CIDR ranges of trusted proxies (e.g., "10.0.0.0/8", "192.168.1.0/24")
}

// TrustedProxyExtractor extracts client IP considering trusted proxies.
type TrustedProxyExtractor struct {
	trustedNets []*net.IPNet
}

// NewTrustedProxyExtractor creates an extractor with the given trusted CIDR ranges.
func NewTrustedProxyExtractor(trustedCIDRs []string) *TrustedProxyExtractor {
	tpe := &TrustedProxyExtractor{
		trustedNets: make([]*net.IPNet, 0, len(trustedCIDRs)),
	}
	for _, cidr := range trustedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as single IP
			if ip := net.ParseIP(cidr); ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				ipNet = &net.IPNet{IP: ip, Mask: mask}
			} else {
				continue // Skip invalid entries
			}
		}
		tpe.trustedNets = append(tpe.trustedNets, ipNet)
	}
	return tpe
}

// isTrusted checks if the IP is from a trusted proxy.
func (tpe *TrustedProxyExtractor) isTrusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, ipNet := range tpe.trustedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parseIP extracts the IP from an address string (may include port).
func parseIP(addr string) net.IP {
	// Handle host:port format
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(addr)
}

// GetClientIP extracts the real client IP, only trusting X-Forwarded-For
// if the direct connection is from a trusted proxy.
func (tpe *TrustedProxyExtractor) GetClientIP(r *http.Request) string {
	// Get the direct connection IP
	remoteIP := parseIP(r.RemoteAddr)

	// If no trusted proxies configured or remote is not trusted, use RemoteAddr
	if len(tpe.trustedNets) == 0 || !tpe.isTrusted(remoteIP) {
		if remoteIP != nil {
			return remoteIP.String()
		}
		return r.RemoteAddr
	}

	// Remote is trusted, check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For format: client, proxy1, proxy2, ...
		// We need to find the rightmost untrusted IP
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			ip := parseIP(strings.TrimSpace(ips[i]))
			if ip != nil && !tpe.isTrusted(ip) {
				return ip.String()
			}
		}
	}

	// Check X-Real-IP as fallback
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := parseIP(strings.TrimSpace(xri)); ip != nil {
			return ip.String()
		}
	}

	// All IPs in chain are trusted, use the leftmost (original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			if ip := parseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip.String()
			}
		}
	}

	// Fallback to direct connection
	if remoteIP != nil {
		return remoteIP.String()
	}
	return r.RemoteAddr
}

// KeyFunc returns a KeyFunc that uses this extractor.
func (tpe *TrustedProxyExtractor) KeyFunc() KeyFunc {
	return func(r *http.Request) string {
		return tpe.GetClientIP(r)
	}
}

// DefaultKeyFunc returns the client IP as the rate limit key.
// SECURITY WARNING: This function trusts X-Forwarded-For and X-Real-IP headers,
// which can be spoofed. For production behind reverse proxies, use
// NewTrustedProxyExtractor with your trusted proxy CIDRs instead.
func DefaultKeyFunc(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take just the first IP (client IP in standard X-Forwarded-For format)
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr (strip port if present)
	if ip := parseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return r.RemoteAddr
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 100 // Default: 100 requests per second
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.Rate) // Default: burst = rate
	}
	if cfg.KeyFunc == nil {
		// Use trusted proxy extractor if trusted proxies are configured
		if len(cfg.TrustedProxies) > 0 {
			extractor := NewTrustedProxyExtractor(cfg.TrustedProxies)
			cfg.KeyFunc = extractor.KeyFunc()
		} else {
			cfg.KeyFunc = DefaultKeyFunc
		}
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}

	rl := &RateLimiter{
		rate:       cfg.Rate,
		burst:      cfg.Burst,
		buckets:    make(map[string]*bucket),
		keyFunc:    cfg.KeyFunc,
		cleanupInt: cfg.CleanupInterval,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request is allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		if b, exists = rl.buckets[key]; !exists {
			b = &bucket{
				tokens:     float64(rl.burst),
				lastUpdate: time.Now(),
			}
			rl.buckets[key] = b
		}
		rl.mu.Unlock()
	}

	return b.take(rl.rate, rl.burst)
}

// take attempts to take a token from the bucket.
func (b *bucket) take(rate float64, burst int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastUpdate).Seconds()
	b.lastUpdate = now

	// Add tokens based on elapsed time
	b.tokens += elapsed * rate
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}

	// Try to take a token
	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// cleanup periodically removes old buckets.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.doCleanup()
		}
	}
}

// doCleanup removes buckets that haven't been used recently.
func (rl *RateLimiter) doCleanup() {
	threshold := time.Now().Add(-rl.cleanupInt * 2)

	// First pass: collect keys to delete (read lock only)
	var keysToDelete []string

	rl.mu.RLock()
	for key, b := range rl.buckets {
		b.mu.Lock()
		shouldDelete := b.lastUpdate.Before(threshold)
		b.mu.Unlock()
		if shouldDelete {
			keysToDelete = append(keysToDelete, key)
		}
	}
	rl.mu.RUnlock()

	// Second pass: delete collected keys (write lock, no iteration)
	if len(keysToDelete) > 0 {
		rl.mu.Lock()
		for _, key := range keysToDelete {
			// Re-check before deleting in case bucket was accessed after first pass
			if b, exists := rl.buckets[key]; exists {
				b.mu.Lock()
				if b.lastUpdate.Before(threshold) {
					delete(rl.buckets, key)
				}
				b.mu.Unlock()
			}
		}
		rl.mu.Unlock()
	}
}

// Stop stops the rate limiter cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// Stats returns rate limiter statistics.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return RateLimiterStats{
		ActiveBuckets: len(rl.buckets),
		Rate:          rl.rate,
		Burst:         rl.burst,
	}
}

// RateLimiterStats contains rate limiter statistics.
type RateLimiterStats struct {
	ActiveBuckets int
	Rate          float64
	Burst         int
}

// Middleware returns an HTTP middleware for rate limiting.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rl.keyFunc(r)

			if !rl.Allow(key) {
				w.Header().Set("X-RateLimit-Limit", formatFloat(rl.rate))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "1")
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// formatFloat formats a float64 for headers.
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// PerRouteRateLimiter provides rate limiting per route.
type PerRouteRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
	defaults RateLimiterConfig
}

// NewPerRouteRateLimiter creates a rate limiter that can have different limits per route.
func NewPerRouteRateLimiter(defaults RateLimiterConfig) *PerRouteRateLimiter {
	return &PerRouteRateLimiter{
		limiters: make(map[string]*RateLimiter),
		defaults: defaults,
	}
}

// SetRouteLimit sets the rate limit for a specific route.
func (prl *PerRouteRateLimiter) SetRouteLimit(routeID string, rate float64, burst int) {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	// Stop existing limiter if any
	if existing, ok := prl.limiters[routeID]; ok {
		existing.Stop()
	}

	prl.limiters[routeID] = NewRateLimiter(RateLimiterConfig{
		Rate:    rate,
		Burst:   burst,
		KeyFunc: prl.defaults.KeyFunc,
	})
}

// Allow checks if a request is allowed for a specific route.
func (prl *PerRouteRateLimiter) Allow(routeID, key string) bool {
	prl.mu.RLock()
	limiter, ok := prl.limiters[routeID]
	prl.mu.RUnlock()

	if !ok {
		// Use default limiter
		prl.mu.Lock()
		if limiter, ok = prl.limiters[routeID]; !ok {
			limiter = NewRateLimiter(prl.defaults)
			prl.limiters[routeID] = limiter
		}
		prl.mu.Unlock()
	}

	return limiter.Allow(key)
}

// Stop stops all rate limiters.
func (prl *PerRouteRateLimiter) Stop() {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	for _, limiter := range prl.limiters {
		limiter.Stop()
	}
}
