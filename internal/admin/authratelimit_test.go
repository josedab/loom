package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultAuthRateLimitConfig(t *testing.T) {
	cfg := DefaultAuthRateLimitConfig()

	if cfg.MaxAttempts != 5 {
		t.Errorf("expected MaxAttempts 5, got %d", cfg.MaxAttempts)
	}
	if cfg.Window != 1*time.Minute {
		t.Errorf("expected Window 1m, got %v", cfg.Window)
	}
	if cfg.LockoutDuration != 15*time.Minute {
		t.Errorf("expected LockoutDuration 15m, got %v", cfg.LockoutDuration)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
}

func TestNewAuthRateLimiter(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts:     3,
		Window:          30 * time.Second,
		LockoutDuration: 5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		Enabled:         true,
	}

	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	if arl.config.MaxAttempts != 3 {
		t.Errorf("expected MaxAttempts 3, got %d", arl.config.MaxAttempts)
	}
}

func TestNewAuthRateLimiter_Defaults(t *testing.T) {
	cfg := AuthRateLimitConfig{Enabled: true}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	if arl.config.MaxAttempts != 5 {
		t.Errorf("expected default MaxAttempts 5, got %d", arl.config.MaxAttempts)
	}
	if arl.config.Window != 1*time.Minute {
		t.Errorf("expected default Window 1m, got %v", arl.config.Window)
	}
}

func TestAuthRateLimiter_Disabled(t *testing.T) {
	arl := NewAuthRateLimiter(AuthRateLimitConfig{Enabled: false})

	// Should always allow when disabled
	for i := 0; i < 100; i++ {
		if !arl.CheckAllowed("192.168.1.1") {
			t.Error("should always allow when disabled")
		}
		if !arl.RecordAttempt("192.168.1.1", false) {
			t.Error("should always allow when disabled")
		}
	}
}

func TestAuthRateLimiter_AllowsInitialAttempts(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts: 3,
		Window:      1 * time.Minute,
		Enabled:     true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// First 3 attempts should be allowed
	for i := 0; i < 3; i++ {
		if !arl.CheckAllowed("192.168.1.1") {
			t.Errorf("attempt %d should be allowed", i+1)
		}
		if !arl.RecordAttempt("192.168.1.1", false) {
			t.Errorf("attempt %d should return true", i+1)
		}
	}

	// 4th attempt should be blocked
	if arl.CheckAllowed("192.168.1.1") {
		t.Error("4th attempt should be blocked")
	}
}

func TestAuthRateLimiter_DifferentIPs(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts: 2,
		Window:      1 * time.Minute,
		Enabled:     true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Use up attempts for IP1
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.1", false)

	// IP1 should be blocked
	if arl.CheckAllowed("192.168.1.1") {
		t.Error("192.168.1.1 should be blocked")
	}

	// IP2 should still be allowed
	if !arl.CheckAllowed("192.168.1.2") {
		t.Error("192.168.1.2 should be allowed")
	}
}

func TestAuthRateLimiter_SuccessResetsCounter(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts: 3,
		Window:      1 * time.Minute,
		Enabled:     true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Record 2 failed attempts
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.1", false)

	// Record successful attempt
	arl.RecordAttempt("192.168.1.1", true)

	// Should be allowed again (counter reset)
	if !arl.CheckAllowed("192.168.1.1") {
		t.Error("should be allowed after successful auth")
	}

	// Should have 3 remaining attempts
	remaining := arl.RemainingAttempts("192.168.1.1")
	if remaining != 3 {
		t.Errorf("expected 3 remaining attempts, got %d", remaining)
	}
}

func TestAuthRateLimiter_Lockout(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts:     2,
		Window:          1 * time.Minute,
		LockoutDuration: 100 * time.Millisecond,
		Enabled:         true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Exhaust attempts
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.1", false)

	// Should be locked out
	if !arl.IsLockedOut("192.168.1.1") {
		t.Error("should be locked out")
	}

	// Wait for lockout to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if arl.IsLockedOut("192.168.1.1") {
		t.Error("should not be locked out after lockout expires")
	}
	if !arl.CheckAllowed("192.168.1.1") {
		t.Error("should be allowed after lockout expires")
	}
}

func TestAuthRateLimiter_RemainingAttempts(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts: 5,
		Window:      1 * time.Minute,
		Enabled:     true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// New IP should have max attempts
	if remaining := arl.RemainingAttempts("192.168.1.1"); remaining != 5 {
		t.Errorf("expected 5 remaining, got %d", remaining)
	}

	// After 2 failed attempts
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.1", false)

	if remaining := arl.RemainingAttempts("192.168.1.1"); remaining != 3 {
		t.Errorf("expected 3 remaining, got %d", remaining)
	}
}

func TestAuthRateLimiter_LockoutRemaining(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts:     1,
		Window:          1 * time.Minute,
		LockoutDuration: 1 * time.Second,
		Enabled:         true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Trigger lockout
	arl.RecordAttempt("192.168.1.1", false)

	remaining := arl.LockoutRemaining("192.168.1.1")
	if remaining <= 0 {
		t.Error("expected positive lockout remaining")
	}
	if remaining > 1*time.Second {
		t.Errorf("expected lockout remaining <= 1s, got %v", remaining)
	}
}

func TestAuthRateLimiter_Stats(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts: 2,
		Window:      1 * time.Minute,
		Enabled:     true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Add some IPs
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.2", false)
	arl.RecordAttempt("192.168.1.2", false) // Lock out this IP

	stats := arl.Stats()

	if stats.TrackedIPs != 2 {
		t.Errorf("expected 2 tracked IPs, got %d", stats.TrackedIPs)
	}
	if stats.LockedOutIPs != 1 {
		t.Errorf("expected 1 locked out IP, got %d", stats.LockedOutIPs)
	}
	if stats.MaxAttempts != 2 {
		t.Errorf("expected MaxAttempts 2, got %d", stats.MaxAttempts)
	}
}

func TestGetAuthClientIP(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		expectedIP string
	}{
		{
			name: "X-Forwarded-For single",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Forwarded-For multiple",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
			},
			expectedIP: "10.0.0.1",
		},
		{
			name: "X-Real-IP",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "10.0.0.5")
			},
			expectedIP: "10.0.0.5",
		},
		{
			name: "RemoteAddr fallback",
			setupReq: func(r *http.Request) {
				// No headers
			},
			expectedIP: "192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			ip := getAuthClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("expected %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestAuthRateLimiter_WindowExpiry(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts:     2,
		Window:          50 * time.Millisecond,
		LockoutDuration: 50 * time.Millisecond, // Short lockout for test
		Enabled:         true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Use all attempts (triggers lockout)
	arl.RecordAttempt("192.168.1.1", false)
	arl.RecordAttempt("192.168.1.1", false)

	// Should be at limit
	if arl.RemainingAttempts("192.168.1.1") != 0 {
		t.Error("should have 0 remaining")
	}

	// Wait for both window and lockout to expire
	time.Sleep(60 * time.Millisecond)

	// Should have full attempts again
	if !arl.CheckAllowed("192.168.1.1") {
		t.Error("should be allowed after window expires")
	}
}

func TestAuthRateLimiter_Cleanup(t *testing.T) {
	cfg := AuthRateLimitConfig{
		MaxAttempts:     2,
		Window:          10 * time.Millisecond,
		CleanupInterval: 20 * time.Millisecond,
		Enabled:         true,
	}
	arl := NewAuthRateLimiter(cfg)
	defer arl.Stop()

	// Record some attempts
	arl.RecordAttempt("192.168.1.1", false)

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Entry should have been cleaned up
	stats := arl.Stats()
	if stats.TrackedIPs != 0 {
		t.Errorf("expected 0 tracked IPs after cleanup, got %d", stats.TrackedIPs)
	}
}
