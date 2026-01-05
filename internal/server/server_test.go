package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "gateway.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return configPath
}

func TestLoomStructFields(t *testing.T) {
	// Test that the Loom struct has expected fields
	lm := &Loom{}

	// These should all be nil initially
	if lm.config != nil {
		t.Error("expected nil config")
	}
	if lm.router != nil {
		t.Error("expected nil router")
	}
	if lm.upstreams != nil {
		t.Error("expected nil upstreams")
	}
	if lm.healthCheck != nil {
		t.Error("expected nil healthCheck")
	}
	if lm.pluginRT != nil {
		t.Error("expected nil pluginRT")
	}
	if lm.pipeline != nil {
		t.Error("expected nil pipeline")
	}
	if lm.listeners != nil {
		t.Error("expected nil listeners")
	}
	if lm.adminServer != nil {
		t.Error("expected nil adminServer")
	}
	if lm.metrics != nil {
		t.Error("expected nil metrics")
	}
	if lm.rateLimiter != nil {
		t.Error("expected nil rateLimiter")
	}
	if lm.tracing != nil {
		t.Error("expected nil tracing")
	}
	if lm.wsHandler != nil {
		t.Error("expected nil wsHandler")
	}
	if lm.logger != nil {
		t.Error("expected nil logger")
	}
}

func TestRunWithInvalidConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, "/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config")
	}
}

func TestRunWithInvalidYAML(t *testing.T) {
	content := `
this is not valid yaml [
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, configPath)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestRunWithMissingListeners(t *testing.T) {
	content := `
# No listeners
routes:
  - id: api
    path: /api/*
    upstream: backend
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, configPath)
	if err == nil {
		t.Error("expected error for missing listeners")
	}
}

func TestRunWithMissingUpstreams(t *testing.T) {
	content := `
listeners:
  - name: http
    address: ":0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, configPath)
	if err == nil {
		t.Error("expected error for missing upstream")
	}
}

func TestRunWithValidConfig(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithAdminEnabled(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090

admin:
  enabled: true
  address: "127.0.0.1:0"
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithRateLimitEnabled(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090

rate_limit:
  enabled: true
  rate: 100
  burst: 200
  cleanup_interval: 5m
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithCORSEnabled(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090

cors:
  enabled: true
  allow_origins:
    - "*"
  allow_methods:
    - GET
    - POST
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithFullConfig(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend
    methods:
      - GET
      - POST
    priority: 100

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s
      timeout: 5s
      healthy_threshold: 2
      unhealthy_threshold: 3

admin:
  enabled: true
  address: "127.0.0.1:0"

metrics:
  prometheus:
    enabled: true
    path: /metrics

rate_limit:
  enabled: true
  rate: 100
  burst: 200

cors:
  enabled: true
  allow_origins:
    - "*"
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithMultipleListeners(t *testing.T) {
	content := `
listeners:
  - name: http1
    address: "127.0.0.1:0"
    protocol: http
  - name: http2
    address: "127.0.0.1:0"
    protocol: http
  - name: h2c
    address: "127.0.0.1:0"
    protocol: h2c

routes:
  - id: api
    path: /api/*
    upstream: backend

upstreams:
  - name: backend
    endpoints:
      - localhost:9090
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}

func TestRunWithMultipleUpstreams(t *testing.T) {
	content := `
listeners:
  - name: http
    address: "127.0.0.1:0"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend1
  - id: admin
    path: /admin/*
    upstream: backend2

upstreams:
  - name: backend1
    endpoints:
      - localhost:9090
      - localhost:9091
  - name: backend2
    endpoints:
      - localhost:9092
`
	configPath := createTempConfig(t, content)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, configPath)
	}()

	// Give it time to start
	time.Sleep(300 * time.Millisecond)

	// Trigger shutdown
	cancel()

	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for shutdown")
	}
}
