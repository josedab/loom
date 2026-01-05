// Package webhook provides a reliable webhook delivery system with retry logic,
// signature verification, and delivery status tracking.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Common errors.
var (
	ErrWebhookNotFound    = errors.New("webhook not found")
	ErrInvalidURL         = errors.New("invalid webhook URL")
	ErrInvalidSecret      = errors.New("invalid webhook secret")
	ErrDeliveryFailed     = errors.New("webhook delivery failed")
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	ErrWebhookDisabled    = errors.New("webhook is disabled")
	ErrInvalidSignature   = errors.New("invalid webhook signature")
	ErrPayloadTooLarge    = errors.New("payload too large")
)

// Webhook represents a registered webhook endpoint.
type Webhook struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret,omitempty"`
	Events      []string          `json:"events"`
	Headers     map[string]string `json:"headers,omitempty"`
	Enabled     bool              `json:"enabled"`
	Description string            `json:"description,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Event represents an event to be delivered via webhook.
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Source    string                 `json:"source,omitempty"`
}

// Delivery represents a webhook delivery attempt.
type Delivery struct {
	ID            string        `json:"id"`
	WebhookID     string        `json:"webhook_id"`
	EventID       string        `json:"event_id"`
	EventType     string        `json:"event_type"`
	URL           string        `json:"url"`
	Status        DeliveryStatus `json:"status"`
	StatusCode    int           `json:"status_code,omitempty"`
	RequestBody   string        `json:"request_body,omitempty"`
	ResponseBody  string        `json:"response_body,omitempty"`
	Attempts      int           `json:"attempts"`
	NextRetryAt   *time.Time    `json:"next_retry_at,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	CompletedAt   *time.Time    `json:"completed_at,omitempty"`
	Error         string        `json:"error,omitempty"`
	Duration      time.Duration `json:"duration_ms"`
}

// DeliveryStatus represents the status of a webhook delivery.
type DeliveryStatus string

const (
	DeliveryStatusPending   DeliveryStatus = "pending"
	DeliveryStatusDelivered DeliveryStatus = "delivered"
	DeliveryStatusFailed    DeliveryStatus = "failed"
	DeliveryStatusRetrying  DeliveryStatus = "retrying"
)

// RetryConfig configures retry behavior for webhook deliveries.
type RetryConfig struct {
	// MaxAttempts is the maximum number of delivery attempts.
	MaxAttempts int
	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration
	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration
	// Multiplier is the backoff multiplier.
	Multiplier float64
	// RetryableStatusCodes are HTTP status codes that should trigger a retry.
	RetryableStatusCodes []int
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:          5,
		InitialDelay:         time.Second,
		MaxDelay:             5 * time.Minute,
		Multiplier:           2.0,
		RetryableStatusCodes: []int{408, 429, 500, 502, 503, 504},
	}
}

// Manager manages webhooks and their deliveries.
type Manager struct {
	webhooks    map[string]*Webhook
	deliveries  map[string]*Delivery
	eventQueue  chan *queuedEvent
	mu          sync.RWMutex
	client      *http.Client
	retryConfig RetryConfig
	logger      *slog.Logger
	maxPayload  int64
	workers     int
	done        chan struct{}
	wg          sync.WaitGroup
}

type queuedEvent struct {
	webhook *Webhook
	event   *Event
}

// ManagerConfig configures the webhook manager.
type ManagerConfig struct {
	// HTTPClient for making webhook requests.
	HTTPClient *http.Client
	// RetryConfig for retry behavior.
	RetryConfig RetryConfig
	// Logger for webhook events.
	Logger *slog.Logger
	// MaxPayloadSize is the maximum payload size in bytes.
	MaxPayloadSize int64
	// Workers is the number of concurrent delivery workers.
	Workers int
	// QueueSize is the size of the event queue.
	QueueSize int
}

// NewManager creates a new webhook manager.
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxPayloadSize == 0 {
		cfg.MaxPayloadSize = 1024 * 1024 // 1MB default
	}
	if cfg.Workers == 0 {
		cfg.Workers = 5
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 1000
	}
	if cfg.RetryConfig.MaxAttempts == 0 {
		cfg.RetryConfig = DefaultRetryConfig()
	}

	m := &Manager{
		webhooks:    make(map[string]*Webhook),
		deliveries:  make(map[string]*Delivery),
		eventQueue:  make(chan *queuedEvent, cfg.QueueSize),
		client:      cfg.HTTPClient,
		retryConfig: cfg.RetryConfig,
		logger:      cfg.Logger,
		maxPayload:  cfg.MaxPayloadSize,
		workers:     cfg.Workers,
		done:        make(chan struct{}),
	}

	return m
}

// Start begins processing webhook deliveries.
func (m *Manager) Start() {
	for i := 0; i < m.workers; i++ {
		m.wg.Add(1)
		go m.worker(i)
	}
	m.logger.Info("webhook manager started", "workers", m.workers)
}

// Stop gracefully stops the webhook manager.
func (m *Manager) Stop() {
	close(m.done)
	m.wg.Wait()
	m.logger.Info("webhook manager stopped")
}

func (m *Manager) worker(id int) {
	defer m.wg.Done()

	for {
		select {
		case <-m.done:
			return
		case qe := <-m.eventQueue:
			if qe != nil {
				m.deliverWithRetry(context.Background(), qe.webhook, qe.event)
			}
		}
	}
}

// Register adds a new webhook.
func (m *Manager) Register(webhook *Webhook) error {
	if webhook.URL == "" {
		return ErrInvalidURL
	}
	if !strings.HasPrefix(webhook.URL, "http://") && !strings.HasPrefix(webhook.URL, "https://") {
		return ErrInvalidURL
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if webhook.ID == "" {
		webhook.ID = generateID()
	}
	webhook.CreatedAt = time.Now()
	webhook.UpdatedAt = webhook.CreatedAt
	if webhook.Events == nil {
		webhook.Events = []string{"*"}
	}

	m.webhooks[webhook.ID] = webhook
	m.logger.Info("webhook registered",
		"id", webhook.ID,
		"url", webhook.URL,
		"events", webhook.Events,
	)

	return nil
}

// Unregister removes a webhook.
func (m *Manager) Unregister(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.webhooks[id]; !exists {
		return ErrWebhookNotFound
	}

	delete(m.webhooks, id)
	m.logger.Info("webhook unregistered", "id", id)

	return nil
}

// Get retrieves a webhook by ID.
func (m *Manager) Get(id string) (*Webhook, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	webhook, exists := m.webhooks[id]
	if !exists {
		return nil, ErrWebhookNotFound
	}

	return webhook, nil
}

// List returns all registered webhooks.
func (m *Manager) List() []*Webhook {
	m.mu.RLock()
	defer m.mu.RUnlock()

	webhooks := make([]*Webhook, 0, len(m.webhooks))
	for _, w := range m.webhooks {
		webhooks = append(webhooks, w)
	}

	return webhooks
}

// Update updates a webhook.
func (m *Manager) Update(id string, update func(*Webhook)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	webhook, exists := m.webhooks[id]
	if !exists {
		return ErrWebhookNotFound
	}

	update(webhook)
	webhook.UpdatedAt = time.Now()

	return nil
}

// Enable enables a webhook.
func (m *Manager) Enable(id string) error {
	return m.Update(id, func(w *Webhook) {
		w.Enabled = true
	})
}

// Disable disables a webhook.
func (m *Manager) Disable(id string) error {
	return m.Update(id, func(w *Webhook) {
		w.Enabled = false
	})
}

// Dispatch sends an event to all matching webhooks.
func (m *Manager) Dispatch(event *Event) error {
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	m.mu.RLock()
	webhooks := make([]*Webhook, 0)
	for _, w := range m.webhooks {
		if w.Enabled && m.matchesEvent(w, event.Type) {
			webhooks = append(webhooks, w)
		}
	}
	m.mu.RUnlock()

	for _, webhook := range webhooks {
		select {
		case m.eventQueue <- &queuedEvent{webhook: webhook, event: event}:
		default:
			m.logger.Warn("event queue full, dropping event",
				"webhook_id", webhook.ID,
				"event_id", event.ID,
			)
		}
	}

	m.logger.Debug("event dispatched",
		"event_id", event.ID,
		"event_type", event.Type,
		"webhooks", len(webhooks),
	)

	return nil
}

// DispatchSync sends an event synchronously (blocking).
func (m *Manager) DispatchSync(ctx context.Context, event *Event) ([]*Delivery, error) {
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	m.mu.RLock()
	webhooks := make([]*Webhook, 0)
	for _, w := range m.webhooks {
		if w.Enabled && m.matchesEvent(w, event.Type) {
			webhooks = append(webhooks, w)
		}
	}
	m.mu.RUnlock()

	deliveries := make([]*Delivery, 0, len(webhooks))
	for _, webhook := range webhooks {
		delivery := m.deliverWithRetry(ctx, webhook, event)
		deliveries = append(deliveries, delivery)
	}

	return deliveries, nil
}

func (m *Manager) matchesEvent(webhook *Webhook, eventType string) bool {
	for _, pattern := range webhook.Events {
		if pattern == "*" {
			return true
		}
		if pattern == eventType {
			return true
		}
		// Support wildcard patterns like "user.*"
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, ".*")
			if strings.HasPrefix(eventType, prefix+".") {
				return true
			}
		}
	}
	return false
}

func (m *Manager) deliverWithRetry(ctx context.Context, webhook *Webhook, event *Event) *Delivery {
	delivery := &Delivery{
		ID:        generateID(),
		WebhookID: webhook.ID,
		EventID:   event.ID,
		EventType: event.Type,
		URL:       webhook.URL,
		Status:    DeliveryStatusPending,
		CreatedAt: time.Now(),
	}

	// Store delivery
	m.mu.Lock()
	m.deliveries[delivery.ID] = delivery
	m.mu.Unlock()

	payload, err := json.Marshal(event)
	if err != nil {
		delivery.Status = DeliveryStatusFailed
		delivery.Error = err.Error()
		now := time.Now()
		delivery.CompletedAt = &now
		return delivery
	}

	if int64(len(payload)) > m.maxPayload {
		delivery.Status = DeliveryStatusFailed
		delivery.Error = ErrPayloadTooLarge.Error()
		now := time.Now()
		delivery.CompletedAt = &now
		return delivery
	}

	delivery.RequestBody = string(payload)

	for attempt := 1; attempt <= m.retryConfig.MaxAttempts; attempt++ {
		delivery.Attempts = attempt

		statusCode, responseBody, duration, err := m.deliver(ctx, webhook, payload)
		delivery.StatusCode = statusCode
		delivery.ResponseBody = responseBody
		delivery.Duration = duration

		if err == nil && statusCode >= 200 && statusCode < 300 {
			delivery.Status = DeliveryStatusDelivered
			now := time.Now()
			delivery.CompletedAt = &now
			m.logger.Info("webhook delivered",
				"delivery_id", delivery.ID,
				"webhook_id", webhook.ID,
				"event_id", event.ID,
				"attempts", attempt,
				"duration_ms", duration.Milliseconds(),
			)
			return delivery
		}

		// Check if we should retry
		if attempt < m.retryConfig.MaxAttempts && m.shouldRetry(statusCode, err) {
			delay := m.calculateBackoff(attempt)
			nextRetry := time.Now().Add(delay)
			delivery.NextRetryAt = &nextRetry
			delivery.Status = DeliveryStatusRetrying

			m.logger.Debug("webhook delivery retry scheduled",
				"delivery_id", delivery.ID,
				"attempt", attempt,
				"next_retry", nextRetry,
			)

			select {
			case <-ctx.Done():
				delivery.Status = DeliveryStatusFailed
				delivery.Error = ctx.Err().Error()
				now := time.Now()
				delivery.CompletedAt = &now
				return delivery
			case <-time.After(delay):
				continue
			}
		}

		// Final failure
		delivery.Status = DeliveryStatusFailed
		if err != nil {
			delivery.Error = err.Error()
		} else {
			delivery.Error = fmt.Sprintf("HTTP %d", statusCode)
		}
	}

	now := time.Now()
	delivery.CompletedAt = &now

	m.logger.Warn("webhook delivery failed",
		"delivery_id", delivery.ID,
		"webhook_id", webhook.ID,
		"event_id", event.ID,
		"attempts", delivery.Attempts,
		"error", delivery.Error,
	)

	return delivery
}

func (m *Manager) deliver(ctx context.Context, webhook *Webhook, payload []byte) (int, string, time.Duration, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, "", time.Since(start), err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "WebhookDelivery/1.0")
	req.Header.Set("X-Webhook-ID", webhook.ID)
	req.Header.Set("X-Delivery-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Sign the request if secret is configured
	if webhook.Secret != "" {
		signature := Sign(payload, webhook.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
		req.Header.Set("X-Webhook-Signature-256", "sha256="+signature)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, "", time.Since(start), err
	}
	defer resp.Body.Close()

	// Read response body (limit to 64KB)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	return resp.StatusCode, string(body), time.Since(start), nil
}

func (m *Manager) shouldRetry(statusCode int, err error) bool {
	if err != nil {
		return true // Network errors are retryable
	}

	for _, code := range m.retryConfig.RetryableStatusCodes {
		if statusCode == code {
			return true
		}
	}

	return false
}

func (m *Manager) calculateBackoff(attempt int) time.Duration {
	delay := float64(m.retryConfig.InitialDelay) * math.Pow(m.retryConfig.Multiplier, float64(attempt-1))
	if delay > float64(m.retryConfig.MaxDelay) {
		delay = float64(m.retryConfig.MaxDelay)
	}
	return time.Duration(delay)
}

// GetDelivery retrieves a delivery by ID.
func (m *Manager) GetDelivery(id string) (*Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	delivery, exists := m.deliveries[id]
	if !exists {
		return nil, errors.New("delivery not found")
	}

	return delivery, nil
}

// ListDeliveries returns deliveries for a webhook.
func (m *Manager) ListDeliveries(webhookID string, limit int) []*Delivery {
	m.mu.RLock()
	defer m.mu.RUnlock()

	deliveries := make([]*Delivery, 0)
	for _, d := range m.deliveries {
		if d.WebhookID == webhookID {
			deliveries = append(deliveries, d)
			if limit > 0 && len(deliveries) >= limit {
				break
			}
		}
	}

	return deliveries
}

// Retry manually retries a failed delivery.
func (m *Manager) Retry(ctx context.Context, deliveryID string) (*Delivery, error) {
	m.mu.RLock()
	oldDelivery, exists := m.deliveries[deliveryID]
	if !exists {
		m.mu.RUnlock()
		return nil, errors.New("delivery not found")
	}

	webhook, webhookExists := m.webhooks[oldDelivery.WebhookID]
	m.mu.RUnlock()

	if !webhookExists {
		return nil, ErrWebhookNotFound
	}

	// Recreate the event from the delivery
	var event Event
	if err := json.Unmarshal([]byte(oldDelivery.RequestBody), &event); err != nil {
		return nil, err
	}

	return m.deliverWithRetry(ctx, webhook, &event), nil
}

// Sign creates an HMAC-SHA256 signature for a payload.
func Sign(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify verifies an HMAC-SHA256 signature.
func Verify(payload []byte, secret, signature string) bool {
	expected := Sign(payload, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// VerifyRequest verifies a webhook request signature.
func VerifyRequest(r *http.Request, secret string) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	signature := r.Header.Get("X-Webhook-Signature")
	if signature == "" {
		signature = strings.TrimPrefix(r.Header.Get("X-Webhook-Signature-256"), "sha256=")
	}

	if signature == "" {
		return ErrInvalidSignature
	}

	if !Verify(body, secret, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// Stats holds webhook delivery statistics.
type Stats struct {
	TotalWebhooks    int            `json:"total_webhooks"`
	ActiveWebhooks   int            `json:"active_webhooks"`
	TotalDeliveries  int            `json:"total_deliveries"`
	DeliveredCount   int            `json:"delivered_count"`
	FailedCount      int            `json:"failed_count"`
	PendingCount     int            `json:"pending_count"`
	RetryingCount    int            `json:"retrying_count"`
	AverageLatencyMs float64        `json:"average_latency_ms"`
	ByStatus         map[string]int `json:"by_status"`
}

// Stats returns delivery statistics.
func (m *Manager) Stats() *Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &Stats{
		TotalWebhooks: len(m.webhooks),
		ByStatus:      make(map[string]int),
	}

	for _, w := range m.webhooks {
		if w.Enabled {
			stats.ActiveWebhooks++
		}
	}

	var totalLatency time.Duration
	for _, d := range m.deliveries {
		stats.TotalDeliveries++
		stats.ByStatus[string(d.Status)]++
		totalLatency += d.Duration

		switch d.Status {
		case DeliveryStatusDelivered:
			stats.DeliveredCount++
		case DeliveryStatusFailed:
			stats.FailedCount++
		case DeliveryStatusPending:
			stats.PendingCount++
		case DeliveryStatusRetrying:
			stats.RetryingCount++
		}
	}

	if stats.TotalDeliveries > 0 {
		stats.AverageLatencyMs = float64(totalLatency.Milliseconds()) / float64(stats.TotalDeliveries)
	}

	return stats
}

// generateID generates a simple unique ID.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
