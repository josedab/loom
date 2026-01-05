package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(ManagerConfig{})

	if m == nil {
		t.Fatal("expected manager to be created")
	}
	if m.client == nil {
		t.Error("expected default HTTP client")
	}
	if m.workers != 5 {
		t.Errorf("expected 5 workers, got %d", m.workers)
	}
	if m.maxPayload != 1024*1024 {
		t.Errorf("expected 1MB max payload, got %d", m.maxPayload)
	}
}

func TestManager_Register(t *testing.T) {
	m := NewManager(ManagerConfig{})

	tests := []struct {
		name    string
		webhook *Webhook
		wantErr error
	}{
		{
			name: "valid webhook",
			webhook: &Webhook{
				URL:     "https://example.com/webhook",
				Events:  []string{"user.created"},
				Enabled: true,
			},
			wantErr: nil,
		},
		{
			name: "empty URL",
			webhook: &Webhook{
				Events: []string{"user.created"},
			},
			wantErr: ErrInvalidURL,
		},
		{
			name: "invalid URL scheme",
			webhook: &Webhook{
				URL: "ftp://example.com/webhook",
			},
			wantErr: ErrInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.Register(tt.webhook)
			if err != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.webhook.ID == "" {
				t.Error("expected ID to be generated")
			}
		})
	}
}

func TestManager_GetListUnregister(t *testing.T) {
	m := NewManager(ManagerConfig{})

	webhook := &Webhook{
		URL:     "https://example.com/webhook",
		Events:  []string{"*"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Get
	got, err := m.Get(webhook.ID)
	if err != nil {
		t.Errorf("Get() error = %v", err)
	}
	if got.URL != webhook.URL {
		t.Errorf("Get() URL = %v, want %v", got.URL, webhook.URL)
	}

	// List
	webhooks := m.List()
	if len(webhooks) != 1 {
		t.Errorf("List() len = %d, want 1", len(webhooks))
	}

	// Get not found
	_, err = m.Get("nonexistent")
	if err != ErrWebhookNotFound {
		t.Errorf("Get() error = %v, want ErrWebhookNotFound", err)
	}

	// Unregister
	if err := m.Unregister(webhook.ID); err != nil {
		t.Errorf("Unregister() error = %v", err)
	}

	// Verify removed
	webhooks = m.List()
	if len(webhooks) != 0 {
		t.Errorf("List() after unregister len = %d, want 0", len(webhooks))
	}

	// Unregister not found
	if err := m.Unregister("nonexistent"); err != ErrWebhookNotFound {
		t.Errorf("Unregister() error = %v, want ErrWebhookNotFound", err)
	}
}

func TestManager_Update(t *testing.T) {
	m := NewManager(ManagerConfig{})

	webhook := &Webhook{
		URL:         "https://example.com/webhook",
		Events:      []string{"*"},
		Enabled:     true,
		Description: "Original",
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Update
	err := m.Update(webhook.ID, func(w *Webhook) {
		w.Description = "Updated"
	})
	if err != nil {
		t.Errorf("Update() error = %v", err)
	}

	// Verify update
	got, _ := m.Get(webhook.ID)
	if got.Description != "Updated" {
		t.Errorf("Description = %v, want Updated", got.Description)
	}

	// Update not found
	err = m.Update("nonexistent", func(w *Webhook) {})
	if err != ErrWebhookNotFound {
		t.Errorf("Update() error = %v, want ErrWebhookNotFound", err)
	}
}

func TestManager_EnableDisable(t *testing.T) {
	m := NewManager(ManagerConfig{})

	webhook := &Webhook{
		URL:     "https://example.com/webhook",
		Events:  []string{"*"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Disable
	if err := m.Disable(webhook.ID); err != nil {
		t.Errorf("Disable() error = %v", err)
	}

	got, _ := m.Get(webhook.ID)
	if got.Enabled {
		t.Error("expected webhook to be disabled")
	}

	// Enable
	if err := m.Enable(webhook.ID); err != nil {
		t.Errorf("Enable() error = %v", err)
	}

	got, _ = m.Get(webhook.ID)
	if !got.Enabled {
		t.Error("expected webhook to be enabled")
	}
}

func TestManager_MatchesEvent(t *testing.T) {
	m := NewManager(ManagerConfig{})

	tests := []struct {
		name      string
		events    []string
		eventType string
		want      bool
	}{
		{
			name:      "wildcard matches all",
			events:    []string{"*"},
			eventType: "user.created",
			want:      true,
		},
		{
			name:      "exact match",
			events:    []string{"user.created"},
			eventType: "user.created",
			want:      true,
		},
		{
			name:      "no match",
			events:    []string{"user.created"},
			eventType: "order.created",
			want:      false,
		},
		{
			name:      "prefix wildcard match",
			events:    []string{"user.*"},
			eventType: "user.created",
			want:      true,
		},
		{
			name:      "prefix wildcard no match",
			events:    []string{"user.*"},
			eventType: "order.created",
			want:      false,
		},
		{
			name:      "multiple events",
			events:    []string{"user.created", "user.updated"},
			eventType: "user.updated",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &Webhook{Events: tt.events}
			got := m.matchesEvent(webhook, tt.eventType)
			if got != tt.want {
				t.Errorf("matchesEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManager_Delivery(t *testing.T) {
	var received atomic.Int32
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)

		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type application/json")
		}
		if r.Header.Get("X-Webhook-ID") == "" {
			t.Error("expected X-Webhook-ID header")
		}

		// Read body
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		receivedBody = buf.Bytes()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{
			MaxAttempts:  1,
			InitialDelay: time.Millisecond,
		},
	})
	m.Start()
	defer m.Stop()

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"test.event"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	event := &Event{
		Type: "test.event",
		Data: map[string]interface{}{
			"message": "hello",
		},
	}

	deliveries, err := m.DispatchSync(context.Background(), event)
	if err != nil {
		t.Fatalf("DispatchSync() error = %v", err)
	}

	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.Status != DeliveryStatusDelivered {
		t.Errorf("status = %v, want %v", delivery.Status, DeliveryStatusDelivered)
	}
	if delivery.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", delivery.StatusCode)
	}
	if received.Load() != 1 {
		t.Errorf("received = %d, want 1", received.Load())
	}

	// Verify body was sent correctly
	var sentEvent Event
	if err := json.Unmarshal(receivedBody, &sentEvent); err != nil {
		t.Errorf("failed to unmarshal sent body: %v", err)
	}
	if sentEvent.Type != "test.event" {
		t.Errorf("sent event type = %v, want test.event", sentEvent.Type)
	}
}

func TestManager_DeliveryWithSignature(t *testing.T) {
	secret := "test-secret-key"
	var receivedSignature string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-Webhook-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
	})

	webhook := &Webhook{
		URL:     server.URL,
		Secret:  secret,
		Events:  []string{"*"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	event := &Event{
		Type: "test.event",
		Data: map[string]interface{}{"key": "value"},
	}

	deliveries, _ := m.DispatchSync(context.Background(), event)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	if receivedSignature == "" {
		t.Error("expected signature header")
	}

	// Verify the signature is valid
	payload, _ := json.Marshal(event)
	if !Verify(payload, secret, receivedSignature) {
		t.Error("signature verification failed")
	}
}

func TestManager_RetryOnFailure(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		if attempt < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{
			MaxAttempts:          5,
			InitialDelay:         time.Millisecond,
			MaxDelay:             10 * time.Millisecond,
			Multiplier:           2.0,
			RetryableStatusCodes: []int{500},
		},
	})

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}

	deliveries, _ := m.DispatchSync(context.Background(), event)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.Status != DeliveryStatusDelivered {
		t.Errorf("status = %v, want %v", delivery.Status, DeliveryStatusDelivered)
	}
	if delivery.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", delivery.Attempts)
	}
	if attempts.Load() != 3 {
		t.Errorf("server received %d requests, want 3", attempts.Load())
	}
}

func TestManager_MaxRetriesExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{
			MaxAttempts:          3,
			InitialDelay:         time.Millisecond,
			MaxDelay:             10 * time.Millisecond,
			Multiplier:           2.0,
			RetryableStatusCodes: []int{500},
		},
	})

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: true,
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}

	deliveries, _ := m.DispatchSync(context.Background(), event)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.Status != DeliveryStatusFailed {
		t.Errorf("status = %v, want %v", delivery.Status, DeliveryStatusFailed)
	}
	if delivery.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", delivery.Attempts)
	}
}

func TestManager_DisabledWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("disabled webhook should not receive requests")
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{})

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: false, // Disabled
	}

	if err := m.Register(webhook); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}

	deliveries, _ := m.DispatchSync(context.Background(), event)
	if len(deliveries) != 0 {
		t.Errorf("expected 0 deliveries for disabled webhook, got %d", len(deliveries))
	}
}

func TestManager_Stats(t *testing.T) {
	m := NewManager(ManagerConfig{})

	// Register webhooks
	webhook1 := &Webhook{URL: "https://example.com/1", Events: []string{"*"}, Enabled: true}
	webhook2 := &Webhook{URL: "https://example.com/2", Events: []string{"*"}, Enabled: false}

	m.Register(webhook1)
	m.Register(webhook2)

	stats := m.Stats()

	if stats.TotalWebhooks != 2 {
		t.Errorf("TotalWebhooks = %d, want 2", stats.TotalWebhooks)
	}
	if stats.ActiveWebhooks != 1 {
		t.Errorf("ActiveWebhooks = %d, want 1", stats.ActiveWebhooks)
	}
}

func TestSign_Verify(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := "my-secret-key"

	signature := Sign(payload, secret)

	if signature == "" {
		t.Error("expected non-empty signature")
	}

	// Verify with correct secret
	if !Verify(payload, secret, signature) {
		t.Error("expected verification to pass")
	}

	// Verify with wrong secret
	if Verify(payload, "wrong-secret", signature) {
		t.Error("expected verification to fail with wrong secret")
	}

	// Verify with modified payload
	if Verify([]byte(`{"event":"modified"}`), secret, signature) {
		t.Error("expected verification to fail with modified payload")
	}
}

func TestVerifyRequest(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := "my-secret-key"
	signature := Sign(payload, secret)

	// Valid request
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Signature", signature)

	err := VerifyRequest(req, secret)
	if err != nil {
		t.Errorf("VerifyRequest() error = %v", err)
	}

	// Invalid signature
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Signature", "invalid")

	err = VerifyRequest(req, secret)
	if err != ErrInvalidSignature {
		t.Errorf("VerifyRequest() error = %v, want ErrInvalidSignature", err)
	}

	// Missing signature
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))

	err = VerifyRequest(req, secret)
	if err != ErrInvalidSignature {
		t.Errorf("VerifyRequest() error = %v, want ErrInvalidSignature", err)
	}
}

func TestHandler_CRUD(t *testing.T) {
	m := NewManager(ManagerConfig{})
	h := NewHandler(m, nil)

	// Create webhook
	createBody := `{
		"url": "https://example.com/webhook",
		"events": ["user.created"],
		"enabled": true,
		"description": "Test webhook"
	}`

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Create status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var created map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&created)
	webhookID := created["id"].(string)

	// List webhooks
	req = httptest.NewRequest(http.MethodGet, "/webhooks", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("List status = %d, want %d", rec.Code, http.StatusOK)
	}

	var listed []map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&listed)
	if len(listed) != 1 {
		t.Errorf("List count = %d, want 1", len(listed))
	}

	// Get webhook
	req = httptest.NewRequest(http.MethodGet, "/webhooks/"+webhookID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Get status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Update webhook
	updateBody := `{"description": "Updated description"}`
	req = httptest.NewRequest(http.MethodPut, "/webhooks/"+webhookID, strings.NewReader(updateBody))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Update status = %d, want %d", rec.Code, http.StatusOK)
	}

	var updated map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&updated)
	if updated["description"] != "Updated description" {
		t.Errorf("Updated description = %v, want 'Updated description'", updated["description"])
	}

	// Delete webhook
	req = httptest.NewRequest(http.MethodDelete, "/webhooks/"+webhookID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Delete status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Verify deleted
	req = httptest.NewRequest(http.MethodGet, "/webhooks/"+webhookID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Get deleted status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandler_EnableDisable(t *testing.T) {
	m := NewManager(ManagerConfig{})
	h := NewHandler(m, nil)

	// Create webhook
	webhook := &Webhook{
		URL:     "https://example.com/webhook",
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	// Disable
	req := httptest.NewRequest(http.MethodPost, "/webhooks/"+webhook.ID+"/disable", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Disable status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&result)
	if result["enabled"].(bool) != false {
		t.Error("expected enabled to be false")
	}

	// Enable
	req = httptest.NewRequest(http.MethodPost, "/webhooks/"+webhook.ID+"/enable", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Enable status = %d, want %d", rec.Code, http.StatusOK)
	}

	json.NewDecoder(rec.Body).Decode(&result)
	if result["enabled"].(bool) != true {
		t.Error("expected enabled to be true")
	}
}

func TestHandler_Dispatch(t *testing.T) {
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
	})
	m.Start()
	defer m.Stop()

	h := NewHandler(m, nil)

	// Register webhook
	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"test.event"},
		Enabled: true,
	}
	m.Register(webhook)

	// Dispatch event synchronously
	body := `{"type": "test.event", "data": {"key": "value"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks/dispatch?sync=true", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Dispatch status = %d, want %d", rec.Code, http.StatusOK)
	}

	select {
	case <-received:
		// OK
	case <-time.After(time.Second):
		t.Error("webhook not received")
	}
}

func TestHandler_Stats(t *testing.T) {
	m := NewManager(ManagerConfig{})
	h := NewHandler(m, nil)

	// Register a webhook
	webhook := &Webhook{
		URL:     "https://example.com/webhook",
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	req := httptest.NewRequest(http.MethodGet, "/webhooks/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Stats status = %d, want %d", rec.Code, http.StatusOK)
	}

	var stats Stats
	json.NewDecoder(rec.Body).Decode(&stats)

	if stats.TotalWebhooks != 1 {
		t.Errorf("TotalWebhooks = %d, want 1", stats.TotalWebhooks)
	}
	if stats.ActiveWebhooks != 1 {
		t.Errorf("ActiveWebhooks = %d, want 1", stats.ActiveWebhooks)
	}
}

func TestHandler_Deliveries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
	})

	h := NewHandler(m, nil)

	// Register webhook and dispatch event
	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}
	m.DispatchSync(context.Background(), event)

	// Get deliveries
	req := httptest.NewRequest(http.MethodGet, "/webhooks/"+webhook.ID+"/deliveries", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Deliveries status = %d, want %d", rec.Code, http.StatusOK)
	}

	var deliveries []*Delivery
	json.NewDecoder(rec.Body).Decode(&deliveries)

	if len(deliveries) != 1 {
		t.Errorf("Deliveries count = %d, want 1", len(deliveries))
	}
}

func TestHandler_Test(t *testing.T) {
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
	})

	h := NewHandler(m, nil)

	// Register webhook
	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"webhook.test"},
		Enabled: true,
	}
	m.Register(webhook)

	// Test webhook
	req := httptest.NewRequest(http.MethodPost, "/webhooks/"+webhook.ID+"/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Test status = %d, want %d", rec.Code, http.StatusOK)
	}

	select {
	case <-received:
		// OK
	case <-time.After(time.Second):
		t.Error("test webhook not received")
	}

	var delivery Delivery
	json.NewDecoder(rec.Body).Decode(&delivery)

	if delivery.Status != DeliveryStatusDelivered {
		t.Errorf("Delivery status = %v, want delivered", delivery.Status)
	}
}

func TestReceiverMiddleware(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"event":"test"}`)
	signature := Sign(payload, secret)

	handler := ReceiverMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Valid signature
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Signature", signature)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Valid signature status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Invalid signature
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Signature", "invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Invalid signature status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestCalculateBackoff(t *testing.T) {
	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{
			MaxAttempts:  10,
			InitialDelay: time.Second,
			MaxDelay:     30 * time.Second,
			Multiplier:   2.0,
		},
	})

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, time.Second},           // 1 * 2^0 = 1s
		{2, 2 * time.Second},       // 1 * 2^1 = 2s
		{3, 4 * time.Second},       // 1 * 2^2 = 4s
		{4, 8 * time.Second},       // 1 * 2^3 = 8s
		{10, 30 * time.Second},     // capped at max (512s > 30s)
	}

	for _, tt := range tests {
		got := m.calculateBackoff(tt.attempt)
		if got != tt.want {
			t.Errorf("calculateBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestAsyncDispatch(t *testing.T) {
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
		QueueSize:   10,
	})
	m.Start()
	defer m.Stop()

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}
	m.Dispatch(event)

	select {
	case <-received:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("async dispatch not received")
	}
}

func TestPayloadTooLarge(t *testing.T) {
	m := NewManager(ManagerConfig{
		MaxPayloadSize: 100, // 100 bytes limit
		RetryConfig:    RetryConfig{MaxAttempts: 1},
	})

	webhook := &Webhook{
		URL:     "https://example.com/webhook",
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	// Create large event
	largeData := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		largeData[string(rune('a'+i%26))] = "some value that makes this large"
	}

	event := &Event{Type: "test.event", Data: largeData}

	deliveries, _ := m.DispatchSync(context.Background(), event)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.Status != DeliveryStatusFailed {
		t.Errorf("status = %v, want failed", delivery.Status)
	}
	if delivery.Error != ErrPayloadTooLarge.Error() {
		t.Errorf("error = %v, want %v", delivery.Error, ErrPayloadTooLarge.Error())
	}
}

func TestContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		RetryConfig: RetryConfig{
			MaxAttempts:  3,
			InitialDelay: time.Millisecond,
		},
	})

	webhook := &Webhook{
		URL:     server.URL,
		Events:  []string{"*"},
		Enabled: true,
	}
	m.Register(webhook)

	// Cancel context quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}

	deliveries, _ := m.DispatchSync(ctx, event)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(deliveries))
	}

	delivery := deliveries[0]
	if delivery.Status != DeliveryStatusFailed {
		t.Errorf("status = %v, want failed", delivery.Status)
	}
}

func TestCustomHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager(ManagerConfig{
		RetryConfig: RetryConfig{MaxAttempts: 1},
	})

	webhook := &Webhook{
		URL:    server.URL,
		Events: []string{"*"},
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer token123",
		},
		Enabled: true,
	}
	m.Register(webhook)

	event := &Event{Type: "test.event", Data: map[string]interface{}{}}
	m.DispatchSync(context.Background(), event)

	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %v, want custom-value", receivedHeaders.Get("X-Custom-Header"))
	}
	if receivedHeaders.Get("Authorization") != "Bearer token123" {
		t.Errorf("Authorization = %v, want Bearer token123", receivedHeaders.Get("Authorization"))
	}
}
