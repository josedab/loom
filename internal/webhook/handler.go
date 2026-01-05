package webhook

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Handler provides HTTP API for webhook management.
type Handler struct {
	manager *Manager
	logger  *slog.Logger
}

// NewHandler creates a new webhook handler.
func NewHandler(manager *Manager, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		manager: manager,
		logger:  logger,
	}
}

// ServeHTTP handles webhook API requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/webhooks")
	if path == "" {
		path = "/"
	}

	switch {
	case path == "/" || path == "":
		switch r.Method {
		case http.MethodGet:
			h.handleList(w, r)
		case http.MethodPost:
			h.handleCreate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/stats":
		if r.Method == http.MethodGet {
			h.handleStats(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case path == "/dispatch":
		if r.Method == http.MethodPost {
			h.handleDispatch(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case strings.HasPrefix(path, "/"):
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		webhookID := parts[0]

		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				h.handleGet(w, r, webhookID)
			case http.MethodPut:
				h.handleUpdate(w, r, webhookID)
			case http.MethodDelete:
				h.handleDelete(w, r, webhookID)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		} else if len(parts) >= 2 {
			switch parts[1] {
			case "enable":
				if r.Method == http.MethodPost {
					h.handleEnable(w, r, webhookID)
				} else {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			case "disable":
				if r.Method == http.MethodPost {
					h.handleDisable(w, r, webhookID)
				} else {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			case "deliveries":
				if r.Method == http.MethodGet {
					h.handleDeliveries(w, r, webhookID)
				} else {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			case "test":
				if r.Method == http.MethodPost {
					h.handleTest(w, r, webhookID)
				} else {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			default:
				http.NotFound(w, r)
			}
		} else {
			http.NotFound(w, r)
		}

	default:
		http.NotFound(w, r)
	}
}

type createWebhookRequest struct {
	URL         string            `json:"url"`
	Secret      string            `json:"secret,omitempty"`
	Events      []string          `json:"events"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description string            `json:"description,omitempty"`
	Enabled     bool              `json:"enabled"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	webhook := &Webhook{
		URL:         req.URL,
		Secret:      req.Secret,
		Events:      req.Events,
		Headers:     req.Headers,
		Description: req.Description,
		Enabled:     req.Enabled,
		Metadata:    req.Metadata,
	}

	if err := h.manager.Register(webhook); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(webhook)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	webhooks := h.manager.List()

	// Mask secrets in response
	response := make([]map[string]interface{}, len(webhooks))
	for i, wh := range webhooks {
		response[i] = map[string]interface{}{
			"id":          wh.ID,
			"url":         wh.URL,
			"events":      wh.Events,
			"headers":     wh.Headers,
			"enabled":     wh.Enabled,
			"description": wh.Description,
			"created_at":  wh.CreatedAt,
			"updated_at":  wh.UpdatedAt,
			"has_secret":  wh.Secret != "",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	webhook, err := h.manager.Get(id)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":          webhook.ID,
		"url":         webhook.URL,
		"events":      webhook.Events,
		"headers":     webhook.Headers,
		"enabled":     webhook.Enabled,
		"description": webhook.Description,
		"created_at":  webhook.CreatedAt,
		"updated_at":  webhook.UpdatedAt,
		"has_secret":  webhook.Secret != "",
		"metadata":    webhook.Metadata,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type updateWebhookRequest struct {
	URL         *string           `json:"url,omitempty"`
	Secret      *string           `json:"secret,omitempty"`
	Events      []string          `json:"events,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Description *string           `json:"description,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var req updateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	err := h.manager.Update(id, func(wh *Webhook) {
		if req.URL != nil {
			wh.URL = *req.URL
		}
		if req.Secret != nil {
			wh.Secret = *req.Secret
		}
		if req.Events != nil {
			wh.Events = req.Events
		}
		if req.Headers != nil {
			wh.Headers = req.Headers
		}
		if req.Description != nil {
			wh.Description = *req.Description
		}
		if req.Enabled != nil {
			wh.Enabled = *req.Enabled
		}
		if req.Metadata != nil {
			wh.Metadata = req.Metadata
		}
	})

	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	webhook, _ := h.manager.Get(id)
	response := map[string]interface{}{
		"id":          webhook.ID,
		"url":         webhook.URL,
		"events":      webhook.Events,
		"headers":     webhook.Headers,
		"enabled":     webhook.Enabled,
		"description": webhook.Description,
		"created_at":  webhook.CreatedAt,
		"updated_at":  webhook.UpdatedAt,
		"has_secret":  webhook.Secret != "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.manager.Unregister(id); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleEnable(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.manager.Enable(id); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"enabled": true,
	})
}

func (h *Handler) handleDisable(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.manager.Disable(id); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"enabled": false,
	})
}

func (h *Handler) handleDeliveries(w http.ResponseWriter, r *http.Request, id string) {
	// Check if webhook exists
	if _, err := h.manager.Get(id); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	limit := 100
	deliveries := h.manager.ListDeliveries(id, limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deliveries)
}

func (h *Handler) handleTest(w http.ResponseWriter, r *http.Request, id string) {
	webhook, err := h.manager.Get(id)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Create a test event
	event := &Event{
		Type: "webhook.test",
		Data: map[string]interface{}{
			"message": "This is a test webhook delivery",
			"webhook": map[string]interface{}{
				"id":  webhook.ID,
				"url": webhook.URL,
			},
		},
		Source: "webhook-api",
	}

	// Dispatch synchronously
	deliveries, err := h.manager.DispatchSync(r.Context(), event)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Find the delivery for this webhook
	var delivery *Delivery
	for _, d := range deliveries {
		if d.WebhookID == id {
			delivery = d
			break
		}
	}

	if delivery == nil {
		h.jsonError(w, "delivery not created", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(delivery)
}

type dispatchRequest struct {
	Type   string                 `json:"type"`
	Data   map[string]interface{} `json:"data"`
	Source string                 `json:"source,omitempty"`
}

func (h *Handler) handleDispatch(w http.ResponseWriter, r *http.Request) {
	var req dispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		h.jsonError(w, "event type is required", http.StatusBadRequest)
		return
	}

	event := &Event{
		Type:   req.Type,
		Data:   req.Data,
		Source: req.Source,
	}

	// Check if synchronous delivery is requested
	if r.URL.Query().Get("sync") == "true" {
		deliveries, err := h.manager.DispatchSync(r.Context(), event)
		if err != nil {
			h.jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"event_id":   event.ID,
			"deliveries": deliveries,
		})
		return
	}

	// Async dispatch
	if err := h.manager.Dispatch(event); err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"event_id": event.ID,
		"status":   "queued",
	})
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.manager.Stats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// ReceiverMiddleware creates middleware for receiving and verifying incoming webhooks.
func ReceiverMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := VerifyRequest(r, secret); err != nil {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
