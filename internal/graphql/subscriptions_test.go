package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestSubscriptionManager_NewAndConfig(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.MaxConnections = 100
	config.MaxSubscriptionsPerConnection = 10

	manager := NewSubscriptionManager(config, gateway)
	if manager == nil {
		t.Fatal("expected manager to be created")
	}

	if manager.GetConnectionCount() != 0 {
		t.Errorf("expected 0 connections, got %d", manager.GetConnectionCount())
	}

	stats := manager.GetStats()
	if stats.ActiveConnections != 0 {
		t.Errorf("expected 0 active connections, got %d", stats.ActiveConnections)
	}
}

func TestPubSub_SubscribePublish(t *testing.T) {
	pubsub := NewPubSub(nil)
	defer pubsub.Close()

	// Create subscription
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := &Subscription{
		ID:           "sub1",
		ConnectionID: "conn1",
		Topics:       []string{"users"},
		DataCh:       make(chan *SubscriptionData, 10),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Subscribe
	pubsub.Subscribe("users", sub)

	if pubsub.GetTopicCount() != 1 {
		t.Errorf("expected 1 topic, got %d", pubsub.GetTopicCount())
	}

	if pubsub.GetSubscriberCount("users") != 1 {
		t.Errorf("expected 1 subscriber, got %d", pubsub.GetSubscriberCount("users"))
	}

	// Publish
	data := &SubscriptionData{
		Data: map[string]interface{}{"user": "test"},
	}
	if err := pubsub.Publish("users", data); err != nil {
		t.Fatalf("publish failed: %v", err)
	}

	// Receive
	select {
	case received := <-sub.DataCh:
		if received.Data == nil {
			t.Error("expected data")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for data")
	}

	// Unsubscribe
	pubsub.Unsubscribe("users", sub)

	if pubsub.GetSubscriberCount("users") != 0 {
		t.Errorf("expected 0 subscribers, got %d", pubsub.GetSubscriberCount("users"))
	}
}

func TestPubSub_MultipleSubscribers(t *testing.T) {
	pubsub := NewPubSub(nil)
	defer pubsub.Close()

	subs := make([]*Subscription, 3)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		subs[i] = &Subscription{
			ID:           "sub" + string(rune('0'+i)),
			ConnectionID: "conn" + string(rune('0'+i)),
			Topics:       []string{"events"},
			DataCh:       make(chan *SubscriptionData, 10),
			ctx:          ctx,
			cancel:       cancel,
		}
		pubsub.Subscribe("events", subs[i])
	}

	if pubsub.GetSubscriberCount("events") != 3 {
		t.Errorf("expected 3 subscribers, got %d", pubsub.GetSubscriberCount("events"))
	}

	// Publish
	data := &SubscriptionData{
		Data: map[string]interface{}{"event": "test"},
	}
	pubsub.Publish("events", data)

	// All should receive
	for i, sub := range subs {
		select {
		case <-sub.DataCh:
		case <-time.After(time.Second):
			t.Errorf("subscriber %d didn't receive data", i)
		}
	}
}

func TestPubSub_PublishFiltered(t *testing.T) {
	pubsub := NewPubSub(nil)
	defer pubsub.Close()

	// Create subscriptions with different variables
	subs := make([]*Subscription, 2)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		subs[i] = &Subscription{
			ID:           "sub" + string(rune('0'+i)),
			ConnectionID: "conn" + string(rune('0'+i)),
			Topics:       []string{"notifications"},
			Variables:    map[string]interface{}{"userID": i + 1},
			DataCh:       make(chan *SubscriptionData, 10),
			ctx:          ctx,
			cancel:       cancel,
		}
		pubsub.Subscribe("notifications", subs[i])
	}

	// Publish with filter (only userID=1)
	data := &SubscriptionData{
		Data: map[string]interface{}{"notification": "hello"},
	}
	pubsub.PublishFiltered("notifications", data, func(sub *Subscription) bool {
		userID, ok := sub.Variables["userID"]
		return ok && userID == 1
	})

	// Only first should receive
	select {
	case <-subs[0].DataCh:
	case <-time.After(time.Second):
		t.Error("first subscriber didn't receive data")
	}

	select {
	case <-subs[1].DataCh:
		t.Error("second subscriber shouldn't receive data")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestSubscription_Send(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := &Subscription{
		ID:     "test",
		DataCh: make(chan *SubscriptionData, 1),
		ctx:    ctx,
		cancel: cancel,
	}

	// Send should succeed
	data := &SubscriptionData{Data: "test"}
	if err := sub.Send(data); err != nil {
		t.Errorf("send failed: %v", err)
	}

	// Fill buffer
	<-sub.DataCh

	// Send again
	if err := sub.Send(data); err != nil {
		t.Errorf("send failed: %v", err)
	}

	// Buffer full - should return backpressure
	if err := sub.Send(data); err != ErrBackpressure {
		t.Errorf("expected backpressure error, got %v", err)
	}

	// Cancel context
	cancel()

	// Send should return connection closed
	if err := sub.Send(data); err != ErrConnectionClosed {
		t.Errorf("expected connection closed error, got %v", err)
	}
}

func TestSubscriptionFilter_Match(t *testing.T) {
	sub := &Subscription{
		ID:           "sub1",
		ConnectionID: "conn1",
		Topics:       []string{"users", "events"},
		Variables:    map[string]interface{}{"userID": 123, "admin": true},
	}

	tests := []struct {
		name   string
		filter *SubscriptionFilter
		want   bool
	}{
		{
			name:   "empty filter matches all",
			filter: &SubscriptionFilter{},
			want:   true,
		},
		{
			name: "matching topic",
			filter: &SubscriptionFilter{
				Topics: []string{"users"},
			},
			want: true,
		},
		{
			name: "non-matching topic",
			filter: &SubscriptionFilter{
				Topics: []string{"orders"},
			},
			want: false,
		},
		{
			name: "matching connection",
			filter: &SubscriptionFilter{
				ConnectionID: "conn1",
			},
			want: true,
		},
		{
			name: "non-matching connection",
			filter: &SubscriptionFilter{
				ConnectionID: "conn2",
			},
			want: false,
		},
		{
			name: "matching variable",
			filter: &SubscriptionFilter{
				Variables: map[string]interface{}{"userID": 123},
			},
			want: true,
		},
		{
			name: "non-matching variable",
			filter: &SubscriptionFilter{
				Variables: map[string]interface{}{"userID": 456},
			},
			want: false,
		},
		{
			name: "custom filter true",
			filter: &SubscriptionFilter{
				Custom: func(s *Subscription) bool {
					return s.Variables["admin"] == true
				},
			},
			want: true,
		},
		{
			name: "custom filter false",
			filter: &SubscriptionFilter{
				Custom: func(s *Subscription) bool {
					return s.Variables["admin"] == false
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Match(sub); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTriggerHandler_Fire(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	handler := NewTriggerHandler(manager, nil)

	// Register a transform
	handler.RegisterTransform("userCreated", func(trigger *SubscriptionTrigger) (*SubscriptionData, error) {
		return &SubscriptionData{
			Data: map[string]interface{}{
				"userCreated": trigger.Payload,
			},
		}, nil
	})

	// Create a subscription
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub := &Subscription{
		ID:           "sub1",
		ConnectionID: "conn1",
		Topics:       []string{"users"},
		DataCh:       make(chan *SubscriptionData, 10),
		ctx:          ctx,
		cancel:       cancel,
	}
	manager.pubsub.Subscribe("users", sub)

	// Fire trigger
	trigger := &SubscriptionTrigger{
		Topic:   "users",
		Event:   "userCreated",
		Payload: map[string]interface{}{"id": 1, "name": "Test"},
	}

	if err := handler.Fire(trigger); err != nil {
		t.Fatalf("fire failed: %v", err)
	}

	// Verify data received
	select {
	case data := <-sub.DataCh:
		dataMap, ok := data.Data.(map[string]interface{})
		if !ok {
			t.Fatal("expected map data")
		}
		if _, exists := dataMap["userCreated"]; !exists {
			t.Error("expected userCreated key in data")
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for data")
	}
}

func TestTriggerHandler_FireWithFilter(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	handler := NewTriggerHandler(manager, nil)

	// Create subscriptions with different userIDs
	subs := make([]*Subscription, 2)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		subs[i] = &Subscription{
			ID:           "sub" + string(rune('0'+i)),
			ConnectionID: "conn" + string(rune('0'+i)),
			Topics:       []string{"notifications"},
			Variables:    map[string]interface{}{"userID": i + 1},
			DataCh:       make(chan *SubscriptionData, 10),
			ctx:          ctx,
			cancel:       cancel,
		}
		manager.pubsub.Subscribe("notifications", subs[i])
	}

	// Fire with filter
	trigger := &SubscriptionTrigger{
		Topic:   "notifications",
		Event:   "notify",
		Payload: "hello",
		Filter: &SubscriptionFilter{
			Variables: map[string]interface{}{"userID": 1},
		},
	}

	handler.Fire(trigger)

	// Only first should receive
	select {
	case <-subs[0].DataCh:
	case <-time.After(time.Second):
		t.Error("first subscriber didn't receive")
	}

	select {
	case <-subs[1].DataCh:
		t.Error("second subscriber shouldn't receive")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestExtractTopics(t *testing.T) {
	tests := []struct {
		name     string
		analysis *QueryAnalysis
		want     []string
	}{
		{
			name: "single field",
			analysis: &QueryAnalysis{
				Fields: []string{"userCreated"},
			},
			want: []string{"userCreated"},
		},
		{
			name: "nested fields",
			analysis: &QueryAnalysis{
				Fields: []string{"userCreated.id", "userCreated.name"},
			},
			want: []string{"userCreated"},
		},
		{
			name: "multiple topics",
			analysis: &QueryAnalysis{
				Fields: []string{"userCreated.id", "messageReceived.content"},
			},
			want: []string{"userCreated", "messageReceived"},
		},
		{
			name:     "empty fields",
			analysis: &QueryAnalysis{Fields: []string{}},
			want:     []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTopics(tt.analysis)
			if len(got) != len(tt.want) {
				t.Errorf("extractTopics() = %v, want %v", got, tt.want)
				return
			}
			for i, topic := range got {
				if topic != tt.want[i] {
					t.Errorf("extractTopics()[%d] = %v, want %v", i, topic, tt.want[i])
				}
			}
		})
	}
}

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     SubscriptionProtocol
	}{
		{
			name:     "graphql-transport-ws",
			protocol: "graphql-transport-ws",
			want:     ProtocolGraphQLWS,
		},
		{
			name:     "graphql-ws (legacy)",
			protocol: "graphql-ws",
			want:     ProtocolSubscriptionsTransportWS,
		},
		{
			name:     "empty defaults to new",
			protocol: "",
			want:     ProtocolGraphQLWS,
		},
		{
			name:     "multiple protocols prefers new",
			protocol: "graphql-transport-ws, graphql-ws",
			want:     ProtocolGraphQLWS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
			if tt.protocol != "" {
				req.Header.Set("Sec-WebSocket-Protocol", tt.protocol)
			}
			got := detectProtocol(req)
			if got != tt.want {
				t.Errorf("detectProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubscriptionMessage_JSON(t *testing.T) {
	msg := SubscriptionMessage{
		ID:   "1",
		Type: MessageSubscribe,
		Payload: json.RawMessage(`{"query": "subscription { userCreated { id } }"}`),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded SubscriptionMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ID != msg.ID {
		t.Errorf("ID = %v, want %v", decoded.ID, msg.ID)
	}
	if decoded.Type != msg.Type {
		t.Errorf("Type = %v, want %v", decoded.Type, msg.Type)
	}
}

func TestSubscriptionPayload_Parse(t *testing.T) {
	raw := `{
		"query": "subscription { userCreated { id name } }",
		"operationName": "UserSub",
		"variables": {"userId": 123}
	}`

	var payload SubscriptionPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if payload.Query == "" {
		t.Error("expected query")
	}
	if payload.OperationName != "UserSub" {
		t.Errorf("OperationName = %v, want UserSub", payload.OperationName)
	}
	if payload.Variables["userId"] != float64(123) {
		t.Errorf("variables.userId = %v, want 123", payload.Variables["userId"])
	}
}

func TestSubscriptionStats(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	stats := manager.GetStats()
	if stats.ActiveConnections != 0 {
		t.Errorf("ActiveConnections = %d, want 0", stats.ActiveConnections)
	}
	if stats.TotalConnections != 0 {
		t.Errorf("TotalConnections = %d, want 0", stats.TotalConnections)
	}
}

func TestDefaultSubscriptionConfig(t *testing.T) {
	config := DefaultSubscriptionConfig()

	if config.MaxConnections <= 0 {
		t.Error("MaxConnections should be positive")
	}
	if config.MaxSubscriptionsPerConnection <= 0 {
		t.Error("MaxSubscriptionsPerConnection should be positive")
	}
	if config.ConnectionTimeout <= 0 {
		t.Error("ConnectionTimeout should be positive")
	}
	if config.KeepAliveInterval <= 0 {
		t.Error("KeepAliveInterval should be positive")
	}
	if config.BufferSize <= 0 {
		t.Error("BufferSize should be positive")
	}
}

func TestGenerateConnectionID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateConnectionID()
		if len(id) == 0 {
			t.Error("empty connection ID")
		}
		if ids[id] {
			t.Errorf("duplicate connection ID: %s", id)
		}
		ids[id] = true
	}
}

func TestGetInitParamsFromContext(t *testing.T) {
	// Empty context
	ctx := context.Background()
	params := GetInitParamsFromContext(ctx)
	if params != nil {
		t.Error("expected nil params from empty context")
	}

	// Context with params
	expectedParams := map[string]interface{}{"token": "abc123"}
	ctx = context.WithValue(ctx, subscriptionInitParamsKey, expectedParams)
	params = GetInitParamsFromContext(ctx)
	if params == nil {
		t.Fatal("expected params")
	}
	if params["token"] != "abc123" {
		t.Errorf("token = %v, want abc123", params["token"])
	}
}

func TestPubSub_ConcurrentAccess(t *testing.T) {
	pubsub := NewPubSub(nil)
	defer pubsub.Close()

	const numGoroutines = 10
	const numOps = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sub := &Subscription{
				ID:           "sub" + string(rune('0'+id)),
				ConnectionID: "conn" + string(rune('0'+id)),
				Topics:       []string{"concurrent"},
				DataCh:       make(chan *SubscriptionData, numOps),
				ctx:          ctx,
				cancel:       cancel,
			}

			for j := 0; j < numOps; j++ {
				pubsub.Subscribe("concurrent", sub)
				pubsub.Publish("concurrent", &SubscriptionData{Data: j})
				pubsub.Unsubscribe("concurrent", sub)
			}
		}(i)
	}

	wg.Wait()
}

func TestSubscriptionManager_Close(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)

	// Close should not panic
	if err := manager.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

func TestSubscriptionManager_Handler(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	handler := manager.Handler()
	if handler == nil {
		t.Fatal("expected handler")
	}
}

func TestSubscriptionMiddleware(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	// Create middleware
	middleware := SubscriptionMiddleware(manager)

	// Create a dummy handler
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(next)

	// Non-WebSocket request should pass through
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should have been called")
	}
}

func TestSubscriptionAdminHandler_Stats(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	admin := NewSubscriptionAdminHandler(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/subscriptions/admin/stats", nil)
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var stats SubscriptionStatsSnapshot
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
}

func TestSubscriptionAdminHandler_Connections(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	admin := NewSubscriptionAdminHandler(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/subscriptions/admin/connections", nil)
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestSubscriptionAdminHandler_NotFound(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	admin := NewSubscriptionAdminHandler(manager, nil)

	req := httptest.NewRequest(http.MethodGet, "/subscriptions/admin/unknown", nil)
	rec := httptest.NewRecorder()

	admin.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSubscriptionWebSocket_Integration(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.ConnectionTimeout = 5 * time.Second
	config.KeepAliveInterval = 0 // Disable for test
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	// Create test server
	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + server.URL[4:]

	// Connect via WebSocket
	ws, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Send connection_init
	initMsg := SubscriptionMessage{Type: MessageConnectionInit}
	if err := websocket.JSON.Send(ws, initMsg); err != nil {
		t.Fatalf("send init failed: %v", err)
	}

	// Receive connection_ack
	var ackMsg SubscriptionMessage
	if err := websocket.JSON.Receive(ws, &ackMsg); err != nil {
		t.Fatalf("receive ack failed: %v", err)
	}

	if ackMsg.Type != MessageConnectionAck {
		t.Errorf("type = %s, want %s", ackMsg.Type, MessageConnectionAck)
	}

	// Send subscribe
	subPayload := SubscriptionPayload{
		Query: "subscription { userCreated { id name } }",
	}
	payloadBytes, _ := json.Marshal(subPayload)

	subMsg := SubscriptionMessage{
		ID:      "1",
		Type:    MessageSubscribe,
		Payload: payloadBytes,
	}
	if err := websocket.JSON.Send(ws, subMsg); err != nil {
		t.Fatalf("send subscribe failed: %v", err)
	}

	// Wait for subscription to be registered
	time.Sleep(100 * time.Millisecond)

	// Verify subscription count
	if count := manager.GetSubscriptionCount(); count != 1 {
		t.Errorf("subscription count = %d, want 1", count)
	}

	// Publish data
	manager.Publish("userCreated", &SubscriptionData{
		Data: map[string]interface{}{
			"userCreated": map[string]interface{}{"id": "1", "name": "Test"},
		},
	})

	// Receive data
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var dataMsg SubscriptionMessage
	if err := websocket.JSON.Receive(ws, &dataMsg); err != nil {
		t.Fatalf("receive data failed: %v", err)
	}

	if dataMsg.Type != MessageNext {
		t.Errorf("type = %s, want %s", dataMsg.Type, MessageNext)
	}
	if dataMsg.ID != "1" {
		t.Errorf("id = %s, want 1", dataMsg.ID)
	}

	// Send complete
	completeMsg := SubscriptionMessage{
		ID:   "1",
		Type: MessageComplete,
	}
	if err := websocket.JSON.Send(ws, completeMsg); err != nil {
		t.Fatalf("send complete failed: %v", err)
	}

	// Wait for unsubscribe
	time.Sleep(100 * time.Millisecond)

	// Verify subscription removed
	if count := manager.GetSubscriptionCount(); count != 0 {
		t.Errorf("subscription count = %d, want 0", count)
	}
}

func TestSubscriptionWebSocket_Ping(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.ConnectionTimeout = 5 * time.Second
	config.KeepAliveInterval = 0
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	wsURL := "ws" + server.URL[4:]
	ws, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Init
	websocket.JSON.Send(ws, SubscriptionMessage{Type: MessageConnectionInit})
	var ack SubscriptionMessage
	websocket.JSON.Receive(ws, &ack)

	// Send ping
	pingMsg := SubscriptionMessage{Type: MessagePing}
	if err := websocket.JSON.Send(ws, pingMsg); err != nil {
		t.Fatalf("send ping failed: %v", err)
	}

	// Receive pong
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pongMsg SubscriptionMessage
	if err := websocket.JSON.Receive(ws, &pongMsg); err != nil {
		t.Fatalf("receive pong failed: %v", err)
	}

	if pongMsg.Type != MessagePong {
		t.Errorf("type = %s, want %s", pongMsg.Type, MessagePong)
	}
}

func TestSubscriptionWebSocket_LegacyProtocol(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.ConnectionTimeout = 5 * time.Second
	config.KeepAliveInterval = 0
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Connect with legacy protocol header
	wsConfig, err := websocket.NewConfig(wsURL, "http://localhost")
	if err != nil {
		t.Fatalf("config failed: %v", err)
	}
	wsConfig.Protocol = []string{"graphql-ws"}

	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Init
	websocket.JSON.Send(ws, SubscriptionMessage{Type: LegacyMessageConnectionInit})

	// Should receive ack and ka
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg1, msg2 SubscriptionMessage
	websocket.JSON.Receive(ws, &msg1)
	websocket.JSON.Receive(ws, &msg2)

	// One should be ack, one should be ka
	gotAck := msg1.Type == MessageConnectionAck || msg2.Type == MessageConnectionAck
	gotKA := msg1.Type == LegacyMessageConnectionKeepAlive || msg2.Type == LegacyMessageConnectionKeepAlive

	if !gotAck {
		t.Error("expected connection_ack")
	}
	if !gotKA {
		t.Error("expected keep-alive")
	}

	// Use legacy start message
	subPayload := SubscriptionPayload{
		Query: "subscription { userCreated { id } }",
	}
	payloadBytes, _ := json.Marshal(subPayload)

	startMsg := SubscriptionMessage{
		ID:      "1",
		Type:    LegacyMessageStart,
		Payload: payloadBytes,
	}
	websocket.JSON.Send(ws, startMsg)

	time.Sleep(100 * time.Millisecond)

	// Verify subscription
	if count := manager.GetSubscriptionCount(); count != 1 {
		t.Errorf("subscription count = %d, want 1", count)
	}

	// Send stop
	stopMsg := SubscriptionMessage{
		ID:   "1",
		Type: LegacyMessageStop,
	}
	websocket.JSON.Send(ws, stopMsg)

	time.Sleep(100 * time.Millisecond)

	if count := manager.GetSubscriptionCount(); count != 0 {
		t.Errorf("subscription count = %d, want 0", count)
	}
}

func TestSubscriptionManager_ConnectionLimit(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.MaxConnections = 2
	config.ConnectionTimeout = 5 * time.Second
	config.KeepAliveInterval = 0
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Create connections up to limit
	var conns []*websocket.Conn
	for i := 0; i < 2; i++ {
		ws, err := websocket.Dial(wsURL, "", "http://localhost")
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		conns = append(conns, ws)
		defer ws.Close()

		// Init
		websocket.JSON.Send(ws, SubscriptionMessage{Type: MessageConnectionInit})
		var ack SubscriptionMessage
		ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		websocket.JSON.Receive(ws, &ack)
	}

	// Wait for connections to register
	time.Sleep(100 * time.Millisecond)

	// Verify count
	if count := manager.GetConnectionCount(); count != 2 {
		t.Errorf("connection count = %d, want 2", count)
	}
}

func TestSubscriptionManager_SubscriptionLimit(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.MaxSubscriptionsPerConnection = 2
	config.ConnectionTimeout = 5 * time.Second
	config.KeepAliveInterval = 0
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	wsURL := "ws" + server.URL[4:]
	ws, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Init
	websocket.JSON.Send(ws, SubscriptionMessage{Type: MessageConnectionInit})
	var ack SubscriptionMessage
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	websocket.JSON.Receive(ws, &ack)

	// Create subscriptions up to limit
	for i := 0; i < 2; i++ {
		subPayload := SubscriptionPayload{
			Query: "subscription { userCreated { id } }",
		}
		payloadBytes, _ := json.Marshal(subPayload)
		subMsg := SubscriptionMessage{
			ID:      string(rune('0' + i)),
			Type:    MessageSubscribe,
			Payload: payloadBytes,
		}
		websocket.JSON.Send(ws, subMsg)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify count
	if count := manager.GetSubscriptionCount(); count != 2 {
		t.Errorf("subscription count = %d, want 2", count)
	}

	// Try to create one more - should fail
	subPayload := SubscriptionPayload{
		Query: "subscription { userCreated { id } }",
	}
	payloadBytes, _ := json.Marshal(subPayload)
	subMsg := SubscriptionMessage{
		ID:      "extra",
		Type:    MessageSubscribe,
		Payload: payloadBytes,
	}
	websocket.JSON.Send(ws, subMsg)

	// Should receive error
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var errMsg SubscriptionMessage
	websocket.JSON.Receive(ws, &errMsg)

	if errMsg.Type != MessageError {
		t.Errorf("type = %s, want %s", errMsg.Type, MessageError)
	}
}

func TestSubscriptionConnection_Concurrent(t *testing.T) {
	gateway := NewGateway(DefaultGatewayConfig(), nil)
	config := DefaultSubscriptionConfig()
	config.ConnectionTimeout = 10 * time.Second
	config.KeepAliveInterval = 0
	config.MaxSubscriptionsPerConnection = 100
	manager := NewSubscriptionManager(config, gateway)
	defer manager.Close()

	server := httptest.NewServer(manager.Handler())
	defer server.Close()

	wsURL := "ws" + server.URL[4:]
	ws, err := websocket.Dial(wsURL, "", "http://localhost")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	// Init
	websocket.JSON.Send(ws, SubscriptionMessage{Type: MessageConnectionInit})
	var ack SubscriptionMessage
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	websocket.JSON.Receive(ws, &ack)

	// Concurrent subscribe/unsubscribe
	var wg sync.WaitGroup
	var subCount int64

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 5; j++ {
				subID := string(rune('A'+id)) + string(rune('0'+j))

				// Subscribe
				subPayload := SubscriptionPayload{
					Query: "subscription { userCreated { id } }",
				}
				payloadBytes, _ := json.Marshal(subPayload)
				subMsg := SubscriptionMessage{
					ID:      subID,
					Type:    MessageSubscribe,
					Payload: payloadBytes,
				}
				websocket.JSON.Send(ws, subMsg)
				atomic.AddInt64(&subCount, 1)

				time.Sleep(10 * time.Millisecond)

				// Complete
				completeMsg := SubscriptionMessage{
					ID:   subID,
					Type: MessageComplete,
				}
				websocket.JSON.Send(ws, completeMsg)
				atomic.AddInt64(&subCount, -1)
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// All subscriptions should be cleaned up
	if count := manager.GetSubscriptionCount(); count != 0 {
		t.Errorf("subscription count = %d, want 0", count)
	}
}
