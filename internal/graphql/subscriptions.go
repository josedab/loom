// Package graphql provides GraphQL gateway capabilities including subscriptions.
package graphql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

// Common subscription errors.
var (
	ErrConnectionClosed    = errors.New("connection closed")
	ErrSubscriptionExists  = errors.New("subscription already exists")
	ErrSubscriptionNotFound = errors.New("subscription not found")
	ErrInvalidMessage      = errors.New("invalid message")
	ErrTooManyConnections  = errors.New("too many connections")
	ErrTooManySubscriptions = errors.New("too many subscriptions")
	ErrTopicNotFound       = errors.New("topic not found")
	ErrBackpressure        = errors.New("backpressure: subscriber too slow")
)

// SubscriptionProtocol defines the WebSocket subprotocol.
type SubscriptionProtocol string

const (
	// ProtocolGraphQLWS is the graphql-ws protocol (newer).
	ProtocolGraphQLWS SubscriptionProtocol = "graphql-transport-ws"
	// ProtocolSubscriptionsTransportWS is the legacy subscriptions-transport-ws protocol.
	ProtocolSubscriptionsTransportWS SubscriptionProtocol = "graphql-ws"
)

// Message types for graphql-transport-ws protocol.
const (
	MessageConnectionInit      = "connection_init"
	MessageConnectionAck       = "connection_ack"
	MessagePing                = "ping"
	MessagePong                = "pong"
	MessageSubscribe           = "subscribe"
	MessageNext                = "next"
	MessageError               = "error"
	MessageComplete            = "complete"
	MessageConnectionKeepAlive = "ka"
)

// Legacy message types for subscriptions-transport-ws protocol.
const (
	LegacyMessageConnectionInit      = "connection_init"
	LegacyMessageConnectionAck       = "connection_ack"
	LegacyMessageConnectionError     = "connection_error"
	LegacyMessageConnectionKeepAlive = "ka"
	LegacyMessageStart               = "start"
	LegacyMessageData                = "data"
	LegacyMessageError               = "error"
	LegacyMessageComplete            = "complete"
	LegacyMessageStop                = "stop"
	LegacyMessageConnectionTerminate = "connection_terminate"
)

// SubscriptionMessage represents a WebSocket message.
type SubscriptionMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// SubscriptionPayload is the payload for subscribe messages.
type SubscriptionPayload struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	Extensions    map[string]interface{} `json:"extensions,omitempty"`
}

// SubscriptionData represents data sent to subscribers.
type SubscriptionData struct {
	Data   interface{}            `json:"data,omitempty"`
	Errors []GatewayResponseError `json:"errors,omitempty"`
}

// SubscriptionConfig configures the subscription system.
type SubscriptionConfig struct {
	// MaxConnections limits total concurrent WebSocket connections.
	MaxConnections int
	// MaxSubscriptionsPerConnection limits subscriptions per connection.
	MaxSubscriptionsPerConnection int
	// ConnectionTimeout is the connection initialization timeout.
	ConnectionTimeout time.Duration
	// KeepAliveInterval is the interval for keep-alive messages.
	KeepAliveInterval time.Duration
	// WriteTimeout is the write deadline for messages.
	WriteTimeout time.Duration
	// ReadTimeout is the read deadline for messages.
	ReadTimeout time.Duration
	// BufferSize is the message buffer size per subscription.
	BufferSize int
	// AllowedOrigins restricts WebSocket origins (empty = all allowed).
	AllowedOrigins []string
	// EnableCompression enables WebSocket compression.
	EnableCompression bool
	// Logger for subscription events.
	Logger *slog.Logger
}

// DefaultSubscriptionConfig returns default configuration.
func DefaultSubscriptionConfig() SubscriptionConfig {
	return SubscriptionConfig{
		MaxConnections:                10000,
		MaxSubscriptionsPerConnection: 100,
		ConnectionTimeout:             10 * time.Second,
		KeepAliveInterval:             30 * time.Second,
		WriteTimeout:                  10 * time.Second,
		ReadTimeout:                   60 * time.Second,
		BufferSize:                    100,
		AllowedOrigins:                []string{},
		EnableCompression:             true,
	}
}

// SubscriptionManager manages WebSocket connections and subscriptions.
type SubscriptionManager struct {
	config      SubscriptionConfig
	gateway     *Gateway
	connections map[string]*SubscriptionConnection
	pubsub      *PubSub
	stats       *SubscriptionStats
	logger      *slog.Logger
	mu          sync.RWMutex
	stopCh      chan struct{}
}

// SubscriptionStats tracks subscription statistics.
type SubscriptionStats struct {
	activeConnections   int64
	totalConnections    int64
	activeSubscriptions int64
	totalSubscriptions  int64
	messagesPublished   int64
	messagesDelivered   int64
	errors              int64
}

// SubscriptionStatsSnapshot is a point-in-time snapshot of stats.
type SubscriptionStatsSnapshot struct {
	ActiveConnections   int64 `json:"active_connections"`
	TotalConnections    int64 `json:"total_connections"`
	ActiveSubscriptions int64 `json:"active_subscriptions"`
	TotalSubscriptions  int64 `json:"total_subscriptions"`
	MessagesPublished   int64 `json:"messages_published"`
	MessagesDelivered   int64 `json:"messages_delivered"`
	Errors              int64 `json:"errors"`
}

// NewSubscriptionManager creates a new subscription manager.
func NewSubscriptionManager(config SubscriptionConfig, gateway *Gateway) *SubscriptionManager {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	sm := &SubscriptionManager{
		config:      config,
		gateway:     gateway,
		connections: make(map[string]*SubscriptionConnection),
		pubsub:      NewPubSub(config.Logger),
		stats:       &SubscriptionStats{},
		logger:      config.Logger,
		stopCh:      make(chan struct{}),
	}

	return sm
}

// Handler returns an HTTP handler for WebSocket connections.
func (sm *SubscriptionManager) Handler() http.Handler {
	return websocket.Handler(sm.handleWebSocket)
}

func (sm *SubscriptionManager) handleWebSocket(ws *websocket.Conn) {
	// Check connection limit
	sm.mu.RLock()
	connCount := len(sm.connections)
	sm.mu.RUnlock()

	if connCount >= sm.config.MaxConnections {
		sm.logger.Warn("connection rejected: too many connections", "current", connCount, "max", sm.config.MaxConnections)
		atomic.AddInt64(&sm.stats.errors, 1)
		return
	}

	// Detect protocol
	protocol := detectProtocol(ws.Request())

	// Create connection
	conn := newSubscriptionConnection(sm, ws, protocol)

	// Register connection
	sm.mu.Lock()
	sm.connections[conn.id] = conn
	sm.mu.Unlock()

	atomic.AddInt64(&sm.stats.activeConnections, 1)
	atomic.AddInt64(&sm.stats.totalConnections, 1)

	sm.logger.Debug("new connection", "id", conn.id, "protocol", protocol)

	// Handle connection
	conn.run()

	// Cleanup
	sm.mu.Lock()
	delete(sm.connections, conn.id)
	sm.mu.Unlock()

	atomic.AddInt64(&sm.stats.activeConnections, -1)
	sm.logger.Debug("connection closed", "id", conn.id)
}

// Publish publishes data to a topic.
func (sm *SubscriptionManager) Publish(topic string, data *SubscriptionData) error {
	atomic.AddInt64(&sm.stats.messagesPublished, 1)
	return sm.pubsub.Publish(topic, data)
}

// PublishToSubscription publishes data directly to a subscription.
func (sm *SubscriptionManager) PublishToSubscription(connectionID, subscriptionID string, data *SubscriptionData) error {
	sm.mu.RLock()
	conn, ok := sm.connections[connectionID]
	sm.mu.RUnlock()

	if !ok {
		return ErrConnectionClosed
	}

	return conn.sendData(subscriptionID, data)
}

// GetStats returns current statistics.
func (sm *SubscriptionManager) GetStats() SubscriptionStatsSnapshot {
	return SubscriptionStatsSnapshot{
		ActiveConnections:   atomic.LoadInt64(&sm.stats.activeConnections),
		TotalConnections:    atomic.LoadInt64(&sm.stats.totalConnections),
		ActiveSubscriptions: atomic.LoadInt64(&sm.stats.activeSubscriptions),
		TotalSubscriptions:  atomic.LoadInt64(&sm.stats.totalSubscriptions),
		MessagesPublished:   atomic.LoadInt64(&sm.stats.messagesPublished),
		MessagesDelivered:   atomic.LoadInt64(&sm.stats.messagesDelivered),
		Errors:              atomic.LoadInt64(&sm.stats.errors),
	}
}

// GetConnectionCount returns the number of active connections.
func (sm *SubscriptionManager) GetConnectionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.connections)
}

// GetSubscriptionCount returns total active subscriptions.
func (sm *SubscriptionManager) GetSubscriptionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, conn := range sm.connections {
		count += conn.getSubscriptionCount()
	}
	return count
}

// CloseConnection closes a specific connection.
func (sm *SubscriptionManager) CloseConnection(connectionID string) error {
	sm.mu.RLock()
	conn, ok := sm.connections[connectionID]
	sm.mu.RUnlock()

	if !ok {
		return ErrConnectionClosed
	}

	return conn.close()
}

// Close shuts down the subscription manager.
func (sm *SubscriptionManager) Close() error {
	close(sm.stopCh)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, conn := range sm.connections {
		conn.close()
	}
	sm.connections = make(map[string]*SubscriptionConnection)

	sm.pubsub.Close()

	return nil
}

// SubscriptionConnection represents a WebSocket connection.
type SubscriptionConnection struct {
	id            string
	manager       *SubscriptionManager
	ws            *websocket.Conn
	protocol      SubscriptionProtocol
	subscriptions map[string]*Subscription
	initialized   bool
	initParams    map[string]interface{}
	sendCh        chan *SubscriptionMessage
	stopCh        chan struct{}
	logger        *slog.Logger
	mu            sync.RWMutex
	closed        bool
}

func newSubscriptionConnection(manager *SubscriptionManager, ws *websocket.Conn, protocol SubscriptionProtocol) *SubscriptionConnection {
	return &SubscriptionConnection{
		id:            generateConnectionID(),
		manager:       manager,
		ws:            ws,
		protocol:      protocol,
		subscriptions: make(map[string]*Subscription),
		sendCh:        make(chan *SubscriptionMessage, 256),
		stopCh:        make(chan struct{}),
		logger:        manager.logger.With("connection_id", generateConnectionID()),
	}
}

func (c *SubscriptionConnection) run() {
	// Start writer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.writeLoop()
	}()

	// Start keep-alive
	if c.manager.config.KeepAliveInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.keepAliveLoop()
		}()
	}

	// Read loop (blocking)
	c.readLoop()

	// Cleanup
	close(c.stopCh)
	wg.Wait()

	// Clean up subscriptions
	c.mu.Lock()
	for _, sub := range c.subscriptions {
		sub.cancel()
	}
	c.subscriptions = make(map[string]*Subscription)
	c.closed = true
	c.mu.Unlock()
}

func (c *SubscriptionConnection) readLoop() {
	// Set connection init timeout
	if !c.initialized {
		c.ws.SetReadDeadline(time.Now().Add(c.manager.config.ConnectionTimeout))
	}

	for {
		var msg SubscriptionMessage
		if err := websocket.JSON.Receive(c.ws, &msg); err != nil {
			if err != io.EOF {
				c.logger.Debug("read error", "error", err)
			}
			return
		}

		if err := c.handleMessage(&msg); err != nil {
			c.logger.Debug("message handling error", "error", err, "type", msg.Type)
			if errors.Is(err, ErrInvalidMessage) {
				c.sendError(msg.ID, err.Error())
			}
		}

		// After initialization, use normal read timeout
		if c.initialized && c.manager.config.ReadTimeout > 0 {
			c.ws.SetReadDeadline(time.Now().Add(c.manager.config.ReadTimeout))
		}
	}
}

func (c *SubscriptionConnection) writeLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		case msg := <-c.sendCh:
			if c.manager.config.WriteTimeout > 0 {
				c.ws.SetWriteDeadline(time.Now().Add(c.manager.config.WriteTimeout))
			}
			if err := websocket.JSON.Send(c.ws, msg); err != nil {
				c.logger.Debug("write error", "error", err)
				return
			}
		}
	}
}

func (c *SubscriptionConnection) keepAliveLoop() {
	ticker := time.NewTicker(c.manager.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			msgType := MessagePing
			if c.protocol == ProtocolSubscriptionsTransportWS {
				msgType = MessageConnectionKeepAlive
			}
			c.send(&SubscriptionMessage{Type: msgType})
		}
	}
}

func (c *SubscriptionConnection) handleMessage(msg *SubscriptionMessage) error {
	switch c.protocol {
	case ProtocolGraphQLWS:
		return c.handleGraphQLWSMessage(msg)
	case ProtocolSubscriptionsTransportWS:
		return c.handleLegacyMessage(msg)
	default:
		// Try to detect from message type
		switch msg.Type {
		case LegacyMessageStart, LegacyMessageStop, LegacyMessageConnectionTerminate:
			return c.handleLegacyMessage(msg)
		default:
			return c.handleGraphQLWSMessage(msg)
		}
	}
}

func (c *SubscriptionConnection) handleGraphQLWSMessage(msg *SubscriptionMessage) error {
	switch msg.Type {
	case MessageConnectionInit:
		return c.handleConnectionInit(msg.Payload)

	case MessagePing:
		c.send(&SubscriptionMessage{Type: MessagePong, Payload: msg.Payload})
		return nil

	case MessagePong:
		return nil // Ignore pong

	case MessageSubscribe:
		if !c.initialized {
			return ErrInvalidMessage
		}
		return c.handleSubscribe(msg.ID, msg.Payload)

	case MessageComplete:
		return c.handleComplete(msg.ID)

	default:
		return fmt.Errorf("%w: unknown type %s", ErrInvalidMessage, msg.Type)
	}
}

func (c *SubscriptionConnection) handleLegacyMessage(msg *SubscriptionMessage) error {
	switch msg.Type {
	case LegacyMessageConnectionInit:
		return c.handleConnectionInit(msg.Payload)

	case LegacyMessageStart:
		if !c.initialized {
			return ErrInvalidMessage
		}
		return c.handleSubscribe(msg.ID, msg.Payload)

	case LegacyMessageStop:
		return c.handleComplete(msg.ID)

	case LegacyMessageConnectionTerminate:
		c.close()
		return nil

	default:
		return fmt.Errorf("%w: unknown type %s", ErrInvalidMessage, msg.Type)
	}
}

func (c *SubscriptionConnection) handleConnectionInit(payload json.RawMessage) error {
	if c.initialized {
		return nil // Already initialized
	}

	// Parse init params
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &c.initParams); err != nil {
			c.logger.Debug("failed to parse init params", "error", err)
		}
	}

	c.initialized = true

	// Send ack
	c.send(&SubscriptionMessage{Type: MessageConnectionAck})

	// For legacy protocol, also send keep-alive
	if c.protocol == ProtocolSubscriptionsTransportWS {
		c.send(&SubscriptionMessage{Type: LegacyMessageConnectionKeepAlive})
	}

	c.logger.Debug("connection initialized")
	return nil
}

func (c *SubscriptionConnection) handleSubscribe(id string, payload json.RawMessage) error {
	// Check subscription limit
	c.mu.RLock()
	subCount := len(c.subscriptions)
	_, exists := c.subscriptions[id]
	c.mu.RUnlock()

	if exists {
		return ErrSubscriptionExists
	}

	if subCount >= c.manager.config.MaxSubscriptionsPerConnection {
		c.sendError(id, "too many subscriptions")
		return ErrTooManySubscriptions
	}

	// Parse payload
	var subPayload SubscriptionPayload
	if err := json.Unmarshal(payload, &subPayload); err != nil {
		c.sendError(id, "invalid payload")
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}

	// Validate query through gateway
	req := &GatewayRequest{
		Query:         subPayload.Query,
		OperationName: subPayload.OperationName,
		Variables:     subPayload.Variables,
	}

	ctx := context.Background()
	if c.initParams != nil {
		ctx = context.WithValue(ctx, subscriptionInitParamsKey, c.initParams)
	}

	_, analysis, err := c.manager.gateway.ProcessRequest(ctx, req)
	if err != nil {
		c.sendError(id, err.Error())
		return nil
	}

	if !analysis.HasSubscription {
		c.sendError(id, "query is not a subscription")
		return nil
	}

	// Create subscription
	subCtx, cancel := context.WithCancel(ctx)
	sub := &Subscription{
		ID:            id,
		ConnectionID:  c.id,
		Query:         subPayload.Query,
		OperationName: subPayload.OperationName,
		Variables:     subPayload.Variables,
		Analysis:      analysis,
		Topics:        extractTopics(analysis),
		DataCh:        make(chan *SubscriptionData, c.manager.config.BufferSize),
		ctx:           subCtx,
		cancel:        cancel,
	}

	// Register subscription
	c.mu.Lock()
	c.subscriptions[id] = sub
	c.mu.Unlock()

	// Subscribe to topics
	for _, topic := range sub.Topics {
		c.manager.pubsub.Subscribe(topic, sub)
	}

	// Start data forwarding
	go c.forwardSubscriptionData(sub)

	atomic.AddInt64(&c.manager.stats.activeSubscriptions, 1)
	atomic.AddInt64(&c.manager.stats.totalSubscriptions, 1)

	c.logger.Debug("subscription created", "id", id, "topics", sub.Topics)
	return nil
}

func (c *SubscriptionConnection) forwardSubscriptionData(sub *Subscription) {
	for {
		select {
		case <-sub.ctx.Done():
			return
		case data := <-sub.DataCh:
			if err := c.sendData(sub.ID, data); err != nil {
				c.logger.Debug("failed to send data", "subscription", sub.ID, "error", err)
				return
			}
		}
	}
}

func (c *SubscriptionConnection) handleComplete(id string) error {
	c.mu.Lock()
	sub, exists := c.subscriptions[id]
	if exists {
		delete(c.subscriptions, id)
	}
	c.mu.Unlock()

	if !exists {
		return nil
	}

	// Unsubscribe from topics
	for _, topic := range sub.Topics {
		c.manager.pubsub.Unsubscribe(topic, sub)
	}

	sub.cancel()
	atomic.AddInt64(&c.manager.stats.activeSubscriptions, -1)

	c.logger.Debug("subscription completed", "id", id)
	return nil
}

func (c *SubscriptionConnection) send(msg *SubscriptionMessage) {
	select {
	case c.sendCh <- msg:
	default:
		c.logger.Debug("send buffer full, dropping message")
	}
}

func (c *SubscriptionConnection) sendData(id string, data *SubscriptionData) error {
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()

	if closed {
		return ErrConnectionClosed
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	msgType := MessageNext
	if c.protocol == ProtocolSubscriptionsTransportWS {
		msgType = LegacyMessageData
	}

	c.send(&SubscriptionMessage{
		ID:      id,
		Type:    msgType,
		Payload: payload,
	})

	atomic.AddInt64(&c.manager.stats.messagesDelivered, 1)
	return nil
}

func (c *SubscriptionConnection) sendError(id string, message string) {
	errPayload := []GatewayResponseError{{Message: message}}
	payload, _ := json.Marshal(errPayload)

	c.send(&SubscriptionMessage{
		ID:      id,
		Type:    MessageError,
		Payload: payload,
	})
}

func (c *SubscriptionConnection) sendComplete(id string) {
	c.send(&SubscriptionMessage{
		ID:   id,
		Type: MessageComplete,
	})
}

func (c *SubscriptionConnection) close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	return c.ws.Close()
}

func (c *SubscriptionConnection) getSubscriptionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.subscriptions)
}

// Subscription represents an active GraphQL subscription.
type Subscription struct {
	ID            string
	ConnectionID  string
	Query         string
	OperationName string
	Variables     map[string]interface{}
	Analysis      *QueryAnalysis
	Topics        []string
	DataCh        chan *SubscriptionData
	ctx           context.Context
	cancel        context.CancelFunc
}

// Send sends data to this subscription.
func (s *Subscription) Send(data *SubscriptionData) error {
	select {
	case s.DataCh <- data:
		return nil
	case <-s.ctx.Done():
		return ErrConnectionClosed
	default:
		return ErrBackpressure
	}
}

// Context returns the subscription context.
func (s *Subscription) Context() context.Context {
	return s.ctx
}

// PubSub provides topic-based message distribution.
type PubSub struct {
	topics  map[string]*Topic
	logger  *slog.Logger
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// Topic represents a subscription topic.
type Topic struct {
	name        string
	subscribers map[string]*Subscription
	mu          sync.RWMutex
}

// NewPubSub creates a new pub/sub system.
func NewPubSub(logger *slog.Logger) *PubSub {
	if logger == nil {
		logger = slog.Default()
	}
	return &PubSub{
		topics: make(map[string]*Topic),
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Subscribe adds a subscription to a topic.
func (ps *PubSub) Subscribe(topicName string, sub *Subscription) {
	ps.mu.Lock()
	topic, exists := ps.topics[topicName]
	if !exists {
		topic = &Topic{
			name:        topicName,
			subscribers: make(map[string]*Subscription),
		}
		ps.topics[topicName] = topic
	}
	ps.mu.Unlock()

	topic.mu.Lock()
	topic.subscribers[sub.ID+":"+sub.ConnectionID] = sub
	topic.mu.Unlock()
}

// Unsubscribe removes a subscription from a topic.
func (ps *PubSub) Unsubscribe(topicName string, sub *Subscription) {
	ps.mu.RLock()
	topic, exists := ps.topics[topicName]
	ps.mu.RUnlock()

	if !exists {
		return
	}

	topic.mu.Lock()
	delete(topic.subscribers, sub.ID+":"+sub.ConnectionID)
	count := len(topic.subscribers)
	topic.mu.Unlock()

	// Clean up empty topics
	if count == 0 {
		ps.mu.Lock()
		topic.mu.RLock()
		if len(topic.subscribers) == 0 {
			delete(ps.topics, topicName)
		}
		topic.mu.RUnlock()
		ps.mu.Unlock()
	}
}

// Publish publishes data to all subscribers of a topic.
func (ps *PubSub) Publish(topicName string, data *SubscriptionData) error {
	ps.mu.RLock()
	topic, exists := ps.topics[topicName]
	ps.mu.RUnlock()

	if !exists {
		return nil // No subscribers, not an error
	}

	topic.mu.RLock()
	subscribers := make([]*Subscription, 0, len(topic.subscribers))
	for _, sub := range topic.subscribers {
		subscribers = append(subscribers, sub)
	}
	topic.mu.RUnlock()

	var errors []error
	for _, sub := range subscribers {
		if err := sub.Send(data); err != nil {
			errors = append(errors, fmt.Errorf("subscriber %s: %w", sub.ID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("publish errors: %v", errors)
	}
	return nil
}

// PublishFiltered publishes data only to subscriptions matching the filter.
func (ps *PubSub) PublishFiltered(topicName string, data *SubscriptionData, filter func(*Subscription) bool) error {
	ps.mu.RLock()
	topic, exists := ps.topics[topicName]
	ps.mu.RUnlock()

	if !exists {
		return nil
	}

	topic.mu.RLock()
	for _, sub := range topic.subscribers {
		if filter == nil || filter(sub) {
			sub.Send(data)
		}
	}
	topic.mu.RUnlock()

	return nil
}

// GetTopicCount returns the number of topics.
func (ps *PubSub) GetTopicCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.topics)
}

// GetSubscriberCount returns the total subscriber count for a topic.
func (ps *PubSub) GetSubscriberCount(topicName string) int {
	ps.mu.RLock()
	topic, exists := ps.topics[topicName]
	ps.mu.RUnlock()

	if !exists {
		return 0
	}

	topic.mu.RLock()
	defer topic.mu.RUnlock()
	return len(topic.subscribers)
}

// Close shuts down the pub/sub system.
func (ps *PubSub) Close() {
	close(ps.stopCh)
}

// SubscriptionFilter defines filtering criteria for subscriptions.
type SubscriptionFilter struct {
	// Topics filters by topic names.
	Topics []string
	// Variables filters by variable values.
	Variables map[string]interface{}
	// ConnectionID filters by connection.
	ConnectionID string
	// Custom is a custom filter function.
	Custom func(*Subscription) bool
}

// Match returns true if the subscription matches the filter.
func (f *SubscriptionFilter) Match(sub *Subscription) bool {
	// Check topics
	if len(f.Topics) > 0 {
		matched := false
		for _, topic := range f.Topics {
			for _, subTopic := range sub.Topics {
				if topic == subTopic {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check connection ID
	if f.ConnectionID != "" && sub.ConnectionID != f.ConnectionID {
		return false
	}

	// Check variables
	for key, value := range f.Variables {
		subValue, exists := sub.Variables[key]
		if !exists || subValue != value {
			return false
		}
	}

	// Custom filter
	if f.Custom != nil && !f.Custom(sub) {
		return false
	}

	return true
}

// SubscriptionTrigger represents an event that triggers subscription updates.
type SubscriptionTrigger struct {
	Topic     string
	Event     string
	Payload   interface{}
	Filter    *SubscriptionFilter
	Timestamp time.Time
}

// TriggerHandler processes subscription triggers.
type TriggerHandler struct {
	manager    *SubscriptionManager
	transforms map[string]TriggerTransform
	logger     *slog.Logger
	mu         sync.RWMutex
}

// TriggerTransform transforms trigger payloads to subscription data.
type TriggerTransform func(trigger *SubscriptionTrigger) (*SubscriptionData, error)

// NewTriggerHandler creates a new trigger handler.
func NewTriggerHandler(manager *SubscriptionManager, logger *slog.Logger) *TriggerHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &TriggerHandler{
		manager:    manager,
		transforms: make(map[string]TriggerTransform),
		logger:     logger,
	}
}

// RegisterTransform registers a transform for an event type.
func (h *TriggerHandler) RegisterTransform(event string, transform TriggerTransform) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.transforms[event] = transform
}

// Fire triggers a subscription update.
func (h *TriggerHandler) Fire(trigger *SubscriptionTrigger) error {
	if trigger.Timestamp.IsZero() {
		trigger.Timestamp = time.Now()
	}

	h.mu.RLock()
	transform, exists := h.transforms[trigger.Event]
	h.mu.RUnlock()

	var data *SubscriptionData
	if exists {
		var err error
		data, err = transform(trigger)
		if err != nil {
			return fmt.Errorf("transform failed: %w", err)
		}
	} else {
		// Default: wrap payload as data
		data = &SubscriptionData{
			Data: map[string]interface{}{
				trigger.Event: trigger.Payload,
			},
		}
	}

	// Publish with filter
	if trigger.Filter != nil {
		return h.manager.pubsub.PublishFiltered(trigger.Topic, data, trigger.Filter.Match)
	}

	return h.manager.Publish(trigger.Topic, data)
}

// Context key for subscription init params.
const subscriptionInitParamsKey contextKey = "subscription_init_params"

// GetInitParamsFromContext retrieves subscription init params from context.
func GetInitParamsFromContext(ctx context.Context) map[string]interface{} {
	if params, ok := ctx.Value(subscriptionInitParamsKey).(map[string]interface{}); ok {
		return params
	}
	return nil
}

// Helper functions.

func generateConnectionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func detectProtocol(r *http.Request) SubscriptionProtocol {
	// Check Sec-WebSocket-Protocol header
	protocols := r.Header.Get("Sec-WebSocket-Protocol")
	if protocols != "" {
		for _, p := range strings.Split(protocols, ",") {
			p = strings.TrimSpace(p)
			switch p {
			case string(ProtocolGraphQLWS):
				return ProtocolGraphQLWS
			case string(ProtocolSubscriptionsTransportWS):
				return ProtocolSubscriptionsTransportWS
			}
		}
	}

	// Default to newer protocol
	return ProtocolGraphQLWS
}

func extractTopics(analysis *QueryAnalysis) []string {
	// Extract topic names from the subscription fields
	// Convention: first field of subscription becomes the topic
	topics := []string{}

	for _, field := range analysis.Fields {
		// Take the first-level field as topic
		parts := strings.Split(field, ".")
		if len(parts) > 0 {
			topic := parts[0]
			// Avoid duplicates
			found := false
			for _, t := range topics {
				if t == topic {
					found = true
					break
				}
			}
			if !found {
				topics = append(topics, topic)
			}
		}
	}

	return topics
}

// SubscriptionMiddleware provides HTTP middleware for subscription endpoints.
func SubscriptionMiddleware(manager *SubscriptionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a WebSocket upgrade request
			if strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") {
				manager.Handler().ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SubscriptionAdminHandler provides admin endpoints for subscriptions.
type SubscriptionAdminHandler struct {
	manager *SubscriptionManager
	logger  *slog.Logger
}

// NewSubscriptionAdminHandler creates a new admin handler.
func NewSubscriptionAdminHandler(manager *SubscriptionManager, logger *slog.Logger) *SubscriptionAdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &SubscriptionAdminHandler{
		manager: manager,
		logger:  logger,
	}
}

// ServeHTTP handles admin requests.
func (h *SubscriptionAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/subscriptions/admin")

	switch {
	case path == "/stats" || path == "/stats/":
		h.handleStats(w, r)

	case path == "/connections" || path == "/connections/":
		h.handleConnections(w, r)

	case strings.HasPrefix(path, "/connections/"):
		h.handleConnection(w, r, strings.TrimPrefix(path, "/connections/"))

	default:
		http.NotFound(w, r)
	}
}

func (h *SubscriptionAdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.manager.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *SubscriptionAdminHandler) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.manager.mu.RLock()
	connections := make([]map[string]interface{}, 0, len(h.manager.connections))
	for _, conn := range h.manager.connections {
		conn.mu.RLock()
		connections = append(connections, map[string]interface{}{
			"id":             conn.id,
			"protocol":       conn.protocol,
			"initialized":    conn.initialized,
			"subscriptions":  len(conn.subscriptions),
		})
		conn.mu.RUnlock()
	}
	h.manager.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":       len(connections),
		"connections": connections,
	})
}

func (h *SubscriptionAdminHandler) handleConnection(w http.ResponseWriter, r *http.Request, connID string) {
	switch r.Method {
	case http.MethodGet:
		h.manager.mu.RLock()
		conn, exists := h.manager.connections[connID]
		h.manager.mu.RUnlock()

		if !exists {
			http.Error(w, "connection not found", http.StatusNotFound)
			return
		}

		conn.mu.RLock()
		subs := make([]map[string]interface{}, 0, len(conn.subscriptions))
		for _, sub := range conn.subscriptions {
			subs = append(subs, map[string]interface{}{
				"id":             sub.ID,
				"operation_name": sub.OperationName,
				"topics":         sub.Topics,
			})
		}
		info := map[string]interface{}{
			"id":            conn.id,
			"protocol":      conn.protocol,
			"initialized":   conn.initialized,
			"subscriptions": subs,
		}
		conn.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)

	case http.MethodDelete:
		if err := h.manager.CloseConnection(connID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
