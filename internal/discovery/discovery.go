// Package discovery provides service discovery for backend services.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Endpoint represents a discovered service endpoint.
type Endpoint struct {
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Weight   int               `json:"weight,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Healthy  bool              `json:"healthy"`
}

// HostPort returns the endpoint as host:port string.
func (e *Endpoint) HostPort() string {
	return fmt.Sprintf("%s:%d", e.Address, e.Port)
}

// Service represents a discovered service.
type Service struct {
	Name      string     `json:"name"`
	Endpoints []Endpoint `json:"endpoints"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// HealthyEndpoints returns only healthy endpoints.
func (s *Service) HealthyEndpoints() []Endpoint {
	var healthy []Endpoint
	for _, e := range s.Endpoints {
		if e.Healthy {
			healthy = append(healthy, e)
		}
	}
	return healthy
}

// Provider is the interface for service discovery providers.
type Provider interface {
	// Name returns the provider name.
	Name() string
	// Discover discovers endpoints for a service.
	Discover(ctx context.Context, serviceName string) (*Service, error)
	// Watch watches for changes to a service.
	Watch(ctx context.Context, serviceName string, callback func(*Service)) error
}

// Registry manages service discovery across multiple providers.
type Registry struct {
	providers  map[string]Provider
	services   map[string]*Service
	watchers   map[string][]func(*Service)
	mu         sync.RWMutex
	logger     *slog.Logger
	updateChan chan serviceUpdate
	done       chan struct{}
}

type serviceUpdate struct {
	name    string
	service *Service
}

// NewRegistry creates a new service registry.
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}

	r := &Registry{
		providers:  make(map[string]Provider),
		services:   make(map[string]*Service),
		watchers:   make(map[string][]func(*Service)),
		logger:     logger,
		updateChan: make(chan serviceUpdate, 100),
		done:       make(chan struct{}),
	}

	go r.processUpdates()

	return r
}

// RegisterProvider registers a discovery provider.
func (r *Registry) RegisterProvider(provider Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
	r.logger.Info("provider registered", "provider", provider.Name())
}

// Discover discovers a service using the first available provider.
func (r *Registry) Discover(ctx context.Context, serviceName string) (*Service, error) {
	r.mu.RLock()
	providers := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	r.mu.RUnlock()

	for _, provider := range providers {
		service, err := provider.Discover(ctx, serviceName)
		if err == nil && len(service.Endpoints) > 0 {
			r.cacheService(service)
			return service, nil
		}
	}

	return nil, fmt.Errorf("service not found: %s", serviceName)
}

// GetService returns a cached service.
func (r *Registry) GetService(serviceName string) *Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.services[serviceName]
}

// Watch registers a callback for service changes.
func (r *Registry) Watch(serviceName string, callback func(*Service)) {
	r.mu.Lock()
	r.watchers[serviceName] = append(r.watchers[serviceName], callback)
	r.mu.Unlock()

	// Start watching with all providers
	for _, provider := range r.providers {
		go func(p Provider) {
			ctx := context.Background()
			if err := p.Watch(ctx, serviceName, func(svc *Service) {
				r.updateChan <- serviceUpdate{name: serviceName, service: svc}
			}); err != nil {
				r.logger.Error("watch failed", "provider", p.Name(), "service", serviceName, "error", err)
			}
		}(provider)
	}
}

// cacheService caches a discovered service.
func (r *Registry) cacheService(service *Service) {
	r.mu.Lock()
	r.services[service.Name] = service
	r.mu.Unlock()
}

// processUpdates processes service updates.
func (r *Registry) processUpdates() {
	for {
		select {
		case <-r.done:
			return
		case update := <-r.updateChan:
			r.cacheService(update.service)

			r.mu.RLock()
			callbacks := r.watchers[update.name]
			r.mu.RUnlock()

			for _, callback := range callbacks {
				callback(update.service)
			}
		}
	}
}

// Close closes the registry.
func (r *Registry) Close() {
	close(r.done)
}

// DNSProvider discovers services using DNS.
type DNSProvider struct {
	resolver  *net.Resolver
	port      int
	ttl       time.Duration
	dnsServer string
	logger    *slog.Logger
}

// DNSConfig configures DNS discovery.
type DNSConfig struct {
	// DNSServer is the DNS server address (optional).
	DNSServer string
	// DefaultPort is the default port for discovered endpoints.
	DefaultPort int
	// TTL is the cache duration for DNS results.
	TTL time.Duration
	// Logger for DNS provider events.
	Logger *slog.Logger
}

// NewDNSProvider creates a new DNS discovery provider.
func NewDNSProvider(cfg DNSConfig) *DNSProvider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DefaultPort == 0 {
		cfg.DefaultPort = 80
	}
	if cfg.TTL == 0 {
		cfg.TTL = 30 * time.Second
	}

	resolver := net.DefaultResolver
	if cfg.DNSServer != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, cfg.DNSServer)
			},
		}
	}

	return &DNSProvider{
		resolver:  resolver,
		port:      cfg.DefaultPort,
		ttl:       cfg.TTL,
		dnsServer: cfg.DNSServer,
		logger:    cfg.Logger,
	}
}

// Name returns the provider name.
func (p *DNSProvider) Name() string {
	return "dns"
}

// Discover discovers endpoints using DNS.
func (p *DNSProvider) Discover(ctx context.Context, serviceName string) (*Service, error) {
	// Try SRV record first
	_, srvRecords, err := p.resolver.LookupSRV(ctx, "", "", serviceName)
	if err == nil && len(srvRecords) > 0 {
		return p.fromSRVRecords(serviceName, srvRecords), nil
	}

	// Fall back to A records
	addrs, err := p.resolver.LookupHost(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}

	endpoints := make([]Endpoint, 0, len(addrs))
	for _, addr := range addrs {
		endpoints = append(endpoints, Endpoint{
			Address: addr,
			Port:    p.port,
			Weight:  1,
			Healthy: true,
		})
	}

	return &Service{
		Name:      serviceName,
		Endpoints: endpoints,
		UpdatedAt: time.Now(),
	}, nil
}

// fromSRVRecords creates a service from SRV records.
func (p *DNSProvider) fromSRVRecords(name string, records []*net.SRV) *Service {
	endpoints := make([]Endpoint, 0, len(records))
	for _, srv := range records {
		endpoints = append(endpoints, Endpoint{
			Address: strings.TrimSuffix(srv.Target, "."),
			Port:    int(srv.Port),
			Weight:  int(srv.Weight),
			Healthy: true,
		})
	}

	// Sort by priority
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Weight > endpoints[j].Weight
	})

	return &Service{
		Name:      name,
		Endpoints: endpoints,
		UpdatedAt: time.Now(),
	}
}

// Watch watches for DNS changes by polling.
func (p *DNSProvider) Watch(ctx context.Context, serviceName string, callback func(*Service)) error {
	ticker := time.NewTicker(p.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			service, err := p.Discover(ctx, serviceName)
			if err != nil {
				p.logger.Error("dns watch poll failed", "service", serviceName, "error", err)
				continue
			}
			callback(service)
		}
	}
}

// ConsulProvider discovers services using Consul.
type ConsulProvider struct {
	addr       string
	token      string
	datacenter string
	httpClient *http.Client
	logger     *slog.Logger
}

// ConsulConfig configures Consul discovery.
type ConsulConfig struct {
	// Address is the Consul HTTP address.
	Address string
	// Token is the Consul ACL token (optional).
	Token string
	// Datacenter is the Consul datacenter (optional).
	Datacenter string
	// Logger for Consul provider events.
	Logger *slog.Logger
}

// NewConsulProvider creates a new Consul discovery provider.
func NewConsulProvider(cfg ConsulConfig) *ConsulProvider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Address == "" {
		cfg.Address = "http://localhost:8500"
	}

	return &ConsulProvider{
		addr:       strings.TrimSuffix(cfg.Address, "/"),
		token:      cfg.Token,
		datacenter: cfg.Datacenter,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     cfg.Logger,
	}
}

// Name returns the provider name.
func (p *ConsulProvider) Name() string {
	return "consul"
}

// consulServiceEntry represents a Consul service entry.
type consulServiceEntry struct {
	Service struct {
		ID      string            `json:"ID"`
		Service string            `json:"Service"`
		Tags    []string          `json:"Tags"`
		Address string            `json:"Address"`
		Port    int               `json:"Port"`
		Meta    map[string]string `json:"Meta"`
		Weights struct {
			Passing int `json:"Passing"`
			Warning int `json:"Warning"`
		} `json:"Weights"`
	} `json:"Service"`
	Checks []struct {
		Status string `json:"Status"`
	} `json:"Checks"`
}

// Discover discovers endpoints using Consul.
func (p *ConsulProvider) Discover(ctx context.Context, serviceName string) (*Service, error) {
	url := fmt.Sprintf("%s/v1/health/service/%s?passing=false", p.addr, serviceName)
	if p.datacenter != "" {
		url += "&dc=" + p.datacenter
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if p.token != "" {
		req.Header.Set("X-Consul-Token", p.token)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consul request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("consul returned %d: %s", resp.StatusCode, string(body))
	}

	var entries []consulServiceEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("consul decode failed: %w", err)
	}

	endpoints := make([]Endpoint, 0, len(entries))
	for _, entry := range entries {
		healthy := true
		for _, check := range entry.Checks {
			if check.Status != "passing" {
				healthy = false
				break
			}
		}

		address := entry.Service.Address
		if address == "" {
			address = entry.Service.ID
		}

		weight := entry.Service.Weights.Passing
		if weight == 0 {
			weight = 1
		}

		endpoints = append(endpoints, Endpoint{
			Address:  address,
			Port:     entry.Service.Port,
			Weight:   weight,
			Tags:     entry.Service.Tags,
			Metadata: entry.Service.Meta,
			Healthy:  healthy,
		})
	}

	return &Service{
		Name:      serviceName,
		Endpoints: endpoints,
		UpdatedAt: time.Now(),
	}, nil
}

// Watch watches for Consul service changes using blocking queries.
func (p *ConsulProvider) Watch(ctx context.Context, serviceName string, callback func(*Service)) error {
	var index uint64 = 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s/v1/health/service/%s?index=%d&wait=30s", p.addr, serviceName, index)
		if p.datacenter != "" {
			url += "&dc=" + p.datacenter
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}

		if p.token != "" {
			req.Header.Set("X-Consul-Token", p.token)
		}

		resp, err := p.httpClient.Do(req)
		if err != nil {
			p.logger.Error("consul watch failed", "service", serviceName, "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Parse new index
		if newIndex := resp.Header.Get("X-Consul-Index"); newIndex != "" {
			fmt.Sscanf(newIndex, "%d", &index)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		var entries []consulServiceEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			resp.Body.Close()
			p.logger.Error("consul decode failed", "error", err)
			continue
		}
		resp.Body.Close()

		endpoints := make([]Endpoint, 0, len(entries))
		for _, entry := range entries {
			healthy := true
			for _, check := range entry.Checks {
				if check.Status != "passing" {
					healthy = false
					break
				}
			}

			address := entry.Service.Address
			if address == "" {
				address = entry.Service.ID
			}

			weight := entry.Service.Weights.Passing
			if weight == 0 {
				weight = 1
			}

			endpoints = append(endpoints, Endpoint{
				Address:  address,
				Port:     entry.Service.Port,
				Weight:   weight,
				Tags:     entry.Service.Tags,
				Metadata: entry.Service.Meta,
				Healthy:  healthy,
			})
		}

		callback(&Service{
			Name:      serviceName,
			Endpoints: endpoints,
			UpdatedAt: time.Now(),
		})
	}
}

// KubernetesProvider discovers services using Kubernetes.
type KubernetesProvider struct {
	apiServer   string
	namespace   string
	token       string
	httpClient  *http.Client
	logger      *slog.Logger
	inCluster   bool
}

// KubernetesConfig configures Kubernetes discovery.
type KubernetesConfig struct {
	// APIServer is the Kubernetes API server URL.
	APIServer string
	// Namespace is the Kubernetes namespace (defaults to "default").
	Namespace string
	// Token is the service account token.
	Token string
	// InCluster indicates if running inside a Kubernetes cluster.
	InCluster bool
	// Logger for Kubernetes provider events.
	Logger *slog.Logger
}

// NewKubernetesProvider creates a new Kubernetes discovery provider.
func NewKubernetesProvider(cfg KubernetesConfig) *KubernetesProvider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}

	return &KubernetesProvider{
		apiServer:  strings.TrimSuffix(cfg.APIServer, "/"),
		namespace:  cfg.Namespace,
		token:      cfg.Token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     cfg.Logger,
		inCluster:  cfg.InCluster,
	}
}

// Name returns the provider name.
func (p *KubernetesProvider) Name() string {
	return "kubernetes"
}

// k8sEndpoints represents Kubernetes endpoints.
type k8sEndpoints struct {
	Kind    string `json:"kind"`
	Subsets []struct {
		Addresses []struct {
			IP       string `json:"ip"`
			NodeName string `json:"nodeName"`
		} `json:"addresses"`
		NotReadyAddresses []struct {
			IP string `json:"ip"`
		} `json:"notReadyAddresses"`
		Ports []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
		} `json:"ports"`
	} `json:"subsets"`
}

// Discover discovers endpoints using Kubernetes.
func (p *KubernetesProvider) Discover(ctx context.Context, serviceName string) (*Service, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/endpoints/%s",
		p.apiServer, p.namespace, serviceName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubernetes returned %d: %s", resp.StatusCode, string(body))
	}

	var endpoints k8sEndpoints
	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return nil, fmt.Errorf("kubernetes decode failed: %w", err)
	}

	return p.parseEndpoints(serviceName, &endpoints), nil
}

// parseEndpoints parses Kubernetes endpoints.
func (p *KubernetesProvider) parseEndpoints(name string, k8sEp *k8sEndpoints) *Service {
	var eps []Endpoint

	for _, subset := range k8sEp.Subsets {
		port := 80
		if len(subset.Ports) > 0 {
			port = subset.Ports[0].Port
		}

		for _, addr := range subset.Addresses {
			eps = append(eps, Endpoint{
				Address: addr.IP,
				Port:    port,
				Weight:  1,
				Healthy: true,
				Metadata: map[string]string{
					"nodeName": addr.NodeName,
				},
			})
		}

		// Add not-ready addresses as unhealthy
		for _, addr := range subset.NotReadyAddresses {
			eps = append(eps, Endpoint{
				Address: addr.IP,
				Port:    port,
				Weight:  1,
				Healthy: false,
			})
		}
	}

	return &Service{
		Name:      name,
		Endpoints: eps,
		UpdatedAt: time.Now(),
	}
}

// Watch watches for Kubernetes endpoint changes.
func (p *KubernetesProvider) Watch(ctx context.Context, serviceName string, callback func(*Service)) error {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/endpoints?watch=true&fieldSelector=metadata.name=%s",
		p.apiServer, p.namespace, serviceName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("kubernetes watch failed: %w", err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)

	type watchEvent struct {
		Type   string       `json:"type"`
		Object k8sEndpoints `json:"object"`
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var event watchEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("kubernetes watch decode failed: %w", err)
		}

		service := p.parseEndpoints(serviceName, &event.Object)
		callback(service)
	}
}

// StaticProvider provides static service endpoints.
type StaticProvider struct {
	services map[string]*Service
	mu       sync.RWMutex
	logger   *slog.Logger
}

// NewStaticProvider creates a new static discovery provider.
func NewStaticProvider(logger *slog.Logger) *StaticProvider {
	if logger == nil {
		logger = slog.Default()
	}
	return &StaticProvider{
		services: make(map[string]*Service),
		logger:   logger,
	}
}

// Name returns the provider name.
func (p *StaticProvider) Name() string {
	return "static"
}

// RegisterService registers a static service.
func (p *StaticProvider) RegisterService(name string, endpoints []Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.services[name] = &Service{
		Name:      name,
		Endpoints: endpoints,
		UpdatedAt: time.Now(),
	}
}

// Discover returns a static service.
func (p *StaticProvider) Discover(ctx context.Context, serviceName string) (*Service, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if svc, ok := p.services[serviceName]; ok {
		return svc, nil
	}
	return nil, fmt.Errorf("service not found: %s", serviceName)
}

// Watch does nothing for static provider.
func (p *StaticProvider) Watch(ctx context.Context, serviceName string, callback func(*Service)) error {
	// Static provider doesn't support watching
	<-ctx.Done()
	return ctx.Err()
}

// LoadBalancer provides load balancing across endpoints.
type LoadBalancer struct {
	strategy LoadBalancerStrategy
	mu       sync.Mutex
	index    int
}

// LoadBalancerStrategy defines load balancing strategies.
type LoadBalancerStrategy int

const (
	RoundRobin LoadBalancerStrategy = iota
	Random
	WeightedRoundRobin
	LeastConnections
)

// NewLoadBalancer creates a new load balancer.
func NewLoadBalancer(strategy LoadBalancerStrategy) *LoadBalancer {
	return &LoadBalancer{
		strategy: strategy,
	}
}

// SelectEndpoint selects an endpoint from the service.
func (lb *LoadBalancer) SelectEndpoint(service *Service) *Endpoint {
	endpoints := service.HealthyEndpoints()
	if len(endpoints) == 0 {
		return nil
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()

	switch lb.strategy {
	case RoundRobin:
		ep := &endpoints[lb.index%len(endpoints)]
		lb.index++
		return ep
	case WeightedRoundRobin:
		return lb.selectWeighted(endpoints)
	default:
		return &endpoints[lb.index%len(endpoints)]
	}
}

// selectWeighted selects an endpoint based on weight.
func (lb *LoadBalancer) selectWeighted(endpoints []Endpoint) *Endpoint {
	totalWeight := 0
	for _, ep := range endpoints {
		totalWeight += ep.Weight
	}

	if totalWeight == 0 {
		return &endpoints[0]
	}

	lb.index = (lb.index + 1) % totalWeight
	current := lb.index

	for i := range endpoints {
		current -= endpoints[i].Weight
		if current < 0 {
			return &endpoints[i]
		}
	}

	return &endpoints[0]
}

// Handler provides an HTTP API for service discovery.
type Handler struct {
	registry *Registry
	logger   *slog.Logger
}

// NewHandler creates a new discovery handler.
func NewHandler(registry *Registry, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		registry: registry,
		logger:   logger,
	}
}

// ServeHTTP handles discovery requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/discovery")

	switch {
	case path == "" || path == "/":
		h.handleList(w, r)
	case strings.HasPrefix(path, "/services/"):
		serviceName := strings.TrimPrefix(path, "/services/")
		h.handleService(w, r, serviceName)
	default:
		http.NotFound(w, r)
	}
}

// handleList lists all cached services.
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	h.registry.mu.RLock()
	services := make([]*Service, 0, len(h.registry.services))
	for _, svc := range h.registry.services {
		services = append(services, svc)
	}
	h.registry.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}

// handleService returns a specific service.
func (h *Handler) handleService(w http.ResponseWriter, r *http.Request, serviceName string) {
	ctx := r.Context()

	service, err := h.registry.Discover(ctx, serviceName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}
