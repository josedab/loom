# ADR-0009: Pluggable Load Balancing Strategy Interface

## Status

Accepted

## Context

Load balancing is fundamental to API gateway functionality. Different use cases require different distribution strategies:

- **Stateless APIs** - Round-robin or random distribution works well
- **Stateful sessions** - Need sticky sessions or consistent hashing
- **Heterogeneous backends** - Some endpoints have more capacity than others
- **Real-time applications** - Should route to least-loaded endpoint
- **A/B testing** - May need predictable assignment based on user ID

Loom needed a load balancing system that could:

1. **Support multiple algorithms** - Different upstreams may need different strategies
2. **Be configurable per-upstream** - Strategy selected via configuration
3. **Handle dynamic endpoints** - Endpoints come and go (health checks, scaling)
4. **Be extensible** - New algorithms can be added without core changes
5. **Be efficient** - Selection happens on every request

## Decision

We defined a **LoadBalancer interface** with five built-in implementations, selectable per-upstream via configuration.

```go
// internal/upstream/upstream.go
type LoadBalancer interface {
    // Select chooses an endpoint from the available set
    Select(endpoints []*Endpoint, req *http.Request) *Endpoint

    // Name returns the balancer's identifier
    Name() string
}

// Available implementations
type RoundRobinBalancer struct {
    counter atomic.Uint64
}

type WeightedBalancer struct {
    // Uses weighted random selection
}

type LeastConnBalancer struct {
    // Tracks active connections per endpoint
}

type RandomBalancer struct {
    // Uniform random selection
}

type ConsistentHashBalancer struct {
    hashRing *HashRing
    hashKey  string  // Header or property to hash
    replicas int     // Virtual nodes per endpoint
}
```

Implementation examples:

```go
// Round-robin: simple atomic counter
func (b *RoundRobinBalancer) Select(endpoints []*Endpoint, req *http.Request) *Endpoint {
    if len(endpoints) == 0 {
        return nil
    }
    idx := b.counter.Add(1) % uint64(len(endpoints))
    return endpoints[idx]
}

// Consistent hash: hash ring with virtual nodes
func (b *ConsistentHashBalancer) Select(endpoints []*Endpoint, req *http.Request) *Endpoint {
    if len(endpoints) == 0 {
        return nil
    }

    // Get hash key from request
    key := b.getHashKey(req)
    hash := fnv64(key)

    // Find endpoint on ring
    return b.hashRing.Get(hash)
}

func (b *ConsistentHashBalancer) getHashKey(req *http.Request) string {
    switch b.hashKey {
    case "client_ip":
        return clientIP(req)
    case "uri":
        return req.URL.Path
    default:
        // Header name
        return req.Header.Get(b.hashKey)
    }
}

// Least connections: track active requests per endpoint
func (b *LeastConnBalancer) Select(endpoints []*Endpoint, req *http.Request) *Endpoint {
    if len(endpoints) == 0 {
        return nil
    }

    var selected *Endpoint
    minConn := int64(math.MaxInt64)

    for _, ep := range endpoints {
        conn := ep.activeConns.Load()
        if conn < minConn {
            minConn = conn
            selected = ep
        }
    }

    return selected
}
```

Factory function for configuration:

```go
func NewLoadBalancer(cfg config.LoadBalancerConfig) (LoadBalancer, error) {
    switch cfg.Strategy {
    case "round_robin", "":
        return &RoundRobinBalancer{}, nil

    case "weighted":
        return NewWeightedBalancer(cfg.Weights), nil

    case "least_conn":
        return &LeastConnBalancer{}, nil

    case "random":
        return &RandomBalancer{}, nil

    case "consistent_hash":
        return NewConsistentHashBalancer(cfg.HashKey, cfg.Replicas), nil

    default:
        return nil, fmt.Errorf("unknown load balancer strategy: %s", cfg.Strategy)
    }
}
```

## Consequences

### Positive

- **Right tool for the job** - Each upstream can use the most appropriate algorithm. Payment service uses consistent hashing for session affinity; CDN uses round-robin.

- **Easy to extend** - Adding a new algorithm requires implementing the interface and adding a factory case. No changes to routing or proxy code.

- **Configuration-driven** - Strategy changes via YAML, no code changes or restarts needed (with hot reload):
  ```yaml
  upstreams:
    - name: user-service
      load_balancer: consistent_hash
      consistent_hash:
        key: X-User-ID
        replicas: 150
  ```

- **Testable** - Each balancer is a standalone unit, easily tested:
  ```go
  func TestRoundRobin(t *testing.T) {
      balancer := &RoundRobinBalancer{}
      endpoints := []*Endpoint{{Address: "a"}, {Address: "b"}, {Address: "c"}}

      counts := make(map[string]int)
      for i := 0; i < 300; i++ {
          ep := balancer.Select(endpoints, nil)
          counts[ep.Address]++
      }

      // Each should get exactly 100 (300/3)
      assert.Equal(t, 100, counts["a"])
      assert.Equal(t, 100, counts["b"])
      assert.Equal(t, 100, counts["c"])
  }
  ```

- **Works with health checking** - Balancers receive only healthy endpoints. When an endpoint fails health checks, it's removed from the input slice.

### Negative

- **Strategy proliferation** - Five strategies may be confusing. Documentation must clearly explain when to use each.

- **Consistent hash complexity** - Hash ring implementation is non-trivial. Ring rebuilding on endpoint changes can be expensive.

- **Weighted balancer edge cases** - Zero weights, negative weights, and all-zero weights need careful handling.

- **Request access in interface** - Some strategies don't need the request (round-robin), but interface requires passing it for those that do (consistent hash).

### Strategy Selection Guide

| Strategy | Use Case | Pros | Cons |
|----------|----------|------|------|
| **round_robin** | Stateless APIs, homogeneous backends | Simple, fair distribution | No affinity |
| **weighted** | Heterogeneous capacity | Respects capacity differences | Manual weight management |
| **least_conn** | Variable request durations | Adapts to actual load | Tracking overhead |
| **random** | Large endpoint pools | No coordination needed | Can be uneven short-term |
| **consistent_hash** | Session affinity, caching | Predictable routing | Uneven with few endpoints |

### Configuration Examples

```yaml
# Default round-robin
upstreams:
  - name: api
    endpoints:
      - api1:8080
      - api2:8080
    load_balancer: round_robin

# Weighted for heterogeneous capacity
upstreams:
  - name: compute
    endpoints:
      - large-instance:8080
      - small-instance:8080
    load_balancer: weighted
    weights:
      large-instance:8080: 80
      small-instance:8080: 20

# Consistent hash for session affinity
upstreams:
  - name: user-sessions
    endpoints:
      - session1:8080
      - session2:8080
      - session3:8080
    load_balancer: consistent_hash
    consistent_hash:
      key: X-Session-ID   # Hash this header
      replicas: 150       # Virtual nodes per endpoint

# Least connections for variable workloads
upstreams:
  - name: processor
    endpoints:
      - worker1:8080
      - worker2:8080
    load_balancer: least_conn
```

### Consistent Hashing Details

The consistent hash implementation uses a hash ring with virtual nodes:

```go
type HashRing struct {
    ring     []uint64           // Sorted hash values
    nodes    map[uint64]*Endpoint
    replicas int
}

func (r *HashRing) Add(endpoint *Endpoint) {
    for i := 0; i < r.replicas; i++ {
        hash := fnv64(fmt.Sprintf("%s-%d", endpoint.Address, i))
        r.ring = append(r.ring, hash)
        r.nodes[hash] = endpoint
    }
    sort.Slice(r.ring, func(i, j int) bool {
        return r.ring[i] < r.ring[j]
    })
}

func (r *HashRing) Get(hash uint64) *Endpoint {
    idx := sort.Search(len(r.ring), func(i int) bool {
        return r.ring[i] >= hash
    })
    if idx == len(r.ring) {
        idx = 0  // Wrap around
    }
    return r.nodes[r.ring[idx]]
}
```

Benefits of virtual nodes (replicas):
- More even distribution across endpoints
- Smoother rebalancing when endpoints added/removed
- Recommended: 100-200 replicas per endpoint

## Alternatives Considered

1. **Single algorithm** - Rejected; different use cases have genuinely different needs

2. **External load balancer only** - Rejected; gateway should work standalone, not require separate LB

3. **Plugin-based strategies** - Considered; decided built-in strategies cover most cases, can add plugin support later

4. **P2C (Power of Two Choices)** - Considered for future addition; combines benefits of random and least-conn

5. **Maglev hashing** - Considered; consistent hash with better distribution, more complex implementation

## References

- [Consistent Hashing (Wikipedia)](https://en.wikipedia.org/wiki/Consistent_hashing)
- [Load Balancing Algorithms](https://kemptechnologies.com/load-balancer/load-balancing-algorithms-techniques)
- [Maglev: A Fast and Reliable Software Network Load Balancer](https://research.google/pubs/pub44824/)
- [The Power of Two Random Choices](https://www.eecs.harvard.edu/~michaelm/postscripts/mythesis.pdf)
