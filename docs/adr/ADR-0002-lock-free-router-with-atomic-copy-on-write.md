# ADR-0002: Lock-Free Router with Atomic Copy-on-Write

## Status

Accepted

## Context

The router is the hottest path in any API gateway—every single request must be matched against routing rules to determine which upstream should handle it. Loom needed a routing solution that could:

1. **Handle high concurrency** - Thousands of concurrent requests matching routes simultaneously
2. **Support dynamic updates** - Routes can be added, modified, or removed via hot-reload without restarts
3. **Minimize latency** - Route matching should add minimal overhead to request processing
4. **Scale with route count** - Performance should not degrade significantly as routes are added

Traditional approaches to concurrent data structures involve read-write locks (RWMutex), which create contention under high read loads. Even read locks require atomic operations and cache line bouncing across CPU cores.

## Decision

We implemented a **lock-free router using `atomic.Value` with copy-on-write semantics** for configuration updates.

```go
// internal/router/router.go
type Router struct {
    routes atomic.Value // holds *routeTable (immutable snapshot)
    mu     sync.Mutex   // only held during writes
}

type routeTable struct {
    tree     *radixTree           // immutable after creation
    byID     map[string]*Route    // route lookup by ID
    byHost   map[string]*radixTree // host-based routing
}

func (r *Router) Match(host, path string) (*Route, map[string]string) {
    // Lock-free read - no synchronization needed
    table := r.routes.Load().(*routeTable)

    // Try host-specific routes first
    if hostTree, ok := table.byHost[host]; ok {
        if route, params := hostTree.match(path); route != nil {
            return route, params
        }
    }

    // Fall back to default routes
    return table.tree.match(path)
}

func (r *Router) Configure(routes []config.RouteConfig) error {
    r.mu.Lock()
    defer r.mu.Unlock()

    // Build entirely new routing table
    newTable := buildRouteTable(routes)

    // Atomic swap - readers see old or new, never partial
    r.routes.Store(newTable)
    return nil
}
```

The radix tree (prefix tree) provides O(m) lookup where m is the path length, independent of the number of routes.

## Consequences

### Positive

- **Zero contention on reads** - `atomic.Value.Load()` is a single atomic pointer read. No locks, no CAS loops, no cache line invalidation from lock state changes. This is critical for the hot path.

- **Consistent performance under load** - Read performance does not degrade as concurrency increases. 1000 concurrent readers perform the same as 1 reader.

- **Safe concurrent updates** - Writers hold a mutex (rare operation), but readers are never blocked. Configuration updates happen atomically—readers see either the old complete state or the new complete state, never a partial update.

- **Simplified reasoning** - The routing table is immutable once published. No need to reason about concurrent modification, iterator invalidation, or partial visibility.

- **Natural hot-reload support** - Swapping the entire routing table atomically aligns perfectly with file-based configuration reload. When config changes, we build a new table and swap it in.

### Negative

- **Memory amplification during updates** - Each configuration change creates an entirely new routing table. For a brief period, both old and new tables exist in memory. With large route counts (10,000+), this can cause memory spikes.

- **Update latency** - Building a new radix tree is O(n * m) where n is route count and m is average path length. For very large configurations, updates may take tens of milliseconds.

- **No incremental updates** - Cannot efficiently add a single route; must rebuild the entire table. This is acceptable for file-based config but would be inefficient for high-frequency programmatic updates.

### Tradeoffs Accepted

We optimized for read performance at the cost of write efficiency. This matches Loom's usage pattern:

- **Reads**: Millions per second (every request)
- **Writes**: Rare (configuration changes, typically minutes to hours apart)

For use cases requiring frequent programmatic route updates, a different data structure (concurrent skip list, lock-striped map) might be more appropriate.

## Alternatives Considered

1. **sync.RWMutex** - Rejected due to read lock contention under high concurrency
2. **sync.Map** - Rejected because route matching requires tree traversal, not key lookup
3. **Channel-based updates** - Rejected due to complexity and no performance benefit for reads
4. **Lock-free radix tree** - Rejected due to implementation complexity; copy-on-write is simpler and sufficient

## References

- [Go atomic.Value documentation](https://pkg.go.dev/sync/atomic#Value)
- [Radix tree data structure](https://en.wikipedia.org/wiki/Radix_tree)
- [Copy-on-write concurrency pattern](https://en.wikipedia.org/wiki/Copy-on-write)
