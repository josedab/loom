# ADR-0003: Sharded In-Memory Cache Architecture

## Status

Accepted

## Context

Response caching is essential for API gateway performance, reducing backend load and improving response latency for cacheable content. Loom needed a caching solution that could:

1. **Handle extreme concurrency** - Thousands of concurrent cache reads and writes
2. **Provide predictable latency** - Cache operations should not introduce latency spikes
3. **Support TTL and eviction** - Entries must expire and memory must be bounded
4. **Enable stale-while-revalidate** - Serve stale content while refreshing in background
5. **Minimize external dependencies** - Avoid requiring Redis/Memcached for basic caching

The naive approach of a single `sync.RWMutex`-protected map creates a bottleneck: all cache operations serialize on a single lock, causing contention and latency spikes under high load.

## Decision

We implemented a **sharded cache with 256 independent shards**, each with its own mutex and entry map.

```go
// internal/cache/cache.go
type Cache struct {
    shards      []*shard
    shardCount  int           // default: 256
    maxSize     int64         // default: 100MB
    currentSize atomic.Int64
    defaultTTL  time.Duration // default: 5 minutes
    stats       *Stats
}

type shard struct {
    entries map[string]*Entry
    mu      sync.RWMutex
}

type Entry struct {
    Key        string
    StatusCode int
    Headers    http.Header
    Body       []byte
    CreatedAt  time.Time
    ExpiresAt  time.Time
    Size       int64
    ETag       string
    VaryKeys   []string
}

func (c *Cache) Get(key string) (*Entry, bool) {
    shard := c.getShard(key)
    shard.mu.RLock()
    entry, ok := shard.entries[key]
    shard.mu.RUnlock()

    if !ok || time.Now().After(entry.ExpiresAt) {
        c.stats.misses.Add(1)
        return nil, false
    }

    c.stats.hits.Add(1)
    return entry, true
}

func (c *Cache) getShard(key string) *shard {
    hash := fnv32(key)
    return c.shards[hash%uint32(c.shardCount)]
}
```

The shard count (256) was chosen to provide good distribution while maintaining cache locality—each shard's map fits comfortably in CPU cache.

## Consequences

### Positive

- **Reduced lock contention** - With 256 shards, the probability of two concurrent operations hitting the same shard is ~0.4%. Lock contention drops by two orders of magnitude compared to a single lock.

- **Predictable latency** - No single lock becomes a bottleneck. P99 latency remains stable even under high load because operations parallelize across shards.

- **Good cache locality** - Each shard's map is small enough to benefit from CPU cache. Frequently accessed entries stay in L1/L2 cache.

- **Simple implementation** - Sharding is a well-understood pattern. Each shard is a simple mutex-protected map, easy to reason about and debug.

- **Independent cleanup** - Background cleanup goroutine can process shards independently, spreading eviction work over time without stop-the-world pauses.

- **Atomic statistics** - Hit/miss/eviction counters use atomic operations, avoiding lock contention for observability.

### Negative

- **Uneven distribution possible** - Poor key distribution could cause hot shards. FNV-32 hash provides good distribution for typical URL-based keys, but pathological patterns could cause imbalance.

- **Memory overhead** - 256 maps have higher base memory overhead than a single map. Each map has internal bookkeeping structures.

- **Cross-shard operations are expensive** - Operations like "evict all entries matching pattern" require iterating all shards with locks. Bulk operations don't parallelize well.

- **Size tracking is approximate** - Global size tracking uses atomic addition, which can drift slightly under extreme concurrent updates. Periodic reconciliation ensures bounds are respected.

### Configuration

```yaml
cache:
  max_size: 100MB
  default_ttl: 5m
  shard_count: 256
  stale_while_revalidate: 30s
  cleanup_interval: 1m
```

### Stale-While-Revalidate Implementation

```go
func (c *Cache) GetWithStale(key string, staleDuration time.Duration) (*Entry, CacheStatus) {
    shard := c.getShard(key)
    shard.mu.RLock()
    entry, ok := shard.entries[key]
    shard.mu.RUnlock()

    if !ok {
        return nil, CacheMiss
    }

    now := time.Now()
    if now.Before(entry.ExpiresAt) {
        return entry, CacheHit
    }

    // Entry expired but within stale window
    if now.Before(entry.ExpiresAt.Add(staleDuration)) {
        c.stats.staleHits.Add(1)
        return entry, CacheStale // Caller should revalidate async
    }

    return nil, CacheMiss
}
```

## Alternatives Considered

1. **Single sync.Map** - Rejected; still has internal sharding but optimized for different access patterns (few writers, many readers of disjoint keys)

2. **External cache (Redis)** - Available as optional distributed cache, but not required for single-instance deployments. Network round-trip adds latency.

3. **Lock-free hash map** - Rejected due to implementation complexity and unclear benefits over sharded approach

4. **Per-CPU sharding** - Considered but rejected; 256 shards already exceeds typical core counts, and key-based sharding provides better cache hit distribution

## References

- [Sharded Map Pattern](https://github.com/orcaman/concurrent-map)
- [FNV Hash Function](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function)
- [Stale-While-Revalidate (RFC 5861)](https://datatracker.ietf.org/doc/html/rfc5861)
