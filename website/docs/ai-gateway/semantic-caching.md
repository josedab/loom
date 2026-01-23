---
sidebar_position: 4
title: Semantic Caching
description: Cache LLM responses for similar queries to reduce costs.
---

# Semantic Caching

Semantic caching stores LLM responses and returns them for similar (not just identical) queries.

## How It Works

```mermaid
flowchart TB
    Query[New Query] --> Embed[Generate Embedding]
    Embed --> Search[Vector Similarity Search]
    Search --> Check{Similar Query<br/>Found?}
    Check -->|Yes, similarity > threshold| Return[Return Cached Response]
    Check -->|No| Forward[Forward to LLM]
    Forward --> Response[LLM Response]
    Response --> Store[Store Query + Response + Embedding]
    Store --> Return2[Return Response]
```

## Enable Semantic Caching

```yaml
ai_gateway:
  semantic_cache:
    enabled: true
    similarity_threshold: 0.95
    ttl: 1h
```

## Configuration Options

```yaml
ai_gateway:
  semantic_cache:
    enabled: true

    # Similarity threshold (0.0-1.0)
    # Higher = more strict matching
    similarity_threshold: 0.95

    # Cache TTL
    ttl: 1h

    # Embedding model
    embedding:
      provider: openai
      model: text-embedding-3-small

    # Storage backend
    storage:
      type: memory  # or redis, postgres
      max_entries: 10000

    # Cache key components
    cache_key:
      include_model: true
      include_system_prompt: true
      include_temperature: false
```

## Similarity Thresholds

| Threshold | Behavior |
|-----------|----------|
| 0.99+ | Nearly identical queries only |
| 0.95 | Very similar queries |
| 0.90 | Similar intent queries |
| 0.85 | Broadly similar queries |

```yaml
# Strict matching for code generation
ai_gateway:
  semantic_cache:
    routes:
      - path: /v1/code/*
        similarity_threshold: 0.99

# Looser matching for general chat
      - path: /v1/chat/*
        similarity_threshold: 0.90
```

## Embedding Providers

### OpenAI

```yaml
ai_gateway:
  semantic_cache:
    embedding:
      provider: openai
      model: text-embedding-3-small
      api_key: ${OPENAI_API_KEY}
```

### Local

```yaml
ai_gateway:
  semantic_cache:
    embedding:
      provider: local
      model: all-MiniLM-L6-v2
      endpoint: http://embedding-server:8000
```

### Cached Embeddings

Cache embeddings to reduce costs:

```yaml
ai_gateway:
  semantic_cache:
    embedding:
      cache:
        enabled: true
        ttl: 7d
```

## Storage Backends

### In-Memory

Fast but not persistent:

```yaml
ai_gateway:
  semantic_cache:
    storage:
      type: memory
      max_entries: 10000
      eviction: lru
```

### Redis with Vector Search

```yaml
ai_gateway:
  semantic_cache:
    storage:
      type: redis
      redis:
        address: redis:6379
        password: secret
        index: loom_semantic_cache
```

### PostgreSQL with pgvector

```yaml
ai_gateway:
  semantic_cache:
    storage:
      type: postgres
      postgres:
        connection_string: postgres://user:pass@localhost/loom
        table: semantic_cache
```

### Pinecone

```yaml
ai_gateway:
  semantic_cache:
    storage:
      type: pinecone
      pinecone:
        api_key: ${PINECONE_API_KEY}
        environment: us-west1-gcp
        index: loom-cache
```

## Cache Key Components

Control what makes queries "different":

```yaml
ai_gateway:
  semantic_cache:
    cache_key:
      # Include model in cache key
      include_model: true

      # Include system prompt
      include_system_prompt: true

      # Include user ID (per-user caching)
      include_user: false

      # Ignore these parameters
      ignore:
        - temperature
        - top_p
        - presence_penalty
```

### Per-User Caching

```yaml
ai_gateway:
  semantic_cache:
    cache_key:
      include_user: true
      user_key: header:X-User-ID
```

## Selective Caching

### By Route

```yaml
ai_gateway:
  semantic_cache:
    routes:
      - path: /v1/chat/completions
        enabled: true
        ttl: 1h

      - path: /v1/completions
        enabled: true
        ttl: 30m

      - path: /v1/embeddings
        enabled: false  # Don't cache embeddings
```

### By Model

```yaml
ai_gateway:
  semantic_cache:
    models:
      gpt-4:
        enabled: true
        ttl: 2h  # Cache longer for expensive model

      gpt-3.5-turbo:
        enabled: true
        ttl: 30m

      claude-3-opus:
        enabled: true
        ttl: 2h
```

### By Request Header

```yaml
ai_gateway:
  semantic_cache:
    bypass_header: X-Cache-Bypass
```

Requests with `X-Cache-Bypass: true` skip the cache.

## Cache Warmup

Pre-populate cache with common queries:

```yaml
ai_gateway:
  semantic_cache:
    warmup:
      enabled: true
      file: /etc/loom/cache-warmup.jsonl
```

```jsonl title="cache-warmup.jsonl"
{"query": "What is the capital of France?", "response": "The capital of France is Paris."}
{"query": "How do I reset my password?", "response": "To reset your password, click 'Forgot Password' on the login page..."}
```

## Cache Headers

Include cache status in response:

```yaml
ai_gateway:
  semantic_cache:
    response_headers: true
```

Headers:

```
X-Cache: HIT
X-Cache-Similarity: 0.97
X-Cache-Age: 1800
X-Cache-Key: abc123
```

## Cache Management

### View Cache Stats

```bash
curl http://localhost:9091/ai/cache/stats
```

```json
{
  "entries": 5000,
  "size_bytes": 52428800,
  "hit_rate": 0.35,
  "hits": 10000,
  "misses": 18571,
  "avg_similarity": 0.96
}
```

### Search Cache

```bash
curl "http://localhost:9091/ai/cache/search?query=what%20is%20AI"
```

### Invalidate Cache

```bash
# By query
curl -X DELETE "http://localhost:9091/ai/cache?query=what%20is%20AI"

# By model
curl -X DELETE "http://localhost:9091/ai/cache?model=gpt-4"

# Clear all
curl -X DELETE "http://localhost:9091/ai/cache?all=true"
```

## Monitoring

### Prometheus Metrics

```
# Cache operations
loom_ai_cache_requests_total{status="hit"}
loom_ai_cache_requests_total{status="miss"}

# Similarity distribution
loom_ai_cache_similarity_bucket{le="0.90"}
loom_ai_cache_similarity_bucket{le="0.95"}
loom_ai_cache_similarity_bucket{le="0.99"}

# Tokens saved
loom_ai_cache_tokens_saved_total

# Cost saved
loom_ai_cache_cost_saved_total

# Embedding latency
loom_ai_embedding_duration_seconds
```

## Complete Example

```yaml
ai_gateway:
  enabled: true

  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}

  semantic_cache:
    enabled: true
    similarity_threshold: 0.95
    ttl: 1h

    embedding:
      provider: openai
      model: text-embedding-3-small
      cache:
        enabled: true
        ttl: 7d

    storage:
      type: redis
      redis:
        address: redis:6379
        index: loom_semantic_cache

    cache_key:
      include_model: true
      include_system_prompt: true
      include_user: false
      ignore:
        - temperature
        - top_p

    routes:
      - path: /v1/chat/completions
        enabled: true
        similarity_threshold: 0.95

      - path: /v1/embeddings
        enabled: false

    models:
      gpt-4:
        ttl: 2h
      gpt-3.5-turbo:
        ttl: 30m

    bypass_header: X-Cache-Bypass
    response_headers: true

    warmup:
      enabled: true
      file: /etc/loom/cache-warmup.jsonl
```

## Best Practices

1. **Start with high threshold** - Begin at 0.95+, lower if hit rate is too low
2. **Monitor similarity scores** - Understand what's being matched
3. **Exclude dynamic content** - Don't cache time-sensitive queries
4. **Use per-user caching carefully** - May reduce hit rate significantly
5. **Warm up with common queries** - Improve initial hit rate

## Next Steps

- **[Security](./security)** - Protect against prompt injection
- **[Token Accounting](./token-accounting)** - Track savings from caching
- **[Multi-Provider](./multi-provider)** - Provider routing
