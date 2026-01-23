---
sidebar_position: 3
title: Token Accounting
description: Track token usage and costs per user, team, or API key.
---

# Token Accounting

Track token usage and costs across providers, users, and applications.

## How Token Counting Works

```mermaid
flowchart LR
    Request --> Count[Count Input Tokens]
    Count --> Forward[Forward to Provider]
    Forward --> Response
    Response --> CountOut[Count Output Tokens]
    CountOut --> Store[Store Usage]
    Store --> Metrics
    Store --> Billing
```

## Enable Token Accounting

```yaml
ai_gateway:
  token_accounting:
    enabled: true
    storage: memory  # or redis
```

## Counting Methods

### From Response Headers

Most providers return token counts in response:

```yaml
ai_gateway:
  token_accounting:
    source: response
```

### Client-Side Estimation

Estimate tokens before sending (for rate limiting):

```yaml
ai_gateway:
  token_accounting:
    source: estimate
    tokenizer: cl100k_base  # GPT-4 tokenizer
```

### Hybrid

Estimate for rate limiting, use response for billing:

```yaml
ai_gateway:
  token_accounting:
    input_source: estimate
    output_source: response
```

## Usage Keys

Track usage by different dimensions:

### By API Key

```yaml
ai_gateway:
  token_accounting:
    key: header:X-API-Key
```

### By User

```yaml
ai_gateway:
  token_accounting:
    key: jwt:sub
```

### By Organization

```yaml
ai_gateway:
  token_accounting:
    key: header:X-Organization-ID
```

### Composite Key

```yaml
ai_gateway:
  token_accounting:
    key: "{header:X-Organization-ID}:{jwt:sub}"
```

## Token Limits

### Per-Request Limits

```yaml
ai_gateway:
  limits:
    max_input_tokens: 8000
    max_output_tokens: 4000
    max_total_tokens: 12000
```

### Per-User Limits

```yaml
ai_gateway:
  token_accounting:
    key: jwt:sub
    limits:
      - name: per_minute
        window: 1m
        max_tokens: 10000

      - name: per_day
        window: 24h
        max_tokens: 1000000
```

### Tiered Limits

```yaml
ai_gateway:
  token_accounting:
    tiers:
      - name: free
        match:
          header: X-Plan
          value: free
        limits:
          per_day: 10000

      - name: pro
        match:
          header: X-Plan
          value: pro
        limits:
          per_day: 1000000

      - name: enterprise
        match:
          header: X-Plan
          value: enterprise
        limits:
          per_day: unlimited
```

## Cost Tracking

### Provider Costs

```yaml
ai_gateway:
  providers:
    - name: openai
      cost:
        gpt-4:
          input_per_1k: 0.03
          output_per_1k: 0.06
        gpt-3.5-turbo:
          input_per_1k: 0.0005
          output_per_1k: 0.0015

    - name: anthropic
      cost:
        claude-3-opus:
          input_per_1k: 0.015
          output_per_1k: 0.075
        claude-3-sonnet:
          input_per_1k: 0.003
          output_per_1k: 0.015
```

### Cost Limits

```yaml
ai_gateway:
  token_accounting:
    key: header:X-API-Key
    cost_limits:
      - window: 1h
        max_cost: 10.00

      - window: 24h
        max_cost: 100.00

      - window: 720h  # 30 days
        max_cost: 1000.00
```

## Storage Backends

### In-Memory

```yaml
ai_gateway:
  token_accounting:
    storage: memory
    retention: 24h
```

### Redis

```yaml
ai_gateway:
  token_accounting:
    storage: redis
    redis:
      address: redis:6379
      password: secret
      db: 0
      key_prefix: "loom:tokens:"
```

### PostgreSQL

```yaml
ai_gateway:
  token_accounting:
    storage: postgres
    postgres:
      connection_string: postgres://user:pass@localhost/loom
      table: token_usage
```

## Usage API

### Get Usage

```bash
curl "http://localhost:9091/ai/usage?key=user-123&window=24h"
```

```json
{
  "key": "user-123",
  "window": "24h",
  "usage": {
    "input_tokens": 50000,
    "output_tokens": 25000,
    "total_tokens": 75000,
    "cost_usd": 2.25,
    "requests": 150
  },
  "limits": {
    "tokens_remaining": 925000,
    "cost_remaining": 97.75
  },
  "by_provider": {
    "openai": {
      "input_tokens": 30000,
      "output_tokens": 15000,
      "cost_usd": 1.35
    },
    "anthropic": {
      "input_tokens": 20000,
      "output_tokens": 10000,
      "cost_usd": 0.90
    }
  },
  "by_model": {
    "gpt-4": {
      "input_tokens": 20000,
      "output_tokens": 10000
    },
    "gpt-3.5-turbo": {
      "input_tokens": 10000,
      "output_tokens": 5000
    }
  }
}
```

### List Top Users

```bash
curl "http://localhost:9091/ai/usage/top?window=24h&limit=10"
```

### Reset Usage

```bash
curl -X DELETE "http://localhost:9091/ai/usage?key=user-123"
```

## Response Headers

Include usage information in response:

```yaml
ai_gateway:
  token_accounting:
    response_headers:
      enabled: true
```

Headers returned:

```
X-Tokens-Input: 1000
X-Tokens-Output: 500
X-Tokens-Total: 1500
X-Tokens-Remaining: 8500
X-Cost-USD: 0.045
X-Rate-Limit-Remaining: 50
X-Rate-Limit-Reset: 1705312800
```

## Webhooks

Notify on usage events:

```yaml
ai_gateway:
  token_accounting:
    webhooks:
      - url: https://billing.example.com/webhook
        events:
          - limit_warning  # 80% of limit
          - limit_reached
        threshold: 0.8
```

Webhook payload:

```json
{
  "event": "limit_warning",
  "key": "user-123",
  "limit": "per_day",
  "current_usage": 800000,
  "limit_value": 1000000,
  "percentage": 80,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Monitoring

### Prometheus Metrics

```
# Total tokens
loom_ai_tokens_total{provider="openai",model="gpt-4",type="input"}
loom_ai_tokens_total{provider="openai",model="gpt-4",type="output"}

# Tokens per key
loom_ai_tokens_by_key{key="user-123",type="input"}

# Cost
loom_ai_cost_total{provider="openai",model="gpt-4"}
loom_ai_cost_by_key{key="user-123"}

# Rate limit hits
loom_ai_rate_limit_exceeded_total{key="user-123",limit="per_minute"}
```

## Complete Example

```yaml
ai_gateway:
  enabled: true

  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}
      cost:
        gpt-4:
          input_per_1k: 0.03
          output_per_1k: 0.06
        gpt-3.5-turbo:
          input_per_1k: 0.0005
          output_per_1k: 0.0015

  token_accounting:
    enabled: true
    key: header:X-API-Key
    storage: redis
    redis:
      address: redis:6379

    limits:
      - name: per_minute
        window: 1m
        max_tokens: 10000

      - name: per_day
        window: 24h
        max_tokens: 1000000

    cost_limits:
      - window: 24h
        max_cost: 100.00

      - window: 720h
        max_cost: 1000.00

    tiers:
      - name: free
        match:
          header: X-Plan
          value: free
        limits:
          per_day: 10000
        cost_limits:
          per_day: 1.00

      - name: pro
        match:
          header: X-Plan
          value: pro
        limits:
          per_day: 1000000
        cost_limits:
          per_day: 100.00

    response_headers:
      enabled: true

    webhooks:
      - url: https://billing.example.com/webhook
        events: [limit_warning, limit_reached]
        threshold: 0.8
```

## Next Steps

- **[Semantic Caching](./semantic-caching)** - Reduce token usage with caching
- **[Security](./security)** - Protect against abuse
- **[Multi-Provider](./multi-provider)** - Route to cheapest provider
