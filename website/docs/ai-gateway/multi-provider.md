---
sidebar_position: 2
title: Multi-Provider Routing
description: Route LLM requests across multiple providers with failover and load balancing.
---

# Multi-Provider Routing

Loom routes LLM requests to multiple providers based on configurable strategies.

## Provider Configuration

### OpenAI

```yaml
ai_gateway:
  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}
      base_url: https://api.openai.com/v1
      organization: org-xxx  # Optional
      models:
        - gpt-4
        - gpt-4-turbo
        - gpt-3.5-turbo
      rate_limit:
        requests_per_minute: 500
        tokens_per_minute: 90000
```

### Anthropic

```yaml
ai_gateway:
  providers:
    - name: anthropic
      type: anthropic
      api_key: ${ANTHROPIC_API_KEY}
      base_url: https://api.anthropic.com
      models:
        - claude-3-opus-20240229
        - claude-3-sonnet-20240229
        - claude-3-haiku-20240307
```

### Azure OpenAI

```yaml
ai_gateway:
  providers:
    - name: azure
      type: azure
      api_key: ${AZURE_API_KEY}
      base_url: https://your-resource.openai.azure.com
      api_version: "2024-02-15-preview"
      deployments:
        gpt-4: my-gpt4-deployment
        gpt-35-turbo: my-gpt35-deployment
```

### Google Vertex AI

```yaml
ai_gateway:
  providers:
    - name: vertex
      type: vertex
      project_id: your-project
      location: us-central1
      credentials_file: /path/to/credentials.json
      models:
        - gemini-pro
        - gemini-pro-vision
```

### Local/Self-Hosted

```yaml
ai_gateway:
  providers:
    - name: local
      type: openai  # OpenAI-compatible API
      base_url: http://localhost:8000/v1
      api_key: dummy  # Required but not validated
      models:
        - llama-2-70b
        - mistral-7b
```

## Routing Strategies

### Priority-Based Routing

Route to highest priority available provider:

```yaml
ai_gateway:
  routing:
    strategy: priority
    providers:
      - name: openai
        priority: 1
        health_check:
          enabled: true
          interval: 30s

      - name: anthropic
        priority: 2

      - name: local
        priority: 3
```

### Round Robin

Distribute requests evenly:

```yaml
ai_gateway:
  routing:
    strategy: round_robin
    providers:
      - name: openai
      - name: anthropic
```

### Weighted Distribution

Custom weights per provider:

```yaml
ai_gateway:
  routing:
    strategy: weighted
    providers:
      - name: openai
        weight: 60

      - name: anthropic
        weight: 30

      - name: local
        weight: 10
```

### Cost-Optimized

Route to cheapest provider:

```yaml
ai_gateway:
  routing:
    strategy: cost
    providers:
      - name: openai
        cost:
          input_per_1k: 0.01
          output_per_1k: 0.03

      - name: anthropic
        cost:
          input_per_1k: 0.008
          output_per_1k: 0.024

      - name: local
        cost:
          input_per_1k: 0.0
          output_per_1k: 0.0
```

### Latency-Optimized

Route to fastest responding provider:

```yaml
ai_gateway:
  routing:
    strategy: latency
    latency:
      window: 5m
      percentile: 95
    providers:
      - name: openai
      - name: anthropic
```

## Model-Based Routing

Route specific models to specific providers:

```yaml
ai_gateway:
  routing:
    strategy: model
    model_routes:
      # GPT models to OpenAI
      gpt-4: openai
      gpt-3.5-turbo: openai

      # Claude models to Anthropic
      claude-3-opus: anthropic
      claude-3-sonnet: anthropic

      # Fallback for unknown models
      default: openai
```

## Failover Configuration

### Basic Failover

```yaml
ai_gateway:
  routing:
    failover:
      enabled: true
      max_retries: 2
      retry_codes:
        - 429  # Rate limited
        - 500  # Server error
        - 502  # Bad gateway
        - 503  # Service unavailable
```

### Circuit Breaker

```yaml
ai_gateway:
  routing:
    failover:
      enabled: true
      circuit_breaker:
        failure_threshold: 5
        success_threshold: 3
        timeout: 60s
```

### Fallback Provider

```yaml
ai_gateway:
  routing:
    strategy: priority
    fallback:
      provider: local
      on_error: true
      on_rate_limit: true
```

## Health Checking

### Active Health Checks

```yaml
ai_gateway:
  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}
      health_check:
        enabled: true
        interval: 30s
        timeout: 5s
        endpoint: /v1/models  # List models endpoint
```

### Provider Status

```bash
curl http://localhost:9091/ai/providers/openai/health
```

```json
{
  "name": "openai",
  "status": "healthy",
  "latency_ms": 145,
  "last_check": "2024-01-15T10:30:00Z",
  "error": null
}
```

## Rate Limiting Per Provider

```yaml
ai_gateway:
  providers:
    - name: openai
      rate_limit:
        requests_per_minute: 500
        tokens_per_minute: 90000
        concurrent_requests: 50

    - name: anthropic
      rate_limit:
        requests_per_minute: 1000
        tokens_per_minute: 100000
```

When a provider's rate limit is reached, requests failover to next provider.

## Request Transformation

### Header Modification

```yaml
ai_gateway:
  providers:
    - name: openai
      headers:
        X-Custom-Header: value

    - name: azure
      headers:
        api-key: ${AZURE_API_KEY}  # Azure uses different header
```

### Model Mapping

Map generic model names:

```yaml
ai_gateway:
  model_mapping:
    # Client requests "gpt-4", provider receives specific model
    gpt-4:
      openai: gpt-4-turbo-preview
      azure: gpt-4
      anthropic: claude-3-opus-20240229

    # Client requests "fast", routes to fastest model
    fast:
      openai: gpt-3.5-turbo
      anthropic: claude-3-haiku-20240307
```

## Monitoring

### Prometheus Metrics

```
# Requests per provider
loom_ai_requests_total{provider="openai",status="success"}
loom_ai_requests_total{provider="openai",status="error"}

# Failovers
loom_ai_failovers_total{from="openai",to="anthropic",reason="rate_limit"}

# Provider latency
loom_ai_provider_latency_seconds{provider="openai",quantile="0.99"}

# Provider health
loom_ai_provider_health{provider="openai"}  # 1=healthy, 0=unhealthy
```

### Admin API

```bash
# List all providers
curl http://localhost:9091/ai/providers

# Provider statistics
curl http://localhost:9091/ai/providers/openai/stats
```

## Complete Example

```yaml
ai_gateway:
  enabled: true

  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}
      models: [gpt-4, gpt-3.5-turbo]
      rate_limit:
        requests_per_minute: 500
        tokens_per_minute: 90000
      health_check:
        enabled: true
        interval: 30s
      cost:
        input_per_1k: 0.01
        output_per_1k: 0.03

    - name: anthropic
      type: anthropic
      api_key: ${ANTHROPIC_API_KEY}
      models: [claude-3-opus, claude-3-sonnet]
      rate_limit:
        requests_per_minute: 1000
      cost:
        input_per_1k: 0.015
        output_per_1k: 0.075

    - name: local
      type: openai
      base_url: http://llm-server:8000/v1
      api_key: dummy
      models: [llama-2-70b]
      cost:
        input_per_1k: 0.0
        output_per_1k: 0.0

  routing:
    strategy: priority
    providers:
      - name: openai
        priority: 1
      - name: anthropic
        priority: 2
      - name: local
        priority: 3

    failover:
      enabled: true
      max_retries: 2
      retry_codes: [429, 500, 502, 503]
      circuit_breaker:
        failure_threshold: 5
        timeout: 60s

  model_mapping:
    gpt-4:
      openai: gpt-4-turbo-preview
      anthropic: claude-3-opus-20240229
      local: llama-2-70b
```

## Next Steps

- **[Token Accounting](./token-accounting)** - Track token usage
- **[Semantic Caching](./semantic-caching)** - Cache responses
- **[Security](./security)** - Protect against prompt injection
