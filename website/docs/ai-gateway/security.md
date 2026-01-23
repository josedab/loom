---
sidebar_position: 5
title: AI Gateway Security
description: Protect against prompt injection, content filtering, and PII detection.
---

# AI Gateway Security

Loom provides security features to protect your LLM deployments from abuse and attacks.

## Prompt Injection Detection

Detect and block prompt injection attempts:

```yaml
ai_gateway:
  security:
    prompt_injection:
      enabled: true
      action: block  # or warn, log
```

### Detection Patterns

Loom detects common injection patterns:

| Pattern | Example |
|---------|---------|
| Ignore instructions | "Ignore previous instructions and..." |
| Role manipulation | "You are now a different AI..." |
| System prompt extraction | "Print your system prompt" |
| Jailbreak attempts | "DAN mode enabled" |

### Configuration

```yaml
ai_gateway:
  security:
    prompt_injection:
      enabled: true
      action: block

      # Detection sensitivity
      sensitivity: high  # low, medium, high

      # Custom patterns (regex)
      patterns:
        - "ignore.*(previous|above|all).*instructions"
        - "you are now"
        - "print.*system.*prompt"
        - "DAN|jailbreak|bypass"

      # Whitelist patterns
      whitelist:
        - "ignore case sensitivity"
        - "you are now logged in"

      # Response when blocked
      response:
        status: 400
        body: |
          {
            "error": "request_blocked",
            "message": "Request contains potentially harmful content"
          }
```

### Detection Modes

```yaml
# Block request
action: block

# Allow but log warning
action: warn

# Silent logging
action: log
```

## Content Filtering

Filter inappropriate or harmful content:

```yaml
ai_gateway:
  security:
    content_filter:
      enabled: true

      # Filter categories
      categories:
        - hate_speech
        - violence
        - sexual_content
        - self_harm
        - illegal_activity

      # Threshold (0.0-1.0)
      threshold: 0.7

      # Apply to
      apply_to:
        - input
        - output
```

### External Moderation

Use OpenAI's moderation API:

```yaml
ai_gateway:
  security:
    content_filter:
      provider: openai
      api_key: ${OPENAI_API_KEY}
```

### Custom Moderation

```yaml
ai_gateway:
  security:
    content_filter:
      provider: custom
      endpoint: http://moderation-service:8000/check
      timeout: 2s
```

## PII Detection

Detect and redact personally identifiable information:

```yaml
ai_gateway:
  security:
    pii_detection:
      enabled: true
      action: redact  # or block, warn

      types:
        - email
        - phone
        - ssn
        - credit_card
        - ip_address
        - name

      # Redaction format
      redaction: "[REDACTED]"
```

### Selective PII Handling

```yaml
ai_gateway:
  security:
    pii_detection:
      types:
        email:
          action: redact
          replacement: "[EMAIL]"

        credit_card:
          action: block

        name:
          action: warn
```

## Rate Limiting

Prevent abuse with rate limits:

```yaml
ai_gateway:
  security:
    rate_limit:
      enabled: true

      # Per API key
      per_key:
        requests_per_minute: 60
        tokens_per_minute: 10000

      # Per IP
      per_ip:
        requests_per_minute: 10

      # Global
      global:
        requests_per_minute: 1000
```

## Input Validation

Validate request structure:

```yaml
ai_gateway:
  security:
    validation:
      enabled: true

      # Maximum input length
      max_input_tokens: 8000

      # Maximum messages
      max_messages: 100

      # Maximum message length
      max_message_length: 32000

      # Required fields
      required_fields:
        - model
        - messages

      # Blocked models
      blocked_models:
        - gpt-4-vision-preview  # If not supported
```

## Output Filtering

Filter LLM outputs:

```yaml
ai_gateway:
  security:
    output_filter:
      enabled: true

      # Block responses containing
      block_patterns:
        - "I cannot help with"
        - "As an AI"

      # Redact patterns
      redact_patterns:
        - pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
          replacement: "[EMAIL]"
```

## Audit Logging

Log all requests for compliance:

```yaml
ai_gateway:
  security:
    audit:
      enabled: true

      # What to log
      log:
        - request_id
        - timestamp
        - user_id
        - model
        - input_tokens
        - output_tokens
        - duration
        - status

      # Include content (careful with privacy)
      include_content: false

      # Storage
      storage:
        type: file
        path: /var/log/loom/audit.jsonl

      # Or external service
      # storage:
      #   type: http
      #   endpoint: https://audit.example.com/log
```

## IP Allowlist/Blocklist

```yaml
ai_gateway:
  security:
    ip_filter:
      # Allow only these IPs
      allowlist:
        - 10.0.0.0/8
        - 192.168.1.0/24

      # Block these IPs
      blocklist:
        - 1.2.3.4
```

## API Key Validation

```yaml
ai_gateway:
  security:
    api_keys:
      enabled: true
      header: X-API-Key

      keys:
        - key: sk_live_abc123
          name: production
          permissions:
            - models: [gpt-4, gpt-3.5-turbo]
            - max_tokens_per_request: 4000

        - key: sk_test_xyz789
          name: development
          permissions:
            - models: [gpt-3.5-turbo]
            - max_tokens_per_request: 1000
```

## Security Headers

Add security headers to responses:

```yaml
ai_gateway:
  security:
    headers:
      X-Content-Type-Options: nosniff
      X-Frame-Options: DENY
      Content-Security-Policy: "default-src 'none'"
```

## Monitoring

### Prometheus Metrics

```
# Blocked requests
loom_ai_security_blocked_total{reason="prompt_injection"}
loom_ai_security_blocked_total{reason="content_filter"}
loom_ai_security_blocked_total{reason="pii_detected"}
loom_ai_security_blocked_total{reason="rate_limit"}

# Detection counts
loom_ai_injection_detected_total{severity="high"}
loom_ai_pii_detected_total{type="email"}

# False positive tracking
loom_ai_security_false_positive_total
```

### Alerts

```yaml
# Alert on injection attempts
- alert: HighInjectionAttempts
  expr: rate(loom_ai_injection_detected_total[5m]) > 10
  for: 5m
  labels:
    severity: warning
```

## Complete Example

```yaml
ai_gateway:
  enabled: true

  providers:
    - name: openai
      type: openai
      api_key: ${OPENAI_API_KEY}

  security:
    # Prompt injection
    prompt_injection:
      enabled: true
      action: block
      sensitivity: high
      patterns:
        - "ignore.*(previous|above).*instructions"
        - "you are now"
        - "jailbreak"

    # Content filtering
    content_filter:
      enabled: true
      provider: openai
      categories:
        - hate_speech
        - violence
      threshold: 0.7
      apply_to: [input, output]

    # PII detection
    pii_detection:
      enabled: true
      action: redact
      types:
        - email
        - phone
        - credit_card

    # Input validation
    validation:
      max_input_tokens: 8000
      max_messages: 50

    # Rate limiting
    rate_limit:
      per_key:
        requests_per_minute: 60
        tokens_per_minute: 40000

    # Audit logging
    audit:
      enabled: true
      include_content: false
      storage:
        type: file
        path: /var/log/loom/audit.jsonl

    # API keys
    api_keys:
      enabled: true
      header: X-API-Key
```

## Best Practices

1. **Enable prompt injection detection** - Essential for public-facing APIs
2. **Use content filtering** - Especially for user-generated content
3. **Implement rate limiting** - Prevent abuse and cost overruns
4. **Enable audit logging** - Required for compliance
5. **Regularly review logs** - Identify new attack patterns

## Next Steps

- **[Token Accounting](./token-accounting)** - Track usage
- **[Multi-Provider](./multi-provider)** - Provider routing
- **[Observability](/docs/guides/observability)** - Monitor security events
