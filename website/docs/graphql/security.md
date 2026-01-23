---
sidebar_position: 4
title: GraphQL Security
description: Query limits, field authorization, and introspection control.
---

# GraphQL Security

Loom provides comprehensive security features for GraphQL APIs.

## Query Depth Limiting

Prevent deeply nested queries:

```yaml
graphql:
  security:
    max_depth: 10
```

### Per-Operation Limits

```yaml
graphql:
  security:
    depth:
      query: 10
      mutation: 5
      subscription: 5
```

## Query Complexity

Limit query complexity based on field costs:

```yaml
graphql:
  security:
    max_complexity: 1000

    complexity:
      default_field_cost: 1
      default_list_cost: 10

      # Custom field costs
      fields:
        Query.users: 50
        Query.expensiveReport: 500
        User.orders: 20
```

### List Multiplier

Multiply cost by list size:

```yaml
graphql:
  security:
    complexity:
      list_multiplier: true
      default_list_size: 10
```

Query `users(first: 100) { orders { id } }`:
- Base: 1 (users) + 10 (default list) × 100 (first arg) × 20 (orders cost) = 20,001

## Introspection Control

### Disable Introspection

```yaml
graphql:
  security:
    introspection: false
```

### Conditional Introspection

```yaml
graphql:
  security:
    introspection:
      enabled: true

      # Only in development
      environments: [development, staging]

      # Or with header
      allowed_headers:
        X-Introspection-Key: secret123
```

## Field Authorization

Role-based field access:

```yaml
graphql:
  security:
    authorization:
      enabled: true

      rules:
        # Admin-only fields
        - field: User.email
          roles: [admin]

        - field: User.ssn
          roles: [admin, compliance]

        # Pattern matching
        - field: "*.secretField"
          roles: [admin]

        # Mutation restrictions
        - field: Mutation.deleteUser
          roles: [admin]
```

### Authorization Sources

```yaml
graphql:
  security:
    authorization:
      # Extract role from JWT
      role_source: jwt:roles

      # Or from header
      # role_source: header:X-User-Roles
```

## Blocked Fields

Completely block certain fields:

```yaml
graphql:
  security:
    blocked_fields:
      - User.password
      - User.internalId
      - "*.debugInfo"
```

## Rate Limiting

### Per-Operation

```yaml
graphql:
  security:
    rate_limit:
      query:
        requests_per_minute: 100
      mutation:
        requests_per_minute: 20
      subscription:
        connections_per_user: 10
```

### Per-Field

```yaml
graphql:
  security:
    rate_limit:
      fields:
        Query.expensiveReport:
          requests_per_minute: 5
        Mutation.sendEmail:
          requests_per_minute: 10
```

## Operation Allowlist

Only allow specific operations:

```yaml
graphql:
  security:
    allowlist:
      enabled: true

      operations:
        - name: GetUser
          hash: abc123...

        - name: ListOrders
          hash: def456...
```

## Query Validation

```yaml
graphql:
  security:
    validation:
      # Require operation name
      require_operation_name: true

      # Require persisted queries in production
      require_persisted_queries: true

      # Maximum query size
      max_query_size: 10KB

      # Maximum aliases
      max_aliases: 10

      # Maximum root fields
      max_root_fields: 10
```

## Audit Logging

```yaml
graphql:
  security:
    audit:
      enabled: true

      log:
        - operation_name
        - query_hash
        - user_id
        - complexity
        - depth
        - duration

      # Log denied operations
      log_denied: true
```

## CSRF Protection

```yaml
graphql:
  security:
    csrf:
      enabled: true
      header: X-CSRF-Token
      cookie: csrf_token
```

## Monitoring

### Prometheus Metrics

```
# Blocked queries
loom_graphql_blocked_total{reason="depth"}
loom_graphql_blocked_total{reason="complexity"}
loom_graphql_blocked_total{reason="unauthorized"}

# Query stats
loom_graphql_depth{quantile="0.99"}
loom_graphql_complexity{quantile="0.99"}

# Authorization
loom_graphql_auth_denied_total{field="User.email"}
```

## Complete Example

```yaml
graphql:
  enabled: true

  security:
    # Query limits
    max_depth: 10
    max_complexity: 1000

    complexity:
      default_field_cost: 1
      default_list_cost: 10
      list_multiplier: true
      fields:
        Query.users: 50
        Query.expensiveReport: 500

    # Introspection
    introspection:
      enabled: true
      environments: [development]

    # Authorization
    authorization:
      enabled: true
      role_source: jwt:roles
      rules:
        - field: User.email
          roles: [admin, self]
        - field: Mutation.deleteUser
          roles: [admin]

    # Blocked fields
    blocked_fields:
      - User.password
      - "*.internalId"

    # Rate limiting
    rate_limit:
      query:
        requests_per_minute: 100
      mutation:
        requests_per_minute: 20
      fields:
        Query.expensiveReport:
          requests_per_minute: 5

    # Validation
    validation:
      require_operation_name: true
      max_query_size: 10KB
      max_aliases: 10

    # Audit
    audit:
      enabled: true
      log_denied: true
```

## Next Steps

- **[Persisted Queries](./persisted-queries)** - APQ setup
- **[Federation](./federation)** - Multi-service
- **[Overview](./overview)** - GraphQL features
