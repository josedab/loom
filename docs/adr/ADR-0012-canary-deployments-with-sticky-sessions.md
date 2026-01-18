# ADR-0012: Canary Deployments with Sticky Sessions

## Status

Accepted

## Context

Deploying new versions of services is risky. Even with thorough testing, production traffic can reveal issues that weren't caught in staging. Canary deployments reduce this risk by gradually shifting traffic to new versions while monitoring for problems.

Loom needed traffic management capabilities that would:

1. **Split traffic by percentage** - Route X% of requests to new version
2. **Support gradual rollout** - Increase percentage over time
3. **Maintain session consistency** - Same user should see same version
4. **Allow targeted testing** - Route specific users/headers to canary
5. **Enable quick rollback** - Instantly shift traffic back to stable
6. **Provide observability** - Track metrics per deployment target

## Decision

We implemented a **canary deployment system** with weighted routing and cookie-based sticky sessions.

```go
// internal/canary/canary.go
type Manager struct {
    deployments map[string]*Deployment  // routeID -> deployment
    mu          sync.RWMutex
}

type Deployment struct {
    ID           string
    RouteID      string
    Targets      []Target
    Sticky       bool
    StickyCookie string        // default: "canary-session"
    CookieTTL    time.Duration // default: 1 hour
    HeaderMatch  *HeaderMatch  // Optional header-based routing
    metrics      *DeploymentMetrics
}

type Target struct {
    Name     string  // "stable", "canary", "v2"
    Upstream string  // Upstream name to route to
    Weight   int     // 0-100, all weights should sum to 100
}

type HeaderMatch struct {
    Header string            // Header to inspect
    Values map[string]string // Header value -> target name
}

func (m *Manager) SelectTarget(routeID string, r *http.Request) (*Target, string) {
    m.mu.RLock()
    deployment, ok := m.deployments[routeID]
    m.mu.RUnlock()

    if !ok {
        return nil, ""
    }

    // 1. Check header-based override
    if deployment.HeaderMatch != nil {
        headerValue := r.Header.Get(deployment.HeaderMatch.Header)
        if targetName, ok := deployment.HeaderMatch.Values[headerValue]; ok {
            return deployment.findTarget(targetName), ""
        }
    }

    // 2. Check sticky session cookie
    if deployment.Sticky {
        if cookie, err := r.Cookie(deployment.StickyCookie); err == nil {
            if target := deployment.findTarget(cookie.Value); target != nil {
                deployment.metrics.stickyHits.Add(1)
                return target, ""  // No new cookie needed
            }
        }
    }

    // 3. Weighted random selection
    target := deployment.selectByWeight()

    // 4. Generate sticky cookie if enabled
    var setCookie string
    if deployment.Sticky {
        cookie := &http.Cookie{
            Name:     deployment.StickyCookie,
            Value:    target.Name,
            Path:     "/",
            MaxAge:   int(deployment.CookieTTL.Seconds()),
            HttpOnly: true,
            SameSite: http.SameSiteLaxMode,
        }
        setCookie = cookie.String()
    }

    deployment.metrics.selections[target.Name].Add(1)
    return target, setCookie
}

func (d *Deployment) selectByWeight() *Target {
    total := 0
    for _, t := range d.Targets {
        total += t.Weight
    }

    r := rand.Intn(total)
    cumulative := 0

    for i := range d.Targets {
        cumulative += d.Targets[i].Weight
        if r < cumulative {
            return &d.Targets[i]
        }
    }

    return &d.Targets[len(d.Targets)-1]
}
```

Middleware integration:

```go
// internal/canary/middleware.go
func Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            routeID := cfg.RouteIDFunc(r)

            target, setCookie := cfg.Manager.SelectTarget(routeID, r)
            if target != nil {
                // Override upstream for this request
                r = r.WithContext(context.WithValue(
                    r.Context(),
                    upstreamOverrideKey,
                    target.Upstream,
                ))

                if setCookie != "" {
                    w.Header().Add("Set-Cookie", setCookie)
                }
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

## Consequences

### Positive

- **Gradual rollout** - Start with 1% traffic to canary, increase as confidence grows. Minimize blast radius of issues.

- **Session consistency** - Sticky sessions ensure users don't flip between versions mid-session, preventing confusing UX and state issues.

- **Targeted testing** - Header-based routing allows QA team or specific users to test canary without affecting others:
  ```
  curl -H "X-Canary: true" https://api.example.com/
  ```

- **Quick rollback** - Set canary weight to 0 for instant rollback. No deployment needed.

- **Observable** - Per-target metrics show success rate, latency, and error rate. Compare canary vs stable in real-time.

- **Configuration-driven** - Deployments managed via YAML or Admin API:
  ```yaml
  canary:
    deployments:
      - route_id: api
        targets:
          - name: stable
            upstream: api-v1
            weight: 95
          - name: canary
            upstream: api-v2
            weight: 5
        sticky: true
        sticky_cookie: api-session
        header_match:
          header: X-Canary
          values:
            "true": canary
  ```

### Negative

- **Cookie overhead** - Sticky sessions require cookies. API clients may not handle cookies well.

- **Uneven load per endpoint** - If canary upstream has fewer endpoints than stable, each canary endpoint sees disproportionate load.

- **Not true isolation** - Canary and stable may share databases, caches, etc. Issues can still propagate.

- **Weight precision** - Integer weights (0-100) limit precision. Cannot do 0.1% canary.

- **No automatic rollback** - Must manually adjust weights or integrate with external monitoring.

### Auto-Rollout Support

For automated gradual rollouts:

```go
// internal/canary/rollout.go
type AutoRollout struct {
    manager    *Manager
    routeID    string
    canary     string
    stable     string
    stages     []int  // Weight progression
    stageIndex int
}

var DefaultStages = []int{1, 5, 25, 50, 100}

func (r *AutoRollout) Advance() error {
    if r.stageIndex >= len(r.stages) {
        return ErrRolloutComplete
    }

    newWeight := r.stages[r.stageIndex]
    stableWeight := 100 - newWeight

    err := r.manager.UpdateWeights(r.routeID, map[string]int{
        r.canary: newWeight,
        r.stable: stableWeight,
    })
    if err != nil {
        return err
    }

    r.stageIndex++
    return nil
}

func (r *AutoRollout) Rollback() error {
    return r.manager.UpdateWeights(r.routeID, map[string]int{
        r.canary: 0,
        r.stable: 100,
    })
}

func (r *AutoRollout) Complete() error {
    // Promote canary to 100%, effectively becoming new stable
    return r.manager.UpdateWeights(r.routeID, map[string]int{
        r.canary: 100,
        r.stable: 0,
    })
}
```

Usage:

```go
rollout := canary.NewAutoRollout(manager, "api", "canary", "stable")

// Gradual progression: 1% -> 5% -> 25% -> 50% -> 100%
for {
    err := rollout.Advance()
    if err == canary.ErrRolloutComplete {
        break
    }

    // Monitor for 10 minutes at each stage
    time.Sleep(10 * time.Minute)

    // Check metrics
    if errorRateTooHigh() {
        rollout.Rollback()
        break
    }
}
```

### Metrics

```go
var (
    canarySelectionsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "loom_canary_selections_total",
            Help: "Total canary target selections",
        },
        []string{"route_id", "target"},
    )
    canaryStickyHitsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "loom_canary_sticky_hits_total",
            Help: "Requests routed via sticky session cookie",
        },
        []string{"route_id"},
    )
    canaryTargetWeight = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "loom_canary_target_weight",
            Help: "Current weight for canary targets",
        },
        []string{"route_id", "target"},
    )
)
```

Grafana dashboard query examples:

```promql
# Traffic split percentage
loom_canary_selections_total{route_id="api"} / ignoring(target) group_left
sum(loom_canary_selections_total{route_id="api"})

# Error rate comparison
sum(rate(loom_upstream_errors_total{upstream="api-v2"}[5m])) /
sum(rate(loom_upstream_requests_total{upstream="api-v2"}[5m]))
```

### Configuration Examples

```yaml
# Simple 90/10 split
canary:
  deployments:
    - route_id: api
      targets:
        - name: stable
          upstream: api-v1
          weight: 90
        - name: canary
          upstream: api-v2
          weight: 10

# Header-based testing (internal testers only)
canary:
  deployments:
    - route_id: api
      targets:
        - name: stable
          upstream: api-v1
          weight: 100
        - name: canary
          upstream: api-v2
          weight: 0
      header_match:
        header: X-Employee-ID
        values:
          "12345": canary
          "67890": canary

# Multi-version (A/B/C testing)
canary:
  deployments:
    - route_id: checkout
      targets:
        - name: control
          upstream: checkout-v1
          weight: 34
        - name: variant-a
          upstream: checkout-v2a
          weight: 33
        - name: variant-b
          upstream: checkout-v2b
          weight: 33
      sticky: true
```

## Alternatives Considered

1. **DNS-based traffic splitting** - Rejected; too coarse-grained, no sticky sessions

2. **Load balancer weighted backends** - External LB can do this, but Loom should work standalone

3. **Service mesh traffic management (Istio)** - Valid for mesh environments; Loom targets standalone deployments

4. **Feature flags instead of canary** - Complementary but different; canary is infrastructure-level, flags are application-level

5. **Blue-green deployment** - All-or-nothing switch. Canary's gradual approach reduces risk further.

## References

- [Canary Deployments (Martin Fowler)](https://martinfowler.com/bliki/CanaryRelease.html)
- [Progressive Delivery](https://www.split.io/glossary/progressive-delivery/)
- [Istio Traffic Management](https://istio.io/latest/docs/concepts/traffic-management/)
- [Argo Rollouts](https://argoproj.github.io/argo-rollouts/)
