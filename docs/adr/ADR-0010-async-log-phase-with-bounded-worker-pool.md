# ADR-0010: Async Log Phase with Bounded Worker Pool

## Status

Accepted

## Context

Loom's Proxy-Wasm plugin system supports an `on_log` phase that executes after the response has been sent to the client. This phase is used for:

- Access logging to external systems
- Metrics emission
- Audit trail recording
- Analytics event publishing

The challenge: logging operations may involve I/O (network calls, disk writes) that could block the request goroutine. If `on_log` executes synchronously:

1. **Latency impact** - Client sees delay even though response is "done"
2. **Resource waste** - Request goroutine blocked on logging I/O
3. **Backpressure** - Slow logging backends affect request throughput

However, async execution introduces its own problems:

1. **Unbounded goroutines** - Spawning a goroutine per request risks memory exhaustion
2. **Lost logs** - Graceful shutdown must wait for pending logs
3. **Ordering** - Logs may arrive out of order

## Decision

We implemented the `on_log` phase as **async execution via a bounded worker pool** with a fixed number of workers and a bounded queue.

```go
// internal/plugin/pipeline.go
type Pipeline struct {
    runtime     *Runtime
    chains      map[string][]*PluginInstance
    logWorkers  *WorkerPool
    mu          sync.RWMutex
}

type WorkerPool struct {
    queue    chan *LogTask
    workers  int
    wg       sync.WaitGroup
    shutdown atomic.Bool
}

type LogTask struct {
    routeID string
    ctx     *RequestContext
    plugins []*PluginInstance
}

func NewWorkerPool(workers, queueSize int) *WorkerPool {
    wp := &WorkerPool{
        queue:   make(chan *LogTask, queueSize),
        workers: workers,
    }

    // Start workers
    for i := 0; i < workers; i++ {
        wp.wg.Add(1)
        go wp.worker()
    }

    return wp
}

func (wp *WorkerPool) worker() {
    defer wp.wg.Done()

    for task := range wp.queue {
        wp.executeLogPhase(task)
    }
}

func (wp *WorkerPool) Submit(task *LogTask) bool {
    if wp.shutdown.Load() {
        return false
    }

    select {
    case wp.queue <- task:
        return true
    default:
        // Queue full, drop task (with metric)
        logDroppedTasks.Inc()
        return false
    }
}

func (wp *WorkerPool) Shutdown(ctx context.Context) error {
    wp.shutdown.Store(true)
    close(wp.queue)

    done := make(chan struct{})
    go func() {
        wp.wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}
```

Integration with pipeline:

```go
func (p *Pipeline) ExecuteRequestPhase(ctx context.Context, routeID string, phase Phase, reqCtx *RequestContext) (Action, error) {
    if phase == PhaseOnLog {
        // Async execution for log phase
        task := &LogTask{
            routeID: routeID,
            ctx:     reqCtx.Clone(),  // Clone to avoid races
            plugins: p.getChain(routeID),
        }
        p.logWorkers.Submit(task)
        return ActionContinue, nil
    }

    // Sync execution for other phases
    return p.executeSyncPhase(ctx, routeID, phase, reqCtx)
}
```

## Consequences

### Positive

- **Request latency unaffected** - Response returns to client immediately. Logging happens in background without blocking the request goroutine.

- **Bounded resource usage** - Fixed worker count (default: 10) and queue size (default: 1000) prevent unbounded growth. Under extreme load, oldest tasks are dropped rather than exhausting memory.

- **Graceful degradation** - When queue is full, tasks are dropped with a metric increment. System remains responsive; logging is sacrificed to preserve core functionality.

- **Clean shutdown** - `Shutdown()` closes the queue and waits for workers to drain. Pending logs are processed before exit (up to timeout).

- **Backpressure isolation** - Slow logging backends don't affect request processing. Workers may back up, but request handlers continue independently.

### Negative

- **Log loss under load** - When queue fills, logs are dropped. This is intentional (fail-open) but means logging is best-effort, not guaranteed.

- **Out-of-order logs** - Multiple workers process concurrently. Logs may arrive at backends out of request order. Consumers must handle this (timestamps, sequence IDs).

- **Delayed visibility** - Logs appear after response completes. Real-time monitoring may see slight delay.

- **Context cloning overhead** - Request context must be cloned to avoid races between request completion and async log execution.

### Configuration

```go
// Default configuration
const (
    DefaultLogWorkers   = 10    // Concurrent log processors
    DefaultLogQueueSize = 1000  // Pending log buffer
)

// Can be configured via environment or code
logWorkers := NewWorkerPool(
    getEnvInt("LOOM_LOG_WORKERS", DefaultLogWorkers),
    getEnvInt("LOOM_LOG_QUEUE_SIZE", DefaultLogQueueSize),
)
```

### Sizing Guidelines

| Scenario | Workers | Queue Size | Rationale |
|----------|---------|------------|-----------|
| Low latency logging | 20 | 500 | More workers, smaller queue |
| High throughput | 10 | 5000 | Larger buffer for bursts |
| Resource constrained | 5 | 1000 | Fewer resources for logging |
| Guaranteed delivery | 10 | 10000 | Large queue, retry on drop |

### Metrics and Observability

```go
var (
    logTasksSubmitted = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "loom_log_tasks_submitted_total",
        Help: "Total log tasks submitted to worker pool",
    })
    logTasksDropped = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "loom_log_tasks_dropped_total",
        Help: "Log tasks dropped due to full queue",
    })
    logTasksProcessed = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "loom_log_tasks_processed_total",
        Help: "Log tasks successfully processed",
    })
    logQueueLength = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "loom_log_queue_length",
        Help: "Current number of pending log tasks",
    })
    logProcessingDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "loom_log_processing_duration_seconds",
        Help:    "Time to process log tasks",
        Buckets: prometheus.DefBuckets,
    })
)
```

Alert on dropped logs:

```yaml
- alert: LogTasksDropped
  expr: rate(loom_log_tasks_dropped_total[5m]) > 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Log tasks being dropped due to queue overflow"
```

### Context Cloning

To safely pass request context to async workers:

```go
func (ctx *RequestContext) Clone() *RequestContext {
    clone := &RequestContext{
        RequestHeaders:  make(map[string]string, len(ctx.RequestHeaders)),
        ResponseHeaders: make(map[string]string, len(ctx.ResponseHeaders)),
        Properties:      make(map[string][]byte, len(ctx.Properties)),
    }

    // Deep copy maps
    for k, v := range ctx.RequestHeaders {
        clone.RequestHeaders[k] = v
    }
    for k, v := range ctx.ResponseHeaders {
        clone.ResponseHeaders[k] = v
    }
    for k, v := range ctx.Properties {
        clone.Properties[k] = append([]byte(nil), v...)
    }

    // Copy body slices
    if ctx.RequestBody != nil {
        clone.RequestBody = append([]byte(nil), ctx.RequestBody...)
    }
    if ctx.ResponseBody != nil {
        clone.ResponseBody = append([]byte(nil), ctx.ResponseBody...)
    }

    return clone
}
```

### Graceful Shutdown Sequence

```go
func (s *Server) Shutdown(ctx context.Context) error {
    // 1. Stop accepting new requests
    s.listener.Shutdown(ctx)

    // 2. Wait for in-flight requests
    s.requestWg.Wait()

    // 3. Drain log queue (with timeout)
    logCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    s.pipeline.LogWorkers().Shutdown(logCtx)

    // 4. Close other resources
    s.upstreams.Close()
    s.metrics.Close()

    return nil
}
```

## Alternatives Considered

1. **Sync logging** - Rejected; logging I/O would directly impact request latency

2. **Goroutine per request** - Rejected; unbounded goroutine creation risks OOM under load

3. **Channel without workers** - Rejected; still needs bounded consumers to process

4. **External log queue (Kafka, etc.)** - Valid for high-reliability logging; adds operational complexity. Worker pool is simpler for most deployments.

5. **Ring buffer with overwrite** - Considered; chosen bounded queue with drop instead for simpler semantics

## References

- [Worker Pool Pattern in Go](https://gobyexample.com/worker-pools)
- [Bounded Queues for Backpressure](https://mechanical-sympathy.blogspot.com/2012/05/apply-back-pressure-when-overloaded.html)
- [Proxy-Wasm Logging Phase](https://github.com/proxy-wasm/spec/blob/master/abi-versions/vNEXT/README.md#on_log)
