---
sidebar_position: 7
title: Benchmarks
description: Performance benchmarks and comparisons for Loom API Gateway.
---

# Benchmarks

This page presents performance benchmarks for Loom compared to other API gateways.

:::note
Benchmarks are conducted on specific hardware and workloads. Your results may vary based on configuration, network conditions, and use case. Always benchmark with your actual workload.
:::

## Test Environment

### Hardware
- **CPU**: AMD EPYC 7763 (8 vCPUs)
- **Memory**: 16 GB RAM
- **Network**: 10 Gbps
- **OS**: Ubuntu 22.04 LTS
- **Kernel**: 5.15.0

### Software Versions
- Loom: 1.0.0
- Envoy: 1.28.0
- Kong: 3.5.0
- NGINX: 1.25.3

### Test Configuration
- Backend: Simple HTTP server returning 1KB JSON response
- Load generator: wrk2 with constant throughput
- Test duration: 60 seconds per test
- Connections: 100 concurrent

## Latency Benchmarks

### Simple Proxy (No Plugins)

Proxying requests to a backend without any middleware or plugins.

| Gateway | p50 (ms) | p99 (ms) | p99.9 (ms) | Max (ms) |
|---------|----------|----------|------------|----------|
| **Loom** | **0.42** | **1.12** | **2.34** | **8.21** |
| Envoy | 0.51 | 1.45 | 3.12 | 12.45 |
| Kong | 0.89 | 2.87 | 6.45 | 24.32 |
| NGINX | 0.38 | 1.08 | 2.21 | 7.89 |

### With Rate Limiting

Rate limiting enabled at 10,000 requests/second.

| Gateway | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---------|----------|----------|------------|
| **Loom** | **0.48** | **1.34** | **2.89** |
| Envoy | 0.62 | 1.78 | 4.21 |
| Kong | 1.12 | 3.45 | 8.12 |
| NGINX | N/A* | N/A* | N/A* |

*NGINX rate limiting requires NGINX Plus or additional modules.

### With Authentication (JWT)

JWT validation on every request.

| Gateway | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---------|----------|----------|------------|
| **Loom** | **0.56** | **1.52** | **3.21** |
| Envoy | 0.71 | 1.89 | 4.56 |
| Kong | 1.34 | 4.12 | 9.87 |
| NGINX | N/A* | N/A* | N/A* |

*NGINX JWT validation requires NGINX Plus.

### With WASM Plugin

Custom WASM plugin performing header manipulation.

| Gateway | p50 (ms) | p99 (ms) | p99.9 (ms) |
|---------|----------|----------|------------|
| **Loom** | **0.61** | **1.78** | **3.89** |
| Envoy | 0.89 | 2.34 | 5.67 |

Kong and NGINX don't support Proxy-Wasm plugins.

## Throughput Benchmarks

### Maximum Requests Per Second

Single instance, 100 concurrent connections.

| Gateway | RPS | CPU Usage | Memory |
|---------|-----|-----------|--------|
| **Loom** | **142,000** | 78% | 52 MB |
| Envoy | 128,000 | 82% | 98 MB |
| Kong | 45,000 | 85% | 245 MB |
| NGINX | 156,000 | 75% | 28 MB |

### Throughput Under Load

Measuring throughput while maintaining p99 under 10ms.

| Gateway | RPS @ p99 &lt; 10ms | CPU Usage |
|---------|----------------|-----------|
| **Loom** | **98,000** | 65% |
| Envoy | 85,000 | 72% |
| Kong | 32,000 | 78% |
| NGINX | 105,000 | 58% |

## Memory Efficiency

### Idle Memory Usage

Gateway running with minimal configuration, no traffic.

| Gateway | Memory |
|---------|--------|
| **Loom** | **18 MB** |
| Envoy | 42 MB |
| Kong | 128 MB |
| NGINX | 8 MB |

### Memory Under Load

At 50,000 RPS sustained traffic.

| Gateway | Memory | Per-Connection |
|---------|--------|----------------|
| **Loom** | **52 MB** | ~0.5 KB |
| Envoy | 98 MB | ~1.0 KB |
| Kong | 245 MB | ~2.5 KB |
| NGINX | 28 MB | ~0.3 KB |

## Startup Time

### Cold Start

Time from process start to accepting connections.

| Gateway | Startup Time |
|---------|--------------|
| **Loom** | **45 ms** |
| Envoy | 180 ms |
| Kong | 2,400 ms |
| NGINX | 25 ms |

### Configuration Reload

Time to apply configuration changes.

| Gateway | Reload Time | Connections Dropped |
|---------|-------------|---------------------|
| **Loom** | **12 ms** | 0 |
| Envoy | 25 ms | 0 |
| Kong | 800 ms | 0 |
| NGINX | 50 ms | Some* |

*NGINX reload can drop connections during worker process replacement.

## WASM Plugin Performance

### Plugin Execution Overhead

Comparing WASM plugin execution between Loom and Envoy.

| Operation | Loom (wazero) | Envoy (V8) |
|-----------|---------------|------------|
| Simple header read | 0.8 μs | 1.2 μs |
| Header manipulation | 1.2 μs | 1.8 μs |
| Body inspection (1KB) | 2.4 μs | 3.6 μs |
| JSON parsing (1KB) | 8.5 μs | 12.3 μs |

### Plugin Memory Overhead

Per-plugin memory usage.

| Metric | Loom | Envoy |
|--------|------|-------|
| Base overhead | 2 MB | 8 MB |
| Per-instance | 256 KB | 512 KB |

## Protocol Comparison

### HTTP/1.1 vs HTTP/2 vs HTTP/3

Loom performance across protocols (same workload).

| Protocol | p50 (ms) | p99 (ms) | RPS |
|----------|----------|----------|-----|
| HTTP/1.1 | 0.42 | 1.12 | 142,000 |
| HTTP/2 | 0.38 | 0.98 | 158,000 |
| **HTTP/3** | **0.35** | **0.89** | **168,000** |

HTTP/3 benefits from reduced connection overhead and no head-of-line blocking.

## Feature Comparison Impact

### Cumulative Feature Overhead

Adding features one at a time, measuring p99 latency increase.

| Configuration | p99 (ms) | Overhead |
|---------------|----------|----------|
| Baseline (proxy only) | 1.12 | - |
| + Rate limiting | 1.34 | +0.22 |
| + JWT auth | 1.52 | +0.18 |
| + WASM plugin | 1.78 | +0.26 |
| + Tracing | 1.95 | +0.17 |
| + Caching | 2.08 | +0.13 |
| **Total** | **2.08** | **+0.96** |

## Methodology

### Test Scripts

Latency test:
```bash
wrk2 -t4 -c100 -d60s -R50000 --latency http://gateway:8080/api/test
```

Throughput test:
```bash
wrk -t8 -c100 -d60s http://gateway:8080/api/test
```

### Configuration

All gateways configured with equivalent settings:
- Connection pooling: 100 connections per upstream
- Timeouts: 30 second request timeout
- Health checks: Disabled for benchmark consistency
- Logging: Disabled for benchmark consistency

### Reproduction

Benchmark scripts and configurations available at:
[github.com/josedab/loom/tree/main/benchmarks](https://github.com/josedab/loom/tree/main/benchmarks)

## Optimization Tips

### Maximize Throughput

```yaml
# Increase connection pool
upstreams:
  - name: backend
    connection:
      max_idle: 200
      max_per_host: 200

# Enable HTTP/2 upstream
    http2: true
```

### Minimize Latency

```yaml
# Reduce plugin count
routes:
  - id: api
    plugins: []  # Only essential plugins

# Use memory cache
cache:
  store:
    type: memory
```

### Enable eBPF (Linux)

```yaml
ebpf:
  enabled: true
  socket_redirect: true
```

eBPF acceleration can improve throughput by 15-25% on supported kernels.

## Running Your Own Benchmarks

```bash
# Clone the repository
git clone https://github.com/josedab/loom.git
cd loom/benchmarks

# Start the test environment
docker-compose up -d

# Run benchmarks
./run-benchmarks.sh

# View results
cat results/summary.md
```

## Conclusion

Loom offers competitive performance with significantly simpler operations:

- **Latency**: Comparable to NGINX and Envoy
- **Throughput**: Higher than Kong, competitive with others
- **Memory**: Lower than Envoy and Kong
- **Startup**: Faster than Envoy and Kong
- **WASM**: Lower overhead than Envoy's V8 runtime

The combination of Go's efficient runtime and wazero's AOT compilation delivers excellent performance without external dependencies.
