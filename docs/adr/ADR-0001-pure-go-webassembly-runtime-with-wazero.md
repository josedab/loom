# ADR-0001: Pure Go WebAssembly Runtime with Wazero

## Status

Accepted

## Context

Loom is designed as a WASM-first API gateway, requiring a WebAssembly runtime to execute Proxy-Wasm plugins. The plugin system is central to Loom's extensibility, allowing users to add custom authentication, transformation, and observability logic without modifying core gateway code.

Several WebAssembly runtimes were considered:

1. **Wasmer** - High-performance runtime with CGO bindings to native code
2. **Wasmtime** - Mozilla's production runtime, also requires CGO
3. **wazero** - Pure Go implementation with zero dependencies
4. **V8/wasm** - JavaScript engine with WASM support, heavy dependency

Key requirements for the runtime selection:

- **Proxy-Wasm ABI compatibility** - Must support the Proxy-Wasm specification used by Envoy and other service meshes
- **Deployment simplicity** - Gateway should be a single static binary without native library dependencies
- **Cross-platform builds** - Must support Linux, macOS, and Windows from a single build pipeline
- **Memory safety** - Runtime must provide strong isolation between plugins and the host
- **Performance** - Must handle high request throughput with acceptable latency overhead

## Decision

We chose **wazero** (github.com/tetratelabs/wazero) as Loom's WebAssembly runtime.

Key implementation details:

```go
// internal/plugin/runtime.go
type Runtime struct {
    runtime wazero.Runtime
    modules map[string]*CompiledPlugin
    mu      sync.RWMutex
}

type CompiledPlugin struct {
    Name         string
    Module       wazero.CompiledModule  // Pre-compiled for reuse
    instancePool sync.Pool              // Recycle module instances
    version      uint64                 // Incremented on reload
}
```

The runtime pre-compiles WASM modules at load time and pools instances for reuse across requests, amortizing instantiation costs.

## Consequences

### Positive

- **Single binary deployment** - No CGO means `go build` produces a fully static binary with no external dependencies. This simplifies container images, CI/CD pipelines, and operational deployment.

- **Cross-compilation works** - Can build for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, and windows/amd64 from any platform without cross-compilation toolchains.

- **Memory safety guarantees** - wazero provides strong sandboxing. Plugins cannot access host memory outside of explicitly shared regions, preventing security vulnerabilities from malicious or buggy plugins.

- **Predictable performance** - Pure Go means no FFI overhead for crossing language boundaries. Performance characteristics are consistent and profiling works with standard Go tools.

- **Active maintenance** - wazero is maintained by Tetrate (creators of Envoy) and has strong community support for Proxy-Wasm use cases.

### Negative

- **Lower peak throughput** - Native runtimes like Wasmer can achieve higher peak performance through JIT compilation. wazero uses an interpreter and AOT compilation that may be 2-5x slower for CPU-intensive plugins.

- **WASM 2.0 feature lag** - As a newer runtime, wazero may lag behind native runtimes in supporting bleeding-edge WASM proposals (though core Proxy-Wasm features are fully supported).

- **Memory overhead** - Pure Go implementation may use more memory per instance compared to native runtimes with optimized allocators.

### Tradeoffs Accepted

We explicitly traded peak plugin performance for deployment simplicity. For Loom's use case (HTTP request/response processing), the plugin overhead is typically small compared to network I/O, making this an acceptable tradeoff. Users with CPU-intensive plugin workloads may need to optimize their plugin code or consider native language implementations.

## References

- [wazero GitHub](https://github.com/tetratelabs/wazero)
- [Proxy-Wasm ABI Specification](https://github.com/proxy-wasm/spec)
- [wazero Performance Benchmarks](https://wazero.io/docs/how_the_optimizing_compiler_works/)
