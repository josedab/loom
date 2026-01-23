# Loom Plugin Development Guide

This guide covers developing WebAssembly plugins for Loom using the Proxy-Wasm ABI.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Plugin Lifecycle](#plugin-lifecycle)
- [Proxy-Wasm ABI](#proxy-wasm-abi)
- [Rust Plugin Development](#rust-plugin-development)
- [Go/TinyGo Plugin Development](#gotinygo-plugin-development)
- [Configuration](#configuration)
- [Best Practices](#best-practices)
- [Debugging](#debugging)

## Overview

Loom plugins are WebAssembly modules that implement the Proxy-Wasm ABI. This allows plugins to:

- Inspect and modify request/response headers
- Read and transform request/response bodies
- Short-circuit requests with custom responses
- Log and emit metrics
- Make async HTTP calls to external services

### Why WASM?

- **Portability**: Same plugin works across Loom, Envoy, APISIX
- **Isolation**: Memory safety with sandboxed execution
- **Performance**: Near-native speed with AOT compilation
- **Language Choice**: Write in Rust, Go, TypeScript, or any WASM target

## Getting Started

### Prerequisites

**For Rust:**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target
rustup target add wasm32-wasip1
```

**For Go/TinyGo:**
```bash
# Install TinyGo (required for WASM)
# macOS
brew install tinygo

# Linux
wget https://github.com/tinygo-org/tinygo/releases/download/v0.30.0/tinygo_0.30.0_amd64.deb
sudo dpkg -i tinygo_0.30.0_amd64.deb
```

### Minimal Plugin (Rust)

```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> {
        Box::new(MinimalPlugin)
    });
}}

struct MinimalPlugin;

impl Context for MinimalPlugin {}

impl HttpContext for MinimalPlugin {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Add custom header
        self.add_http_request_header("X-Plugin", "minimal");
        Action::Continue
    }
}
```

### Build and Deploy

```bash
# Build
cargo build --target wasm32-wasip1 --release

# Copy to plugins directory
cp target/wasm32-wasip1/release/minimal_plugin.wasm /plugins/

# Configure in loom.yaml
```

```yaml
plugins:
  - name: minimal
    path: /plugins/minimal_plugin.wasm
    phase: on_request_headers
    priority: 100
```

## Plugin Lifecycle

### Execution Phases

```
Request arrives
      │
      ▼
┌─────────────────────────┐
│  on_request_headers     │  ◄── Inspect/modify request headers
└───────────┬─────────────┘      Can short-circuit here
            │
            ▼
┌─────────────────────────┐
│  on_request_body        │  ◄── Inspect/modify request body
└───────────┬─────────────┘      Called per chunk if streaming
            │
            ▼
      [Upstream Call]
            │
            ▼
┌─────────────────────────┐
│  on_response_headers    │  ◄── Inspect/modify response headers
└───────────┬─────────────┘      Can short-circuit here
            │
            ▼
┌─────────────────────────┐
│  on_response_body       │  ◄── Inspect/modify response body
└───────────┬─────────────┘      Called per chunk if streaming
            │
            ▼
      [Response Sent]
            │
            ▼
┌─────────────────────────┐
│  on_log                 │  ◄── Async logging/metrics
└─────────────────────────┘      Background worker pool
```

### Execution Order

**Request phases** execute in **priority order** (high → low):
```
Plugin A (priority: 200) → Plugin B (priority: 100) → Plugin C (priority: 50)
```

**Response phases** execute in **reverse priority** (low → high):
```
Plugin C (priority: 50) → Plugin B (priority: 100) → Plugin A (priority: 200)
```

### Actions

| Action | Description |
|--------|-------------|
| `Continue` | Proceed to next plugin/phase |
| `Pause` | Stop processing, send immediate response |

## Proxy-Wasm ABI

### Header Operations

```rust
// Get single header
let value = self.get_http_request_header("Authorization");

// Get all headers
let headers = self.get_http_request_headers();

// Add header (appends if exists)
self.add_http_request_header("X-Custom", "value");

// Set header (replaces if exists)
self.set_http_request_header("X-Custom", Some("value"));

// Remove header
self.set_http_request_header("X-Remove-Me", None);

// Response headers (in response phase)
self.set_http_response_header("X-Response", Some("value"));
```

### Body Operations

```rust
impl HttpContext for MyPlugin {
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // Get body bytes
        if let Some(body) = self.get_http_request_body(0, body_size) {
            // Inspect body
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            // Modify body
            let modified = serde_json::to_vec(&json).unwrap();
            self.set_http_request_body(0, body_size, &modified);
        }

        // Wait for full body if streaming
        if !end_of_stream {
            return Action::Pause;
        }

        Action::Continue
    }
}
```

### Sending Immediate Responses

```rust
fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    // Check authentication
    if self.get_http_request_header("Authorization").is_none() {
        self.send_http_response(
            401,
            vec![("Content-Type", "application/json")],
            Some(b"{\"error\": \"Unauthorized\"}")
        );
        return Action::Pause;
    }
    Action::Continue
}
```

### Properties

Access contextual information:

```rust
// Get property
if let Some(value) = self.get_property(vec!["request", "path"]) {
    // Use path
}

// Set property (for downstream plugins)
self.set_property(vec!["custom", "key"], Some(b"value"));
```

### Logging

```rust
use log::{info, warn, error, debug, trace};

fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    info!("Processing request");
    debug!("Headers: {:?}", self.get_http_request_headers());

    if some_error {
        error!("Something went wrong");
    }

    Action::Continue
}
```

### Metrics

```rust
impl Context for MyPlugin {
    fn on_vm_start(&mut self, _: usize) -> bool {
        // Define metrics
        self.define_metric(MetricType::Counter, "my_plugin_requests_total");
        self.define_metric(MetricType::Gauge, "my_plugin_active_requests");
        self.define_metric(MetricType::Histogram, "my_plugin_latency");
        true
    }
}

impl HttpContext for MyPlugin {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Increment counter
        self.increment_metric(0, 1);  // metric_id=0

        // Set gauge
        self.record_metric(1, 42);    // metric_id=1

        Action::Continue
    }
}
```

### HTTP Calls

Make async requests to external services:

```rust
fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    // Async HTTP call
    self.dispatch_http_call(
        "auth_service",  // Upstream name
        vec![
            (":method", "POST"),
            (":path", "/validate"),
            (":authority", "auth.internal"),
            ("content-type", "application/json"),
        ],
        Some(b"{\"token\": \"...\"}"),
        vec![],
        Duration::from_secs(5),
    ).unwrap();

    Action::Pause  // Wait for response
}

fn on_http_call_response(&mut self, _token_id: u32, _: usize, body_size: usize, _: usize) {
    if let Some(body) = self.get_http_call_response_body(0, body_size) {
        // Process response
        if body == b"valid" {
            self.resume_http_request();
        } else {
            self.send_http_response(403, vec![], Some(b"Forbidden"));
        }
    }
}
```

## Rust Plugin Development

### Project Setup

```bash
cargo new --lib my-plugin
cd my-plugin
```

**Cargo.toml:**
```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
proxy-wasm = "0.2"
log = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "s"      # Optimize for size
lto = true           # Link-time optimization
```

### Complete Example: Rate Limiter

```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(RateLimitRoot {
            config: RateLimitConfig::default(),
        })
    });
}}

#[derive(Default)]
struct RateLimitConfig {
    requests_per_second: u32,
    burst: u32,
}

struct RateLimitRoot {
    config: RateLimitConfig,
}

impl Context for RateLimitRoot {}

impl RootContext for RateLimitRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        // Parse plugin configuration
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(config) = serde_json::from_slice::<serde_json::Value>(&config_bytes) {
                self.config.requests_per_second = config["requests_per_second"]
                    .as_u64()
                    .unwrap_or(100) as u32;
                self.config.burst = config["burst"]
                    .as_u64()
                    .unwrap_or(10) as u32;
            }
        }
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(RateLimitPlugin {
            requests_per_second: self.config.requests_per_second,
            burst: self.config.burst,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct RateLimitPlugin {
    requests_per_second: u32,
    burst: u32,
}

impl Context for RateLimitPlugin {}

impl HttpContext for RateLimitPlugin {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Get client identifier
        let client_ip = self.get_http_request_header("x-forwarded-for")
            .or_else(|| self.get_property(vec!["source", "address"])
                .map(|v| String::from_utf8_lossy(&v).to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        // Check rate limit (simplified - use shared state in production)
        let key = format!("ratelimit:{}", client_ip);

        if let Some(count) = self.get_shared_data(&key) {
            let current: u32 = u32::from_le_bytes(count.try_into().unwrap_or([0; 4]));

            if current >= self.burst {
                self.send_http_response(
                    429,
                    vec![
                        ("Content-Type", "application/json"),
                        ("Retry-After", "1"),
                    ],
                    Some(b"{\"error\": \"Rate limit exceeded\"}")
                );
                return Action::Pause;
            }

            // Increment counter
            self.set_shared_data(&key, Some(&(current + 1).to_le_bytes()), None);
        } else {
            // Initialize counter
            self.set_shared_data(&key, Some(&1u32.to_le_bytes()), None);
        }

        Action::Continue
    }
}
```

### Building

```bash
# Development build
cargo build --target wasm32-wasip1

# Release build (optimized)
cargo build --target wasm32-wasip1 --release

# Further optimization with wasm-opt (optional)
wasm-opt -Os target/wasm32-wasip1/release/my_plugin.wasm -o my_plugin.wasm
```

## Go/TinyGo Plugin Development

### Project Setup

```bash
mkdir my-plugin
cd my-plugin
go mod init my-plugin
```

**main.go:**
```go
package main

import (
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
    proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
    types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
    return &pluginContext{}
}

type pluginContext struct {
    types.DefaultPluginContext
}

func (*pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
    return &httpContext{}
}

type httpContext struct {
    types.DefaultHttpContext
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
    // Add custom header
    if err := proxywasm.AddHttpRequestHeader("X-Plugin", "go-example"); err != nil {
        proxywasm.LogErrorf("failed to add header: %v", err)
    }
    return types.ActionContinue
}
```

### Complete Example: JWT Validator

```go
package main

import (
    "encoding/base64"
    "encoding/json"
    "strings"

    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
    proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
    types.DefaultVMContext
}

type pluginContext struct {
    types.DefaultPluginContext
    secret string
}

type httpContext struct {
    types.DefaultHttpContext
    secret string
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
    return &pluginContext{}
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
    data, err := proxywasm.GetPluginConfiguration()
    if err != nil {
        proxywasm.LogErrorf("failed to get config: %v", err)
        return types.OnPluginStartStatusFailed
    }

    var config map[string]string
    if err := json.Unmarshal(data, &config); err != nil {
        proxywasm.LogErrorf("failed to parse config: %v", err)
        return types.OnPluginStartStatusFailed
    }

    ctx.secret = config["secret"]
    return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
    return &httpContext{secret: ctx.secret}
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
    auth, err := proxywasm.GetHttpRequestHeader("Authorization")
    if err != nil || !strings.HasPrefix(auth, "Bearer ") {
        ctx.sendUnauthorized("Missing or invalid Authorization header")
        return types.ActionPause
    }

    token := strings.TrimPrefix(auth, "Bearer ")

    // Parse JWT (simplified - use proper library in production)
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        ctx.sendUnauthorized("Invalid token format")
        return types.ActionPause
    }

    // Decode payload
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        ctx.sendUnauthorized("Invalid token encoding")
        return types.ActionPause
    }

    var claims map[string]interface{}
    if err := json.Unmarshal(payload, &claims); err != nil {
        ctx.sendUnauthorized("Invalid token payload")
        return types.ActionPause
    }

    // Add user info to headers for downstream
    if sub, ok := claims["sub"].(string); ok {
        proxywasm.AddHttpRequestHeader("X-User-ID", sub)
    }

    proxywasm.LogInfof("JWT validated for user: %v", claims["sub"])
    return types.ActionContinue
}

func (ctx *httpContext) sendUnauthorized(message string) {
    body := []byte(`{"error": "` + message + `"}`)
    proxywasm.SendHttpResponse(401, [][2]string{
        {"Content-Type", "application/json"},
        {"WWW-Authenticate", "Bearer"},
    }, body, -1)
}
```

### Building

```bash
tinygo build -o my-plugin.wasm -scheduler=none -target=wasi main.go
```

## Configuration

### Plugin Configuration in loom.yaml

```yaml
plugins:
  - name: my-plugin
    path: /plugins/my-plugin.wasm
    phase: on_request_headers
    priority: 100
    config:
      key1: value1
      key2: 123
      nested:
        key3: true
    memory_limit: 16MB
    timeout: 100ms
```

### Accessing Configuration in Plugins

**Rust:**
```rust
impl RootContext for MyRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            let config: serde_json::Value = serde_json::from_slice(&config_bytes).unwrap();
            self.key1 = config["key1"].as_str().unwrap().to_string();
            self.key2 = config["key2"].as_u64().unwrap() as u32;
        }
        true
    }
}
```

**Go:**
```go
func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
    data, _ := proxywasm.GetPluginConfiguration()
    var config map[string]interface{}
    json.Unmarshal(data, &config)
    ctx.key1 = config["key1"].(string)
    return types.OnPluginStartStatusOK
}
```

## Best Practices

### Performance

1. **Minimize allocations**: Reuse buffers where possible
2. **Avoid blocking**: Use async HTTP calls instead of synchronous
3. **Batch operations**: Combine multiple header operations
4. **Use appropriate phase**: Don't process body if only headers needed

### Security

1. **Validate inputs**: Never trust request data
2. **Sanitize outputs**: Escape data in responses
3. **Use constant-time comparison**: For secrets/tokens
4. **Limit resource usage**: Set memory limits and timeouts

### Error Handling

```rust
fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    match self.validate_request() {
        Ok(_) => Action::Continue,
        Err(e) => {
            log::error!("Validation failed: {}", e);
            self.send_http_response(400, vec![], Some(e.as_bytes()));
            Action::Pause
        }
    }
}
```

### Testing

**Unit Testing (Rust):**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parsing() {
        let result = parse_auth_header("Bearer token123");
        assert_eq!(result, Some("token123".to_string()));
    }
}
```

**Integration Testing:**
```bash
# Start Loom with test config
loom -config test-config.yaml &

# Run integration tests
curl -H "Authorization: Bearer test" http://localhost:8080/api/test
```

## Debugging

### Logging

```rust
use log::{trace, debug, info, warn, error};

fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    trace!("Entering on_http_request_headers");
    debug!("Headers: {:?}", self.get_http_request_headers());
    info!("Processing request");

    if let Err(e) = self.process() {
        error!("Processing failed: {}", e);
    }

    Action::Continue
}
```

### Admin API

Check plugin status:
```bash
# List loaded plugins
curl http://localhost:9091/plugins

# Get plugin details
curl http://localhost:9091/plugins/my-plugin

# Hot-reload plugin
curl -X POST http://localhost:9091/plugins/my-plugin/reload
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Plugin not loading | Invalid WASM | Check build target is wasm32-wasip1 |
| Timeout errors | Plugin too slow | Increase timeout or optimize code |
| Memory errors | Exceeding limit | Increase memory_limit or reduce usage |
| Headers not modified | Wrong phase | Use correct phase for operation |
| Body not available | Not buffered | Return Pause to buffer body |

### Debugging with wasm-tools

```bash
# Install wasm-tools
cargo install wasm-tools

# Inspect module
wasm-tools print my-plugin.wasm

# Validate module
wasm-tools validate my-plugin.wasm

# Check exports
wasm-tools objdump -x my-plugin.wasm
```

## Resources

- [Proxy-Wasm Spec](https://github.com/proxy-wasm/spec)
- [proxy-wasm-rust-sdk](https://github.com/proxy-wasm/proxy-wasm-rust-sdk)
- [proxy-wasm-go-sdk](https://github.com/tetratelabs/proxy-wasm-go-sdk)
- [wazero Runtime](https://wazero.io/)
