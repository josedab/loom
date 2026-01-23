---
sidebar_position: 4
title: Your First Plugin
description: Write your first WASM plugin for Loom using Rust or Go.
---

# Your First WASM Plugin

Loom's plugin system uses the [Proxy-Wasm](https://github.com/proxy-wasm/spec) ABI, which means plugins you write work across Loom, Envoy, and APISIX. This guide walks you through creating your first plugin.

## Prerequisites

Choose your language:

- **Rust**: Install [rustup](https://rustup.rs/) and add the WASM target
- **Go**: Install [TinyGo](https://tinygo.org/getting-started/install/)

## Plugin Phases

Plugins execute in specific phases during request processing:

| Phase | When it runs | Use case |
|-------|--------------|----------|
| `on_request_headers` | After receiving request headers | Authentication, rate limiting |
| `on_request_body` | After receiving request body | Request validation, transformation |
| `on_response_headers` | After receiving response headers | Header modification |
| `on_response_body` | After receiving response body | Response transformation |
| `on_log` | After request completes | Logging, metrics |

## Rust Plugin

Let's create a simple plugin that adds a custom header to every request.

### Setup

```bash
# Create a new Rust project
cargo new --lib add-header-plugin
cd add-header-plugin

# Add the WASM target
rustup target add wasm32-wasip1
```

### Dependencies

Update `Cargo.toml`:

```toml title="Cargo.toml"
[package]
name = "add-header-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
proxy-wasm = "0.2"
log = "0.4"

[profile.release]
lto = true
opt-level = "z"
```

### Implementation

Create `src/lib.rs`:

```rust title="src/lib.rs"
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(AddHeaderRoot)
    });
}}

struct AddHeaderRoot;

impl Context for AddHeaderRoot {}

impl RootContext for AddHeaderRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(AddHeaderPlugin))
    }
}

struct AddHeaderPlugin;

impl Context for AddHeaderPlugin {}

impl HttpContext for AddHeaderPlugin {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Add a custom header to the request
        self.add_http_request_header("X-Processed-By", "Loom");

        // Log the action
        log::info!("Added X-Processed-By header");

        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // Add a header to the response
        self.add_http_response_header("X-Gateway", "Loom");

        Action::Continue
    }
}
```

### Build

```bash
cargo build --target wasm32-wasip1 --release
```

The compiled plugin is at `target/wasm32-wasip1/release/add_header_plugin.wasm`.

## TinyGo Plugin

Here's the same plugin in Go using TinyGo.

### Setup

```bash
mkdir add-header-plugin
cd add-header-plugin
go mod init add-header-plugin
```

### Dependencies

```bash
go get github.com/tetratelabs/proxy-wasm-go-sdk
```

### Implementation

Create `main.go`:

```go title="main.go"
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
	// Add a custom header to the request
	if err := proxywasm.AddHttpRequestHeader("X-Processed-By", "Loom"); err != nil {
		proxywasm.LogErrorf("failed to add header: %v", err)
	}

	proxywasm.LogInfo("Added X-Processed-By header")
	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	// Add a header to the response
	if err := proxywasm.AddHttpResponseHeader("X-Gateway", "Loom"); err != nil {
		proxywasm.LogErrorf("failed to add header: %v", err)
	}

	return types.ActionContinue
}
```

### Build

```bash
tinygo build -o add-header-plugin.wasm -scheduler=none -target=wasi main.go
```

## Configure Loom

Add your plugin to Loom's configuration:

```yaml title="loom.yaml"
plugins:
  - name: add-header
    path: /path/to/add-header-plugin.wasm
    phase: on_request_headers
    priority: 100
    memory_limit: 16MB
    timeout: 50ms

routes:
  - id: api
    path: /api/*
    upstream: backend
    plugins:
      - add-header  # Reference the plugin by name
```

## Test Your Plugin

```bash
# Start Loom
loom -config loom.yaml

# Make a request
curl -v http://localhost:8080/api/test
```

You should see the `X-Gateway: Loom` header in the response.

## More Examples

### Rate Limiting Plugin (Rust)

```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct RateLimitPlugin {
    requests: u32,
    limit: u32,
    window_start: u64,
    window_size: u64,
}

impl HttpContext for RateLimitPlugin {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Reset window if expired
        if now - self.window_start >= self.window_size {
            self.requests = 0;
            self.window_start = now;
        }

        self.requests += 1;

        if self.requests > self.limit {
            self.send_http_response(
                429,
                vec![("Content-Type", "application/json")],
                Some(b"{\"error\": \"rate limit exceeded\"}"),
            );
            return Action::Pause;
        }

        Action::Continue
    }
}
```

### Request Validation Plugin (Go)

```go
func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
    if !endOfStream {
        return types.ActionPause
    }

    body, err := proxywasm.GetHttpRequestBody(0, bodySize)
    if err != nil {
        proxywasm.LogErrorf("failed to get body: %v", err)
        return types.ActionContinue
    }

    // Validate JSON
    if !json.Valid(body) {
        proxywasm.SendHttpResponse(400, nil, []byte(`{"error": "invalid JSON"}`), -1)
        return types.ActionPause
    }

    return types.ActionContinue
}
```

## Plugin Configuration

Plugins can receive configuration from Loom:

```yaml
plugins:
  - name: rate-limit
    path: /path/to/rate-limit.wasm
    config:
      requests_per_second: 100
      burst: 200
```

Access configuration in your plugin:

```rust
impl RootContext for RateLimitRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            // Parse configuration (JSON, YAML, etc.)
            let config: Config = serde_json::from_slice(&config_bytes).unwrap();
            self.limit = config.requests_per_second;
        }
        true
    }
}
```

## Debugging Plugins

### Enable Debug Logging

```yaml
plugins:
  - name: my-plugin
    path: /path/to/plugin.wasm
    log_level: debug
```

### View Plugin Logs

Plugin logs appear in Loom's output:

```bash
loom -config loom.yaml -log-level debug
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Plugin not loading | Check the `.wasm` file path and permissions |
| Memory errors | Increase `memory_limit` in config |
| Timeout errors | Increase `timeout` or optimize plugin code |
| Missing headers | Verify the plugin phase matches when headers are available |

## Next Steps

- **[Plugin API Reference](/docs/core-concepts/plugins)** - Full Proxy-Wasm API documentation
- **[Example Plugins](https://github.com/josedab/loom/tree/main/examples/plugins)** - More plugin examples
- **[Core Concepts](/docs/core-concepts/architecture)** - Understand Loom's architecture
