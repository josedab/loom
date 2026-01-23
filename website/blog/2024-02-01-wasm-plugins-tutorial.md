---
slug: wasm-plugins-tutorial
title: "Building Your First WASM Plugin for Loom"
authors: [loom]
tags: [tutorial]
---

# Building Your First WASM Plugin for Loom

Learn how to write, compile, and deploy a WebAssembly plugin for Loom using Rust and the Proxy-Wasm SDK.

<!-- truncate -->

## Why WASM Plugins?

WebAssembly plugins offer unique advantages:

- **Language flexibility**: Write in Rust, Go, TypeScript, or any language targeting WASM
- **Portability**: Same plugin works on Loom, Envoy, and APISIX
- **Security**: Sandboxed execution with controlled capabilities
- **Performance**: Near-native speed with AOT compilation

## Prerequisites

You'll need:
- Rust toolchain (`rustup`)
- WASM target: `rustup target add wasm32-wasi`
- Loom installed: `go install github.com/josedab/loom/cmd/loom@latest`

## Project Setup

Create a new Rust library project:

```bash
cargo new --lib loom-auth-plugin
cd loom-auth-plugin
```

Update `Cargo.toml`:

```toml
[package]
name = "loom-auth-plugin"
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
opt-level = "s"
lto = true
```

## Writing the Plugin

Let's build an API key authentication plugin. Create `src/lib.rs`:

```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::collections::HashSet;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(AuthRootContext::default())
    });
}}

// Configuration structure
#[derive(Deserialize, Default)]
struct AuthConfig {
    header_name: String,
    valid_keys: Vec<String>,
}

// Root context holds shared state
#[derive(Default)]
struct AuthRootContext {
    config: AuthConfig,
    valid_keys_set: HashSet<String>,
}

impl Context for AuthRootContext {}

impl RootContext for AuthRootContext {
    fn on_configure(&mut self, _: usize) -> bool {
        // Load configuration from Loom
        if let Some(config_bytes) = self.get_plugin_configuration() {
            match serde_json::from_slice::<AuthConfig>(&config_bytes) {
                Ok(config) => {
                    log::info!("Loaded auth config with {} keys", config.valid_keys.len());
                    self.valid_keys_set = config.valid_keys.iter().cloned().collect();
                    self.config = config;
                    return true;
                }
                Err(e) => {
                    log::error!("Failed to parse config: {}", e);
                    return false;
                }
            }
        }
        log::error!("No configuration provided");
        false
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(AuthHttpContext {
            header_name: self.config.header_name.clone(),
            valid_keys: self.valid_keys_set.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

// HTTP context handles individual requests
struct AuthHttpContext {
    header_name: String,
    valid_keys: HashSet<String>,
}

impl Context for AuthHttpContext {}

impl HttpContext for AuthHttpContext {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // Get the API key header
        let api_key = match self.get_http_request_header(&self.header_name) {
            Some(key) => key,
            None => {
                log::warn!("Missing API key header");
                self.send_http_response(
                    401,
                    vec![("Content-Type", "application/json")],
                    Some(br#"{"error": "Missing API key"}"#),
                );
                return Action::Pause;
            }
        };

        // Validate the key
        if !self.valid_keys.contains(&api_key) {
            log::warn!("Invalid API key: {}", api_key);
            self.send_http_response(
                403,
                vec![("Content-Type", "application/json")],
                Some(br#"{"error": "Invalid API key"}"#),
            );
            return Action::Pause;
        }

        log::info!("Request authenticated successfully");

        // Add header to indicate successful auth
        self.set_http_request_header("X-Auth-Status", Some("valid"));

        Action::Continue
    }

    fn on_log(&mut self) {
        log::info!("Request completed");
    }
}
```

## Building the Plugin

Compile to WebAssembly:

```bash
cargo build --target wasm32-wasi --release
```

The compiled plugin will be at `target/wasm32-wasi/release/loom_auth_plugin.wasm`.

## Deploying to Loom

Create a Loom configuration that uses the plugin:

```yaml
# loom.yaml
listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: protected-api
    path: /api/*
    upstream: backend
    plugins:
      - auth

  - id: public
    path: /public/*
    upstream: backend
    # No plugins - public access

upstreams:
  - name: backend
    endpoints:
      - "localhost:3000"

plugins:
  - name: auth
    path: ./target/wasm32-wasi/release/loom_auth_plugin.wasm
    phase: on_request_headers
    config:
      header_name: X-API-Key
      valid_keys:
        - "key-abc123"
        - "key-def456"
        - "key-ghi789"

admin:
  enabled: true
  address: ":9091"
```

Start Loom:

```bash
loom -config loom.yaml
```

## Testing the Plugin

```bash
# Without API key - should return 401
curl -v http://localhost:8080/api/users
# Response: 401 {"error": "Missing API key"}

# With invalid API key - should return 403
curl -v -H "X-API-Key: invalid" http://localhost:8080/api/users
# Response: 403 {"error": "Invalid API key"}

# With valid API key - should succeed
curl -v -H "X-API-Key: key-abc123" http://localhost:8080/api/users
# Response: 200 (proxied to backend)

# Public endpoint - no auth required
curl -v http://localhost:8080/public/info
# Response: 200 (proxied to backend)
```

## Adding More Features

### Rate Limiting Per Key

Extend the plugin to track usage per API key:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;

struct AuthHttpContext {
    header_name: String,
    valid_keys: HashSet<String>,
    rate_limits: Arc<Mutex<HashMap<String, AtomicU64>>>,
    max_requests_per_minute: u64,
}

impl HttpContext for AuthHttpContext {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        // ... authentication logic ...

        // Check rate limit
        let mut limits = self.rate_limits.lock().unwrap();
        let count = limits
            .entry(api_key.clone())
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= self.max_requests_per_minute {
            self.send_http_response(
                429,
                vec![
                    ("Content-Type", "application/json"),
                    ("Retry-After", "60"),
                ],
                Some(br#"{"error": "Rate limit exceeded"}"#),
            );
            return Action::Pause;
        }

        Action::Continue
    }
}
```

### Making HTTP Calls

Plugins can call external services:

```rust
impl HttpContext for AuthHttpContext {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let api_key = self.get_http_request_header("X-API-Key")?;

        // Call auth service to validate
        self.dispatch_http_call(
            "auth-service",
            vec![
                (":method", "POST"),
                (":path", "/validate"),
                ("Content-Type", "application/json"),
            ],
            Some(format!(r#"{{"key": "{}"}}"#, api_key).as_bytes()),
            vec![],
            Duration::from_secs(5),
        ).ok();

        Action::Pause // Wait for response
    }

    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            if body == b"valid" {
                self.resume_http_request();
                return;
            }
        }
        self.send_http_response(403, vec![], Some(b"Unauthorized"));
    }
}
```

## Debugging Tips

### Enable Logging

```rust
log::info!("Debug message: {:?}", some_value);
log::error!("Error occurred: {}", error);
```

View logs:
```bash
loom -config loom.yaml -log-level debug
```

### Check Plugin Status

```bash
curl http://localhost:9091/plugins
```

### Common Issues

1. **Plugin not loading**: Check WASM file path and permissions
2. **Config parse error**: Validate JSON config matches expected structure
3. **Memory issues**: Increase WASM memory limits in config

## Alternative: TinyGo Plugin

You can also write plugins in Go using TinyGo:

```go
package main

import (
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
    proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct{}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
    return &pluginContext{}
}

// ... rest of implementation
```

Build with:
```bash
tinygo build -o plugin.wasm -scheduler=none -target=wasi main.go
```

## Next Steps

- [Plugin API Reference](/docs/core-concepts/plugins)
- [Advanced Plugin Patterns](/docs/guides/authentication)
- [Performance Optimization](/docs/reference/benchmarks)

---

*Questions? Join our [GitHub Discussions](https://github.com/josedab/loom/discussions) or [Discord](https://discord.gg/loom).*
