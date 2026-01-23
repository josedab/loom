---
sidebar_position: 4
title: CLI Reference
description: Command-line interface reference for Loom.
---

# CLI Reference

Complete reference for Loom's command-line interface.

## Basic Usage

```bash
loom [flags]
```

## Flags

### -config

Specify the configuration file path.

```bash
loom -config /path/to/config.yaml
```

**Default:** `loom.yaml` in current directory

Multiple config files can be specified and are merged in order:

```bash
loom -config base.yaml -config production.yaml
```

### -log-level

Set the logging level.

```bash
loom -log-level debug
```

**Values:** `debug`, `info`, `warn`, `error`

**Default:** `info`

### -log-format

Set the log output format.

```bash
loom -log-format json
```

**Values:** `json`, `text`

**Default:** `json`

### -validate

Validate configuration and exit.

```bash
loom -config config.yaml -validate
```

Returns exit code 0 if valid, 1 if invalid.

### -version

Print version information and exit.

```bash
loom -version
```

**Output:**
```
Loom v1.0.0
Go: go1.21.0
Commit: abc1234
Built: 2024-01-15T10:00:00Z
```

### -help

Show help message.

```bash
loom -help
```

## Environment Variables

Loom supports configuration via environment variables.

### LOOM_CONFIG

Path to configuration file.

```bash
export LOOM_CONFIG=/etc/loom/config.yaml
loom
```

### LOOM_LOG_LEVEL

Logging level.

```bash
export LOOM_LOG_LEVEL=debug
loom
```

### LOOM_LOG_FORMAT

Log format.

```bash
export LOOM_LOG_FORMAT=text
loom
```

### Variable Substitution

Environment variables can be used in configuration files:

```yaml
# config.yaml
upstreams:
  - name: backend
    endpoints:
      - ${BACKEND_HOST}:${BACKEND_PORT}

admin:
  auth:
    basic:
      password: ${ADMIN_PASSWORD}
```

## Signals

Loom responds to the following Unix signals:

### SIGTERM / SIGINT

Graceful shutdown.

```bash
kill -TERM <pid>
# or
kill -INT <pid>
```

Loom will:
1. Stop accepting new connections
2. Wait for in-flight requests to complete (up to graceful timeout)
3. Close all connections
4. Exit

### SIGHUP

Reload configuration.

```bash
kill -HUP <pid>
```

Loom will:
1. Read the configuration file
2. Validate the new configuration
3. Apply changes without dropping connections
4. Log any errors if reload fails

### SIGUSR1

Dump goroutine stacks (debug).

```bash
kill -USR1 <pid>
```

### SIGUSR2

Trigger garbage collection (debug).

```bash
kill -USR2 <pid>
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success / Clean shutdown |
| 1 | Configuration error |
| 2 | Runtime error |
| 3 | Port binding error |

## Examples

### Basic Startup

```bash
# Start with default config (./loom.yaml)
loom

# Start with specific config
loom -config /etc/loom/config.yaml

# Start with debug logging
loom -config config.yaml -log-level debug
```

### Validation

```bash
# Validate config file
loom -config config.yaml -validate

# Validate with verbose output
loom -config config.yaml -validate -log-level debug
```

### Production Startup

```bash
# Production with all flags
loom \
  -config /etc/loom/config.yaml \
  -log-level info \
  -log-format json
```

### Systemd Service

```ini
# /etc/systemd/system/loom.service
[Unit]
Description=Loom API Gateway
After=network.target

[Service]
Type=simple
User=loom
Group=loom
ExecStart=/usr/local/bin/loom -config /etc/loom/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/loom

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable loom
sudo systemctl start loom

# Reload config
sudo systemctl reload loom

# View logs
journalctl -u loom -f
```

### Docker

```dockerfile
FROM ghcr.io/loom/loom:latest

COPY config.yaml /etc/loom/config.yaml

EXPOSE 8080 8443 9091

CMD ["loom", "-config", "/etc/loom/config.yaml"]
```

```bash
# Run with Docker
docker run -d \
  -p 8080:8080 \
  -p 9091:9091 \
  -v $(pwd)/config.yaml:/etc/loom/config.yaml \
  ghcr.io/loom/loom:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  loom:
    image: ghcr.io/loom/loom:latest
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9091:9091"
    volumes:
      - ./config.yaml:/etc/loom/config.yaml:ro
      - ./certs:/etc/loom/certs:ro
    environment:
      - LOOM_LOG_LEVEL=info
      - BACKEND_HOST=backend
      - BACKEND_PORT=8080
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9091/health"]
      interval: 10s
      timeout: 5s
      retries: 3
```

### Kubernetes Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: loom
spec:
  containers:
    - name: loom
      image: ghcr.io/loom/loom:latest
      args:
        - -config
        - /etc/loom/config.yaml
        - -log-level
        - info
      ports:
        - containerPort: 8080
          name: http
        - containerPort: 9091
          name: admin
      env:
        - name: BACKEND_HOST
          value: backend-service
      volumeMounts:
        - name: config
          mountPath: /etc/loom
          readOnly: true
      livenessProbe:
        httpGet:
          path: /health
          port: admin
        initialDelaySeconds: 10
      readinessProbe:
        httpGet:
          path: /ready
          port: admin
        initialDelaySeconds: 5
  volumes:
    - name: config
      configMap:
        name: loom-config
```

## loomctl (Admin CLI)

Loom also provides an admin CLI tool for interacting with running instances.

### Installation

```bash
# Install loomctl
go install github.com/loom/loom/cmd/loomctl@latest
```

### Configuration

```bash
# Set admin URL
export LOOM_ADMIN_URL=http://localhost:9091

# Or use flag
loomctl --admin-url http://localhost:9091 routes list
```

### Commands

#### Routes

```bash
# List routes
loomctl routes list

# Get route details
loomctl routes get api

# Create route
loomctl routes create -f route.yaml

# Delete route
loomctl routes delete api

# Enable/disable route
loomctl routes enable api
loomctl routes disable api
```

#### Upstreams

```bash
# List upstreams
loomctl upstreams list

# Get upstream details
loomctl upstreams get backend

# Get health status
loomctl upstreams health backend

# Add endpoint
loomctl upstreams add-endpoint backend api3.internal:8080

# Remove endpoint
loomctl upstreams remove-endpoint backend api3.internal:8080

# Drain endpoint
loomctl upstreams drain backend api2.internal:8080 --timeout 30s
```

#### Circuit Breaker

```bash
# Get status
loomctl circuit-breaker status backend

# Reset
loomctl circuit-breaker reset backend

# Trip (force open)
loomctl circuit-breaker trip backend
```

#### Cache

```bash
# Get stats
loomctl cache stats

# Clear all
loomctl cache clear

# Clear by pattern
loomctl cache clear --pattern "/api/products/*"
```

#### Config

```bash
# Reload config
loomctl config reload

# Validate config
loomctl config validate -f config.yaml

# Get current config
loomctl config get
```

#### Plugins

```bash
# List plugins
loomctl plugins list

# Get plugin info
loomctl plugins get auth

# Reload plugin
loomctl plugins reload auth

# Enable/disable
loomctl plugins enable auth
loomctl plugins disable auth
```

#### Stats

```bash
# Get overview
loomctl stats

# Get route stats
loomctl stats routes

# Get upstream stats
loomctl stats upstreams

# Watch real-time stats
loomctl stats --watch
```

### Output Formats

```bash
# Table (default)
loomctl routes list

# JSON
loomctl routes list -o json

# YAML
loomctl routes list -o yaml

# Wide table
loomctl routes list -o wide
```

## Completion

Generate shell completion scripts:

```bash
# Bash
loom completion bash > /etc/bash_completion.d/loom
loomctl completion bash > /etc/bash_completion.d/loomctl

# Zsh
loom completion zsh > "${fpath[1]}/_loom"
loomctl completion zsh > "${fpath[1]}/_loomctl"

# Fish
loom completion fish > ~/.config/fish/completions/loom.fish
loomctl completion fish > ~/.config/fish/completions/loomctl.fish
```

## Next Steps

- **[Configuration](./configuration)** - Configuration reference
- **[Admin API](./admin-api)** - REST API reference
- **[Quickstart](../getting-started/quickstart)** - Get started with Loom
