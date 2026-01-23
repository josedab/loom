---
sidebar_position: 2
title: Installation
description: Install Loom on your system using Go, Docker, or from source.
---

# Installation

Loom can be installed using several methods. Choose the one that best fits your environment.

## Prerequisites

- Go 1.21 or later (for building from source)
- Docker (optional, for containerized deployment)

## Install with Go

The quickest way to install Loom is using `go install`:

```bash
go install github.com/josedab/loom/cmd/loom@latest
```

This installs the `loom` binary to your `$GOPATH/bin` directory.

Verify the installation:

```bash
loom -h
```

## Download Binary

Download pre-built binaries from the [GitHub releases page](https://github.com/josedab/loom/releases).

### Linux (amd64)

```bash
curl -LO https://github.com/josedab/loom/releases/latest/download/loom-linux-amd64.tar.gz
tar -xzf loom-linux-amd64.tar.gz
sudo mv loom /usr/local/bin/
```

### macOS (Apple Silicon)

```bash
curl -LO https://github.com/josedab/loom/releases/latest/download/loom-darwin-arm64.tar.gz
tar -xzf loom-darwin-arm64.tar.gz
sudo mv loom /usr/local/bin/
```

### macOS (Intel)

```bash
curl -LO https://github.com/josedab/loom/releases/latest/download/loom-darwin-amd64.tar.gz
tar -xzf loom-darwin-amd64.tar.gz
sudo mv loom /usr/local/bin/
```

## Docker

Run Loom in a container:

```bash
docker run -p 8080:8080 -p 9091:9091 \
  -v $(pwd)/loom.yaml:/etc/loom/loom.yaml \
  ghcr.io/josedab/loom:latest \
  -config /etc/loom/loom.yaml
```

Or use Docker Compose:

```yaml title="docker-compose.yml"
version: '3.8'
services:
  loom:
    image: ghcr.io/josedab/loom:latest
    ports:
      - "8080:8080"   # Main proxy port
      - "9091:9091"   # Admin API
    volumes:
      - ./loom.yaml:/etc/loom/loom.yaml
    command: ["-config", "/etc/loom/loom.yaml"]
```

## Build from Source

Clone the repository and build:

```bash
git clone https://github.com/josedab/loom.git
cd loom
go build -o bin/loom ./cmd/loom
```

Run the built binary:

```bash
./bin/loom -config configs/loom.yaml
```

### Build Options

Build with version information:

```bash
go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse HEAD)" \
  -o bin/loom ./cmd/loom
```

Build for a specific platform:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o bin/loom-linux ./cmd/loom

# macOS
GOOS=darwin GOARCH=arm64 go build -o bin/loom-darwin ./cmd/loom

# Windows
GOOS=windows GOARCH=amd64 go build -o bin/loom.exe ./cmd/loom
```

## Kubernetes

Deploy Loom to Kubernetes using Helm:

```bash
helm repo add loom https://josedab.github.io/loom/charts
helm install loom loom/loom
```

Or apply the manifests directly:

```bash
kubectl apply -f https://raw.githubusercontent.com/josedab/loom/main/deploy/kubernetes/loom.yaml
```

See [Kubernetes Deployment](/docs/kubernetes/deployment) for detailed instructions.

## Verify Installation

After installation, verify Loom is working:

```bash
# Check version
loom -h

# Start with example config
loom -config /path/to/loom.yaml

# Check health endpoint (in another terminal)
curl http://localhost:9091/health
```

Expected output:

```json
{"status":"healthy"}
```

## Next Steps

Now that Loom is installed, continue to the [Quickstart](./quickstart) guide to configure your first gateway.
