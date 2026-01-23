---
sidebar_position: 1
title: HTTP/3 Setup
description: Configure HTTP/3 (QUIC) for reduced latency and improved performance.
---

# HTTP/3 (QUIC) Setup

HTTP/3 uses QUIC as its transport protocol, providing significant performance improvements over HTTP/1.1 and HTTP/2.

## Benefits of HTTP/3

| Feature | Benefit |
|---------|---------|
| 0-RTT connections | Instant reconnection for returning clients |
| No head-of-line blocking | Lost packets don't delay other streams |
| Connection migration | Seamless network switches (WiFi to cellular) |
| Built-in encryption | TLS 1.3 is mandatory |

## Prerequisites

HTTP/3 requires TLS certificates since QUIC mandates encryption.

## Basic Configuration

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
```

## Dual-Stack Setup

Run HTTP/2 and HTTP/3 on the same port with Alt-Svc advertisement:

```yaml
listeners:
  # HTTP/2 over TLS
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
    http3:
      advertise: true  # Send Alt-Svc header

  # HTTP/3 over QUIC (same port)
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
```

The `advertise: true` setting adds the `Alt-Svc` header to HTTP/2 responses:

```
Alt-Svc: h3=":443"; ma=86400
```

Clients that support HTTP/3 will automatically upgrade on subsequent requests.

## Advanced Options

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
    quic:
      max_idle_timeout: 30s
      max_incoming_streams: 100
      max_incoming_uni_streams: 100
      initial_stream_receive_window: 512KB
      max_stream_receive_window: 6MB
      initial_connection_receive_window: 512KB
      max_connection_receive_window: 15MB
```

### QUIC Options

| Option | Default | Description |
|--------|---------|-------------|
| `max_idle_timeout` | `30s` | Close connection after idle period |
| `max_incoming_streams` | `100` | Max concurrent bidirectional streams |
| `max_incoming_uni_streams` | `100` | Max concurrent unidirectional streams |
| `initial_stream_receive_window` | `512KB` | Initial flow control window per stream |
| `max_stream_receive_window` | `6MB` | Max flow control window per stream |
| `initial_connection_receive_window` | `512KB` | Initial flow control window per connection |
| `max_connection_receive_window` | `15MB` | Max flow control window per connection |

## 0-RTT Configuration

Enable 0-RTT for instant reconnection:

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
    quic:
      enable_0rtt: true
      max_0rtt_size: 16KB
```

**Security Note:** 0-RTT data can be replayed. Only enable for idempotent requests.

## Certificate Management

### Using Let's Encrypt

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/letsencrypt/live/example.com/fullchain.pem
      key_file: /etc/letsencrypt/live/example.com/privkey.pem
```

Loom watches certificate files and reloads them automatically when renewed.

### Multiple Certificates (SNI)

```yaml
listeners:
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      certificates:
        - cert_file: /etc/loom/tls/example.com.pem
          key_file: /etc/loom/tls/example.com-key.pem
          hosts: ["example.com", "www.example.com"]

        - cert_file: /etc/loom/tls/api.example.com.pem
          key_file: /etc/loom/tls/api.example.com-key.pem
          hosts: ["api.example.com"]
```

## Testing HTTP/3

### Using curl

```bash
# curl 7.66+ with HTTP/3 support
curl --http3 https://localhost:443/api/test
```

### Using Chrome

1. Enable QUIC in Chrome: `chrome://flags/#enable-quic`
2. Visit your site
3. Check DevTools → Network → Protocol column for "h3"

### Verify with openssl

```bash
# Check QUIC is listening
openssl s_client -connect localhost:443 -servername example.com
```

## Firewall Configuration

QUIC uses UDP instead of TCP:

```bash
# Allow UDP port 443
sudo iptables -A INPUT -p udp --dport 443 -j ACCEPT

# Or with ufw
sudo ufw allow 443/udp
```

## Monitoring HTTP/3

### Prometheus Metrics

```
# HTTP/3 connections
loom_http3_connections_total
loom_http3_connections_active

# QUIC stream metrics
loom_quic_streams_opened_total
loom_quic_streams_closed_total

# 0-RTT metrics
loom_quic_0rtt_accepted_total
loom_quic_0rtt_rejected_total
```

### Admin API

```bash
curl http://localhost:9091/listeners
```

```json
{
  "listeners": [
    {
      "name": "quic",
      "address": ":443",
      "protocol": "http3",
      "active_connections": 42
    }
  ]
}
```

## Troubleshooting

### Connection Refused

Check that UDP is allowed through your firewall and that Loom is listening:

```bash
# Check Loom is listening
ss -ulnp | grep 443

# Test UDP connectivity
nc -u -v localhost 443
```

### Slow Connections

If HTTP/3 is slower than HTTP/2, check:

1. QUIC flow control windows may be too small
2. Network may have high UDP packet loss
3. Client may not have HTTP/3 session cache

### Certificate Errors

QUIC requires valid TLS certificates. Self-signed certificates may not work with all clients.

## Complete Example

```yaml
listeners:
  # HTTP (redirects to HTTPS)
  - name: http
    address: ":80"
    protocol: http
    redirect_https: true

  # HTTP/2 with Alt-Svc
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
    http3:
      advertise: true

  # HTTP/3
  - name: quic
    address: ":443"
    protocol: http3
    tls:
      cert_file: /etc/loom/tls/cert.pem
      key_file: /etc/loom/tls/key.pem
    quic:
      max_idle_timeout: 30s
      enable_0rtt: true
```

## Next Steps

- **[gRPC Proxying](./grpc-proxying)** - Proxy gRPC traffic
- **[Observability](./observability)** - Monitor HTTP/3 traffic
- **[Configuration Reference](/docs/reference/configuration)** - Full configuration options
