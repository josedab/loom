---
sidebar_position: 11
title: Migrate from NGINX
description: Step-by-step guide for migrating from NGINX to Loom.
---

# Migrating from NGINX

This guide helps you migrate from NGINX to Loom, covering common configurations and patterns.

## Key Differences

| Aspect | NGINX | Loom |
|--------|-------|------|
| Configuration | nginx.conf DSL | YAML |
| Reload | `nginx -s reload` | Automatic file watching |
| Plugins | C modules, Lua | WASM (Proxy-Wasm) |
| Load Balancing | Built-in | Built-in |
| Health Checks | nginx Plus | Built-in (free) |
| HTTP/3 | nginx Plus/patches | Built-in (free) |

## Configuration Mapping

### Server Blocks to Listeners

**NGINX:**
```nginx
server {
    listen 80;
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
}
```

**Loom:**
```yaml
listeners:
  - name: http
    address: ":80"
    protocol: http

  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/ssl/cert.pem
      key_file: /etc/loom/ssl/key.pem
```

### Location Blocks to Routes

**NGINX:**
```nginx
location /api/ {
    proxy_pass http://backend;
    proxy_connect_timeout 30s;
    proxy_read_timeout 60s;
}

location /static/ {
    proxy_pass http://cdn;
}

location = /health {
    return 200 'OK';
}
```

**Loom:**
```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
    timeout: 60s

  - id: static
    path: /static/*
    upstream: cdn

  - id: health
    path: /health
    methods: [GET]
    upstream: health-service
```

### Upstream Blocks

**NGINX:**
```nginx
upstream backend {
    least_conn;
    server api1.internal:8080 weight=5;
    server api2.internal:8080 weight=3;
    server api3.internal:8080 backup;

    keepalive 32;
}
```

**Loom:**
```yaml
upstreams:
  - name: backend
    endpoints:
      - host: api1.internal
        port: 8080
        weight: 5
      - host: api2.internal
        port: 8080
        weight: 3
      - host: api3.internal
        port: 8080
        weight: 1
        backup: true
    load_balancer: least_conn
    connection:
      max_idle: 32
```

### SSL/TLS Configuration

**NGINX:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
```

**Loom:**
```yaml
listeners:
  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/ssl/cert.pem
      key_file: /etc/loom/ssl/key.pem
      min_version: "1.2"
      cipher_suites:
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

### Rate Limiting

**NGINX:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
    }
}
```

**Loom:**
```yaml
rate_limit:
  enabled: true
  key: ${client_ip}
  default:
    requests_per_second: 10
    burst: 20
```

### Header Manipulation

**NGINX:**
```nginx
location /api/ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    add_header X-Response-Time $request_time;
}
```

**Loom:**
```yaml
routes:
  - id: api
    path: /api/*
    upstream: backend
    headers:
      request:
        set:
          Host: ${host}
          X-Real-IP: ${client_ip}
          X-Forwarded-For: ${forwarded_for}
          X-Forwarded-Proto: ${scheme}
      response:
        add:
          X-Response-Time: ${response_time}
```

### Caching

**NGINX:**
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=api_cache:10m max_size=1g;

location /api/ {
    proxy_cache api_cache;
    proxy_cache_valid 200 5m;
    proxy_cache_bypass $http_cache_control;
}
```

**Loom:**
```yaml
cache:
  enabled: true
  store:
    type: memory
    max_size: 1GB
  default_ttl: 5m
  bypass_header: Cache-Control
  rules:
    - match:
        paths: ["/api/*"]
        status_codes: [200]
      ttl: 5m
```

### Rewrites and Redirects

**NGINX:**
```nginx
location /old-api/ {
    rewrite ^/old-api/(.*)$ /api/v2/$1 break;
    proxy_pass http://backend;
}

location /legacy {
    return 301 /new-path;
}
```

**Loom:**
```yaml
routes:
  - id: old-api
    path: /old-api/*
    upstream: backend
    strip_prefix: true
    add_prefix: /api/v2

  - id: legacy-redirect
    path: /legacy
    redirect:
      url: /new-path
      code: 301
```

### Basic Authentication

**NGINX:**
```nginx
location /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://admin-backend;
}
```

**Loom:**
```yaml
routes:
  - id: admin
    path: /admin/*
    upstream: admin-backend
    middleware:
      auth:
        type: basic
        realm: "Admin Area"
        users:
          - username: admin
            password: ${ADMIN_PASSWORD_HASH}
```

### Gzip Compression

**NGINX:**
```nginx
gzip on;
gzip_types text/plain application/json application/javascript;
gzip_min_length 1000;
gzip_comp_level 6;
```

**Loom:**
```yaml
middleware:
  compression:
    enabled: true
    types:
      - text/plain
      - application/json
      - application/javascript
    min_length: 1000
    level: 6
```

### WebSocket Proxying

**NGINX:**
```nginx
location /ws/ {
    proxy_pass http://websocket-backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

**Loom:**
```yaml
routes:
  - id: websocket
    path: /ws/*
    upstream: websocket-backend
    websocket: true  # Automatic upgrade handling
```

## Complete Migration Example

### Original NGINX Configuration

```nginx
# /etc/nginx/nginx.conf
user nginx;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        least_conn;
        server api1.internal:8080;
        server api2.internal:8080;
        keepalive 32;
    }

    upstream static_backend {
        server cdn1.internal:80;
        server cdn2.internal:80;
    }

    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

    server {
        listen 80;
        server_name api.example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name api.example.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        location /api/ {
            limit_req zone=api burst=200 nodelay;
            proxy_pass http://api_backend;
            proxy_connect_timeout 30s;
            proxy_read_timeout 60s;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /static/ {
            proxy_pass http://static_backend;
            proxy_cache_valid 200 1h;
        }

        location /health {
            return 200 'OK';
            add_header Content-Type text/plain;
        }
    }
}
```

### Equivalent Loom Configuration

```yaml
# loom.yaml
listeners:
  - name: http
    address: ":80"
    protocol: http

  - name: https
    address: ":443"
    protocol: https
    tls:
      cert_file: /etc/loom/ssl/cert.pem
      key_file: /etc/loom/ssl/key.pem
      min_version: "1.2"

routes:
  # HTTP to HTTPS redirect
  - id: http-redirect
    path: /*
    listener: http
    redirect:
      url: https://${host}${path}
      code: 301

  # API routes
  - id: api
    path: /api/*
    methods: [GET, POST, PUT, DELETE]
    upstream: api-backend
    timeout: 60s
    headers:
      request:
        set:
          Host: ${host}
          X-Real-IP: ${client_ip}

  # Static content
  - id: static
    path: /static/*
    upstream: static-backend
    cache:
      ttl: 1h

  # Health check
  - id: health
    path: /health
    methods: [GET]
    static_response:
      status: 200
      body: "OK"
      headers:
        Content-Type: text/plain

upstreams:
  - name: api-backend
    endpoints:
      - "api1.internal:8080"
      - "api2.internal:8080"
    load_balancer: least_conn
    connection:
      max_idle: 32
    health_check:
      enabled: true
      path: /health
      interval: 10s

  - name: static-backend
    endpoints:
      - "cdn1.internal:80"
      - "cdn2.internal:80"
    load_balancer: round_robin

rate_limit:
  enabled: true
  key: ${client_ip}
  default:
    requests_per_second: 100
    burst: 200

admin:
  enabled: true
  address: ":9091"
```

## OpenResty/Lua Migration

If you're using OpenResty with Lua:

**Lua Script (auth.lua):**
```lua
local jwt = require "resty.jwt"

local function authenticate()
    local token = ngx.req.get_headers()["Authorization"]
    if not token then
        ngx.exit(401)
    end
    local jwt_obj = jwt:verify("secret", token:gsub("Bearer ", ""))
    if not jwt_obj.verified then
        ngx.exit(403)
    end
end

authenticate()
```

**Loom WASM Plugin (Rust):**
```rust
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

struct JwtAuth;

impl HttpContext for JwtAuth {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        if let Some(auth) = self.get_http_request_header("Authorization") {
            // Verify JWT token
            if verify_jwt(&auth) {
                return Action::Continue;
            }
        }
        self.send_http_response(401, vec![], Some(b"Unauthorized"));
        Action::Pause
    }
}
```

Or use Loom's built-in JWT authentication:

```yaml
middleware:
  auth:
    type: jwt
    secret: ${JWT_SECRET}
    header: Authorization
```

## Verification

After migration, verify:

```bash
# Test routes
curl -v https://api.example.com/api/test
curl -v https://api.example.com/static/image.png
curl -v https://api.example.com/health

# Check rate limiting
for i in {1..150}; do curl -s -o /dev/null -w "%{http_code}\n" https://api.example.com/api/test; done

# Verify TLS
openssl s_client -connect api.example.com:443 -tls1_2

# Check metrics
curl http://localhost:9091/metrics
```

## Next Steps

- [Configuration Reference](/docs/reference/configuration)
- [Troubleshooting](/docs/reference/troubleshooting)
- [Performance Tuning](/docs/advanced/ebpf-acceleration)
