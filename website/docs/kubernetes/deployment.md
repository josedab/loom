---
sidebar_position: 2
title: Kubernetes Deployment
description: Deploy and operate Loom in Kubernetes environments.
---

# Kubernetes Deployment

This guide covers deploying Loom in Kubernetes using Helm charts, manifests, and best practices for production environments.

## Deployment Options

| Method | Best For |
|--------|----------|
| **Helm Chart** | Production deployments, GitOps |
| **Raw Manifests** | Learning, customization |
| **Operator** | Advanced lifecycle management |

## Helm Installation

### Add Helm Repository

```bash
helm repo add loom https://charts.loom.dev
helm repo update
```

### Basic Installation

```bash
helm install loom loom/loom \
  --namespace loom-system \
  --create-namespace
```

### Production Installation

```bash
helm install loom loom/loom \
  --namespace loom-system \
  --create-namespace \
  --values production-values.yaml
```

### Production Values

```yaml title="production-values.yaml"
replicaCount: 3

image:
  repository: ghcr.io/loom/loom
  tag: v1.0.0
  pullPolicy: IfNotPresent

resources:
  requests:
    cpu: 500m
    memory: 256Mi
  limits:
    cpu: 2000m
    memory: 1Gi

# Horizontal Pod Autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# Pod Disruption Budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# Service configuration
service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"

# Ingress (if not using Gateway API)
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com

# Loom configuration
config:
  listeners:
    - name: http
      address: ":8080"
      protocol: http

    - name: https
      address: ":8443"
      protocol: https
      tls:
        cert_file: /etc/loom/tls/tls.crt
        key_file: /etc/loom/tls/tls.key

    - name: admin
      address: ":9091"
      protocol: http

  admin:
    enabled: true
    address: ":9091"

  metrics:
    enabled: true
    path: /metrics

# TLS secrets
tls:
  enabled: true
  secretName: loom-tls

# Service account
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/loom-role

# Pod security
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

# Probes
livenessProbe:
  httpGet:
    path: /health
    port: admin
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: admin
  initialDelaySeconds: 5
  periodSeconds: 5

# Node placement
nodeSelector:
  kubernetes.io/os: linux

tolerations: []

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - loom
          topologyKey: kubernetes.io/hostname

# Priority class
priorityClassName: system-cluster-critical

# Topology spread
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: loom
```

## Raw Manifests

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: loom-system
  labels:
    app.kubernetes.io/name: loom
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: loom-config
  namespace: loom-system
data:
  loom.yaml: |
    listeners:
      - name: http
        address: ":8080"
        protocol: http

      - name: admin
        address: ":9091"
        protocol: http

    admin:
      enabled: true

    routes:
      - id: api
        path: /api/*
        upstream: backend

    upstreams:
      - name: backend
        endpoints:
          - backend-service.default.svc.cluster.local:8080
        health_check:
          enabled: true
          interval: 10s
          path: /health
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: loom
  namespace: loom-system
  labels:
    app.kubernetes.io/name: loom
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: loom
  template:
    metadata:
      labels:
        app.kubernetes.io/name: loom
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9091"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: loom
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: loom
          image: ghcr.io/loom/loom:v1.0.0
          args:
            - -config
            - /etc/loom/loom.yaml
            - -log-level
            - info
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: admin
              containerPort: 9091
              protocol: TCP
          resources:
            requests:
              cpu: 500m
              memory: 256Mi
            limits:
              cpu: 2000m
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          livenessProbe:
            httpGet:
              path: /health
              port: admin
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: admin
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: config
              mountPath: /etc/loom
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: loom-config
        - name: tmp
          emptyDir: {}
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchExpressions:
                    - key: app.kubernetes.io/name
                      operator: In
                      values:
                        - loom
                topologyKey: kubernetes.io/hostname
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: loom
  namespace: loom-system
  labels:
    app.kubernetes.io/name: loom
spec:
  type: LoadBalancer
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
    - name: https
      port: 443
      targetPort: https
      protocol: TCP
  selector:
    app.kubernetes.io/name: loom
---
apiVersion: v1
kind: Service
metadata:
  name: loom-admin
  namespace: loom-system
spec:
  type: ClusterIP
  ports:
    - name: admin
      port: 9091
      targetPort: admin
  selector:
    app.kubernetes.io/name: loom
```

### ServiceAccount and RBAC

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: loom
  namespace: loom-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: loom
rules:
  - apiGroups: [""]
    resources: ["services", "endpoints", "secrets", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways", "httproutes", "grpcroutes", "tcproutes", "tlsroutes", "referencegrants"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways/status", "httproutes/status", "grpcroutes/status"]
    verbs: ["update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: loom
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: loom
subjects:
  - kind: ServiceAccount
    name: loom
    namespace: loom-system
```

### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: loom
  namespace: loom-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: loom
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 4
          periodSeconds: 15
      selectPolicy: Max
```

### PodDisruptionBudget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: loom
  namespace: loom-system
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: loom
```

## TLS Configuration

### Using cert-manager

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: loom-tls
  namespace: loom-system
spec:
  secretName: loom-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - api.example.com
    - "*.api.example.com"
```

### Manual TLS Secret

```bash
kubectl create secret tls loom-tls \
  --namespace loom-system \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

## Configuration Management

### External Configuration

Use ConfigMap for Loom configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: loom-config
  namespace: loom-system
data:
  loom.yaml: |
    # Full Loom configuration here
```

### Secrets Management

Use Kubernetes Secrets for sensitive values:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: loom-secrets
  namespace: loom-system
type: Opaque
stringData:
  api-key: your-secret-api-key
  jwt-secret: your-jwt-secret
```

Reference in configuration:

```yaml
# In loom.yaml
auth:
  jwt:
    secret: ${JWT_SECRET}
```

Mount as environment variable:

```yaml
env:
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: loom-secrets
        key: jwt-secret
```

### External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: loom-secrets
  namespace: loom-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: loom-secrets
  data:
    - secretKey: api-key
      remoteRef:
        key: loom/api-key
```

## Multi-Zone Deployment

### Zone-Aware Topology

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: loom
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: loom
```

### Zone-Aware Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: loom
  annotations:
    service.kubernetes.io/topology-mode: Auto
spec:
  topologyKeys:
    - topology.kubernetes.io/zone
    - "*"
```

## Monitoring

### ServiceMonitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: loom
  namespace: loom-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: loom
  endpoints:
    - port: admin
      path: /metrics
      interval: 15s
```

### Grafana Dashboard

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: loom-dashboard
  namespace: monitoring
  labels:
    grafana_dashboard: "1"
data:
  loom-dashboard.json: |
    {
      "title": "Loom API Gateway",
      "panels": [...]
    }
```

## Upgrading

### Rolling Update

```bash
# Update image
kubectl set image deployment/loom \
  loom=ghcr.io/loom/loom:v1.1.0 \
  -n loom-system

# Or with Helm
helm upgrade loom loom/loom \
  --namespace loom-system \
  --set image.tag=v1.1.0
```

### Blue-Green Deployment

```bash
# Deploy new version
helm install loom-v2 loom/loom \
  --namespace loom-system \
  --set nameOverride=loom-v2 \
  --values production-values.yaml \
  --set image.tag=v1.1.0

# Switch traffic
kubectl patch service loom -n loom-system \
  -p '{"spec":{"selector":{"app.kubernetes.io/name":"loom-v2"}}}'

# Remove old version
helm uninstall loom -n loom-system
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n loom-system -l app.kubernetes.io/name=loom
kubectl describe pod -n loom-system -l app.kubernetes.io/name=loom
```

### View Logs

```bash
kubectl logs -n loom-system -l app.kubernetes.io/name=loom --tail=100 -f
```

### Check Configuration

```bash
kubectl exec -n loom-system deploy/loom -- cat /etc/loom/loom.yaml
```

### Test Connectivity

```bash
kubectl run test-pod --rm -it --image=curlimages/curl -- \
  curl -v http://loom.loom-system.svc.cluster.local:8080/health
```

## Next Steps

- **[Service Discovery](./service-discovery)** - Dynamic backend discovery
- **[Gateway API](./gateway-api)** - Gateway API resources
- **[Observability](../guides/observability)** - Monitoring and tracing
