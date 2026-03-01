# Container Security & Hardening Reference

# ความรู้อ้างอิงด้านความปลอดภัยและการทำ Hardening ของ Container

> **Purpose / วัตถุประสงค์**: Domain knowledge for the container security agent to audit Dockerfiles, container images, Kubernetes manifests, and runtime configurations. Covers CIS Docker Benchmark, Dockerfile best practices, Pod Security Standards, image optimization, and runtime security.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: CIS Docker Benchmark v1.6.0, Kubernetes v1.30, OCI Image Spec v1.1

---

## 1. CIS Docker Benchmark v1.6.0 Key Controls

## การควบคุมหลักตาม CIS Docker Benchmark v1.6.0

### 1.1 Host Configuration (Section 1)

| Control ID | Description                                 | Level | Automated |
| ---------- | ------------------------------------------- | ----- | --------- |
| 1.1.1      | Ensure a separate partition for containers  | L1    | Yes       |
| 1.1.2      | Ensure only trusted users in docker group   | L1    | Yes       |
| 1.1.3      | Audit Docker daemon activities              | L1    | Yes       |
| 1.1.4      | Audit Docker files and directories          | L1    | Yes       |
| 1.2.1      | Ensure Docker is up to date                 | L1    | Yes       |
| 1.2.2      | Ensure package manager databases up to date | L1    | Yes       |

### 1.2 Docker Daemon Configuration (Section 2)

```json
// /etc/docker/daemon.json — Hardened configuration
{
  "icc": false,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-default.json",
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 64000, "Soft": 64000 },
    "nproc": { "Name": "nproc", "Hard": 4096, "Soft": 4096 }
  },
  "storage-driver": "overlay2",
  "tls": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "tlsverify": true
}
```

### 1.3 Critical CIS Controls Summary

```
MUST IMPLEMENT (CIS Level 1):
  2.1  Restrict network traffic between containers (--icc=false)
  2.2  Set logging level to INFO
  2.3  Allow Docker to make iptables changes
  2.5  Do not use insecure registries
  2.6  Setup auditd rules for Docker
  2.8  Enable user namespace support
  2.14 Restrict containers from acquiring new privileges
  3.x  Ensure Docker socket/config file permissions (644/600)
  4.1  Ensure container image has no unnecessary packages
  4.2  Create a user for the container (non-root)
  4.5  Enable Content Trust (DOCKER_CONTENT_TRUST=1)
  4.6  Add HEALTHCHECK instruction
  4.9  Use COPY instead of ADD
  4.10 Do not store secrets in Dockerfiles
  5.2  Verify AppArmor or SELinux profile is applied
  5.4  Do not run containers as privileged
  5.7  Do not map privileged ports (< 1024) unless required
  5.10 Limit memory for container
  5.11 Set CPU priority for container
  5.12 Mount root filesystem as read-only
  5.25 Restrict container from acquiring additional privileges
```

---

## 2. Dockerfile Best Practices

## แนวปฏิบัติที่ดีสำหรับ Dockerfile

### 2.1 Secure Multi-Stage Dockerfile Template

```dockerfile
# ===== Build Stage =====
FROM node:22-alpine AS builder

# Create non-root user for build
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy dependency files first (cache optimization)
COPY --chown=appuser:appgroup package.json package-lock.json ./

# Install dependencies (no dev, no scripts for security)
RUN npm ci --only=production --ignore-scripts && \
    npm cache clean --force

# Copy source and build
COPY --chown=appuser:appgroup src/ ./src/
COPY --chown=appuser:appgroup tsconfig.json ./
RUN npm run build

# ===== Production Stage =====
FROM node:22-alpine AS production

# Security updates
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy only production artifacts
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package.json ./

# Security: non-root, read-only compatible
USER appuser:appgroup

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) })"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]

# Metadata
LABEL org.opencontainers.image.source="https://github.com/org/repo"
LABEL org.opencontainers.image.version="2.1.0"
LABEL org.opencontainers.image.description="My Application"
```

### 2.2 Common Dockerfile Security Issues

```
CRITICAL Issues:
  - Running as root (no USER instruction)
  - COPY/ADD of .env, credentials, or private keys
  - Using :latest tag (unpinned base image)
  - ADD with remote URL (untrusted source download)
  - Secrets in ENV or ARG instructions
  - Installing curl/wget in production image unnecessarily

HIGH Issues:
  - No HEALTHCHECK instruction
  - Using ADD instead of COPY for local files
  - Not pinning base image digest
  - Package manager cache not cleaned
  - Installing build tools in production stage
  - Exposing unnecessary ports

MEDIUM Issues:
  - No .dockerignore file
  - Excessive COPY layers (cache invalidation)
  - apt-get install without --no-install-recommends
  - Missing --no-cache flag for apk
  - Not using multi-stage build
```

### 2.3 Base Image Selection Guide

| Use Case      | Recommended Base                           | Size    | Security               |
| ------------- | ------------------------------------------ | ------- | ---------------------- |
| Node.js       | node:22-alpine                             | ~50MB   | Minimal attack surface |
| Python        | python:3.12-slim                           | ~120MB  | No extras              |
| Go            | scratch or distroless                      | ~2-20MB | Minimal                |
| Java          | eclipse-temurin:21-jre-alpine              | ~100MB  | JRE only               |
| .NET          | mcr.microsoft.com/dotnet/aspnet:8.0-alpine | ~100MB  | Runtime only           |
| Static binary | gcr.io/distroless/static-debian12          | ~2MB    | No shell, minimal      |
| Debug build   | gcr.io/distroless/base-debian12:debug      | ~20MB   | Includes busybox       |

### 2.4 Image Pinning Strategy

```dockerfile
# BAD - unpinned, can change unexpectedly
FROM node:22-alpine

# BETTER - pinned to minor version
FROM node:22.12-alpine3.20

# BEST - pinned to digest (immutable)
FROM node:22.12-alpine3.20@sha256:abc123def456...

# Verify digest
docker manifest inspect node:22.12-alpine3.20 | jq '.config.digest'
```

---

## 3. Kubernetes Pod Security Standards

## มาตรฐานความปลอดภัย Kubernetes Pod

### 3.1 Pod Security Standards (PSS) Levels

```yaml
# Privileged (unrestricted — avoid in production)
# Baseline (minimally restrictive — prevent known escalations)
# Restricted (hardened — security best practices)

# Apply via namespace labels (Kubernetes v1.25+)
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.30
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 3.2 Restricted Pod Security — Complete Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      # Pod-level security
      automountServiceAccountToken: false
      serviceAccountName: secure-app-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: app
          image: registry.example.com/app:v2.1.0@sha256:abc123...
          ports:
            - containerPort: 8080
              protocol: TCP

          # Container-level security
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1001
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault

          # Resource limits (prevent resource abuse)
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
              ephemeral-storage: 50Mi
            limits:
              cpu: 500m
              memory: 256Mi
              ephemeral-storage: 100Mi

          # Probes
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10

          # Volume mounts for writable directories
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: app-cache
              mountPath: /app/.cache

          # Environment from secrets (not inline)
          envFrom:
            - secretRef:
                name: app-secrets
            - configMapRef:
                name: app-config

      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 50Mi
        - name: app-cache
          emptyDir:
            sizeLimit: 100Mi

      # Topology and scheduling
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: secure-app
```

### 3.3 Network Policy (Zero Trust)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secure-app-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: secure-app
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
        - podSelector:
            matchLabels:
              app: ingress-controller
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: production
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

---

## 4. Image Layer Optimization

## การเพิ่มประสิทธิภาพเลเยอร์ Image

### 4.1 Layer Optimization Strategies

```dockerfile
# BAD — Each RUN creates a layer, cache invalidation on any change
RUN apt-get update
RUN apt-get install -y python3
RUN apt-get install -y pip
RUN pip install flask
RUN apt-get clean

# GOOD — Single layer, proper cleanup
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      python3 \
      python3-pip && \
    pip install --no-cache-dir flask && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
```

### 4.2 .dockerignore Template

```
# .dockerignore — keep build context small and secure
.git
.github
.env
.env.*
*.md
LICENSE
docker-compose*.yml
Dockerfile*
.dockerignore
node_modules
.npm
.cache
coverage
.nyc_output
test
tests
__tests__
*.test.*
*.spec.*
.vscode
.idea
*.swp
*.swo
```

### 4.3 Image Scanning Integration

```bash
# Trivy — comprehensive vulnerability scan
trivy image --severity CRITICAL,HIGH --exit-code 1 \
  --ignore-unfixed myapp:latest

# Grype — fast vulnerability scan
grype myapp:latest --fail-on high --output sarif > grype.sarif

# Docker Scout (Docker Desktop / CLI)
docker scout cves myapp:latest --format sarif --output scout.sarif

# Syft — generate SBOM from image
syft myapp:latest -o cyclonedx-json > image-sbom.json

# Hadolint — Dockerfile linter
hadolint Dockerfile --format sarif > hadolint.sarif

# Dockle — CIS Benchmark checker for images
dockle --exit-code 1 --exit-level warn myapp:latest
```

---

## 5. Runtime Security

## ความปลอดภัยขณะทำงาน (Runtime)

### 5.1 Seccomp Profiles

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "bind",
        "clone",
        "close",
        "connect",
        "dup",
        "dup2",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "execve",
        "exit",
        "exit_group",
        "fstat",
        "futex",
        "getcwd",
        "getdents64",
        "getpid",
        "getppid",
        "getsockname",
        "getsockopt",
        "ioctl",
        "listen",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "nanosleep",
        "open",
        "openat",
        "pipe2",
        "poll",
        "read",
        "readlink",
        "recvfrom",
        "recvmsg",
        "rt_sigaction",
        "rt_sigprocmask",
        "sendmsg",
        "sendto",
        "setsockopt",
        "set_tid_address",
        "socket",
        "stat",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### 5.2 AppArmor Profile

```
# /etc/apparmor.d/containers/app-profile
#include <tunables/global>

profile app-container flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Network access
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,

  # File access
  /app/** r,
  /app/dist/** r,
  /tmp/** rw,
  /proc/*/status r,

  # Deny dangerous operations
  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /proc/*/mem rw,
  deny /sys/** w,
  deny mount,
  deny umount,
  deny ptrace,
}
```

### 5.3 Falco Runtime Rules (v0.37+)

```yaml
# Custom Falco rules for container runtime monitoring
- rule: Container Shell Spawned
  desc: Detect shell execution in container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh, zsh, dash, ash) and
    not proc.pname in (crond, entrypoint.sh)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name
     shell=%proc.name parent=%proc.pname
     image=%container.image.repository)
  priority: WARNING

- rule: Sensitive File Access
  desc: Detect access to sensitive files in containers
  condition: >
    open_read and container and
    fd.name in (/etc/shadow, /etc/gshadow, /proc/self/environ)
  output: >
    Sensitive file read in container
    (file=%fd.name user=%user.name container=%container.name
     image=%container.image.repository)
  priority: CRITICAL

- rule: Container Drift Detected
  desc: New executable not in original image
  condition: >
    spawned_process and container and
    not proc.name pmatch (node, python, java, nginx) and
    not container.image.repository = "debug"
  output: >
    Unexpected process in container
    (proc=%proc.name container=%container.name
     image=%container.image.repository)
  priority: ERROR
```

---

## 6. Container Security Scanning Pipeline

## ไปป์ไลน์การสแกนความปลอดภัย Container

### CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/container-security.yml
name: Container Security
on:
  push:
    paths:
      - "Dockerfile*"
      - ".dockerignore"
      - "src/**"

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Lint Dockerfile
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          failure-threshold: warning

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: CIS Benchmark check
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            goodwithtech/dockle:latest --exit-code 1 myapp:${{ github.sha }}

      - name: Vulnerability scan
        uses: aquasecurity/trivy-action@0.20.0
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Generate SBOM
        run: |
          syft myapp:${{ github.sha }} -o cyclonedx-json > container-sbom.json

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```

---

## 7. Quick Reference — Container Security Checklist

## อ้างอิงด่วน — รายการตรวจสอบความปลอดภัย Container

```
BUILD TIME:
  [ ] Base image pinned by digest
  [ ] Multi-stage build (no build tools in production)
  [ ] Non-root USER specified
  [ ] No secrets in Dockerfile (ENV, ARG, COPY)
  [ ] HEALTHCHECK defined
  [ ] COPY used instead of ADD
  [ ] .dockerignore excludes sensitive files
  [ ] Minimal packages installed (--no-install-recommends)
  [ ] Package manager cache cleaned
  [ ] Image scanned with trivy/grype (0 CRITICAL/HIGH)
  [ ] Hadolint passes with no warnings
  [ ] SBOM generated and attached to image

DEPLOY TIME:
  [ ] Image pulled from trusted registry only
  [ ] Image signature verified (cosign/notation)
  [ ] Pod Security Standard: restricted
  [ ] Resource limits set (CPU, memory, ephemeral-storage)
  [ ] Read-only root filesystem
  [ ] No privileged containers
  [ ] No host namespaces (hostPID, hostIPC, hostNetwork)
  [ ] Capabilities dropped (ALL), only add required
  [ ] automountServiceAccountToken: false
  [ ] Network policies applied (default deny)
  [ ] Seccomp profile applied (RuntimeDefault minimum)

RUNTIME:
  [ ] Container drift detection enabled (Falco/Sysdig)
  [ ] Log aggregation configured
  [ ] No shell access in production containers
  [ ] Image update policy enforced (no :latest)
  [ ] Vulnerability monitoring active (continuous scan)
```
