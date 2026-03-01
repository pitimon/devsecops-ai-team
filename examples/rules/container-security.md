# Container Security Rules

## Dockerfile Fitness Functions

- Base image MUST use specific version tag (not :latest)
- Base image MUST be from trusted registry (Docker Hub official, GHCR, ECR)
- Dockerfile MUST include a USER instruction (non-root)
- Dockerfile MUST NOT use ADD for remote URLs (use COPY + curl)
- Dockerfile MUST NOT include secrets or credentials
- Multi-stage build SHOULD be used for compiled languages
- HEALTHCHECK SHOULD be defined
- .dockerignore MUST exist and exclude sensitive files

## Container Runtime Rules

- Containers MUST NOT run as root (runAsNonRoot: true)
- Containers MUST drop all capabilities and add only needed ones
- Read-only root filesystem SHOULD be enabled
- Resource limits (CPU, memory) MUST be set
- Privileged mode MUST NOT be used
- Host networking MUST NOT be used unless explicitly justified

## Image Scanning Rules

- All production images MUST be scanned by Trivy before deployment
- No CRITICAL CVE allowed in production images
- HIGH CVE MUST have documented risk acceptance or fix timeline
- Base image MUST be updated within 30 days of security patch
- SBOM MUST be generated for all production images

## Kubernetes Pod Security

- Pods MUST have SecurityContext defined
- Pods MUST NOT use hostPID, hostIPC, or hostNetwork
- Service accounts MUST have minimal RBAC permissions
- Network policies MUST restrict pod-to-pod traffic
- Secrets MUST be mounted as volumes, not environment variables
