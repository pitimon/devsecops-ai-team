# Installation Guide

## Standard Installation

```bash
claude plugin add pitimon/devsecops-ai-team
```

## Manual Installation

```bash
git clone https://github.com/pitimon/devsecops-ai-team.git
cd devsecops-ai-team
claude plugin add .
```

## Air-Gapped Installation

1. Download the release tarball from GitHub Releases
2. Extract to a local directory
3. Run `claude plugin add /path/to/devsecops-ai-team`

## Prerequisites

### Required

- **Docker Engine** 20.10+ — `docker --version`
- **Docker Compose** v2+ — `docker compose version`
- **Disk space** 2GB+ free for tool container images

### Optional

- **Claude Governance plugin** — for extended fitness functions
- **Git** — for secret scanning git history

## Setting Up the Runner

### Minimal Mode (recommended for dev)

Uses `docker run --rm` for each scan — no persistent containers:

```bash
bash runner/install-runner.sh --mode minimal
```

### Full Mode (recommended for CI/CD)

Persistent sidecar with tool containers running as Docker profiles:

```bash
bash runner/install-runner.sh --mode full
docker compose -f runner/docker-compose.yml --profile sast --profile secret up -d
```

### Verify Installation

```bash
bash scripts/check-prerequisites.sh
```

## Uninstallation

```bash
claude plugin remove devsecops-ai-team
docker compose -f runner/docker-compose.yml down -v
docker rmi returntocorp/semgrep anchore/grype aquasec/trivy \
  bridgecrew/checkov zricethezav/gitleaks ghcr.io/zaproxy/zaproxy anchore/syft
```

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.
