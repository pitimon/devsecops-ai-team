# CI/CD Integration Guide

DevSecOps AI Team provides ready-to-use templates for both GitHub Actions and GitLab CI. These templates run security scans via Docker containers and produce platform-native reports.

## GitHub Actions

### Reusable Workflows

The plugin provides 4 reusable workflows (using `workflow_call`) in `.github/workflows/templates/`:

| Workflow                       | Tool     | Purpose                               |
| ------------------------------ | -------- | ------------------------------------- |
| `devsecops-sast.yml`           | Semgrep  | Static Application Security Testing   |
| `devsecops-sca.yml`            | Grype    | Software Composition Analysis         |
| `devsecops-container-scan.yml` | Trivy    | Container image vulnerability scan    |
| `devsecops-full-pipeline.yml`  | Multiple | Full pipeline with concurrency groups |

### Quick Start (GitHub)

Add to your `.github/workflows/security.yml`:

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  sast:
    uses: pitimon/devsecops-ai-team/.github/workflows/templates/devsecops-sast.yml@main
    with:
      target: ./src
      sarif-upload: true
    permissions:
      contents: read
      security-events: write

  sca:
    uses: pitimon/devsecops-ai-team/.github/workflows/templates/devsecops-sca.yml@main
    with:
      sarif-upload: true
    permissions:
      contents: read
      security-events: write

  container:
    uses: pitimon/devsecops-ai-team/.github/workflows/templates/devsecops-container-scan.yml@main
    with:
      image: myapp:latest
      sarif-upload: true
    permissions:
      contents: read
      security-events: write
```

### Full Pipeline (GitHub)

For a comprehensive scan with concurrency-aware scheduling:

```yaml
jobs:
  security:
    uses: pitimon/devsecops-ai-team/.github/workflows/templates/devsecops-full-pipeline.yml@main
    with:
      tools: "semgrep,grype,gitleaks,trivy"
      target: .
      format: sarif
      sarif-upload: true
    permissions:
      contents: read
      security-events: write
```

### SARIF Integration

All GitHub workflows support uploading SARIF results to the Security tab via `github/codeql-action/upload-sarif@v3`. Set `sarif-upload: true` (default) to enable.

Results appear in:

- **Security tab** > Code scanning alerts
- **Pull request** checks

---

## GitLab CI

### Templates

Templates are in `ci-templates/`:

| Template                       | Tool    | GitLab Report Type    |
| ------------------------------ | ------- | --------------------- |
| `sast.gitlab-ci.yml`           | Semgrep | `sast`                |
| `sca.gitlab-ci.yml`            | Grype   | `dependency_scanning` |
| `container-scan.gitlab-ci.yml` | Trivy   | `container_scanning`  |
| `devsecops.gitlab-ci.yml`      | All     | Includes all above    |

### Quick Start (GitLab)

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: "https://raw.githubusercontent.com/pitimon/devsecops-ai-team/main/ci-templates/devsecops.gitlab-ci.yml"

variables:
  DEVSECOPS_TARGET: "."
  DEVSECOPS_FAIL_ON_FINDINGS: "false"
```

Or include individual templates:

```yaml
include:
  - remote: "https://raw.githubusercontent.com/pitimon/devsecops-ai-team/main/ci-templates/sast.gitlab-ci.yml"

variables:
  SEMGREP_RULES: "auto"
```

### GitLab Report Integration

Templates produce GitLab-native report artifacts:

- **SAST**: `gl-sast-report.json` (v15.0.7 schema)
- **Dependency Scanning**: `gl-dependency-scanning-report.json`
- **Container Scanning**: `gl-container-scanning-report.json`

These reports integrate with:

- **Merge Request** > Security widget
- **Security Dashboard** (Ultimate tier)

### Converter Script

For custom normalized JSON output, use the converter:

```bash
bash ci-templates/converters/gitlab-sast-converter.sh \
  --input normalized-results.json \
  --output gl-sast-report.json
```

---

## Pipeline Runner (CI-Agnostic)

For platform-independent usage, use `runner/run-pipeline.sh` directly:

```bash
bash runner/run-pipeline.sh \
  --tools "semgrep,grype,gitleaks" \
  --target /path/to/project \
  --format sarif
```

### Concurrency Groups

The pipeline runner classifies tools by resource requirements (`runner/concurrency-groups.json`):

| Group  | Tools                                   | Max Parallel | Memory |
| ------ | --------------------------------------- | ------------ | ------ |
| Heavy  | ZAP                                     | 1            | 2GB    |
| Medium | Trivy                                   | 2            | 1GB    |
| Light  | Semgrep, GitLeaks, Grype, Checkov, Syft | 4            | 512MB  |

### CI Adapter

`runner/ci-adapter.sh` provides platform-agnostic functions:

| Function             | GitHub Actions        | GitLab CI        | Local     |
| -------------------- | --------------------- | ---------------- | --------- |
| `ci_detect_platform` | `"github"`            | `"gitlab"`       | `"local"` |
| `ci_set_output`      | `GITHUB_OUTPUT`       | `ci_outputs.env` | stdout    |
| `ci_upload_artifact` | `::notice::`          | file path        | stdout    |
| `ci_fail_step`       | `::error::`           | stderr           | `[FAIL]`  |
| `ci_group_start/end` | `::group::`           | section markers  | `===`     |
| `ci_summary`         | `GITHUB_STEP_SUMMARY` | file             | stdout    |

---

## Prerequisites

- Docker (for running security tool containers)
- Python 3.8+ (for report conversion)
- Node.js 18+ (for MCP server, if used)

## Security Considerations

- All scans run in Docker containers with read-only workspace mounts
- No secrets are transmitted to external services
- SARIF results contain file paths relative to workspace root
- ZAP scans use `resource_group` in GitLab to prevent concurrent DAST
