---
name: container-scan
description: Scan Docker container images for vulnerabilities using Trivy. Checks OS packages, language libraries, and Dockerfile misconfigurations.
argument-hint: "[--image <name:tag>] [--target <path>]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# Container Scan (Trivy)

Scan container images and Dockerfiles for vulnerabilities using Trivy.

**Decision Loop**: Out-of-Loop (scan), On-the-Loop (policy changes)

## Scan Process

### 1. Detect Targets

- If `--image` provided, scan that image
- If Dockerfile found, scan the built image or filesystem
- Scan for `docker-compose.yml` to find all service images

### 2. Run Trivy

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool trivy \
  --target /workspace \
  --image "myapp:latest" \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน Container (Container Scan Results)

### สรุป (Summary)

- Tool: Trivy
- Image: myapp:latest
- OS Vulnerabilities: X | Library Vulnerabilities: Y

### ผลการตรวจพบ (Findings)

| #   | Severity | CVE           | Package | Installed | Fixed | CVSS |
| --- | -------- | ------------- | ------- | --------- | ----- | ---- |
| 1   | CRITICAL | CVE-2024-XXXX | libssl  | 3.1.0     | 3.1.1 | 9.1  |

### Dockerfile Best Practices

- [ ] Use specific base image tags (not :latest)
- [ ] Run as non-root user
- [ ] Multi-stage build to minimize attack surface
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/container-hardening.md` for deep analysis.
