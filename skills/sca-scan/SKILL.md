---
name: sca-scan
description: Scan project dependencies for known vulnerabilities using Grype in a Docker container. Identifies CVEs in packages, libraries, and transitive dependencies.
argument-hint: "[--target <path>]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# SCA Scan (Grype)

Scan dependencies for known vulnerabilities using Grype.

**Decision Loop**: Out-of-Loop (AI autonomous — safe read-only scan)

## Scan Process

### 1. Identify Dependency Files

Search for: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `build.gradle`

### 2. Run Grype

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool grype \
  --target /workspace \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน SCA (Dependency Scan Results)

### สรุป (Summary)

- Tool: Grype
- Dependencies scanned: X
- Vulnerabilities: Y total

### ผลการตรวจพบ (Findings)

| #   | Severity | CVE           | Package  | Version | Fixed In | CVSS |
| --- | -------- | ------------- | -------- | ------- | -------- | ---- |
| 1   | CRITICAL | CVE-2024-XXXX | lib-name | 1.2.3   | 1.2.4    | 9.8  |

### คำแนะนำ (Recommendations)

1. Update packages with known fixes
2. Run `/sbom-generate` for full dependency inventory
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/sca-supply-chain.md` for deep analysis.
