---
name: full-pipeline
description: Run all security scans in parallel — SAST, SCA, Container, IaC, Secrets, SBOM. Produces unified report with compliance mappings and gate decision.
argument-hint: "[--policy default|strict] [--skip dast]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Grep", "Bash"]
---

# Full Pipeline Scan

Run all enabled security scans and produce a unified report.

**Decision Loop**: On-the-Loop (AI proposes results, human reviews gate decision)

## Pipeline Process

### 1. Load Configuration

Read `.devsecops.yml` or use defaults. Determine which scans to run based on detected stack.

### 2. Run Scans in Parallel

Execute enabled scans via job-dispatcher. Run these in parallel where possible:

```bash
# These can run simultaneously
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool semgrep --target /workspace &
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool gitleaks --target /workspace &
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool grype --target /workspace &
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool trivy --target /workspace &
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool checkov --target /workspace &
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh --tool syft --target /workspace &
wait
```

DAST (ZAP) is NEVER included automatically — requires explicit In-the-Loop approval.

### 3. Collect and Normalize Results

For each completed scan, run the result collector and normalize to unified format.

### 4. Aggregate Findings

Merge all normalized findings:

- Deduplicate by (tool, cwe_id, file, line)
- Sort by severity (CRITICAL first)
- Apply compliance mappings from `mappings/cwe-to-*.json`

### 5. Run Security Gate

Evaluate against active policy:

```bash
# Read policy from .devsecops.yml or --policy argument
# Compare findings against thresholds
```

### 6. Present Unified Report

```markdown
## รายงานความปลอดภัยแบบครบวงจร (Full Pipeline Security Report)

### สรุปรวม (Executive Summary)

| Tool      | Scan Type | Critical | High  | Medium | Low    | Status |
| --------- | --------- | -------- | ----- | ------ | ------ | ------ |
| Semgrep   | SAST      | 0        | 2     | 5      | 3      | Done   |
| GitLeaks  | Secret    | 1        | 0     | 0      | 0      | Done   |
| Grype     | SCA       | 0        | 1     | 3      | 8      | Done   |
| Trivy     | Container | 1        | 0     | 2      | 1      | Done   |
| Checkov   | IaC       | 0        | 2     | 1      | 0      | Done   |
| Syft      | SBOM      | —        | —     | —      | —      | Done   |
| **Total** |           | **2**    | **5** | **11** | **12** |        |

### Security Gate: FAIL

- Policy: default (developer)
- Reason: 2 CRITICAL findings (threshold: 0)
- Action required: Fix CRITICAL findings before deployment

### ผลการตรวจพบที่สำคัญ (Top Findings)

[List top 10 findings by severity]

### Compliance Coverage

| Framework    | Controls Mapped | Coverage |
| ------------ | --------------- | -------- |
| OWASP Top 10 | 7/10            | 70%      |
| NIST 800-53  | 15/20           | 75%      |
```
