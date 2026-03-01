---
name: iac-scan
description: Scan Infrastructure as Code files for security misconfigurations using Checkov. Supports Terraform, Kubernetes, Helm, CloudFormation, and more.
argument-hint: "[--target <path>] [--framework terraform|kubernetes|helm]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# IaC Scan (Checkov)

Scan Infrastructure as Code for security misconfigurations using Checkov.

**Decision Loop**: Out-of-Loop (AI autonomous — safe read-only scan)

## Scan Process

### 1. Detect IaC Files

Search for: `*.tf`, `*.tfvars`, `*.yml`/`*.yaml` in `k8s/`, `helm/`, `kustomize/`, `ansible/`, `cloudformation/`, `*.json` (CloudFormation)

### 2. Run Checkov

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool checkov \
  --target /workspace \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน IaC (IaC Scan Results)

### สรุป (Summary)

- Tool: Checkov
- Framework: Terraform
- Checks: Passed X / Failed Y / Skipped Z

### ผลการตรวจพบ (Findings)

| #   | Severity | Check ID    | Resource           | Description               |
| --- | -------- | ----------- | ------------------ | ------------------------- |
| 1   | HIGH     | CKV_AWS_145 | aws_s3_bucket.data | S3 encryption not enabled |

### CIS Benchmark Mapping

- CIS AWS 2.1.1: S3 bucket encryption
- CIS AWS 2.1.2: S3 bucket logging
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/iac-security-patterns.md` for deep analysis.
