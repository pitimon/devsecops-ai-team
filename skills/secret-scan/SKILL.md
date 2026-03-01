---
name: secret-scan
description: Scan for leaked secrets and credentials using GitLeaks in a Docker container. Detects API keys, passwords, tokens, and other sensitive data in source code and git history.
argument-hint: "[--target <path>] [--no-git]"
user-invocable: true
allowed-tools: ["Read", "Bash"]
---

# Secret Scan (GitLeaks)

Scan the project for leaked secrets and credentials using GitLeaks.

**Decision Loop**: Out-of-Loop (AI autonomous — safe read-only scan)

## Scan Process

### 1. Verify Prerequisites

Check that the runner is available:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/check-prerequisites.sh --tool gitleaks
```

### 2. Run GitLeaks

Execute the scan via the job dispatcher:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool gitleaks \
  --target /workspace \
  --format json
```

If `--no-git` argument provided, add `--no-git` flag to scan directory only (no git history).

### 3. Collect Results

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/result-collector.sh \
  --job-id <JOB_ID> \
  --format json
```

### 4. Present Findings

Read the normalized JSON results and present:

```markdown
## ผลการสแกน Secret (Secret Scan Results)

### สรุป (Summary)

- Tool: GitLeaks
- Target: <path>
- Findings: X total (Y critical, Z high)
- Scan time: <duration>

### ผลการตรวจพบ (Findings)

| #   | Severity | Type           | File            | Line | Description       |
| --- | -------- | -------------- | --------------- | ---- | ----------------- |
| 1   | CRITICAL | AWS Access Key | src/config.ts   | 12   | AKIA... detected  |
| 2   | HIGH     | GitHub Token   | .env.production | 3    | ghp\_... detected |

### คำแนะนำ (Recommendations)

1. Rotate compromised credentials immediately
2. Add entries to `.gitleaksignore` for false positives
3. Use environment variables or vault for secrets
4. Run `git filter-branch` or BFG to remove from history
```

### 5. Audit Trail

Append scan result to `.devsecops/audit.jsonl` if it exists.
