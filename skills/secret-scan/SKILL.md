---
name: secret-scan
description: Scan for leaked secrets and credentials using GitLeaks and/or TruffleHog in Docker containers. Detects API keys, passwords, tokens, and other sensitive data in source code and git history.
argument-hint: "[--target <path>] [--no-git] [--tool gitleaks|trufflehog|both]"
user-invocable: true
allowed-tools: ["Read", "Bash"]
---

# Secret Scan (GitLeaks + TruffleHog)

Scan the project for leaked secrets and credentials using GitLeaks and/or TruffleHog.

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

### 2b. Run TruffleHog (เมื่อเลือก `--tool trufflehog` หรือ `--tool both`)

TruffleHog รองรับ 3 โหมดการสแกน (scan modes):

| Mode         | คำอธิบาย (Description)                  | ใช้เมื่อ (Use When)                             |
| ------------ | --------------------------------------- | ----------------------------------------------- |
| `git`        | สแกนประวัติ git repository (default)    | ต้องการตรวจ secrets ใน commit history           |
| `filesystem` | สแกน filesystem โดยไม่ใช้ git history   | โปรเจกต์ไม่มี git หรือต้องการสแกนไฟล์อย่างเดียว |
| `s3`         | สแกน S3 bucket (ต้องมี AWS credentials) | ตรวจ secrets ใน cloud storage                   |

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool trufflehog \
  --target /workspace \
  --mode git \
  --format json
```

สำหรับ `filesystem` mode:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool trufflehog \
  --target /workspace \
  --mode filesystem \
  --format json
```

สำหรับ `s3` mode (ต้องตั้ง `AWS_ACCESS_KEY_ID` และ `AWS_SECRET_ACCESS_KEY`):

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool trufflehog \
  --target s3://bucket-name \
  --mode s3 \
  --format json
```

### 2c. Deduplication (เมื่อใช้ `--tool both`)

เมื่อรันทั้ง GitLeaks และ TruffleHog พร้อมกัน ผลลัพธ์อาจซ้ำกัน ใช้ `dedup-findings.sh` เพื่อรวมผลลัพธ์และตัดรายการซ้ำออก:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/dedup-findings.sh \
  --inputs gitleaks-results.json trufflehog-results.json \
  --output merged-secrets.json
```

Script จะจับคู่ findings ตาม file path + line number + secret type แล้วรวมเป็นรายการเดียว โดยเก็บข้อมูลว่า tool ใดตรวจพบ

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

- Tool: GitLeaks / TruffleHog / Both
- Target: <path>
- Findings: X total (Y critical, Z high)
- Scan time: <duration>

### ผลการตรวจพบ (Findings)

| #   | Severity | Type           | File            | Line | Source     | Description       |
| --- | -------- | -------------- | --------------- | ---- | ---------- | ----------------- |
| 1   | CRITICAL | AWS Access Key | src/config.ts   | 12   | GitLeaks   | AKIA... detected  |
| 2   | HIGH     | GitHub Token   | .env.production | 3    | TruffleHog | ghp\_... detected |
| 3   | HIGH     | Slack Webhook  | deploy.sh       | 45   | Both       | xoxb-... detected |

### คำแนะนำ (Recommendations)

1. Rotate compromised credentials immediately
2. Add entries to `.gitleaksignore` for false positives
3. Use environment variables or vault for secrets
4. Run `git filter-branch` or BFG to remove from history
```

### 5. Audit Trail

Append scan result to `.devsecops/audit.jsonl` if it exists.
