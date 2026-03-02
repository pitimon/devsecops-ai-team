---
name: dast-scan
description: Run Dynamic Application Security Testing using OWASP ZAP in a Docker container. Supports baseline, full, and API scan modes. REQUIRES explicit user approval for target URL.
argument-hint: "<target-url> [--mode baseline|full|api] [--auth-token <token>] [--api-spec <path>]"
user-invocable: true
allowed-tools: ["Read", "Bash", "AskUserQuestion"]
---

# DAST Scan (ZAP)

Run dynamic application security testing against a web application using OWASP ZAP.

**Decision Loop**: In-the-Loop (DAST target approval REQUIRED from user)

## IMPORTANT: User Approval Required

DAST scanning actively probes a web application. ALWAYS confirm the target URL with the user before scanning. NEVER scan a URL without explicit approval.

## Scan Modes

| Mode       | Script             | Timeout | Active Attacks | Use Case                    |
| ---------- | ------------------ | ------- | -------------- | --------------------------- |
| `baseline` | `zap-baseline.py`  | 120s    | No             | CI/CD pipeline gate         |
| `full`     | `zap-full-scan.py` | 1800s   | Yes            | Pre-release security review |
| `api`      | `zap-api-scan.py`  | 600s    | Yes            | OpenAPI/Swagger API testing |

> **Note**: `full` and `api` modes perform active scanning (injecting payloads). These require **In-the-Loop** approval and should only target staging/test environments.

## Scan Process

### 1. Get Target Approval

Use AskUserQuestion to confirm:

- Target URL
- Scan mode (baseline = passive + spider, full = active scanning, api = spec-driven)
- Authentication requirements (if any)
- For `api` mode: OpenAPI spec URL/path

### 2. Run ZAP

```bash
# Baseline scan (default — passive only)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool zap \
  --target "http://localhost:3000" \
  --format json

# Full scan (active — requires explicit approval)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool zap \
  --target "http://localhost:3000" \
  --mode full \
  --format json

# API scan (spec-driven — requires OpenAPI spec)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool zap \
  --target "http://localhost:3000" \
  --mode api \
  --api-spec "http://localhost:3000/openapi.json" \
  --format json

# Authenticated scan (any mode + bearer token)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool zap \
  --target "http://localhost:3000" \
  --mode full \
  --auth-token "$TOKEN" \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน DAST (Dynamic Scan Results)

### สรุป (Summary)

- Tool: OWASP ZAP
- Target: http://localhost:3000
- Mode: Baseline | Full | API
- Duration: Xs
- Alerts: X total

### ผลการตรวจพบ (Findings)

| #   | Risk   | Confidence | Alert         | URL             | CWE     |
| --- | ------ | ---------- | ------------- | --------------- | ------- |
| 1   | High   | High       | SQL Injection | /api/users?id=1 | CWE-89  |
| 2   | Medium | Medium     | CSRF          | /api/update     | CWE-352 |

### Header Security

- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Content-Security-Policy
- [ ] Strict-Transport-Security
```

### 4. NCSA Validation (Optional)

After ZAP scan, run NCSA Website Security Standard checks:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/dast-ncsa-validator.sh \
  --target "http://localhost:3000"
```

This validates HTTP security headers (NCSA 1.x), transport security (NCSA 2.x), and session management (NCSA 4.x).

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/dast-methodology.md` for deep analysis.
