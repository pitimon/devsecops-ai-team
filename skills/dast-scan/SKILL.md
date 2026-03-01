---
name: dast-scan
description: Run Dynamic Application Security Testing using OWASP ZAP in a Docker container. Tests running web applications for vulnerabilities. REQUIRES explicit user approval for target URL.
argument-hint: "<target-url> [--mode baseline|full]"
user-invocable: true
allowed-tools: ["Read", "Bash", "AskUserQuestion"]
---

# DAST Scan (ZAP)

Run dynamic application security testing against a web application using OWASP ZAP.

**Decision Loop**: In-the-Loop (DAST target approval REQUIRED from user)

## IMPORTANT: User Approval Required

DAST scanning actively probes a web application. ALWAYS confirm the target URL with the user before scanning. NEVER scan a URL without explicit approval.

## Scan Process

### 1. Get Target Approval

Use AskUserQuestion to confirm:

- Target URL
- Scan mode (baseline = passive + spider, full = active scanning)
- Authentication requirements (if any)

### 2. Run ZAP

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool zap \
  --target "http://localhost:3000" \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน DAST (Dynamic Scan Results)

### สรุป (Summary)

- Tool: OWASP ZAP
- Target: http://localhost:3000
- Mode: Baseline
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

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/dast-methodology.md` for deep analysis.
