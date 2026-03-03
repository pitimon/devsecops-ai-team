---
name: dast-scan
description: Run Dynamic Application Security Testing using OWASP ZAP or Nuclei in Docker containers. Supports multiple scan modes. REQUIRES explicit user approval for target URL.
argument-hint: "<target-url> [--tool zap|nuclei] [--mode baseline|full|api|cve|custom] [--auth-token <token>] [--api-spec <path>]"
user-invocable: true
allowed-tools: ["Read", "Bash", "AskUserQuestion"]
---

# DAST Scan (ZAP / Nuclei)

Run dynamic application security testing against a web application using OWASP ZAP or Nuclei.

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

### Nuclei Scan Modes

| Mode     | Templates     | Timeout | Use Case                         |
| -------- | ------------- | ------- | -------------------------------- |
| `cve`    | CVE/NVD only  | 120s    | Known vulnerability detection    |
| `full`   | All templates | 600s    | Comprehensive vulnerability scan |
| `custom` | User-provided | 300s    | Targeted template scanning       |

**Nuclei** complements ZAP by focusing on **known vulnerability detection** using 11,000+ community templates. While ZAP performs active scanning to discover new issues, Nuclei checks for known CVEs and misconfigurations.

Usage:

- `--tool nuclei --mode cve` — Quick known CVE scan (~2 min)
- `--tool nuclei --mode full` — All templates (~10 min)
- `--tool nuclei --mode custom --templates /path/to/templates` — Custom templates

## Scan Process

### 1. Get Target Approval

Use AskUserQuestion to confirm:

- Target URL
- Tool choice (zap = active/passive scanning, nuclei = known CVE detection; default: zap)
- Scan mode (ZAP: baseline/full/api; Nuclei: cve/full/custom)
- Authentication requirements (if any)
- For ZAP `api` mode: OpenAPI spec URL/path
- For Nuclei `custom` mode: template path

### 2. Run Scan

#### ZAP Examples

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

#### Nuclei Examples

```bash
# CVE scan (known vulnerabilities only — quick)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool nuclei \
  --target "http://localhost:3000" \
  --mode cve \
  --format json

# Full scan (all 11,000+ templates)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool nuclei \
  --target "http://localhost:3000" \
  --mode full \
  --format json

# Custom templates scan
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool nuclei \
  --target "http://localhost:3000" \
  --mode custom \
  --templates "/path/to/templates" \
  --format json

# Authenticated scan (bearer token)
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool nuclei \
  --target "http://localhost:3000" \
  --mode cve \
  --auth-token "$TOKEN" \
  --format json
```

### 3. Present Findings

```markdown
## ผลการสแกน DAST (Dynamic Scan Results)

### สรุป (Summary)

- Tool: OWASP ZAP | Nuclei
- Target: http://localhost:3000
- Mode: Baseline | Full | API | CVE | Custom
- Duration: Xs
- Alerts: X total

### ผลการตรวจพบ (Findings)

| #   | Risk   | Confidence | Alert         | URL             | CWE     | Source |
| --- | ------ | ---------- | ------------- | --------------- | ------- | ------ |
| 1   | High   | High       | SQL Injection | /api/users?id=1 | CWE-89  | zap    |
| 2   | Medium | Medium     | CSRF          | /api/update     | CWE-352 | zap    |
| 3   | High   | High       | CVE-2024-XXXX | /api/login      | CWE-287 | nuclei |

### Header Security (ZAP)

- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Content-Security-Policy
- [ ] Strict-Transport-Security
```

> **Note**: ผลลัพธ์จาก Nuclei จะถูก normalize เป็นรูปแบบ JSON เดียวกับ ZAP โดยมี `source_tool: "nuclei"` เพื่อระบุแหล่งที่มาของ finding

### 4. NCSA Validation (Optional)

After ZAP or Nuclei scan, run NCSA Website Security Standard checks:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/dast-ncsa-validator.sh \
  --target "http://localhost:3000"
```

This validates HTTP security headers (NCSA 1.x), transport security (NCSA 2.x), and session management (NCSA 4.x).

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/dast-methodology.md` for deep analysis.
