# Feature Reference

> Comprehensive reference for all features provided by the `devsecops-ai-team` plugin.
> For a high-level overview and quick start, see the [README](../README.md).

---

## Table of Contents

- [16 Skills](#16-skills--คำสั่งทั้งหมด)
- [18 AI Agents](#18-ai-agents--ทีมผู้เชี่ยวชาญ)
- [Vulnerability Prioritization](#vulnerability-prioritization)
- [Role-Based Security Policy](#role-based-security-policy)
- [MCP Server Integration](#mcp-server-integration-v20)
- [Compliance Mapping](#compliance-mapping)
- [Output Formats](#output-formats)
- [Autonomous Security Controls](#autonomous-security-controls--การป้องกันอัตโนมัติ)
- [Sidecar Runner Architecture](#sidecar-runner-architecture)

---

## 16 Skills — คำสั่งทั้งหมด

### Security Scanning

| Skill             | Tool                 | ทำอะไร                                                              | Decision Loop |
| ----------------- | -------------------- | ------------------------------------------------------------------- | ------------- |
| `/sast-scan`      | Semgrep              | วิเคราะห์ source code หา SQL Injection, XSS, SSRF ฯลฯ               | Out-of-Loop   |
| `/dast-scan`      | ZAP                  | ทดสอบ web application แบบ dynamic (3 modes: baseline/full/api)      | In-the-Loop   |
| `/sca-scan`       | Grype                | สแกน dependencies หา CVE ที่ทราบแล้ว                                | Out-of-Loop   |
| `/container-scan` | Trivy                | ตรวจสอบ Docker image หาช่องโหว่ + misconfiguration                  | Out-of-Loop   |
| `/iac-scan`       | Checkov              | ตรวจ Terraform/K8s/Helm ตาม CIS Benchmarks                          | Out-of-Loop   |
| `/secret-scan`    | GitLeaks, TruffleHog | ค้นหา API keys, passwords, tokens ที่หลุดเข้า code + validity check | Out-of-Loop   |
| `/sbom-generate`  | Syft                 | สร้าง Software Bill of Materials (CycloneDX/SPDX)                   | Out-of-Loop   |
| `/slsa-assess`    | —                    | ประเมิน SLSA provenance level ตาม SLSA v1.1 specification           | On-the-Loop   |
| `/k8s-scan`       | kube-bench, Semgrep  | สแกน K8s manifests + CIS Benchmark compliance                       | Out-of-Loop   |
| `/graphql-scan`   | Semgrep, Nuclei      | ตรวจสอบ GraphQL endpoints: introspection, depth, batching           | On-the-Loop   |

### Orchestration & Reporting

| Skill                | ทำอะไร                                                           | Decision Loop |
| -------------------- | ---------------------------------------------------------------- | ------------- |
| `/devsecops-setup`   | ตรวจจับ tech stack + แนะนำ scan profile + สร้าง config           | On-the-Loop   |
| `/full-pipeline`     | รันทุก scan แบบ parallel แล้วรวมผลเป็น unified report            | On-the-Loop   |
| `/compliance-report` | Map findings ไปยัง NIST 800-53, OWASP Top 10, MITRE ATT&CK, NCSA | On-the-Loop   |
| `/incident-response` | สร้าง IR playbook ตาม NIST 800-61 เมื่อพบ CRITICAL findings      | In-the-Loop   |
| `/security-gate`     | ตัดสินใจ pass/fail ตาม severity policy ก่อน deploy               | In-the-Loop   |
| `/auto-fix`          | อ่านผล scan → สร้าง patch → ขออนุมัติ → แก้ code → re-scan       | On-the-Loop   |

> **Decision Loop** อธิบายระดับการตัดสินใจ:
>
> - **Out-of-Loop** = AI ทำเองได้ (ไม่ต้องขออนุมัติ)
> - **On-the-Loop** = AI เสนอ, มนุษย์อนุมัติ
> - **In-the-Loop** = มนุษย์ตัดสินใจ (AI ช่วยวิเคราะห์)

---

## 18 AI Agents — ทีมผู้เชี่ยวชาญ

### Orchestrators — ผู้ประสานงาน (3 agents)

| Agent                      | หน้าที่                                                                   | Routing Cue                      |
| -------------------------- | ------------------------------------------------------------------------- | -------------------------------- |
| **devsecops-lead**         | หัวหน้าทีม — วิเคราะห์ request แล้ว MUST delegate ให้ specialist          | Coordinator (ห้ามทำงานเอง)       |
| **security-stack-analyst** | ตรวจจับ tech stack (ภาษา, framework, container, IaC) เพื่อเลือกเครื่องมือ | MUST BE USED on session start    |
| **team-configurator**      | ตั้งค่า agent mappings อัตโนมัติตาม project ที่ตรวจเจอ                    | MUST BE USED on /devsecops-setup |

### Security Specialists — ผู้เชี่ยวชาญเฉพาะด้าน (7 agents)

| Agent                             | เชี่ยวชาญ                                                           | เครื่องมือ | Routing Cue                 |
| --------------------------------- | ------------------------------------------------------------------- | ---------- | --------------------------- |
| **sast-specialist**               | วิเคราะห์ source code, สร้าง custom rules, กรอง false positives     | Semgrep    | MUST BE USED when SAST      |
| **dast-specialist**               | ทดสอบ web app, authenticated scanning, API fuzzing, NCSA validation | ZAP        | MUST BE USED when DAST      |
| **sca-specialist**                | ประเมินความเสี่ยง dependency, license compliance, upgrade paths     | Grype      | MUST BE USED when SCA       |
| **container-security-specialist** | Dockerfile hardening, image optimization, runtime security          | Trivy      | MUST BE USED when container |
| **iac-security-specialist**       | CIS benchmarks, misconfig detection, policy-as-code                 | Checkov    | MUST BE USED when IaC       |
| **secret-scanner-specialist**     | Git history analysis, entropy detection, rotation guidance          | GitLeaks   | MUST BE USED when secret    |
| **sbom-analyst**                  | CycloneDX/SPDX, license compatibility, component inventory          | Syft       | MUST BE USED when SBOM      |

### Universal Experts — ผู้เชี่ยวชาญข้ามสาขา (4 agents)

| Agent                   | หน้าที่                                                           | Routing Cue                        |
| ----------------------- | ----------------------------------------------------------------- | ---------------------------------- |
| **compliance-officer**  | Map findings → NIST 800-53, OWASP Top 10, MITRE ATT&CK, NCSA, CIS | Use PROACTIVELY after scans        |
| **threat-modeler**      | วิเคราะห์ภัยคุกคามด้วย STRIDE/PASTA methodology                   | Use PROACTIVELY on arch changes    |
| **vuln-triager**        | จัดลำดับความสำคัญ: CVSS scoring, exploitability, business impact  | Use PROACTIVELY after scan results |
| **remediation-advisor** | แนะนำวิธีแก้ไขพร้อมตัวอย่างโค้ด (Django, React, Express, Spring)  | Use PROACTIVELY after triage       |

### Core Team — ทีมหลัก (4 agents)

| Agent                      | หน้าที่                                                           | Routing Cue                        |
| -------------------------- | ----------------------------------------------------------------- | ---------------------------------- |
| **security-code-reviewer** | Code review เชิง security: injection, auth bypass, data exposure  | MUST BE USED on code changes       |
| **incident-responder**     | สร้าง IR playbook ตาม NIST 800-61, กำหนด severity, ติดตามการแก้ไข | MUST BE USED when CRITICAL found   |
| **report-generator**       | สร้างรายงาน: HTML dashboard, Markdown PR comment, SARIF, JSON     | MUST BE USED for report generation |
| **pipeline-guardian**      | Security gate — ตัดสินใจ pass/fail ก่อน deploy ตาม policy         | MUST BE USED for gate enforcement  |

---

## Vulnerability Prioritization

`vuln-triager` agent ใช้ CVSS v4.0 ในการจัดลำดับความสำคัญของ findings — ไม่ใช่แค่ severity label:

### Exploitability Classification

| ระดับ           | ความหมาย                             | ตัวอย่าง                 |
| --------------- | ------------------------------------ | ------------------------ |
| **Weaponized**  | มี exploit สำเร็จรูปแพร่ในธรรมชาติ   | Log4Shell, EternalBlue   |
| **Active**      | กำลังถูกโจมตีจริง (KEV listed)       | CVE ที่อยู่ใน CISA KEV   |
| **POC**         | มี proof-of-concept เผยแพร่          | GitHub POC repositories  |
| **Theoretical** | เป็นไปได้ในทฤษฎี แต่ยังไม่มี exploit | CWE ที่ยังไม่มี CVE จริง |
| **None**        | ไม่สามารถ exploit ได้ในบริบทนี้      | Info-level findings      |

### SLA Priority Matrix

| Priority | SLA        | Severity               | Action                        |
| -------- | ---------- | ---------------------- | ----------------------------- |
| **P1**   | 24 ชั่วโมง | CRITICAL + Weaponized  | IR playbook + hotfix ทันที    |
| **P2**   | 7 วัน      | HIGH หรือ CRITICAL+POC | วางแผนแก้ไขใน sprint ปัจจุบัน |
| **P3**   | 30 วัน     | MEDIUM                 | เข้า backlog sprint ถัดไป     |
| **P4**   | Backlog    | LOW / INFO             | ติดตามเท่านั้น                |

---

## Role-Based Security Policy

`severity-policy.json` กำหนด RBAC สำหรับ security gate — แต่ละ role มี policy ต่างกัน:

| Setting              | developer    | security-lead                | release-manager                         |
| -------------------- | ------------ | ---------------------------- | --------------------------------------- |
| **Fail on**          | CRITICAL     | CRITICAL, HIGH               | CRITICAL, HIGH, MEDIUM                  |
| **Required scans**   | sast, secret | sast, sca, secret, container | sast, sca, secret, container, iac, sbom |
| **Suppress allowed** | No           | Yes                          | Yes                                     |
| **Max age (hours)**  | 48           | 24                           | 24                                      |

**Gate override** ถูกปิดโดย default (`allow_gate_override: false`) — ต้องมี security-lead role จึงจะ override ได้ นี่คือ enterprise security feature ที่ทำให้ gate เป็น genuinely blocking ไม่ใช่แค่ advisory

---

## MCP Server Integration (v2.0)

MCP server ช่วยให้ MCP-compatible clients (เช่น Claude Desktop, IDE plugins) เรียกใช้ security scanning ได้โดยตรงโดยไม่ต้องพิมพ์ skill commands:

```
Claude Code / MCP Client ---- stdio ----> mcp/server.mjs
                                              |
                                +-------------+-------------+
                                v             v             v
                          job-dispatcher  result-collector  mappings/*.json
                                |
                          Docker containers (Semgrep, Grype, Trivy, ...)
```

### MCP Tools

| MCP Tool                      | Input                         | Output                       | ทำอะไร                                      |
| ----------------------------- | ----------------------------- | ---------------------------- | ------------------------------------------- |
| `devsecops_scan`              | tool, target, rules           | job_id + normalized findings | รัน security scan (เลือก tool ได้)          |
| `devsecops_results`           | job_id, format                | formatted results            | ดึงผลลัพธ์ scan ในรูปแบบที่ต้องการ          |
| `devsecops_gate`              | results_file, policy          | PASS/FAIL + violations       | ประเมิน pass/fail ตาม severity policy       |
| `devsecops_compliance`        | findings_file, frameworks     | cross-walk matrix            | Map findings ไปยัง OWASP/NIST/MITRE/NCSA    |
| `devsecops_status`            | (none)                        | runner + images status       | ตรวจสอบ Docker + tool images ที่พร้อมใช้งาน |
| `devsecops_compare`           | baseline_file, current_file   | new/fixed/unchanged + trend  | เปรียบเทียบ 2 ผลสแกน (trend analysis)       |
| `devsecops_compliance_status` | findings_file                 | per-framework coverage       | สรุป compliance ข้าม 7 frameworks           |
| `devsecops_suggest_fix`       | cwe_id, rule_id, finding_file | remediation suggestions      | แนะนำวิธีแก้ไขจาก CWE/rule knowledge        |
| `devsecops_history`           | query, limit                  | scan history records         | ค้นหาประวัติ scan จาก SQLite DB             |
| `devsecops_pipeline`          | pipeline, target              | pipeline execution results   | รัน DAG pipeline กับหลาย tools พร้อมกัน     |

### ติดตั้ง MCP

```bash
cd mcp && npm install

# ตรวจสอบ
node --check mcp/server.mjs
bash tests/test-mcp-server.sh   # 23 tests
bash tests/test-mcp-compare.sh  # 22 compare tests
```

MCP server จะถูก load อัตโนมัติผ่าน `.mcp.json` — ไม่ต้องตั้งค่าเพิ่มเติม

---

## Compliance Mapping

Plugin นี้ map ผลลัพธ์จาก CWE ไปยัง compliance frameworks อัตโนมัติ — **488 CWE mappings** across 7 frameworks:

| Framework             | Version   | CWE Count | ใช้ทำอะไร                                             |
| --------------------- | --------- | --------- | ----------------------------------------------------- |
| **OWASP Top 10**      | 2021+2025 | 122       | Web application security categories (dual-version)    |
| **NIST SP 800-53**    | Rev. 5    | 100       | Federal security controls                             |
| **MITRE ATT&CK**      | v16       | 93        | Adversary tactics & techniques                        |
| **NCSA Web Security** | 1.0       | 62        | Thai national web security standard (สพธอ.)           |
| **SOC 2**             | TSC 2017  | ~40       | Trust Service Criteria (Security, Availability, etc.) |
| **ISO 27001**         | 2022      | ~41       | Information security management (Annex A controls)    |
| **PDPA**              | 2562      | 30        | Thai Personal Data Protection Act (พ.ร.บ. คุ้มครองฯ)  |

### Additional Frameworks Tracked

| Framework          | Version | ใช้ทำอะไร                         |
| ------------------ | ------- | --------------------------------- |
| **CIS Benchmarks** | Various | Configuration hardening baselines |
| **PCI DSS**        | 4.0.1   | Payment card industry compliance  |
| **CVSS**           | 4.0     | Vulnerability severity scoring    |
| **NIST 800-61**    | Rev. 3  | Incident response lifecycle       |

> ดูรายละเอียดทั้ง 19 frameworks ที่ติดตามใน [`frameworks.json`](../frameworks.json)

### NCSA Website Security Standard (สพธอ.)

มาตรฐานความมั่นคงปลอดภัยเว็บไซต์ โดย สำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สพธอ./NCSA):

| Category     | ตรวจสอบอะไร                                                                                 | Method                   |
| ------------ | ------------------------------------------------------------------------------------------- | ------------------------ |
| **NCSA 1.x** | HTTP Security Headers (HSTS, X-Frame-Options, CSP, Permissions-Policy, COOP, COEP)          | DAST + Header validation |
| **NCSA 2.x** | Transport Security (TLS >= 1.2, TLS 1.3 preferred, HTTPS enforcement, certificate validity) | DAST + TLS check         |
| **NCSA 3.x** | Authentication & Access Control                                                             | SAST + DAST              |
| **NCSA 4.x** | Session Management (Cookie Secure, HttpOnly, SameSite flags)                                | DAST + Cookie check      |
| **NCSA 5.x** | Input Validation (SQLi, XSS, SSRF prevention)                                               | SAST + DAST              |
| **NCSA 6.x** | Error Handling & Logging                                                                    | SAST + Custom A09 rules  |
| **NCSA 7.x** | Data Protection (encryption at rest/transit)                                                | SAST + Config check      |

---

## Output Formats

ผลลัพธ์จากทุก scan สามารถ export ได้ 8 รูปแบบ:

| Format           | ใช้ทำอะไร                                                       | ตัวอย่าง           |
| ---------------- | --------------------------------------------------------------- | ------------------ |
| **SARIF** v2.1.0 | Upload ไป GitHub Security tab                                   | `results.sarif`    |
| **JSON**         | ใช้กับ CI/CD pipeline หรือ custom tooling                       | `results.json`     |
| **Markdown**     | แปะเป็น PR comment                                              | `results.md`       |
| **HTML**         | Executive dashboard สำหรับผู้บริหาร                             | `results.html`     |
| **PDF**          | Enterprise report สำหรับ audit / mgmt                           | `results.pdf`      |
| **CSV**          | Import ลง spreadsheet / SIEM                                    | `results.csv`      |
| **VEX**          | Vulnerability Exploitability eXchange (CycloneDX VEX + OpenVEX) | `results.vex.json` |
| **Dashboard**    | Alpine.js + Chart.js self-contained HTML security dashboard     | `dashboard.html`   |

### Unified Finding Schema

ผลจากทุก tool ถูก normalize เป็นรูปแบบเดียวกัน:

```json
{
  "findings": [
    {
      "id": "FINDING-20260301-001",
      "source_tool": "semgrep",
      "scan_type": "sast",
      "severity": "HIGH",
      "title": "SQL Injection via string concatenation",
      "cwe_id": "CWE-89",
      "location": { "file": "src/api/users.py", "line_start": 45 },
      "status": "open"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}
```

### Cross-tool Deduplication

เมื่อรันหลาย tools พร้อมกัน (`/full-pipeline`) ระบบจะ deduplicate ผลอัตโนมัติ:

- **Dedup key**: `(cve_id, file, line_start)` สำหรับ file findings, `(cve_id, package)` สำหรับ dependencies
- **On merge**: เก็บ severity สูงสุด, รวม source tools

---

## Autonomous Security Controls — การป้องกันอัตโนมัติ

Plugin ติดตั้ง 3 hooks ที่ทำงานอัตโนมัติ — ไม่ต้องเรียกคำสั่ง:

| Hook                | ทำงานเมื่อ       | ทำอะไร                                            |
| ------------------- | ---------------- | ------------------------------------------------- |
| **session-start**   | เปิด Claude Code | แสดงสถานะ runner + แนะนำ scan ตาม project files   |
| **scan-on-write**   | แก้ไข/สร้างไฟล์  | สแกนหา secrets + injection patterns ทันที (500ms) |
| **pre-commit-gate** | `git commit`     | บล็อก commit ถ้ามี CRITICAL findings ที่ยังไม่แก้ |

### Real-Time Secret Detection

`scan-on-write` hook ตรวจจับ 8 secret patterns ก่อนเขียนลง disk — **บล็อกทันที (exit 2)**:

| Pattern          | ตัวอย่าง                        |
| ---------------- | ------------------------------- |
| AWS Access Key   | `AKIA...` (16 chars)            |
| API Secret Key   | `sk-...` (20+ chars)            |
| GitHub PAT/OAuth | `ghp_...`, `gho_...`, `ghs_...` |
| Slack Token      | `xoxb-...`, `xoxp-...`          |
| JWT Token        | `eyJ...` (3-part base64)        |

นอกจากนี้ยังตรวจจับ **4 injection patterns** แบบ warning (ไม่บล็อก):
`eval()`, `exec()`, `child_process.exec()`, `subprocess(shell=True)`

### Smart Project Detection

`session-start.sh` ตรวจจับไฟล์ project แล้วแนะนำ scans อัตโนมัติ:

| ตรวจเจอ                                      | แนะนำ             | ภาษา/Framework          |
| -------------------------------------------- | ----------------- | ----------------------- |
| `package.json`, `requirements.txt`, `go.mod` | `/sca-scan`       | Node.js, Python, Go     |
| `Dockerfile`, `docker-compose*.yml`          | `/container-scan` | Docker                  |
| `*.tf`, `k8s/`, `kubernetes/`                | `/iac-scan`       | Terraform, Kubernetes   |
| `.git/`                                      | `/secret-scan`    | ทุก project ที่มี Git   |
| `*.py`, `*.js`, `*.ts`, `*.java`, `*.go`     | `/sast-scan`      | Python, JS/TS, Java, Go |

---

## Sidecar Runner Architecture

เครื่องมือทั้งหมดทำงานใน Docker containers ด้วย 2 โหมด:

### Minimal Mode (แนะนำสำหรับ Development)

```bash
# ไม่ต้องรัน container ค้างไว้ — เรียกใช้ทีละตัวแบบ oneshot
bash scripts/install-runner.sh --mode minimal
```

- ใช้ `docker run --rm` — รันแล้วลบ container ทันที
- ใช้ RAM/CPU น้อย
- เหมาะสำหรับ development และ CI/CD

### Full Mode (สำหรับ Production/Heavy Use)

```bash
# รัน sidecar container ค้างไว้ — scan เร็วขึ้น
bash scripts/install-runner.sh --mode full
```

- ใช้ persistent containers + `docker exec`
- ไม่ต้อง pull image ทุกครั้ง — scan เร็วขึ้น
- เหมาะสำหรับ production environment

### Volume Security

| Volume       | Access      | วัตถุประสงค์                  |
| ------------ | ----------- | ----------------------------- |
| `/workspace` | Read-only   | Source code ของ project       |
| `/results`   | tmpfs (RAM) | ผลสแกน — ไม่เขียนลง disk      |
| `/config`    | Read-only   | Rules, policies, configs      |
| `/cache`     | Persistent  | Tool DB caches (Trivy, Grype) |
