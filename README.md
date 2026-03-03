<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=for-the-badge&logo=anthropic" alt="Claude Code Plugin">
  <img src="https://img.shields.io/badge/Version-2.6.0-brightgreen?style=for-the-badge" alt="v2.6.0">
  <img src="https://img.shields.io/badge/Tests-770%2B-success?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Agents-18-blue?style=flat-square" alt="18 Agents">
  <img src="https://img.shields.io/badge/Skills-13-green?style=flat-square" alt="13 Skills">
  <img src="https://img.shields.io/badge/Tools-7-orange?style=flat-square" alt="7 Tools">
  <img src="https://img.shields.io/badge/MCP-8_Tools-purple?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/OWASP_Top_10-10%2F10-critical?style=flat-square" alt="OWASP 10/10">
  <img src="https://img.shields.io/badge/CWE_Mappings-360-informational?style=flat-square" alt="360 CWEs">
  <img src="https://img.shields.io/badge/Frameworks-4-blueviolet?style=flat-square" alt="4 Compliance Frameworks">
  <img src="https://img.shields.io/badge/QA_Rounds-8_(54%2F54)-success?style=flat-square" alt="QA 54/54">
</p>

<h1 align="center">DevSecOps AI Team</h1>

<p align="center">
  <strong>Enterprise DevSecOps Plugin Skill Pack for Claude Code</strong><br>
  Multi-Agent AI Security Team — 18 agents ทำงานร่วมกันเพื่อรักษาความปลอดภัยของซอฟต์แวร์ตลอด SDLC
</p>

<p align="center">
  <a href="https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml"><img src="https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml/badge.svg" alt="Validation"></a>
  <a href="https://github.com/pitimon/devsecops-ai-team/actions/workflows/security-scan.yml"><img src="https://github.com/pitimon/devsecops-ai-team/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan"></a>
  <a href="https://github.com/pitimon/devsecops-ai-team/releases"><img src="https://img.shields.io/github/v/release/pitimon/devsecops-ai-team" alt="Release"></a>
  <a href="https://github.com/pitimon/devsecops-ai-team/wiki"><img src="https://img.shields.io/badge/Wiki-Documentation-blue" alt="Wiki"></a>
</p>

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Key Highlights](#key-highlights)
- [OWASP Top 10 Coverage](#owasp-top-10-coverage)
- [What's New (v2.6.0)](#whats-new)
- [Use Cases](#use-cases)
- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [13 Skills](#13-skills--คำสั่งทั้งหมด)
- [18 AI Agents](#18-ai-agents--ทีมผู้เชี่ยวชาญ)
- [Vulnerability Prioritization](#vulnerability-prioritization)
- [Role-Based Security Policy](#role-based-security-policy)
- [MCP Server Integration](#mcp-server-integration-v20)
- [Compliance Mapping](#compliance-mapping)
- [Output Formats](#output-formats)
- [Autonomous Security Controls](#autonomous-security-controls--การป้องกันอัตโนมัติ)
- [Sidecar Runner Architecture](#sidecar-runner-architecture)
- [Security & Privacy](#security--privacy)
- [Testing & Quality](#testing--quality)
- [ROI & Business Value](#roi--business-value)
- [Comparison with Alternatives](#comparison-with-alternatives)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Executive Summary

| Metric                    | Value                                                                                          |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| **Project Type**          | Claude Code Plugin Skill Pack (pure markdown/JSON/shell)                                       |
| **AI Agents**             | 18 agents across 4 groups (Orchestrators, Specialists, Experts, Core Team)                     |
| **Skills (Commands)**     | 13 slash commands (/sast-scan, /dast-scan, /full-pipeline, ...)                                |
| **Security Tools**        | 7 open-source tools in Docker containers (Semgrep, ZAP, Grype, Trivy, Checkov, GitLeaks, Syft) |
| **MCP Tools**             | 8 composable tools for programmatic integration                                                |
| **Compliance Frameworks** | 4 frameworks — OWASP Top 10, NIST 800-53, MITRE ATT&CK, NCSA Web Security                      |
| **CWE Mappings**          | 360 total (OWASP 105 + NIST 100 + MITRE 93 + NCSA 62)                                          |
| **OWASP Top 10 Coverage** | 10/10 categories (100%)                                                                        |
| **Tests**                 | 700+ checks across 19 suites — all passing                                                     |
| **QA Rounds**             | 8 rounds, 54/54 latest (cumulative 950+ checks)                                                |
| **ROI**                   | 10,222% — 3,100 THB actual vs 320,000 THB equivalent (133x speed)                              |
| **Version**               | 2.5.0 (2026-03-03)                                                                             |

---

## Key Highlights

- **18 AI Agents, 1 Team** — Orchestrators delegate งานให้ Specialists, Experts วิเคราะห์ผลข้ามเครื่องมือ, Core Team enforce quality gates — ทั้งหมดทำงานร่วมกันผ่าน mandatory routing table
- **7 Security Tools, 1 Command** — `/full-pipeline` รันทุกเครื่องมือแบบ parallel, deduplicate ผลข้าม tools, สร้าง unified report ในคำสั่งเดียว
- **Real-Time Protection** — บล็อก commits ที่มี CRITICAL findings, ตรวจจับ secrets (AWS keys, GitHub tokens, JWT) ก่อนเขียนลง disk — ทำงานใน 500ms
- **CVSS v4.0 Prioritization** — วิเคราะห์ business impact, exploitability (Weaponized → None), กำหนด SLA tiers (P1: 24 ชม. → P4: backlog)
- **360 CWE Compliance Mappings** — Auto-map ผลสแกนไปยัง OWASP Top 10 (105), NIST 800-53 (100), MITRE ATT&CK (93), NCSA (62)
- **NCSA Web Security Standard** — รองรับมาตรฐานความมั่นคงปลอดภัยเว็บไซต์ สพธอ. (HTTP Headers, TLS, Session Management)
- **MCP Server** — 8 composable tools สำหรับ programmatic integration กับ MCP-compatible clients (compare, compliance_status, suggest_fix)
- **Custom OWASP Rules** — 33 custom Semgrep rules for A01 (access control), A03 (injection), A09 (logging), A10 (SSRF)
- **6 Output Formats** — SARIF, JSON, Markdown, HTML, PDF, CSV

---

## OWASP Top 10 Coverage

ครอบคลุม OWASP Top 10 (2021) ทั้ง 10 categories ด้วย tools และ rules ที่เหมาะสม:

| #   | Category                  | Tools                         | Detection Method                                                                                  |
| --- | ------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------- |
| A01 | Broken Access Control     | **Custom Semgrep rules**, ZAP | 8 rules: missing authz, IDOR, path traversal, CORS, privilege escalation (CWE-862/639/22/942/269) |
| A02 | Cryptographic Failures    | Semgrep, GitLeaks             | Weak crypto patterns + exposed secrets                                                            |
| A03 | Injection                 | **Custom Semgrep rules**, ZAP | 11 rules: SQLi, command injection, XSS, LDAP injection, template injection (CWE-89/78/79/90/1336) |
| A04 | Insecure Design           | Checkov, Semgrep              | IaC misconfig + design pattern rules                                                              |
| A05 | Security Misconfiguration | Trivy, Checkov, ZAP           | Container/IaC/header misconfiguration                                                             |
| A06 | Vulnerable Components     | Grype, Syft                   | CVE matching + SBOM dependency analysis                                                           |
| A07 | Auth Failures             | Semgrep, ZAP                  | Auth bypass patterns + session testing                                                            |
| A08 | Data Integrity Failures   | Semgrep, Trivy                | Deserialization + unsigned image detection                                                        |
| A09 | Logging Failures          | **Custom Semgrep rules**      | 7 rules: missing auth logs, silent catch, PII in logs, log injection, rate-limit logging          |
| A10 | SSRF                      | **Custom Semgrep rules**, ZAP | 7 rules: cloud metadata, DNS rebinding, private IP detection (CWE-918)                            |

---

## What's New

> ดู [CHANGELOG.md](CHANGELOG.md) สำหรับรายละเอียดทั้งหมด (v1.0.0 → v2.6.0)

### v2.6.0 — Custom OWASP Rules (A01/A03/A10), 3 New MCP Tools, PDF/CSV (Latest)

- **A01/A03/A10 Custom Semgrep Rules** — 26 new rules ตรวจจับ access control, injection, SSRF anti-patterns
- **3 New MCP Tools** — `devsecops_compare` (trend diff), `devsecops_compliance_status` (aggregate compliance), `devsecops_suggest_fix` (remediation)
- **PDF/CSV Formatters** — enterprise PDF export (pandoc), spreadsheet CSV export
- **700+ tests** across 19 suites (was 587)

<details>
<summary>Previous versions</summary>

### v2.4.0 — DAST Infrastructure, A09 Detection & NCSA Validation

- **A09 Custom Semgrep Rules** — 7 rules (5 categories) ตรวจจับ OWASP A09:2021 anti-patterns (CWE-117/390/532/778) ใน Python + JS/TS
- **ZAP Multi-Mode Dispatcher** — 3 modes: `baseline` (passive, 120s), `full` (active, 1800s), `api` (OpenAPI, 600s) + authenticated scanning
- **NCSA Website Security Validator** — ตรวจ HTTP Security Headers (1.x), Transport Security (2.x), Session Management (4.x) ตามมาตรฐาน สพธอ.
- **DAST Live Testing** — conditional test suite สำหรับ live ZAP scan (ต้องตั้ง `DAST_TARGET`)
- **587 tests** across 15 suites (was 461)

### v2.3.0 — NCSA Compliance Mapping

- **NCSA Website Security Standard v1.0** — 62 CWE mappings across 7 categories (มาตรฐานความมั่นคงปลอดภัยเว็บไซต์ สพธอ.)
- **MCP `ncsa` framework support** — `devsecops_compliance` รองรับ NCSA framework
- **Auto-Fix Skill** — `/auto-fix` อ่านผล scan → สร้าง patch → ขออนุมัติ → แก้ code → re-scan

### v2.2.0 — Framework Remediation + Test Hardening

- **Framework-Aware Remediation** — 4 reference files (Django, React/Next.js, Express/Node, Spring) + auto-detection routing
- **Syft Normalizer** — SBOM component inventory from CycloneDX-JSON
- **65 new functional tests** — hooks (27), dedup (15), MCP handlers (23)

### v2.1.0 — Security Fixes + Coverage Gaps

- **Security Fixes** — Python3 dependency guard, MCP command injection fix (execFile), ZAP OOM memory limits
- **RBAC Gate** — role-based policy (developer/security-lead/release-manager)
- **Zod Validation** — MCP inputs validated ด้วย Zod schemas ทั้ง 5 tools

### v2.0.0 — MCP Server + Agent Orchestration

- **MCP Server** — 5 MCP tools สำหรับ programmatic integration
- **Agent Orchestration** — mandatory routing table + delegation chain
- **Cross-tool Dedup** — deduplicate ด้วย (cve_id, file, line)
- **Smart Detection** — session-start.sh ตรวจจับ tech stack อัตโนมัติ

### v1.0.0 — Initial Release

- 18 AI agents, 12 skills, 7 Docker security tools
- SARIF/JSON/Markdown output formatters
- CWE → OWASP/NIST/MITRE compliance mappings

</details>

---

## Use Cases

### 1. Development Team — Daily Security Scanning

```
Developer เปิด Claude Code ในโปรเจค → session-start ตรวจจับ tech stack อัตโนมัติ
→ แก้ไขโค้ด → scan-on-write ตรวจจับ secrets ทันที (500ms)
→ พิมพ์ /sast-scan → พบ SQL Injection → /auto-fix สร้าง patch + re-scan
→ git commit → pre-commit-gate บล็อกถ้ามี CRITICAL ค้างอยู่
```

### 2. Security Team — Pre-Release Assessment

```
Security Lead เรียก /full-pipeline → รัน 7 tools parallel
→ vuln-triager จัดลำดับตาม CVSS v4.0 + exploitability
→ compliance-officer map ไปยัง OWASP/NIST/MITRE/NCSA
→ /security-gate ตัดสินใจ PASS/FAIL ตาม role-based policy
→ report-generator สร้าง HTML dashboard + SARIF สำหรับ GitHub Security tab
```

### 3. Compliance Officer — Audit & Reporting

```
เรียก /compliance-report --framework all
→ ได้ cross-walk matrix: CWE → OWASP Top 10 + NIST 800-53 + MITRE ATT&CK + NCSA
→ export เป็น SARIF upload ไป GitHub / JSON ส่งเข้า SIEM
→ /incident-response สร้าง IR playbook ตาม NIST 800-61 เมื่อพบ CRITICAL
```

### 4. CI/CD Pipeline — Automated Gate

```yaml
# GitHub Actions example
- name: Security Gate
  run: |
    # MCP tool: scan → gate → report
    devsecops_scan --tool semgrep --target .
    devsecops_scan --tool grype --target .
    devsecops_gate --policy security-lead
```

### 5. DAST — Web Application Testing

```
Security Engineer ตั้งค่า DAST_TARGET → เลือก scan mode:
→ baseline (CI/CD, passive only, 120s)
→ full (pre-release, active attacks, 1800s)
→ api (OpenAPI spec-driven, 600s)
→ NCSA validator ตรวจ HTTP headers + TLS + session cookies
→ ผลรวมกับ SAST findings ใน unified report
```

---

## Why DevSecOps AI Team?

> **ปัญหา**: ทีม Dev ต้องใช้เครื่องมือ security หลายตัว แต่ละตัวมี CLI, output format, และวิธีตีความผลต่างกัน ทำให้เสียเวลาในการเรียนรู้และ integrate เข้ากับ workflow

> **วิธีแก้**: Plugin นี้รวม 7 เครื่องมือ security ชั้นนำ (ทั้งหมด Open Source) ให้ทำงานผ่าน Claude Code ด้วยภาษาธรรมชาติ — พิมพ์ `/sast-scan` แทนการจำ CLI ยาวๆ ได้ผลลัพธ์ที่เข้าใจง่ายพร้อมคำแนะนำการแก้ไข

| ก่อนใช้ Plugin                                          | หลังใช้ Plugin                               |
| ------------------------------------------------------- | -------------------------------------------- |
| `semgrep scan --config p/owasp-top-ten --sarif ...`     | `/sast-scan`                                 |
| `gitleaks detect --source . --report-format json ...`   | `/secret-scan`                               |
| `trivy image --severity HIGH,CRITICAL myapp:latest ...` | `/container-scan`                            |
| ต้องรัน 7 tools แยกกัน แล้ว merge ผลเอง                 | `/full-pipeline` (รันทั้ง 7 tools พร้อมกัน)  |
| เปิด spreadsheet map CWE → NIST เอง                     | `/compliance-report --framework all`         |
| ถกกันว่า deploy ได้ไหม                                  | `/security-gate` (ตัดสินอัตโนมัติตาม policy) |

---

## Quick Start

### 1. Install Plugin

```bash
# Step 1: ลงทะเบียน marketplace
claude plugin marketplace add pitimon/devsecops-ai-team

# Step 2: ติดตั้ง plugin
claude plugin install devsecops-ai-team@pitimon-devsecops
```

> **ทางเลือก**: ติดตั้งจาก local directory
>
> ```bash
> git clone https://github.com/pitimon/devsecops-ai-team.git
> claude plugin marketplace add ./devsecops-ai-team
> claude plugin install devsecops-ai-team@pitimon-devsecops
> ```

### 2. ตรวจสอบ Prerequisites

```bash
# ต้องมี Docker Engine 20.10+ และ Docker Compose v2+
bash scripts/check-prerequisites.sh
```

### 3. (Optional) ติดตั้ง MCP Server

```bash
cd mcp && npm install
```

MCP server จะถูก load อัตโนมัติผ่าน `.mcp.json` เมื่อเปิด Claude Code session

### 4. เริ่มใช้งาน

```bash
# เปิด Claude Code แล้วพิมพ์
/devsecops-setup          # ตรวจจับ tech stack + ตั้งค่าอัตโนมัติ
/secret-scan              # สแกนหา secrets ที่หลุดเข้า codebase
/sast-scan                # สแกนช่องโหว่ในโค้ด (SQL Injection, XSS, ...)
/full-pipeline            # รันทุก scan แบบ parallel แล้วสรุปผล
```

> **หมายเหตุ**: ทุกเครื่องมือทำงานใน Docker containers บนเครื่อง local — ไม่ส่ง source code ไปที่ไหน

---

## Architecture Overview

```
      You (Claude Code)
           |
           +--- Skill commands (/sast-scan, /full-pipeline, ...)
           |
           +--- MCP tools (devsecops_scan, devsecops_gate, ...)   <-- v2.0
           |
           v
+------------------------------------------------------------------+
|                      18 AI Agents                                 |
|                                                                   |
|  +---------------+  +---------------+  +------------------------+ |
|  | Orchestrators |  |  Specialists  |  |  Experts + Core Team   | |
|  |  (3 agents)   |  |  (7 agents)   |  |     (8 agents)         | |
|  |               |  |               |  |                        | |
|  | devsecops-    |  | sast          |  | compliance-officer     | |
|  |   lead <------+--+ dast          |  | threat-modeler         | |
|  |   (router)    |  | sca           |  | vuln-triager           | |
|  | stack-        |  | container     |  | remediation-advisor    | |
|  |   analyst     |  | iac           |  | code-reviewer          | |
|  | team-         |  | secret        |  | incident-responder     | |
|  |   configurator|  | sbom          |  | report-generator       | |
|  |               |  |               |  | pipeline-guardian      | |
|  +---------------+  +---------------+  +------------------------+ |
+----------------------------+--------------------------------------+
                             | bash -> job-dispatcher.sh
                             v
+------------------------------------------------------------------+
|              Sidecar Runner (Alpine + Docker CLI)                 |
|      job-dispatcher.sh -> result-collector.sh -> normalize        |
|                  -> dedup-findings.sh -> format                   |
+--+------+------+------+------+------+-------+--------------------+
   |      |      |      |      |      |       |
 +-v-+ +--v--++--v--++--v--++--v--++--v--++--v--+
 |Sem| |Grype||Trivy||Chek ||GitL || ZAP ||Syft |
 |gre| |     ||     ||ov   ||eaks ||     ||     |
 |p  | | SCA || Con || IaC || Sec ||DAST ||SBOM |
 +---+ +-----++-----++-----++-----++-----++-----+
         All tools run locally in Docker containers
```

### How It Works

1. **คุณพิมพ์คำสั่ง** เช่น `/sast-scan` ใน Claude Code (หรือเรียกผ่าน MCP tool)
2. **Orchestrator** (`devsecops-lead`) วิเคราะห์ request แล้ว **MUST delegate** ไปยัง specialist ตาม routing table
3. **Specialist agent** ส่งงานผ่าน `job-dispatcher.sh` ไปยัง Docker container
4. **Tool** (เช่น Semgrep) รันใน container แล้วส่งผลกลับ
5. **json-normalizer.sh** แปลงผลเป็น Unified Finding Schema (severity mapped ถูกต้อง)
6. **dedup-findings.sh** รวมผลจากหลาย tools แล้วตัด duplicate ออก
7. **Expert agents** วิเคราะห์: จัดลำดับความสำคัญ, map compliance, แนะนำการแก้ไข
8. **Report generator** สร้างรายงานในรูปแบบที่ต้องการ (SARIF/JSON/Markdown/HTML)

### Full Pipeline Delegation Chain

เมื่อเรียก `/full-pipeline` ระบบจะ delegate ตามลำดับนี้:

```
1. @security-stack-analyst   -> ตรวจจับ tech stack
2. Scan Specialists (parallel):
   +-- @sast-specialist      -> ถ้ามี source code
   +-- @secret-scanner       -> เสมอ
   +-- @sca-specialist       -> ถ้ามี dependency files
   +-- @container-specialist -> ถ้ามี Dockerfile
   +-- @iac-specialist       -> ถ้ามี Terraform/K8s
   +-- @sbom-analyst         -> เสมอ
3. @vuln-triager             -> deduplicate + prioritize
4. @compliance-officer       -> map to OWASP/NIST/MITRE/NCSA
5. @remediation-advisor      -> fix guidance (HIGH+)
6. @report-generator         -> unified report
7. @pipeline-guardian        -> gate decision (PASS/FAIL)
```

### Decision Loop Model

การตัดสินใจแบ่งเป็น 3 ระดับตามความเสี่ยง:

```
  Out-of-Loop           On-the-Loop           In-the-Loop
  (AI autonomous)       (AI proposes)         (Human decides)
  +-----------+         +-----------+         +-----------+
  | /sast-scan|         |/full-pipe |         | /dast-scan|
  | /sca-scan |         |/compliance|         | /security |
  | /secret-  |         |/auto-fix  |         |   -gate   |
  |   scan    |         |/devsecops-|         | /incident-|
  | /container|         |   setup   |         |  response |
  | /iac-scan |         |           |         |           |
  | /sbom-gen |         |           |         |           |
  +-----------+         +-----------+         +-----------+
  Low risk               Medium risk           High risk
  No approval            AI proposes,          Human must
  needed                 human approves        decide
```

---

## 13 Skills — คำสั่งทั้งหมด

### Security Scanning

| Skill             | Tool     | ทำอะไร                                                         | Decision Loop |
| ----------------- | -------- | -------------------------------------------------------------- | ------------- |
| `/sast-scan`      | Semgrep  | วิเคราะห์ source code หา SQL Injection, XSS, SSRF ฯลฯ          | Out-of-Loop   |
| `/dast-scan`      | ZAP      | ทดสอบ web application แบบ dynamic (3 modes: baseline/full/api) | In-the-Loop   |
| `/sca-scan`       | Grype    | สแกน dependencies หา CVE ที่ทราบแล้ว                           | Out-of-Loop   |
| `/container-scan` | Trivy    | ตรวจสอบ Docker image หาช่องโหว่ + misconfiguration             | Out-of-Loop   |
| `/iac-scan`       | Checkov  | ตรวจ Terraform/K8s/Helm ตาม CIS Benchmarks                     | Out-of-Loop   |
| `/secret-scan`    | GitLeaks | ค้นหา API keys, passwords, tokens ที่หลุดเข้า code             | Out-of-Loop   |
| `/sbom-generate`  | Syft     | สร้าง Software Bill of Materials (CycloneDX/SPDX)              | Out-of-Loop   |

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
| `devsecops_compliance_status` | findings_file                 | per-framework coverage       | สรุป compliance ข้าม 4 frameworks           |
| `devsecops_suggest_fix`       | cwe_id, rule_id, finding_file | remediation suggestions      | แนะนำวิธีแก้ไขจาก CWE/rule knowledge        |

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

Plugin นี้ map ผลลัพธ์จาก CWE ไปยัง compliance frameworks อัตโนมัติ — **360 CWE mappings** across 4 frameworks:

| Framework             | Version | CWE Count | ใช้ทำอะไร                                   |
| --------------------- | ------- | --------- | ------------------------------------------- |
| **OWASP Top 10**      | 2021    | 105       | Web application security categories         |
| **NIST SP 800-53**    | Rev. 5  | 100       | Federal security controls                   |
| **MITRE ATT&CK**      | v16     | 93        | Adversary tactics & techniques              |
| **NCSA Web Security** | 1.0     | 62        | Thai national web security standard (สพธอ.) |

### Additional Frameworks Tracked

| Framework          | Version | ใช้ทำอะไร                         |
| ------------------ | ------- | --------------------------------- |
| **CIS Benchmarks** | Various | Configuration hardening baselines |
| **PCI DSS**        | 4.0.1   | Payment card industry compliance  |
| **CVSS**           | 4.0     | Vulnerability severity scoring    |
| **NIST 800-61**    | Rev. 3  | Incident response lifecycle       |

> ดูรายละเอียดทั้ง 16 frameworks ที่ติดตามใน [`frameworks.json`](frameworks.json)

### NCSA Website Security Standard (สพธอ.)

มาตรฐานความมั่นคงปลอดภัยเว็บไซต์ โดย สำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สพธอ./NCSA):

| Category     | ตรวจสอบอะไร                                                                                 | Method                   |
| ------------ | ------------------------------------------------------------------------------------------- | ------------------------ |
| **NCSA 1.x** | HTTP Security Headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy) | DAST + Header validation |
| **NCSA 2.x** | Transport Security (TLS >= 1.2, HTTPS enforcement, certificate validity)                    | DAST + TLS check         |
| **NCSA 3.x** | Authentication & Access Control                                                             | SAST + DAST              |
| **NCSA 4.x** | Session Management (Cookie Secure, HttpOnly, SameSite flags)                                | DAST + Cookie check      |
| **NCSA 5.x** | Input Validation (SQLi, XSS, SSRF prevention)                                               | SAST + DAST              |
| **NCSA 6.x** | Error Handling & Logging                                                                    | SAST + Custom A09 rules  |
| **NCSA 7.x** | Data Protection (encryption at rest/transit)                                                | SAST + Config check      |

---

## Output Formats

ผลลัพธ์จากทุก scan สามารถ export ได้ 6 รูปแบบ:

| Format           | ใช้ทำอะไร                                 | ตัวอย่าง        |
| ---------------- | ----------------------------------------- | --------------- |
| **SARIF** v2.1.0 | Upload ไป GitHub Security tab             | `results.sarif` |
| **JSON**         | ใช้กับ CI/CD pipeline หรือ custom tooling | `results.json`  |
| **Markdown**     | แปะเป็น PR comment                        | `results.md`    |
| **HTML**         | Executive dashboard สำหรับผู้บริหาร       | `results.html`  |
| **PDF**          | Enterprise report สำหรับ audit / mgmt     | `results.pdf`   |
| **CSV**          | Import ลง spreadsheet / SIEM              | `results.csv`   |

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

---

## Security & Privacy

- **Source code ไม่ออกจากเครื่อง** — ทุก tool รันใน local Docker containers
- **ผลสแกนอยู่ใน RAM** — ใช้ tmpfs volume, ไม่เขียนลง disk
- **Workspace mount เป็น read-only** — tools อ่านได้อย่างเดียว แก้ไขไม่ได้
- **ไม่มี network access** — containers ไม่ต้องการ internet (ยกเว้น ZAP ที่ต้องเข้าถึง target URL)
- **Non-root containers** — Dockerfile ใช้ USER ที่ไม่ใช่ root + tini init

> ดู [SECURITY.md](SECURITY.md) สำหรับ vulnerability reporting policy

---

## Testing & Quality

### Test Results (700+)

```
Validation:       236/236 structural checks (plugin structure, skills, agents, mappings)
Normalizer:        41/41  severity mapping + multi-array + null safety
MCP Server:        23/23  config + syntax + tool definitions
MCP Handlers:      25/25  Zod validation + gate logic + compliance crosswalk + NCSA
Hooks:             27/27  session-start + scan-on-write + pre-commit-gate
Dedup:             15/15  cross-tool deduplication
Auto-Fix:          37/37  SKILL.md structure + agent config + routing
DAST Integration:  22/22  ZAP fixture + normalizer + dispatcher
MCP Integration:   38/38  Docker availability + handler logic + runner
A01 Rules:         29/29  A01 access control rule YAML + metadata + CWE cross-ref
A03 Rules:         32/32  A03 injection rule YAML + metadata + CWE cross-ref
A09 Rules:         28/28  A09 logging rule YAML + metadata + CWE cross-ref + semgrep --validate
A10 Rules:         23/23  A10 SSRF rule YAML + metadata + CWE cross-ref
ZAP Modes:         34/34  mode parsing + timeout + Docker commands + fixtures
NCSA Validator:    24/24  script structure + header checks + output format
MCP Compare:       22/22  compare + compliance_status + suggest_fix tools
DAST Live:          0/0   conditional (requires DAST_TARGET env var)
Formatters:        16/16  SARIF + JSON + Markdown + HTML + CSV + PDF formatter validation
Runner:            28/28  job-dispatcher + result-collector + Docker orchestration
--------------------------------------------------------------
Total:            700+ checks passed (19 suites)
```

### QA History

| Round | Score     | Version | Key Focus                   |
| ----- | --------- | ------- | --------------------------- |
| QA 1  | 39/54     | v2.0.0  | Initial comprehensive audit |
| QA 2  | 45/54     | v2.0.1  | Null safety + CWE coverage  |
| QA 3  | 48/54     | v2.0.2  | Compliance mapping gaps     |
| QA 4  | 50/54     | v2.1.0  | Security fixes + RBAC       |
| QA 5  | 51/54     | v2.2.0  | Framework remediation       |
| QA 6  | 52/54     | v2.2.0  | Test hardening              |
| QA 7  | 53/54     | v2.3.0  | NCSA compliance             |
| QA 8  | **54/54** | v2.4.0  | Full coverage achieved      |

### Run Tests Locally

```bash
# Run all suites
for f in tests/validate-plugin.sh tests/test-*.sh; do bash "$f"; done

# Or individually
bash tests/validate-plugin.sh          # 236 structural checks
bash tests/test-normalizer.sh          # 41 normalizer unit tests
bash tests/test-mcp-server.sh          # 23 MCP server tests
bash tests/test-mcp-handlers.sh        # 25 MCP handler logic tests
bash tests/test-hooks.sh               # 27 hook tests
bash tests/test-dedup.sh               # 15 dedup tests
bash tests/test-auto-fix.sh            # 37 auto-fix skill tests
bash tests/test-dast-integration.sh    # 22 DAST integration tests
bash tests/test-mcp-integration.sh     # 38 MCP Docker integration tests
bash tests/test-a01-rules.sh           # 29 A01 access control rules tests
bash tests/test-a03-rules.sh           # 32 A03 injection rules tests
bash tests/test-a09-rules.sh           # 28 A09 custom rules tests
bash tests/test-a10-rules.sh           # 23 A10 SSRF rules tests
bash tests/test-mcp-compare.sh         # 22 MCP compare tests
bash tests/test-zap-modes.sh           # 34 ZAP multi-mode tests
bash tests/test-ncsa-validator.sh      # 24 NCSA validator tests
bash tests/test-dast-live.sh           # conditional (needs DAST_TARGET)
bash tests/test-formatters.sh          # 16 formatter tests
bash tests/test-runner.sh              # 28 runner tests
```

---

## ROI & Business Value

> ข้อมูลจาก [MANDAY-ESTIMATION.md](docs/MANDAY-ESTIMATION.md) — การวิเคราะห์ ROI เปรียบเทียบกับการพัฒนาแบบ manual

### Development Cost Comparison

| Metric         | Manual Development     | Claude Code (Actual)           | Savings     |
| -------------- | ---------------------- | ------------------------------ | ----------- |
| **Duration**   | 40 man-days (2 months) | 2.4 days (~19 hours)           | 133x faster |
| **Cost**       | 320,000 THB            | 3,100 THB                      | 99% less    |
| **ROI**        | —                      | **10,222%**                    | —           |
| **Break-even** | —                      | 3.1 hours of manual work saved | —           |

### 3-Year TCO Analysis

| Cost Component      | Traditional Team  | AI-Assisted    | Savings                   |
| ------------------- | ----------------- | -------------- | ------------------------- |
| Initial development | 320,000 THB       | 3,100 THB      | 316,900 THB               |
| Annual maintenance  | 384,000 THB/yr    | 6,000 THB/yr   | 378,000 THB/yr            |
| **3-Year Total**    | **1,304,000 THB** | **93,700 THB** | **1,210,300 THB (92.8%)** |

### Value Delivered

| Deliverable                  | Quantity                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| AI Agents                    | 18 (fully configured with routing + delegation)                                      |
| Security Skills              | 13 (7 scanning + 6 orchestration)                                                    |
| Docker Tool Integrations     | 7 (Semgrep, ZAP, Grype, Trivy, Checkov, GitLeaks, Syft)                              |
| MCP Tools                    | 8 (scan, results, gate, compliance, status, compare, compliance_status, suggest_fix) |
| CWE Compliance Mappings      | 360 across 4 frameworks                                                              |
| Custom Security Rules        | 33 (OWASP A01/A03/A09/A10 Semgrep rules)                                             |
| Automated Tests              | 700+ across 19 suites                                                                |
| Reference Documents          | 16 domain knowledge files (~500-800 lines each)                                      |
| Hooks (Real-time Protection) | 3 (session-start, scan-on-write, pre-commit-gate)                                    |
| Output Formatters            | 6 (SARIF, JSON, Markdown, HTML, PDF, CSV)                                            |

---

## Comparison with Alternatives

| Feature                | DevSecOps AI Team | GitHub Advanced Security | Snyk             | SonarQube    |
| ---------------------- | ----------------- | ------------------------ | ---------------- | ------------ |
| **Pricing**            | Free (MIT)        | $49/user/mo              | $52/user/mo+     | $150+/mo     |
| **SAST**               | Semgrep           | CodeQL                   | Snyk Code        | SonarQube    |
| **DAST**               | ZAP (3 modes)     | —                        | —                | —            |
| **SCA**                | Grype             | Dependabot               | Snyk Open Source | —            |
| **Container**          | Trivy             | —                        | Snyk Container   | —            |
| **IaC**                | Checkov           | —                        | Snyk IaC         | —            |
| **Secrets**            | GitLeaks          | Secret scanning          | —                | —            |
| **SBOM**               | Syft              | —                        | —                | —            |
| **AI Agents**          | 18 agents         | —                        | —                | —            |
| **NLP Interface**      | Natural language  | —                        | —                | —            |
| **NCSA Compliance**    | Built-in          | —                        | —                | —            |
| **Offline/Air-gapped** | Full support      | Partial                  | —                | Self-hosted  |
| **Data Privacy**       | 100% local        | Cloud                    | Cloud            | Self-hosted  |
| **Custom Rules**       | A01/A03/A09/A10   | Custom CodeQL            | —                | Custom rules |
| **MCP Integration**    | 8 tools           | —                        | —                | —            |

> **Note**: DevSecOps AI Team ใช้ open-source tools ทั้งหมด — ไม่มี vendor lock-in, source code ไม่ออกจากเครื่อง

---

## Project Structure

```
devsecops-ai-team/
+-- .claude-plugin/          # Plugin metadata (plugin.json, marketplace.json)
+-- .mcp.json                # MCP server declaration
+-- .github/workflows/       # CI/CD (validate, security-scan, framework-review, release)
+-- agents/                  # 18 AI agents (4 subdirectories)
|   +-- orchestrators/       #   3 orchestrator agents
|   +-- specialists/         #   7 specialist agents
|   +-- experts/             #   4 expert agents
|   +-- core-team/           #   4 core team agents
+-- skills/                  # 13 skill definitions (SKILL.md)
|   +-- references/          # 16 domain knowledge files (~500-800 lines each)
+-- runner/                  # Sidecar Runner (Dockerfile, compose, dispatcher, collector)
+-- formatters/              # SARIF, Markdown, HTML, PDF, CSV, JSON normalizer, dedup
+-- mcp/                     # MCP server -- 8 tools
|   +-- server.mjs           #   ESM module, stdio transport
|   +-- package.json         #   @modelcontextprotocol/sdk + zod
+-- mappings/                # CWE->OWASP, CWE->NIST, CWE->MITRE, CWE->NCSA, severity policy
+-- rules/                   # Custom Semgrep rules (A01, A03, A09, A10)
+-- templates/               # Report templates (HTML, Markdown)
+-- hooks/                   # 3 hooks (session-start, scan-on-write, pre-commit-gate)
+-- scripts/                 # install-runner, install-rules, check-prerequisites, NCSA validator
+-- tests/                   # 700+ tests across 19 suites
+-- docs/                    # INSTALL, TROUBLESHOOTING, AGENT-CATALOG, RUNBOOK, MANDAY
+-- examples/                # Rules, policies, DOMAIN.md, Semgrep rules
+-- frameworks.json          # 16 tracked security frameworks with version info
```

---

## Documentation

| Document                                                        | เนื้อหา                                            |
| --------------------------------------------------------------- | -------------------------------------------------- |
| [**Wiki**](https://github.com/pitimon/devsecops-ai-team/wiki)   | Comprehensive documentation with ASCII diagrams    |
| [INSTALL.md](docs/INSTALL.md)                                   | วิธีติดตั้งแบบ standard, manual, air-gapped, MCP   |
| [AGENT-CATALOG.md](docs/AGENT-CATALOG.md)                       | รายละเอียด 18 agents พร้อม routing cues + triggers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)                   | แก้ปัญหาที่พบบ่อย (8 scenarios)                    |
| [FRAMEWORK-UPDATE-RUNBOOK.md](docs/FRAMEWORK-UPDATE-RUNBOOK.md) | ขั้นตอนอัพเดท framework versions                   |
| [MANDAY-ESTIMATION.md](docs/MANDAY-ESTIMATION.md)               | ROI analysis + cost comparison (10,222% ROI)       |
| [CLAUDE.md](CLAUDE.md)                                          | Architecture + contributing guidelines             |
| [CHANGELOG.md](CHANGELOG.md)                                    | Version history (v1.0.0 → v2.6.0)                  |
| [SECURITY.md](SECURITY.md)                                      | Vulnerability reporting policy                     |

---

## Bilingual Output — ภาษาไทย + English

ทุก output ใช้ **Thai prose + English technical terms**:

```
## ผลการสแกน (Scan Results)

พบช่องโหว่ SQL Injection ในไฟล์ `src/api/users.py` บรรทัด 45
ความรุนแรง: HIGH (CWE-89, OWASP A03:2021)
คำแนะนำ: ใช้ parameterized queries แทน string concatenation
```

---

## Governance Integration

Plugin นี้ออกแบบมาให้ทำงานร่วมกับ [claude-governance](https://github.com/pitimon/claude-governance) ได้อย่างสมบูรณ์:

```
claude-governance (base)          devsecops-ai-team (extends)
+-- Pre-commit checks             +-- + Secret scan (GitLeaks)
+-- DOMAIN.md validation          +-- + SAST quick-check (Semgrep)
+-- Conventional commits          +-- + Pre-commit security gate
+-- Test coverage >= 80%          +-- + Full pipeline scan results
+-- Architecture fitness          +-- + Container/IaC/SCA checks
```

เมื่อติดตั้งทั้ง 2 plugins — hooks ทำงานร่วมกัน (additive, ไม่ conflict)

---

## Requirements

| Requirement    | Minimum | Recommended | หมายเหตุ                |
| -------------- | ------- | ----------- | ----------------------- |
| Docker Engine  | 20.10+  | 25.0+       | จำเป็นสำหรับทุก scan    |
| Docker Compose | v2.0+   | v2.24+      | จำเป็นสำหรับ full mode  |
| Node.js        | 18+     | 20+         | จำเป็นสำหรับ MCP server |
| Python         | 3.8+    | 3.12+       | จำเป็นสำหรับ formatters |
| Disk Space     | 2 GB    | 5 GB        | Docker images           |
| Claude Code    | Latest  | Latest      |                         |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, etc.
4. Run validation: `bash tests/validate-plugin.sh`
5. Run all tests: `for f in tests/validate-plugin.sh tests/test-*.sh; do bash "$f"; done`
6. Submit a Pull Request

ดูรายละเอียดใน [CLAUDE.md](CLAUDE.md)

---

## Roadmap

| Version | Status      | Theme           | Key Features                                                     |
| ------- | ----------- | --------------- | ---------------------------------------------------------------- |
| v1.0.0  | Released    | Foundation      | 18 agents, 12 skills, 7 tools, compliance mappings               |
| v2.0.0  | Released    | MCP & Quality   | MCP server, orchestration, dedup, smart detection                |
| v2.1.0  | Released    | Security & RBAC | 3 security fixes, RBAC gate, Zod validation                      |
| v2.2.0  | Released    | Remediation     | Framework-aware fixes (Django/React/Express/Spring)              |
| v2.3.0  | Released    | Automation      | /auto-fix skill, NCSA compliance, integration tests              |
| v2.4.0  | Released    | Detection       | A09 custom rules, ZAP multi-mode, NCSA validator                 |
| v2.5.0  | Released    | Rules & MCP     | 33 rules (A01/A03/A09/A10), 3 MCP tools, PDF/CSV                 |
| v2.6.0  | **Current** | CI/CD           | GitHub Actions, GitLab CI, SARIF per-tool, MCP bundle, tech debt |
| v2.7.0  | Planned     | OWASP 2025      | Mapping migration, Nuclei, NCSA 1.0, PDPA                        |
| v2.8.0  | Planned     | Supply Chain    | SLSA, VEX, 10/10 OWASP rules, SOC 2                              |
| v3.0.0  | Planned     | Platform        | Historical DB, dashboard UI, K8s, GraphQL                        |

> ดูรายละเอียด roadmap ทั้งหมดได้ที่ [docs/PRD.md](docs/PRD.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>DevSecOps AI Team</strong> — Enterprise Security Plugin for Claude Code<br>
  <sub>18 AI Agents | 13 Skills | 7 Tools | 8 MCP Tools | 6 Output Formats | 360 CWE Mappings | OWASP 10/10</sub><br>
  <sub>Built with <a href="https://claude.ai/claude-code">Claude Code</a> | Powered by Open Source Security Tools</sub>
</p>

<p align="center">
  <a href="https://github.com/pitimon/devsecops-ai-team">GitHub</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/wiki">Wiki</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/releases">Releases</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/issues">Issues</a>
</p>
