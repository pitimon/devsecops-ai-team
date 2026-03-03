<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=for-the-badge&logo=anthropic" alt="Claude Code Plugin">
  <img src="https://img.shields.io/badge/Version-3.1.0-brightgreen?style=for-the-badge" alt="v3.1.0">
  <img src="https://img.shields.io/badge/Tests-1302%2B-success?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Agents-18-blue?style=flat-square" alt="18 Agents">
  <img src="https://img.shields.io/badge/Skills-16-green?style=flat-square" alt="16 Skills">
  <img src="https://img.shields.io/badge/Tools-11-orange?style=flat-square" alt="11 Tools">
  <img src="https://img.shields.io/badge/MCP-10_Tools-purple?style=flat-square" alt="MCP">
  <img src="https://img.shields.io/badge/OWASP_2021%2B2025-10%2F10-critical?style=flat-square" alt="OWASP 2021+2025 10/10">
  <img src="https://img.shields.io/badge/CWE_Mappings-488-informational?style=flat-square" alt="488 CWEs">
  <img src="https://img.shields.io/badge/Frameworks-7-blueviolet?style=flat-square" alt="7 Compliance Frameworks">
  <img src="https://img.shields.io/badge/QA_Rounds-13_(75%2F75)-success?style=flat-square" alt="QA 75/75">
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
- [What's New (v3.1.0)](#whats-new)
- [Use Cases](#use-cases)
- [Why DevSecOps AI Team?](#why-devsecops-ai-team)
- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [Features at a Glance](#features-at-a-glance)
- [Security & Privacy](#security--privacy)
- [Testing & Quality](#testing--quality)
- [ROI & Business Value](#roi--business-value)
- [Comparison with Alternatives](#comparison-with-alternatives)
- [Services](#services--บริการ-consulting--training)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Executive Summary

| Metric                    | Value                                                                                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Project Type**          | Claude Code Plugin Skill Pack (pure markdown/JSON/shell)                                                                                        |
| **AI Agents**             | 18 agents across 4 groups (Orchestrators, Specialists, Experts, Core Team)                                                                      |
| **Skills (Commands)**     | 16 slash commands (/sast-scan, /dast-scan, /full-pipeline, /k8s-scan, /graphql-scan, ...)                                                       |
| **Security Tools**        | 11 open-source tools in Docker containers (Semgrep, ZAP, Nuclei, Grype, Trivy, Checkov, GitLeaks, Syft, TruffleHog, kube-bench, Nuclei-GraphQL) |
| **MCP Tools**             | 10 composable tools for programmatic integration                                                                                                |
| **Compliance Frameworks** | 7 frameworks — OWASP Top 10 (2021+2025), NIST 800-53, MITRE ATT&CK, NCSA, PDPA, SOC 2, ISO 27001                                                |
| **CWE Mappings**          | 488 total (OWASP 122 + NIST 100 + MITRE 93 + NCSA 62 + PDPA 30 + SOC 2 40 + ISO 27001 41)                                                       |
| **OWASP Top 10 Coverage** | 10/10 categories — dual-version 2021+2025 mapping                                                                                               |
| **Tests**                 | 1,302+ checks across 42 suites — all passing                                                                                                    |
| **QA Rounds**             | 13 rounds, 75/75 latest (cumulative 1,300+ checks)                                                                                              |
| **ROI**                   | 10,222% — 3,100 THB actual vs 320,000 THB equivalent (133x speed)                                                                               |
| **Version**               | 3.0.4 (2026-03-03)                                                                                                                              |

---

## Key Highlights

- **18 AI Agents, 1 Team** — Orchestrators delegate งานให้ Specialists, Experts วิเคราะห์ผลข้ามเครื่องมือ, Core Team enforce quality gates — ทั้งหมดทำงานร่วมกันผ่าน mandatory routing table
- **11 Security Tools, 1 Command** — `/full-pipeline` รันทุกเครื่องมือแบบ parallel, deduplicate ผลข้าม tools, สร้าง unified report ในคำสั่งเดียว
- **Real-Time Protection** — บล็อก commits ที่มี CRITICAL findings, ตรวจจับ secrets (AWS keys, GitHub tokens, JWT) ก่อนเขียนลง disk — ทำงานใน 500ms
- **CVSS v4.0 Prioritization** — วิเคราะห์ business impact, exploitability (Weaponized → None), กำหนด SLA tiers (P1: 24 ชม. → P4: backlog)
- **488 CWE Compliance Mappings** — Auto-map ผลสแกนไปยัง OWASP Top 10 (122), NIST 800-53 (100), MITRE ATT&CK (93), NCSA (62), PDPA (30), SOC 2 (40), ISO 27001 (41)
- **NCSA Web Security Standard** — รองรับมาตรฐานความมั่นคงปลอดภัยเว็บไซต์ สพธอ. (HTTP Headers, TLS, Session Management)
- **MCP Server** — 10 composable tools สำหรับ programmatic integration กับ MCP-compatible clients (compare, compliance_status, suggest_fix, history, pipeline)
- **Custom OWASP Rules** — 84 custom Semgrep rules for A01 (access control), A02 (crypto), A03 (injection), A04 (insecure design), A05 (misconfig), A06 (vulnerable components), A07 (auth failures), A08 (integrity failures), A09 (logging), A10 (SSRF + exception handling), K8s manifests, GraphQL endpoints
- **8 Output Formats** — SARIF, JSON, Markdown, HTML, PDF, CSV, VEX, Dashboard

---

## OWASP Top 10 Coverage

ครอบคลุม OWASP Top 10 ทั้ง 2021 และ 2025 ด้วย dual-version mapping, tools และ custom rules:

| #   | Category (2021)           | Category (2025)               | Tools                                | Detection Method                                                                                  |
| --- | ------------------------- | ----------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------- |
| A01 | Broken Access Control     | Broken Access Control         | **Custom rules (8)**, ZAP, Nuclei    | Missing authz, IDOR, path traversal, CORS, privilege escalation (CWE-862/639/22/942/269)          |
| A02 | Cryptographic Failures    | Cryptographic Failures        | **Custom rules (6)**, GitLeaks       | Weak crypto, hardcoded keys, insecure algorithms, missing encryption (CWE-327/328/330/338/916)    |
| A03 | Injection                 | Injection                     | **Custom rules (11)**, ZAP, Nuclei   | SQLi, command injection, XSS, LDAP injection, template injection (CWE-89/78/79/90/1336)           |
| A04 | Insecure Design           | Insecure Design               | **Custom rules (4)**, Checkov        | Missing rate limiting, insecure file upload, business logic bypass (CWE-770/434/840/841)          |
| A05 | Security Misconfiguration | Security Misconfiguration     | **Custom rules (6)**, Trivy, Checkov | Debug mode, directory listing, default creds, verbose errors (CWE-16/215/548/756/1004)            |
| A06 | Vulnerable Components     | Vulnerable Components         | **Custom rules (5)**, Grype, Syft    | Outdated dependencies, known CVEs, version pinning, SBOM analysis (CWE-1104/937/1035)             |
| A07 | Auth Failures             | Identification Failures       | **Custom rules (5)**, ZAP, Nuclei    | Weak passwords, missing MFA, session fixation, credential stuffing (CWE-287/306/384/640/521)      |
| A08 | Data Integrity Failures   | Data Integrity Failures       | **Custom rules (5)**, Trivy          | Unsafe deserialization, unsigned artifacts, CI/CD integrity (CWE-502/829/494/915/345)             |
| A09 | Logging Failures          | Logging Failures              | **Custom rules (7)**                 | Missing auth logs, silent catch, PII in logs, log injection, rate-limit logging                   |
| A10 | SSRF                      | Exception Handling (new 2025) | **Custom rules (7+4)**, ZAP, Nuclei  | SSRF: cloud metadata, DNS rebinding + Exception: stack trace leak, global catch (CWE-918/209/392) |

---

## What's New

> ดู [CHANGELOG.md](CHANGELOG.md) สำหรับรายละเอียดทั้งหมด (v1.0.0 → v3.1.0)

### v3.1.0 — Commercial Ready (Latest)

- **Professional README Redesign** — Commercial-grade product presentation (1,071 → 615 lines)
- **Quick Start Guide** — Install to first scan in 5 minutes ([docs/QUICK-START.md](docs/QUICK-START.md))
- **First Scan Walkthrough** — Behind-the-scenes agent orchestration explained ([docs/FIRST-SCAN-WALKTHROUGH.md](docs/FIRST-SCAN-WALKTHROUGH.md))
- **Demo Scenarios** — 3 presenter-ready demos (5/10/15 min) with bilingual talk track ([demo/](demo/))
- **Demo Vulnerable Project** — Onboarding sample with intentional vulnerabilities ([tests/fixtures/demo-project/](tests/fixtures/demo-project/))
- **Service Tiers** — Starter / Pro / Enterprise consulting + training offerings
- **Consolidated Documentation** — Architecture, Features, Project Structure extracted to dedicated docs

<details>
<summary>Previous versions</summary>

### v3.0.4 — Platform Release

- **SQLite Historical Database** — `scripts/scan-db.sh` with 7 subcommands for persistent scan tracking and trend analysis
- **DAG Pipeline Engine** — `runner/pipeline-engine.sh` with topological sort and 4 built-in pipeline definitions
- **Security Dashboard** — Alpine.js + Chart.js self-contained HTML dashboard with 6 panels
- **K8s Security Scanning** — `/k8s-scan` skill with 8 Semgrep rules + kube-bench CIS Benchmark integration
- **GraphQL Security Scanning** — `/graphql-scan` skill with 8 Semgrep rules + 4 Nuclei templates
- **2 New MCP Tools** — `devsecops_history` and `devsecops_pipeline` (10 total)
- **84 Custom Semgrep Rules** — +16 new rules (8 K8s + 8 GraphQL)

### v2.8.0 — Supply Chain Compliance + OWASP 10/10

- **OWASP 10/10 Custom Rules** — A06 Vulnerable Components (5), A07 Auth Failures (5), A08 Integrity Failures (5) — total 68 custom Semgrep rules
- **SLSA Provenance Assessment** — `/slsa-assess` skill with SLSA v1.1 reference for EU CRA compliance
- **VEX Output Format** — CycloneDX VEX + OpenVEX as 7th output format
- **TruffleHog Secret Scanning** — 9th security tool with git/filesystem/s3 modes
- **SOC 2 + ISO 27001 Compliance** — 2 new mapping files (~81 CWEs total), 7 frameworks

### v2.7.0 — OWASP 2025, Nuclei DAST, PDPA Compliance

- **OWASP Top 10 2025** — dual-version mapping (2021+2025) across all 122 CWEs, 4 new rule sets (A02/A04/A05/A10-exception)
- **53 Custom Semgrep Rules** — was 33, added A02 Cryptographic Failures (6), A04 Insecure Design (4), A05 Misconfiguration (6), A10 Exception Handling (4)
- **Nuclei DAST Integration** — second DAST tool alongside ZAP with Docker, dispatcher, normalizer
- **PDPA Compliance** — 30 CWE mappings for Thai Personal Data Protection Act
- **NCSA 1.0 Enhanced** — Permissions-Policy, COOP, COEP, TLS 1.3 checks

### v2.5.0 — Custom OWASP Rules (A01/A03/A10), 3 New MCP Tools, PDF/CSV

- **A01/A03/A10 Custom Semgrep Rules** — 26 new rules ตรวจจับ access control, injection, SSRF anti-patterns
- **3 New MCP Tools** — `devsecops_compare` (trend diff), `devsecops_compliance_status` (aggregate compliance), `devsecops_suggest_fix` (remediation)
- **PDF/CSV Formatters** — enterprise PDF export (pandoc), spreadsheet CSV export
- **700+ tests** across 19 suites (was 587)

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

Full installation guide: [docs/INSTALL.md](docs/INSTALL.md) | Quick start walkthrough: [docs/QUICK-START.md](docs/QUICK-START.md)

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
+--+------+------+------+------+------+-------+-------+------------+
   |      |      |      |      |      |       |       |
 +-v-+ +--v--++--v--++--v--++--v--++--v--++--v--++---v---+
 |Sem| |Grype||Trivy||Chek ||GitL || ZAP ||Syft ||Truf  |
 |gre| |     ||     ||ov   ||eaks ||     ||     ||fleHog|
 |p  | | SCA || Con || IaC || Sec ||DAST ||SBOM || Sec  |
 +---+ +-----++-----++-----++-----++-----++-----++------+
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

See [Architecture Reference](docs/ARCHITECTURE.md) for pipeline delegation and decision loop details

---

## Features at a Glance

| Category                    | Details                                                                                                                                                                                                                                                                                       |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **16 Skills**               | 10 scanning + 6 orchestration slash commands — `/sast-scan`, `/dast-scan`, `/full-pipeline`, `/k8s-scan`, `/graphql-scan`, and more. See [Feature Reference](docs/FEATURES.md#16-skills--คำสั่งทั้งหมด)                                                                                       |
| **18 AI Agents**            | 3 Orchestrators, 7 Specialists, 4 Experts, 4 Core Team — mandatory routing + delegation chain. See [Agent Catalog](docs/AGENT-CATALOG.md)                                                                                                                                                     |
| **Output Formats**          | SARIF, JSON, Markdown, HTML, PDF, CSV, VEX, Dashboard                                                                                                                                                                                                                                         |
| **10 MCP Tools**            | `devsecops_scan`, `devsecops_results`, `devsecops_gate`, `devsecops_compliance`, `devsecops_status`, `devsecops_compare`, `devsecops_compliance_status`, `devsecops_suggest_fix`, `devsecops_history`, `devsecops_pipeline`. See [MCP Reference](docs/FEATURES.md#mcp-server-integration-v20) |
| **7 Compliance Frameworks** | OWASP Top 10 (2021+2025), NIST 800-53, MITRE ATT&CK, NCSA, PDPA, SOC 2, ISO 27001 — 488 CWE mappings total                                                                                                                                                                                    |
| **3 Autonomous Hooks**      | `session-start` (tech stack detection), `scan-on-write` (real-time secret/injection detection), `pre-commit-gate` (block CRITICAL findings)                                                                                                                                                   |
| **Sidecar Runner**          | Docker container orchestration — minimal mode (oneshot) or full mode (persistent). See [Runner Reference](docs/FEATURES.md#sidecar-runner-architecture)                                                                                                                                       |
| **84 Custom Rules**         | Semgrep rules covering OWASP A01-A10 + K8s manifests + GraphQL endpoints                                                                                                                                                                                                                      |
| **CVSS v4.0 Triage**        | Exploitability classification (Weaponized/Active/POC/Theoretical/None) + SLA priority matrix (P1: 24h → P4: backlog)                                                                                                                                                                          |
| **RBAC Security Gate**      | Role-based policy (developer/security-lead/release-manager) with configurable severity thresholds                                                                                                                                                                                             |

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

### Test Results (1,302+)

```
Validation:          276/276 structural checks (plugin structure, skills, agents, mappings)
Normalizer:           41/41  severity mapping + multi-array + null safety
MCP Server:           30/30  config + syntax + tool definitions
MCP Handlers:         37/37  Zod validation + gate logic + compliance crosswalk + NCSA + PDPA
Hooks:                27/27  session-start + scan-on-write + pre-commit-gate
Dedup:                15/15  cross-tool deduplication
Auto-Fix:             37/37  SKILL.md structure + agent config + routing
DAST Integration:     22/22  ZAP fixture + normalizer + dispatcher
MCP Integration:      38/38  Docker availability + handler logic + runner
A01 Rules:            30/30  A01 access control rule YAML + metadata + CWE + OWASP 2025
A02 Rules:            17/17  A02 cryptographic failures rule YAML + metadata + CWE
A03 Rules:            33/33  A03 injection rule YAML + metadata + CWE + OWASP 2025
A04 Rules:            17/17  A04 insecure design rule YAML + metadata + CWE
A05 Rules:            18/18  A05 security misconfiguration rule YAML + metadata + CWE
A06 Rules:            17/17  A06 vulnerable components rule YAML + metadata + CWE
A07 Rules:            18/18  A07 authentication failures rule YAML + metadata + CWE
A08 Rules:            16/16  A08 integrity failures rule YAML + metadata + CWE
A09 Rules:            28/28  A09 logging rule YAML + metadata + CWE + OWASP 2025
A10 Rules:            31/31  A10 SSRF + exception handling rules + OWASP 2025
ZAP Modes:            34/34  mode parsing + timeout + Docker commands + fixtures
NCSA Validator:       28/28  script structure + header checks + TLS 1.3 + output format
MCP Compare:          22/22  compare + compliance_status + suggest_fix tools
DAST Live:             0/0   conditional (requires DAST_TARGET env var)
Nuclei Integration:   22/22  Nuclei fixture + normalizer + dispatcher
PDPA Mapping:         17/17  PDPA CWE mappings + structure + coverage
SOC 2 Mapping:        17/17  SOC 2 Trust Service Criteria mappings
ISO 27001 Mapping:    17/17  ISO 27001 Annex A control mappings
SLSA Skill:           15/15  SLSA provenance assessment skill
VEX Formatter:        20/20  CycloneDX + OpenVEX output format
TruffleHog:           21/21  TruffleHog fixture + normalizer + dispatcher
Secret Verifier:      18/18  secret validity checking + provider verification
Formatters:           29/29  SARIF + JSON + Markdown + HTML + CSV + PDF formatter validation
Runner:               28/28  job-dispatcher + result-collector + Docker orchestration
Version Bump:         17/17  version-bump.sh script tests
CI Adapter:           25/25  CI platform detection + adapter functions
CI Templates:         65/65  GitHub Actions + GitLab CI template validation
Release:              12/12  release checklist script tests
Scan DB:              39/39  SQLite scan history database + 7 subcommands + OWASP enrichment + compliance + multi-tool lifecycle
Pipeline Engine:      25/25  DAG pipeline engine + topological sort + cycle detection
K8s Scan:             23/23  K8s skill + rules + kube-bench + normalizer integration
GraphQL Scan:         34/34  GraphQL skill + rules + Nuclei templates + normalizer + metadata
Dashboard:            26/26  dashboard generator + template + data injection + special character regression
--------------------------------------------------------------
Total:              1302+ checks passed (42 suites)
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

| Deliverable                  | Quantity                                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------- |
| AI Agents                    | 18 (fully configured with routing + delegation)                                                          |
| Security Skills              | 16 (10 scanning + 6 orchestration)                                                                       |
| Docker Tool Integrations     | 11 (Semgrep, ZAP, Nuclei, Grype, Trivy, Checkov, GitLeaks, Syft, TruffleHog, kube-bench, Nuclei-GraphQL) |
| MCP Tools                    | 10 (scan, results, gate, compliance, status, compare, compliance_status, suggest_fix, history, pipeline) |
| CWE Compliance Mappings      | 488 across 7 frameworks                                                                                  |
| Custom Security Rules        | 84 (OWASP A01-A10 + K8s + GraphQL Semgrep rules)                                                         |
| Automated Tests              | 1,302+ across 42 suites                                                                                  |
| Reference Documents          | 19 domain knowledge files (~500-800 lines each)                                                          |
| Hooks (Real-time Protection) | 3 (session-start, scan-on-write, pre-commit-gate)                                                        |
| Output Formatters            | 8 (SARIF, JSON, Markdown, HTML, PDF, CSV, VEX, Dashboard)                                                |

---

## Comparison with Alternatives

| Feature                | DevSecOps AI Team                   | GitHub Advanced Security | Snyk             | SonarQube    |
| ---------------------- | ----------------------------------- | ------------------------ | ---------------- | ------------ |
| **Pricing**            | Free (MIT)                          | $49/user/mo              | $52/user/mo+     | $150+/mo     |
| **SAST**               | Semgrep                             | CodeQL                   | Snyk Code        | SonarQube    |
| **DAST**               | ZAP + Nuclei                        | —                        | —                | —            |
| **SCA**                | Grype                               | Dependabot               | Snyk Open Source | —            |
| **Container**          | Trivy                               | —                        | Snyk Container   | —            |
| **IaC**                | Checkov                             | —                        | Snyk IaC         | —            |
| **Secrets**            | GitLeaks + TruffleHog               | Secret scanning          | —                | —            |
| **SBOM**               | Syft                                | —                        | —                | —            |
| **AI Agents**          | 18 agents                           | —                        | —                | —            |
| **NLP Interface**      | Natural language                    | —                        | —                | —            |
| **NCSA Compliance**    | Built-in                            | —                        | —                | —            |
| **Offline/Air-gapped** | Full support                        | Partial                  | —                | Self-hosted  |
| **Data Privacy**       | 100% local                          | Cloud                    | Cloud            | Self-hosted  |
| **Custom Rules**       | 84 rules (10 OWASP + K8s + GraphQL) | Custom CodeQL            | —                | Custom rules |
| **MCP Integration**    | 10 tools                            | —                        | —                | —            |

> **Note**: DevSecOps AI Team ใช้ open-source tools ทั้งหมด — ไม่มี vendor lock-in, source code ไม่ออกจากเครื่อง

---

## Services — บริการ Consulting + Training

DevSecOps AI Team พร้อมให้บริการ consulting, implementation, และ training สำหรับองค์กรในประเทศไทย

| Tier           | รายละเอียด                                                                               | เหมาะสำหรับ                           |
| -------------- | ---------------------------------------------------------------------------------------- | ------------------------------------- |
| **Starter**    | Training + Workshop — สอนทีมใช้ plugin, OWASP, NCSA compliance                           | ทีมที่เริ่มต้น DevSecOps              |
| **Pro**        | Implementation + Training — setup pipeline, customize rules, integrate CI/CD, train ทีม  | องค์กรที่ต้องการ hands-on setup       |
| **Enterprise** | Managed Security Service — scan ต่อเนื่อง, วิเคราะห์ผล, รายงานรายเดือน, priority support | องค์กรที่ต้องการ expert ดูแลต่อเนื่อง |

สนใจ? ติดต่อผ่าน [GitHub Issues](https://github.com/pitimon/devsecops-ai-team/issues) หรือ email

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

## Documentation

| Document                                                        | เนื้อหา                                            |
| --------------------------------------------------------------- | -------------------------------------------------- |
| [**Wiki**](https://github.com/pitimon/devsecops-ai-team/wiki)   | Comprehensive documentation with ASCII diagrams    |
| [QUICK-START.md](docs/QUICK-START.md)                           | Install to first scan in 5 minutes                 |
| [FIRST-SCAN-WALKTHROUGH.md](docs/FIRST-SCAN-WALKTHROUGH.md)     | Behind the scenes — agent orchestration explained  |
| [INSTALL.md](docs/INSTALL.md)                                   | วิธีติดตั้งแบบ standard, manual, air-gapped, MCP   |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md)                         | Pipeline delegation, decision loop, system design  |
| [FEATURES.md](docs/FEATURES.md)                                 | Skills, agents, MCP, compliance, output formats    |
| [PROJECT-STRUCTURE.md](docs/PROJECT-STRUCTURE.md)               | Directory tree + file descriptions                 |
| [AGENT-CATALOG.md](docs/AGENT-CATALOG.md)                       | รายละเอียด 18 agents พร้อม routing cues + triggers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)                   | แก้ปัญหาที่พบบ่อย (8 scenarios)                    |
| [FRAMEWORK-UPDATE-RUNBOOK.md](docs/FRAMEWORK-UPDATE-RUNBOOK.md) | ขั้นตอนอัพเดท framework versions                   |
| [MANDAY-ESTIMATION.md](docs/MANDAY-ESTIMATION.md)               | ROI analysis + cost comparison (10,222% ROI)       |
| [CLAUDE.md](CLAUDE.md)                                          | Architecture + contributing guidelines             |
| [CHANGELOG.md](CHANGELOG.md)                                    | Version history (v1.0.0 → v3.1.0)                  |
| [SECURITY.md](SECURITY.md)                                      | Vulnerability reporting policy                     |

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
| v2.6.x  | Released    | CI/CD           | GitHub Actions, GitLab CI, SARIF per-tool, MCP bundle, tech debt |
| v2.7.0  | Released    | OWASP 2025      | Dual mapping, 53 rules, Nuclei, NCSA 1.0, PDPA                   |
| v2.8.0  | Released    | Supply Chain    | SLSA, VEX, 10/10 OWASP rules, SOC 2, ISO 27001, TruffleHog       |
| v3.0.x  | Released    | Platform        | SQLite DB, DAG pipeline, dashboard, K8s scan, GraphQL scan       |
| v3.1.0  | **Current** | Commercial      | README redesign, onboarding, demos, service tiers                |

> ดูรายละเอียด roadmap ทั้งหมดได้ที่ [docs/PRD.md](docs/PRD.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>DevSecOps AI Team</strong> — Enterprise Security Plugin for Claude Code<br>
  <sub>18 AI Agents | 16 Skills | 11 Tools | 10 MCP Tools | 8 Output Formats | 488 CWE Mappings | OWASP 10/10</sub><br>
  <sub>Built with <a href="https://claude.ai/claude-code">Claude Code</a> | Powered by Open Source Security Tools</sub>
</p>

<p align="center">
  <a href="https://github.com/pitimon/devsecops-ai-team">GitHub</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/wiki">Wiki</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/releases">Releases</a> |
  <a href="https://github.com/pitimon/devsecops-ai-team/issues">Issues</a>
</p>
