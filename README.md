<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=for-the-badge&logo=anthropic" alt="Claude Code Plugin">
  <img src="https://img.shields.io/badge/Agents-18-blue?style=for-the-badge" alt="18 Agents">
  <img src="https://img.shields.io/badge/Skills-12-green?style=for-the-badge" alt="12 Skills">
  <img src="https://img.shields.io/badge/Tools-7-orange?style=for-the-badge" alt="7 Tools">
  <img src="https://img.shields.io/badge/Version-2.0.1-brightgreen?style=for-the-badge" alt="v2.0.1">
  <img src="https://img.shields.io/badge/Tests-334%2F334-success?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/MCP-5_Tools-purple?style=for-the-badge" alt="MCP">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License">
</p>

<h1 align="center">DevSecOps AI Team</h1>

<p align="center">
  <strong>Enterprise Plugin Skill Pack สำหรับ Claude Code</strong><br>
  ทีม AI 18 ตัวที่ทำงานร่วมกันเพื่อรักษาความปลอดภัยของซอฟต์แวร์ตลอด Development Lifecycle
</p>

<p align="center">
  <a href="https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml"><img src="https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml/badge.svg" alt="Validation"></a>
  <a href="https://github.com/pitimon/devsecops-ai-team/actions/workflows/security-scan.yml"><img src="https://github.com/pitimon/devsecops-ai-team/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan"></a>
  <a href="https://github.com/pitimon/devsecops-ai-team/releases"><img src="https://img.shields.io/github/v/release/pitimon/devsecops-ai-team" alt="Release"></a>
</p>

---

## Key Highlights

- **18 AI Agents, 1 Team** — Orchestrators delegate งานให้ Specialists, Experts วิเคราะห์ผลข้ามเครื่องมือ, Core Team enforce quality gates — ทั้งหมดทำงานร่วมกันผ่าน mandatory routing table
- **7 Security Tools, 1 Command** — `/full-pipeline` รันทุกเครื่องมือแบบ parallel, deduplicate ผลข้าม tools, สร้าง unified report ในคำสั่งเดียว
- **Real-Time Protection** — บล็อก commits ที่มี CRITICAL findings, ตรวจจับ secrets (AWS keys, GitHub tokens, JWT) ก่อนเขียนลง disk — ทำงานใน 500ms
- **CVSS v4.0 Prioritization** — ไม่ใช่แค่ severity labels — วิเคราะห์ business impact, exploitability (Weaponized → None), กำหนด SLA tiers (P1: 24 ชม. → P4: backlog)
- **66+ CWE Compliance Mappings** — Auto-map ผลสแกนไปยัง OWASP Top 10 (66 CWEs), NIST 800-53 (58 CWEs), MITRE ATT&CK (48 CWEs)
- **MCP Server** — 5 composable tools (`devsecops_scan`, `devsecops_gate`, ...) สำหรับ programmatic integration กับ MCP-compatible clients

---

## What's New

> ดู [CHANGELOG.md](CHANGELOG.md) สำหรับรายละเอียดทั้งหมด (v1.0.0 → v2.0.1)

### v2.0.1 — Patch

- **BUG-6/7/8 Fixed** — null-safety fixes ใน json-normalizer.sh (Semgrep null severity, Trivy null arrays, CWE ID parsing)
- **25 Memory-Safety CWEs** — เพิ่ม buffer overflow, use-after-free, integer overflow, race condition ฯลฯ ใน compliance mappings ทั้ง 3 ไฟล์ (OWASP 41→66, NIST 33→58, MITRE 23→48)
- **Version bump** — อัพเดท version ใน 6 config/doc files

### v2.0.0 Highlights

- **MCP Server** — 5 MCP tools ให้ MCP-compatible clients เรียกใช้ security scanning ได้โดยตรง
- **Bug Fixes** — แก้ 5 bugs ที่ทำให้ normalizer สูญเสียข้อมูลถึง 95% (Semgrep severity, Checkov multi-array, Trivy misconfigs)
- **Agent Orchestration** — mandatory routing table + delegation chain ป้องกัน agent ทำงานผิดบทบาท
- **Smart Detection** — session-start.sh ตรวจจับไฟล์ project แล้วแนะนำ scan ที่เหมาะสมอัตโนมัติ
- **Cross-tool Dedup** — `dedup-findings.sh` รวมผลจากหลาย tools แล้ว deduplicate ด้วย (cve_id, file, line)
- **334 Tests** — เพิ่ม 73 tests ใหม่ (normalizer 34 + MCP 23 + validate 16)

---

## Why DevSecOps AI Team?

> **ปัญหา**: ทีม Dev ต้องใช้เครื่องมือ security หลายตัว แต่ละตัวมี CLI, output format, และวิธีตีความผลต่างกัน ทำให้เสียเวลาในการเรียนรู้และ integrate เข้ากับ workflow

> **วิธีแก้**: Plugin นี้รวม 7 เครื่องมือ security ชั้นนำ (ทั้งหมด Open Source) ให้ทำงานผ่าน Claude Code ด้วยภาษาธรรมชาติ — พิมพ์ `/sast-scan` แทนการจำ CLI ยาวๆ ได้ผลลัพธ์ที่เข้าใจง่ายพร้อมคำแนะนำการแก้ไข

### ทำอะไรได้บ้าง?

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
           │
           ├─── Skill commands (/sast-scan, /full-pipeline, ...)
           │
           ├─── MCP tools (devsecops_scan, devsecops_gate, ...)   ← v2.0
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     18 AI Agents                                │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Orchestrators│  │  Specialists │  │  Experts + Core Team   │ │
│  │  (3 agents)  │  │  (7 agents)  │  │     (8 agents)         │ │
│  │              │  │              │  │                        │ │
│  │ devsecops-   │  │ sast         │  │ compliance-officer     │ │
│  │   lead ◄─────┼──┤ dast         │  │ threat-modeler         │ │
│  │   (router)   │  │ sca          │  │ vuln-triager           │ │
│  │ stack-       │  │ container    │  │ remediation-advisor    │ │
│  │   analyst    │  │ iac          │  │ code-reviewer          │ │
│  │ team-        │  │ secret       │  │ incident-responder     │ │
│  │   configurator│  │ sbom         │  │ report-generator       │ │
│  │              │  │              │  │ pipeline-guardian      │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────────┘
                          │ bash → job-dispatcher.sh
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│              Sidecar Runner (Alpine + Docker CLI)               │
│      job-dispatcher.sh → result-collector.sh → normalize        │
│                  → dedup-findings.sh → format                   │
└──┬──────┬──────┬──────┬──────┬──────┬───────┬───────────────────┘
   │      │      │      │      │      │       │
 ┌─▼─┐ ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐
 │Sem│ │Grype││Trivy││Chek ││GitL ││ ZAP ││Syft │
 │gre│ │     ││     ││ov   ││eaks ││     ││     │
 │p  │ │ SCA ││ Con ││ IaC ││ Sec ││DAST ││SBOM │
 └───┘ └─────┘└─────┘└─────┘└─────┘└─────┘└─────┘
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

### Full Pipeline Delegation Chain (v2.0)

เมื่อเรียก `/full-pipeline` ระบบจะ delegate ตามลำดับนี้:

```
1. @security-stack-analyst   → ตรวจจับ tech stack
2. Scan Specialists (parallel):
   ├── @sast-specialist      → ถ้ามี source code
   ├── @secret-scanner       → เสมอ
   ├── @sca-specialist       → ถ้ามี dependency files
   ├── @container-specialist → ถ้ามี Dockerfile
   ├── @iac-specialist       → ถ้ามี Terraform/K8s
   └── @sbom-analyst         → เสมอ
3. @vuln-triager             → deduplicate + prioritize
4. @compliance-officer       → map to OWASP/NIST/MITRE
5. @remediation-advisor      → fix guidance (HIGH+)
6. @report-generator         → unified report
7. @pipeline-guardian        → gate decision (PASS/FAIL)
```

---

## 12 Skills — คำสั่งทั้งหมด

### Security Scanning

| Skill             | Tool     | ทำอะไร                                                    | Decision Loop |
| ----------------- | -------- | --------------------------------------------------------- | ------------- |
| `/sast-scan`      | Semgrep  | วิเคราะห์ source code หา SQL Injection, XSS, SSRF ฯลฯ     | Out-of-Loop   |
| `/dast-scan`      | ZAP      | ทดสอบ web application แบบ dynamic (ต้องระบุ URL เป้าหมาย) | In-the-Loop   |
| `/sca-scan`       | Grype    | สแกน dependencies หา CVE ที่ทราบแล้ว                      | Out-of-Loop   |
| `/container-scan` | Trivy    | ตรวจสอบ Docker image หาช่องโหว่ + misconfiguration        | Out-of-Loop   |
| `/iac-scan`       | Checkov  | ตรวจ Terraform/K8s/Helm ตาม CIS Benchmarks                | Out-of-Loop   |
| `/secret-scan`    | GitLeaks | ค้นหา API keys, passwords, tokens ที่หลุดเข้า code        | Out-of-Loop   |
| `/sbom-generate`  | Syft     | สร้าง Software Bill of Materials (CycloneDX/SPDX)         | Out-of-Loop   |

### Orchestration & Reporting

| Skill                | ทำอะไร                                                      | Decision Loop |
| -------------------- | ----------------------------------------------------------- | ------------- |
| `/devsecops-setup`   | ตรวจจับ tech stack + แนะนำ scan profile + สร้าง config      | On-the-Loop   |
| `/full-pipeline`     | รันทุก scan แบบ parallel แล้วรวมผลเป็น unified report       | On-the-Loop   |
| `/compliance-report` | Map findings ไปยัง NIST 800-53, OWASP Top 10, MITRE ATT&CK  | On-the-Loop   |
| `/incident-response` | สร้าง IR playbook ตาม NIST 800-61 เมื่อพบ CRITICAL findings | In-the-Loop   |
| `/security-gate`     | ตัดสินใจ pass/fail ตาม severity policy ก่อน deploy          | In-the-Loop   |

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

| Agent                             | เชี่ยวชาญ                                                       | เครื่องมือ | Routing Cue                 |
| --------------------------------- | --------------------------------------------------------------- | ---------- | --------------------------- |
| **sast-specialist**               | วิเคราะห์ source code, สร้าง custom rules, กรอง false positives | Semgrep    | MUST BE USED when SAST      |
| **dast-specialist**               | ทดสอบ web app, authenticated scanning, API fuzzing              | ZAP        | MUST BE USED when DAST      |
| **sca-specialist**                | ประเมินความเสี่ยง dependency, license compliance, upgrade paths | Grype      | MUST BE USED when SCA       |
| **container-security-specialist** | Dockerfile hardening, image optimization, runtime security      | Trivy      | MUST BE USED when container |
| **iac-security-specialist**       | CIS benchmarks, misconfig detection, policy-as-code             | Checkov    | MUST BE USED when IaC       |
| **secret-scanner-specialist**     | Git history analysis, entropy detection, rotation guidance      | GitLeaks   | MUST BE USED when secret    |
| **sbom-analyst**                  | CycloneDX/SPDX, license compatibility, component inventory      | Syft       | MUST BE USED when SBOM      |

### Universal Experts — ผู้เชี่ยวชาญข้ามสาขา (4 agents)

| Agent                   | หน้าที่                                                          | Routing Cue                        |
| ----------------------- | ---------------------------------------------------------------- | ---------------------------------- |
| **compliance-officer**  | Map findings → NIST 800-53, OWASP Top 10, MITRE ATT&CK, CIS      | Use PROACTIVELY after scans        |
| **threat-modeler**      | วิเคราะห์ภัยคุกคามด้วย STRIDE/PASTA methodology                  | Use PROACTIVELY on arch changes    |
| **vuln-triager**        | จัดลำดับความสำคัญ: CVSS scoring, exploitability, business impact | Use PROACTIVELY after scan results |
| **remediation-advisor** | แนะนำวิธีแก้ไขพร้อมตัวอย่างโค้ด, ประเมิน effort                  | Use PROACTIVELY after triage       |

### Core Team — ทีมหลัก (4 agents)

| Agent                      | หน้าที่                                                          | Routing Cue                        |
| -------------------------- | ---------------------------------------------------------------- | ---------------------------------- |
| **security-code-reviewer** | Code review เชิง security: injection, auth bypass, data exposure | MUST BE USED on code changes       |
| **incident-responder**     | สร้าง IR playbook, กำหนด severity, ติดตามการแก้ไข                | MUST BE USED when CRITICAL found   |
| **report-generator**       | สร้างรายงาน: HTML dashboard, Markdown PR comment, SARIF, JSON    | MUST BE USED for report generation |
| **pipeline-guardian**      | Security gate — ตัดสินใจ pass/fail ก่อน deploy ตาม policy        | MUST BE USED for gate enforcement  |

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

> vuln-triager ยังใช้ STRIDE/PASTA methodology สำหรับ threat modeling ร่วมกับ `threat-modeler` agent

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
Claude Code / MCP Client ──── stdio ────▶ mcp/server.mjs
                                              │
                                ┌─────────────┼─────────────┐
                                ▼             ▼             ▼
                          job-dispatcher  result-collector  mappings/*.json
                                │
                          Docker containers (Semgrep, Grype, Trivy, ...)
```

### MCP Tools

| MCP Tool               | Input                     | Output                       | ทำอะไร                                      |
| ---------------------- | ------------------------- | ---------------------------- | ------------------------------------------- |
| `devsecops_scan`       | tool, target, rules       | job_id + normalized findings | รัน security scan (เลือก tool ได้)          |
| `devsecops_results`    | job_id, format            | formatted results            | ดึงผลลัพธ์ scan ในรูปแบบที่ต้องการ          |
| `devsecops_gate`       | results_file, policy      | PASS/FAIL + violations       | ประเมิน pass/fail ตาม severity policy       |
| `devsecops_compliance` | findings_file, frameworks | cross-walk matrix            | Map findings ไปยัง OWASP/NIST/MITRE         |
| `devsecops_status`     | (none)                    | runner + images status       | ตรวจสอบ Docker + tool images ที่พร้อมใช้งาน |

### ติดตั้ง MCP

```bash
cd mcp && npm install

# ตรวจสอบ
node --check mcp/server.mjs
bash tests/test-mcp-server.sh   # 23 tests
```

MCP server จะถูก load อัตโนมัติผ่าน `.mcp.json` — ไม่ต้องตั้งค่าเพิ่มเติม

---

## Output Formats

ผลลัพธ์จากทุก scan สามารถ export ได้ 4 รูปแบบ:

| Format           | ใช้ทำอะไร                                 | ตัวอย่าง        |
| ---------------- | ----------------------------------------- | --------------- |
| **SARIF** v2.1.0 | Upload ไป GitHub Security tab ← แนะนำ     | `results.sarif` |
| **JSON**         | ใช้กับ CI/CD pipeline หรือ custom tooling | `results.json`  |
| **Markdown**     | แปะเป็น PR comment                        | `results.md`    |
| **HTML**         | Executive dashboard สำหรับผู้บริหาร       | `results.html`  |

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

### Cross-tool Deduplication (v2.0)

เมื่อรันหลาย tools พร้อมกัน (`/full-pipeline`) ระบบจะ deduplicate ผลอัตโนมัติ:

- **Dedup key**: `(cve_id, file, line_start)` สำหรับ file findings, `(cve_id, package)` สำหรับ dependencies
- **On merge**: เก็บ severity สูงสุด, รวม source tools

```bash
bash formatters/dedup-findings.sh --inputs semgrep.json,grype.json,trivy.json --output merged.json
```

---

## Compliance Mapping

Plugin นี้ map ผลลัพธ์จาก CWE ไปยัง compliance frameworks อัตโนมัติ — **66 CWEs** mapped to OWASP, **58 CWEs** to NIST, **48 CWEs** to MITRE:

| Framework          | Version | ใช้ทำอะไร                           |
| ------------------ | ------- | ----------------------------------- |
| **OWASP Top 10**   | 2021    | Web application security categories |
| **NIST SP 800-53** | Rev. 5  | Federal security controls           |
| **MITRE ATT&CK**   | v16     | Adversary tactics & techniques      |
| **CIS Benchmarks** | Various | Configuration hardening baselines   |
| **PCI DSS**        | 4.0.1   | Payment card industry compliance    |
| **CVSS**           | 4.0     | Vulnerability severity scoring      |

> ดูรายละเอียดทั้ง 15 frameworks ที่ติดตามใน [`frameworks.json`](frameworks.json)

---

## Autonomous Security Controls — การป้องกันอัตโนมัติ

Plugin ติดตั้ง 3 hooks ที่ทำงานอัตโนมัติ — ไม่ต้องเรียกคำสั่ง:

| Hook                | ทำงานเมื่อ       | ทำอะไร                                                 |
| ------------------- | ---------------- | ------------------------------------------------------ |
| **session-start**   | เปิด Claude Code | แสดงสถานะ runner + แนะนำ scan ตาม project files (v2.0) |
| **scan-on-write**   | แก้ไข/สร้างไฟล์  | สแกนหา secrets + injection patterns ทันที (500ms)      |
| **pre-commit-gate** | `git commit`     | บล็อก commit ถ้ามี CRITICAL findings ที่ยังไม่แก้      |

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

### Pre-Commit Security Gate

เมื่อ `git commit` ถูกเรียก hook จะตรวจสอบว่ามี CRITICAL findings ที่ยังไม่แก้หรือไม่ — **บล็อกอัตโนมัติ**ตาม severity policy ของ role ปัจจุบัน Gate override ถูกปิดโดย default (`allow_gate_override: false`) ต้องมี security-lead role จึงจะ override ได้

### Smart Project Detection (v2.0)

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
├── Pre-commit checks             ├── + Secret scan (GitLeaks)
├── DOMAIN.md validation          ├── + SAST quick-check (Semgrep)
├── Conventional commits          ├── + Pre-commit security gate
├── Test coverage ≥ 80%           ├── + Full pipeline scan results
└── Architecture fitness          └── + Container/IaC/SCA checks
```

เมื่อติดตั้งทั้ง 2 plugins — hooks ทำงานร่วมกัน (additive, ไม่ conflict)

---

## Project Structure

```
devsecops-ai-team/
├── .claude-plugin/          # Plugin metadata (plugin.json, marketplace.json)
├── .mcp.json                # MCP server declaration (v2.0)
├── .github/workflows/       # CI/CD (validate, security-scan, framework-review, release)
├── agents/                  # 18 AI agents (4 subdirectories)
│   ├── orchestrators/       #   3 orchestrator agents (lead, stack-analyst, configurator)
│   ├── specialists/         #   7 specialist agents (sast, dast, sca, container, iac, secret, sbom)
│   ├── experts/             #   4 expert agents (compliance, threat, triage, remediation)
│   └── core-team/           #   4 core team agents (reviewer, IR, report, guardian)
├── skills/                  # 12 skill definitions (SKILL.md)
│   └── references/          # 10 domain knowledge files (~500-800 lines each)
├── runner/                  # Sidecar Runner (Dockerfile, compose, dispatcher, collector)
├── formatters/              # SARIF, Markdown, HTML, JSON normalizer, dedup (v2.0)
├── mcp/                     # MCP server — 5 tools (v2.0)
│   ├── server.mjs           #   ESM module, stdio transport
│   └── package.json         #   @modelcontextprotocol/sdk + zod
├── mappings/                # CWE→OWASP, CWE→NIST, CWE→MITRE, severity policy
├── templates/               # Report templates (HTML, Markdown)
├── hooks/                   # 3 hooks (session-start, scan-on-write, pre-commit-gate)
├── examples/                # Rules, policies, DOMAIN.md, Semgrep rules
├── scripts/                 # install-runner, install-rules, check-prerequisites
├── tests/                   # 334 tests (validate 223, normalizer 34, MCP 23, runner 28, formatters 11, frameworks 15)
├── docs/                    # INSTALL, TROUBLESHOOTING, AGENT-CATALOG, RUNBOOK, MANDAY
└── frameworks.json          # 15 tracked security frameworks with version info
```

---

## Documentation

| Document                                                        | เนื้อหา                                            |
| --------------------------------------------------------------- | -------------------------------------------------- |
| [INSTALL.md](docs/INSTALL.md)                                   | วิธีติดตั้งแบบ standard, manual, air-gapped, MCP   |
| [AGENT-CATALOG.md](docs/AGENT-CATALOG.md)                       | รายละเอียด 18 agents พร้อม routing cues + triggers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)                   | แก้ปัญหาที่พบบ่อย (8 scenarios)                    |
| [FRAMEWORK-UPDATE-RUNBOOK.md](docs/FRAMEWORK-UPDATE-RUNBOOK.md) | ขั้นตอนอัพเดท framework versions                   |
| [MANDAY-ESTIMATION.md](docs/MANDAY-ESTIMATION.md)               | ROI analysis + cost comparison (10,222% ROI)       |
| [CLAUDE.md](CLAUDE.md)                                          | Architecture + contributing guidelines             |
| [CHANGELOG.md](CHANGELOG.md)                                    | Version history (v1.0.0 → v2.0.1)                  |
| [SECURITY.md](SECURITY.md)                                      | Vulnerability reporting policy                     |

---

## Testing & Quality

```
Validation:  223/223 structural checks passed (incl. MCP + normalizer sections)
Runner:       28/28  normalizer + integration tests passed
Formatters:   11/11  SARIF + Markdown + HTML tests passed
Normalizer:   34/34  severity mapping + multi-array + null safety tests passed
MCP Server:   23/23  config + syntax + tool definitions tests passed
Frameworks:   15/15  staleness checks OK
──────────────────────────────────────────────────
Total:       334/334 checks passed
```

### Run Tests Locally

```bash
bash tests/validate-plugin.sh          # 223 structural checks
bash tests/test-runner.sh              # Runner + normalizer tests
bash tests/test-formatters.sh          # Formatter tests
bash tests/test-normalizer.sh          # Normalizer unit tests (v2.0)
bash tests/test-mcp-server.sh          # MCP server tests (v2.0)
bash tests/check-framework-updates.sh  # Framework staleness check
```

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
5. Run normalizer tests: `bash tests/test-normalizer.sh`
6. Submit a Pull Request

ดูรายละเอียดใน [CLAUDE.md](CLAUDE.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <sub>Built with Claude Code | Powered by Open Source Security Tools</sub>
</p>
