<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-Plugin-blueviolet?style=for-the-badge&logo=anthropic" alt="Claude Code Plugin">
  <img src="https://img.shields.io/badge/Agents-18-blue?style=for-the-badge" alt="18 Agents">
  <img src="https://img.shields.io/badge/Skills-12-green?style=for-the-badge" alt="12 Skills">
  <img src="https://img.shields.io/badge/Tools-7-orange?style=for-the-badge" alt="7 Tools">
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
# ติดตั้งผ่าน Claude Code
claude plugin add pitimon/devsecops-ai-team
```

### 2. ตรวจสอบ Prerequisites

```bash
# ต้องมี Docker Engine 20.10+ และ Docker Compose v2+
bash scripts/check-prerequisites.sh
```

### 3. เริ่มใช้งาน

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
           │  /sast-scan, /secret-scan, /full-pipeline, ...
           ▼
┌─────────────────────────────────────────────────────────────┐
│                    18 AI Agents                              │
│                                                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ Orchestrators│ │  Specialists │ │  Experts + Core Team │ │
│  │  (3 agents)  │ │  (7 agents)  │ │     (8 agents)       │ │
│  │              │ │              │ │                      │ │
│  │ devsecops-   │ │ sast         │ │ compliance-officer   │ │
│  │   lead       │ │ dast         │ │ threat-modeler       │ │
│  │ stack-       │ │ sca          │ │ vuln-triager         │ │
│  │   analyst    │ │ container    │ │ remediation-advisor  │ │
│  │ team-        │ │ iac          │ │ code-reviewer        │ │
│  │   configurator│ │ secret      │ │ incident-responder   │ │
│  │              │ │ sbom         │ │ report-generator     │ │
│  │              │ │              │ │ pipeline-guardian    │ │
│  └──────────────┘ └──────────────┘ └──────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │ bash → job-dispatcher.sh
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Sidecar Runner (Alpine + Docker CLI)           │
│              result-collector.sh → normalize → format       │
└──┬──────┬──────┬──────┬──────┬──────┬───────┬───────────────┘
   │      │      │      │      │      │       │
 ┌─▼─┐ ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐
 │Sem│ │Grype││Trivy││Chek ││GitL ││ ZAP ││Syft │
 │gre│ │     ││     ││ov   ││eaks ││     ││     │
 │p  │ │ SCA ││ Con ││ IaC ││ Sec ││DAST ││SBOM │
 └───┘ └─────┘└─────┘└─────┘└─────┘└─────┘└─────┘
         All tools run locally in Docker containers
```

### How It Works

1. **คุณพิมพ์คำสั่ง** เช่น `/sast-scan` ใน Claude Code
2. **Orchestrator agent** วิเคราะห์ project และเลือก specialist ที่เหมาะสม
3. **Specialist agent** ส่งงานผ่าน `job-dispatcher.sh` ไปยัง Docker container
4. **Tool** (เช่น Semgrep) รันใน container แล้วส่งผลกลับ
5. **Result collector** normalize ผลลัพธ์เป็น Unified Finding Schema
6. **Expert agents** วิเคราะห์: จัดลำดับความสำคัญ, map compliance, แนะนำการแก้ไข
7. **Report generator** สร้างรายงานในรูปแบบที่ต้องการ (SARIF/JSON/Markdown/HTML)

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

| Agent                      | หน้าที่                                                                   |
| -------------------------- | ------------------------------------------------------------------------- |
| **devsecops-lead**         | หัวหน้าทีม — วิเคราะห์ request แล้วส่งต่อให้ specialist ที่เหมาะสม        |
| **security-stack-analyst** | ตรวจจับ tech stack (ภาษา, framework, container, IaC) เพื่อเลือกเครื่องมือ |
| **team-configurator**      | ตั้งค่า agent mappings อัตโนมัติตาม project ที่ตรวจเจอ                    |

### Security Specialists — ผู้เชี่ยวชาญเฉพาะด้าน (7 agents)

| Agent                             | เชี่ยวชาญ                                                       | เครื่องมือ |
| --------------------------------- | --------------------------------------------------------------- | ---------- |
| **sast-specialist**               | วิเคราะห์ source code, สร้าง custom rules, กรอง false positives | Semgrep    |
| **dast-specialist**               | ทดสอบ web app, authenticated scanning, API fuzzing              | ZAP        |
| **sca-specialist**                | ประเมินความเสี่ยง dependency, license compliance, upgrade paths | Grype      |
| **container-security-specialist** | Dockerfile hardening, image optimization, runtime security      | Trivy      |
| **iac-security-specialist**       | CIS benchmarks, misconfig detection, policy-as-code             | Checkov    |
| **secret-scanner-specialist**     | Git history analysis, entropy detection, rotation guidance      | GitLeaks   |
| **sbom-analyst**                  | CycloneDX/SPDX, license compatibility, component inventory      | Syft       |

### Universal Experts — ผู้เชี่ยวชาญข้ามสาขา (4 agents)

| Agent                   | หน้าที่                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| **compliance-officer**  | Map findings → NIST 800-53, OWASP Top 10, MITRE ATT&CK, CIS      |
| **threat-modeler**      | วิเคราะห์ภัยคุกคามด้วย STRIDE/PASTA methodology                  |
| **vuln-triager**        | จัดลำดับความสำคัญ: CVSS scoring, exploitability, business impact |
| **remediation-advisor** | แนะนำวิธีแก้ไขพร้อมตัวอย่างโค้ด, ประเมิน effort                  |

### Core Team — ทีมหลัก (4 agents)

| Agent                      | หน้าที่                                                          |
| -------------------------- | ---------------------------------------------------------------- |
| **security-code-reviewer** | Code review เชิง security: injection, auth bypass, data exposure |
| **incident-responder**     | สร้าง IR playbook, กำหนด severity, ติดตามการแก้ไข                |
| **report-generator**       | สร้างรายงาน: HTML dashboard, Markdown PR comment, SARIF, JSON    |
| **pipeline-guardian**      | Security gate — ตัดสินใจ pass/fail ก่อน deploy ตาม policy        |

---

## Output Formats

ผลลัพธ์จากทุก scan สามารถ export ได้ 4 รูปแบบ:

| Format           | ใช้ทำอะไร                                 | ตัวอย่าง        |
| ---------------- | ----------------------------------------- | --------------- |
| **SARIF** v2.1.0 | Upload ไป GitHub Security tab ← แนะนำ     | `results.sarif` |
| **JSON**         | ใช้กับ CI/CD pipeline หรือ custom tooling | `results.json`  |
| **Markdown**     | แปะเป็น PR comment                        | `results.md`    |
| **HTML**         | Executive dashboard สำหรับผู้บริหาร       | `results.html`  |

---

## Compliance Mapping

Plugin นี้ map ผลลัพธ์จาก CWE ไปยัง 5+ compliance frameworks อัตโนมัติ:

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

## Hook System — การป้องกันอัตโนมัติ

Plugin ติดตั้ง 3 hooks ที่ทำงานอัตโนมัติ:

| Hook                | ทำงานเมื่อ       | ทำอะไร                                            |
| ------------------- | ---------------- | ------------------------------------------------- |
| **session-start**   | เปิด Claude Code | แสดงสถานะ runner + scan ที่แนะนำ                  |
| **scan-on-write**   | แก้ไข/สร้างไฟล์  | สแกนหา secrets + injection patterns ทันที (500ms) |
| **pre-commit-gate** | `git commit`     | บล็อก commit ถ้ามี CRITICAL findings ที่ยังไม่แก้ |

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
├── .claude-plugin/          # Plugin metadata
├── .github/workflows/       # CI/CD (validate, security-scan, framework-review, release)
├── agents/                  # 18 AI agents (4 subdirectories)
│   ├── orchestrators/       #   3 orchestrator agents
│   ├── specialists/         #   7 specialist agents
│   ├── experts/             #   4 expert agents
│   └── core-team/           #   4 core team agents
├── skills/                  # 12 skill definitions (SKILL.md)
│   └── references/          # 10 domain knowledge files (~500-800 lines each)
├── runner/                  # Sidecar Runner (Dockerfile, compose, scripts)
├── formatters/              # SARIF, Markdown, HTML, JSON normalizer
├── mappings/                # CWE→OWASP, CWE→NIST, CWE→MITRE, severity policy
├── templates/               # Report templates (HTML, Markdown)
├── hooks/                   # 3 hooks (session-start, scan-on-write, pre-commit-gate)
├── examples/                # Rules, policies, DOMAIN.md, Semgrep rules
├── scripts/                 # install-runner, install-rules, check-prerequisites
├── tests/                   # validate-plugin (207 checks), test-runner, test-formatters
├── docs/                    # INSTALL, TROUBLESHOOTING, AGENT-CATALOG, etc.
└── frameworks.json          # 15 tracked security frameworks with version info
```

---

## Documentation

| Document                                                        | เนื้อหา                                              |
| --------------------------------------------------------------- | ---------------------------------------------------- |
| [INSTALL.md](docs/INSTALL.md)                                   | วิธีติดตั้งแบบ standard, manual, และ air-gapped      |
| [AGENT-CATALOG.md](docs/AGENT-CATALOG.md)                       | รายละเอียด 18 agents ทั้งหมดพร้อม trigger conditions |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)                   | แก้ปัญหาที่พบบ่อย (8 scenarios)                      |
| [FRAMEWORK-UPDATE-RUNBOOK.md](docs/FRAMEWORK-UPDATE-RUNBOOK.md) | ขั้นตอนอัพเดท framework versions                     |
| [MANDAY-ESTIMATION.md](docs/MANDAY-ESTIMATION.md)               | WBS + cost estimation สำหรับ implementation          |
| [CLAUDE.md](CLAUDE.md)                                          | Architecture + contributing guidelines               |
| [CHANGELOG.md](CHANGELOG.md)                                    | Version history                                      |

---

## Testing & Quality

```
Validation:  207/207 structural checks passed
Runner:       28/28  normalizer + integration tests passed
Formatters:   11/11  SARIF + Markdown + HTML tests passed
Frameworks:   15/15  staleness checks OK
──────────────────────────────────────────────────
Total:       261/261 checks passed
```

### Run Tests Locally

```bash
bash tests/validate-plugin.sh          # 207 structural checks
bash tests/test-runner.sh              # Runner + normalizer tests
bash tests/test-formatters.sh          # Formatter tests
bash tests/check-framework-updates.sh  # Framework staleness check
```

---

## Requirements

| Requirement    | Minimum | Recommended |
| -------------- | ------- | ----------- |
| Docker Engine  | 20.10+  | 25.0+       |
| Docker Compose | v2.0+   | v2.24+      |
| Disk Space     | 2 GB    | 5 GB        |
| Claude Code    | Latest  | Latest      |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, etc.
4. Run validation: `bash tests/validate-plugin.sh`
5. Submit a Pull Request

ดูรายละเอียดใน [CLAUDE.md](CLAUDE.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <sub>Built with Claude Code | Powered by Open Source Security Tools</sub>
</p>
