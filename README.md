# DevSecOps AI Team — Enterprise Plugin Skill Pack

> ทีม AI 18 ตัว + 12 Skills สำหรับ DevSecOps Full Pipeline ใช้ Open Source tools ทำงานผ่าน Docker containers

[![Plugin Validation](https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml/badge.svg)](https://github.com/pitimon/devsecops-ai-team/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Claude Code Plugin Skill Pack ที่รวม AI Agents ทำงานด้าน DevSecOps แบบครบวงจร:

- **SAST** (Static Analysis) — Semgrep
- **DAST** (Dynamic Analysis) — ZAP
- **SCA** (Software Composition Analysis) — Grype
- **Container Security** — Trivy
- **IaC Security** — Checkov
- **Secret Scanning** — GitLeaks
- **SBOM Generation** — Syft

ทุกเครื่องมือทำงานผ่าน Docker containers บนเครื่อง local ด้วย Sidecar Runner architecture

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Orchestrators (3)    │  Specialists (7)     │  Experts (4)         │
│  devsecops-lead       │  sast-specialist     │  compliance-officer  │
│  security-stack-      │  dast-specialist     │  threat-modeler      │
│    analyst            │  sca-specialist      │  vuln-triager        │
│  team-configurator    │  container-security  │  remediation-advisor │
│                       │  iac-security        │                      │
│  Core Team (4)        │  secret-scanner      │                      │
│  security-code-       │  sbom-analyst        │                      │
│    reviewer           │                      │                      │
│  incident-responder   │                      │                      │
│  report-generator     │                      │                      │
│  pipeline-guardian    │                      │                      │
└───────────────────────┴──────────────────────┴──────────────────────┘
                           │
                    job-dispatcher.sh
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Sidecar Runner (Alpine + Docker CLI)           │
└──┬──────┬──────┬──────┬──────┬──────┬───────┬───────────────┘
   │      │      │      │      │      │       │
┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐
│Semg ││Grype││Trivy││Check││GitL ││ ZAP ││Syft │
│rep  ││     ││     ││ov   ││eaks ││     ││     │
└─────┘└─────┘└─────┘└─────┘└─────┘└─────┘└─────┘
```

## Installation

### Quick Install

```bash
claude plugin add pitimon/devsecops-ai-team
```

### Manual Install

```bash
git clone https://github.com/pitimon/devsecops-ai-team.git
claude plugin add ./devsecops-ai-team
```

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2+
- 2GB+ free disk space (for tool images)

ดูรายละเอียดเพิ่มเติมที่ [docs/INSTALL.md](docs/INSTALL.md)

## Skills (12 commands)

| Skill                | Tool     | Description                               |
| -------------------- | -------- | ----------------------------------------- |
| `/devsecops-setup`   | —        | ตั้งค่า DevSecOps สำหรับ project ปัจจุบัน |
| `/sast-scan`         | Semgrep  | Static code analysis                      |
| `/dast-scan`         | ZAP      | Dynamic web application testing           |
| `/sca-scan`          | Grype    | Dependency vulnerability scanning         |
| `/container-scan`    | Trivy    | Container image security                  |
| `/iac-scan`          | Checkov  | Infrastructure as Code scanning           |
| `/secret-scan`       | GitLeaks | Secret/credential detection               |
| `/sbom-generate`     | Syft     | Software Bill of Materials                |
| `/full-pipeline`     | All      | รันทุก scan แบบ parallel                  |
| `/compliance-report` | —        | สร้าง compliance mapping report           |
| `/incident-response` | —        | สร้าง IR playbook                         |
| `/security-gate`     | —        | ตัดสิน pass/fail ก่อน deploy              |

## Agents (18 ตัว)

### Orchestrators (ผู้ประสานงาน)

- **devsecops-lead** — Senior tech lead สำหรับ security workflows
- **security-stack-analyst** — ตรวจจับ tech stack + routing
- **team-configurator** — Auto-configure agent mappings

### Security Specialists (ผู้เชี่ยวชาญเฉพาะทาง)

- **sast-specialist** — Deep static analysis (Semgrep)
- **dast-specialist** — Dynamic testing (ZAP)
- **sca-specialist** — Supply chain security (Grype)
- **container-security-specialist** — Container hardening (Trivy)
- **iac-security-specialist** — IaC scanning (Checkov)
- **secret-scanner-specialist** — Credential detection (GitLeaks)
- **sbom-analyst** — Software composition (Syft)

### Universal Experts (ผู้เชี่ยวชาญข้ามสาขา)

- **compliance-officer** — NIST/OWASP/MITRE/CIS mapping
- **threat-modeler** — STRIDE/PASTA threat modeling
- **vuln-triager** — Severity assessment + prioritization
- **remediation-advisor** — Fix suggestions + patch guidance

### Core Team (ทีมหลัก)

- **security-code-reviewer** — Security-focused code review
- **incident-responder** — IR playbook + coordination
- **report-generator** — Executive dashboards + reports
- **pipeline-guardian** — CI/CD security gates

## Compliance Frameworks

| Framework      | Version | Mapping             |
| -------------- | ------- | ------------------- |
| OWASP Top 10   | 2021    | CWE → A01-A10       |
| NIST 800-53    | Rev. 5  | CWE → Controls      |
| MITRE ATT&CK   | v16     | CWE → Techniques    |
| CIS Benchmarks | Various | Container/K8s/Cloud |
| CVSS           | 4.0     | Severity scoring    |

## Output Formats

- **SARIF** v2.1.0 — GitHub Security tab integration
- **JSON** — Machine-readable unified format
- **Markdown** — PR comment-ready
- **HTML** — Executive dashboard

## Governance Integration

Plugin นี้ขยาย (extend) จาก [claude-governance](https://github.com/pitimon/claude-governance):

- Three Loops Decision Model สำหรับ DevSecOps
- Extended fitness functions (security scans at pre-commit/pre-PR)
- ADR template with threat model + compliance fields
- Cross-plugin hooks ทำงานร่วมกันได้

## Three Loops Decision Model

| Level                           | DevSecOps Actions                                               |
| ------------------------------- | --------------------------------------------------------------- |
| **Out-of-Loop** (AI autonomous) | Secret scan on write, format results, SBOM, lint-level SAST     |
| **On-the-Loop** (AI proposes)   | New scan rules, severity policy, scan config, compliance report |
| **In-the-Loop** (Human decides) | Gate override, IR escalation, vuln suppression, DAST target     |

## Contributing

ดู [CLAUDE.md](CLAUDE.md) สำหรับ contributing guidelines

## License

MIT License - see [LICENSE](LICENSE)
