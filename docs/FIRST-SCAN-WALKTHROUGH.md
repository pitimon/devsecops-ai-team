# First Scan Walkthrough / เบื้องหลังการสแกนครั้งแรก

เอกสารนี้อธิบายกลไกเบื้องหลังตั้งแต่คุณพิมพ์คำสั่ง scan จนถึงรายงานผลลัพธ์ เพื่อให้เข้าใจสถาปัตยกรรมและสามารถ customize ได้ตามต้องการ

---

## 1. Skill Matching — จับคู่ keyword กับ SKILL.md

เมื่อคุณพิมพ์ข้อความใน Claude Code เช่น:

```
Scan this project for security vulnerabilities
```

Claude Code จะค้นหา keyword ที่ตรงกับ **SKILL.md frontmatter** ของ plugin ที่ติดตั้งอยู่ แต่ละ skill มี frontmatter กำหนดชื่อ คำอธิบาย และ tools ที่อนุญาต:

```yaml
---
name: sast-scan
description: Run Static Application Security Testing using Semgrep...
argument-hint: "[--rules <ruleset>] [--target <path>]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Grep", "Bash"]
---
```

### การจับคู่ keyword

| คุณพิมพ์                   | Skill ที่ถูกเลือก | เหตุผล                                   |
| -------------------------- | ----------------- | ---------------------------------------- |
| "scan for vulnerabilities" | `/sast-scan`      | keyword match: "scan", "vulnerabilities" |
| "check dependencies"       | `/sca-scan`       | keyword match: "dependencies"            |
| "find secrets"             | `/secret-scan`    | keyword match: "secrets"                 |
| "run full pipeline"        | `/full-pipeline`  | keyword match: "pipeline"                |
| `/sast-scan` (explicit)    | `/sast-scan`      | direct invocation                        |

เมื่อ skill ถูกเลือก Claude Code จะ load เนื้อหา SKILL.md เข้า context ทำให้ AI agent รู้ว่าต้องทำอะไร ใช้ tool อะไร และตาม process ใด

---

## 2. Agent Orchestration — DevSecOps Lead มอบหมายงาน

SKILL.md บอก agent ให้ทำงานตาม **Decision Loop** pattern ที่กำหนด:

### Orchestrator Layer

**DevSecOps Lead** (orchestrator) รับ request แล้วทำหน้าที่:

1. วิเคราะห์ว่าต้องใช้ tool อะไร
2. เลือก specialist ที่เหมาะสมจาก routing table
3. Delegate งานไปยัง specialist

```
DevSecOps Lead (Orchestrator)
  |
  +-- "SAST request" --> SAST Specialist
  +-- "SCA request"  --> SCA Specialist
  +-- "Secrets"      --> Secret Scanner Specialist
  +-- "Container"    --> Container Security Specialist
  +-- "IaC"          --> IaC Security Specialist
  +-- "DAST"         --> DAST Specialist
  +-- "Multi-tool"   --> Pipeline Guardian (orchestrates parallel)
```

### Specialist Layer

**SAST Specialist** (ในตัวอย่างนี้) รับหน้าที่:

1. ตรวจสอบ target path ว่ามีอยู่จริง
2. Detect ภาษาและเลือก rule pack ที่เหมาะสม
3. สั่งรัน scan ผ่าน `job-dispatcher.sh`
4. รอผลแล้วส่งไปยัง normalizer

### Decision Loop Classification

แต่ละ skill กำหนดระดับ autonomy ไว้ชัดเจน:

- **Out-of-Loop** — AI ทำงานอัตโนมัติ เช่น SAST scan (lint-level)
- **On-the-Loop** — AI ทำงานแต่มนุษย์ต้อง approve เช่น auto-fix
- **In-the-Loop** — มนุษย์ต้อง confirm ทุกขั้นตอน เช่น secret verification

---

## 3. Docker Container Execution — รัน tool แบบ isolated

`job-dispatcher.sh` เป็นตัวกลางที่ส่งงานไปยัง Docker container ของแต่ละ tool:

### Security Isolation

ทุก container รันด้วย security constraints:

```bash
docker run --rm \
  -v /path/to/project:/workspace:ro \   # read-only mount
  -v /results:/results \                 # output directory
  --network=none \                       # no network access
  returntocorp/semgrep:latest \
  semgrep --config "p/security-audit" --json \
  --output "/results/semgrep-results.json" \
  /workspace
```

| Constraint       | ความหมาย                                               |
| ---------------- | ------------------------------------------------------ |
| `--rm`           | ลบ container หลังรันเสร็จ                              |
| `:ro`            | Source code mount แบบ read-only — tool แก้ไขโค้ดไม่ได้ |
| `--network=none` | ตัดการเชื่อมต่อ network — ป้องกัน data exfiltration    |
| `/results`       | Output directory แยกจาก source code                    |

### Runner Modes

Plugin รองรับ 2 modes:

- **Minimal mode** (default) — ใช้ `docker run --rm` ทุกครั้ง เหมาะสำหรับ development
- **Full mode** — ใช้ persistent containers ผ่าน Docker Compose เหมาะสำหรับ CI/CD ที่ scan บ่อย

### Tool Routing

`job-dispatcher.sh` route ไปยัง tool ที่เหมาะสม:

| Tool       | Image                               | Scan Type | Timeout   |
| ---------- | ----------------------------------- | --------- | --------- |
| Semgrep    | `returntocorp/semgrep:latest`       | SAST      | 120s      |
| GitLeaks   | `zricethezav/gitleaks:latest`       | Secrets   | 60s       |
| Grype      | `anchore/grype:latest`              | SCA       | 120s      |
| Trivy      | `aquasec/trivy:latest`              | Container | 120s      |
| Checkov    | `bridgecrew/checkov:latest`         | IaC       | 120s      |
| ZAP        | `ghcr.io/zaproxy/zaproxy:stable`    | DAST      | 120-1800s |
| Syft       | `anchore/syft:latest`               | SBOM      | 120s      |
| Nuclei     | `projectdiscovery/nuclei:latest`    | DAST      | 120-600s  |
| TruffleHog | `trufflesecurity/trufflehog:latest` | Secrets   | 120s      |
| kube-bench | `aquasec/kube-bench:latest`         | K8s CIS   | 300s      |

---

## 4. Result Normalization — แปลง raw JSON เป็น Unified Finding Schema

แต่ละ tool ให้ output ในรูปแบบที่แตกต่างกัน `json-normalizer.sh` แปลงผลทุก tool ให้เป็น schema เดียวกัน:

### ตัวอย่าง: Semgrep raw output

```json
{
  "results": [
    {
      "check_id": "python.lang.security.audit.dangerous-system-call",
      "path": "app.py",
      "start": { "line": 65, "col": 4 },
      "end": { "line": 65, "col": 44 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected os.system() call with user input...",
        "metadata": {
          "cwe": ["CWE-78"],
          "confidence": "HIGH"
        },
        "lines": "    output = os.system(f\"ping -c 1 {host}\")"
      }
    }
  ]
}
```

### หลัง Normalization: Unified Finding Schema

```json
{
  "findings": [
    {
      "id": "FINDING-20260303-001",
      "source_tool": "semgrep",
      "scan_type": "sast",
      "severity": "HIGH",
      "confidence": "HIGH",
      "title": "Detected os.system() call with user input...",
      "cwe_id": "CWE-78",
      "location": {
        "file": "app.py",
        "line_start": 65,
        "line_end": 65,
        "snippet": "    output = os.system(f\"ping -c 1 {host}\")"
      },
      "rule_id": "python.lang.security.audit.dangerous-system-call",
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

### Severity Mapping

Normalizer แปลง severity ของแต่ละ tool ให้เป็นมาตรฐานเดียวกัน:

| Tool     | Original      | Normalized |
| -------- | ------------- | ---------- |
| Semgrep  | ERROR         | HIGH       |
| Semgrep  | WARNING       | MEDIUM     |
| Grype    | Critical      | CRITICAL   |
| Trivy    | HIGH          | HIGH       |
| GitLeaks | (all secrets) | CRITICAL   |
| Checkov  | FAILED        | HIGH       |
| ZAP      | 3 (High)      | HIGH       |

---

## 5. Triage & Prioritization — จัดลำดับความสำคัญ

หลัง normalization ระบบจะ triage findings ตามหลายปัจจัย:

### Severity Scoring

```
CRITICAL  →  ต้องแก้ไขทันที (เช่น secrets in code, RCE)
HIGH      →  ควรแก้ไขก่อน merge (เช่น SQL injection, command injection)
MEDIUM    →  ควรแก้ไขในรอบถัดไป (เช่น weak crypto)
LOW       →  พิจารณาแก้ไขเมื่อมีเวลา (เช่น information disclosure)
INFO      →  ข้อมูลเพิ่มเติม ไม่จำเป็นต้องแก้ไข
```

### Enrichment — เพิ่ม context

ระบบเพิ่มข้อมูล compliance mapping อัตโนมัติ:

- **OWASP Top 10** (2021 + 2025) — เช่น CWE-89 maps to A03:2021 (Injection), A05:2025 (Injection)
- **NIST SP 800-53** — เช่น CWE-89 maps to SI-10 (Input Validation)
- **MITRE ATT&CK** — เช่น CWE-89 maps to T1190 (Exploit Public-Facing Application)
- **NCSA** — Thai national cybersecurity standards
- **SOC 2** — Trust services criteria mapping
- **ISO 27001** — Information security controls

Mapping data มาจากไฟล์ใน `mappings/` directory (7 mapping files, 380+ CWE entries)

### Deduplication

เมื่อใช้หลาย tools พร้อมกัน (เช่น full pipeline) อาจพบ findings ซ้ำกัน `dedup-findings.sh` จะ:

1. เปรียบเทียบ file + line + CWE
2. รวม findings ที่ซ้ำกัน โดยเก็บ source tools ทั้งหมดไว้
3. ใช้ severity สูงสุดจาก tools ที่พบ

---

## 6. Output — รูปแบบรายงาน

Plugin รองรับ 8 output formats:

| Format        | Use Case                                          | คำสั่ง                |
| ------------- | ------------------------------------------------- | --------------------- |
| **JSON**      | Programmatic processing, API integration          | Default output        |
| **SARIF**     | GitHub Code Scanning, IDE integration             | `--format sarif`      |
| **Markdown**  | Pull request comments, documentation              | `--format md`         |
| **HTML**      | Standalone report สำหรับ stakeholders             | `--format html`       |
| **PDF**       | Formal security assessment reports                | `--format pdf`        |
| **CSV**       | Spreadsheet analysis, executive reporting         | `--format csv`        |
| **VEX**       | Vulnerability exchange (CycloneDX / OpenVEX)      | `--format vex`        |
| **Dashboard** | Interactive HTML dashboard (Alpine.js + Chart.js) | `/security-dashboard` |

### ตัวอย่าง SARIF output

SARIF format ใช้สำหรับ upload เข้า GitHub Code Scanning หรือเปิดใน VS Code:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "version": "latest"
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.dangerous-system-call",
          "level": "error",
          "message": {
            "text": "Detected os.system() call with user input..."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app.py" },
                "region": { "startLine": 65 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 7. Customizing Scans / ปรับแต่งการสแกน

### Custom Semgrep Rules

Plugin มี **84 custom Semgrep rules** ครอบคลุม OWASP Top 10 ทั้ง 2021 และ 2025:

```bash
rules/
  a01-access-control-rules.yml   # 8 rules — Broken Access Control
  a02-crypto-rules.yml           # 6 rules — Cryptographic Failures
  a03-injection-rules.yml        # 11 rules — Injection
  a04-insecure-design-rules.yml  # 4 rules — Insecure Design
  a05-misconfig-rules.yml        # 6 rules — Security Misconfiguration
  a06-component-rules.yml        # 5 rules — Vulnerable Components
  a07-auth-rules.yml             # 5 rules — Authentication Failures
  a08-integrity-rules.yml        # 5 rules — Software Integrity Failures
  a09-logging-rules.yml          # 7 rules — Logging Failures
  a10-ssrf-rules.yml             # 7 rules — SSRF (A10:2021 / A01:2025)
  a10-exception-rules.yml        # 4 rules — Exception Handling (A10:2025)
  k8s-manifest-rules.yml         # 8 rules — Kubernetes manifests
  graphql-rules.yml              # 8 rules — GraphQL-specific
```

ใช้ custom rules ใน scan:

```
/sast-scan --rules rules/a03-injection-rules.yml --target ./src
```

### Multi-Tool DAG Pipeline

สำหรับ scan หลาย tools พร้อมกัน ใช้ pipeline engine ที่รัน tools แบบ parallel ตาม dependency graph:

```yaml
# runner/pipelines/default.yml
stages:
  - name: scan
    parallel:
      - tool: semgrep
      - tool: gitleaks
      - tool: grype
      - tool: trivy
  - name: normalize
    depends_on: [scan]
    run: json-normalizer.sh
  - name: dedup
    depends_on: [normalize]
    run: dedup-findings.sh
  - name: report
    depends_on: [dedup]
    run: format-output.sh
```

```
/full-pipeline --target ./my-project
```

### Compliance-Focused Scanning

ตรวจสอบ compliance กับ framework เฉพาะ:

```
/compliance-check --framework owasp --target ./src
/compliance-check --framework ncsa --target ./src
/compliance-check --framework iso27001 --target ./src
```

รองรับ 7 compliance frameworks: OWASP, NIST, MITRE, NCSA, PDPA, SOC 2, ISO 27001

---

## Further Reading / อ่านเพิ่มเติม

- [ARCHITECTURE.md](ARCHITECTURE.md) — สถาปัตยกรรมเชิงลึก
- [FEATURES.md](FEATURES.md) — รายละเอียดทุก feature
- [CI-INTEGRATION.md](CI-INTEGRATION.md) — ตั้งค่า CI/CD pipeline
- [AGENT-CATALOG.md](AGENT-CATALOG.md) — รายละเอียด 18 agents
