# Demo Guide — DevSecOps AI Team

คู่มือสำหรับสาธิต plugin ในงาน workshop, conference, หรือ sales demo
รองรับ 3 scenarios ตามเวลาที่มี: 5 นาที / 10 นาที / 15 นาที

## Pre-Demo Checklist

### 1. Docker พร้อมใช้งาน

```bash
docker info          # ต้องเห็น Server Version
docker compose version   # ต้องเป็น v2+
```

### 2. Pull Docker images ล่วงหน้า (ใช้เวลา ~5 นาที ครั้งแรก)

```bash
docker pull returntocorp/semgrep:latest       # SAST — ~800MB
docker pull anchore/grype:latest              # SCA — ~120MB
docker pull zricethezav/gitleaks:latest       # Secret scanning — ~50MB
docker pull aquasec/trivy:latest              # Container scanning — ~200MB
docker pull anchore/syft:latest               # SBOM generation — ~100MB
```

> **Tip:** ถ้า demo full pipeline ให้ pull เพิ่ม:
>
> ```bash
> docker pull bridgecrew/checkov:latest        # IaC scanning
> docker pull ghcr.io/zaproxy/zaproxy:stable   # DAST (ZAP)
> docker pull projectdiscovery/nuclei:latest   # DAST (Nuclei)
> ```

### 3. Plugin ติดตั้งแล้ว

```bash
# ตรวจสอบว่า plugin ทำงาน
claude "/devsecops-setup"
```

### 4. Demo project พร้อม

```bash
ls tests/fixtures/demo-project/
# ต้องเห็น: app.py  Dockerfile  package.json  README.md
```

### 5. Terminal setup

- Font size: **18pt+** (ผู้ชมมองเห็นชัด)
- Theme: Dark background + high contrast
- Split terminal: ซ้ายสำหรับ commands, ขวาสำหรับ results
- ปิด notification ทั้งหมด

---

## Scenario A: Quick Win (5 นาที)

**เป้าหมาย:** แสดงว่า security scanning ทำได้ง่ายแค่พิมพ์คำสั่งเดียว

### Step 1: SAST Scan on Demo Project

```bash
claude "/sast-scan --target tests/fixtures/demo-project/"
```

**Expected findings (6-8 รายการ):**

| CWE     | ช่องโหว่                         | ไฟล์         | ความรุนแรง |
| ------- | -------------------------------- | ------------ | ---------- |
| CWE-89  | SQL Injection (f-string)         | app.py:44    | Critical   |
| CWE-89  | SQL Injection (concatenation)    | app.py:56    | Critical   |
| CWE-78  | OS Command Injection (os.system) | app.py:74    | Critical   |
| CWE-78  | OS Command Injection (os.popen)  | app.py:83    | High       |
| CWE-327 | Broken Crypto (MD5)              | app.py:65    | Medium     |
| CWE-798 | Hard-coded Credentials           | app.py:29-30 | High       |
| CWE-532 | Sensitive Data in Logs           | app.py:93-95 | Medium     |
| CWE-22  | Path Traversal                   | app.py:104   | High       |

**Talking point:** _"เห็นไหมครับ แค่คำสั่งเดียว Semgrep วิเคราะห์ code ได้ทั้งไฟล์ พบ 6-8 ช่องโหว่ ตั้งแต่ SQL Injection ไปจนถึง hard-coded credentials ใช้เวลาไม่ถึง 30 วินาที"_

### Step 2: Auto-Fix Suggestion

```bash
claude "/auto-fix --severity critical --target tests/fixtures/demo-project/"
```

**Expected output:** AI เสนอ patch สำหรับ SQL Injection:

```python
# Before (VULNERABLE)
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor = db.execute(query)

# After (FIXED — parameterized query)
query = "SELECT * FROM users WHERE username = ?"
cursor = db.execute(query, (username,))
```

**Talking point:** _"AI ไม่แค่บอกว่าผิดตรงไหน แต่เสนอ fix ให้เลย แบบ On-the-Loop คือ AI เสนอ คนตัดสินใจ approve"_

### Step 3: SARIF Output

```bash
claude "/sast-scan --target tests/fixtures/demo-project/ --format sarif"
```

**Talking point:** _"output เป็น SARIF standard เปิดใน VS Code, GitHub Security tab, หรือ Defect Dojo ได้เลย ไม่ vendor lock-in"_

### Step 4: Quick Summary

รวมสิ่งที่ demo ได้ใน 5 นาที:

- SAST scan พบช่องโหว่ 6-8 รายการ
- Auto-fix เสนอ patch ให้ทันที
- Output เป็น SARIF standard
- ทั้งหมดใช้ open-source tools — **ไม่มีค่าใช้จ่าย license**

---

## Scenario B: Full Pipeline (10 นาที)

**เป้าหมาย:** แสดง multi-tool orchestration, dashboard, และ compliance mapping

### Step 1: Full Pipeline Scan

```bash
claude "/full-pipeline --target tests/fixtures/demo-project/"
```

pipeline จะรัน 5 tools พร้อมกัน (DAG-based):

```
Semgrep (SAST) ─┐
Grype (SCA) ────┤
GitLeaks (Secret)┤──→ Normalize ──→ Dedup ──→ Format
Trivy (Container)┤
Checkov (IaC) ──┘
```

**Expected findings (~20-30 รายการรวม):**

- **SAST (Semgrep):** 6-8 code vulnerabilities
- **SCA (Grype):** 8-12 vulnerable dependencies (lodash, express, jsonwebtoken, etc.)
- **Secrets (GitLeaks):** 1-2 hard-coded credentials
- **Container (Trivy):** 3-5 CVEs from node:14 base image
- **IaC (Checkov):** 3-4 Dockerfile misconfigurations

**Talking point:** _"5 tools ทำงานพร้อมกันแบบ DAG pipeline ไม่ต้อง config อะไรเลย plugin จัดการ orchestration ให้ทั้งหมด"_

### Step 2: Security Dashboard

```bash
claude "/full-pipeline --target tests/fixtures/demo-project/ --format dashboard"
```

**Expected output:** Self-contained HTML file พร้อม:

- Severity distribution chart (Chart.js)
- Findings table with filters (Alpine.js)
- Trend comparison (ถ้ามี scan history)
- เปิดใน browser ได้เลย ไม่ต้องมี server

**Talking point:** _"dashboard นี้ส่งให้ผู้บริหารดูได้เลย เป็นไฟล์ HTML เดียว ไม่ต้องติดตั้งอะไรเพิ่ม"_

### Step 3: NCSA Compliance Check

```bash
claude "/compliance-report --framework ncsa --target tests/fixtures/demo-project/"
```

**Expected output:**

```
NCSA Compliance Status
━━━━━━━━━━━━━━━━━━━━━
Category 1 (Confidentiality): 3 findings — FAIL
Category 2 (Integrity):       1 finding  — WARN
Category 4 (Access Control):  2 findings — FAIL
Category 5 (Monitoring):      1 finding  — PASS (with caveats)

Overall: NOT COMPLIANT — 6 items require remediation
Deadline: September 16, 2026
```

**Talking point:** _"NCSA กำหนดให้หน่วยงานสำคัญต้อง comply ภายใน 16 กันยายน 2026 plugin map findings ไปยังมาตรฐานให้อัตโนมัติ"_

### Step 4: PDPA Compliance Check

```bash
claude "/compliance-report --framework pdpa --target tests/fixtures/demo-project/"
```

**Expected output:**

```
PDPA Compliance Status
━━━━━━━━━━━━━━━━━━━━━
Section 23 (Consent):         PASS
Section 26 (Sensitive Data):  2 findings — FAIL
Section 37 (Security):        4 findings — FAIL
Section 77 (Breach Notify):   1 finding  — WARN

Overall: NOT COMPLIANT — 7 items require remediation
```

**Talking point:** _"PDPA คือ พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล มีผลบังคับใช้แล้ว ถ้าข้อมูลรั่ว ปรับสูงสุด 5 ล้านบาท plugin ช่วยตรวจว่า code จัดการ personal data ถูกต้องไหม"_

### Step 5: Quick Summary

รวมสิ่งที่ demo ได้ใน 10 นาที:

- Full pipeline orchestration (5 tools พร้อมกัน)
- Self-contained HTML dashboard
- NCSA compliance mapping (deadline กันยายน 2026)
- PDPA compliance mapping (บังคับใช้แล้ว)
- ทั้งหมดรองรับ 7 compliance frameworks

---

## Scenario C: Enterprise Story (15 นาที)

**เป้าหมาย:** แสดง enterprise-grade features ที่ commercial tools เท่านั้นที่มี

### Steps 1-4: ทำ Scenario B ก่อน (10 นาที)

(ดูด้านบน)

### Step 5: Custom Semgrep Rules

```bash
# แสดง custom rules ที่เขียนเอง
ls runner/semgrep-rules/
```

**Talking point:** _"เรามี custom Semgrep rules 84 rules ครอบคลุม OWASP Top 10 ทั้ง 2021 และ 2025 รวม K8s manifest rules และ GraphQL rules รวมแล้ว 13 rule files"_

| Rule File                     | จำนวน Rules | ครอบคลุม                        |
| ----------------------------- | ----------- | ------------------------------- |
| a01-access-control-rules.yml  | 8           | OWASP A01:2021 + A01:2025       |
| a02-crypto-rules.yml          | 6           | OWASP A02                       |
| a03-injection-rules.yml       | 11          | OWASP A03:2021 + A05:2025       |
| a04-insecure-design-rules.yml | 4           | OWASP A04                       |
| a05-misconfig-rules.yml       | 6           | OWASP A05:2021                  |
| a06-component-rules.yml       | 5           | OWASP A06                       |
| a07-auth-rules.yml            | 5           | OWASP A07                       |
| a08-integrity-rules.yml       | 5           | OWASP A08                       |
| a09-logging-rules.yml         | 7           | OWASP A09                       |
| a10-ssrf-rules.yml            | 7           | OWASP A10:2021 + A01:2025       |
| a10-exception-rules.yml       | 4           | OWASP A10:2025                  |
| k8s-manifest-rules.yml        | 8           | Kubernetes CIS                  |
| graphql-rules.yml             | 8           | GraphQL Security                |
| **รวม**                       | **84**      | **OWASP 10/10 + K8s + GraphQL** |

### Step 6: CI/CD Integration

```bash
# แสดง CI templates
ls ci-templates/
ls .github/workflows/templates/
```

**Talking point:** _"มี templates สำเร็จรูปสำหรับ GitHub Actions และ GitLab CI copy-paste ใช้ได้เลย ไม่ต้อง config จาก scratch"_

**GitHub Actions example:**

```yaml
# .github/workflows/devsecops.yml
name: DevSecOps Pipeline
on: [push, pull_request]
jobs:
  security:
    uses: ./.github/workflows/templates/devsecops-full-pipeline.yml
    with:
      scan-target: "."
      compliance-frameworks: "owasp,ncsa,pdpa"
```

**GitLab CI example:**

```yaml
# .gitlab-ci.yml
include:
  - local: "ci-templates/devsecops.gitlab-ci.yml"

variables:
  SCAN_TARGET: "."
  COMPLIANCE_FRAMEWORKS: "owasp,ncsa,pdpa"
```

### Step 7: SLSA Assessment

```bash
claude "/slsa-assess"
```

**Expected output:**

```
SLSA Assessment — Supply-chain Levels for Software Artifacts
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Current Level: SLSA L1 (Build — basic provenance)

L1 Requirements:          Status
  Build process exists     PASS (CI/CD detected)
  Provenance generated     PASS (SBOM available)

L2 Requirements:          Status
  Hosted build service     PASS (GitHub Actions)
  Provenance authenticated FAIL (no signing)

L3 Requirements:          Status
  Hardened builds          FAIL
  Non-falsifiable proofs   FAIL

Recommendation: Achieve L2 by adding artifact signing
EU CRA Deadline: September 11, 2026
```

**Talking point:** _"SLSA framework เป็นมาตรฐาน supply chain security จาก Google ตอนนี้ EU CRA กำหนดให้ software ที่ขายใน EU ต้อง comply ภายกันยายน 2026"_

### Step 8: SBOM Generation

```bash
claude "/sbom-generate --target tests/fixtures/demo-project/"
```

**Expected output:** CycloneDX SBOM with full dependency tree

**Talking point:** _"SBOM คือ Bill of Materials ของ software EU CRA กำหนดให้ต้องมี SBOM สำหรับ software ที่ขายใน EU ภายในธันวาคม 2027"_

### Step 9: Scan History Comparison

```bash
# บันทึก scan results ลง SQLite
claude "Store current scan results in history"

# เปรียบเทียบกับ scan ก่อนหน้า
claude "Compare current scan with previous scan results"
```

**Expected output:**

```
Scan History Comparison
━━━━━━━━━━━━━━━━━━━━━━
                  Previous    Current    Delta
Critical          4           2          -2  (improved)
High              6           5          -1  (improved)
Medium            8           8           0  (stable)
Low               3           3           0  (stable)

New findings:     1
Resolved:         4
Regression:       0
```

**Talking point:** _"เก็บ scan history ใน SQLite ดู trend ได้ว่า security posture ดีขึ้นหรือแย่ลง ใช้ประกอบ audit report ได้"_

### Step 10: Quick Summary

รวมสิ่งที่ demo ได้ใน 15 นาที (ทั้ง Scenario B + C):

- Full pipeline orchestration (5 tools พร้อมกัน)
- Self-contained HTML dashboard
- 7 compliance frameworks (OWASP, NIST, MITRE, NCSA, PDPA, SOC 2, ISO 27001)
- Custom Semgrep rules 84 rules (OWASP 10/10 + K8s + GraphQL)
- CI/CD templates สำเร็จรูป (GitHub Actions + GitLab CI)
- SLSA supply chain assessment (EU CRA alignment)
- SBOM generation (CycloneDX format)
- Scan history + trend comparison
- **ทั้งหมดนี้ฟรี ใช้ open-source tools 11 ตัว ไม่มีค่า license**

---

## Common Questions & Answers

| คำถาม                          | คำตอบ                                                                                                                                                                                                                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ทำไมไม่ใช้ Snyk?**           | Snyk ดีมาก แต่ราคาเริ่มต้น $52/developer/month สำหรับ Business plan, scan ได้แค่ SCA+SAST. Plugin นี้ใช้ 11 open-source tools ฟรี ครอบคลุม SAST+DAST+SCA+Container+IaC+Secrets+SBOM+Compliance. สำหรับองค์กรที่ budget จำกัด เริ่มต้นด้วย open-source แล้วค่อยเพิ่ม commercial tools ตามความจำเป็น |
| **Security ของ plugin เอง?**   | Plugin ทำงานแบบ local-first — code ไม่ถูกส่งไปที่ไหน tools รันใน Docker containers บน isolated network (bridge + internal). Results เก็บใน tmpfs. ไม่มี telemetry หรือ data collection. Source code เป็น MIT license ตรวจสอบได้ทุกบรรทัด                                                           |
| **รองรับ CI/CD อะไร?**         | มี templates สำเร็จรูปสำหรับ GitHub Actions (4 reusable workflows) และ GitLab CI (4 templates). สำหรับ Jenkins, Azure DevOps, หรือ CI อื่นๆ ใช้ `runner/ci-adapter.sh` ที่มี platform-agnostic functions                                                                                           |
| **ต้องมี internet ไหม?**       | ครั้งแรกต้อง pull Docker images (~1.5GB รวม). หลังจากนั้น scan ทำงาน offline ได้ทั้งหมด ยกเว้น DAST (ต้องเข้าถึง target URL) และ vulnerability database updates (Grype/Trivy DB)                                                                                                                   |
| **รองรับภาษาอะไร?**            | Semgrep (SAST) รองรับ 30+ ภาษา: Python, JavaScript, TypeScript, Go, Java, C#, Ruby, PHP, Kotlin, Swift, Rust, etc. SCA (Grype) รองรับทุกภาษาที่มี package manager. Container scanning (Trivy) รองรับทุก OS/distro                                                                                  |
| **NCSA compliance คืออะไร?**   | พ.ร.บ. การรักษาความมั่นคงปลอดภัยไซเบอร์ (NCSA) กำหนดให้หน่วยงานโครงสร้างพื้นฐานสำคัญ (CII) ต้องมีมาตรการรักษาความมั่นคงปลอดภัย. Deadline: 16 กันยายน 2026. Plugin map findings ไปยัง NCSA categories อัตโนมัติ ช่วยเตรียมพร้อมสำหรับ audit                                                         |
| **ใช้กับ monorepo ได้ไหม?**    | ได้ ใช้ `--target` ระบุ path ของ sub-project ได้. Pipeline engine รองรับ concurrent scanning หลาย targets                                                                                                                                                                                          |
| **Output formats มีอะไรบ้าง?** | 8 formats: JSON, SARIF, Markdown, HTML, PDF, CSV, VEX (CycloneDX + OpenVEX), Dashboard (self-contained HTML)                                                                                                                                                                                       |

---

## Troubleshooting

### Docker images ไม่ pull

```bash
# ตรวจสอบ disk space (images ใช้ ~2-3GB)
docker system df

# ลบ images เก่า ถ้า disk เต็ม
docker system prune -f
```

### Scan ช้ากว่าปกติ

```bash
# ตรวจสอบ Docker resource limits
docker info | grep -i memory
# แนะนำ: RAM >= 4GB, CPU >= 2 cores สำหรับ Docker

# ใช้ sast-only pipeline ถ้าต้องการ quick demo
claude "/sast-scan --target tests/fixtures/demo-project/"
```

### Plugin ไม่ตอบสนอง

```bash
# ตรวจสอบ plugin installation
claude "/devsecops-setup"

# ตรวจสอบ Docker daemon
docker ps
```
