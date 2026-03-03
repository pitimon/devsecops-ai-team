# Demo Talk Track — DevSecOps AI Team

Presenter script สำหรับ demo plugin ในงาน workshop, conference, หรือ sales meeting
ใช้คู่กับ `demo/README.md` ซึ่งมี commands และ expected output

---

## Opening (1 นาที)

### Elevator Pitch

> สวัสดีครับ/ค่ะ วันนี้จะมาแสดงให้ดูว่า **DevSecOps ไม่จำเป็นต้องแพง**
>
> หลายองค์กรคิดว่า security scanning ต้องใช้เครื่องมือราคาหลักแสนต่อปี
> แต่จริงๆ แล้ว tools ที่ Netflix, Google, Shopify ใช้ในการสแกน
> มันเป็น open-source ทั้งหมด
>
> สิ่งที่ขาดคือ **คนที่รู้วิธีใช้งานมัน** และ **การ orchestrate tools หลายตัวเข้าด้วยกัน**
>
> Plugin ตัวนี้แก้ปัญหาทั้งสองอย่าง — มี AI agents 18 ตัว
> ที่รู้วิธีใช้ security tools 11 ตัว ทำงานร่วมกันอัตโนมัติ
> ผ่าน Claude Code

### Key Messages (จำ 3 ข้อนี้)

1. **ฟรี + ระดับ Enterprise** — 11 open-source tools, 84 custom rules, 7 compliance frameworks
2. **ใช้ง่าย** — พิมพ์คำสั่งเดียว AI จัดการทั้งหมด
3. **Thailand-ready** — NCSA + PDPA compliance mapping ในตัว

---

## Scenario A: Quick Win (5 นาที)

### [0:00 - 0:30] Introduction

> เรามาเริ่มจากสิ่งง่ายๆ กัน
> นี่คือ demo project ที่มี intentional vulnerabilities —
> SQL Injection, Command Injection, Hard-coded credentials
> ลองดูว่า AI จะจับได้กี่ตัว

**Action:** เปิด `tests/fixtures/demo-project/app.py` ให้ผู้ชมเห็น code

> ลองดู code นี้ครับ เห็นอะไรผิดปกติไหม?
> _(ให้เวลาผู้ชม 5 วินาที)_
> ดูเผินๆ อาจเหมือน code ปกติ แต่มีช่องโหว่ซ่อนอยู่อย่างน้อย 6 จุด

### [0:30 - 1:30] Run SAST Scan

**Action:** รัน command

```bash
claude "/sast-scan --target tests/fixtures/demo-project/"
```

> แค่คำสั่งเดียว Semgrep จะวิเคราะห์ code ทั้งหมด
> _(รอ scan เสร็จ ~10-20 วินาที)_
>
> ขณะรอ: Semgrep คือ SAST tool ที่ใช้กันอย่างแพร่หลาย
> รองรับกว่า 30 ภาษา มี rule registry กว่า 3,000 rules
> Netflix, Dropbox, Slack ใช้อยู่ทุกวัน

### [1:30 - 3:00] Review Results

**Action:** scroll ดู findings ทีละรายการ

> มาดู findings กันครับ

**Finding 1 — SQL Injection (ใช้เวลาอธิบาย 30 วินาที):**

> อันแรก CWE-89 SQL Injection — ดูบรรทัดที่ 44
> programmer ใช้ f-string ใส่ user input ลงไปใน SQL query ตรงๆ
> attacker แค่ใส่ `' OR 1=1 --` ก็ดึงข้อมูลทั้ง database ได้
> Severity: **Critical** — ต้องแก้ก่อน deploy

**Finding 2 — OS Command Injection (ใช้เวลาอธิบาย 20 วินาที):**

> CWE-78 Command Injection — `os.system()` เอา user input ไปรัน shell ตรงๆ
> attacker ใส่ `; rm -rf /` ก็จบเลย
> Severity: **Critical**

**Finding 3 — Hard-coded Credentials (ใช้เวลาอธิบาย 10 วินาที):**

> CWE-798 — database password และ service token ฝังอยู่ใน source code
> ถ้า push ขึ้น GitHub ก็เป็น public ทันที

### [3:00 - 4:00] Auto-Fix

**Action:** รัน auto-fix

```bash
claude "/auto-fix --severity critical --target tests/fixtures/demo-project/"
```

> ทีนี้มาดูว่า AI จะเสนอ fix ยังไง
> _(รอ fix generation ~10 วินาที)_

**เมื่อ fix ปรากฏ:**

> ดูครับ — AI เปลี่ยน f-string SQL เป็น parameterized query
> จาก `f"SELECT * FROM users WHERE username = '{username}'"`
> เป็น `"SELECT * FROM users WHERE username = ?"` แล้วส่ง parameter แยก
>
> **สำคัญ:** AI เสนอ fix แต่ **คนต้อง approve** ก่อน apply
> เราเรียกว่า On-the-Loop — AI ทำงาน คนคุมอยู่

### [4:00 - 5:00] SARIF Output + Closing

**Action:** รัน SARIF output

```bash
claude "/sast-scan --target tests/fixtures/demo-project/ --format sarif"
```

> Output เป็น SARIF standard — เปิดได้ใน VS Code, GitHub Security tab,
> Defect Dojo, หรือ SIEM อะไรก็ได้ ไม่มี vendor lock-in
>
> **สรุป 5 นาทีนี้:** scan 1 คำสั่ง → พบ 6-8 ช่องโหว่ → AI เสนอ fix → output เป็น standard
> ทั้งหมดนี้ **ฟรี ไม่มีค่า license**

---

## Scenario B: Full Pipeline (10 นาที)

### [0:00 - 1:00] Introduction

> Scenario A เราใช้แค่ tool เดียว (Semgrep) สำหรับ SAST
> แต่ security จริงๆ ต้องดูหลายมุม —
> dependencies มี CVE ไหม? Docker image ปลอดภัยไหม? มี secret หลุดไหม?
>
> plugin นี้มี 11 tools ทำงานร่วมกัน วันนี้จะโชว์ 5 ตัวหลัก

**Action:** แสดง DAG diagram (วาดบน whiteboard หรือ slide)

```
Semgrep (SAST) ─┐
Grype (SCA) ────┤
GitLeaks (Secret)┤──→ Normalize ──→ Dedup ──→ Report
Trivy (Container)┤
Checkov (IaC) ──┘
```

> 5 tools รันพร้อมกันแบบ parallel ใน DAG pipeline
> ผลรวมออกมาเป็น report เดียว ไม่ต้องดูทีละ tool

### [1:00 - 3:00] Run Full Pipeline

**Action:** รัน full pipeline

```bash
claude "/full-pipeline --target tests/fixtures/demo-project/"
```

> _(ขณะรอ scan ~30-60 วินาที อธิบาย:)_
>
> pipeline engine ใช้ topological sort จัด execution order
> tools ที่ไม่มี dependency รันพร้อมกันได้ — ประหยัดเวลา 3-4 เท่า
> เทียบกับการรันทีละตัว
>
> ตอนนี้ Semgrep สแกน code, Grype ตรวจ dependencies,
> GitLeaks หา secrets, Trivy สแกน Docker image, Checkov ตรวจ Dockerfile config
>
> _(เมื่อ scan เสร็จ:)_
>
> เห็นไหมครับ ~20-30 findings จาก 5 tools
> ระบบ deduplicate ให้แล้ว ไม่ซ้ำกัน
> จัดเรียงตาม severity: Critical ก่อน แล้ว High, Medium, Low

**Highlight SCA findings:**

> ดูตรงนี้ — Grype พบว่า `lodash 4.17.15` มี Prototype Pollution CVE
> และ `express 4.16.0` มี Path Traversal CVE
> แค่เปลี่ยน version ใน package.json ก็แก้ได้

**Highlight Container findings:**

> Trivy พบว่า `node:14` base image มีอย่างน้อย 3 CVEs
> เพราะ node 14 EOL ไปแล้ว ควรเปลี่ยนเป็น node:20-slim

### [3:00 - 5:00] Security Dashboard

**Action:** สร้าง dashboard

```bash
claude "/full-pipeline --target tests/fixtures/demo-project/ --format dashboard"
```

> Dashboard เป็น self-contained HTML file — เปิดใน browser ได้เลย
>
> _(เปิด browser แสดง dashboard)_
>
> มี severity distribution chart ด้านบน
> ข้างล่างเป็น findings table ที่ filter ได้ตาม severity, tool, CWE
> ส่งให้ผู้บริหารดูได้โดยไม่ต้องอธิบายว่า SARIF คืออะไร

**Talking point สำหรับ CTO/CISO:**

> ถ้าผู้บริหารถามว่า "security posture ของเราเป็นยังไง?"
> ส่ง dashboard นี้ไปเลย — อ่านเข้าใจง่าย มี chart มีตาราง
> ไม่ต้องอ่าน raw JSON

### [5:00 - 7:00] Compliance Checks

**Action:** รัน NCSA compliance

```bash
claude "/compliance-report --framework ncsa --target tests/fixtures/demo-project/"
```

> NCSA — พ.ร.บ. ไซเบอร์ กำหนดให้หน่วยงาน CII ต้อง comply
> deadline 16 กันยายน 2026 — **เหลือ 6 เดือน**
>
> plugin map findings ไปยัง NCSA categories อัตโนมัติ
> เห็นได้เลยว่าผ่านตรงไหน ไม่ผ่านตรงไหน

**Action:** รัน PDPA compliance

```bash
claude "/compliance-report --framework pdpa --target tests/fixtures/demo-project/"
```

> PDPA — พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล มีผลบังคับใช้แล้ว
> ถ้าข้อมูลรั่ว ปรับสูงสุด 5 ล้านบาท
> plugin ตรวจว่า code จัดการ personal data ถูกต้องไหม
> เช่น sensitive data ใน logs (CWE-532) map ไปที่ PDPA Section 37
>
> **Key message:** plugin รองรับ 7 frameworks ครบ:
> OWASP, NIST, MITRE ATT&CK, NCSA, PDPA, SOC 2, ISO 27001

### [7:00 - 10:00] Q&A

> _(เปิดให้ถามคำถาม)_
>
> ถ้าไม่มีคำถาม ถามกลับ:
> "ตอนนี้องค์กรของท่านใช้ tool อะไรสแกน security อยู่บ้างครับ?"
> "CI/CD ใช้ GitHub Actions หรือ GitLab CI ครับ?"
>
> _(ใช้คำตอบเป็น segue ไป Scenario C ถ้ามีเวลา)_

---

## Scenario C: Enterprise Story (15 นาที)

### [0:00 - 7:00] ทำ Scenario B ก่อน

(ดู Scenario B ด้านบน)

### [7:00 - 9:00] Custom Rules + CI/CD

**Action:** แสดง custom Semgrep rules

```bash
ls runner/semgrep-rules/
```

> เรามี custom rules 84 rules ครอบคลุม OWASP Top 10
> ทั้ง version 2021 และ 2025 (เพิ่งออกปีนี้)
>
> สิ่งที่ต่างจาก default rules ของ Semgrep คือ:
>
> 1. **Dual-version tagging** — rules tag ทั้ง OWASP 2021 และ 2025
> 2. **K8s manifest rules** — 8 rules สำหรับ Kubernetes config
> 3. **GraphQL rules** — 8 rules สำหรับ GraphQL API security
>
> OWASP 2025 มีการเปลี่ยนแปลงสำคัญ:
>
> - A03 เปลี่ยนจาก Injection เป็น Supply Chain (ใหม่)
> - A05 เปลี่ยนเป็น Injection (ย้ายจาก A03:2021)
> - A10 ใหม่เป็น Exception Handling
> - SSRF merge เข้า A01
>
> rules ของเราครอบคลุมทั้งหมดแล้ว

**Action:** แสดง CI/CD templates

```bash
ls ci-templates/
ls .github/workflows/templates/
```

> มี templates สำเร็จรูปสำหรับ GitHub Actions 4 workflows
> และ GitLab CI 4 templates — copy-paste ใช้ได้เลย
>
> _(แสดงตัวอย่าง GitHub Actions workflow)_
>
> แค่ 8 บรรทัด ก็ได้ full security pipeline ใน CI/CD
> scan ทุก push, ทุก PR — shift-left security ตั้งแต่ตอน develop

### [9:00 - 11:00] SLSA + SBOM

**Action:** รัน SLSA assessment

```bash
claude "/slsa-assess"
```

> SLSA คือ Supply-chain Levels for Software Artifacts
> framework จาก Google สำหรับ supply chain security
>
> EU CRA — Cyber Resilience Act กำหนดให้ software ที่ขายใน EU
> ต้อง comply ภายใน 11 กันยายน 2026
> ถ้าขายอะไรก็ตามใน EU ต้องเตรียมตัว
>
> plugin ประเมินได้ว่าตอนนี้อยู่ SLSA Level ไหน
> และต้องทำอะไรเพิ่มเพื่อขยับ level

**Action:** สร้าง SBOM

```bash
claude "/sbom-generate --target tests/fixtures/demo-project/"
```

> SBOM — Software Bill of Materials
> EU CRA กำหนดให้ต้องมี SBOM ภายในธันวาคม 2027
> แต่ดีกว่าเริ่มทำตั้งแต่ตอนนี้
>
> plugin ใช้ Syft สร้าง SBOM แบบ CycloneDX
> ใช้ได้กับ Dependency-Track, OWASP DefectDojo, หรือ GUAC

### [11:00 - 13:00] Scan History + Trends

**Action:** แสดง scan history

```bash
claude "Store current scan results in history"
claude "Compare current scan with previous scan results"
```

> เก็บ scan results ใน SQLite — ทุกครั้งที่ scan เก็บ timestamp, tool, findings
> เปรียบเทียบกับ scan ก่อนหน้าได้:
>
> - findings ใหม่ที่เพิ่งเจอ
> - findings เก่าที่แก้แล้ว
> - regression — ช่องโหว่ที่เคยแก้แล้วกลับมา
>
> ใช้ประกอบ audit report ได้ว่า security posture ดีขึ้นตามเวลา

### [13:00 - 15:00] Closing + Q&A

> **สรุปสิ่งที่เห็นวันนี้:**
>
> 1. **SAST scan** — 1 คำสั่ง พบช่องโหว่ใน 30 วินาที
> 2. **Full pipeline** — 5 tools ทำงานพร้อมกัน
> 3. **Dashboard** — ส่งให้ผู้บริหารได้เลย
> 4. **Compliance** — NCSA, PDPA, OWASP, NIST, MITRE, SOC 2, ISO 27001
> 5. **Custom rules** — 84 rules ครอบคลุม OWASP 10/10
> 6. **CI/CD** — templates สำเร็จรูป
> 7. **SLSA + SBOM** — พร้อมสำหรับ EU CRA
> 8. **Scan history** — ติดตาม trend ตลอด
>
> **ทั้งหมดนี้ฟรี** — plugin เป็น MIT license, tools เป็น open-source
> ไม่มีค่า license สักบาท

---

## Objection Handling

### "ของฟรีจะดีจริงหรือ?"

> คำถามดีมากครับ เข้าใจความกังวล
>
> แต่ tools ที่ใช้ไม่ใช่ของฟรีแบบ hobby project —
> **Semgrep** ใช้โดย Dropbox, Slack, Figma, Netflix
> **Trivy** ใช้โดย AWS, Google Cloud, Azure
> **ZAP** เป็น DAST tool อันดับ 1 ของ OWASP
> **GitLeaks** ใช้โดย Uber, Shopify
>
> tools เหล่านี้มี community ใหญ่ มีบริษัทใหญ่ sponsor
> update สม่ำเสมอ มี CVE database อัพเดทรายวัน
>
> สิ่งที่ plugin เพิ่มคือ **AI orchestration** —
> ทำให้ใช้ tools เหล่านี้ง่ายขึ้น ไม่ต้องเป็น security expert

### "ทำไมไม่ใช้ GitHub Advanced Security?"

> GitHub Advanced Security ดีมากครับ แต่:
>
> - **ราคา $49/user/month** — 10 คน = $490/month = ~17,000 บาท/เดือน
> - ได้แค่ **CodeQL** (SAST) กับ **Dependabot** (SCA) กับ **Secret Scanning**
> - **ไม่มี DAST**, ไม่มี container scanning, ไม่มี IaC scanning
> - **ไม่มี compliance mapping** สำหรับ NCSA/PDPA
> - **lock-in** กับ GitHub เท่านั้น
>
> Plugin นี้:
>
> - **ฟรี** — $0/month
> - **11 tools** — SAST+DAST+SCA+Container+IaC+Secrets+SBOM+K8s+GraphQL
> - **7 compliance frameworks** — รวม NCSA และ PDPA
> - **ไม่ lock-in** — ใช้ได้กับ GitHub, GitLab, Jenkins, Azure DevOps
>
> ถ้า budget มี $49/user ใช้ GitHub Advanced Security ได้เลย
> แต่ถ้า budget จำกัด plugin นี้ให้มากกว่าในราคา $0

### "มี support ไหม?"

> เรามี 3 tiers ครับ:
>
> | Tier           | รายละเอียด                                                                                                     | ราคา       |
> | -------------- | -------------------------------------------------------------------------------------------------------------- | ---------- |
> | **Starter**    | Plugin ฟรี + community support (GitHub Issues) + documentation                                                 | ฟรี        |
> | **Pro**        | Workshop 2 วัน + setup assistance + custom rules สำหรับ tech stack ขององค์กร + email support 3 เดือน           | สอบถามราคา |
> | **Enterprise** | ทุกอย่างใน Pro + on-site consulting + compliance audit assistance + dedicated Slack channel + quarterly review | สอบถามราคา |
>
> **Starter** เพียงพอสำหรับทีมที่มี DevOps/Security engineer อยู่แล้ว
> **Pro** เหมาะสำหรับทีมที่เพิ่งเริ่ม DevSecOps ต้องการ guidance
> **Enterprise** เหมาะสำหรับองค์กรที่ต้อง comply NCSA/PDPA/ISO 27001

### "ใช้ยากไหม? ทีมไม่มี security background"

> นั่นคือจุดประสงค์ของ plugin เลยครับ
> ไม่ต้องรู้ว่า Semgrep config ยังไง, Trivy ใช้ยังไง
> แค่พิมพ์ `/full-pipeline` — AI จัดการทั้งหมด
>
> Output เป็นภาษาไทย (Thai prose + English technical terms)
> มี severity ranking บอกว่าแก้อะไรก่อน
> มี auto-fix เสนอ patch ให้
>
> ถ้าทีมต้องการ deep dive เรามี **workshop 2 วัน**
> สอน DevSecOps ตั้งแต่ concept จนถึงใช้งาน tools ได้จริง

### "เทียบกับ Snyk, SonarQube, Checkmarx ยังไง?"

> | Feature    | Plugin (ฟรี)          | Snyk Business    | SonarQube Enterprise | Checkmarx |
> | ---------- | --------------------- | ---------------- | -------------------- | --------- |
> | SAST       | Semgrep               | Snyk Code        | SonarQube            | CxSAST    |
> | SCA        | Grype                 | Snyk Open Source | Dependency Check     | CxSCA     |
> | DAST       | ZAP + Nuclei          | --               | --                   | CxDAST    |
> | Container  | Trivy                 | Snyk Container   | --                   | --        |
> | IaC        | Checkov               | Snyk IaC         | --                   | --        |
> | Secrets    | GitLeaks + TruffleHog | --               | --                   | --        |
> | SBOM       | Syft                  | --               | --                   | --        |
> | K8s CIS    | kube-bench            | --               | --                   | --        |
> | Compliance | 7 frameworks          | --               | --                   | --        |
> | ราคา       | **$0**                | $52/dev/mo       | $20K+/yr             | $40K+/yr  |
>
> Commercial tools ดีตรงที่มี GUI สวย, support 24/7, และ integration สำเร็จรูป
> แต่ถ้า budget จำกัด plugin นี้ครอบคลุมกว้างกว่าในราคา $0

---

## Closing

### Service Pitch (30 วินาที)

> ก่อนจบ ขอแนะนำ services ของเราสั้นๆ:
>
> **1. Workshop DevSecOps (2 วัน)**
>
> - วันแรก: concept + hands-on กับ 11 tools
> - วันสอง: CI/CD integration + compliance mapping + custom rules
> - ผู้เข้าร่วมได้ plugin + custom rules สำหรับ tech stack ขององค์กร
>
> **2. Security Consulting**
>
> - ตรวจสอบ security posture ขององค์กร
> - เตรียมพร้อมสำหรับ NCSA/PDPA compliance
> - Setup CI/CD security pipeline
>
> **3. Compliance Audit Assistance**
>
> - NCSA (deadline กันยายน 2026)
> - PDPA (บังคับใช้แล้ว)
> - ISO 27001, SOC 2

### Contact Information

> สนใจติดต่อ:
>
> - GitHub: `github.com/pitimon/devsecops-ai-team`
> - Plugin: ฟรี ติดตั้งวันนี้ได้เลย
> - Workshop/Consulting: ติดต่อทาง GitHub Issues หรือ email
>
> ขอบคุณครับ/ค่ะ

---

## Presenter Notes

### Before the Demo

- [ ] Docker running, images pre-pulled
- [ ] Terminal font size 18pt+
- [ ] Dark theme + high contrast
- [ ] Browser ready (สำหรับ dashboard)
- [ ] Backup screenshots ถ้า demo ค้าง
- [ ] Airplane mode ON (ปิด notifications)

### If Something Goes Wrong

| ปัญหา                   | แก้ไข                                                                                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Docker ไม่ start        | ใช้ screenshot จาก `demo/screenshots/` (ถ้ามี)                                                                       |
| Scan ช้ามาก             | พูดอธิบาย architecture ระหว่างรอ, skip ไป dashboard ที่เตรียมไว้                                                     |
| Plugin error            | เปลี่ยนเป็นรัน docker command ตรงๆ: `docker run --rm -v $(pwd):/src returntocorp/semgrep semgrep --config auto /src` |
| ผู้ชมถามเรื่องที่ไม่รู้ | "ขอบคุณคำถามดีมากครับ ขอนำไปตอบหลัง session นะครับ"                                                                  |

### Timing Tips

- Scenario A ทำได้ใน 3 นาทีจริงๆ — เผื่อ 2 นาที สำหรับ Q&A
- Scenario B ทำได้ใน 7 นาทีจริงๆ — เผื่อ 3 นาที สำหรับ Q&A
- ถ้าเวลาน้อย skip PDPA compliance (ใช้แค่ NCSA ก็พอ)
- ถ้าเวลาเหลือ เพิ่ม SLSA หรือ SBOM (Scenario C content)
