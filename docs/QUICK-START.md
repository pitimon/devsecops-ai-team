# Quick Start / เริ่มต้นใช้งานใน 5 นาที

จาก install จนถึง first scan ภายใน 5 นาที ไม่ต้องตั้งค่าอะไรเพิ่มเติม

---

## 1. Prerequisites / ข้อกำหนดเบื้องต้น

ตรวจสอบว่ามีเครื่องมือเหล่านี้พร้อมใช้งาน:

| Requirement        | Minimum | ตรวจสอบด้วย              |
| ------------------ | ------- | ------------------------ |
| **Docker Engine**  | 20.10+  | `docker --version`       |
| **Docker Compose** | v2.0+   | `docker compose version` |
| **Claude Code**    | Latest  | `claude --version`       |
| **Disk Space**     | 2 GB+   | `df -h .`                |

> **หมายเหตุ**: Docker images จะถูก pull อัตโนมัติตอน scan ครั้งแรก ไม่ต้อง pull ล่วงหน้า

---

## 2. ติดตั้ง Plugin (1 คำสั่ง)

```bash
# ลงทะเบียน marketplace + ติดตั้ง plugin ในคำสั่งเดียว
claude plugin marketplace add pitimon/devsecops-ai-team && \
claude plugin install devsecops-ai-team@pitimon-devsecops
```

เมื่อติดตั้งเสร็จ จะได้รับ:

- **16 skills** — SAST, DAST, SCA, Container, IaC, Secrets, SBOM, Compliance, IR, SLSA, K8s, GraphQL, และอื่นๆ
- **18 AI agents** — ทีม security specialists ที่ทำงานร่วมกัน
- **11 Docker tools** — Semgrep, ZAP, Nuclei, Grype, Trivy, Checkov, GitLeaks, TruffleHog, Syft, kube-bench, และอื่นๆ

---

## 3. ตรวจสอบการติดตั้ง

เปิด Claude Code session ใหม่ แล้วพิมพ์:

```
/devsecops-setup
```

ถ้าเห็น DevSecOps AI Team context prompt แสดงว่าติดตั้งสำเร็จ ระบบจะแสดง:

```
DevSecOps AI Team v3.0.4 — 18 agents, 16 skills, 11 tools
Type /sast-scan, /secret-scan, /full-pipeline, etc. to begin
```

> **ถ้าไม่เห็น prompt**: ตรวจสอบให้แน่ใจว่าปิดแล้วเปิด Claude Code ใหม่หลังติดตั้ง ดูรายละเอียดที่ [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 4. First SAST Scan / สแกนครั้งแรก

ใช้ demo project ที่มาพร้อม plugin เพื่อทดสอบ:

```
Scan this project for security vulnerabilities: tests/fixtures/demo-project/
```

หรือใช้ skill command โดยตรง:

```
/sast-scan --target tests/fixtures/demo-project/
```

---

## 5. สิ่งที่จะเกิดขึ้น — AI Agent Flow

เมื่อคุณสั่ง scan ระบบจะทำงานตามลำดับนี้:

```
คุณ: "Scan for security vulnerabilities"
  |
  v
1. Skill Matching — Claude จับคู่ keyword กับ SKILL.md
  |
  v
2. DevSecOps Lead — orchestrator วิเคราะห์ request
  |                  แล้ว delegate ไปยัง specialist ที่เหมาะสม
  v
3. SAST Specialist — สั่ง job-dispatcher.sh
  |                   เปิด Docker container (Semgrep)
  v
4. Semgrep Container — สแกนโค้ดใน isolated container
  |                     (--network=none, read-only mount)
  v
5. Result Normalization — แปลงผลเป็น Unified Finding Schema
  |
  v
6. Triage & Enrichment — จัดลำดับความสำคัญ + เพิ่ม OWASP/CWE context
  |
  v
7. Report — แสดงผลลัพธ์พร้อมคำแนะนำการแก้ไข
```

### ตัวอย่างผลลัพธ์ที่คาดหวัง

จาก demo project คุณจะเห็นผลลัพธ์ประมาณนี้:

```
ผลการสแกน SAST (Scan Results)
================================
พบ 9 findings (5 HIGH, 2 MEDIUM, 1 LOW, 1 INFO)

HIGH: SQL Injection (CWE-89) — app.py:41
  f-string interpolation ใน SQL query ทำให้ attacker สามารถ inject SQL ได้
  แนะนำ: ใช้ parameterized queries แทน

HIGH: Command Injection (CWE-78) — app.py:65
  os.system() รับ user input โดยตรง
  แนะนำ: ใช้ subprocess.run() กับ list arguments

MEDIUM: Weak Cryptography (CWE-327) — app.py:58
  hashlib.md5() ไม่ปลอดภัยสำหรับ cryptographic use
  แนะนำ: ใช้ hashlib.sha256() หรือ bcrypt แทน
...
```

---

## 6. ลองสแกนเพิ่มเติม

### Secret Scanning — ค้นหา credentials ที่หลุดเข้าไปในโค้ด

```
/secret-scan --target tests/fixtures/demo-project/
```

### SCA (Software Composition Analysis) — ตรวจสอบ dependency ที่มีช่องโหว่

```
/sca-scan --target tests/fixtures/demo-project/
```

### Full Pipeline — สแกนทุก tool พร้อมกัน

```
/full-pipeline --target tests/fixtures/demo-project/
```

Pipeline จะรัน tools แบบ parallel ตาม DAG dependency graph:

```
Secrets (GitLeaks + TruffleHog) ─┐
SAST (Semgrep) ──────────────────┼──> Normalize ──> Triage ──> Report
SCA (Grype) ─────────────────────┤
Container (Trivy) ───────────────┘
```

### สแกนโปรเจกต์ของคุณเอง

เมื่อคุ้นเคยกับ demo project แล้ว ลองสแกนโปรเจกต์จริง:

```
/sast-scan --target /path/to/your/project
/full-pipeline --target /path/to/your/project
```

---

## 7. ดู Security Dashboard

หลังจาก scan หลายรอบ คุณสามารถสร้าง HTML dashboard เพื่อดูภาพรวม:

```
/security-dashboard
```

Dashboard จะแสดง:

- **Severity distribution** — กราฟแท่งแยกตาม severity level
- **Trend analysis** — แนวโน้มจำนวน findings ตามเวลา
- **Tool coverage** — เครื่องมือที่ใช้สแกนและผลลัพธ์
- **Compliance status** — สถานะตาม OWASP, NIST, NCSA และ framework อื่นๆ

---

## 8. ขั้นตอนถัดไป

| ต้องการ                                             | อ่านเพิ่มที่                                           |
| --------------------------------------------------- | ------------------------------------------------------ |
| ดูรายละเอียดทุก feature ของ plugin                  | [FEATURES.md](FEATURES.md)                             |
| เข้าใจสถาปัตยกรรมภายใน                              | [ARCHITECTURE.md](ARCHITECTURE.md)                     |
| ตั้งค่า CI/CD pipeline (GitHub Actions / GitLab CI) | [CI-INTEGRATION.md](CI-INTEGRATION.md)                 |
| เข้าใจกลไกเบื้องหลังการ scan                        | [FIRST-SCAN-WALKTHROUGH.md](FIRST-SCAN-WALKTHROUGH.md) |
| แก้ปัญหาที่พบบ่อย                                   | [TROUBLESHOOTING.md](TROUBLESHOOTING.md)               |
| ดูรายละเอียดการติดตั้งแบบ advanced                  | [INSTALL.md](INSTALL.md)                               |
