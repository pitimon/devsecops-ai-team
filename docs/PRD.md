# Product Requirements Document — DevSecOps AI Team

> **Version**: 1.0 | **Date**: 2026-03-03 | **Status**: Approved
> **Owner**: DevSecOps AI Team | **Plugin**: `devsecops-ai-team@pitimon-devsecops`

---

## 1. Product Vision

**ทุกทีมพัฒนาสามารถรักษาความปลอดภัยระดับองค์กรได้ — ด้วย AI agents ที่ทำงานร่วมกันใน Claude Code**

Every development team can achieve enterprise-grade security — powered by AI agents collaborating inside Claude Code.

DevSecOps AI Team เป็น Claude Code plugin ที่รวม open-source security tools 7+ ตัว เข้ากับ AI agents 18 ตัว เพื่อให้ทีมพัฒนาสามารถ scan, analyze, remediate และ comply ได้อัตโนมัติ ตลอด software development lifecycle

### Core Principles

1. **Shift-Left by Default** — security scanning เริ่มตั้งแต่ developer เขียน code
2. **AI-Augmented, Human-Decided** — AI เสนอ, มนุษย์ตัดสินใจ (Three-Loop Decision Model)
3. **Open-Source First** — ใช้เครื่องมือ open-source ที่ community ดูแล
4. **Compliance-Mapped** — ทุก finding map ไปยัง OWASP, NIST, MITRE, NCSA, PDPA
5. **Bilingual** — output เป็นภาษาไทยผสม English technical terms

---

## 2. Current State (v2.8.0)

| Metric                  | Value | Notes                                                                                       |
| ----------------------- | ----- | ------------------------------------------------------------------------------------------- |
| Agents                  | 18    | 4 groups: Orchestrators, Specialists, Experts, Core                                         |
| Skills                  | 14    | 12 original + `/auto-fix` + `/slsa-assess`                                                  |
| Docker Tools            | 9     | Semgrep, ZAP, Nuclei, Grype, Trivy, Checkov, GitLeaks, Syft, TruffleHog                     |
| MCP Tools               | 8     | scan, normalize, results, triage, enrich, compare, compliance_status, suggest_fix           |
| Custom Semgrep Rules    | 68    | A01 (8), A02 (6), A03 (11), A04 (4), A05 (6), A06 (5), A07 (5), A08 (5), A09 (7), A10 (7+4) |
| OWASP Category Coverage | 10/10 | A01, A02, A03, A04, A05, A06, A07, A08, A09, A10                                            |
| Compliance Frameworks   | 7     | OWASP (2021+2025), NIST 800-53, MITRE ATT&CK, NCSA, PDPA, SOC 2, ISO 27001                  |
| CWE Mappings            | 486   | Across 7 mapping files                                                                      |
| Output Formats          | 7     | JSON, SARIF, Markdown, HTML, PDF, CSV, VEX                                                  |
| Test Suites             | 28    | 978+ individual tests                                                                       |
| QA Rounds               | 10    | 1,070+ checks passed                                                                        |

### Architecture Summary

```
User prompt → keyword match in SKILL.md frontmatter
  → SKILL.md loaded → agent assigned
  → Agent loads reference file from skills/references/
  → job-dispatcher.sh → Docker container tool
  → result-collector.sh → normalizer
  → Formatter → SARIF/JSON/MD/HTML/PDF/CSV
```

---

## 3. Target Users & Personas

### 3.1 Solo Developer (นักพัฒนาเดี่ยว)

- **Need**: automated security scanning โดยไม่ต้องเป็น security expert
- **Pain**: ไม่มีเวลาเรียนรู้ security tools หลายตัว
- **Value**: scan ครั้งเดียวครอบคลุม SAST+SCA+Secrets พร้อม remediation guidance
- **Decision Loop**: Out-of-Loop (AI ทำงานอัตโนมัติ)

### 3.2 DevSecOps Engineer (วิศวกร DevSecOps)

- **Need**: orchestration ของ security tools + compliance reports
- **Pain**: ต้อง configure เครื่องมือหลายตัวและ merge results ด้วยมือ
- **Value**: unified pipeline ที่ normalize findings จากทุก tool
- **Decision Loop**: On-the-Loop (AI เสนอ, review ก่อน apply)

### 3.3 Security Lead (หัวหน้าฝ่ายความปลอดภัย)

- **Need**: gate decisions + trend analysis ข้ามโปรเจ็กต์
- **Pain**: ขาด visibility ของ security posture ทั้ง organization
- **Value**: MCP tools สำหรับ compare scans, track compliance coverage
- **Decision Loop**: In-the-Loop (ตัดสินใจ gate pass/fail)

### 3.4 Compliance Officer (เจ้าหน้าที่ compliance)

- **Need**: framework mapping + evidence generation สำหรับ audit
- **Pain**: ต้อง map findings ไปยัง regulatory frameworks ด้วยมือ
- **Value**: auto-mapping ไปยัง OWASP, NIST, NCSA, PDPA + export reports
- **Decision Loop**: In-the-Loop (approve compliance status reports)

---

## 4. Problem Statement & Gaps

### 4.1 OWASP 2025 Migration

**Problem**: All 4 CWE-to-OWASP mapping files reference OWASP Top 10 2021 categories. OWASP 2025 introduced 2 new categories (A03 Supply Chain, A10 Exception Handling) and reorganized others (SSRF merged into A01, Injection moved to A05).

**Impact**: ผู้ใช้จะเห็น outdated OWASP references ที่ไม่ตรงกับ standard ปัจจุบัน

### 4.2 No CI/CD Integration

**Problem**: Plugin works interactively in Claude Code but has no templates for automated pipeline integration (GitHub Actions, GitLab CI, Jenkins).

**Impact**: ไม่สามารถ integrate เข้า CI/CD pipeline ของ consumer projects ได้

### 4.3 Incomplete OWASP Rule Coverage

**Problem**: Custom Semgrep rules cover 4 out of 10 OWASP 2021 categories. Missing: A02 (Crypto), A04 (Insecure Design), A05 (Misconfiguration), A06 (Vulnerable Components), A07 (Auth Failures), A08 (Data Integrity).

**Impact**: ขาด detection depth สำหรับ 60% ของ OWASP categories

### 4.4 No Supply Chain Compliance

**Problem**: No SLSA provenance assessment, no VEX output, no EU CRA compliance tracking despite regulatory deadlines in 2026-2027.

**Impact**: ไม่พร้อมสำหรับ EU CRA vulnerability reporting (Sep 2026) และ SBOM requirements (Dec 2027)

### 4.5 NCSA Standards 1.0 Review Needed

**Problem**: NCSA validator built against draft standards. Final NCSA Website Security Standards 1.0 needs review before Sep 16, 2026 compliance deadline.

**Impact**: อาจมี gaps ระหว่าง implementation กับ final standard

### 4.6 No PDPA-Specific Scanning

**Problem**: PDPA (Thailand Personal Data Protection Act) enforcement escalated with THB 21.5M in fines in 2025. No PDPA-specific CWE mapping exists.

**Impact**: ขาด compliance mapping สำหรับกฎหมายไทยที่สำคัญที่สุด

### 4.7 Single DAST Tool

**Problem**: ZAP is the only DAST tool. Nuclei (11K+ templates) offers complementary coverage especially for known CVE detection.

**Impact**: DAST coverage จำกัดอยู่ที่ active scanning patterns ของ ZAP เท่านั้น

### 4.8 No Historical Scan Data

**Problem**: Scan results are ephemeral — no persistence, no trend analysis, no baseline comparison across releases.

**Impact**: ไม่สามารถ track security posture improvement over time

### 4.9 Technical Debt

**Problem**: scan-on-write hook uses fragile compact JSON grep; validate-plugin.sh has hardcoded skill count; MCP server needs `npm install` after plugin install (#29).

**Impact**: brittle tests และ user friction on first install

---

## 5. Competitive Landscape

| Feature                     | DevSecOps AI Team | Snyk (CLI)  | GitHub Advanced Security | Semgrep App  |
| --------------------------- | ----------------- | ----------- | ------------------------ | ------------ |
| AI-powered remediation      | Yes (agents)      | Limited     | Copilot Autofix          | AI rules     |
| Multi-tool orchestration    | 9 tools           | 3 tools     | CodeQL + Dependabot      | Semgrep only |
| Custom rule authoring       | Yes (68 rules)    | No          | CodeQL QL                | Yes          |
| Compliance mapping          | 7 frameworks      | 1 (OWASP)   | None                     | None         |
| Thai regulatory (NCSA/PDPA) | Yes               | No          | No                       | No           |
| Open-source tools           | 100%              | Proprietary | Proprietary              | Freemium     |
| Claude Code native          | Yes               | No          | No                       | No           |
| MCP integration             | 8 tools           | No          | No                       | No           |

**Differentiation**: Native Claude Code integration + Thai regulatory compliance + open-source multi-tool orchestration. ไม่มี competitor ที่ทำ 3 อย่างนี้พร้อมกัน

---

## 6. Release Roadmap

### v2.6.0 — CI/CD Integration + Tech Debt (Target: Q1 2026)

**Theme**: ทำให้ plugin ใช้งานได้ใน CI/CD pipelines และแก้ tech debt ที่ค้างมา

| #   | Deliverable                           | Priority | Notes                                   |
| --- | ------------------------------------- | -------- | --------------------------------------- |
| 1   | MCP dependency bundling fix (#29)     | P0       | esbuild bundle or vendored node_modules |
| 2   | GitHub Actions reusable workflows     | P0       | SARIF upload, matrix strategy           |
| 3   | GitLab CI integration templates       | P0       | gl-\*.json output format                |
| 4   | SARIF multi-run fix (Jul 2025 change) | P0       | Separate analysis per tool              |
| 5   | Version bump automation script        | P0       | `scripts/version-bump.sh` for 7 files   |
| 6   | Tech debt cleanup                     | P0       | compact JSON grep, stale counts         |
| 7   | CI adapter layer + concurrency groups | P0       | Resource-aware parallel scanning        |

### v2.7.0 — OWASP 2025 Migration + DAST Expansion (Target: Q2 2026)

**Theme**: migrate ไปยัง OWASP 2025 และเพิ่ม DAST capabilities

| #   | Deliverable                                | Priority | Notes                             |
| --- | ------------------------------------------ | -------- | --------------------------------- |
| 1   | OWASP Top 10 2025 mapping migration        | P1       | Dual-version in cwe-to-owasp.json |
| 2   | Custom rules A02/A05:2025                  | P1       | ~12 new rules                     |
| 3   | Nuclei DAST integration                    | P1       | 11K+ templates, SARIF output      |
| 4   | NCSA Website Security Standards 1.0 review | P1       | Sep 2026 deadline                 |
| 5   | Custom rules A04/A10:2025                  | P1       | ~8 new rules                      |
| 6   | PDPA compliance mapping                    | P1       | cwe-to-pdpa.json + MCP enum       |

### v2.8.0 — Supply Chain Compliance + Rules Expansion (Target: Q3 2026)

**Theme**: supply chain security compliance และ complete OWASP rule coverage

| #   | Deliverable                                    | Priority | Notes                            |
| --- | ---------------------------------------------- | -------- | -------------------------------- |
| 1   | SLSA provenance assessment skill               | P2       | /slsa-assess, EU CRA deadline    |
| 2   | VEX output format                              | P2       | CycloneDX VEX + OpenVEX          |
| 3   | Custom rules A06/A07/A08:2025 — complete 10/10 | P2       | ~15 new rules                    |
| 4   | SOC 2 / ISO 27001 compliance mapping           | P2       | 2 new mapping files              |
| 5   | TruffleHog secret scanning                     | P2       | Complement GitLeaks              |
| 6   | Secret validity checking                       | P2       | Active verification, In-the-Loop |

### v3.0.0 — Platform (daggr-inspired) (Target: Q4 2026)

**Theme**: transform จาก tool collection เป็น platform ด้วย DAG-based orchestration

| #   | Deliverable                       | Priority | Notes                       |
| --- | --------------------------------- | -------- | --------------------------- |
| 1   | Historical scan database (SQLite) | P3       | Provenance tracking, replay |
| 2   | DAG-based pipeline orchestration  | P3       | Tool = node, typed I/O      |
| 3   | Security dashboard UI (HTML SPA)  | P3       | Visual canvas, trend charts |
| 4   | Kubernetes security scanning      | P3       | kube-bench + Trivy K8s mode |
| 5   | GraphQL security scanning         | P3       | Introspection, depth, batch |

### 6b. v3.0.0 Architecture Vision (daggr-inspired)

ได้รับแรงบันดาลใจจาก [gradio-app/daggr](https://github.com/gradio-app/daggr) — DAG-based AI workflow library:

1. **DAG Node Graph** — Scan pipeline modeled as a directed acyclic graph. แต่ละ tool เป็น node ที่มี typed inputs/outputs สามารถ compose pipeline ได้อย่างยืดหยุ่น

2. **Provenance Tracking** — ทุก scan result ถูก persist ใน SQLite พร้อม exact inputs สำหรับ replay. Full execution history enables audit trail และ trend analysis

3. **Step Re-execution** — สามารถ re-run individual tool (เช่น Semgrep) โดยไม่ต้อง re-run ทั้ง pipeline. ลด scan time สำหรับ iterative development

4. **Visual Canvas** — HTML dashboard แสดง pipeline graph + per-node results. Interactive drill-down จาก overview ไปยัง finding details

5. **Concurrency Groups** — Resource-aware parallel execution. เช่น ZAP ใช้ memory เยอะ จึงรันได้ 1 instance ขณะที่ Semgrep + Grype รันพร้อมกันได้ (v2.6.0 foundation)

---

## 7. Success Metrics

| Metric                      | Current (v2.8.0) | v2.8.0 Target | v3.0.0 Target |
| --------------------------- | ---------------- | ------------- | ------------- |
| OWASP custom rules coverage | 10/10            | 10/10         | 10/10         |
| CWE mappings                | 486              | 450+          | 500+          |
| Test count                  | 978+             | 1100+         | 1300+         |
| MCP tools                   | 8                | 10+           | 12+           |
| CI/CD platforms supported   | 3                | 3             | 3+            |
| Compliance frameworks       | 7                | 7+            | 8+            |
| Custom Semgrep rules        | 68               | 65+           | 75+           |
| DAST tools                  | 2 (ZAP+Nuclei)   | 2+            | 3+            |
| Output formats              | 7                | 7+ (VEX)      | 8+            |

---

## 8. Non-Functional Requirements

### 8.1 Performance

- Full 8-tool scan MUST complete within 30 minutes for a medium project (100K LOC)
- Individual tool scan MUST complete within 5 minutes
- MCP tool responses MUST return within 10 seconds (excluding scan execution)
- Deduplication MUST process 1,000 findings in under 5 seconds

### 8.2 Security

- Plugin MUST NOT store or transmit source code outside Docker containers
- Docker containers MUST run with `--network=none` where possible (except ZAP DAST)
- No credentials stored in plugin files — use environment variables
- DAST targets MUST require explicit user approval (In-the-Loop)
- Secret scanning MUST NOT log found secrets in output

### 8.3 Compatibility

- Docker Engine 20.10+ required
- Node.js 18+ for MCP server
- Claude Code latest stable release
- Supports macOS (arm64, x86_64) and Linux (x86_64)

### 8.4 Reliability

- All test suites MUST pass before release (validate-plugin.sh = gate)
- QA station testing MUST be completed for every release
- Graceful degradation when individual tools are unavailable
- MCP server MUST validate all inputs via Zod schemas

### 8.5 Maintainability

- Function size limit: 50 lines (governance enforced)
- File size limit: 800 lines
- Conventional commits required
- CHANGELOG.md updated for every release

---

## 9. Risk Assessment

| Risk                                                  | Likelihood | Impact | Mitigation                                           |
| ----------------------------------------------------- | ---------- | ------ | ---------------------------------------------------- |
| OWASP 2025 mapping breaks existing reports            | Medium     | High   | Dual-version tagging (2021+2025) in v2.7.0           |
| EU CRA deadline missed (Sep 2026)                     | Low        | High   | SLSA skill prioritized in v2.8.0                     |
| NCSA Standards 1.0 changes from draft                 | Medium     | Medium | Review scheduled for v2.7.0 before Sep deadline      |
| ZAP community support decline (Checkmarx acquisition) | Low        | Medium | Nuclei as complement in v2.7.0                       |
| GitHub SARIF format changes again                     | Low        | Medium | Abstract SARIF generation behind formatter interface |
| Docker Desktop licensing changes                      | Low        | Low    | Document Podman as alternative                       |
| daggr library abandoned/API changes                   | Medium     | Low    | Inspired by patterns, not dependent on library       |
| MCP protocol breaking changes                         | Medium     | Medium | Zod schema validation + version negotiation          |

### Regulatory Timeline

| Regulation                          | Deadline     | Impact                          | Release |
| ----------------------------------- | ------------ | ------------------------------- | ------- |
| NCSA Website Security Standards 1.0 | Sep 16, 2026 | Thai government/CII compliance  | v2.7.0  |
| EU CRA vulnerability reporting      | Sep 11, 2026 | SBOM + vulnerability disclosure | v2.8.0  |
| EU CRA full SBOM requirement        | Dec 11, 2027 | CycloneDX/SPDX compliance       | v3.0.0  |
| PDPA enforcement (ongoing)          | Continuous   | THB 21.5M fines in 2025         | v2.7.0  |

---

_Document generated: 2026-03-03 | Updated: v2.8.0 release | Next review: v3.0.0 release_
