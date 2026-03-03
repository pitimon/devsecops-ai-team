# Product Requirements Document — DevSecOps AI Team

> **Version**: 2.0 | **Date**: 2026-03-03 | **Status**: Approved
> **Owner**: DevSecOps AI Team | **Plugin**: `devsecops-ai-team@pitimon-devsecops`

---

## 1. Product Vision

**ทุกทีมพัฒนาสามารถรักษาความปลอดภัยระดับองค์กรได้ — ด้วย AI agents ที่ทำงานร่วมกันใน Claude Code**

Every development team can achieve enterprise-grade security — powered by AI agents collaborating inside Claude Code.

DevSecOps AI Team เป็น Claude Code plugin ที่รวม open-source security tools 11 ตัว เข้ากับ AI agents 18 ตัว เพื่อให้ทีมพัฒนาสามารถ scan, analyze, remediate และ comply ได้อัตโนมัติ ตลอด software development lifecycle

### Core Principles

1. **Shift-Left by Default** — security scanning เริ่มตั้งแต่ developer เขียน code
2. **AI-Augmented, Human-Decided** — AI เสนอ, มนุษย์ตัดสินใจ (Three-Loop Decision Model)
3. **Open-Source First** — ใช้เครื่องมือ open-source ที่ community ดูแล
4. **Compliance-Mapped** — ทุก finding map ไปยัง OWASP, NIST, MITRE, NCSA, PDPA, SOC 2, ISO 27001
5. **Bilingual** — output เป็นภาษาไทยผสม English technical terms

---

## 2. Current State (v3.1.0)

| Metric                  | Value  | Notes                                                                                                 |
| ----------------------- | ------ | ----------------------------------------------------------------------------------------------------- |
| Agents                  | 18     | 4 groups: Orchestrators (3), Specialists (7), Experts (4), Core Team (4)                              |
| Skills                  | 16     | 12 original + `/auto-fix` (v2.3.0) + `/slsa-assess` (v2.8.0) + `/k8s-scan` + `/graphql-scan` (v3.0.0) |
| Docker Tools            | 11     | Semgrep, ZAP, Nuclei, Grype, Trivy, Checkov, GitLeaks, Syft, TruffleHog, kube-bench, Nuclei-GraphQL   |
| MCP Tools               | 10     | scan, normalize, results, triage, enrich, compare, compliance_status, suggest_fix, history, pipeline  |
| Custom Semgrep Rules    | 84     | OWASP A01-A10 (68) + K8s (8) + GraphQL (8) — dual 2021+2025 tagging                                   |
| OWASP Category Coverage | 10/10  | A01-A10 complete (both 2021 and 2025 versions)                                                        |
| Compliance Frameworks   | 7      | OWASP (2021+2025), NIST 800-53, MITRE ATT&CK, NCSA, PDPA, SOC 2, ISO 27001                            |
| CWE Mappings            | ~486   | Across 8 mapping files (including severity-policy.json)                                               |
| Output Formats          | 8      | JSON, SARIF, Markdown, HTML, PDF, CSV, VEX (CycloneDX+OpenVEX), Dashboard                             |
| Test Suites             | 42     | 1,302+ individual checks                                                                              |
| Pipeline Engine         | DAG    | Kahn's topological sort, 4 built-in pipelines, cycle detection                                        |
| Scan History            | SQLite | 7 subcommands, fingerprint upsert, multi-tool lifecycle scoping                                       |
| Security Dashboard      | HTML   | Alpine.js 3 + Chart.js 4, 6 panels, dark mode, self-contained                                         |
| Releases                | 20     | v1.0.0 → v3.1.0, shipped in 3 calendar days                                                           |
| QA Rounds               | 13     | 1,300+ checks passed                                                                                  |

### Architecture Summary

```
User prompt → keyword match in SKILL.md frontmatter
  → SKILL.md loaded → agent assigned
  → Agent loads reference file from skills/references/
  → job-dispatcher.sh → Docker container tool
  → result-collector.sh → json-normalizer.sh (10 tools)
  → dedup-findings.sh → scan-db.sh (SQLite persist)
  → Formatter → SARIF/JSON/MD/HTML/PDF/CSV/VEX/Dashboard
```

### Business Model (v3.1.0)

- **Plugin**: Free / MIT license — open-source
- **Revenue**: Consulting + Training services
- **Target market**: Thailand-first (NCSA/PDPA compliance as differentiator)
- **Service tiers**: Starter (training) → Pro (implementation) → Enterprise (managed security)

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
- **Value**: unified pipeline ที่ normalize findings จากทุก tool + DAG engine
- **Decision Loop**: On-the-Loop (AI เสนอ, review ก่อน apply)

### 3.3 Security Lead (หัวหน้าฝ่ายความปลอดภัย)

- **Need**: gate decisions + trend analysis ข้ามโปรเจ็กต์
- **Pain**: ขาด visibility ของ security posture ทั้ง organization
- **Value**: MCP tools สำหรับ compare scans, track compliance, security dashboard
- **Decision Loop**: In-the-Loop (ตัดสินใจ gate pass/fail)

### 3.4 Compliance Officer (เจ้าหน้าที่ compliance)

- **Need**: framework mapping + evidence generation สำหรับ audit
- **Pain**: ต้อง map findings ไปยัง regulatory frameworks ด้วยมือ
- **Value**: auto-mapping ไปยัง 7 frameworks + export SARIF/VEX/PDF reports
- **Decision Loop**: In-the-Loop (approve compliance status reports)

---

## 4. Problem Statement & Gaps

### Resolved Gaps (v2.1.0 → v3.1.0)

| #   | Gap                        | Resolution                                                  | Release |
| --- | -------------------------- | ----------------------------------------------------------- | ------- |
| 4.1 | OWASP 2025 Migration       | Dual-version tagging (2021+2025) in cwe-to-owasp.json       | v2.7.0  |
| 4.2 | No CI/CD Integration       | GitHub Actions (4 reusable + 4 copy-paste) + GitLab CI (4)  | v2.6.0  |
| 4.3 | Incomplete OWASP Rules     | 84 rules covering 10/10 OWASP categories                    | v2.8.0  |
| 4.4 | No Supply Chain Compliance | SLSA skill + VEX formatter + TruffleHog integration         | v2.8.0  |
| 4.5 | NCSA Standards 1.0 Review  | NCSA validator with Permissions-Policy, COOP, COEP, TLS 1.3 | v2.7.0  |
| 4.6 | No PDPA-Specific Scanning  | cwe-to-pdpa.json (30 CWEs) + MCP compliance_status          | v2.7.0  |
| 4.7 | Single DAST Tool           | Nuclei integration (3 modes: cve/full/custom)               | v2.7.0  |
| 4.8 | No Historical Scan Data    | SQLite scan-db.sh (7 subcommands) + security dashboard      | v3.0.0  |
| 4.9 | Technical Debt             | esbuild bundle, version-bump.sh, python3 JSON parser        | v2.6.0  |

### Open Gaps (future work)

| #    | Gap                          | Impact                                                 | Priority |
| ---- | ---------------------------- | ------------------------------------------------------ | -------- |
| 4.10 | No real-time scanning        | ไม่สามารถ scan ขณะ developer พิมพ์ code                | P3       |
| 4.11 | Single-project scope         | Dashboard/history ไม่รองรับ multi-project view         | P2       |
| 4.12 | No GitHub/GitLab PR comments | Findings ไม่แสดงเป็น inline comments ใน PR             | P2       |
| 4.13 | Limited language detection   | Stack analyst ตรวจจับ 6 languages (ขาด Go, Kotlin)     | P3       |
| 4.14 | No Podman support            | Docker Desktop licensing อาจเป็นปัญหา                  | P3       |
| 4.15 | NCSA final standard review   | Final standard อาจแตกต่างจาก draft (deadline Sep 2026) | P1       |

---

## 5. Competitive Landscape

| Feature                     | DevSecOps AI Team | Snyk (CLI)  | GitHub Advanced Security | Semgrep App  |
| --------------------------- | ----------------- | ----------- | ------------------------ | ------------ |
| AI-powered remediation      | Yes (18 agents)   | Limited     | Copilot Autofix          | AI rules     |
| Multi-tool orchestration    | 11 tools          | 3 tools     | CodeQL + Dependabot      | Semgrep only |
| DAG pipeline engine         | Yes               | No          | No                       | No           |
| Custom rule authoring       | Yes (84 rules)    | No          | CodeQL QL                | Yes          |
| Compliance mapping          | 7 frameworks      | 1 (OWASP)   | None                     | None         |
| Thai regulatory (NCSA/PDPA) | Yes               | No          | No                       | No           |
| Open-source tools           | 100%              | Proprietary | Proprietary              | Freemium     |
| Claude Code native          | Yes               | No          | No                       | No           |
| MCP integration             | 10 tools          | No          | No                       | No           |
| Security dashboard          | Yes (self-hosted) | Cloud only  | Cloud only               | Cloud only   |
| Scan history + trends       | Yes (SQLite)      | Cloud only  | Cloud only               | Cloud only   |
| Pricing                     | Free (MIT)        | $25+/dev/mo | $49+/committer/mo        | Free tier    |

**Differentiation**: Native Claude Code integration + Thai regulatory compliance + open-source multi-tool orchestration + DAG pipeline + self-hosted (no data leaves your machine). ไม่มี competitor ที่ทำทั้ง 5 อย่างนี้พร้อมกัน

---

## 6. Release Roadmap

### Completed Milestones

| Version | Theme                           | Status  | Date       | Key Deliverables                                      |
| ------- | ------------------------------- | ------- | ---------- | ----------------------------------------------------- |
| v2.6.0  | CI/CD Integration + Tech Debt   | ✅ Done | 2026-03-03 | GitHub Actions, GitLab CI, esbuild bundle, ci-adapter |
| v2.7.0  | OWASP 2025 + DAST Expansion     | ✅ Done | 2026-03-03 | Dual OWASP, Nuclei DAST, PDPA mapping, 20 new rules   |
| v2.8.0  | Supply Chain Compliance + Rules | ✅ Done | 2026-03-03 | SLSA, VEX, TruffleHog, SOC 2/ISO 27001, OWASP 10/10   |
| v3.0.0  | Platform (daggr-inspired)       | ✅ Done | 2026-03-03 | DAG pipeline, scan-db, dashboard, K8s, GraphQL        |
| v3.1.0  | Commercial Ready                | ✅ Done | 2026-03-03 | README redesign, onboarding docs, demo scenarios      |

### Future Roadmap

| Version | Theme                          | Priority | Target  | Key Deliverables                                    |
| ------- | ------------------------------ | -------- | ------- | --------------------------------------------------- |
| v3.2.0  | Multi-Project & PR Integration | P2       | Q2 2026 | Multi-project dashboard, GitHub PR inline comments  |
| v3.3.0  | Extended Language Support      | P3       | Q2 2026 | Go, Kotlin, Swift detection + Semgrep rules         |
| v4.0.0  | Enterprise Platform            | P2       | Q3 2026 | Team workspace, RBAC, centralized policy management |

### v3.0.0 Architecture (daggr-inspired) — Implemented

ได้รับแรงบันดาลใจจาก [gradio-app/daggr](https://github.com/gradio-app/daggr) — DAG-based AI workflow library:

1. **DAG Node Graph** — Scan pipeline modeled as a directed acyclic graph. แต่ละ tool เป็น node ที่มี typed inputs/outputs สามารถ compose pipeline ได้อย่างยืดหยุ่น (`runner/pipeline-engine.sh`)

2. **Provenance Tracking** — ทุก scan result ถูก persist ใน SQLite พร้อม exact inputs สำหรับ replay. Full execution history enables audit trail และ trend analysis (`scripts/scan-db.sh`)

3. **Step Re-execution** — สามารถ re-run individual tool (เช่น Semgrep) โดยไม่ต้อง re-run ทั้ง pipeline. ลด scan time สำหรับ iterative development

4. **Visual Canvas** — HTML dashboard แสดง pipeline results + per-tool breakdown. Interactive drill-down จาก overview ไปยัง finding details (`templates/dashboard.html`)

5. **Concurrency Groups** — Resource-aware parallel execution. เช่น ZAP ใช้ memory เยอะ จึงรันได้ 1 instance ขณะที่ Semgrep + Grype รันพร้อมกันได้ (`runner/ci-adapter.sh`)

---

## 7. Success Metrics

| Metric                      | v3.1.0 Actual | v3.0.0 Target | v4.0.0 Target |
| --------------------------- | ------------- | ------------- | ------------- |
| OWASP custom rules coverage | 10/10 ✅      | 10/10 ✅      | 10/10         |
| CWE mappings                | ~486 ✅       | 500+          | 600+          |
| Test count                  | 1,302+ ✅     | 1,300+ ✅     | 1,500+        |
| MCP tools                   | 10 ✅         | 12+           | 14+           |
| CI/CD platforms supported   | 3 ✅          | 3+ ✅         | 4+            |
| Compliance frameworks       | 7 ✅          | 8+            | 9+            |
| Custom Semgrep rules        | 84 ✅         | 75+ ✅        | 100+          |
| DAST tools                  | 2 ✅          | 3+            | 3+            |
| Output formats              | 8 ✅          | 8+ ✅         | 10+           |
| Docker tool integrations    | 11 ✅         | 10+ ✅        | 13+           |
| Documentation pages         | 20+ ✅        | —             | 25+           |

---

## 8. Non-Functional Requirements

### 8.1 Performance

- Full 11-tool scan MUST complete within 30 minutes for a medium project (100K LOC)
- Individual tool scan MUST complete within 5 minutes
- MCP tool responses MUST return within 10 seconds (excluding scan execution)
- Deduplication MUST process 1,000 findings in under 5 seconds
- DAG pipeline MUST detect cycles before execution (fail-fast)

### 8.2 Security

- Plugin MUST NOT store or transmit source code outside Docker containers
- Docker containers MUST run with `--network=none` where possible (except ZAP/Nuclei DAST)
- No credentials stored in plugin files — use environment variables
- DAST targets MUST require explicit user approval (In-the-Loop)
- Secret scanning MUST NOT log found secrets in output
- Secret verifier MUST require `--confirm` flag (In-the-Loop)
- Dashboard MUST be self-contained HTML (no external CDN dependencies)

### 8.3 Compatibility

- Docker Engine 20.10+ required
- Node.js 18+ for MCP server
- Claude Code latest stable release
- Supports macOS (arm64, x86_64) and Linux (x86_64)

### 8.4 Reliability

- All test suites MUST pass before release (validate-plugin.sh = gate, currently 276 checks)
- QA station testing MUST be completed for every release
- Graceful degradation when individual tools are unavailable
- MCP server MUST validate all inputs via Zod schemas
- scan-db.sh MUST scope finding lifecycle by source_tool (v3.0.4 fix)

### 8.5 Maintainability

- Function size limit: 50 lines (governance enforced)
- File size limit: 800 lines
- Conventional commits required (feat, fix, refactor, docs, test, chore, perf, ci)
- CHANGELOG.md updated for every release
- Version synced across 7 files via `scripts/version-bump.sh`

---

## 9. Risk Assessment

| Risk                                                  | Likelihood | Impact | Mitigation                                                     | Status        |
| ----------------------------------------------------- | ---------- | ------ | -------------------------------------------------------------- | ------------- |
| OWASP 2025 mapping breaks existing reports            | Medium     | High   | Dual-version tagging (2021+2025) in cwe-to-owasp.json          | ✅ Mitigated  |
| EU CRA deadline missed (Sep 2026)                     | Low        | High   | SLSA skill + VEX formatter implemented in v2.8.0               | ✅ Mitigated  |
| NCSA Standards 1.0 changes from draft                 | Medium     | Medium | Validator built, review needed before Sep 2026 deadline        | ⚠️ Monitoring |
| ZAP community support decline (Checkmarx acquisition) | Low        | Medium | Nuclei added as complement in v2.7.0                           | ✅ Mitigated  |
| GitHub SARIF format changes again                     | Low        | Medium | SARIF formatter behind abstract interface                      | ✅ Mitigated  |
| Docker Desktop licensing changes                      | Low        | Low    | Document Podman as alternative (open gap #4.14)                | ⚠️ Open       |
| daggr library abandoned/API changes                   | Medium     | Low    | Inspired by patterns, not dependent on library                 | ✅ N/A        |
| MCP protocol breaking changes                         | Medium     | Medium | Zod schema validation + esbuild bundle                         | ✅ Mitigated  |
| Claude Code plugin API changes                        | Medium     | High   | validate-plugin.sh (276 checks) catches structural regressions | ⚠️ Monitoring |

### Regulatory Timeline

| Regulation                          | Deadline     | Impact                          | Status                       |
| ----------------------------------- | ------------ | ------------------------------- | ---------------------------- |
| NCSA Website Security Standards 1.0 | Sep 16, 2026 | Thai government/CII compliance  | ✅ Validator built (v2.7.0)  |
| EU CRA vulnerability reporting      | Sep 11, 2026 | SBOM + vulnerability disclosure | ✅ SLSA + VEX ready (v2.8.0) |
| EU CRA full SBOM requirement        | Dec 11, 2027 | CycloneDX/SPDX compliance       | ✅ Syft SBOM + VEX (v2.8.0)  |
| PDPA enforcement (ongoing)          | Continuous   | THB 21.5M fines in 2025         | ✅ Mapping ready (v2.7.0)    |

---

_Document version: 2.0 | Updated: v3.1.0 release (2026-03-03) | Next review: v4.0.0 planning_
