# Changelog

All notable changes to the DevSecOps AI Team plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.7.0] — 2026-03-03

### Added

- OWASP Top 10 2025 dual-version mapping (2021+2025) across all 114 CWEs
- OWASP 2025 framework entry in frameworks.json (17 frameworks)
- Custom Semgrep rules: A02 Cryptographic Failures (6 rules)
- Custom Semgrep rules: A04 Insecure Design (4 rules)
- Custom Semgrep rules: A05 Security Misconfiguration (6 rules)
- Custom Semgrep rules: A10 Exception Handling (4 rules, new 2025 category)
- Nuclei DAST integration (Docker, dispatcher, normalizer, skill, tests)
- PDPA compliance mapping (30 CWEs, mappings/cwe-to-pdpa.json)
- PDPA support in MCP compliance_status tool (5 frameworks)
- NCSA 1.0 validator: Permissions-Policy, COOP, COEP, TLS 1.3 checks
- 7 new test suites (test-a02, test-a04, test-a05, test-nuclei-integration, test-pdpa-mapping, test-a10 extended)

### Changed

- OWASP 2025 dual-tags added to all 33 existing custom Semgrep rules
- DAST skill extended to support Nuclei alongside ZAP
- cwe-to-owasp.json migrated to dual-version format with 114 entries
- MCP compliance_status now supports 5 frameworks (added PDPA)
- frameworks.json OWASP 2021 entry marked as superseded

## [2.6.1] — 2026-03-03

### Added

- **GitHub Actions copy-paste templates** (`ci-templates/github/`) — 4 workflow files mirroring `.github/workflows/templates/` for copy-paste consumption parity with GitLab templates (#57)
- CI-INTEGRATION.md updated with copy-paste template documentation
- validate-plugin.sh Section 15 checks for `ci-templates/github/` files (+4 checks)
- test-ci-templates.sh Section 2 with 20 GitHub copy-paste template tests (existence, triggers, inputs, headers, content parity)

## [2.6.0] — 2026-03-03

### Added

- **GitHub Actions reusable workflows** — 4 templates (SAST, SCA, container scan, full pipeline) with SARIF upload via `workflow_call` (#33)
- **GitLab CI templates** — 4 templates producing native report artifacts (sast, dependency_scanning, container_scanning) with `resource_group` for heavy tools (#34)
- **CI adapter layer** (`runner/ci-adapter.sh`) — platform-agnostic CI/CD functions for GitHub Actions, GitLab CI, and local execution (#38)
- **Concurrency groups** (`runner/concurrency-groups.json`) — tool classification by resource weight (heavy/medium/light) for parallel scheduling (#38)
- **Pipeline runner** (`runner/run-pipeline.sh`) — orchestrates multiple tools with concurrency-aware scheduling (#38)
- **MCP server esbuild bundle** (`mcp/dist/server.js`) — zero npm install deployment, committed ~622KB bundle (#32)
- **Per-tool SARIF output** — SARIF formatter now creates one run per source tool with proper metadata; `--combined` flag for legacy mode (#35)
- **Version bump script** (`scripts/version-bump.sh`) — automated version bump across all 7 files with `--dry-run` support (#36)
- **GitLab SAST converter** (`ci-templates/converters/gitlab-sast-converter.sh`) — normalized JSON to GitLab v15.0.7 schema
- **CI integration documentation** (`docs/CI-INTEGRATION.md`) — consumer guide for both GitHub Actions and GitLab CI
- **Product Requirements Document** (`docs/PRD.md`) — 9-section strategic blueprint covering v2.6.0 → v3.0.0 roadmap
- **Domain Model** (`DOMAIN.md`) — 11 entities, 6 bounded contexts, 19 invariants, 7 domain events
- GitHub milestones (v2.6.0, v2.7.0, v2.8.0, v3.0.0) and 24 roadmap issues
- 4 new test suites: test-version-bump.sh (17), test-ci-adapter.sh (25), test-ci-templates.sh (45), test-formatters.sh (+12)

### Changed

- `hooks/scan-on-write.sh` — replaced fragile grep-based JSON parsing with robust python3 parser (#37)
- `tests/validate-plugin.sh` — replaced 6 hardcoded counts with dynamic computation (#37)
- `.mcp.json` — now points to bundled `mcp/dist/server.js` instead of `mcp/server.mjs` (#32)
- Validate-plugin checks expanded from 237 to 249+
- Total test count: ~770+ (was 719)

## [2.5.0] — 2026-03-03

### Added

- **A01 Broken Access Control** — 8 custom Semgrep rules (CWE-862, CWE-639, CWE-22, CWE-942, CWE-269)
- **A03 Injection** — 11 custom Semgrep rules (CWE-89, CWE-78, CWE-79, CWE-90, CWE-1336)
- **A10 SSRF** — 7 custom Semgrep rules (CWE-918) with cloud metadata, DNS rebinding, private IP detection
- **MCP compare tool** (`devsecops_compare`) — diff two scans showing new/fixed/unchanged findings with trend
- **MCP compliance_status tool** (`devsecops_compliance_status`) — aggregate compliance across 4 frameworks
- **MCP suggest_fix tool** (`devsecops_suggest_fix`) — remediation suggestions from CWE/rule knowledge
- **PDF formatter** (`formatters/pdf-formatter.sh`) — enterprise PDF export via pandoc
- **CSV formatter** (`formatters/csv-formatter.sh`) — spreadsheet-compatible CSV export
- 4 new test suites: test-a01-rules.sh (29), test-a03-rules.sh (32), test-a10-rules.sh (23), test-mcp-compare.sh (22)
- 6 new test fixtures for A01, A03, A10 findings and compare baseline/current

### Changed

- Custom OWASP rule coverage expanded from 1/10 (A09) to 4/10 (A01, A03, A09, A10)
- MCP server tools expanded from 5 to 8
- Output formats expanded from 4 to 6 (added PDF, CSV)
- Job dispatcher now loads A01, A03, A10 custom rules alongside A09
- SAST patterns reference expanded with A01, A03, A10 rule documentation
- Total test count: ~700+ (was 587)

### Fixed

- DAST specialist agent now references NCSA validator step (QA Round 8 issue #28)

## [2.4.0] - 2026-03-02

### Added

- **A09 Custom Semgrep Rules** — 7 rules (5 categories) targeting OWASP A09:2021 anti-patterns:
  - `a09-missing-auth-logging` (CWE-778): Auth functions without audit logs
  - `a09-catch-without-logging` (CWE-390): Silent exception swallowing (Python + JS/TS)
  - `a09-sensitive-data-in-log` (CWE-532): PII/secrets in log output (Python + JS/TS)
  - `a09-log-injection` (CWE-117): Unsanitized request data in logs
  - `a09-missing-rate-limit-logging` (CWE-778): Rate limit events not logged
  - Auto-loaded by `job-dispatcher.sh` during SAST scans
- **ZAP Multi-Mode Dispatcher** — 3 scan modes in `run_zap()`:
  - `baseline` (default, 120s): passive scan via `zap-baseline.py`
  - `full` (1800s): active scan via `zap-full-scan.py` with injection payloads
  - `api` (600s): spec-driven scan via `zap-api-scan.py` with OpenAPI support
  - `--auth-token` flag for authenticated scanning (Bearer token injection)
  - `--api-spec` flag for OpenAPI/Swagger-driven API scans
- **NCSA Website Security Validator** — `scripts/dast-ncsa-validator.sh`:
  - NCSA 1.x: HTTP Security Headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy)
  - NCSA 2.x: Transport Security (TLS >= 1.2, HTTPS, certificate validity)
  - NCSA 4.x: Session Management (Cookie Secure, HttpOnly, SameSite flags)
  - ZAP results cross-reference (CWE → NCSA category mapping)
  - JSON report output with pass/fail/warning per check
- **DAST Live Testing** — `tests/test-dast-live.sh` (conditional on `DAST_TARGET` env var):
  - ZAP baseline/full scan against real targets
  - NCSA validation integration with live output
  - Normalizer and gate evaluation on live results
- **86 new tests** across 3 new suites:
  - `test-a09-rules.sh` (28): rule YAML, metadata, CWE cross-ref, semgrep --validate
  - `test-zap-modes.sh` (34): mode parsing, timeout, Docker commands, fixtures, docs
  - `test-ncsa-validator.sh` (24): script structure, header checks, output format, NCSA mapping
  - `test-dast-live.sh` (15 conditional): live ZAP + NCSA + normalizer integration

### Changed

- `runner/job-dispatcher.sh` — A09 rule auto-loading + ZAP multi-mode dispatch
- `skills/dast-scan/SKILL.md` — 3 scan modes, NCSA validation step
- `agents/specialists/dast-specialist.md` — mode selection decision tree
- `skills/references/logging-monitoring.md` — Section 8: custom rules reference
- **547 total tests** (was 461)

## [2.3.0] - 2026-03-02

### Added

- **`/auto-fix` skill** (Issue #7 Phase 2) — automated security remediation ที่อ่าน scan results, generate patches, present for approval, apply edits, แล้ว re-scan verify:
  - `skills/auto-fix/SKILL.md` — 8-step On-the-Loop workflow (AI เสนอ fix, มนุษย์อนุมัติ)
  - Flags: `--dry-run`, `--severity`, `--file`, `--cwe` สำหรับ targeted fixing
  - Delegates to `@agent-remediation-advisor` พร้อม framework detection อัตโนมัติ
  - `agents/experts/remediation-advisor.md` — เพิ่ม `Edit` tool + Section 6 "Apply Fixes"
  - `agents/orchestrators/devsecops-lead.md` — เพิ่ม auto-fix routing entry
- **A08/A09 reference files** — ปิด compliance coverage gaps:
  - `skills/references/software-integrity.md` — OWASP A08 patterns: CI/CD pipeline integrity, Sigstore/cosign, SLSA, SRI, unsafe deserialization (CWE-502), mass assignment (CWE-915)
  - `skills/references/logging-monitoring.md` — OWASP A09 patterns: security event taxonomy, structured logging, log injection (CWE-117), SIEM integration, sensitive data in logs (CWE-532)
- **DAST integration tests** — `tests/test-dast-integration.sh` (22 tests): ZAP fixture validation, normalizer integration, job-dispatcher config, conditional Docker live scan
- **MCP Docker integration tests** — `tests/test-mcp-integration.sh` (37 tests): Docker availability, tool images, MCP handler logic, runner infrastructure, conditional functional test
- **ZAP baseline fixture** — `tests/fixtures/sample-zap-baseline.json` with 5 alerts across mixed severity levels (Medium + Low)
- **Auto-fix tests** — `tests/test-auto-fix.sh` (37 tests): SKILL.md structure, process steps, arguments, agent config, orchestrator routing, bilingual output
- **NCSA Session/Error coverage expansion** — `cwe-to-ncsa.json` expanded 52→62 CWEs:
  - Session Management (4.x): +6 CWEs covering items 4.1-4.5 (CWE-613, CWE-1004, CWE-614, CWE-330, CWE-331)
  - Error Handling (6.x): +4 CWEs covering items 6.1-6.4 (CWE-489, CWE-754, CWE-755, updated CWE-223)
- **13 CWEs เพิ่มเติมใน cross-mappings** — sync ข้าม 4 ไฟล์:
  - `cwe-to-owasp.json`: 96 → 105 CWEs (+9: A07 session, A08 integrity, A09 logging)
  - `cwe-to-nist.json`: 90 → 100 CWEs (+10: AC-12, SC-23, SC-13, AU families)
  - `cwe-to-mitre.json`: 83 → 93 CWEs (+10: T1539, T1557, T1110, T1082 techniques)

### Changed

- **Skills count**: 12 → 13 (added `/auto-fix`)
- **Reference files count**: 10 → 12 (added `software-integrity.md`, `logging-monitoring.md`)
- **Test suites**: 6 → 9 (added `test-auto-fix.sh`, `test-dast-integration.sh`, `test-mcp-integration.sh`)
- **Total tests**: 354 → 461 (+107 tests)
- **`compliance-frameworks.md`** — expanded A08/A09 OWASP table rows with full CWE lists; NCSA Session 5→11 CWEs, Error 4→10 CWEs
- **`sbom-generate/SKILL.md`** — loads `software-integrity.md` reference for A08 verification

## [2.2.1] - 2026-03-02

### Added

- **NCSA Website Security Standard v1.0 mapping** — เพิ่ม `mappings/cwe-to-ncsa.json` จำนวน 52 CWEs ใน 7 หมวดหมู่ (HTTP Security, Transport Security, Authentication, Session Management, Input Validation, Error Handling, Access Control) มาตรฐานความมั่นคงปลอดภัยเว็บไซต์ระดับชาติจาก สพธอ.
- **MCP `ncsa` framework support** — `devsecops_compliance` รองรับ `ncsa` ใน frameworks enum; default framework list รวม NCSA
- **NCSA section ใน compliance reference** — เพิ่มหมวดหมู่, ข้อกำหนดสำคัญ, และ NCSA→OWASP→NIST cross-walk table ใน `compliance-frameworks.md`
- **2 MCP handler tests ใหม่** — ตรวจสอบ NCSA mapping + Zod schema (handlers 23→25, รวม 354)
- **NCSA entry ใน `frameworks.json`** — ติดตาม 16 frameworks (เดิม 15)

### Fixed

- **ตัวเลขเก่าใน README** (Issue #13): test badge 334→354, CWE counts 86/78/68→96/90/83, test breakdown อัปเดตเป็น 6 suites

## [2.2.0] - 2026-03-02

### Fixed

- **BUG-9 (MEDIUM)**: C# false positive detection in `session-start.sh` — `ls *.csproj | head -1` always returned 0 due to pipeline semantics; replaced with `compgen -G` glob check. Also fixed `[ -f "*.sln" ]` which tested literal filename instead of globbing (closes #10, #11)

### Added

- **Framework-aware remediation** (Issue #7 Phase 1):
  - `skills/references/remediation-django.md` — Django 5.x/4.x patterns: `|safe` decision tree, `format_html()`, ORM vs raw SQL, CSRF, session security, DRF permissions
  - `skills/references/remediation-react-nextjs.md` — React 18+/Next.js 14+ patterns: `dangerouslySetInnerHTML` alternatives, Server Components boundaries, CSP in `next.config.js`, Server Actions Zod validation
  - `skills/references/remediation-express-node.md` — Express 4.x/5.x patterns: `helmet.js`, `express-validator`, prototype pollution, `csrf-csrf` migration, `execFileSync` over `execSync`
  - `skills/references/remediation-spring.md` — Spring Boot 3.x/Security 6.x patterns: `SecurityFilterChain`, `@PreAuthorize`, JPA parameterized queries, `th:text` vs `th:utext`, BCrypt/Argon2
  - `agents/experts/remediation-advisor.md` — framework detection + conditional reference loading
- **Syft normalizer** — SBOM component inventory from CycloneDX-JSON format; OS components filtered, PURL preserved
- **65 new functional tests**:
  - `tests/test-hooks.sh` (27 tests) — session-start project detection, scan-on-write secret blocking, pre-commit gate logic
  - `tests/test-dedup.sh` (15 tests) — file/package/URL dedup keys, severity promotion, source concatenation, re-indexing
  - `tests/test-mcp-handlers.sh` (23 tests) — Zod validation, gate violations, compliance crosswalk, helper functions, policy file
- **TROUBLESHOOTING.md** — 5 new sections: MCP Server Connection, RBAC Policy, Zod Validation, CI/CD Integration, Dedup Script

### Removed

- Dead `runShellCommand()` function from `mcp/server.mjs` — defined in v2.1.0 refactor but never called; also removed unused `execSync` import

## [2.1.0] - 2026-03-01

### Security

- **Python3 dependency guard** — `hooks/scan-on-write.sh`, `hooks/pre-commit-gate.sh`, `formatters/json-normalizer.sh` now fail-fast with clear error if `python3` is not installed, preventing silent security bypass
- **MCP command injection fix** — `mcp/server.mjs` replaced `execSync(cmd)` string interpolation with `execFileSync(file, args)` array arguments to prevent command injection via user-supplied tool parameters
- **ZAP memory limits** — `runner/docker-compose.yml` adds `mem_limit: 2g` and `memswap_limit: 2g` to ZAP service to prevent OOM kills

### Added

- **15 CWEs** added to compliance mappings (closes #8):
  - `cwe-to-owasp.json`: 86 → 96 CWEs (+10: CWE-95, CWE-489, CWE-524, CWE-539, CWE-665, CWE-668, CWE-669, CWE-670, CWE-680, CWE-704)
  - `cwe-to-nist.json`: 78 → 90 CWEs (+12: above 10 + CWE-693, CWE-732)
  - `cwe-to-mitre.json`: 68 → 83 CWEs (+15: above 10 + CWE-120, CWE-400, CWE-601, CWE-693, CWE-732)
- **RBAC in `devsecops_gate`** — reads role-based policy from `severity-policy.json`, accepts `role` parameter (developer/security-lead/release-manager), defaults to `developer`
- **Zod input validation** — all 5 MCP tools validate inputs with Zod schemas, returning structured validation errors
- **Language detection** — `session-start.sh` now detects Rust (`Cargo.toml`), C# (`*.csproj`), PHP (`composer.json`)
- **ZAP OOM troubleshooting** — new section in `docs/TROUBLESHOOTING.md` for exit code 137 diagnosis and workarounds

### Fixed

- **`dedup-findings.sh`** — added missing execute permission (`chmod +x`)
- **Error suppression** — `job-dispatcher.sh` now logs tool stderr to `${RESULTS_DIR}/dispatcher.log` instead of `/dev/null`

## [2.0.2] - 2026-03-01

### Added

- **20 high-frequency CWEs** added to all 3 compliance mapping files:
  - `cwe-to-owasp.json`: 66 → 86 CWEs (+20: CWE-16, CWE-209, CWE-223, CWE-252, CWE-259, CWE-276, CWE-290, CWE-306, CWE-308, CWE-319, CWE-345, CWE-353, CWE-384, CWE-639, CWE-778, CWE-829, CWE-942, CWE-1035, CWE-1333, CWE-1336)
  - `cwe-to-nist.json`: 58 → 78 CWEs (mapped to CM-6, AU-2, SI-7, IA-2, SC-23, RA-5 controls)
  - `cwe-to-mitre.json`: 48 → 68 CWEs (mapped to T1562, T1070, T1195, T1565, T1222 techniques)
- Covers previously unmapped tool-reported CWEs: Security Misconfiguration, Vulnerable Components, IDOR, Session Fixation, CORS, ReDoS, Template Injection, Supply Chain, Insufficient Logging

## [2.0.1] - 2026-03-01

### Fixed

- **BUG-6 (MEDIUM)**: Semgrep null severity crash — `severity` key with null value now coalesces to `'MEDIUM'` before `.upper()`
- **BUG-7 (MEDIUM)**: Trivy null `Vulnerabilities`/`Misconfigurations` crash — null values now coalesce to empty list
- **BUG-8 (LOW)**: Trivy CWE IDs like `"CWE-250: Execution with Unnecessary Privileges"` now extract `CWE-NNN` prefix only

### Added

- **25 memory-safety & numeric CWEs** added to all 3 compliance mapping files:
  - `cwe-to-owasp.json`: 41 → 66 CWEs (buffer overflow, use-after-free, integer overflow, race condition, etc.)
  - `cwe-to-nist.json`: 33 → 58 CWEs (mapped to SI-16, SC-5, SC-4 controls)
  - `cwe-to-mitre.json`: 23 → 48 CWEs (mapped to T1203, T1499, T1068 techniques)

## [2.0.0] - 2026-03-01

### Fixed

- **BUG-1 (HIGH)**: Semgrep severity mapping — `ERROR`→`HIGH`, `WARNING`→`MEDIUM` (was 95% data loss)
- **BUG-2 (HIGH)**: Checkov now merges all check types (terraform + kubernetes + dockerfile)
- **BUG-3 (MEDIUM)**: Checkov null severity defaults to `MEDIUM` instead of passing through as null
- **BUG-4 (MEDIUM)**: Trivy now processes both `Vulnerabilities` and `Misconfigurations` arrays
- **BUG-5 (LOW)**: Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`

### Added

- **MCP Server** (`mcp/server.mjs`) — 5 MCP tools: `devsecops_scan`, `devsecops_results`, `devsecops_gate`, `devsecops_compliance`, `devsecops_status`
- **Cross-tool deduplicator** (`formatters/dedup-findings.sh`) — merges findings, keeps highest severity
- **Normalizer unit tests** (`tests/test-normalizer.sh`) — 34 tests covering severity mapping, multi-array, null safety, empty input
- **MCP server tests** (`tests/test-mcp-server.sh`) — 23 tests for server configuration, syntax, and tool definitions
- **New fixtures**: `sample-checkov-multi.json` (3 check types), `sample-trivy-misconfig.json` (vulns + misconfigs)
- **Smart project detection** in `session-start.sh` — recommends scans based on detected project files

### Changed

- **Agent Orchestration**: `devsecops-lead.md` now has mandatory routing table with explicit delegation chain
- **All 18 agents** standardized with orchestrator-cue lines (`MUST BE USED` / `Use PROACTIVELY`) and mission statements
- **`full-pipeline/SKILL.md`** updated with agent delegation chain and dedup step
- **`session-start.sh`** injects recommended scans and MCP tool availability

## [1.0.0] - 2026-03-01

### Added

- Initial release of DevSecOps AI Team plugin skill pack
- 18 specialized AI agents across 4 groups (Orchestrators, Specialists, Experts, Core Team)
- 12 skills covering full DevSecOps pipeline
- Sidecar Runner architecture with Docker container orchestration
- 7 security tools: Semgrep, ZAP, Grype, Trivy, Checkov, GitLeaks, Syft
- Compliance mappings: CWE to OWASP, NIST, MITRE ATT&CK
- Unified Finding Schema with SARIF, JSON, Markdown, HTML formatters
- Hook system: session context, scan-on-write, pre-commit gate
- 10 reference knowledge files for on-demand domain expertise
- Framework version tracking with quarterly staleness checks
- RBAC severity policies (developer, security-lead, release-manager)
- Bilingual Thai+English output
- Governance integration (extends claude-governance)
