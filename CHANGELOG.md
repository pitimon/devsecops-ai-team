# Changelog

All notable changes to the DevSecOps AI Team plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-03-02

### Added

- **NCSA Website Security Standard v1.0 mapping** — new `mappings/cwe-to-ncsa.json` with 52 CWE mappings across 7 categories (HTTP Security, Transport Security, Authentication, Session Management, Input Validation, Error Handling, Access Control). Thai national web security standard จาก สพธอ.
- **MCP `ncsa` framework support** — `devsecops_compliance` tool now accepts `ncsa` in frameworks enum; default framework list includes NCSA
- **NCSA section in compliance reference** — `skills/references/compliance-frameworks.md` expanded with categories, key requirements, and NCSA→OWASP→NIST cross-walk table
- **2 new MCP handler tests** — NCSA mapping validation + Zod schema acceptance (handlers 23→25, total 354)
- **NCSA entry in `frameworks.json`** — 16 frameworks tracked (was 15)

### Fixed

- **Stale README counts** (Issue #13): test badge 334→354, CWE counts 86/78/68→96/90/83, test breakdown updated to 6 current suites

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
