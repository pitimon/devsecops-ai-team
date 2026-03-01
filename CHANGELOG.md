# Changelog

All notable changes to the DevSecOps AI Team plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
