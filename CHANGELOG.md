# Changelog

All notable changes to the DevSecOps AI Team plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
