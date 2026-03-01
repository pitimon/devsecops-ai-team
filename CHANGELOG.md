# Changelog

All notable changes to the DevSecOps AI Team plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
