# DOMAIN.md — DevSecOps AI Team Domain Model

> **Version**: 1.0 | **Date**: 2026-03-03 | **Plugin**: `devsecops-ai-team`

---

## Bounded Contexts

### 1. Scanning

**Responsibility**: เรียกใช้ security tools ผ่าน Docker containers, จัดการ custom rules, route jobs

| Component                        | Role                                                                      |
| -------------------------------- | ------------------------------------------------------------------------- |
| `runner/job-dispatcher.sh`       | Routes scan requests to Docker containers                                 |
| `runner/docker-compose.yml`      | Tool container definitions with profiles                                  |
| `rules/*.yml`                    | Custom Semgrep rules (84 rules across 13 files: 10 OWASP + K8s + GraphQL) |
| `scripts/check-prerequisites.sh` | Validates tool availability                                               |

**Invariants**: Scan targets MUST be validated before execution. DAST targets MUST require explicit user approval (In-the-Loop).

### 2. Analysis

**Responsibility**: normalize ผลลัพธ์จากหลาย tools, deduplicate findings, triage ตาม severity

| Component                      | Role                                             |
| ------------------------------ | ------------------------------------------------ |
| `runner/result-collector.sh`   | Normalizes tool output to unified Finding format |
| `formatters/dedup-findings.sh` | Cross-tool deduplication                         |
| MCP `devsecops_normalize`      | Programmatic normalization via MCP               |
| MCP `devsecops_triage`         | Severity-based triage and prioritization         |

**Invariants**: Findings MUST be deduplicated by (source_tool, cwe_id, location.file, location.line_start).

### 3. Compliance

**Responsibility**: map findings ไปยัง regulatory frameworks, track compliance coverage

| Component                         | Role                                      |
| --------------------------------- | ----------------------------------------- |
| `mappings/cwe-to-owasp.json`      | CWE → OWASP Top 10 (122 mappings)         |
| `mappings/cwe-to-nist.json`       | CWE → NIST 800-53 (100 mappings)          |
| `mappings/cwe-to-mitre.json`      | CWE → MITRE ATT&CK (93 mappings)          |
| `mappings/cwe-to-ncsa.json`       | CWE → NCSA (62 mappings)                  |
| `mappings/cwe-to-pdpa.json`       | CWE → PDPA (30 mappings)                  |
| `mappings/cwe-to-soc2.json`       | CWE → SOC 2 (40 mappings)                 |
| `mappings/cwe-to-iso27001.json`   | CWE → ISO 27001 (41 mappings)             |
| MCP `devsecops_compliance_status` | Aggregate compliance across 7 frameworks  |
| `scripts/dast-ncsa-validator.sh`  | NCSA Website Security Standards validator |

**Invariants**: ComplianceMapping entries MUST reference valid CWE identifiers. Compliance mappings MUST use current framework versions from `frameworks.json`.

### 4. Reporting

**Responsibility**: format findings เป็น output formats ที่หลากหลาย

| Component                           | Role                                         |
| ----------------------------------- | -------------------------------------------- |
| `formatters/sarif-formatter.sh`     | SARIF v2.1.0 output                          |
| `formatters/json-formatter.sh`      | Structured JSON output                       |
| `formatters/markdown-formatter.sh`  | Human-readable Markdown                      |
| `formatters/html-formatter.sh`      | Standalone HTML report                       |
| `formatters/pdf-formatter.sh`       | Enterprise PDF via pandoc                    |
| `formatters/csv-formatter.sh`       | Spreadsheet CSV export                       |
| `formatters/vex-formatter.sh`       | VEX output (CycloneDX VEX + OpenVEX)         |
| `formatters/dashboard-generator.sh` | Alpine.js + Chart.js HTML security dashboard |

**Invariants**: SARIF output MUST include `tool.driver.name` for GitHub Security tab categorization. Each tool MUST produce separate SARIF analysis (GitHub Jul 2025 change).

### 5. Orchestration

**Responsibility**: coordinate AI agents, skills, MCP tools

| Component               | Role                                                                              |
| ----------------------- | --------------------------------------------------------------------------------- |
| `agents/orchestrators/` | 3 orchestrator agents (DevSecOps Lead, Security Stack Analyst, Team Configurator) |
| `agents/specialists/`   | 7 specialist agents (tool-specific)                                               |
| `agents/experts/`       | 4 expert agents (cross-cutting)                                                   |
| `agents/core-team/`     | 4 core team agents (QA, ops)                                                      |
| `skills/*/SKILL.md`     | 16 skill definitions                                                              |
| `mcp/server.mjs`        | 10 MCP tools                                                                      |

**Invariants**: Agent.decision_loop MUST be one of: out-of-loop, on-the-loop, in-the-loop. MCP tools MUST validate input via Zod schemas before execution.

### 6. Gate

**Responsibility**: security gate decisions, RBAC policy, severity thresholds

| Component                              | Role                      |
| -------------------------------------- | ------------------------- |
| `skills/gate-review/SKILL.md`          | Gate review skill         |
| `agents/experts/compliance-advisor.md` | Compliance gate advisor   |
| MCP `devsecops_triage`                 | Gate threshold evaluation |

**Invariants**: GateResult.decision MUST be `fail` if any Finding with severity >= policy threshold exists and status is `open`. Gate decisions MUST reference the policy used and all scan IDs evaluated.

---

## Entities

### Finding

| Field       | Type     | Constraints                                                                                 |
| ----------- | -------- | ------------------------------------------------------------------------------------------- |
| id          | string   | Format: `FINDING-YYYYMMDD-NNN`, unique across all scans                                     |
| source_tool | enum     | One of: semgrep, zap, grype, trivy, checkov, gitleaks, syft, nuclei, trufflehog, kube-bench |
| scan_type   | enum     | One of: sast, dast, sca, container, iac, secret, sbom                                       |
| severity    | enum     | One of: CRITICAL, HIGH, MEDIUM, LOW, INFO                                                   |
| confidence  | enum     | One of: HIGH, MEDIUM, LOW                                                                   |
| title       | string   | Human-readable summary, max 200 chars                                                       |
| description | string   | Detailed explanation with context                                                           |
| cwe_id      | string   | Format: `CWE-NNN`, nullable                                                                 |
| cvss_score  | float    | 0.0-10.0, nullable (for SCA/container findings)                                             |
| location    | Location | Where the finding was detected                                                              |
| compliance  | object   | Framework mappings (OWASP, NIST, MITRE, NCSA, PDPA, SOC 2, ISO 27001)                       |
| owasp_2025  | string   | OWASP Top 10 2025 category (dual-tagging with 2021), nullable                               |
| remediation | object   | Fix guidance with code examples                                                             |
| status      | enum     | One of: open, suppressed, fixed, false_positive                                             |
| first_seen  | datetime | ISO 8601, when first detected                                                               |
| scan_id     | string   | Links to parent ScanRun                                                                     |

### Location

| Field      | Type   | Constraints                             |
| ---------- | ------ | --------------------------------------- |
| file       | string | Relative path from project root         |
| line_start | int    | 1-indexed, nullable (for container/SCA) |
| line_end   | int    | 1-indexed, nullable                     |
| snippet    | string | Code context, max 500 chars             |
| image      | string | Container image reference, nullable     |
| package    | string | Package name for SCA findings, nullable |
| resource   | string | IaC resource identifier, nullable       |

### ScanRun

| Field       | Type     | Constraints                                            |
| ----------- | -------- | ------------------------------------------------------ |
| id          | string   | Format: `SCAN-YYYYMMDD-HHMMSS-TOOL`                    |
| tool        | enum     | Same as Finding.source_tool                            |
| scan_type   | enum     | Same as Finding.scan_type                              |
| started_at  | datetime | ISO 8601                                               |
| finished_at | datetime | ISO 8601                                               |
| target      | string   | Scanned path, image, or URL                            |
| rules_used  | string[] | Rule sets or profiles applied                          |
| exit_code   | int      | Tool exit code                                         |
| summary     | object   | Count by severity: {critical, high, medium, low, info} |

### ComplianceMapping

| Field         | Type     | Constraints                               |
| ------------- | -------- | ----------------------------------------- |
| cwe_id        | string   | Source CWE identifier                     |
| owasp_top_10  | string[] | OWASP Top 10 2021 categories (A01-A10)    |
| owasp_2025    | string[] | OWASP Top 10 2025 categories, nullable    |
| nist_800_53   | string[] | NIST 800-53 control identifiers           |
| mitre_attack  | string[] | MITRE ATT&CK technique IDs                |
| ncsa          | string[] | NCSA Website Security Standards, nullable |
| pdpa          | string[] | PDPA article references, nullable         |
| cis_benchmark | string[] | CIS Benchmark control references          |

### GateResult

| Field        | Type     | Constraints                                   |
| ------------ | -------- | --------------------------------------------- |
| id           | string   | Format: `GATE-YYYYMMDD-HHMMSS`                |
| decision     | enum     | One of: pass, fail, warn                      |
| policy       | string   | Policy name applied (default, strict, custom) |
| role         | enum     | developer, security-lead, release-manager     |
| scan_ids     | string[] | ScanRun IDs evaluated                         |
| violations   | object[] | Findings that triggered failure               |
| evaluated_at | datetime | ISO 8601                                      |

### CustomRule

| Field          | Type     | Constraints                                                           |
| -------------- | -------- | --------------------------------------------------------------------- |
| id             | string   | Format: `{owasp_prefix}-{description}`, e.g. `a01-missing-auth-check` |
| owasp_category | string   | OWASP Top 10 category (e.g. A01, A03, A09, A10)                       |
| cwe_ids        | string[] | Related CWE identifiers                                               |
| severity       | enum     | One of: ERROR, WARNING, INFO                                          |
| languages      | string[] | Target languages (python, javascript, typescript, java)               |
| file_path      | string   | Path to rule YAML file                                                |
| pattern_count  | int      | Number of patterns in rule                                            |

### Agent

| Field         | Type     | Constraints                                            |
| ------------- | -------- | ------------------------------------------------------ |
| name          | string   | Unique agent name                                      |
| group         | enum     | One of: orchestrators, specialists, experts, core-team |
| description   | string   | Agent purpose and capabilities                         |
| model         | string   | Claude model (sonnet, opus, haiku)                     |
| tools         | string[] | Available tools for this agent                         |
| decision_loop | enum     | One of: out-of-loop, on-the-loop, in-the-loop          |

### Skill

| Field            | Type     | Constraints                                   |
| ---------------- | -------- | --------------------------------------------- |
| name             | string   | Skill name matching directory name            |
| trigger_keywords | string[] | Keywords that activate this skill             |
| allowed_tools    | string[] | Tools this skill can invoke                   |
| decision_loop    | enum     | One of: out-of-loop, on-the-loop, in-the-loop |
| reference_files  | string[] | Reference documents loaded by this skill      |

### ScanComparison

| Field       | Type      | Constraints                             |
| ----------- | --------- | --------------------------------------- |
| baseline_id | string    | ScanRun ID of baseline scan             |
| current_id  | string    | ScanRun ID of current scan              |
| new         | Finding[] | Findings in current but not in baseline |
| fixed       | Finding[] | Findings in baseline but not in current |
| unchanged   | Finding[] | Findings present in both                |
| trend       | enum      | One of: improving, degrading, stable    |

### ComplianceStatus

| Field          | Type     | Constraints                                                       |
| -------------- | -------- | ----------------------------------------------------------------- |
| framework      | string   | Framework name (OWASP, NIST, MITRE, NCSA, PDPA, SOC 2, ISO 27001) |
| total_findings | int      | Total findings with CWE mapping                                   |
| mapped_count   | int      | Findings mapped to this framework                                 |
| coverage_pct   | float    | 0.0-100.0, mapped_count/total_findings                            |
| unmapped_cwes  | string[] | CWEs without framework mapping                                    |

### RemediationSuggestion

| Field              | Type   | Constraints                                      |
| ------------------ | ------ | ------------------------------------------------ |
| cwe_id             | string | CWE identifier                                   |
| rule_id            | string | Custom rule ID or tool rule ID, nullable         |
| fix_guidance       | string | Human-readable fix description                   |
| code_example       | string | Code snippet showing fix, nullable               |
| framework_specific | object | Framework-specific fixes (Django, Express, etc.) |

---

## Invariants

### Entity Invariants

1. Finding.severity MUST be one of the 5 defined levels — no custom values
2. Finding.id MUST be globally unique across all scan runs
3. Finding.status transitions: open → suppressed | fixed | false_positive (no reverse)
4. ScanRun.finished_at MUST be after ScanRun.started_at
5. GateResult.decision MUST be `fail` if any Finding with severity >= policy threshold exists and status is `open`
6. Suppressed findings MUST have a justification recorded in audit trail
7. DAST scan targets MUST be explicitly approved by user (In-the-Loop)

### Rule & Mapping Invariants

8. CustomRule.id MUST start with lowercase OWASP category prefix (a01-, a03-, a09-, a10-, etc.)
9. ComplianceMapping.owasp_2025 MUST be populated when owasp_top_10 (2021) exists
10. ComplianceMapping entries MUST reference valid CWE identifiers (`CWE-NNN` format)
11. Compliance mappings MUST use current framework versions from `frameworks.json`

### Agent & Skill Invariants

12. Agent.decision_loop MUST be one of: out-of-loop, on-the-loop, in-the-loop
13. MCP tools MUST validate input via Zod schemas before execution
14. Skill.trigger_keywords MUST be unique across all skills (no ambiguous routing)

### Output Invariants

15. SARIF output MUST include `tool.driver.name` for GitHub Security tab categorization
16. Each tool MUST produce separate SARIF analysis (GitHub Jul 2025 change)
17. All scan results MUST include ScanRun metadata
18. Findings MUST be deduplicated by (source_tool, cwe_id, location.file, location.line_start)
19. Output formats: SARIF v2.1.0, CycloneDX v1.5, SPDX v2.3

---

## API Contract Rules

- All scan results MUST include ScanRun metadata
- Findings MUST be deduplicated by (source_tool, cwe_id, location.file, location.line_start)
- Gate decisions MUST reference the policy used and all scan IDs evaluated
- Compliance mappings MUST use current framework versions from `frameworks.json`
- Output formats: SARIF v2.1.0, CycloneDX v1.5, SPDX v2.3
- MCP tool responses MUST return within 10 seconds (excluding scan execution)
- MCP errors MUST NOT leak internal file paths or stack traces

---

## Domain Events

| Event                  | Trigger                                         | Data                                                |
| ---------------------- | ----------------------------------------------- | --------------------------------------------------- |
| `ScanStarted`          | job-dispatcher.sh invokes Docker container      | ScanRun (partial: id, tool, target, started_at)     |
| `ScanCompleted`        | Container exits                                 | ScanRun (complete: exit_code, summary, finished_at) |
| `FindingDetected`      | Normalizer processes tool output                | Finding (full entity)                               |
| `FindingFixed`         | Comparison shows finding absent in current scan | Finding.id, current ScanRun.id                      |
| `GateEvaluated`        | Gate skill processes scan results               | GateResult (full entity)                            |
| `ComplianceMapped`     | Enrichment maps CWE to framework                | Finding.id, framework, mapped references            |
| `RemediationSuggested` | suggest_fix MCP tool invoked                    | RemediationSuggestion (full entity)                 |

---

## Entity Relationships

```
ScanRun 1──* Finding
Finding *──1 Location
Finding *──* ComplianceMapping (via cwe_id)
Finding *──0..1 RemediationSuggestion
GateResult *──* ScanRun (evaluates)
ScanComparison 1──2 ScanRun (baseline + current)
CustomRule *──* Finding (detects)
Agent *──* Skill (assigned to)
```

---

_Document generated: 2026-03-03 | Follows [governance DOMAIN.md pattern](https://github.com/anthropics/claude-governance)_
