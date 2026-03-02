# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## What This Is

A Claude Code **plugin skill pack** (`devsecops-ai-team`) distributed via the `pitimon-devsecops` marketplace. It provides 18 AI agents and 13 skills for enterprise DevSecOps security scanning across the full pipeline (SAST, DAST, SCA, Container, IaC, Secrets, SBOM, Compliance, IR) using open-source tools in Docker containers.

There are no build/lint/test commands for source code — this is a pure markdown/JSON/shell skill definition repository.

## Architecture

### Plugin System

```
User prompt → keyword match in SKILL.md frontmatter
  → SKILL.md loaded → agent assigned based on task
  → Agent loads reference file from skills/references/
  → job-dispatcher.sh routes to Docker container tool
  → result-collector.sh normalizes output
  → Formatter produces SARIF/JSON/MD/HTML
```

### Three Layers

1. **Plugin metadata** (`.claude-plugin/`) — Marketplace and plugin identity
2. **Skills + Agents** (`skills/`, `agents/`) — 13 skills and 18 agents
3. **Sidecar Runner** (`runner/`) — Docker container orchestration for security tools

### Key Files

| File                              | Role                                               |
| --------------------------------- | -------------------------------------------------- |
| `.claude-plugin/plugin.json`      | Plugin manifest (name, version, skills path)       |
| `.claude-plugin/marketplace.json` | Marketplace registry entry                         |
| `skills/*/SKILL.md`               | Skill definitions (13 skills)                      |
| `skills/references/*.md`          | On-demand domain knowledge (16 files)              |
| `agents/*/`                       | Agent definitions (18 agents in 4 groups)          |
| `hooks/hooks.json`                | Hook registrations (3 hooks)                       |
| `runner/`                         | Sidecar Runner (Dockerfile, compose, scripts)      |
| `formatters/`                     | Output formatters (SARIF, JSON, MD, HTML)          |
| `mappings/`                       | Compliance mappings (CWE to OWASP/NIST/MITRE/NCSA) |
| `frameworks.json`                 | Framework version tracking (16 frameworks)         |

### Agent Groups

| Group         | Count | Purpose                          |
| ------------- | ----- | -------------------------------- |
| Orchestrators | 3     | Coordinate team activities       |
| Specialists   | 7     | Tool-specific deep expertise     |
| Experts       | 4     | Cross-cutting security concerns  |
| Core Team     | 4     | Quality assurance and operations |

### Tools (Docker containers)

| Tool     | Purpose   | Image                            |
| -------- | --------- | -------------------------------- |
| Semgrep  | SAST      | `returntocorp/semgrep:latest`    |
| ZAP      | DAST      | `ghcr.io/zaproxy/zaproxy:stable` |
| Grype    | SCA       | `anchore/grype:latest`           |
| Trivy    | Container | `aquasec/trivy:latest`           |
| Checkov  | IaC       | `bridgecrew/checkov:latest`      |
| GitLeaks | Secrets   | `zricethezav/gitleaks:latest`    |
| Syft     | SBOM      | `anchore/syft:latest`            |

## Critical Naming Conventions

These identifiers must stay consistent across all config files:

| Identifier       | Value                                 | Used in                     |
| ---------------- | ------------------------------------- | --------------------------- |
| Marketplace name | `pitimon-devsecops`                   | marketplace.json            |
| Plugin name      | `devsecops-ai-team`                   | plugin.json, SKILL.md files |
| Install key      | `devsecops-ai-team@pitimon-devsecops` | installed_plugins.json      |
| GitHub path      | `pitimon/devsecops-ai-team`           | marketplace.json source     |
| Source type      | `"github"` (never `"local"`)          | known_marketplaces.json     |

## Contributing

### Adding a New Skill

1. Create `skills/<skill-name>/SKILL.md` with YAML frontmatter
2. Add trigger keywords and allowed-tools
3. Declare Decision Loop classification
4. Update README.md and CHANGELOG.md
5. Add smoke test prompts to `tests/smoke-test-prompts.md`

### Adding a New Agent

1. Create `agents/<group>/<agent-name>.md` with YAML frontmatter (name, description, model, tools)
2. Follow exact format from `agents/orchestrators/devsecops-lead.md`
3. Declare Decision Loop in description
4. Update session-start.sh agent listing
5. Add to `docs/AGENT-CATALOG.md`

### Adding a New Tool

1. Add tool to `runner/docker-compose.yml` with its own profile
2. Create skill in `skills/<tool-name>/SKILL.md`
3. Add test fixture in `tests/fixtures/`
4. Update `scripts/check-prerequisites.sh`
5. Add to `runner/job-dispatcher.sh` routing table

### Framework Version Updates

1. Update `frameworks.json` first (version, released, last_checked)
2. Run `grep -r` using patterns from the entry's `grep_patterns`
3. Update all files listed in `used_in`
4. See `docs/FRAMEWORK-UPDATE-RUNBOOK.md` for details

## Bilingual Output Policy

All skill output uses Thai prose with inline English technical terms:

- Section headers: "ผลการสแกน (Scan Results)"
- Prose: Thai
- Technical terms, tool names, framework names: English
- Code snippets, SARIF, JSON: English

## Governance Integration

This plugin extends (not duplicates) the claude-governance framework:

- Uses same agent format as governance-reviewer.md
- Hooks are additive with governance hooks
- DOMAIN.md follows governance pattern
- ADRs extend governance template with threat model fields
