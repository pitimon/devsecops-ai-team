# Commercial Product Polish Design

**Date**: 2026-03-03
**Version**: v3.1.0 (target)
**Status**: Approved
**Approach**: Surgical Fix (incremental, 4 phases)

## Context

devsecops-ai-team (v3.0.4) is technically mature — 18 agents, 16 skills, 11 Docker tools, 1,302+ tests across 42 suites, DAG pipeline engine, security dashboard, 6 compliance frameworks. However, it lacks the polish needed for commercial consulting/training business.

### Business Model

| Aspect        | Decision                                                               |
| ------------- | ---------------------------------------------------------------------- |
| Revenue model | Consulting + Training (plugin stays free/MIT)                          |
| Target market | Thailand-first (NCSA/PDPA as competitive moat)                         |
| Service tiers | Starter (training) → Pro (implement+train) → Enterprise (full managed) |
| Plugin role   | Lead generator and credibility anchor for services                     |

### Current Gaps

- Stale data across docs (version refs, test counts, format counts)
- README is 70KB info-dense developer doc, not a product presentation
- No onboarding path for new users
- No demo scenarios for sales conversations
- No service offering information

---

## Phase 1: Data Accuracy Fix

**Goal**: Every number, version reference, and count is consistent across all files.

### Known Issues

| Issue               | File(s)                  | Current                  | Correct                        |
| ------------------- | ------------------------ | ------------------------ | ------------------------------ |
| Output format count | README L95               | "7 Output Formats"       | "8 Output Formats"             |
| Output format count | CLAUDE.md formatters row | lists 7                  | list all 8 including Dashboard |
| Test count          | README (6 places)        | "1,284+"                 | "1,302+"                       |
| Test count          | PRD.md (2 places)        | "1,284"                  | "1,302+"                       |
| Test count          | INSTALL.md               | stale count              | "1,302+"                       |
| Version ref         | PRD.md (3 lines)         | "v3.0.2" / "3.0.2"       | "v3.0.4"                       |
| Version ref         | README exec summary      | "3.0.2"                  | "3.0.4"                        |
| MCP tool list       | INSTALL.md               | 5 of 10 listed           | all 10                         |
| Security scope      | SECURITY.md              | v2.0.x, v1.0.x           | + v3.0.x                       |
| What's New          | README                   | v3.0.3 mixed with v3.0.0 | clarify sections               |

### Deliverable

- All files pass `scripts/release-checklist.sh` Section 8 (content accuracy)
- `grep -r` for stale counts returns zero false positives

---

## Phase 2: Professional README Redesign

**Goal**: README transforms from developer documentation to product presentation (70KB → ~25KB).

### New Structure

```
1. Hero Section
   - Product name + 1-line tagline
   - 3 value proposition bullets
   - Badges (version, tests, license, Claude Code Plugin)
   - Quick install command (1 line)

2. Problem → Solution
   - Pain: fragmented tools, manual triage, no Thai compliance
   - Solution: 18 AI agents orchestrate 11 tools automatically

3. Quick Start (30 seconds)
   - Install → first scan → read results
   - Link to QUICK-START.md for full walkthrough

4. Features Overview
   - 8 output formats
   - 11 security tools (table)
   - 6 compliance frameworks

5. Architecture (simplified)
   - 1 visual flow diagram
   - Link to detailed docs

6. Service Offerings (NEW)
   - Starter / Pro / Enterprise tiers (brief)
   - Contact/inquiry link

7. Comparison Table (existing — polish)

8. Documentation Links (curated)

9. Community & Support
```

### Content Migration

Move the following to `docs/`:

- Detailed agent catalog → already in `docs/AGENT-CATALOG.md`
- Full project structure → `docs/PROJECT-STRUCTURE.md` (new)
- Detailed architecture → `docs/ARCHITECTURE.md` (new)
- Changelog/release notes → already in `CHANGELOG.md`

### Tone

From "here's everything about this project" → "here's why you need this, and here's how to start"

---

## Phase 3: Onboarding Experience

**Goal**: New user → first successful scan in 5 minutes.

### Deliverables

1. **`docs/QUICK-START.md`**
   - Prerequisites checklist (Docker, Claude Code)
   - Install plugin (1 command)
   - First SAST scan on demo project
   - Read results — explain each field
   - Next steps (DAST, SCA, full pipeline)

2. **`docs/FIRST-SCAN-WALKTHROUGH.md`**
   - "What happened behind the scenes"
   - Agent orchestration flow
   - Tool selection logic
   - Result normalization
   - How to customize rules

3. **Improved error messages** in runner scripts
   - Docker not running → clear message + fix steps
   - Tool image not pulled → auto-pull suggestion
   - Permission errors → guidance

4. **`tests/fixtures/demo-project/`**
   - Small project with intentional vulnerabilities:
     - SQL injection (Python/Node)
     - Hardcoded secrets (API keys)
     - Outdated dependencies (package.json)
     - Insecure Dockerfile
     - Missing security headers
   - README listing expected findings
   - Used for both onboarding and demo scenarios

---

## Phase 4: Demo Scenarios

**Goal**: Structured demo scripts for sales conversations (15-20 min).

### Deliverables

1. **`demo/README.md`** — Demo guide
   - Pre-demo checklist
   - 3 scenarios (A/B/C)

2. **Demo A: "Quick Win" (5 min)**
   - SAST scan → SQL injection + hardcoded secret found
   - Auto-fix suggestion
   - SARIF output → CI/CD integration

3. **Demo B: "Full Pipeline" (10 min)**
   - Multi-tool pipeline (SAST + SCA + Secrets + Container)
   - Dashboard visualization (Chart.js)
   - Compliance mapping (NCSA + PDPA)
   - Scan history + trend

4. **Demo C: "Enterprise Story" (15 min)**
   - Demo B + custom Semgrep rules
   - CI/CD integration (GitHub Actions template)
   - Team workflow: scan → triage → fix → verify
   - SLSA assessment + SBOM generation

5. **`demo/script.md`** — Talk track
   - Bilingual presenter notes (Thai + English terms)
   - Timing cues
   - FAQ / objection handling
   - "ทำไมไม่ใช้ Snyk?" / "security ของ plugin เอง?"

---

## Success Criteria

| Metric          | Target                              |
| --------------- | ----------------------------------- |
| README size     | ≤ 30KB (from 70KB)                  |
| Onboarding time | ≤ 5 min to first scan               |
| Demo scenarios  | 3 complete scripts with talk tracks |
| Data accuracy   | 0 stale references across all docs  |
| Service info    | Tier descriptions visible in README |

## Version Target

Release as **v3.1.0** — "Commercial Ready" milestone.
