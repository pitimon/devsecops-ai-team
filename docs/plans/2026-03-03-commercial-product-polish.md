# Commercial Product Polish — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform devsecops-ai-team from developer documentation into a commercial-ready product presentation — fix stale data, redesign README, create onboarding guides, and build demo scenarios.

**Architecture:** 4-phase surgical approach — data accuracy first (foundation), then README redesign (presentation), onboarding docs (adoption), and demo scenarios (sales). Each phase is independently shippable.

**Tech Stack:** Markdown, shell scripts, JSON. No build system — pure content work.

**Design Doc:** `docs/plans/2026-03-03-commercial-product-polish-design.md`

---

## Phase 1: Data Accuracy Fix

### Task 1: Fix version reference in README.md

**Files:**

- Modify: `README.md:81`

**Step 1: Fix version in executive summary table**

Line 81 currently shows `3.0.3` — change to `3.0.4`:

```
Old: | **Version**               | 3.0.3 (2026-03-03)
New: | **Version**               | 3.0.4 (2026-03-03)
```

**Step 2: Verify no other stale version references**

Run:

```bash
grep -n "3\.0\.3" README.md
```

Expected: Only CHANGELOG-style historical references, no active claims.

**Step 3: Commit**

```bash
git add README.md
git commit -m "fix: update version reference 3.0.3 → 3.0.4 in README executive summary"
```

---

### Task 2: Fix formatters row in CLAUDE.md

**Files:**

- Modify: `CLAUDE.md:44`

**Step 1: Add Dashboard to formatters list**

Line 44 currently lists 7 formatters — add Dashboard as 8th:

```
Old: | `formatters/`                       | Output formatters (SARIF, JSON, MD, HTML, PDF, CSV, VEX)            |
New: | `formatters/`                       | Output formatters (SARIF, JSON, MD, HTML, PDF, CSV, VEX, Dashboard) |
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "fix: add Dashboard to formatters list in CLAUDE.md (7 → 8 formats)"
```

---

### Task 3: Fix MCP tools list in INSTALL.md

**Files:**

- Modify: `docs/INSTALL.md:163` (approximate — find the MCP tools section)

**Step 1: Read the current MCP section**

Run:

```bash
grep -n -A 5 "MCP tools" docs/INSTALL.md
```

**Step 2: Update MCP tools list from 5 to all 10**

Replace the current 5-tool list with the full 10 MCP tools:

```
devsecops_scan          — Run security scans
devsecops_normalize     — Normalize scan results
devsecops_results       — Query scan results
devsecops_triage        — Prioritize findings
devsecops_enrich        — Add context to findings (OWASP, CWE mappings)
devsecops_compare       — Compare scan results between runs
devsecops_compliance_status — Check compliance framework coverage
devsecops_suggest_fix   — AI-powered fix suggestions
devsecops_history       — Query scan history from SQLite DB
devsecops_pipeline      — Run DAG pipeline with multiple tools
```

**Step 3: Commit**

```bash
git add docs/INSTALL.md
git commit -m "fix: list all 10 MCP tools in INSTALL.md (was showing 5 of 10)"
```

---

### Task 4: Fix SECURITY.md supported versions

**Files:**

- Modify: `SECURITY.md:5-8`

**Step 1: Add v3.0.x to supported versions table**

Current table only shows v2.0.x and v1.0.x. Add v3.0.x:

```markdown
| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |
```

Note: v1.0.x should be marked unsupported since v3.0.x is current.

**Step 2: Commit**

```bash
git add SECURITY.md
git commit -m "fix: update SECURITY.md supported versions — add v3.0.x, deprecate v1.0.x"
```

---

### Task 5: Verify Phase 1 completeness

**Step 1: Run release checklist**

```bash
bash scripts/release-checklist.sh 3.0.4 2>&1 | head -100
```

**Step 2: Grep for remaining stale patterns**

```bash
echo "=== Checking for stale version refs ==="
grep -rn "3\.0\.2\|3\.0\.3" README.md CLAUDE.md docs/INSTALL.md docs/PRD.md SECURITY.md | grep -v CHANGELOG | grep -v "plans/"

echo "=== Checking for stale test counts ==="
grep -rn "1,284\|1284" README.md docs/PRD.md docs/INSTALL.md | grep -v "plans/"

echo "=== Checking for stale format counts ==="
grep -rn "7 [Oo]utput" README.md CLAUDE.md docs/ | grep -v "plans/"
```

Expected: Zero matches for stale patterns.

---

## Phase 2: README Redesign

### Task 6: Create docs/ARCHITECTURE.md (content migration target)

**Files:**

- Create: `docs/ARCHITECTURE.md`

**Step 1: Extract architecture content from README**

Read README.md lines 322-418 (Architecture Overview section). Create `docs/ARCHITECTURE.md` with the full architecture content including:

- System flow / pipeline diagram
- How It Works explanation
- Full Pipeline Delegation Chain
- Decision Loop Model

**Step 2: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs: extract architecture details to docs/ARCHITECTURE.md"
```

---

### Task 7: Create docs/PROJECT-STRUCTURE.md (content migration target)

**Files:**

- Create: `docs/PROJECT-STRUCTURE.md`

**Step 1: Extract project structure from README**

Read README.md lines 925-976 (Project Structure section). Create `docs/PROJECT-STRUCTURE.md` with the full directory tree.

**Step 2: Commit**

```bash
git add docs/PROJECT-STRUCTURE.md
git commit -m "docs: extract project structure to docs/PROJECT-STRUCTURE.md"
```

---

### Task 8: Create docs/FEATURES.md (consolidated feature reference)

**Files:**

- Create: `docs/FEATURES.md`

**Step 1: Consolidate technical feature details from README**

Combine these README sections into one reference doc:

- Skills reference (lines 419-455)
- Vulnerability Prioritization (lines 497-521)
- Role-Based Security Policy (lines 522-536)
- MCP Server Integration (lines 537-578)
- Compliance Mapping (lines 579-619)
- Output Formats (lines 620-671)
- Autonomous Security Controls (lines 672-710)
- Sidecar Runner Architecture (lines 711-747)

**Step 2: Commit**

```bash
git add docs/FEATURES.md
git commit -m "docs: consolidate feature reference details into docs/FEATURES.md"
```

---

### Task 9: Redesign README.md

**Files:**

- Modify: `README.md` (rewrite — from ~1071 lines to ~350 lines)

**Step 1: Read the full current README**

Read `README.md` completely to understand all content.

**Step 2: Rewrite README with new structure**

New structure (target ~300-400 lines):

```
1. [Keep] Hero badge section (lines 1-34)
2. [Condensed] Table of Contents — matching new sections
3. [Keep] Executive Summary — metrics table (fix stale refs)
4. [Keep] Key Highlights — bullet points
5. [Keep] OWASP Top 10 Coverage — matrix
6. [Condensed] What's New — v3.0.4 only (10-15 lines) + link to CHANGELOG
7. [Keep] Use Cases — all 5 (essential for commercial)
8. [Keep] Why DevSecOps AI Team? — value proposition
9. [Condensed] Quick Start — more concise + link to QUICK-START.md
10. [Condensed] Architecture — 1 diagram + summary + link to ARCHITECTURE.md
11. [NEW] Features at a Glance — 1-line per category + links
12. [Keep] Security & Privacy
13. [Condensed] Testing & Quality — badge + summary table only
14. [Keep] ROI & Business Value
15. [Keep] Comparison with Alternatives
16. [NEW] Services — Starter/Pro/Enterprise tiers + contact
17. [Keep] Requirements
18. [Updated] Documentation — links to all docs/
19. [Keep] Contributing, Roadmap, License
```

**Step 3: Verify README renders correctly**

```bash
wc -l README.md  # Target: 300-400 lines
wc -c README.md  # Target: ≤ 30KB
```

**Step 4: Commit**

```bash
git add README.md
git commit -m "docs: redesign README for commercial readability (1071 → ~350 lines)"
```

---

### Task 10: Verify Phase 2 — all links work

**Step 1: Check all internal doc links**

```bash
grep -oP '\(docs/[^)]+\)' README.md | tr -d '()' | while read f; do
  if [ ! -f "$f" ]; then echo "BROKEN: $f"; fi
done
```

Expected: Zero broken links.

**Step 2: Commit any fixes**

---

## Phase 3: Onboarding Experience

### Task 11: Create demo project with intentional vulnerabilities

**Files:**

- Create: `tests/fixtures/demo-project/README.md`
- Create: `tests/fixtures/demo-project/app.py`
- Create: `tests/fixtures/demo-project/package.json`
- Create: `tests/fixtures/demo-project/Dockerfile`
- Create: `tests/fixtures/demo-project/.env.example`

**Step 1: Create demo project directory**

```bash
mkdir -p tests/fixtures/demo-project
```

**Step 2: Create vulnerable source files**

Create files with SAST/SCA/Container-detectable vulnerabilities. **IMPORTANT:** Use clearly-marked demo patterns (e.g., `DEMO_SECRET_DO_NOT_USE`) that pass the project's secret-scanner hook but are still detectable by Semgrep/GitLeaks. Reference `tests/fixtures/` existing patterns for format guidance.

Key vulnerabilities to include:

- SQL Injection via string formatting (Python)
- Weak cryptography (MD5)
- Command injection via os.system
- Sensitive data in logs
- Outdated dependencies in package.json
- Root user in Dockerfile / no USER directive
- Placeholder secrets in .env.example

**Step 3: Create demo project README listing expected findings**

Table mapping: Tool → Finding → Severity → File:Line

**Step 4: Commit**

```bash
git add tests/fixtures/demo-project/
git commit -m "feat: add demo vulnerable project for onboarding and demos"
```

---

### Task 12: Create docs/QUICK-START.md

**Files:**

- Create: `docs/QUICK-START.md`

**Step 1: Write quick-start guide**

Structure:

1. Prerequisites checklist (Docker, Claude Code)
2. Install plugin (1 command)
3. Verify installation
4. First SAST scan on demo project
5. Expected output — explain what you'll see
6. Try more scans (secrets, SCA, pipeline)
7. View dashboard
8. Next steps with links to other docs

Bilingual: Thai prose + English technical terms.

**Step 2: Commit**

```bash
git add docs/QUICK-START.md
git commit -m "docs: add QUICK-START.md — install to first scan in 5 minutes"
```

---

### Task 13: Create docs/FIRST-SCAN-WALKTHROUGH.md

**Files:**

- Create: `docs/FIRST-SCAN-WALKTHROUGH.md`

**Step 1: Write walkthrough**

Structure:

1. Skill matching — how keyword triggers SKILL.md
2. Agent orchestration — DevSecOps Lead assigns to specialist
3. Docker container execution — job-dispatcher.sh launches container
4. Result normalization — raw JSON → unified finding schema
5. Triage & prioritization — severity scoring
6. Output — format options
7. Customizing scans — custom rules, multi-tool pipeline

**Step 2: Commit**

```bash
git add docs/FIRST-SCAN-WALKTHROUGH.md
git commit -m "docs: add FIRST-SCAN-WALKTHROUGH.md — explains what happens behind the scenes"
```

---

## Phase 4: Demo Scenarios

### Task 14: Create demo directory and guide

**Files:**

- Create: `demo/README.md`

**Step 1: Create demo directory**

```bash
mkdir -p demo
```

**Step 2: Write demo guide with 3 scenarios**

Structure:

- Pre-demo checklist (Docker, images, plugin, font size)
- **Scenario A: Quick Win (5 min)** — SAST scan → auto-fix → SARIF output
- **Scenario B: Full Pipeline (10 min)** — Multi-tool → dashboard → compliance (NCSA + PDPA)
- **Scenario C: Enterprise Story (15 min)** — Custom rules → CI/CD → SLSA → SBOM → history
- Common Questions & Answers table

Each scenario includes: commands, talking points, expected output.

**Step 3: Commit**

```bash
git add demo/
git commit -m "docs: add demo guide with 3 scenarios (5/10/15 min) and FAQ"
```

---

### Task 15: Create demo talk track

**Files:**

- Create: `demo/script.md`

**Step 1: Write presenter script**

Structure:

- Opening (1 min) — elevator pitch in Thai
- Scenario A script — timing cues per segment [0:00-0:30], [0:30-1:30], etc.
- Scenario B script — extends A with pipeline + compliance
- Scenario C script — extends B with enterprise features
- Objection handling — "ของฟรีจะดีจริงหรือ?", "ทำไมไม่ใช้ GitHub AS?", "มี support ไหม?"
- Closing — service tiers pitch

Bilingual: Thai presenter notes with English technical terms.

**Step 2: Commit**

```bash
git add demo/script.md
git commit -m "docs: add demo talk track with bilingual presenter notes"
```

---

## Phase 5: Final Polish & Release

### Task 16: Update PRD.md version references

**Files:**

- Modify: `docs/PRD.md`

**Step 1: Find and fix stale version references**

```bash
grep -n "3\.0\.2\|v3\.0\.2" docs/PRD.md
```

Update all "current state" references from "3.0.2" / "v3.0.2" to "3.0.4" / "v3.0.4". Keep historical references intact.

**Step 2: Commit**

```bash
git add docs/PRD.md
git commit -m "fix: update PRD.md stale version references to v3.0.4"
```

---

### Task 17: Version bump to v3.1.0

**Step 1: Run version bump script**

```bash
bash scripts/version-bump.sh 3.1.0
```

**Step 2: Rebuild MCP bundle**

```bash
cd mcp && bash build.sh && cd ..
```

**Step 3: Update CHANGELOG.md**

Add v3.1.0 entry with all changes from this plan:

```markdown
## [3.1.0] - 2026-03-XX

### Added

- Professional README redesign — commercial-grade product presentation
- Quick Start guide (`docs/QUICK-START.md`) — install to first scan in 5 minutes
- First Scan Walkthrough (`docs/FIRST-SCAN-WALKTHROUGH.md`)
- Demo scenarios with talk tracks (`demo/`)
- Demo vulnerable project (`tests/fixtures/demo-project/`)
- Architecture reference (`docs/ARCHITECTURE.md`)
- Features reference (`docs/FEATURES.md`)
- Project structure reference (`docs/PROJECT-STRUCTURE.md`)
- Service tiers section in README

### Fixed

- README version reference 3.0.3 → 3.0.4
- CLAUDE.md formatters list missing Dashboard (7 → 8)
- INSTALL.md MCP tools incomplete (5 → 10)
- SECURITY.md missing v3.0.x support
- PRD.md stale version references
```

**Step 4: Run validation**

```bash
bash tests/validate-plugin.sh
bash scripts/release-checklist.sh 3.1.0
```

**Step 5: Commit**

```bash
git add -A
git commit -m "chore: bump version to v3.1.0 — Commercial Ready release"
```

---

### Task 18: Final review and tag

**Step 1: Review all changes**

```bash
git log --oneline main..HEAD
git diff --stat main
```

**Step 2: Create release**

```bash
git tag v3.1.0
git push origin main --tags
gh release create v3.1.0 --title "v3.1.0 — Commercial Ready" --notes "..."
```

---

## Summary

| Phase              | Tasks | Key Deliverables                         |
| ------------------ | ----- | ---------------------------------------- |
| 1: Data Accuracy   | 1-5   | 4 stale fixes verified                   |
| 2: README Redesign | 6-10  | README 1071→~350 lines + 3 new docs      |
| 3: Onboarding      | 11-13 | Demo project + Quick Start + Walkthrough |
| 4: Demo Scenarios  | 14-15 | 3 demo scripts + talk track              |
| 5: Release         | 16-18 | v3.1.0 tagged and released               |
