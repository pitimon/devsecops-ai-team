# v2.8.0 Supply Chain Compliance + Rules Expansion — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete OWASP 10/10 custom rules, add SOC 2/ISO 27001 compliance mappings, integrate SLSA assessment skill, VEX output format, TruffleHog secret scanning, and secret validity checking — driven by EU CRA Sep 2026 deadline.

**Architecture:** 7-phase implementation following proven v2.7.0 patterns: Phase A (OWASP rules), Phase B (compliance mappings), Phase C (SLSA skill), Phase D (VEX formatter), Phase E (TruffleHog integration), Phase F (secret verification), Phase G (release). Each phase creates files, tests, and commits independently.

**Tech Stack:** Bash, Python3, YAML (Semgrep rules), JSON (mappings/findings), Docker (TruffleHog), esbuild (MCP bundle)

**Design Doc:** `docs/plans/2026-03-03-v280-supply-chain-rules-design.md`

---

## Phase A: OWASP 10/10 Custom Rules (#47)

### Task A1: Create A06 Vulnerable Components rules

**Files:**

- Create: `rules/a06-component-rules.yml`
- Create: `tests/fixtures/sample-a06-findings.json`

**Step 1: Create rule file**

Create `rules/a06-component-rules.yml` with 5 rules. Follow exact header from `rules/a04-insecure-design-rules.yml`:

Header:

```yaml
rules:
  # ==========================================================================
  # A06:2025 Vulnerable and Outdated Components — Custom Semgrep Rules
  # DevSecOps AI Team v2.8.0
  #
  # 5 rules targeting A06 anti-patterns
  # Languages: Python (1 rule), Generic/regex (4 rules)
  # Reference: skills/references/sast-patterns.md
  # ==========================================================================
```

Rules to implement:

1. **a06-unpinned-pip** (CWE-1104, generic) — `pattern-regex` matching unpinned deps in requirements.txt (lines without `==`)
2. **a06-unpinned-npm** (CWE-1104, generic) — `pattern-regex` matching `"*"` or `"latest"` in package.json deps
3. **a06-known-vulnerable-pyyaml** (CWE-829, python) — `yaml.load($DATA)` without SafeLoader/FullLoader
4. **a06-no-lockfile-check** (CWE-829, generic) — `pip install` without `--require-hashes`
5. **a06-untrusted-source** (CWE-829, generic) — `pip install --index-url` pointing to non-PyPI source

All rules: `owasp: ["A06:2021", "A06:2025"]`

Each rule needs full metadata: cwe, owasp, nist, confidence, impact, likelihood, category, technology, references, fix. See `rules/a02-crypto-rules.yml` for exact format.

**Step 2: Create fixture** — `tests/fixtures/sample-a06-findings.json` with 3 sample findings matching a06- rules. Follow format from `tests/fixtures/sample-a04-findings.json`.

**Step 3: Validate**

```bash
python3 -c "import yaml; data=yaml.safe_load(open('rules/a06-component-rules.yml')); assert len(data['rules'])==5; print('5 rules OK')"
python3 -c "import json; json.load(open('tests/fixtures/sample-a06-findings.json')); print('JSON OK')"
```

**Step 4: Commit**

```bash
git add rules/a06-component-rules.yml tests/fixtures/sample-a06-findings.json
git commit -m "feat: add A06 Vulnerable Components custom Semgrep rules (5 rules)"
```

---

### Task A2: Create A07 Authentication Failures rules

**Files:**

- Create: `rules/a07-auth-rules.yml`
- Create: `tests/fixtures/sample-a07-findings.json`

**Step 1: Create rule file**

Create `rules/a07-auth-rules.yml` with 5 rules following the same header pattern:

1. **a07-weak-password-python** (CWE-521, python) — Password validation with `len(password) < 8` or similar weak checks
2. **a07-hardcoded-jwt-secret** (CWE-798, generic) — JWT encode/decode with string literal secret (e.g., `jwt.encode(..., "secret"...)`)
3. **a07-session-no-expire** (CWE-613, python) — Session config without `PERMANENT_SESSION_LIFETIME` or `SESSION_COOKIE_AGE`
4. **a07-missing-mfa-check** (CWE-308, generic) — Auth flow patterns without MFA verification step
5. **a07-permissive-password-reset** (CWE-640, python) — Password reset handler without token verification

All rules: `owasp: ["A07:2021", "A07:2025"]`

**Step 2: Create fixture** — 3 sample findings

**Step 3: Validate YAML + JSON**

**Step 4: Commit**

```bash
git add rules/a07-auth-rules.yml tests/fixtures/sample-a07-findings.json
git commit -m "feat: add A07 Authentication Failures custom Semgrep rules (5 rules)"
```

---

### Task A3: Create A08 Integrity Failures rules

**Files:**

- Create: `rules/a08-integrity-rules.yml`
- Create: `tests/fixtures/sample-a08-findings.json`

**Step 1: Create rule file**

Create `rules/a08-integrity-rules.yml` with 5 rules:

1. **a08-unsafe-pickle** (CWE-502, python) — `pickle.loads(...)`, `pickle.load(...)` on external data
2. **a08-yaml-unsafe-load** (CWE-502, python) — `yaml.load(...)` without SafeLoader
3. **a08-cdn-no-integrity** (CWE-829, generic) — `<script src="http` without `integrity=` SRI attribute
4. **a08-unpinned-action** (CWE-829, generic) — GitHub Actions `uses: owner/action@v` without SHA pin
5. **a08-unsigned-install** (CWE-494, generic) — Piped execution like `curl ... | bash` or `wget ... | sh`

All rules: `owasp: ["A08:2021", "A08:2025"]`

**Step 2: Create fixture** — 3 sample findings

**Step 3: Validate YAML + JSON**

**Step 4: Commit**

```bash
git add rules/a08-integrity-rules.yml tests/fixtures/sample-a08-findings.json
git commit -m "feat: add A08 Integrity Failures custom Semgrep rules (5 rules)"
```

---

### Task A4: Create test suites for A06, A07, A08

**Files:**

- Create: `tests/test-a06-rules.sh`
- Create: `tests/test-a07-rules.sh`
- Create: `tests/test-a08-rules.sh`
- Modify: `mappings/cwe-to-owasp.json` (add missing CWEs)

**Step 1: Create test files**

Follow exact pattern from `tests/test-a04-rules.sh`. Each test file has ~15 tests across 6 sections:

1. **Rules File Structure** (3) — exists, valid YAML, correct rule count
2. **Rule Metadata** (2) — required Semgrep fields present
3. **OWASP Tags** (3) — dual-tagged with 2021+2025
4. **CWE Cross-Reference** (4) — CWEs exist in cwe-to-owasp.json
5. **Language Coverage** (2) — covers expected languages
6. **Fixture Validation** (3) — fixture exists, valid JSON, correct findings count

Key variables per file:

- A06: `RULES_FILE=a06-component-rules.yml`, `EXPECTED_RULES=5`
- A07: `RULES_FILE=a07-auth-rules.yml`, `EXPECTED_RULES=5`
- A08: `RULES_FILE=a08-integrity-rules.yml`, `EXPECTED_RULES=5`

**Step 2: Add missing CWEs to cwe-to-owasp.json**

Check if CWE-1104, CWE-494, CWE-521, CWE-613, CWE-640, CWE-798, CWE-308 exist. Add any missing ones with dual 2021+2025 tags.

**Step 3: Run tests**

```bash
bash tests/test-a06-rules.sh && bash tests/test-a07-rules.sh && bash tests/test-a08-rules.sh
```

Expected: All PASS

**Step 4: Commit**

```bash
git add tests/test-a06-rules.sh tests/test-a07-rules.sh tests/test-a08-rules.sh mappings/cwe-to-owasp.json
git commit -m "test: add A06, A07, A08 rule test suites"
```

---

## Phase B: SOC 2 + ISO 27001 Compliance Mapping (#48)

### Task B1: Create SOC 2 compliance mapping

**Files:**

- Create: `mappings/cwe-to-soc2.json`

**Step 1: Create mapping file**

Follow exact structure from `mappings/cwe-to-pdpa.json`:

```json
{
  "_meta": {
    "description": "CWE to SOC 2 Trust Service Criteria mapping",
    "source": "https://www.aicpa.org/soc2",
    "soc2_version": "2017 (with 2022 updates)",
    "last_updated": "2026-03-03"
  },
  "mappings": {
    "CWE-89": {
      "soc2": ["CC6.1"],
      "category": "Logical Access",
      "name": "SQL Injection",
      "requirement": "Logical access security over information assets"
    }
  }
}
```

Target: ~40 CWE entries covering CC6.x (access), CC7.x (operations), CC8.x (change), CC9.x (risk), C1.x (confidentiality), A1.x (availability), PI1.x (processing integrity).

**Step 2: Validate**

```bash
python3 -c "import json; d=json.load(open('mappings/cwe-to-soc2.json')); print(f\"{len(d['mappings'])} mappings\"); assert len(d['mappings'])>=35"
```

**Step 3: Commit**

```bash
git add mappings/cwe-to-soc2.json
git commit -m "feat: add CWE-to-SOC2 compliance mapping (~40 CWEs)"
```

---

### Task B2: Create ISO 27001 compliance mapping

**Files:**

- Create: `mappings/cwe-to-iso27001.json`

**Step 1: Create mapping file**

```json
{
  "_meta": {
    "description": "CWE to ISO 27001:2022 Annex A controls mapping",
    "source": "https://www.iso.org/standard/27001",
    "iso27001_version": "2022",
    "last_updated": "2026-03-03"
  },
  "mappings": {
    "CWE-89": {
      "iso27001": ["A.8.28"],
      "category": "Technological Controls",
      "name": "SQL Injection",
      "requirement": "Secure coding practices"
    }
  }
}
```

Target: ~40 CWE entries covering A.5 (organizational), A.6 (people), A.7 (physical), A.8 (technological) controls.

**Step 2: Validate and commit**

```bash
python3 -c "import json; d=json.load(open('mappings/cwe-to-iso27001.json')); print(f\"{len(d['mappings'])} mappings\"); assert len(d['mappings'])>=35"
git add mappings/cwe-to-iso27001.json
git commit -m "feat: add CWE-to-ISO27001 compliance mapping (~40 CWEs)"
```

---

### Task B3: Update MCP compliance_status + frameworks.json

**Files:**

- Modify: `mcp/server.mjs` (line 226 description, line 542 frameworks array)
- Modify: `frameworks.json`

**Step 1: Update MCP server**

- Line 226: `"5 frameworks"` → `"7 frameworks"`, add `SOC2, ISO27001` to list
- Line 542: Add `"soc2", "iso27001"` to frameworks array

**Step 2: Add frameworks.json entries** for SOC 2 and ISO 27001

**Step 3: Rebuild MCP bundle**

```bash
cd mcp && bash build.sh && cd ..
grep -c "soc2" mcp/dist/server.js  # Expect >= 2
```

**Step 4: Commit**

```bash
git add mcp/server.mjs mcp/dist/server.js frameworks.json
git commit -m "feat: add SOC2 and ISO27001 to MCP compliance_status (7 frameworks)"
```

---

### Task B4: Create SOC 2 / ISO 27001 mapping tests

**Files:**

- Create: `tests/test-soc2-mapping.sh`
- Create: `tests/test-iso27001-mapping.sh`

**Step 1: Create test files**

Follow exact pattern from `tests/test-pdpa-mapping.sh`. Each ~15 tests across 6 sections: File Structure (4), Meta Section (3), Required Fields (4), CWE Format (2), Cross-Reference (3), MCP Integration (1).

**Step 2: Run and commit**

```bash
bash tests/test-soc2-mapping.sh && bash tests/test-iso27001-mapping.sh
git add tests/test-soc2-mapping.sh tests/test-iso27001-mapping.sh
git commit -m "test: add SOC2 and ISO27001 mapping validation test suites"
```

---

## Phase C: SLSA Provenance Assessment Skill (#45)

### Task C1: Create SLSA reference file

**Files:**

- Create: `skills/references/slsa-reference.md`

**Step 1: Create reference file**

Follow pattern from existing `skills/references/` files. Content covers:

- SLSA v1.1 framework overview
- Level 0-3 requirements table
- Build provenance specification
- Source integrity checks
- Dependency completeness via Syft SBOM
- Assessment methodology (what to look for in a project)
- EU CRA alignment section
- GitHub Artifact Attestations for Level 3

**Step 2: Commit**

```bash
git add skills/references/slsa-reference.md
git commit -m "docs: add SLSA v1.1 reference for provenance assessment"
```

---

### Task C2: Create SLSA assessment skill

**Files:**

- Create: `skills/slsa-assess/SKILL.md`

**Step 1: Create skill definition**

Frontmatter (follow `skills/auto-fix/SKILL.md` pattern):

```yaml
---
name: slsa-assess
description: Assess SLSA (Supply-chain Levels for Software Artifacts) compliance level for a project. Checks build provenance, source integrity, and dependency completeness against SLSA v1.1 framework.
argument-hint: "[--target <path>] [--level 1|2|3]"
user-invocable: true
allowed-tools: ["Read", "Bash", "Glob", "Grep"]
---
```

Body includes:

- Decision Loop: On-the-Loop
- Assessment workflow steps
- What to check per level
- Output template (current level + gap analysis in markdown)
- Reference: `skills/references/slsa-reference.md`

**Step 2: Commit**

```bash
git add skills/slsa-assess/SKILL.md
git commit -m "feat: add /slsa-assess skill for SLSA provenance assessment"
```

---

### Task C3: Update validate-plugin.sh and create SLSA test suite

**Files:**

- Modify: `tests/validate-plugin.sh` (line 53 — add `slsa-assess`)
- Create: `tests/test-slsa-skill.sh`

**Step 1: Update validate-plugin.sh line 53**

Add `slsa-assess` to EXPECTED_SKILLS string (14 skills total).

**Step 2: Create test file**

`tests/test-slsa-skill.sh` with ~12 tests:

1. **Skill File** (4) — exists, frontmatter valid, name=slsa-assess, user-invocable=true
2. **Reference File** (3) — slsa-reference.md exists, covers SLSA levels, mentions EU CRA
3. **Content** (3) — mentions levels 0-3, references Syft, has output template
4. **Integration** (2) — listed in validate-plugin.sh, references slsa-reference.md

**Step 3: Run and commit**

```bash
bash tests/test-slsa-skill.sh && bash tests/validate-plugin.sh
git add tests/validate-plugin.sh tests/test-slsa-skill.sh
git commit -m "test: add SLSA skill test suite and update validate-plugin.sh"
```

---

## Phase D: VEX Output Format (#46)

### Task D1: Create VEX formatter

**Files:**

- Create: `formatters/vex-formatter.sh`

**Step 1: Create formatter script**

Follow pattern from `formatters/sarif-formatter.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — VEX (Vulnerability Exploitability eXchange) Formatter
# Generates CycloneDX VEX or OpenVEX format from normalized findings.
# Usage: vex-formatter.sh --input <findings.json> --output <output.json> [--format cdx|openvex]
```

Args: `--input`, `--output`, `--format cdx|openvex` (default: cdx)

Python3 implementation that:

- Reads normalized findings JSON
- For `cdx`: outputs CycloneDX VEX (bomFormat, specVersion 1.6, vulnerabilities array with analysis.state)
- For `openvex`: outputs OpenVEX (@context, author, timestamp, statements with status)
- Maps severity→VEX status: critical/high→`exploitable`, medium→`under_investigation`, low/info→`not_affected`

**Step 2: Make executable and validate**

```bash
chmod +x formatters/vex-formatter.sh
bash -n formatters/vex-formatter.sh && echo "OK"
```

**Step 3: Commit**

```bash
git add formatters/vex-formatter.sh
git commit -m "feat: add VEX formatter (CycloneDX VEX + OpenVEX)"
```

---

### Task D2: Create VEX formatter tests

**Files:**

- Create: `tests/test-vex-formatter.sh`

**Step 1: Create test file**

~18 tests:

1. **Script Structure** (3) — exists, executable, accepts --input/--output/--format
2. **CycloneDX VEX Output** (5) — valid JSON, bomFormat=CycloneDX, specVersion, vulnerabilities array, finding count matches
3. **OpenVEX Output** (5) — valid JSON, has @context, author, statements array, statement count matches
4. **Status Mapping** (3) — severity-to-status mapping works correctly
5. **Error Handling** (2) — exits 1 on missing args, handles empty findings

Uses temp files with existing fixture as input.

**Step 2: Run and commit**

```bash
bash tests/test-vex-formatter.sh
git add tests/test-vex-formatter.sh
git commit -m "test: add VEX formatter test suite"
```

---

## Phase E: TruffleHog Secret Scanning (#49)

### Task E1: Add TruffleHog to Docker Compose

**Files:**

- Modify: `runner/docker-compose.yml`

**Step 1: Add service after gitleaks (around line 121)**

```yaml
# ─── Secret Scanning: TruffleHog ───
trufflehog:
  image: trufflesecurity/trufflehog:latest
  container_name: devsecops-trufflehog
  entrypoint: ["sleep", "infinity"]
  profiles: ["trufflehog", "secret", "all"]
  volumes:
    - workspace:/workspace:ro
    - results:/results
  mem_limit: 1g
```

Update header comment to list trufflehog profile.

**Step 2: Commit**

```bash
git add runner/docker-compose.yml
git commit -m "feat: add TruffleHog secret scanning to docker-compose"
```

---

### Task E2: Add run_trufflehog() to job-dispatcher

**Files:**

- Modify: `runner/job-dispatcher.sh`

**Step 1: Add function** (before `run_tool()`)

`run_trufflehog()` with 3 modes via `TRUFFLEHOG_MODE` env var:

- `git` (default) — scan git history
- `filesystem` — scan files without git
- `s3` — scan S3 bucket (needs `S3_BUCKET` env var)

Follow `run_nuclei()` pattern with docker exec/run dual path.

**Step 2: Add to run_tool() case** after `nuclei) run_nuclei ;;`:

```bash
    trufflehog) run_trufflehog ;;
```

**Step 3: Update usage comment** (line 11) — add trufflehog to tools list

**Step 4: Commit**

```bash
git add runner/job-dispatcher.sh
git commit -m "feat: add TruffleHog routing to job-dispatcher"
```

---

### Task E3: Add TruffleHog normalizer

**Files:**

- Modify: `formatters/json-normalizer.sh`

**Step 1: Add trufflehog case** before `*)` wildcard

TruffleHog outputs one JSON object per line (JSONL). The normalizer parses:

- `DetectorName` → `rule_id` (prefixed with `trufflehog-`)
- `Raw` → redacted (first 4 chars + `***`)
- `Verified` → `confidence` (true=HIGH, false=MEDIUM) and `severity` (true=CRITICAL, false=HIGH)
- `SourceMetadata.Data` → `location` (file, line)
- Add `verified` boolean field to output

**Step 2: Validate and commit**

```bash
bash -n formatters/json-normalizer.sh && echo "OK"
git add formatters/json-normalizer.sh
git commit -m "feat: add TruffleHog JSON parser to normalizer"
```

---

### Task E4: Create TruffleHog fixtures and tests

**Files:**

- Create: `tests/fixtures/sample-trufflehog.json`
- Create: `tests/test-trufflehog-integration.sh`

**Step 1: Create JSONL fixture**

3 lines, one JSON object per line. Each with DetectorName, Verified, Raw (use obviously fake values like `EXAMPLE_KEY_1234`), SourceMetadata. Do NOT use real secret patterns — use generic placeholder values.

**Step 2: Create test file**

~20 tests:

1. **Docker Compose** (3) — service exists, correct profile, correct image
2. **Job Dispatcher** (4) — run_trufflehog exists, 3 modes, added to run_tool
3. **Normalizer** (5) — trufflehog case exists, parses fixture, verified flag, severity mapping, redaction
4. **Skill Definition** (3) — secret-scan mentions trufflehog
5. **Fixture Validation** (3) — exists, valid JSON lines, has DetectorName
6. **Dedup Compatibility** (2) — output has fields needed by dedup-findings.sh

**Step 3: Run and commit**

```bash
bash tests/test-trufflehog-integration.sh
git add tests/fixtures/sample-trufflehog.json tests/test-trufflehog-integration.sh
git commit -m "test: add TruffleHog integration test suite"
```

---

### Task E5: Extend secret-scan skill for TruffleHog

**Files:**

- Modify: `skills/secret-scan/SKILL.md`

**Step 1: Update skill**

- Update description to mention TruffleHog alongside GitLeaks
- Add `--tool gitleaks|trufflehog|both` to argument-hint
- Add TruffleHog scan modes table (git/filesystem/s3)
- Add deduplication section (when `--tool both`, run dedup-findings.sh)
- Update output template with Source column

**Step 2: Commit**

```bash
git add skills/secret-scan/SKILL.md
git commit -m "feat: extend secret-scan skill to support TruffleHog"
```

---

## Phase F: Secret Validity Checking (#50)

### Task F1: Create secret verifier script

**Files:**

- Create: `scripts/secret-verifier.sh`

**Step 1: Create the script**

```bash
#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Secret Validity Checker
# Verifies if detected secrets are actually active/valid.
# REQUIRES --confirm flag — In-the-Loop (user must approve each verification).
#
# Usage: secret-verifier.sh --input <findings.json> --output <verified.json> --confirm
#        [--audit <audit.json>] [--rate-limit <N>]
```

Implementation:

- Reads normalized findings JSON, filters for secret-type findings
- For each: detects provider by known prefix patterns (AKIA→AWS, xoxb→Slack, etc.)
- If `--confirm`, shows redacted secret (first 4 chars + `***`) and prompts user
- Calls provider-specific curl verification
- Records result in audit trail JSON
- Rate limiting: sleep between verifications (configurable, default 5/min/provider)
- Outputs findings with added `verification_status` field (valid/invalid/expired/unknown/skipped)
- Audit file: timestamp, provider, result, redacted_value (never full secret)

4 providers: AWS (STS GetCallerIdentity), GitHub (GET /user), Slack (auth.test), Generic HTTP (configurable)

**Step 2: Make executable and validate**

```bash
chmod +x scripts/secret-verifier.sh
bash -n scripts/secret-verifier.sh && echo "OK"
```

**Step 3: Commit**

```bash
git add scripts/secret-verifier.sh
git commit -m "feat: add secret validity checker with 4 providers"
```

---

### Task F2: Create secret verifier tests

**Files:**

- Create: `tests/test-secret-verifier.sh`

**Step 1: Create test file**

~18 tests (all mock-based, NO real API calls):

1. **Script Structure** (4) — exists, executable, accepts --input/--output/--confirm, rejects without --confirm
2. **Provider Detection** (4) — script contains patterns for AWS/GitHub/Slack/Generic
3. **Safety Controls** (4) — redaction logic, rate limit default, audit file creation, no full secrets in audit
4. **Output Format** (3) — valid JSON, has verification_status field, statuses in valid set
5. **Audit Trail** (3) — audit format valid, has timestamp/provider/result, redacted values only

**Step 2: Run and commit**

```bash
bash tests/test-secret-verifier.sh
git add tests/test-secret-verifier.sh
git commit -m "test: add secret verifier test suite"
```

---

## Phase G: Release v2.8.0

### Task G1: Run validate-plugin.sh

**Step 1:** `bash tests/validate-plugin.sh` — fix any failures (skill count should be 14)

**Step 2: Commit if changed**

```bash
git add tests/validate-plugin.sh
git commit -m "chore: update validate-plugin.sh for v2.8.0 metrics"
```

---

### Task G2: Version bump and MCP rebuild

**Step 1:** `bash scripts/version-bump.sh 2.8.0`

**Step 2:** `cd mcp && bash build.sh && cd ..`

**Step 3:** `bash scripts/release-checklist.sh 2.8.0`

**Step 4: Commit**

```bash
git add .claude-plugin/plugin.json .claude-plugin/marketplace.json mcp/package.json mcp/server.mjs mcp/dist/server.js README.md docs/INSTALL.md docs/MANDAY-ESTIMATION.md
git commit -m "chore: bump version to 2.8.0"
```

---

### Task G3: Update documentation

**Files:**

- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/PRD.md`
- Modify: `CLAUDE.md`

**Step 1: CHANGELOG entry**

```markdown
## [2.8.0] - 2026-03-XX

### Added

- OWASP 10/10 custom rules: A06 Components (5), A07 Auth (5), A08 Integrity (5) — total 68 rules
- SOC 2 compliance mapping (~40 CWEs, mappings/cwe-to-soc2.json)
- ISO 27001 compliance mapping (~40 CWEs, mappings/cwe-to-iso27001.json)
- SLSA provenance assessment skill (/slsa-assess) with reference file
- VEX output format (CycloneDX VEX + OpenVEX)
- TruffleHog secret scanning (9th security tool)
- Secret validity checking with 4 providers (AWS, GitHub, Slack, Generic)
- 7 new test suites

### Changed

- MCP compliance_status now supports 7 frameworks (+SOC2, +ISO27001)
- Secret-scan skill extended for TruffleHog alongside GitLeaks
- Normalizer supports 9 tools (+TruffleHog)
- frameworks.json updated with SOC2, ISO27001 entries
```

**Step 2: README** — update badges (version, tests, tools=9, OWASP=10/10, frameworks=7, rules=~68, skills=14)

**Step 3: PRD** — update current state to v2.8.0

**Step 4: CLAUDE.md** — update Key Files table if needed

**Step 5: Commit**

```bash
git add CHANGELOG.md README.md docs/PRD.md CLAUDE.md
git commit -m "docs: update documentation for v2.8.0 release"
```

---

### Task G4: QA round and release

**Step 1: Run all tests**

```bash
bash tests/validate-plugin.sh
bash scripts/release-checklist.sh 2.8.0
```

Both must PASS.

**Step 2: Count total tests**

```bash
for f in tests/test-*.sh; do echo "=== $f ==="; bash "$f" 2>&1 | tail -3; done
```

---

## Task Summary

| Phase     | Tasks  | Files Created | Files Modified | Tests Added |
| --------- | ------ | ------------- | -------------- | ----------- |
| A         | 4      | 9             | 1              | ~45         |
| B         | 4      | 4             | 2              | ~30         |
| C         | 3      | 3             | 1              | ~12         |
| D         | 2      | 2             | 0              | ~18         |
| E         | 5      | 3             | 3              | ~20         |
| F         | 2      | 2             | 0              | ~18         |
| G         | 4      | 0             | 6+             | 0           |
| **Total** | **24** | **23**        | **13+**        | **~143**    |

Expected final test count: ~1,120+ (978 existing + ~143 new)
