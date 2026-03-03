# v2.7.0 Design — OWASP 2025 Migration + DAST Expansion + Thai Regulatory

> **Date**: 2026-03-03 | **Status**: Approved
> **Target**: v2.7.0 (Q2 2026) | **Issues**: #39, #40, #41, #42, #43, #44
> **Milestone**: v2.7.0 (#2)

---

## Theme

OWASP 2025 category migration (dual-version), DAST expansion with Nuclei, and Thai regulatory compliance (NCSA 1.0 + PDPA mapping).

## Decisions

| Decision               | Choice                                            | Rationale                                                            |
| ---------------------- | ------------------------------------------------- | -------------------------------------------------------------------- |
| Delivery order         | PRD order + Regulatory-first hybrid               | OWASP mapping is foundation for rules; regulatory has real deadlines |
| OWASP version strategy | Array dual-tag `["A03:2021", "A05:2025"]`         | Backward compatible, no schema break, MCP filters both               |
| Nuclei scope           | Full integration (on par with ZAP)                | Docker + dispatcher + skill + normalizer + tests                     |
| Nuclei skill           | Extend existing `/dast-scan` with `--tool nuclei` | Single DAST entry point, consistent UX                               |

## Delivery Phases

```
Phase A: OWASP 2025 Foundation (#39)        ← mapping + frameworks.json
Phase B: Custom Rules Wave 1 (#40)          ← A02 Crypto + A05 Misconfig (~12 rules)
Phase C: Nuclei DAST Full Integration (#41) ← Docker + dispatcher + skill + normalizer
Phase D: Regulatory (#42 + #44)             ← NCSA 1.0 review + PDPA mapping
Phase E: Custom Rules Wave 2 (#43)          ← A04 Insecure Design + A10 Exception (~8 rules)
Phase F: Release                            ← bump, QA, tag
```

### Dependencies

```
A ──→ B (rules reference 2025 categories)
A ──→ E (rules reference 2025 categories)
C ──→ independent (Nuclei doesn't depend on OWASP mapping)
D ──→ independent (regulatory doesn't depend on rules)
B,C,D,E ──→ F (all must complete before release)
```

---

## Phase A: OWASP 2025 Mapping Foundation (#39)

### OWASP 2025 Category Changes

| 2021 Category                  | 2025 Category                                 | Change                                      |
| ------------------------------ | --------------------------------------------- | ------------------------------------------- |
| A01: Broken Access Control     | A01: Broken Access Control                    | SSRF merged in (from A10:2021)              |
| A02: Cryptographic Failures    | A02: Cryptographic Failures                   | Unchanged                                   |
| A03: Injection                 | A03: **Supply Chain**                         | **NEW** — replaces Injection                |
| A04: Insecure Design           | A04: Insecure Design                          | Unchanged                                   |
| A05: Security Misconfiguration | A05: **Injection**                            | Injection moved here, merged with Misconfig |
| A06: Vulnerable Components     | A06: Vulnerable & Outdated Components         | Unchanged                                   |
| A07: ID & Auth Failures        | A07: Identification & Authentication Failures | Unchanged                                   |
| A08: Data Integrity Failures   | A08: Software & Data Integrity Failures       | Unchanged                                   |
| A09: Security Logging          | A09: Security Logging & Monitoring            | Unchanged                                   |
| A10: SSRF                      | A10: **Exception Handling**                   | **NEW** — replaces SSRF                     |

### Files Changed

**1. `frameworks.json`** — Add entry:

```json
{
  "id": "owasp-top-10-2025",
  "name": "OWASP Top 10 2025",
  "version": "2025",
  "released": "2025-XX-XX",
  "last_checked": "2026-03-03",
  "grep_patterns": ["A0[0-9]:2025", "OWASP.*2025"],
  "used_in": ["mappings/cwe-to-owasp.json", "rules/*.yml"]
}
```

**2. `mappings/cwe-to-owasp.json`** — Dual-tag migration:

Before:

```json
{
  "_meta": { "owasp_version": "2021" },
  "mappings": {
    "CWE-89": {
      "owasp": ["A03:2021"],
      "category": "Injection",
      "name": "SQL Injection"
    }
  }
}
```

After:

```json
{
  "_meta": {
    "owasp_version": ["2021", "2025"],
    "migration_date": "2026-XX-XX"
  },
  "mappings": {
    "CWE-89": {
      "owasp": ["A03:2021", "A05:2025"],
      "category": "Injection",
      "name": "SQL Injection"
    }
  }
}
```

Changes:

- All 105 existing CWEs: add corresponding `A0X:2025` tag
- ~15 new CWE entries for A03:2025 (Supply Chain) and A10:2025 (Exception Handling)
- `_meta.owasp_version` becomes array `["2021", "2025"]`

**3. Normalizer** — `formatters/normalizer.sh` already reads `owasp` as array. Verify no string assumption.

**4. Tests** — Add OWASP 2025 dual-tag validation to existing test suites.

---

## Phase B: Custom Rules Wave 1 — A02/A05:2025 (#40)

### `rules/a02-crypto-rules.yml` (~6 rules)

| Rule ID                    | Pattern                                         | CWE     | Languages                           |
| -------------------------- | ----------------------------------------------- | ------- | ----------------------------------- |
| crypto-weak-hash           | MD5/SHA1 usage                                  | CWE-328 | Python, JS/TS                       |
| crypto-hardcoded-key       | Hardcoded encryption keys                       | CWE-321 | Python, JS/TS, Java                 |
| crypto-insufficient-keylen | Key < 2048 bits (RSA), < 256 bits (AES)         | CWE-326 | Python, JS/TS                       |
| crypto-insecure-random     | `Math.random()`, `random.random()` for security | CWE-338 | Python, JS/TS                       |
| crypto-weak-tls            | TLS < 1.2 configuration                         | CWE-327 | Python, JS/TS                       |
| crypto-missing-hsts        | Missing HSTS header                             | CWE-523 | Python (Django/Flask), JS (Express) |

### `rules/a05-misconfig-rules.yml` (~6 rules)

| Rule ID                     | Pattern                                            | CWE      | Languages                     |
| --------------------------- | -------------------------------------------------- | -------- | ----------------------------- |
| misconfig-debug-mode        | `DEBUG=True`, `NODE_ENV=development` in production | CWE-489  | Python, JS/TS                 |
| misconfig-default-creds     | Default admin/password patterns                    | CWE-798  | Python, JS/TS, Java           |
| misconfig-permissive-cors   | `Access-Control-Allow-Origin: *`                   | CWE-942  | Python, JS/TS                 |
| misconfig-directory-listing | Directory listing enabled                          | CWE-548  | Python (Django), JS (Express) |
| misconfig-verbose-errors    | Stack trace in HTTP responses                      | CWE-209  | Python, JS/TS, Java           |
| misconfig-missing-headers   | Missing X-Frame-Options, CSP                       | CWE-1021 | Python, JS/TS                 |

### Rule Structure

Each rule follows existing pattern:

```yaml
rules:
  - id: devsecops.a02.crypto-weak-hash
    metadata:
      cwe: ["CWE-328"]
      owasp: ["A02:2021", "A02:2025"]
      nist: ["SC-13"]
      mitre: ["T1557"]
      confidence: HIGH
      likelihood: HIGH
    languages: [python]
    severity: WARNING
    message: |
      Weak hash algorithm detected...
    fix: |
      Use SHA-256 or SHA-3...
    patterns:
      - pattern: hashlib.md5(...)
```

### Tests

- `tests/test-a02-rules.sh` (~15 tests) — fixture files with vulnerable + safe patterns
- `tests/test-a05-rules.sh` (~15 tests) — same approach
- Test fixtures in `tests/fixtures/` (Python + JS files)

---

## Phase C: Nuclei DAST Full Integration (#41)

### Docker

**`runner/docker-compose.yml`** — Add profile:

```yaml
nuclei:
  image: projectdiscovery/nuclei:latest
  profiles: ["nuclei", "dast", "all"]
  volumes:
    - ${SCAN_TARGET:-.}:/target:ro
    - ./output:/output
  network_mode: host # Nuclei needs network access for DAST
```

### Job Dispatcher

**`runner/job-dispatcher.sh`** — Add `run_nuclei()`:

```bash
run_nuclei() {
  local target="$1"
  local mode="${2:-cve}"      # cve | full | custom
  local templates="${3:-}"    # custom template path
  local timeout

  case "$mode" in
    cve)  timeout=120  ;;
    full) timeout=600  ;;
    custom) timeout=300 ;;
  esac

  # Run Nuclei with appropriate template set
  docker compose run --rm nuclei \
    -u "$target" \
    -t "/templates/$mode/" \
    -jsonl -o /output/nuclei-results.jsonl \
    -timeout "$timeout"
}
```

Modes:

- `cve` — CVE-specific templates only (~120s, known vulnerability detection)
- `full` — All templates (~600s, comprehensive scan)
- `custom` — User-provided template directory

### Skill Update

**`skills/dast-scan/SKILL.md`** — Extend:

- Add `--tool nuclei` flag (default remains `zap`)
- Add Nuclei scan modes: `--mode cve|full|custom`
- Keep In-the-Loop decision requirement (same as ZAP)
- Bilingual output template for Nuclei results

### Normalizer

**`formatters/normalizer.sh`** — Add Nuclei parser:

- Nuclei outputs JSONL (one finding per line)
- Map to normalized format: `{ id, source_tool: "nuclei", severity, cwe, title, location }`
- Map Nuclei severity (critical/high/medium/low/info) to normalized severity

### Result Collector

**`runner/result-collector.sh`** — Add Nuclei output handling:

- Read JSONL from `/output/nuclei-results.jsonl`
- Convert to normalized JSON array

### Tests

**`tests/test-nuclei-integration.sh`** (~20 tests):

- Dispatcher routing tests (mode selection, timeout values)
- Normalizer parsing tests (JSONL fixtures)
- Skill trigger keyword tests
- Docker compose profile validation

---

## Phase D: Regulatory — NCSA 1.0 + PDPA (#42, #44)

### NCSA 1.0 Review (#42)

**`scripts/dast-ncsa-validator.sh`** — Review against published standard:

Current coverage:

- 1.x: HTTP Security Headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy)
- 2.x: Transport Security (TLS >= 1.2, certificate validity)
- 4.x: Session Management (Cookie Secure, HttpOnly, SameSite)

Review checklist:

- [ ] Compare 1.x checks against NCSA 1.0 final header requirements
- [ ] Verify 2.x TLS checks (TLS 1.3 preference? cipher suite requirements?)
- [ ] Check if 3.x (Access Control) section exists in final standard
- [ ] Verify 4.x cookie flag requirements
- [ ] Add any missing checks
- [ ] Update `test-ncsa-validator.sh` accordingly

### PDPA Mapping (#44)

**New file: `mappings/cwe-to-pdpa.json`** (~30 CWE mappings):

```json
{
  "_meta": {
    "framework": "PDPA",
    "full_name": "Thailand Personal Data Protection Act B.E. 2562 (2019)",
    "version": "1.0",
    "effective_date": "2022-06-01",
    "last_checked": "2026-XX-XX"
  },
  "mappings": {
    "CWE-312": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Cleartext Storage of Sensitive Information",
      "requirement": "appropriate security measures for personal data"
    },
    "CWE-359": {
      "pdpa": ["Section 23", "Section 26"],
      "category": "Consent & Sensitive Data",
      "name": "Exposure of Private Information",
      "requirement": "consent management and sensitive data protection"
    }
  }
}
```

Key PDPA articles to map:

- Section 23: Consent for collection
- Section 26: Sensitive data (requires explicit consent)
- Section 27: Cross-border transfer restrictions
- Section 37: Security measures obligation
- Section 77: Breach notification (72 hours to PDPC)
- Section 90: Penalties (5M THB civil + criminal)

**MCP update**: Add `pdpa` to `compliance_status` tool enum in `mcp/server.mjs`

**Tests**: `tests/test-pdpa-mapping.sh` — JSON structure, required fields, CWE format

---

## Phase E: Custom Rules Wave 2 — A04/A10:2025 (#43)

### `rules/a04-insecure-design-rules.yml` (~4 rules)

| Rule ID                    | Pattern                                  | CWE     | Languages                           |
| -------------------------- | ---------------------------------------- | ------- | ----------------------------------- |
| design-missing-rate-limit  | No rate limiting on auth endpoints       | CWE-770 | Python (Flask/Django), JS (Express) |
| design-no-captcha          | Auth forms without CAPTCHA/anti-bot      | CWE-804 | Python, JS/TS                       |
| design-unrestricted-upload | File upload without type/size validation | CWE-434 | Python, JS/TS                       |
| design-trust-boundary      | User input trusted without validation    | CWE-501 | Python, JS/TS, Java                 |

### `rules/a10-exception-rules.yml` (~4 rules)

| Rule ID                     | Pattern                                  | CWE     | Languages           |
| --------------------------- | ---------------------------------------- | ------- | ------------------- |
| exception-generic-catch     | Bare `except:` / `catch(e)` without type | CWE-396 | Python, JS/TS, Java |
| exception-stack-exposure    | Stack trace returned in HTTP response    | CWE-209 | Python, JS/TS       |
| exception-missing-boundary  | React components without ErrorBoundary   | CWE-755 | JS/TS (React)       |
| exception-unhandled-promise | Unhandled promise rejection              | CWE-755 | JS/TS               |

### Tests

- `tests/test-a04-rules.sh` (~12 tests)
- `tests/test-a10-rules.sh` — already exists (28 tests for A10:2021 SSRF), extend with A10:2025 Exception Handling tests

---

## Phase F: Release

1. Version bump: `scripts/version-bump.sh 2.7.0` (7 files)
2. MCP rebuild: `cd mcp && bash build.sh`
3. Release checklist: `scripts/release-checklist.sh 2.7.0` (31+ checks)
4. Update docs:
   - PRD.md: Current State → v2.7.0, metrics update
   - README.md: badges, test count, OWASP coverage
   - CHANGELOG.md: v2.7.0 entry
5. QA round via GitHub Issue
6. Tag + GitHub Release
7. Close milestone #2

---

## Metrics — Expected v2.7.0 State

| Metric                | v2.6.1 (current) | v2.7.0 (target)         |
| --------------------- | ---------------- | ----------------------- |
| Custom Semgrep rules  | 33 (4/10 OWASP)  | ~53 (8/10 OWASP)        |
| CWE mappings (OWASP)  | 105 (2021 only)  | ~120 (dual 2021+2025)   |
| CWE mappings (PDPA)   | 0                | ~30                     |
| DAST tools            | 1 (ZAP)          | 2 (ZAP + Nuclei)        |
| Compliance frameworks | 4                | 5 (+ PDPA)              |
| Test suites           | 22               | ~28 (+6 new test files) |
| Total tests           | 793+             | ~900+                   |
| Docker tool images    | 7                | 8 (+ Nuclei)            |

---

## Files Summary

| Phase | Action | File                                                 |
| ----- | ------ | ---------------------------------------------------- |
| A     | Modify | `frameworks.json`                                    |
| A     | Modify | `mappings/cwe-to-owasp.json`                         |
| A     | Modify | `formatters/normalizer.sh` (verify array handling)   |
| B     | Create | `rules/a02-crypto-rules.yml`                         |
| B     | Create | `rules/a05-misconfig-rules.yml`                      |
| B     | Create | `tests/test-a02-rules.sh`                            |
| B     | Create | `tests/test-a05-rules.sh`                            |
| B     | Create | `tests/fixtures/a02-*.py`, `tests/fixtures/a02-*.js` |
| B     | Create | `tests/fixtures/a05-*.py`, `tests/fixtures/a05-*.js` |
| C     | Modify | `runner/docker-compose.yml`                          |
| C     | Modify | `runner/job-dispatcher.sh`                           |
| C     | Modify | `skills/dast-scan/SKILL.md`                          |
| C     | Modify | `formatters/normalizer.sh`                           |
| C     | Modify | `runner/result-collector.sh`                         |
| C     | Create | `tests/test-nuclei-integration.sh`                   |
| C     | Create | `tests/fixtures/nuclei-*.jsonl`                      |
| D     | Modify | `scripts/dast-ncsa-validator.sh`                     |
| D     | Create | `mappings/cwe-to-pdpa.json`                          |
| D     | Modify | `mcp/server.mjs`                                     |
| D     | Create | `tests/test-pdpa-mapping.sh`                         |
| E     | Create | `rules/a04-insecure-design-rules.yml`                |
| E     | Create | `rules/a10-exception-rules.yml`                      |
| E     | Create | `tests/test-a04-rules.sh`                            |
| E     | Modify | `tests/test-a10-rules.sh` (extend)                   |
| F     | Modify | 7 version files + MCP bundle + docs                  |

---

_Approved: 2026-03-03_
