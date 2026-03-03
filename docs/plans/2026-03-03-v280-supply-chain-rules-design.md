# v2.8.0 Design — Supply Chain Compliance + Rules Expansion

> **Date**: 2026-03-03
> **Status**: Approved
> **Issues**: #45, #46, #47, #48, #49, #50
> **Theme**: Supply chain security compliance + complete OWASP 10/10 rule coverage
> **Regulatory Driver**: EU CRA vulnerability reporting deadline Sep 11, 2026

## Decisions

| Decision          | Choice                                | Rationale                                               |
| ----------------- | ------------------------------------- | ------------------------------------------------------- |
| Scope             | All 6 features in v2.8.0              | Complete supply chain + OWASP 10/10 in one release      |
| Secret validity   | Full verification with 4 providers    | Production-ready with mock test suite                   |
| SLSA skill        | New `/slsa-assess` skill (14th skill) | Standalone assessment, not bundled into existing skills |
| VEX format        | CycloneDX VEX + OpenVEX dual output   | Both standards gaining adoption, maximize compatibility |
| TruffleHog        | Extend existing `/secret-scan` skill  | No new skill, complement GitLeaks in same workflow      |
| SOC 2 / ISO 27001 | Same mapping pattern as PDPA          | Proven structure from v2.7.0                            |

## Phase A: OWASP 10/10 Custom Rules (#47)

Complete remaining 3 categories. After v2.7.0 we cover A01-A05, A09-A10 (8/10).

### A06:2025 — Vulnerable and Outdated Components (~5 rules)

File: `rules/a06-component-rules.yml`

| Rule ID                     | CWE      | Language | Pattern                                             |
| --------------------------- | -------- | -------- | --------------------------------------------------- |
| a06-unpinned-pip            | CWE-1104 | generic  | `requirements.txt` with unpinned versions (no `==`) |
| a06-unpinned-npm            | CWE-1104 | generic  | `package.json` with `*` or `latest` version ranges  |
| a06-known-vulnerable-pyyaml | CWE-829  | python   | Import of pyyaml < 6.0 patterns                     |
| a06-no-lockfile-check       | CWE-829  | generic  | Package install without lockfile verification       |
| a06-untrusted-source        | CWE-829  | generic  | pip install from non-PyPI sources                   |

### A07:2025 — Identification and Authentication Failures (~5 rules)

File: `rules/a07-auth-rules.yml`

| Rule ID                       | CWE     | Language | Pattern                                   |
| ----------------------------- | ------- | -------- | ----------------------------------------- |
| a07-weak-password-python      | CWE-521 | python   | Password validation with len < 8          |
| a07-hardcoded-jwt-secret      | CWE-798 | generic  | JWT secret as string literal              |
| a07-session-no-expire         | CWE-613 | python   | Session config without expiry             |
| a07-missing-mfa-check         | CWE-308 | generic  | Auth flow without MFA verification        |
| a07-permissive-password-reset | CWE-640 | python   | Password reset without token verification |

### A08:2025 — Software and Data Integrity Failures (~5 rules)

File: `rules/a08-integrity-rules.yml`

| Rule ID              | CWE     | Language | Pattern                                        |
| -------------------- | ------- | -------- | ---------------------------------------------- |
| a08-unsafe-pickle    | CWE-502 | python   | pickle.loads() on untrusted data               |
| a08-yaml-unsafe-load | CWE-502 | python   | yaml.load() without SafeLoader                 |
| a08-cdn-no-integrity | CWE-829 | generic  | `<script src=` without `integrity=`            |
| a08-unpinned-action  | CWE-829 | generic  | GitHub Actions `uses:` without SHA pin         |
| a08-unsigned-install | CWE-494 | generic  | Package install without signature verification |

**Result**: 53 → ~68 rules, 8/10 → 10/10 OWASP coverage

## Phase B: SOC 2 + ISO 27001 Compliance Mapping (#48)

Same proven pattern as PDPA (v2.7.0):

### SOC 2 Trust Service Criteria

File: `mappings/cwe-to-soc2.json`

Structure: `{ _meta, mappings: { "CWE-89": { "soc2": ["CC6.1"], "category": "...", "name": "...", "requirement": "..." } } }`

Categories:

- CC6.x — Logical and Physical Access Controls
- CC7.x — System Operations
- CC8.x — Change Management
- CC9.x — Risk Mitigation
- C1.x — Confidentiality
- A1.x — Availability
- PI1.x — Processing Integrity

Target: ~40 CWE mappings

### ISO 27001:2022 Annex A

File: `mappings/cwe-to-iso27001.json`

Structure: `{ _meta, mappings: { "CWE-89": { "iso27001": ["A.8.28"], "category": "...", "name": "...", "requirement": "..." } } }`

Control groups:

- A.5 — Organizational Controls
- A.6 — People Controls
- A.7 — Physical Controls
- A.8 — Technological Controls

Target: ~40 CWE mappings

### MCP Update

- `compliance_status` frameworks array: 5 → 7 (add "soc2", "iso27001")
- `frameworks.json`: 2 new entries
- Rebuild MCP bundle

## Phase C: SLSA Provenance Assessment Skill (#45)

New skill `/slsa-assess` — 14th skill.

### Skill Definition

`skills/slsa-assess/SKILL.md`:

- Triggers: slsa, provenance, supply chain assessment, supply-chain level
- Decision Loop: On-the-Loop (AI proposes, human approves)
- Allowed tools: Bash, Read, Glob, Grep

### Reference File

`skills/references/slsa-reference.md` — SLSA v1.1 framework:

| Level | Requirements                               | Assessment Checks                               |
| ----- | ------------------------------------------ | ----------------------------------------------- |
| 0     | No guarantees                              | Default if nothing found                        |
| 1     | Build process exists, provenance generated | Dockerfile/CI config exists, SBOM present       |
| 2     | Hosted build platform, signed provenance   | GitHub Actions/GitLab CI, sigstore/cosign usage |
| 3     | Hardened build, non-falsifiable provenance | Isolated build, GitHub Artifact Attestations    |

### Assessment Output

```markdown
## SLSA Assessment — [project-name]

**Current Level**: SLSA 2
**Target Level**: SLSA 3

### Level 1 ✅

- [x] Build process documented (Dockerfile found)
- [x] SBOM generated (Syft integration available)

### Level 2 ✅

- [x] Hosted build platform (GitHub Actions detected)
- [x] Signed provenance (cosign signatures found)

### Level 3 ❌

- [ ] Hardened build environment (no isolated runner config)
- [ ] Non-falsifiable provenance (GitHub Artifact Attestations not enabled)

### Gap Analysis

1. Enable GitHub Artifact Attestations for non-falsifiable provenance
2. Configure ephemeral build runners for build isolation
```

## Phase D: VEX Output Format (#46)

New formatter: `formatters/vex-formatter.sh`

### CycloneDX VEX Format

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": { "name": "NVD" },
      "analysis": {
        "state": "exploitable",
        "justification": "requires_environment",
        "response": ["will_fix"],
        "detail": "Log4j RCE — affects production environment"
      },
      "affects": [
        { "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }
      ]
    }
  ]
}
```

### OpenVEX Format

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "devsecops-ai-team",
  "timestamp": "2026-03-03T10:00:00Z",
  "statements": [
    {
      "vulnerability": { "@id": "CVE-2021-44228" },
      "products": [
        { "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }
      ],
      "status": "affected",
      "justification": "vulnerable_code_in_use"
    }
  ]
}
```

### Integration

- Input: normalized findings JSON (same as all formatters)
- Triage decisions from MCP `devsecops_triage` map to VEX status:
  - `critical`/`high` → `affected`
  - `suppressed` → `not_affected`
  - `resolved` → `fixed`
  - default → `under_investigation`
- `--format vex-cdx` for CycloneDX, `--format vex-openvex` for OpenVEX

## Phase E: TruffleHog Secret Scanning (#49)

9th security tool, follows Nuclei integration pattern from v2.7.0.

### Docker

```yaml
trufflehog:
  image: trufflesecurity/trufflehog:latest
  profiles: ["trufflehog", "secrets", "all"]
  volumes:
    - ${SCAN_TARGET:-.}:/scan:ro
    - ./output:/output
  mem_limit: 1g
```

### Job Dispatcher

`run_trufflehog()` function with 3 modes:

- `git` — scan git repo history (default)
- `filesystem` — scan filesystem (no git history)
- `s3` — scan S3 bucket (requires AWS credentials)

### Normalizer

TruffleHog JSON → Unified Finding Schema:

- `DetectorName` → `rule_id`
- `Raw` → redacted in output (first 4 chars + `***`)
- `SourceMetadata` → `location`
- `Verified` → `confidence` (verified=HIGH, unverified=MEDIUM)

### Skill Extension

Extend `skills/secret-scan/SKILL.md`:

- Add TruffleHog as complementary tool
- `--tool gitleaks|trufflehog|both` flag
- Cross-tool dedup via `dedup-findings.sh`

## Phase F: Secret Validity Checking (#50)

### Architecture

```
scripts/secret-verifier.sh
  ├── Input: normalized findings JSON (from GitLeaks or TruffleHog)
  ├── Filter: only findings with secret-like patterns
  ├── Prompt: user confirmation (--confirm flag or interactive)
  ├── Verify: provider-specific API call
  ├── Output: findings JSON with verification_status added
  └── Audit: verification-audit.json log
```

### Providers

| Provider     | Method                        | Endpoint       | Detection                   |
| ------------ | ----------------------------- | -------------- | --------------------------- |
| AWS          | `aws sts get-caller-identity` | STS API        | `AKIA` prefix               |
| GitHub       | `GET /user` with token        | api.github.com | `ghp_`/`gho_`/`github_pat_` |
| Slack        | `auth.test` with token        | slack.com/api  | `xoxb-`/`xoxp-`             |
| Generic HTTP | Configurable GET/POST         | User-defined   | Pattern match               |

### Safety Controls

- **In-the-Loop**: `--confirm` flag required, interactive prompt per secret
- **Rate limiting**: max 5 verifications/minute/provider
- **Redaction**: only first 4 chars of secret shown in prompts/logs
- **Audit trail**: `verification-audit.json` with timestamp, provider, result, redacted value
- **No storage**: verified secrets never written to disk, only status

### Verification Status

- `valid` — secret is active and working
- `invalid` — secret rejected by provider
- `expired` — secret recognized but expired
- `unknown` — provider unreachable or unsupported
- `skipped` — user declined verification

## Expected Metrics

| Metric                | v2.7.0 | v2.8.0 Target           |
| --------------------- | ------ | ----------------------- |
| Custom Semgrep rules  | 53     | ~68                     |
| OWASP coverage        | 8/10   | 10/10                   |
| Security tools        | 8      | 9 (+TruffleHog)         |
| Compliance frameworks | 5      | 7 (+SOC2, +ISO27001)    |
| CWE mappings          | 405    | ~485                    |
| Output formats        | 6      | 7 (+VEX)                |
| Skills                | 13     | 14 (+/slsa-assess)      |
| Reference files       | 16     | 17 (+slsa-reference.md) |
| Test suites           | 28     | ~35                     |
| Total tests           | 978    | ~1,100+                 |

## Files Summary

| Action | Files                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------- |
| Create | `rules/a06-component-rules.yml`, `rules/a07-auth-rules.yml`, `rules/a08-integrity-rules.yml`      |
| Create | `tests/fixtures/sample-a06-findings.json`, `sample-a07-findings.json`, `sample-a08-findings.json` |
| Create | `tests/test-a06-rules.sh`, `test-a07-rules.sh`, `test-a08-rules.sh`                               |
| Create | `mappings/cwe-to-soc2.json`, `mappings/cwe-to-iso27001.json`                                      |
| Create | `tests/test-soc2-mapping.sh`, `tests/test-iso27001-mapping.sh`                                    |
| Create | `skills/slsa-assess/SKILL.md`, `skills/references/slsa-reference.md`                              |
| Create | `tests/test-slsa-skill.sh`                                                                        |
| Create | `formatters/vex-formatter.sh`, `tests/test-vex-formatter.sh`                                      |
| Create | `tests/fixtures/sample-trufflehog.json`                                                           |
| Create | `tests/test-trufflehog-integration.sh`                                                            |
| Create | `scripts/secret-verifier.sh`, `tests/test-secret-verifier.sh`                                     |
| Modify | `runner/docker-compose.yml`, `runner/job-dispatcher.sh`, `formatters/json-normalizer.sh`          |
| Modify | `mcp/server.mjs`, `mcp/dist/server.js`, `frameworks.json`                                         |
| Modify | `skills/secret-scan/SKILL.md`, `mappings/cwe-to-owasp.json`                                       |
| Modify | `CHANGELOG.md`, `README.md`, `docs/PRD.md`                                                        |
