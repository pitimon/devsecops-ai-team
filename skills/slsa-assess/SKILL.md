---
name: slsa-assess
description: Assess SLSA (Supply-chain Levels for Software Artifacts) compliance level for a project. Checks build provenance, source integrity, and dependency completeness against SLSA v1.1 framework.
argument-hint: "[--target <path>] [--level 1|2|3]"
user-invocable: true
allowed-tools: ["Read", "Bash", "Glob", "Grep"]
---

# SLSA Provenance Assessment

Assess a project's supply chain security posture against the SLSA v1.1 framework. Determines current SLSA level and provides gap analysis for reaching the next level.

**Decision Loop**: On-the-Loop (AI proposes assessment, human reviews findings)

## Agent Delegation

This skill delegates to `@agent-supply-chain-advisor` for SLSA analysis.

## Reference

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/slsa-reference.md` for SLSA framework details, level definitions, and assessment checklist.

## Assessment Workflow

### 1. Project Discovery

Scan the target project for supply chain artifacts:

```bash
# Build process indicators
Glob: Dockerfile, Makefile, .github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile

# SBOM files
Glob: *sbom*.json, *bom*.json, *.spdx.json, *.cdx.json

# Signing and provenance
Glob: cosign.key, cosign.pub, *.sig, *.intoto.jsonl
Grep: "cosign sign", "attest-build-provenance", "slsa-github-generator" in CI configs

# Dependency lock files
Glob: package-lock.json, yarn.lock, pnpm-lock.yaml, go.sum, Cargo.lock, Pipfile.lock, requirements.txt, composer.lock

# Source integrity
Glob: CODEOWNERS, .github/branch-protection.yml
```

### 2. Level Assessment

Evaluate each SLSA level sequentially (L1 → L2 → L3). A level is achieved only when **all** checks for that level pass.

**Level 1** — Build process exists:

- Build process documented (CI config or Dockerfile present)
- SBOM generated or generatable (Syft/CycloneDX tool in CI or SBOM file present)
- Source in version control (git repository with commit history)
- Provenance generated (build logs, artifact uploads in CI)

**Level 2** — Hosted build platform:

- Build runs on hosted/managed CI service (GitHub Actions, GitLab CI, Jenkins)
- Provenance signed by build service (cosign, Sigstore, GitHub Attestations)
- Source authenticated (signed commits, branch protections)
- Dependencies declared in lock files

**Level 3** — Hardened builds:

- Isolated/ephemeral build environment (container-based, ephemeral runners)
- Non-falsifiable provenance (SLSA generator, GitHub Artifact Attestations, in-toto)
- Two-person review enforced (CODEOWNERS + required approvals)
- Hermetic builds (no network during build, all deps pre-fetched)
- Dependencies pinned by hash/SHA (not mutable tags)

### 3. Gap Analysis

For each unmet check at the next target level:

- Describe what is missing
- Estimate implementation effort (Trivial / Small / Medium / Large)
- Assign priority (P1 = quick win, P2 = short-term, P3 = long-term)
- Suggest concrete steps to remediate

### 4. Output

Present the assessment using the bilingual template:

```markdown
## การประเมิน SLSA (SLSA Provenance Assessment)

### สรุป (Summary)

- **Current SLSA Level**: Level X
- **Target Level**: Level Y
- **Gap items**: N items to reach next level
- **EU CRA readiness**: Z% (deadline: Sep 11, 2026)

### ผลการตรวจสอบแต่ละระดับ (Level Checklist)

#### Level 1

| Check                    | Status    | Evidence               |
| ------------------------ | --------- | ---------------------- |
| Build process documented | PASS/FAIL | <file or config found> |
| SBOM present             | PASS/FAIL | <file or tool found>   |
| Source in VCS            | PASS/FAIL | <git history summary>  |
| Provenance generated     | PASS/FAIL | <CI artifact config>   |

#### Level 2

| Check                 | Status    | Evidence             |
| --------------------- | --------- | -------------------- |
| Hosted build platform | PASS/FAIL | <platform name>      |
| Signed provenance     | PASS/FAIL | <signing tool found> |
| Authenticated source  | PASS/FAIL | <signed commits %>   |
| Dependencies declared | PASS/FAIL | <lock files found>   |

#### Level 3

| Check                      | Status    | Evidence                     |
| -------------------------- | --------- | ---------------------------- |
| Hardened build env         | PASS/FAIL | <runner config>              |
| Non-falsifiable provenance | PASS/FAIL | <attestation tool>           |
| Two-person review          | PASS/FAIL | <CODEOWNERS + protection>    |
| Hermetic builds            | PASS/FAIL | <network isolation evidence> |

### Gap Analysis

| Gap | Current | Required for Level Y | Effort | Priority |
| --- | ------- | -------------------- | ------ | -------- |
| ... | ...     | ...                  | ...    | ...      |

### คำแนะนำ (Recommendations)

1. **Quick wins** — items implementable today
2. **Short-term** — items for the next sprint
3. **Long-term** — items requiring architectural changes
```

## EU CRA Note

The EU Cyber Resilience Act (effective **Sep 11, 2026**) requires SBOM, vulnerability handling, and supply chain security documentation for all products with digital elements. SLSA Level 2+ satisfies many EU CRA supply chain requirements. The `/slsa-assess` skill flags EU CRA gaps alongside SLSA gaps in the report.

Thailand NCSA (effective **Sep 16, 2026**) requires supply chain risk assessment for critical infrastructure operators.

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/slsa-reference.md` for full EU CRA alignment mapping.
Load `${CLAUDE_PLUGIN_ROOT}/skills/references/sca-supply-chain.md` for dependency and SBOM analysis context.
Load `${CLAUDE_PLUGIN_ROOT}/skills/references/software-integrity.md` for A08 integrity verification patterns.
