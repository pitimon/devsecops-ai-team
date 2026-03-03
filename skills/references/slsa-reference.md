# SLSA (Supply-chain Levels for Software Artifacts) Reference — v1.1

# ความรู้อ้างอิงด้าน SLSA Framework สำหรับการประเมิน Supply Chain Integrity

> **Purpose / วัตถุประสงค์**: Domain knowledge for the `/slsa-assess` skill to evaluate project supply chain posture against the SLSA v1.1 framework. Covers build provenance, source integrity, dependency completeness, and regulatory alignment (EU CRA, NCSA).
>
> **Version**: 1.0 | **Last Updated**: 2026-03-03 | **Frameworks**: SLSA v1.1, Sigstore/cosign, in-toto, EU CRA 2024/2847

---

## 1. Overview

## ภาพรวม SLSA

SLSA (pronounced "salsa") is a security framework created by Google and the Open Source Security Foundation (OpenSSF) to protect software supply chain integrity. It defines four build levels (0-3) with increasing assurance that artifacts are built correctly from the intended source.

SLSA v1.1 focuses on three trust boundaries:

- **Build integrity**: The build process produces the expected output from the expected source
- **Source integrity**: The source code reflects the intent of the developers
- **Dependency completeness**: All dependencies are accounted for and verified

### Key Terminology

| Term           | Definition                                                             |
| -------------- | ---------------------------------------------------------------------- |
| Provenance     | Metadata describing how an artifact was built (source, builder, steps) |
| Attestation    | Signed statement about an artifact's properties (in-toto format)       |
| Builder        | The platform/service that executes the build (e.g., GitHub Actions)    |
| Hermetic build | A build with no external network access — all inputs declared upfront  |
| Build level    | SLSA 0-3 indicating the strength of the build integrity guarantees     |

---

## 2. SLSA Levels

## ระดับ SLSA

| Level | Build                                        | Provenance                             | Source                                   |
| ----- | -------------------------------------------- | -------------------------------------- | ---------------------------------------- |
| 0     | No guarantees                                | None                                   | None                                     |
| 1     | Build process exists and produces provenance | Provenance generated (may be unsigned) | Version controlled                       |
| 2     | Hosted build platform                        | Signed provenance from build service   | Verified history                         |
| 3     | Hardened, isolated build environment         | Non-falsifiable provenance             | Retained indefinitely, two-person review |

---

## 3. Assessment Checks per Level

## รายการตรวจสอบแต่ละระดับ

### Level 1 Checks

| Check                     | What to Look For                            | Detection Method                                                                              |
| ------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Build process documented  | Dockerfile, Makefile, CI config present     | Glob for `Dockerfile`, `Makefile`, `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile` |
| SBOM present              | CycloneDX or SPDX file in repo or CI output | Glob for `*sbom*.json`, `*bom*.json`, `*.spdx.json`                                           |
| Source in version control | Git repository with history                 | Check `.git/` existence, `git log --oneline -5`                                               |
| Provenance generated      | Build logs with timestamps, CI artifacts    | Check CI config for artifact upload steps                                                     |

### Level 2 Checks

| Check                  | What to Look For                               | Detection Method                                                                                      |
| ---------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Hosted build platform  | GitHub Actions, GitLab CI, Jenkins, CircleCI   | Grep CI config files for platform indicators                                                          |
| Signed provenance      | cosign, Sigstore, GitHub Artifact Attestations | Glob for `.sig`, `*.intoto.jsonl`, `cosign.key`; grep for `cosign sign`, `attest` in CI               |
| Authenticated source   | Signed commits, branch protection rules        | `git log --show-signature`, check for `require_signed_commits`                                        |
| Dependencies declared  | Lock files present and up-to-date              | Glob for `package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `Pipfile.lock`, `requirements.txt` |
| Build service identity | Build triggered by authenticated identity      | Check `permissions:` block in GitHub Actions, GitLab CI `protected` flag                              |

### Level 3 Checks

| Check                      | What to Look For                                      | Detection Method                                                                    |
| -------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Hardened build environment | Ephemeral runners, sandboxed builds                   | Check for self-hosted runner config, `runs-on:` values, container-based jobs        |
| Non-falsifiable provenance | GitHub Artifact Attestations, in-toto, SLSA generator | Grep for `slsa-framework/slsa-github-generator`, `actions/attest-build-provenance`  |
| Two-person review          | Branch protection requiring approvals                 | Check `.github/` settings, `CODEOWNERS` file, `required_pull_request_reviews`       |
| Hermetic builds            | No network access during build, all deps pre-fetched  | Check for `--network=none` in Docker builds, `npm ci --ignore-scripts`, pinned deps |
| Reproducible builds        | Deterministic build output                            | Check for `SOURCE_DATE_EPOCH`, reproducibility CI steps                             |
| Pinned dependencies        | Actions/deps pinned by SHA, not tag                   | Grep for SHA-pinned `uses:` in workflows, `--require-hashes` in pip                 |

---

## 4. Tool Detection Patterns

## รูปแบบการตรวจจับเครื่องมือ

| Tool / Feature       | Detection Pattern                                          | SLSA Relevance                  |
| -------------------- | ---------------------------------------------------------- | ------------------------------- |
| GitHub Actions       | `.github/workflows/*.yml`                                  | Build platform (L2+)            |
| GitLab CI            | `.gitlab-ci.yml`                                           | Build platform (L2+)            |
| Jenkins              | `Jenkinsfile`                                              | Build platform (L2+)            |
| Dockerfile           | `Dockerfile`, `*.dockerfile`                               | Build process (L1+)             |
| cosign               | `cosign sign`, `cosign verify`, `cosign.key`, `cosign.pub` | Signed provenance (L2+)         |
| Sigstore             | `sigstore`, `rekor`, `fulcio` in CI config                 | Signed provenance (L2+)         |
| Syft                 | `syft`, `anchore/syft` in CI config                        | SBOM generation (L1+)           |
| in-toto              | `in-toto`, `.intoto.jsonl`, `slsa-verifier`                | Non-falsifiable provenance (L3) |
| SLSA Generator       | `slsa-framework/slsa-github-generator`                     | Provenance generation (L2-L3)   |
| GitHub Attestations  | `actions/attest-build-provenance`                          | Non-falsifiable provenance (L3) |
| Branch protection    | `CODEOWNERS`, `.github/branch-protection.yml`              | Two-person review (L3)          |
| Lock files           | `package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`   | Dependency declaration (L2+)    |
| npm audit signatures | `npm audit signatures` in CI                               | Registry provenance (L2+)       |

---

## 5. EU CRA Alignment

## ความสอดคล้องกับ EU Cyber Resilience Act

The EU Cyber Resilience Act (Regulation 2024/2847, effective **Sep 11, 2026**) requires:

| EU CRA Requirement                           | SLSA Level | How SLSA Helps                                  |
| -------------------------------------------- | ---------- | ----------------------------------------------- |
| Vulnerability handling processes             | L1+        | Build process documentation, CI/CD traceability |
| SBOM for all products with digital elements  | L1+        | SBOM generation as part of build provenance     |
| Coordinated vulnerability disclosure         | L2+        | Authenticated source, signed releases           |
| Software supply chain security documentation | L2+        | Signed provenance, dependency declaration       |
| Secure by default configuration              | L2+        | Hosted build platform with security controls    |
| Security update mechanism                    | L3         | Hermetic builds, reproducible artifacts         |

**SBOM deadline for EU CRA**: Dec 11, 2027 (extended deadline for SBOM reporting).

**NCSA (Thailand)**: Effective Sep 16, 2026 — requires supply chain risk assessment for critical infrastructure.

### Regulatory Checklist

- [ ] SBOM generated in CycloneDX or SPDX format
- [ ] Vulnerability scanning integrated in CI/CD
- [ ] Signed artifacts for all releases
- [ ] Dependency update policy documented
- [ ] Incident response plan covers supply chain attacks
- [ ] Build provenance available for audit

---

## 6. Provenance Verification Commands

## คำสั่งตรวจสอบ Provenance

```bash
# Verify SLSA provenance for container images
slsa-verifier verify-image \
  --source-uri github.com/org/app \
  --source-tag v2.1.0 \
  myregistry.io/app:v2.1.0

# Verify SLSA provenance for artifacts
slsa-verifier verify-artifact myapp.tar.gz \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/org/app \
  --source-tag v1.0.0

# Verify Sigstore-signed container image
cosign verify \
  --certificate-identity "https://github.com/org/app/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/org/app:v1.0.0

# Verify npm package provenance (npm v9.5+)
npm audit signatures

# Verify Go module checksums
go mod verify
```

---

## 7. Output Template

## รูปแบบรายงานผลการประเมิน

```markdown
## การประเมิน SLSA (SLSA Provenance Assessment)

### สรุป (Summary)

- **Current SLSA Level**: Level X
- **Target Level**: Level Y
- **Gap items**: N items to reach next level
- **EU CRA readiness**: Z% (deadline: Sep 11, 2026)

### ผลการตรวจสอบแต่ละระดับ (Level Checklist)

#### Level 1

| Check                    | Status    | Evidence                             |
| ------------------------ | --------- | ------------------------------------ |
| Build process documented | PASS/FAIL | Dockerfile, .github/workflows/ci.yml |
| SBOM present             | PASS/FAIL | sbom.json (CycloneDX v1.6)           |
| Source in VCS            | PASS/FAIL | git repository with N commits        |
| Provenance generated     | PASS/FAIL | CI artifacts uploaded                |

#### Level 2

| Check                 | Status    | Evidence                  |
| --------------------- | --------- | ------------------------- |
| Hosted build platform | PASS/FAIL | GitHub Actions            |
| Signed provenance     | PASS/FAIL | cosign signatures found   |
| Authenticated source  | PASS/FAIL | Signed commits: X%        |
| Dependencies declared | PASS/FAIL | package-lock.json present |

#### Level 3

| Check                      | Status    | Evidence                       |
| -------------------------- | --------- | ------------------------------ |
| Hardened build env         | PASS/FAIL | Ephemeral runners              |
| Non-falsifiable provenance | PASS/FAIL | GitHub Artifact Attestations   |
| Two-person review          | PASS/FAIL | CODEOWNERS + branch protection |
| Hermetic builds            | PASS/FAIL | --network=none in Dockerfile   |

### Gap Analysis

| Gap               | Current        | Required for Level Y          | Effort  | Priority |
| ----------------- | -------------- | ----------------------------- | ------- | -------- |
| Signed provenance | Not configured | cosign or SLSA generator      | Small   | P1       |
| SBOM generation   | Manual         | Automated in CI               | Trivial | P1       |
| Branch protection | Partial        | Required reviews + CODEOWNERS | Small   | P2       |

### คำแนะนำ (Recommendations)

1. **Quick wins** — items that can be done today
2. **Short-term** — items for the next sprint
3. **Long-term** — items requiring architectural changes

### การปฏิบัติตามกฎหมาย (Regulatory Compliance)

- EU CRA (Sep 11, 2026): X/Y requirements met
- NCSA (Sep 16, 2026): Supply chain assessment status
```
