# SCA & Supply Chain Security Reference

# ความรู้อ้างอิงด้าน Software Composition Analysis และ Supply Chain Security

> **Purpose / วัตถุประสงค์**: Domain knowledge for the SCA agent to analyze dependency risks, generate and validate SBOMs, enforce license compliance, manage dependency updates, and detect supply chain attack patterns.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Standards**: CycloneDX v1.6, SPDX v2.3, OSV Schema v1.5, SLSA v1.0

---

## 1. Dependency Risk Scoring Framework

## กรอบการให้คะแนนความเสี่ยงของ Dependency

### 1.1 Risk Score Components (0-10 Scale)

| Factor                  | Weight | Description                  | Data Source                  |
| ----------------------- | ------ | ---------------------------- | ---------------------------- |
| Known Vulnerabilities   | 30%    | CVE count and severity       | OSV, NVD, GitHub Advisory    |
| Maintenance Status      | 20%    | Last commit, release cadence | GitHub API, package registry |
| Popularity / Adoption   | 10%    | Downloads, dependents, stars | npm, PyPI, Maven Central     |
| License Risk            | 10%    | Copyleft, restrictive terms  | SPDX license data            |
| Supply Chain Indicators | 15%    | Sigstore signing, provenance | SLSA attestations            |
| Dependency Depth        | 15%    | Transitive dependency count  | Lock file analysis           |

### 1.2 Risk Score Calculation

```python
def calculate_risk_score(dep: Dependency) -> float:
    vuln_score = min(10, sum(cvss for v in dep.vulns) / max(len(dep.vulns), 1))
    maintenance = 10 if dep.days_since_commit > 730 else dep.days_since_commit / 73
    popularity = 10 - min(10, math.log10(max(dep.weekly_downloads, 1)))
    license_risk = LICENSE_RISK_MAP.get(dep.license, 5)
    supply_chain = 0 if dep.has_provenance else 7
    depth = min(10, dep.transitive_count / 10)

    return (
        vuln_score * 0.30 +
        maintenance * 0.20 +
        popularity * 0.10 +
        license_risk * 0.10 +
        supply_chain * 0.15 +
        depth * 0.15
    )

# Risk thresholds
# 0-3.0: LOW    — Monitor in next cycle
# 3.1-6.0: MEDIUM — Review and plan update
# 6.1-8.0: HIGH  — Update within 7 days
# 8.1-10.0: CRITICAL — Update immediately, evaluate alternatives
```

### 1.3 OpenSSF Scorecard Integration

```bash
# Run OpenSSF Scorecard on a dependency
scorecard --repo=github.com/expressjs/express --format=json

# Key checks and thresholds
# Check               Min Score   Rationale
# Binary-Artifacts    8           No prebuilt binaries in repo
# Branch-Protection   6           Main branch protections enabled
# Code-Review         6           PRs require review
# Dangerous-Workflow  8           No dangerous GitHub Actions patterns
# Dependency-Update   6           Dependabot/Renovate enabled
# Maintained          6           Active within 90 days
# Pinned-Dependencies 8           Actions/deps pinned by hash
# Signed-Releases     6           Releases are signed
# Token-Permissions   8           Minimal GITHUB_TOKEN permissions
# Vulnerabilities     8           No known unpatched vulns
```

---

## 2. SBOM Standards and Generation

## มาตรฐาน SBOM และการสร้าง

### 2.1 CycloneDX v1.6

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-01T00:00:00Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "cdxgen",
          "version": "10.4.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "my-application",
      "version": "2.1.0",
      "bom-ref": "my-application@2.1.0"
    },
    "lifecycles": [{ "phase": "build" }]
  },
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.21.0",
      "purl": "pkg:npm/express@4.21.0",
      "bom-ref": "pkg:npm/express@4.21.0",
      "licenses": [{ "license": { "id": "MIT" } }],
      "externalReferences": [
        { "type": "vcs", "url": "https://github.com/expressjs/express" }
      ],
      "evidence": {
        "identity": {
          "confidence": 1.0,
          "methods": [{ "technique": "manifest-analysis" }]
        }
      }
    }
  ],
  "dependencies": [
    {
      "ref": "my-application@2.1.0",
      "dependsOn": ["pkg:npm/express@4.21.0"]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/" },
      "ratings": [{ "score": 7.5, "severity": "high", "method": "CVSSv31" }],
      "affects": [{ "ref": "pkg:npm/express@4.21.0" }],
      "analysis": {
        "state": "exploitable",
        "justification": "requires_environment"
      }
    }
  ]
}
```

### 2.2 SPDX v2.3

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-application-sbom",
  "documentNamespace": "https://example.com/sbom/my-application-2.1.0",
  "creationInfo": {
    "created": "2026-03-01T00:00:00Z",
    "creators": ["Tool: syft-1.4.0", "Organization: ExampleCorp"],
    "licenseListVersion": "3.23"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-express-4.21.0",
      "name": "express",
      "versionInfo": "4.21.0",
      "downloadLocation": "https://registry.npmjs.org/express/-/express-4.21.0.tgz",
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/express@4.21.0"
        }
      ],
      "checksums": [{ "algorithm": "SHA256", "checksumValue": "abc123..." }]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-express-4.21.0"
    }
  ]
}
```

### 2.3 SBOM Generation Tools

| Tool                 | Formats         | Languages             | Best For                  |
| -------------------- | --------------- | --------------------- | ------------------------- |
| cdxgen v10.4+        | CycloneDX       | 20+ ecosystems        | CI/CD, comprehensive      |
| syft v1.4+           | CycloneDX, SPDX | Container + code      | Container SBOM            |
| trivy v0.50+         | CycloneDX, SPDX | Multi-source          | All-in-one scanning       |
| CycloneDX CLI v0.27+ | CycloneDX       | Per-ecosystem plugins | Precise ecosystem support |
| SPDX Tools v0.8+     | SPDX            | Language-specific     | SPDX compliance           |

```bash
# Generate CycloneDX SBOM with cdxgen
cdxgen -o sbom.json --spec-version 1.6 -t node .

# Generate SPDX SBOM with syft
syft dir:. -o spdx-json=sbom-spdx.json

# Container SBOM with trivy
trivy image --format cyclonedx --output container-sbom.json myapp:latest

# Validate SBOM
cyclonedx validate --input-file sbom.json --input-version v1_6
```

---

## 3. License Compliance Matrix

## เมทริกซ์การปฏิบัติตามสัญญาอนุญาต

### 3.1 License Categories

```
PERMISSIVE (Low Risk — Generally Safe):
  MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense, CC0-1.0,
  Zlib, BSL-1.0, PostgreSQL, 0BSD

WEAK COPYLEFT (Medium Risk — Review Required):
  LGPL-2.1-only, LGPL-3.0-only, MPL-2.0, EPL-2.0, CDDL-1.0, CPL-1.0
  Note: Typically OK for dynamic linking, review for static linking

STRONG COPYLEFT (High Risk — Legal Review Required):
  GPL-2.0-only, GPL-3.0-only, AGPL-3.0-only, SSPL-1.0, EUPL-1.2
  Note: May require open-sourcing derivative works

COMMERCIAL / PROPRIETARY (Special Handling):
  Proprietary, Commercial, Custom license terms
  Note: Requires procurement/legal approval

NON-SOFTWARE / CREATIVE:
  CC-BY-4.0, CC-BY-SA-4.0, CC-BY-NC-4.0
  Note: May not be suitable for software distribution
```

### 3.2 License Compatibility Matrix

```
Your Project License → Can you use dependencies with these licenses?

                  MIT  Apache-2.0  LGPL-3.0  GPL-3.0  AGPL-3.0
MIT Project       Yes    Yes        Yes*      No**     No**
Apache-2.0 Proj   Yes    Yes        Yes*      No**     No**
LGPL-3.0 Project  Yes    Yes        Yes       Yes*     No**
GPL-3.0 Project   Yes    Yes        Yes       Yes      No**
AGPL-3.0 Project  Yes    Yes        Yes       Yes      Yes

* = With conditions (dynamic linking, file-level separation)
** = Would require relicensing your project
```

### 3.3 Automated License Policy

```yaml
# .licensefinder.yml or policy configuration
permitted_licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - Unlicense

restricted_licenses:
  - GPL-2.0-only
  - GPL-3.0-only
  - AGPL-3.0-only
  - SSPL-1.0

reviewed_packages:
  # Manually approved exceptions
  - name: "readline"
    license: "GPL-3.0"
    approval: "Used only in dev CLI, not distributed"
    approved_by: "legal-team"
    date: "2025-11-15"
```

---

## 4. Dependency Update Strategies

## กลยุทธ์การอัปเดต Dependency

### 4.1 Update Priority Matrix

| Update Type             | Urgency        | Strategy                          | Automation               |
| ----------------------- | -------------- | --------------------------------- | ------------------------ |
| Critical CVE (CVSS 9+)  | Immediate      | Hotfix branch, emergency PR       | Auto-merge if tests pass |
| High CVE (CVSS 7-8.9)   | Within 7 days  | Priority PR with changelog review | Auto-PR, manual merge    |
| Medium CVE (CVSS 4-6.9) | Within 30 days | Batch with other updates          | Weekly auto-PR           |
| Major version bump      | Planned sprint | Dedicated migration ticket        | Manual upgrade           |
| Minor/Patch (no CVE)    | Next cycle     | Batch monthly                     | Monthly auto-PR          |

### 4.2 Renovate Configuration

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    "security:openssf-scorecard",
    ":semanticCommits",
    ":dependencyDashboard"
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"],
    "automerge": true,
    "automergeType": "pr",
    "platformAutomerge": true
  },
  "packageRules": [
    {
      "description": "Auto-merge patch updates for production deps",
      "matchUpdateTypes": ["patch"],
      "matchDepTypes": ["dependencies"],
      "automerge": true,
      "automergeType": "pr",
      "minimumReleaseAge": "3 days"
    },
    {
      "description": "Group minor updates weekly",
      "matchUpdateTypes": ["minor"],
      "groupName": "minor-updates",
      "schedule": ["before 6am on Monday"]
    },
    {
      "description": "Major updates require manual review",
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "labels": ["breaking-change"],
      "prPriority": -1
    },
    {
      "description": "Pin GitHub Actions by SHA",
      "matchManagers": ["github-actions"],
      "pinDigests": true
    }
  ],
  "lockFileMaintenance": {
    "enabled": true,
    "schedule": ["before 6am on Monday"]
  }
}
```

### 4.3 Lock File Integrity

```bash
# Verify lock file integrity (detect supply chain tampering)

# npm — verify package-lock.json
npm ci --ignore-scripts  # Install from lock file only
npm audit signatures      # Verify registry signatures (npm v9+)

# pip — verify requirements with hashes
pip install --require-hashes -r requirements.txt

# Go — verify go.sum
go mod verify

# Generate hash-pinned requirements (Python)
pip-compile --generate-hashes requirements.in -o requirements.txt
```

---

## 5. Supply Chain Attack Patterns

## รูปแบบการโจมตี Supply Chain

### 5.1 Known Attack Vectors

```
TYPOSQUATTING:
  Technique: Register packages with names similar to popular ones
  Examples: "colourama" vs "colorama", "electorn" vs "electron"
  Detection: Levenshtein distance < 2 from popular package names
  Prevention: Pin exact versions, use lock files, verify publisher

DEPENDENCY CONFUSION:
  Technique: Publish malicious package to public registry matching
             internal/private package name with higher version
  Detection: Package exists in both public and private registries
  Prevention: Namespace scoping (@company/pkg), registry priority config

COMPROMISED MAINTAINER:
  Technique: Take over maintainer account via credential stuffing,
             phishing, or social engineering
  Examples: ua-parser-js (2021), event-stream (2018), colors.js (2022)
  Detection: Sudden code changes, new maintainer + immediate publish,
             obfuscated code in postinstall scripts
  Prevention: Audit new releases, pin versions, monitor for anomalies

MALICIOUS INSTALL SCRIPTS:
  Technique: Execute code during npm install / pip install via
             preinstall/postinstall hooks or setup.py
  Detection: Scan for network calls, file system writes, env var reads
             in install scripts
  Prevention: --ignore-scripts flag, sandbox installs, review scripts

BUILD SYSTEM COMPROMISE:
  Technique: Compromise CI/CD to inject malicious code during build
  Examples: SolarWinds (2020), Codecov (2021), 3CX (2023)
  Detection: SLSA provenance verification, reproducible builds
  Prevention: Hermetic builds, signed provenance, minimal CI permissions

STAR JACKING / REPO SUBSTITUTION:
  Technique: Create fake GitHub repo with transferred stars or
             point package metadata to a different repo
  Detection: Verify repo URL matches package registry metadata
  Prevention: Cross-reference package registry with VCS, check SLSA
```

### 5.2 Detection Rules for CI/CD

```yaml
# Supply chain checks to run on every dependency update

checks:
  - name: "New dependency audit"
    trigger: "lock file changed"
    actions:
      - verify_publisher_identity
      - check_package_age # Reject if < 7 days old
      - check_download_count # Flag if < 1000 weekly
      - scan_install_scripts
      - verify_provenance # SLSA attestation
      - check_typosquatting # Levenshtein distance

  - name: "Existing dependency update"
    trigger: "version changed in lock file"
    actions:
      - diff_package_contents # Compare old vs new
      - check_maintainer_change # Flag if maintainer changed
      - verify_signatures # npm audit signatures
      - scan_for_obfuscation # Detect minified/obfuscated code
```

---

## 6. Vulnerability Database Sources

## แหล่งข้อมูลฐานข้อมูลช่องโหว่

### Primary Sources

| Source                 | Coverage              | Format          | Update Frequency |
| ---------------------- | --------------------- | --------------- | ---------------- |
| OSV.dev                | All ecosystems        | OSV Schema v1.5 | Real-time        |
| GitHub Advisory (GHSA) | All GitHub ecosystems | OSV-compatible  | Real-time        |
| NVD (NIST)             | CVE database          | NVD JSON        | Daily            |
| npm Audit              | npm packages          | Proprietary     | Real-time        |
| PyPI Advisory          | Python packages       | OSV Schema      | Real-time        |
| RustSec Advisory       | Rust crates           | OSV-compatible  | Community-driven |
| Go Vulnerability DB    | Go modules            | OSV Schema      | Real-time        |

### Querying OSV API

```bash
# Query OSV for vulnerabilities in a specific package
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "package": {
      "name": "express",
      "ecosystem": "npm"
    },
    "version": "4.17.1"
  }'

# Batch query from SBOM
osv-scanner --sbom=sbom.json --format=json --output=vuln-report.json
```

---

## 7. SLSA Framework (Supply Chain Levels for Software Artifacts)

## กรอบ SLSA สำหรับความปลอดภัย Supply Chain

### SLSA Levels (v1.0)

```
SLSA Build Level 0: No guarantees
  - No provenance, no build integrity

SLSA Build Level 1: Provenance exists
  - Build process documented
  - Provenance generated automatically
  - Format: in-toto / SLSA provenance v1

SLSA Build Level 2: Hosted build platform
  - Build on hosted, managed service
  - Provenance signed by build service
  - Tamper-resistant provenance generation

SLSA Build Level 3: Hardened builds
  - Isolated, ephemeral build environment
  - Hermetic builds (no network during build)
  - Non-falsifiable provenance
  - Two-person review for build configuration
```

### Provenance Verification

```bash
# Verify SLSA provenance for container images
slsa-verifier verify-image \
  --source-uri github.com/my-org/my-app \
  --source-tag v2.1.0 \
  myregistry.io/my-app:v2.1.0

# Verify npm package provenance (npm v9.5+)
npm audit signatures

# Verify Sigstore-signed artifacts
cosign verify-blob \
  --certificate-identity user@example.com \
  --certificate-oidc-issuer https://accounts.google.com \
  --signature artifact.sig \
  artifact.tar.gz
```

---

## 8. SCA Tool Comparison

## การเปรียบเทียบเครื่องมือ SCA

| Tool              | SBOM Gen | Vuln Scan | License | SLSA | Ecosystems   |
| ----------------- | -------- | --------- | ------- | ---- | ------------ |
| Trivy v0.50+      | Yes      | Yes       | Yes     | No   | 15+          |
| Grype v0.74+      | No       | Yes       | No      | No   | 15+          |
| osv-scanner v1.6+ | No       | Yes       | No      | No   | 18+          |
| cdxgen v10.4+     | Yes      | Via SBOM  | Yes     | No   | 20+          |
| Snyk v1.1200+     | Yes      | Yes       | Yes     | No   | 20+          |
| FOSSA v3+         | Yes      | Yes       | Yes     | No   | 25+          |
| Dependabot        | No       | Yes       | No      | No   | 15+          |
| Renovate v37+     | No       | Yes       | No      | No   | 60+ managers |

### Recommended Multi-Tool Strategy

```
Phase 1 (PR Gate): osv-scanner + license check → block on CRITICAL
Phase 2 (Build): cdxgen SBOM generation → attach to release
Phase 3 (Registry): trivy image scan → block deployment on HIGH+
Phase 4 (Runtime): Continuous monitoring via OSV.dev / Snyk Monitor
```
