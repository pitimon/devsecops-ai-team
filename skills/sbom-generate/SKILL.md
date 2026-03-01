---
name: sbom-generate
description: Generate Software Bill of Materials using Syft. Produces CycloneDX or SPDX format SBOMs for compliance and supply chain visibility.
argument-hint: "[--format cyclonedx-json|spdx-json] [--image <name:tag>]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# SBOM Generate (Syft)

Generate a Software Bill of Materials for the project using Syft.

**Decision Loop**: Out-of-Loop (AI autonomous — safe read-only operation)

## Generation Process

### 1. Detect Target

- If `--image` provided, scan that container image
- Otherwise scan the project directory
- Default format: CycloneDX JSON

### 2. Run Syft

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool syft \
  --target /workspace \
  --format cyclonedx-json
```

### 3. Present Results

```markdown
## รายการ SBOM (Software Bill of Materials)

### สรุป (Summary)

- Tool: Syft
- Format: CycloneDX v1.6
- Components: X total
- Licenses: Y unique

### Component Summary

| Type   | Count | Examples               |
| ------ | ----- | ---------------------- |
| npm    | 150   | express, react, lodash |
| pip    | 30    | django, requests       |
| os-pkg | 45    | openssl, zlib          |

### License Distribution

| License    | Count | Risk            |
| ---------- | ----- | --------------- |
| MIT        | 100   | Low             |
| Apache-2.0 | 30    | Low             |
| GPL-3.0    | 5     | High (copyleft) |
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/sca-supply-chain.md` for SBOM analysis context.
