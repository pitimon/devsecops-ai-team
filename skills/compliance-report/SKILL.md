---
name: compliance-report
description: Generate compliance mapping report for scan findings. Maps vulnerabilities to NIST 800-53, OWASP Top 10, MITRE ATT&CK, and CIS Benchmarks.
argument-hint: "[--framework all|nist|owasp|mitre|cis]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# Compliance Report

Generate a compliance mapping report from scan findings.

**Decision Loop**: On-the-Loop (AI generates report, human reviews)

## Report Process

### 1. Load Scan Results

Find latest normalized scan results from all tools.

### 2. Apply Compliance Mappings

For each finding with a CWE ID:

- Map to OWASP Top 10 using `${CLAUDE_PLUGIN_ROOT}/mappings/cwe-to-owasp.json`
- Map to NIST 800-53 using `${CLAUDE_PLUGIN_ROOT}/mappings/cwe-to-nist.json`
- Map to MITRE ATT&CK using `${CLAUDE_PLUGIN_ROOT}/mappings/cwe-to-mitre.json`

### 3. Generate Gap Analysis

Identify which framework controls have findings vs. which are clean.

### 4. Present Report

```markdown
## รายงานการปฏิบัติตามกรอบมาตรฐาน (Compliance Report)

### OWASP Top 10 2021 Coverage

| Category                        | Findings | Status          |
| ------------------------------- | -------- | --------------- |
| A01:2021 Broken Access Control  | 3        | Needs attention |
| A02:2021 Cryptographic Failures | 0        | Clean           |
| A03:2021 Injection              | 2        | Needs attention |
| ...                             |          |                 |

### NIST 800-53 Control Mapping

| Control Family        | Controls Tested | Findings | Status     |
| --------------------- | --------------- | -------- | ---------- |
| AC (Access Control)   | AC-3, AC-6      | 2        | Partial    |
| SI (System Integrity) | SI-10           | 3        | Needs work |
| SC (Comm Protection)  | SC-8, SC-28     | 0        | Clean      |

### Gap Analysis

Areas with no scan coverage that may need manual review:

- AU (Audit and Accountability) — no audit log checks
- PE (Physical) — out of scope for automated scanning
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/compliance-frameworks.md` for framework details.
