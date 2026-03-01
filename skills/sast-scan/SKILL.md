---
name: sast-scan
description: Run Static Application Security Testing using Semgrep in a Docker container. Identifies code vulnerabilities, injection flaws, and security anti-patterns.
argument-hint: "[--rules <ruleset>] [--target <path>]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Grep", "Bash"]
---

# SAST Scan (Semgrep)

Run static application security testing on the project using Semgrep.

**Decision Loop**: Out-of-Loop (AI autonomous — lint-level SAST)

## Scan Process

### 1. Detect Language and Select Rules

Scan the project to determine languages and select appropriate rule packs:

| Language              | Default Rules                                 |
| --------------------- | --------------------------------------------- |
| Python                | p/python, p/django, p/flask                   |
| JavaScript/TypeScript | p/javascript, p/typescript, p/react, p/nextjs |
| Go                    | p/golang                                      |
| Java                  | p/java                                        |
| All                   | p/security-audit, p/owasp-top-ten             |

If `--rules` argument provided, use that instead of auto-detection.

### 2. Run Semgrep

Execute the scan via the job dispatcher:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool semgrep \
  --target /workspace \
  --rules "p/security-audit p/owasp-top-ten" \
  --format json
```

### 3. Collect and Normalize Results

```bash
bash ${CLAUDE_PLUGIN_ROOT}/runner/result-collector.sh \
  --job-id <JOB_ID> \
  --format json
```

### 4. Triage Findings

For each finding:

- Map Semgrep rule ID to CWE
- Determine severity based on rule metadata
- Check if finding is in test/fixture files (lower confidence)
- Deduplicate by (rule_id, file, line)

### 5. Present Findings

````markdown
## ผลการสแกน SAST (SAST Scan Results)

### สรุป (Summary)

- Tool: Semgrep
- Rules: p/security-audit, p/owasp-top-ten
- Files scanned: X
- Findings: Y total (by severity: CRITICAL: a, HIGH: b, MEDIUM: c, LOW: d)

### ผลการตรวจพบ (Findings)

#### CRITICAL

**SQL Injection (CWE-89)**

- File: `src/api/users.ts:45`
- Rule: `python.lang.security.audit.formatted-sql-query`
- OWASP: A03:2021 — Injection

```python
# Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# Fix
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```
````

#### HIGH

...

### Compliance Mapping

| CWE    | OWASP Top 10 | NIST 800-53 | Count |
| ------ | ------------ | ----------- | ----- |
| CWE-89 | A03:2021     | SI-10       | 2     |
| CWE-79 | A03:2021     | SI-10       | 1     |

### คำแนะนำถัดไป (Next Steps)

1. Fix CRITICAL findings first
2. Run `/security-gate` to check deployment readiness
3. Use `/remediation-advisor` for fix guidance

```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/sast-patterns.md` for deep analysis context.
```
