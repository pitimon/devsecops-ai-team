---
name: security-gate
description: Evaluate scan results against severity policy and make pass/fail deployment decision. Reads latest scan results and compares against role-based thresholds.
argument-hint: "[--policy default|strict] [--role developer|security-lead|release-manager]"
user-invocable: true
allowed-tools: ["Read", "Glob", "Bash"]
---

# Security Gate

Evaluate scan results and make a pass/fail deployment decision.

**Decision Loop**: On-the-Loop (gate decision), In-the-Loop (override)

## Gate Process

### 1. Load Policy

Read policy from `--policy` argument or `.devsecops.yml`. Load role-based thresholds from `${CLAUDE_PLUGIN_ROOT}/mappings/severity-policy.json`.

### 2. Gather Latest Scan Results

Find the most recent scan results in `.devsecops/results/` or `/results/`. Check that results are not stale (within `max_age_hours`).

### 3. Evaluate Against Policy

For each finding:

- Check if severity >= threshold for the active role
- Check if finding is suppressed (only if role allows suppression)
- Count violations

### 4. Make Decision

```
IF any_finding.severity in policy.fail_on AND finding.status == "open":
  decision = FAIL
ELIF missing_required_scan_types:
  decision = FAIL (incomplete coverage)
ELIF results_age > max_age_hours:
  decision = FAIL (stale results)
ELSE:
  decision = PASS
```

### 5. Present Gate Result

```markdown
## Security Gate Result

### Decision: PASS / FAIL

| Check                   | Status | Details                         |
| ----------------------- | ------ | ------------------------------- |
| CRITICAL findings       | PASS   | 0 open                          |
| HIGH findings           | PASS   | 2 open (below threshold)        |
| Required scans complete | PASS   | sast, secret (2/2)              |
| Results freshness       | PASS   | 2 hours old (max 48)            |
| SBOM generated          | N/A    | Not required for developer role |

### Policy Applied

- Role: developer
- Fail on: CRITICAL
- Required scans: sast, secret

### Recommendation

Ready for deployment to staging environment.
```
