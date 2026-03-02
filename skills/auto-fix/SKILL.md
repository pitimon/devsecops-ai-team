---
name: auto-fix
description: Automatically apply security fixes from scan results. Reads findings, generates patches, presents for approval, applies edits, and re-scans to verify.
argument-hint: "[--dry-run] [--severity critical|high] [--file <path>] [--cwe <id>]"
user-invocable: true
allowed-tools: ["Read", "Edit", "Glob", "Grep", "Bash"]
---

# Auto-Fix Security Findings

Automatically apply security fixes from scan results. Reads vulnerability findings, generates code patches, presents them for human approval, applies edits, and re-scans to verify the fixes.

**Decision Loop**: On-the-Loop (AI proposes fix plan, human reviews and approves before applying changes)

## Agent Delegation

This skill delegates to `@agent-remediation-advisor` for fix generation and application.

## Auto-Fix Process

### 1. Load Scan Results

Read the latest scan results from the results directory:

```bash
# Look for merged findings first, then individual normalized files
RESULTS_DIR="${CLAUDE_PLUGIN_ROOT}/runner/results"

# Preferred: merged/deduped findings
if [ -f "$RESULTS_DIR/merged-findings.json" ]; then
  cat "$RESULTS_DIR/merged-findings.json"
fi

# Fallback: individual normalized results
ls "$RESULTS_DIR"/normalized-*.json 2>/dev/null
```

If no scan results exist, prompt the user to run `/full-pipeline` or a specific scan first.

### 2. Filter Findings

Apply scope filters based on arguments:

| Flag         | Effect                                      | Default           |
| ------------ | ------------------------------------------- | ----------------- |
| `--severity` | Only fix findings at this severity or above | CRITICAL and HIGH |
| `--file`     | Only fix findings in this file/directory    | All files         |
| `--cwe`      | Only fix findings matching this CWE ID      | All CWEs          |
| `--dry-run`  | Show proposed fixes without applying        | Off (apply)       |

Sort filtered findings by: severity (CRITICAL first) → effort (Trivial first) → file path.

### 3. Detect Framework

Check project files to identify the primary framework and load appropriate remediation patterns:

| Detection File                                            | Framework Match   | Reference File                |
| --------------------------------------------------------- | ----------------- | ----------------------------- |
| `requirements.txt` / `pyproject.toml` containing `django` | Django            | `remediation-django.md`       |
| `package.json` containing `next` or `react`               | React / Next.js   | `remediation-react-nextjs.md` |
| `package.json` containing `express`                       | Express / Node.js | `remediation-express-node.md` |
| `pom.xml` / `build.gradle` containing `spring`            | Spring            | `remediation-spring.md`       |

**Always** load `${CLAUDE_PLUGIN_ROOT}/skills/references/remediation-patterns.md` as the base reference.

### 4. Generate Fix Plan

For each finding, generate a concrete fix with:

- **Before** code (vulnerable)
- **After** code (fixed)
- **Effort** estimate (Trivial / Small / Medium / Large)
- **Breaking changes** assessment (None / Minor / Major)
- **Risk** level of the fix itself (Low / Medium / High)

Categorize fixes by effort:

| Effort  | Auto-fixable? | Examples                                        |
| ------- | ------------- | ----------------------------------------------- |
| Trivial | Yes           | Config change, dependency bump, one-line fix    |
| Small   | Yes           | Add validation, add header, parameterize query  |
| Medium  | With caution  | Refactor module, add middleware, schema change  |
| Large   | No — manual   | Cross-cutting change, replace library, redesign |

### 5. Present Fix Plan (On-the-Loop Checkpoint)

**STOP and present the plan to the user before applying any changes.**

```markdown
## แผนการแก้ไขอัตโนมัติ (Auto-Fix Plan)

### สรุป (Summary)

- Findings to fix: X
- Auto-fixable (Trivial/Small): Y
- Needs review (Medium): Z
- Manual only (Large): W
- Estimated effort: N hours

### รายการแก้ไข (Fix Items)

| #   | Severity | CWE     | File:Line       | Fix Type   | Effort  | Breaking | Risk |
| --- | -------- | ------- | --------------- | ---------- | ------- | -------- | ---- |
| 1   | CRITICAL | CWE-89  | src/db.ts:45    | Code patch | Trivial | None     | Low  |
| 2   | HIGH     | CWE-79  | src/views.ts:12 | Code patch | Small   | None     | Low  |
| 3   | HIGH     | CWE-327 | src/auth.ts:78  | Upgrade    | Medium  | Minor    | Med  |

### ดำเนินการต่อ? (Proceed?)

- ✅ Apply all Trivial/Small fixes
- ⚠️ Review Medium fixes individually
- ❌ Skip Large fixes (manual remediation needed)
```

Wait for user approval before proceeding.

### 6. Apply Fixes

For each approved fix:

1. **Read** the target file to confirm current state matches expected "before" code
2. **Edit** the file with the fix — use the Edit tool for precise patching
3. **Log** the change: file, line, CWE, before/after summary

If `--dry-run` is active, show the Edit commands that would be executed but do NOT apply them.

**Rollback safety**: All changes can be reverted via `git checkout -- <file>` or `git stash`. Remind the user of this after applying fixes.

```bash
# After all fixes applied, show rollback command
echo "Rollback: git checkout -- <modified-files>"
```

### 7. Re-Scan Changed Files

After applying fixes, re-run the relevant scanner on changed files to verify:

```bash
# Determine which tool originally found the issues
# Re-scan only the modified files
bash ${CLAUDE_PLUGIN_ROOT}/runner/job-dispatcher.sh \
  --tool <original-tool> \
  --target /workspace \
  --format json

# Normalize and check
bash ${CLAUDE_PLUGIN_ROOT}/runner/result-collector.sh \
  --job-id <JOB_ID> \
  --format json
```

Compare re-scan results:

- Fixed findings should no longer appear
- No new findings should be introduced
- If new findings appear, flag them immediately

### 8. Summary Report

```markdown
## ผลการแก้ไขอัตโนมัติ (Auto-Fix Results)

### สรุป (Summary)

- Fixes applied: X / Y proposed
- Fixes verified (re-scan clean): X
- New issues introduced: 0
- Remaining findings: Z

### รายละเอียด (Details)

| #   | CWE     | File            | Status     | Verified |
| --- | ------- | --------------- | ---------- | -------- |
| 1   | CWE-89  | src/db.ts:45    | ✅ Fixed   | ✅ Clean |
| 2   | CWE-79  | src/views.ts:12 | ✅ Fixed   | ✅ Clean |
| 3   | CWE-327 | src/auth.ts:78  | ⏭️ Skipped | —        |

### คำแนะนำถัดไป (Next Steps)

1. Review remaining Z findings manually
2. Run `/security-gate` to check deployment readiness
3. Commit fixes: `git add -A && git commit -m "fix: apply auto-fix for X security findings"`

### Rollback

git checkout -- src/db.ts src/views.ts
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/remediation-patterns.md` for fix pattern reference.
