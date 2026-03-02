#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Auto-Fix Skill Tests
# Tests SKILL.md structure, agent configuration, and integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Auto-Fix Skill Tests"
echo "============================================"
echo ""

# ═══════════════════════════════════════════
# Section 1: SKILL.md Structure
# ═══════════════════════════════════════════
echo "--- Section 1: SKILL.md Structure ---"

SKILL_FILE="$ROOT_DIR/skills/auto-fix/SKILL.md"

[ -d "$ROOT_DIR/skills/auto-fix" ] && pass "auto-fix skill directory exists" || fail "auto-fix skill directory missing"
[ -f "$SKILL_FILE" ] && pass "SKILL.md exists" || fail "SKILL.md missing"

# Frontmatter checks
grep -q '^name: auto-fix' "$SKILL_FILE" && pass "frontmatter: name is auto-fix" || fail "frontmatter: name should be auto-fix"
grep -q '^description:' "$SKILL_FILE" && pass "frontmatter: description present" || fail "frontmatter: description missing"
grep -q '^argument-hint:' "$SKILL_FILE" && pass "frontmatter: argument-hint present" || fail "frontmatter: argument-hint missing"
grep -q '^user-invocable: true' "$SKILL_FILE" && pass "frontmatter: user-invocable is true" || fail "frontmatter: user-invocable should be true"
grep -q '^allowed-tools:' "$SKILL_FILE" && pass "frontmatter: allowed-tools present" || fail "frontmatter: allowed-tools missing"

# allowed-tools must include Edit (the key differentiator)
grep 'allowed-tools:' "$SKILL_FILE" | grep -q '"Edit"' && pass "allowed-tools includes Edit" || fail "allowed-tools must include Edit for auto-fix"
grep 'allowed-tools:' "$SKILL_FILE" | grep -q '"Read"' && pass "allowed-tools includes Read" || fail "allowed-tools must include Read"
grep 'allowed-tools:' "$SKILL_FILE" | grep -q '"Bash"' && pass "allowed-tools includes Bash" || fail "allowed-tools must include Bash"

# Decision Loop
grep -q 'On-the-Loop' "$SKILL_FILE" && pass "Decision Loop: On-the-Loop declared" || fail "Decision Loop must be On-the-Loop"

# ═══════════════════════════════════════════
# Section 2: Process Steps
# ═══════════════════════════════════════════
echo ""
echo "--- Section 2: Process Steps ---"

grep -q 'Load Scan Results' "$SKILL_FILE" && pass "step 1: Load Scan Results" || fail "step 1: Load Scan Results missing"
grep -q 'Filter Findings' "$SKILL_FILE" && pass "step 2: Filter Findings" || fail "step 2: Filter Findings missing"
grep -q 'Detect Framework' "$SKILL_FILE" && pass "step 3: Detect Framework" || fail "step 3: Detect Framework missing"
grep -q 'Generate Fix Plan' "$SKILL_FILE" && pass "step 4: Generate Fix Plan" || fail "step 4: Generate Fix Plan missing"
grep -q 'Present Fix Plan' "$SKILL_FILE" && pass "step 5: Present Fix Plan" || fail "step 5: Present Fix Plan missing"
grep -q 'Apply Fixes' "$SKILL_FILE" && pass "step 6: Apply Fixes" || fail "step 6: Apply Fixes missing"
grep -q 'Re-Scan' "$SKILL_FILE" && pass "step 7: Re-Scan" || fail "step 7: Re-Scan missing"
grep -q 'Summary Report' "$SKILL_FILE" && pass "step 8: Summary Report" || fail "step 8: Summary Report missing"

# ═══════════════════════════════════════════
# Section 3: Arguments
# ═══════════════════════════════════════════
echo ""
echo "--- Section 3: Arguments ---"

grep -q '\-\-dry-run' "$SKILL_FILE" && pass "argument: --dry-run supported" || fail "argument: --dry-run missing"
grep -q '\-\-severity' "$SKILL_FILE" && pass "argument: --severity supported" || fail "argument: --severity missing"
grep -q '\-\-file' "$SKILL_FILE" && pass "argument: --file supported" || fail "argument: --file missing"
grep -q '\-\-cwe' "$SKILL_FILE" && pass "argument: --cwe supported" || fail "argument: --cwe missing"

# ═══════════════════════════════════════════
# Section 4: Agent Configuration
# ═══════════════════════════════════════════
echo ""
echo "--- Section 4: Agent Configuration ---"

ADVISOR_FILE="$ROOT_DIR/agents/experts/remediation-advisor.md"

[ -f "$ADVISOR_FILE" ] && pass "remediation-advisor.md exists" || fail "remediation-advisor.md missing"

# remediation-advisor must have Edit tool for auto-fix
grep 'tools:' "$ADVISOR_FILE" | grep -q '"Edit"' && pass "remediation-advisor has Edit tool" || fail "remediation-advisor must have Edit tool for auto-fix"

# remediation-advisor must have Apply Fixes section
grep -q 'Apply Fixes' "$ADVISOR_FILE" && pass "remediation-advisor has Apply Fixes section" || fail "remediation-advisor should have Apply Fixes section"

# ═══════════════════════════════════════════
# Section 5: Orchestrator Routing
# ═══════════════════════════════════════════
echo ""
echo "--- Section 5: Orchestrator Routing ---"

LEAD_FILE="$ROOT_DIR/agents/orchestrators/devsecops-lead.md"

[ -f "$LEAD_FILE" ] && pass "devsecops-lead.md exists" || fail "devsecops-lead.md missing"

grep -q 'Auto-fix' "$LEAD_FILE" && pass "devsecops-lead routes auto-fix requests" || fail "devsecops-lead should route auto-fix requests"
grep -q '/auto-fix' "$LEAD_FILE" && pass "devsecops-lead has /auto-fix delegation" || fail "devsecops-lead should have /auto-fix delegation"

# ═══════════════════════════════════════════
# Section 6: Bilingual Output
# ═══════════════════════════════════════════
echo ""
echo "--- Section 6: Bilingual Output ---"

grep -q 'แผนการแก้ไข' "$SKILL_FILE" && pass "bilingual: Thai fix plan header" || fail "bilingual: Thai fix plan header missing"
grep -q 'ผลการแก้ไข' "$SKILL_FILE" && pass "bilingual: Thai results header" || fail "bilingual: Thai results header missing"
grep -q 'คำแนะนำถัดไป' "$SKILL_FILE" && pass "bilingual: Thai next steps header" || fail "bilingual: Thai next steps header missing"

# ═══════════════════════════════════════════
# Section 7: Integration
# ═══════════════════════════════════════════
echo ""
echo "--- Section 7: Integration ---"

# Skill references job-dispatcher and result-collector
grep -q 'job-dispatcher' "$SKILL_FILE" && pass "references job-dispatcher.sh" || fail "should reference job-dispatcher.sh for re-scan"
grep -q 'result-collector' "$SKILL_FILE" && pass "references result-collector.sh" || fail "should reference result-collector.sh for normalization"
grep -q 'remediation-patterns.md' "$SKILL_FILE" && pass "references remediation-patterns.md" || fail "should reference remediation-patterns.md"
grep -q '@agent-remediation-advisor' "$SKILL_FILE" && pass "delegates to remediation-advisor" || fail "should delegate to @agent-remediation-advisor"

# Rollback safety
grep -q 'git checkout' "$SKILL_FILE" && pass "rollback command documented" || fail "rollback command should be documented"

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Auto-Fix Skill Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL tests failed"
  exit 1
else
  echo "ALL TESTS PASSED"
fi
