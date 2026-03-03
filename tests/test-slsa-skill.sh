#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — SLSA Skill Tests
# Tests SLSA assessment skill structure, reference file, and integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — SLSA Skill Tests"
echo "============================================"
echo ""

# ─── Section 1: Skill File ───
echo "--- Section 1: Skill File ---"

SKILL_FILE="$ROOT_DIR/skills/slsa-assess/SKILL.md"

[ -f "$SKILL_FILE" ] \
  && pass "SKILL.md exists" \
  || fail "SKILL.md missing"

grep -q "^name: slsa-assess" "$SKILL_FILE" \
  && pass "name: slsa-assess in frontmatter" \
  || fail "name: slsa-assess not found in frontmatter"

grep -q "^user-invocable: true" "$SKILL_FILE" \
  && pass "user-invocable: true" \
  || fail "user-invocable not set to true"

grep -q "^allowed-tools:" "$SKILL_FILE" \
  && pass "allowed-tools declared" \
  || fail "allowed-tools missing"

# ─── Section 2: Reference File ───
echo ""
echo "--- Section 2: Reference File ---"

REF_FILE="$ROOT_DIR/skills/references/slsa-reference.md"

[ -f "$REF_FILE" ] \
  && pass "slsa-reference.md exists" \
  || fail "slsa-reference.md missing"

grep -q "Level 0\|Level 1\|Level 2\|Level 3\|SLSA 0\|SLSA Levels\|0-3" "$REF_FILE" \
  && pass "reference covers SLSA levels 0-3" \
  || fail "reference missing SLSA level coverage"

grep -q "EU CRA\|EU Cyber Resilience Act\|2024/2847" "$REF_FILE" \
  && pass "reference mentions EU CRA" \
  || fail "reference missing EU CRA mention"

grep -qi "syft\|anchore/syft" "$REF_FILE" \
  && pass "reference mentions Syft" \
  || fail "reference missing Syft mention"

# ─── Section 3: Skill Content ───
echo ""
echo "--- Section 3: Skill Content ---"

grep -q "On-the-Loop" "$SKILL_FILE" \
  && pass "skill mentions On-the-Loop decision loop" \
  || fail "skill missing On-the-Loop decision loop"

grep -q "slsa-reference.md" "$SKILL_FILE" \
  && pass "skill references slsa-reference.md" \
  || fail "skill does not reference slsa-reference.md"

grep -q "SLSA Provenance Assessment\|Output\|รายงาน\|template" "$SKILL_FILE" \
  && pass "skill has output template" \
  || fail "skill missing output template"

grep -qi "gap analysis\|gap" "$SKILL_FILE" \
  && pass "skill mentions gap analysis" \
  || fail "skill missing gap analysis"

# ─── Section 4: Integration ───
echo ""
echo "--- Section 4: Integration ---"

[ -d "$ROOT_DIR/skills/slsa-assess" ] \
  && pass "slsa-assess directory exists in skills/" \
  || fail "slsa-assess directory missing from skills/"

grep -q "slsa-assess" "$ROOT_DIR/tests/validate-plugin.sh" \
  && pass "validate-plugin.sh includes slsa-assess" \
  || fail "validate-plugin.sh missing slsa-assess"

grep -q "slsa-reference.md" "$ROOT_DIR/tests/validate-plugin.sh" \
  && pass "validate-plugin.sh includes slsa-reference.md" \
  || fail "validate-plugin.sh missing slsa-reference.md"

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Results: $PASS passed / $FAIL failed (total $TOTAL checks)"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "STATUS: FAILED"
  exit 1
else
  echo "STATUS: PASSED"
  exit 0
fi
