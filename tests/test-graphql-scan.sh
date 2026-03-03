#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — GraphQL Scan Tests
# Tests skill definition, reference file, Semgrep rules, Nuclei templates,
# job dispatcher integration, and fixture validation (23 tests)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "================================================="
echo "DevSecOps AI Team — GraphQL Scan Tests"
echo "================================================="
echo ""

SKILL="$ROOT_DIR/skills/graphql-scan/SKILL.md"
REFERENCE="$ROOT_DIR/skills/references/graphql-security-reference.md"
RULES="$ROOT_DIR/rules/graphql-rules.yml"
TEMPLATES_DIR="$ROOT_DIR/runner/nuclei-templates/graphql"
DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-graphql-findings.json"

# ═══════════════════════════════════════════
# Section 1: Skill Definition (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Skill Definition ---"

[ -f "$SKILL" ] \
  && pass "skills/graphql-scan/SKILL.md exists" \
  || fail "skills/graphql-scan/SKILL.md missing"

grep -qi "graphql\|gql\|introspection" "$SKILL" \
  && pass "SKILL.md has trigger keywords (graphql/gql/introspection)" \
  || fail "SKILL.md missing trigger keywords"

grep -q "In-the-Loop\|On-the-Loop" "$SKILL" \
  && pass "SKILL.md has decision loop classification" \
  || fail "SKILL.md missing decision loop classification"

grep -q "allowed-tools\|Bash" "$SKILL" \
  && pass "SKILL.md has allowed-tools" \
  || fail "SKILL.md missing allowed-tools"

echo ""

# ═══════════════════════════════════════════
# Section 2: Reference File (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Reference File ---"

[ -f "$REFERENCE" ] \
  && pass "skills/references/graphql-security-reference.md exists" \
  || fail "skills/references/graphql-security-reference.md missing"

grep -q "OWASP" "$REFERENCE" \
  && pass "Reference mentions OWASP" \
  || fail "Reference does not mention OWASP"

grep -qi "introspection" "$REFERENCE" \
  && pass "Reference mentions introspection attack" \
  || fail "Reference does not mention introspection"

grep -qi "depth" "$REFERENCE" \
  && pass "Reference mentions depth" \
  || fail "Reference does not mention depth"

echo ""

# ═══════════════════════════════════════════
# Section 3: Semgrep Rules (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Semgrep Rules ---"

[ -f "$RULES" ] \
  && pass "rules/graphql-rules.yml exists" \
  || fail "rules/graphql-rules.yml missing"

RULE_COUNT=$(grep -c "id: gql-" "$RULES" 2>/dev/null || echo "0")
[ "$RULE_COUNT" -eq 8 ] \
  && pass "Has 8 rules (got $RULE_COUNT)" \
  || fail "Expected 8 rules, got $RULE_COUNT"

grep -q "gql-introspection-enabled" "$RULES" \
  && pass "Has gql-introspection-enabled rule" \
  || fail "Missing gql-introspection-enabled rule"

grep -q "gql-sql-in-resolver" "$RULES" \
  && pass "Has gql-sql-in-resolver rule" \
  || fail "Missing gql-sql-in-resolver rule"

echo ""

# ═══════════════════════════════════════════
# Section 4: Nuclei Templates (5 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Nuclei Templates ---"

[ -d "$TEMPLATES_DIR" ] \
  && pass "runner/nuclei-templates/graphql/ directory exists" \
  || fail "runner/nuclei-templates/graphql/ directory missing"

[ -f "$TEMPLATES_DIR/graphql-introspection.yaml" ] \
  && pass "graphql-introspection.yaml exists" \
  || fail "graphql-introspection.yaml missing"

[ -f "$TEMPLATES_DIR/graphql-batch-query.yaml" ] \
  && pass "graphql-batch-query.yaml exists" \
  || fail "graphql-batch-query.yaml missing"

[ -f "$TEMPLATES_DIR/graphql-depth-attack.yaml" ] \
  && pass "graphql-depth-attack.yaml exists" \
  || fail "graphql-depth-attack.yaml missing"

# Validate all 4 templates are valid YAML
YAML_PASS=true
for tpl in graphql-introspection.yaml graphql-field-suggestion.yaml graphql-batch-query.yaml graphql-depth-attack.yaml; do
  if [ -f "$TEMPLATES_DIR/$tpl" ]; then
    if ! python3 -c "import yaml; yaml.safe_load(open('$TEMPLATES_DIR/$tpl'))" 2>/dev/null; then
      YAML_PASS=false
      break
    fi
  else
    YAML_PASS=false
    break
  fi
done
$YAML_PASS \
  && pass "All 4 templates are valid YAML" \
  || fail "One or more templates are invalid YAML"

echo ""

# ═══════════════════════════════════════════
# Section 5: Job Dispatcher (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: Job Dispatcher ---"

grep -q "run_graphql_scan" "$DISPATCHER" \
  && pass "run_graphql_scan function exists in job-dispatcher.sh" \
  || fail "run_graphql_scan function missing from job-dispatcher.sh"

grep -q "run_graphql_static" "$DISPATCHER" \
  && pass "run_graphql_static function exists in job-dispatcher.sh" \
  || fail "run_graphql_static function missing from job-dispatcher.sh"

grep -q "run_graphql_live" "$DISPATCHER" \
  && pass "run_graphql_live function exists in job-dispatcher.sh" \
  || fail "run_graphql_live function missing from job-dispatcher.sh"

grep -q "graphql.*run_graphql\|graphql-scan" "$DISPATCHER" \
  && pass "graphql registered in run_tool case statement" \
  || fail "graphql missing from run_tool case statement"

echo ""

# ═══════════════════════════════════════════
# Section 6: Fixture Validation (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 6: Fixture Validation ---"

[ -f "$FIXTURE" ] \
  && pass "sample-graphql-findings.json exists" \
  || fail "sample-graphql-findings.json missing"

python3 -c "
import json, sys
with open('$FIXTURE') as f:
    data = json.load(f)
if 'findings' not in data or not isinstance(data['findings'], list):
    print('Missing or invalid findings array', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" 2>/dev/null \
  && pass "Fixture is valid JSON with findings array" \
  || fail "Fixture is not valid JSON or missing findings array"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "================================================="
TOTAL=$((PASS + FAIL))
echo "GraphQL Scan Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
