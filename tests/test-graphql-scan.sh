#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — GraphQL Scan Tests
# Tests skill definition, reference file, Semgrep rules, Nuclei templates,
# job dispatcher integration, fixture validation, normalizer integration,
# fixture field validation, and rules metadata validation (34 tests)

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
NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
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
# Section 7: Normalizer Integration (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 7: Normalizer Integration ---"

TMPDIR_TEST=$(mktemp -d)
trap "rm -rf $TMPDIR_TEST" EXIT

# Create raw semgrep-format fixture in temp dir
cat > "$TMPDIR_TEST/raw-semgrep-graphql.json" << 'RAWEOF'
{
  "results": [
    {
      "check_id": "gql-introspection-enabled",
      "path": "src/schema.py",
      "start": {"line": 15, "col": 1},
      "end": {"line": 15, "col": 30},
      "extra": {
        "severity": "WARNING",
        "message": "GraphQL introspection is enabled",
        "lines": "introspection: True",
        "metadata": {
          "cwe": ["CWE-200"],
          "confidence": "HIGH"
        }
      }
    },
    {
      "check_id": "gql-sql-in-resolver",
      "path": "src/resolvers/userResolver.js",
      "start": {"line": 42, "col": 5},
      "end": {"line": 44, "col": 10},
      "extra": {
        "severity": "ERROR",
        "message": "SQL query built with template literal inside GraphQL resolver",
        "lines": "db.query(`SELECT * FROM users WHERE id = ${args.id}`)",
        "metadata": {
          "cwe": ["CWE-89"],
          "confidence": "HIGH"
        }
      }
    },
    {
      "check_id": "gql-no-depth-limit",
      "path": "src/server.js",
      "start": {"line": 8, "col": 1},
      "end": {"line": 12, "col": 3},
      "extra": {
        "severity": "WARNING",
        "message": "GraphQL server instantiation detected without depth limiting",
        "lines": "const server = new ApolloServer({",
        "metadata": {
          "cwe": ["CWE-400"],
          "confidence": "MEDIUM"
        }
      }
    }
  ]
}
RAWEOF

OUTPUT="$TMPDIR_TEST/graphql-normalized.json"

if bash "$NORMALIZER" --tool semgrep --input "$TMPDIR_TEST/raw-semgrep-graphql.json" --output "$OUTPUT" 2>/dev/null; then
  pass "Normalizer runs successfully on GraphQL semgrep fixture"

  if python3 -c "import json; json.load(open('$OUTPUT'))" 2>/dev/null; then
    pass "Normalizer produces valid JSON output"
  else
    fail "Normalizer produces invalid JSON output"
  fi

  FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT')).get('findings', [])))" 2>/dev/null)
  [ "$FINDING_COUNT" -eq 3 ] \
    && pass "Output has 3 findings (got $FINDING_COUNT)" \
    || fail "Expected 3 findings, got ${FINDING_COUNT:-0}"

  # Verify all findings have source_tool=semgrep
  TOOL_CHECK=$(python3 -c "
import json
data = json.load(open('$OUTPUT'))
print(all(f.get('source_tool') == 'semgrep' for f in data['findings']))
" 2>/dev/null)
  [ "$TOOL_CHECK" = "True" ] \
    && pass "All findings have source_tool=semgrep" \
    || fail "Some findings missing source_tool=semgrep"

else
  fail "Normalizer runs successfully on GraphQL semgrep fixture"
  fail "Normalizer produces valid JSON output (skipped)"
  fail "Output has 3 findings (skipped)"
  fail "All findings have source_tool=semgrep (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 8: Fixture Field Validation (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 8: Fixture Field Validation ---"

# Validate each finding has required fields
FIELD_CHECK=$(python3 -c "
import json, sys
data = json.load(open('$FIXTURE'))
required = ['rule_id', 'severity', 'source_tool', 'cwe_id', 'title', 'status']
for f in data['findings']:
    for field in required:
        if field not in f:
            print(f'Missing {field} in finding {f.get(\"id\", \"unknown\")}', file=sys.stderr)
            sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "All findings have required fields (rule_id, severity, source_tool, cwe_id, title, status)" \
  || fail "Some findings missing required fields"

# Validate location sub-fields
LOCATION_CHECK=$(python3 -c "
import json, sys
data = json.load(open('$FIXTURE'))
for f in data['findings']:
    loc = f.get('location', {})
    if not loc.get('file') or 'line_start' not in loc:
        print(f'Missing location fields in {f.get(\"id\", \"unknown\")}', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "All findings have location.file and location.line_start" \
  || fail "Some findings missing location fields"

# Validate severity distribution matches summary
SEV_CHECK=$(python3 -c "
import json, sys
data = json.load(open('$FIXTURE'))
summary = data.get('summary', {})
findings = data['findings']
actual_high = sum(1 for f in findings if f['severity'] == 'HIGH')
actual_medium = sum(1 for f in findings if f['severity'] == 'MEDIUM')
if summary.get('high') != actual_high or summary.get('medium') != actual_medium:
    sys.exit(1)
if summary.get('total') != len(findings):
    sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "Summary severity counts match actual findings" \
  || fail "Summary severity counts do not match findings"

# Validate OWASP array present on all findings
OWASP_CHECK=$(python3 -c "
import json, sys
data = json.load(open('$FIXTURE'))
for f in data['findings']:
    owasp = f.get('owasp', [])
    if not isinstance(owasp, list) or len(owasp) == 0:
        sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "All findings have non-empty OWASP array" \
  || fail "Some findings missing OWASP array"

echo ""

# ═══════════════════════════════════════════
# Section 9: Rules Metadata Validation (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 9: Rules Metadata Validation ---"

# Validate rules file parses as valid YAML
python3 -c "import yaml; yaml.safe_load(open('$RULES'))" 2>/dev/null \
  && pass "graphql-rules.yml is valid YAML" \
  || fail "graphql-rules.yml is invalid YAML"

# Validate every rule has CWE metadata
CWE_META=$(python3 -c "
import yaml, sys
data = yaml.safe_load(open('$RULES'))
for rule in data.get('rules', []):
    cwe = rule.get('metadata', {}).get('cwe', [])
    if not cwe:
        print(f'Rule {rule[\"id\"]} missing CWE metadata', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "All 8 rules have CWE metadata" \
  || fail "Some rules missing CWE metadata"

# Validate every rule has both OWASP 2021 and 2025 tags
OWASP_META=$(python3 -c "
import yaml, sys
data = yaml.safe_load(open('$RULES'))
for rule in data.get('rules', []):
    owasp = rule.get('metadata', {}).get('owasp', [])
    has_2021 = any('2021' in tag for tag in owasp)
    has_2025 = any('2025' in tag for tag in owasp)
    if not has_2021 or not has_2025:
        print(f'Rule {rule[\"id\"]} missing OWASP dual-tag (2021+2025)', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" 2>/dev/null) \
  && pass "All 8 rules have OWASP 2021+2025 dual-tags" \
  || fail "Some rules missing OWASP dual-tags"

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
