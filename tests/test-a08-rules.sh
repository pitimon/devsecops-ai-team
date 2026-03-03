#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — A08 Integrity Rules Tests
# Tests a08-integrity-rules.yml structure, metadata,
# OWASP tags, CWE cross-reference, and fixture

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — A08 Integrity Rules Tests"
echo "============================================"
echo ""

RULES_FILE="$ROOT_DIR/rules/a08-integrity-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a08-findings.json"
OWASP_MAP="$ROOT_DIR/mappings/cwe-to-owasp.json"
EXPECTED_RULES=5

# ═══════════════════════════════════════════
# Section 1: Rules File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: Rules File Structure ---"

[ -f "$RULES_FILE" ] && pass "a08-integrity-rules.yml exists" || fail "a08-integrity-rules.yml missing"

# Check YAML validity with python
python3 -c "
import yaml, sys
try:
    with open('$RULES_FILE') as f:
        data = yaml.safe_load(f)
    if 'rules' not in data:
        print('ERROR: no rules key', file=sys.stderr)
        sys.exit(1)
    sys.exit(0)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" && pass "YAML is valid with rules key" || fail "YAML is invalid or missing rules key"

# Count rules (expect 5)
RULE_COUNT=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
print(len(data.get('rules', [])))
")
[ "$RULE_COUNT" -eq "$EXPECTED_RULES" ] && pass "Contains $EXPECTED_RULES rules (got $RULE_COUNT)" || fail "Expected $EXPECTED_RULES rules, got $RULE_COUNT"

echo ""

# ═══════════════════════════════════════════
# Section 2: Rule Metadata
# ═══════════════════════════════════════════
echo "--- Section 2: Rule Metadata ---"

# Every rule must have severity
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
errors = []
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    if 'severity' not in rule:
        errors.append(f'{rid}: missing severity')
if errors:
    for e in errors:
        print(f'METADATA_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have severity field" || fail "Some rules missing severity"

# Every rule must have metadata.cwe
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
errors = []
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    meta = rule.get('metadata', {})
    if 'cwe' not in meta or not meta['cwe']:
        errors.append(f'{rid}: missing metadata.cwe')
if errors:
    for e in errors:
        print(f'METADATA_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have metadata.cwe field" || fail "Some rules missing metadata.cwe"

echo ""

# ═══════════════════════════════════════════
# Section 3: OWASP Tags
# ═══════════════════════════════════════════
echo "--- Section 3: OWASP A08 Tags ---"

# All rules tagged with A08:2021
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    owasp = rule.get('metadata', {}).get('owasp', [])
    if 'A08:2021' not in owasp:
        print(f'{rid} missing A08:2021 tag', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All $RULE_COUNT rules tagged with A08:2021" || fail "Not all rules have A08:2021 tag"

# All rules tagged with A08:2025
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    owasp = rule.get('metadata', {}).get('owasp', [])
    if 'A08:2025' not in owasp:
        print(f'{rid} missing A08:2025 tag', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All $RULE_COUNT rules dual-tagged with A08:2025" || fail "Not all rules have A08:2025 tag"

# Every rule has owasp metadata
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
errors = []
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    owasp = rule.get('metadata', {}).get('owasp', [])
    if not owasp:
        errors.append(f'{rid}: missing owasp')
if errors:
    for e in errors:
        print(f'OWASP_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have owasp metadata" || fail "Some rules missing owasp metadata"

echo ""

# ═══════════════════════════════════════════
# Section 4: CWE Cross-Reference
# ═══════════════════════════════════════════
echo "--- Section 4: CWE Cross-Reference ---"

# Check specific CWEs exist in OWASP mapping
for CWE in CWE-502 CWE-829 CWE-494; do
    python3 -c "
import json, sys
with open('$OWASP_MAP') as f:
    data = json.load(f)
if '$CWE' in data['mappings']:
    sys.exit(0)
sys.exit(1)
" && pass "$CWE found in cwe-to-owasp.json" || fail "$CWE not in cwe-to-owasp.json"
done

echo ""

# ═══════════════════════════════════════════
# Section 5: Language Coverage
# ═══════════════════════════════════════════
echo "--- Section 5: Language Coverage ---"

# Check Python coverage
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
all_langs = set()
for rule in data['rules']:
    all_langs.update(rule.get('languages', []))
if 'python' not in all_langs:
    print('Missing python language', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Rules cover python" || fail "Missing python language coverage"

# Check Generic coverage
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
all_langs = set()
for rule in data['rules']:
    all_langs.update(rule.get('languages', []))
if 'generic' not in all_langs:
    print('Missing generic language', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Rules cover generic" || fail "Missing generic language coverage"

echo ""

# ═══════════════════════════════════════════
# Section 6: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Section 6: A08 Fixture Validation ---"

[ -f "$FIXTURE" ] && pass "sample-a08-findings.json exists" || fail "sample-a08-findings.json missing"

python3 -c "
import json, sys
with open('$FIXTURE') as f:
    data = json.load(f)
if 'findings' not in data:
    print('missing findings key', file=sys.stderr)
    sys.exit(1)
if 'summary' not in data:
    print('missing summary key', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Fixture JSON is valid with findings and summary keys" || fail "Fixture missing required keys"

python3 -c "
import json, sys
with open('$FIXTURE') as f:
    data = json.load(f)
findings = data['findings']
if len(findings) != 3:
    print(f'expected 3 findings, got {len(findings)}', file=sys.stderr)
    sys.exit(1)
for f in findings:
    if not f.get('rule_id', '').startswith('a08-'):
        print(f'{f.get(\"id\",\"?\")} rule_id should start with a08-', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Fixture has 3 findings, all reference a08- rules" || fail "Fixture findings validation failed"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "A08 Rules Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL ($FAIL failures)"; exit 1
else echo "RESULT: ALL PASSED"; exit 0; fi
