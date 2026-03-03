#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — A05 Custom Semgrep Rules Tests
# Validates rule YAML structure, metadata, CWE cross-references,
# language coverage, and fixture JSON integrity
# Docker-based semgrep --validate is run only if Docker is available

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — A05 Rules Tests"
echo "============================================"
echo ""

RULES_FILE="$ROOT_DIR/rules/a05-misconfig-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a05-findings.json"
OWASP_MAP="$ROOT_DIR/mappings/cwe-to-owasp.json"
EXPECTED_RULES=6

# ═══════════════════════════════════════════
# Section 1: Rules File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: Rules File Structure ---"

[ -f "$RULES_FILE" ] && pass "a05-misconfig-rules.yml exists" || fail "a05-misconfig-rules.yml missing"

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
" && pass "YAML is valid" || fail "YAML is invalid"

# Count rules (expect 6)
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

# Every rule must have cwe, owasp, severity, message
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)

errors = []
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    # Check top-level fields
    if 'severity' not in rule:
        errors.append(f'{rid}: missing severity')
    if 'message' not in rule:
        errors.append(f'{rid}: missing message')
    # Check metadata fields
    meta = rule.get('metadata', {})
    if 'cwe' not in meta or not meta['cwe']:
        errors.append(f'{rid}: missing metadata.cwe')
    if 'owasp' not in meta or not meta['owasp']:
        errors.append(f'{rid}: missing metadata.owasp')

if errors:
    for e in errors:
        print(f'METADATA_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have cwe, owasp, severity, message fields" || fail "Some rules missing required metadata"

# Every rule has OWASP 2025 tag
HAS_2025=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
count = 0
for r in data['rules']:
    owasp = r.get('metadata', {}).get('owasp', [])
    if any('2025' in t for t in owasp):
        count += 1
print(count)
")
[ "$HAS_2025" -eq "$RULE_COUNT" ] \
  && pass "All $RULE_COUNT rules have OWASP 2025 tags" \
  || fail "Only $HAS_2025/$RULE_COUNT rules have OWASP 2025 tags"

# All rules tagged with A05:2021
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    owasp = rule.get('metadata', {}).get('owasp', [])
    if 'A05:2021' not in owasp:
        print(f'{rid} missing A05:2021 tag', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All $RULE_COUNT rules tagged with A05:2021" || fail "Not all rules have A05:2021 tag"

# All rules have required Semgrep fields (id, severity, message, languages, pattern)
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)

required_fields = ['id', 'severity', 'message', 'languages']
required_metadata = ['cwe', 'owasp', 'category', 'references']

errors = []
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    for field in required_fields:
        if field not in rule:
            errors.append(f'{rid}: missing {field}')
    has_pattern = any(k in rule for k in ['pattern', 'patterns', 'pattern-either', 'pattern-regex'])
    if not has_pattern:
        errors.append(f'{rid}: missing pattern definition')
    meta = rule.get('metadata', {})
    for mf in required_metadata:
        if mf not in meta:
            errors.append(f'{rid}: missing metadata.{mf}')

if errors:
    for e in errors:
        print(f'METADATA_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have required Semgrep fields (id, severity, message, languages, patterns, metadata)" || fail "Some rules missing required Semgrep fields"

echo ""

# ═══════════════════════════════════════════
# Section 3: CWE Mapping Cross-Reference
# ═══════════════════════════════════════════
echo "--- Section 3: CWE Mapping Cross-Reference ---"

# Extract CWE IDs from rules
RULE_CWES=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
cwes = set()
for rule in data['rules']:
    for c in rule.get('metadata', {}).get('cwe', []):
        cwes.add(c)
print(' '.join(sorted(cwes)))
")

# Check each CWE exists in OWASP mapping
for CWE in $RULE_CWES; do
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
# Section 4: Language Coverage
# ═══════════════════════════════════════════
echo "--- Section 4: Language Coverage ---"

LANG_COUNT=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
all_langs = set()
for rule in data['rules']:
    all_langs.update(rule.get('languages', []))
print(len(all_langs))
")
[ "$LANG_COUNT" -ge 2 ] && pass "At least 2 languages covered across all rules ($LANG_COUNT found)" || fail "Less than 2 languages covered ($LANG_COUNT found)"

# Check Python and JavaScript are both covered
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
all_langs = set()
for rule in data['rules']:
    all_langs.update(rule.get('languages', []))
required = {'python', 'javascript'}
missing = required - all_langs
if missing:
    print(f'Missing languages: {missing}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Rules cover Python and JavaScript" || fail "Missing Python or JavaScript coverage"

echo ""

# ═══════════════════════════════════════════
# Section 5: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Section 5: A05 Fixture Validation ---"

[ -f "$FIXTURE" ] && pass "sample-a05-findings.json exists" || fail "sample-a05-findings.json missing"

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
if not isinstance(findings, list) or len(findings) == 0:
    print(f'findings should be a non-empty array', file=sys.stderr)
    sys.exit(1)
for f in findings:
    if not f.get('rule_id', '').startswith('a05-'):
        print(f'{f.get(\"id\",\"?\")} rule_id should start with a05-', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All fixture findings reference a05- rules" || fail "Fixture findings validation failed"

echo ""

# ═══════════════════════════════════════════
# Section 6: Semgrep --validate (conditional)
# ═══════════════════════════════════════════
echo "--- Section 6: Semgrep --validate (conditional) ---"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    docker run --rm \
        -v "$ROOT_DIR/rules:/rules:ro" \
        -v "$ROOT_DIR:/src:ro" \
        returntocorp/semgrep:latest \
        semgrep --validate --config /rules/a05-misconfig-rules.yml 2>/dev/null \
        && pass "semgrep --validate passes" \
        || fail "semgrep --validate failed"
else
    echo "  [SKIP] Docker not available — skipping semgrep --validate"
fi

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "A05 Rules Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
