#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — A03 Custom Semgrep Rules Tests
# Validates rule YAML structure, metadata, CWE cross-references,
# and sast-patterns.md integration
# Docker-based semgrep --validate is run only if Docker is available

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — A03 Rules Tests"
echo "============================================"
echo ""

RULES_FILE="$ROOT_DIR/rules/a03-injection-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a03-findings.json"
OWASP_MAP="$ROOT_DIR/mappings/cwe-to-owasp.json"
NIST_MAP="$ROOT_DIR/mappings/cwe-to-nist.json"
NCSA_MAP="$ROOT_DIR/mappings/cwe-to-ncsa.json"
SAST_REF="$ROOT_DIR/skills/references/sast-patterns.md"
DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"

# ═══════════════════════════════════════════
# Section 1: Rules File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: Rules File Structure ---"

[ -f "$RULES_FILE" ] && pass "a03-injection-rules.yml exists" || fail "a03-injection-rules.yml missing"

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

# Count rules (expect 11)
RULE_COUNT=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
print(len(data.get('rules', [])))
")
[ "$RULE_COUNT" -eq 11 ] && pass "Contains 11 rules (got $RULE_COUNT)" || fail "Expected 11 rules, got $RULE_COUNT"

echo ""

# ═══════════════════════════════════════════
# Section 2: Individual Rule Validation
# ═══════════════════════════════════════════
echo "--- Section 2: Individual Rule Validation ---"

EXPECTED_IDS="a03-sql-injection a03-sql-injection-js a03-sql-injection-java a03-command-injection a03-command-injection-js a03-xss-dom a03-xss-reflected a03-xss-reflected-java a03-ldap-injection a03-template-injection a03-template-injection-js"

for RULE_ID in $EXPECTED_IDS; do
    python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
ids = [r['id'] for r in data['rules']]
sys.exit(0 if '$RULE_ID' in ids else 1)
" && pass "Rule '$RULE_ID' present" || fail "Rule '$RULE_ID' missing"
done

echo ""

# ═══════════════════════════════════════════
# Section 3: Required Semgrep Metadata
# ═══════════════════════════════════════════
echo "--- Section 3: Required Semgrep Metadata ---"

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
" && pass "All rules have required fields (id, severity, message, languages, patterns)" || fail "Some rules missing required fields"

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
    if 'owasp' not in meta or not meta['owasp']:
        errors.append(f'{rid}: missing metadata.owasp')
    if 'references' not in meta or not meta['references']:
        errors.append(f'{rid}: missing metadata.references')
if errors:
    for e in errors:
        print(f'METADATA_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All rules have CWE, OWASP, and references in metadata" || fail "Missing CWE/OWASP/references metadata"

echo ""

# ═══════════════════════════════════════════
# Section 4: OWASP A03 Tag on All Rules
# ═══════════════════════════════════════════
echo "--- Section 4: OWASP A03 Tag ---"

python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
for rule in data['rules']:
    rid = rule.get('id', 'unknown')
    owasp = rule.get('metadata', {}).get('owasp', [])
    if 'A03:2021' not in owasp:
        print(f'{rid} missing A03:2021 tag', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All 11 rules tagged with A03:2021" || fail "Not all rules have A03:2021 tag"

echo ""

# ═══════════════════════════════════════════
# Section 5: Severity Levels
# ═══════════════════════════════════════════
echo "--- Section 5: Severity Levels ---"

python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
severities = {r['id']: r['severity'] for r in data['rules']}
expected = {
    'a03-sql-injection': 'ERROR',
    'a03-sql-injection-js': 'ERROR',
    'a03-sql-injection-java': 'ERROR',
    'a03-command-injection': 'ERROR',
    'a03-command-injection-js': 'ERROR',
    'a03-xss-dom': 'ERROR',
    'a03-xss-reflected': 'WARNING',
    'a03-xss-reflected-java': 'WARNING',
    'a03-ldap-injection': 'ERROR',
    'a03-template-injection': 'ERROR',
    'a03-template-injection-js': 'ERROR'
}
for rid, sev in expected.items():
    actual = severities.get(rid, 'MISSING')
    if actual != sev:
        print(f'{rid}: expected {sev}, got {actual}', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Severity levels correct (ERROR for CWE-89/78/79-DOM/90/1336, WARNING for CWE-79-reflected)" || fail "Severity levels mismatch"

echo ""

# ═══════════════════════════════════════════
# Section 6: CWE Cross-Reference with Mappings
# ═══════════════════════════════════════════
echo "--- Section 6: CWE Cross-Reference ---"

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

# Check CWEs are in NCSA mapping (best-effort, not all CWEs may be mapped)
NCSA_MAPPED=0
for CWE in $RULE_CWES; do
    python3 -c "
import json, sys
with open('$NCSA_MAP') as f:
    data = json.load(f)
if '$CWE' in data['mappings']:
    sys.exit(0)
sys.exit(1)
" 2>/dev/null && NCSA_MAPPED=$((NCSA_MAPPED + 1))
done
[ "$NCSA_MAPPED" -gt 0 ] && pass "At least 1 A03 CWE mapped in cwe-to-ncsa.json ($NCSA_MAPPED found)" || fail "No A03 CWEs in NCSA mapping"

echo ""

# ═══════════════════════════════════════════
# Section 7: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Section 7: A03 Fixture Validation ---"

[ -f "$FIXTURE" ] && pass "sample-a03-findings.json exists" || fail "sample-a03-findings.json missing"

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
if 'metadata' not in data:
    print('missing metadata key', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Fixture has findings, summary, metadata keys" || fail "Fixture missing required keys"

python3 -c "
import json, sys
with open('$FIXTURE') as f:
    data = json.load(f)
findings = data['findings']
if len(findings) != 6:
    print(f'expected 6 findings, got {len(findings)}', file=sys.stderr)
    sys.exit(1)
# Each finding should reference A03
for f in findings:
    if f.get('owasp') != 'A03:2021':
        print(f'{f[\"id\"]} missing A03:2021 owasp tag', file=sys.stderr)
        sys.exit(1)
    if not f.get('rule_id', '').startswith('a03-'):
        print(f'{f[\"id\"]} rule_id should start with a03-', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Fixture has 6 findings, all tagged A03:2021" || fail "Fixture findings validation failed"

echo ""

# ═══════════════════════════════════════════
# Section 8: SAST-Patterns.md Reference
# ═══════════════════════════════════════════
echo "--- Section 8: SAST-Patterns Reference ---"

grep -q "a03-injection-rules.yml" "$SAST_REF" && pass "sast-patterns.md references A03 rules file" || fail "sast-patterns.md missing A03 rules reference"

echo ""

# ═══════════════════════════════════════════
# Section 9: Job Dispatcher Integration
# ═══════════════════════════════════════════
echo "--- Section 9: Job Dispatcher A03 Support ---"

grep -q "a03" "$DISPATCHER" && pass "job-dispatcher.sh references A03 rules" || fail "job-dispatcher.sh missing A03 support"

echo ""

# ═══════════════════════════════════════════
# Section 10: Language Coverage
# ═══════════════════════════════════════════
echo "--- Section 10: Language Coverage ---"

python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
all_langs = set()
for rule in data['rules']:
    all_langs.update(rule.get('languages', []))
required = {'python', 'javascript', 'typescript', 'java'}
missing = required - all_langs
if missing:
    print(f'Missing languages: {missing}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Rules cover Python, JavaScript, TypeScript, Java" || fail "Missing language coverage"

# Check that all 11 rules are present and cover expected categories
python3 -c "
import yaml, sys
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
ids = [r['id'] for r in data['rules']]
# 11 distinct rule IDs covering 6 logical categories (SQLi, CMDi, XSS-DOM, XSS-reflected, LDAPi, SSTI)
if len(ids) != 11:
    print(f'Expected 11 rule IDs, got {len(ids)}', file=sys.stderr)
    sys.exit(1)
categories = set()
for rid in ids:
    base = rid.replace('-js', '').replace('-java', '')
    categories.add(base)
# 6 logical categories with language variants
if len(categories) < 6:
    print(f'Expected at least 6 categories, got {len(categories)}: {categories}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "11 rules across 6 logical A03 categories covered" || fail "Missing A03 categories"

echo ""

# ═══════════════════════════════════════════
# Section 11: Semgrep --validate (conditional)
# ═══════════════════════════════════════════
echo "--- Section 11: Semgrep --validate (conditional) ---"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    docker run --rm \
        -v "$ROOT_DIR/rules:/rules:ro" \
        -v "$ROOT_DIR:/src:ro" \
        returntocorp/semgrep:latest \
        semgrep --validate --config /rules/a03-injection-rules.yml 2>/dev/null \
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
echo "A03 Rules Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
