#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Secret Verifier Tests
# Tests secret-verifier.sh structure, safety controls, provider detection,
# output format, and audit trail (all mock-based, no real API calls)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Secret Verifier Tests"
echo "============================================"
echo ""

VERIFIER="$ROOT_DIR/scripts/secret-verifier.sh"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Script Structure
# ═══════════════════════════════════════════
echo "--- Section 1: Script Structure ---"

[ -f "$VERIFIER" ] && pass "secret-verifier.sh exists" || fail "secret-verifier.sh missing"

[ -x "$VERIFIER" ] && pass "secret-verifier.sh is executable" || fail "secret-verifier.sh not executable"

grep -q '\-\-input' "$VERIFIER" && pass "accepts --input argument" || fail "--input argument not found"

grep -q '\-\-output' "$VERIFIER" && pass "accepts --output argument" || fail "--output argument not found"

echo ""

# ═══════════════════════════════════════════
# Section 2: Safety Controls — --confirm Gate
# ═══════════════════════════════════════════
echo "--- Section 2: Safety Controls — --confirm Gate ---"

# Run without --confirm, expect non-zero exit
STDERR_OUT=$( bash "$VERIFIER" --input /dev/null --output /dev/null 2>&1 || true )
EXIT_CODE=0
bash "$VERIFIER" --input /dev/null --output /dev/null 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" -ne 0 ] && pass "rejects when --confirm is missing (exit $EXIT_CODE)" || fail "should reject without --confirm"

echo "$STDERR_OUT" | grep -qi "confirm" && pass "error message mentions 'confirm'" || fail "error message should mention 'confirm'"

echo "$STDERR_OUT" | grep -qi "In-the-Loop" && pass "error message mentions 'In-the-Loop'" || fail "error message should mention 'In-the-Loop'"

# With --confirm but missing input file — should fail on file-not-found, not on --confirm gate
CONFIRM_ERR=""
bash "$VERIFIER" --input "$TMPDIR/nonexistent.json" --output "$TMPDIR/out.json" --confirm 2>/dev/null || CONFIRM_ERR=$?
# Any exit code is acceptable as long as it didn't fail on --confirm gate specifically
# The error should be about the missing file, not about --confirm
CONFIRM_STDERR=$( bash "$VERIFIER" --input "$TMPDIR/nonexistent.json" --output "$TMPDIR/out.json" --confirm 2>&1 || true )
if echo "$CONFIRM_STDERR" | grep -qi "confirm.*required"; then
  fail "should accept --confirm flag without --confirm gate error"
else
  pass "accepts --confirm flag (fails on file-not-found, not --confirm gate)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 3: Provider Detection
# ═══════════════════════════════════════════
echo "--- Section 3: Provider Detection ---"

grep -q 'aws' "$VERIFIER" && pass "contains 'aws' provider detection" || fail "'aws' provider detection not found"

grep -q 'github' "$VERIFIER" && pass "contains 'github' provider detection" || fail "'github' provider detection not found"

grep -q 'slack' "$VERIFIER" && pass "contains 'slack' provider detection" || fail "'slack' provider detection not found"

grep -q 'generic' "$VERIFIER" && pass "contains 'generic' provider detection" || fail "'generic' provider detection not found"

echo ""

# ═══════════════════════════════════════════
# Section 4: Output Format
# ═══════════════════════════════════════════
echo "--- Section 4: Output Format ---"

# Create test fixture
cat > "$TMPDIR/test-secrets.json" << 'EOF'
{"findings":[{"id":"TEST-001","source_tool":"gitleaks","scan_type":"secret","rule_id":"gitleaks-aws-key","severity":"HIGH","title":"AWS Key","location":{"file":"test.py","line_start":1,"line_end":1},"message":"test finding","status":"open"}],"summary":{"total":1}}
EOF

# Run verifier in non-TTY mode (skips all interactive prompts)
SECRET_VERIFIER_TTY=0 bash "$VERIFIER" \
  --input "$TMPDIR/test-secrets.json" \
  --output "$TMPDIR/verified.json" \
  --confirm \
  --audit "$TMPDIR/audit.json" 2>/dev/null || true

if [ -f "$TMPDIR/verified.json" ]; then
  pass "output file created"
else
  fail "output file not created"
fi

# Check output is valid JSON
if [ -f "$TMPDIR/verified.json" ] && python3 -c "import json; json.load(open('$TMPDIR/verified.json'))" 2>/dev/null; then
  pass "output file is valid JSON"
else
  fail "output file is not valid JSON"
fi

# Check output has verification_status field
if [ -f "$TMPDIR/verified.json" ] && python3 -c "
import json
data = json.load(open('$TMPDIR/verified.json'))
findings = data.get('findings', [])
assert len(findings) > 0, 'no findings'
assert 'verification_status' in findings[0], 'missing verification_status'
" 2>/dev/null; then
  pass "output has verification_status field"
else
  fail "output should have verification_status field"
fi

echo ""

# ═══════════════════════════════════════════
# Section 5: Audit Trail
# ═══════════════════════════════════════════
echo "--- Section 5: Audit Trail ---"

if [ -f "$TMPDIR/audit.json" ]; then
  pass "audit file created"
else
  fail "audit file not created"
fi

if [ -f "$TMPDIR/audit.json" ] && python3 -c "import json; json.load(open('$TMPDIR/audit.json'))" 2>/dev/null; then
  pass "audit file is valid JSON"
else
  fail "audit file is not valid JSON"
fi

if [ -f "$TMPDIR/audit.json" ] && python3 -c "
import json
data = json.load(open('$TMPDIR/audit.json'))
assert 'entries' in data, 'missing entries'
assert 'summary' in data, 'missing summary'
assert isinstance(data['entries'], list), 'entries not a list'
" 2>/dev/null; then
  pass "audit has entries array and summary"
else
  fail "audit should have entries array and summary"
fi

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Secret Verifier Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL tests failed"
  exit 1
else
  echo "ALL TESTS PASSED"
fi
