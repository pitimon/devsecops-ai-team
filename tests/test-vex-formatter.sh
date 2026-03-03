#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — VEX Formatter Tests
# Tests VEX formatter for CycloneDX VEX and OpenVEX output formats

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — VEX Formatter Tests"
echo "============================================"
echo ""

VEX_FORMATTER="$ROOT_DIR/formatters/vex-formatter.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a06-findings.json"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Count findings in fixture for later comparison
FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$FIXTURE'))['findings']))")

# ─── Section 1: Script Structure ───
echo "--- Script Structure ---"

if [ -f "$VEX_FORMATTER" ]; then
  pass "vex-formatter.sh exists"
else
  fail "vex-formatter.sh not found"
fi

if [ -x "$VEX_FORMATTER" ] || head -1 "$VEX_FORMATTER" | grep -q "bash"; then
  pass "vex-formatter.sh is executable or has bash shebang"
else
  fail "vex-formatter.sh is not executable"
fi

if grep -q -- "--input" "$VEX_FORMATTER" && grep -q -- "--output" "$VEX_FORMATTER" && grep -q -- "--format" "$VEX_FORMATTER"; then
  pass "Accepts --input, --output, --format flags"
else
  fail "Missing one or more required flags (--input, --output, --format)"
fi

# ─── Section 2: CycloneDX VEX Output ───
echo ""
echo "--- CycloneDX VEX Output ---"

CDX_OUT="$TMPDIR/cdx.json"
if bash "$VEX_FORMATTER" --input "$FIXTURE" --output "$CDX_OUT" --format cdx 2>/dev/null; then
  pass "CycloneDX formatter executed successfully"
else
  fail "CycloneDX formatter failed to execute"
fi

if python3 -c "import json; json.load(open('$CDX_OUT'))" 2>/dev/null; then
  pass "CycloneDX output is valid JSON"
else
  fail "CycloneDX output is not valid JSON"
fi

if python3 -c "import json; d=json.load(open('$CDX_OUT')); assert d['bomFormat']=='CycloneDX'" 2>/dev/null; then
  pass "CycloneDX has bomFormat=CycloneDX"
else
  fail "CycloneDX missing bomFormat=CycloneDX"
fi

if python3 -c "import json; d=json.load(open('$CDX_OUT')); assert 'specVersion' in d and d['specVersion']" 2>/dev/null; then
  pass "CycloneDX has specVersion"
else
  fail "CycloneDX missing specVersion"
fi

if python3 -c "import json; d=json.load(open('$CDX_OUT')); assert isinstance(d['vulnerabilities'], list)" 2>/dev/null; then
  pass "CycloneDX has vulnerabilities array"
else
  fail "CycloneDX missing vulnerabilities array"
fi

CDX_VULN_COUNT=$(python3 -c "import json; print(len(json.load(open('$CDX_OUT'))['vulnerabilities']))" 2>/dev/null)
if [ "$CDX_VULN_COUNT" = "$FINDING_COUNT" ]; then
  pass "CycloneDX vulnerability count ($CDX_VULN_COUNT) matches input findings ($FINDING_COUNT)"
else
  fail "CycloneDX vulnerability count ($CDX_VULN_COUNT) does not match input findings ($FINDING_COUNT)"
fi

# ─── Section 3: OpenVEX Output ───
echo ""
echo "--- OpenVEX Output ---"

OPENVEX_OUT="$TMPDIR/openvex.json"
if bash "$VEX_FORMATTER" --input "$FIXTURE" --output "$OPENVEX_OUT" --format openvex 2>/dev/null; then
  pass "OpenVEX formatter executed successfully"
else
  fail "OpenVEX formatter failed to execute"
fi

if python3 -c "import json; json.load(open('$OPENVEX_OUT'))" 2>/dev/null; then
  pass "OpenVEX output is valid JSON"
else
  fail "OpenVEX output is not valid JSON"
fi

if python3 -c "import json; d=json.load(open('$OPENVEX_OUT')); assert 'openvex' in d['@context']" 2>/dev/null; then
  pass "OpenVEX has @context with openvex"
else
  fail "OpenVEX missing @context with openvex"
fi

if python3 -c "import json; d=json.load(open('$OPENVEX_OUT')); assert d['author'] and len(d['author'])>0" 2>/dev/null; then
  pass "OpenVEX has author"
else
  fail "OpenVEX missing author"
fi

if python3 -c "import json; d=json.load(open('$OPENVEX_OUT')); assert isinstance(d['statements'], list)" 2>/dev/null; then
  pass "OpenVEX has statements array"
else
  fail "OpenVEX missing statements array"
fi

OPENVEX_STMT_COUNT=$(python3 -c "import json; print(len(json.load(open('$OPENVEX_OUT'))['statements']))" 2>/dev/null)
if [ "$OPENVEX_STMT_COUNT" = "$FINDING_COUNT" ]; then
  pass "OpenVEX statement count ($OPENVEX_STMT_COUNT) matches input findings ($FINDING_COUNT)"
else
  fail "OpenVEX statement count ($OPENVEX_STMT_COUNT) does not match input findings ($FINDING_COUNT)"
fi

# ─── Section 4: Status Mapping ───
echo ""
echo "--- Status Mapping ---"

# WARNING severity → in_triage (CycloneDX)
if python3 -c "
import json
d = json.load(open('$CDX_OUT'))
vulns = d['vulnerabilities']
warning_vulns = [v for v in vulns if v['id'] == 'CWE-1104']
assert len(warning_vulns) > 0, 'No WARNING-severity vulnerability found'
assert warning_vulns[0]['analysis']['state'] == 'in_triage', f'Expected in_triage, got {warning_vulns[0][\"analysis\"][\"state\"]}'
" 2>/dev/null; then
  pass "CycloneDX maps WARNING severity to in_triage"
else
  fail "CycloneDX does not map WARNING severity to in_triage"
fi

# ERROR severity → exploitable (CycloneDX)
if python3 -c "
import json
d = json.load(open('$CDX_OUT'))
vulns = d['vulnerabilities']
error_vulns = [v for v in vulns if v['id'] == 'CWE-829' and v['affects'][0]['ref'].startswith('app/')]
assert len(error_vulns) > 0, 'No ERROR-severity vulnerability found'
assert error_vulns[0]['analysis']['state'] == 'exploitable', f'Expected exploitable, got {error_vulns[0][\"analysis\"][\"state\"]}'
" 2>/dev/null; then
  pass "CycloneDX maps ERROR severity to exploitable"
else
  fail "CycloneDX does not map ERROR severity to exploitable"
fi

# OpenVEX maps WARNING → under_investigation, ERROR → affected
if python3 -c "
import json
d = json.load(open('$OPENVEX_OUT'))
stmts = d['statements']
# Find WARNING-severity statement (CWE-1104 = unpinned pip, severity WARNING)
warning_stmts = [s for s in stmts if s['vulnerability']['@id'] == 'CWE-1104']
assert len(warning_stmts) > 0, 'No WARNING statement found'
assert warning_stmts[0]['status'] == 'under_investigation', f'Expected under_investigation, got {warning_stmts[0][\"status\"]}'
# Find ERROR-severity statement (CWE-829 from app/config/loader.py)
error_stmts = [s for s in stmts if s['vulnerability']['@id'] == 'CWE-829' and 'app/' in s['products'][0]['@id']]
assert len(error_stmts) > 0, 'No ERROR statement found'
assert error_stmts[0]['status'] == 'affected', f'Expected affected, got {error_stmts[0][\"status\"]}'
" 2>/dev/null; then
  pass "OpenVEX maps WARNING to under_investigation and ERROR to affected"
else
  fail "OpenVEX status mapping incorrect"
fi

# ─── Section 5: Error Handling ───
echo ""
echo "--- Error Handling ---"

if ! bash "$VEX_FORMATTER" 2>/dev/null; then
  pass "Exits non-zero with missing arguments"
else
  fail "Should exit non-zero with missing arguments"
fi

if ! bash "$VEX_FORMATTER" --input "/nonexistent/file.json" --output "$TMPDIR/nope.json" --format cdx 2>/dev/null; then
  pass "Exits non-zero with missing input file"
else
  fail "Should exit non-zero with missing input file"
fi

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "VEX Formatter Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL ($FAIL failures)"; exit 1
else echo "RESULT: ALL PASSED"; exit 0; fi
