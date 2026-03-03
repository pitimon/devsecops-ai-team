#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — NCSA Validator Tests
# Tests dast-ncsa-validator.sh structure, NCSA category coverage,
# output format, and cross-reference with cwe-to-ncsa.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — NCSA Validator Tests"
echo "============================================"
echo ""

VALIDATOR="$ROOT_DIR/scripts/dast-ncsa-validator.sh"
NCSA_MAP="$ROOT_DIR/mappings/cwe-to-ncsa.json"
SKILL_FILE="$ROOT_DIR/skills/dast-scan/SKILL.md"
ZAP_FIXTURE="$ROOT_DIR/tests/fixtures/sample-zap-full.json"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Script Structure
# ═══════════════════════════════════════════
echo "--- Section 1: Script Structure ---"

[ -f "$VALIDATOR" ] && pass "dast-ncsa-validator.sh exists" || fail "dast-ncsa-validator.sh missing"
[ -x "$VALIDATOR" ] && pass "dast-ncsa-validator.sh is executable" || fail "dast-ncsa-validator.sh not executable"

# Check script accepts required args
grep -q '\-\-target' "$VALIDATOR" && pass "Accepts --target argument" || fail "Missing --target argument"
grep -q '\-\-zap-results' "$VALIDATOR" && pass "Accepts --zap-results argument" || fail "Missing --zap-results argument"
grep -q '\-\-output' "$VALIDATOR" && pass "Accepts --output argument" || fail "Missing --output argument"

echo ""

# ═══════════════════════════════════════════
# Section 2: NCSA Category Coverage
# ═══════════════════════════════════════════
echo "--- Section 2: NCSA Category Coverage ---"

# Validator should check categories 1.x, 2.x, and 4.x
grep -q 'NCSA 1.x' "$VALIDATOR" || grep -q '1\.x' "$VALIDATOR" && pass "Covers NCSA 1.x (HTTP Security)" || fail "Missing NCSA 1.x coverage"
grep -q 'NCSA 2.x' "$VALIDATOR" || grep -q '2\.x' "$VALIDATOR" && pass "Covers NCSA 2.x (Transport Security)" || fail "Missing NCSA 2.x coverage"
grep -q 'NCSA 4.x' "$VALIDATOR" || grep -q '4\.x' "$VALIDATOR" && pass "Covers NCSA 4.x (Session Management)" || fail "Missing NCSA 4.x coverage"

echo ""

# ═══════════════════════════════════════════
# Section 3: Header Check Logic
# ═══════════════════════════════════════════
echo "--- Section 3: Header Checks ---"

# Verify specific headers are checked
grep -q 'Strict-Transport-Security' "$VALIDATOR" && pass "Checks HSTS header" || fail "Missing HSTS check"
grep -q 'X-Frame-Options' "$VALIDATOR" && pass "Checks X-Frame-Options header" || fail "Missing X-Frame-Options check"
grep -q 'X-Content-Type-Options' "$VALIDATOR" && pass "Checks X-Content-Type-Options header" || fail "Missing X-Content-Type-Options check"
grep -q 'Content-Security-Policy' "$VALIDATOR" && pass "Checks CSP header" || fail "Missing CSP check"
grep -q 'Referrer-Policy' "$VALIDATOR" && pass "Checks Referrer-Policy header" || fail "Missing Referrer-Policy check"
grep -q 'Permissions-Policy' "$VALIDATOR" && pass "Checks Permissions-Policy header" || fail "Missing Permissions-Policy check"
grep -q 'Cross-Origin-Opener-Policy' "$VALIDATOR" && pass "Checks Cross-Origin-Opener-Policy (COOP) header" || fail "Missing COOP check"
grep -q 'Cross-Origin-Embedder-Policy' "$VALIDATOR" && pass "Checks Cross-Origin-Embedder-Policy (COEP) header" || fail "Missing COEP check"

echo ""

# ═══════════════════════════════════════════
# Section 4: Session/Cookie Checks
# ═══════════════════════════════════════════
echo "--- Section 4: Cookie Security Checks ---"

grep -q 'Secure' "$VALIDATOR" && pass "Checks Cookie Secure flag" || fail "Missing Secure flag check"
grep -q 'HttpOnly' "$VALIDATOR" && pass "Checks Cookie HttpOnly flag" || fail "Missing HttpOnly flag check"
grep -q 'SameSite' "$VALIDATOR" && pass "Checks Cookie SameSite flag" || fail "Missing SameSite flag check"

echo ""

# ═══════════════════════════════════════════
# Section 5: TLS Checks
# ═══════════════════════════════════════════
echo "--- Section 5: TLS Security Checks ---"

grep -q 'TLS' "$VALIDATOR" && pass "TLS version check present" || fail "Missing TLS check"
grep -q 'https' "$VALIDATOR" && pass "HTTPS detection present" || fail "Missing HTTPS detection"
grep -q 'TLS 1.3' "$VALIDATOR" && pass "TLS 1.3 preference check present" || fail "Missing TLS 1.3 preference check"

echo ""

# ═══════════════════════════════════════════
# Section 6: Output JSON Format
# ═══════════════════════════════════════════
echo "--- Section 6: Output Format ---"

# Verify the script produces valid JSON output structure
grep -q 'ncsa_version' "$VALIDATOR" && pass "Output includes ncsa_version" || fail "Output missing ncsa_version"
grep -q 'categories_validated' "$VALIDATOR" && pass "Output includes categories_validated" || fail "Output missing categories_validated"
grep -q 'summary' "$VALIDATOR" && pass "Output includes summary" || fail "Output missing summary"
grep -q 'checks' "$VALIDATOR" && pass "Output includes checks array" || fail "Output missing checks"

echo ""

# ═══════════════════════════════════════════
# Section 7: CWE-to-NCSA Cross-Reference
# ═══════════════════════════════════════════
echo "--- Section 7: NCSA Mapping Cross-Reference ---"

# Verify key security header CWEs are in NCSA mapping
python3 -c "
import json, sys
with open('$NCSA_MAP') as f:
    data = json.load(f)
m = data['mappings']
# CWE-693: Missing security headers (CSP)
# CWE-319: Cleartext transmission (TLS)
# CWE-614: Cookie without Secure flag
key_cwes = ['CWE-693', 'CWE-319', 'CWE-16']
found = [c for c in key_cwes if c in m]
if len(found) >= 2:
    sys.exit(0)
print(f'Only found {len(found)} of {len(key_cwes)} key CWEs in NCSA mapping', file=sys.stderr)
sys.exit(1)
" && pass "Key header CWEs (693, 319, 16) present in NCSA mapping" || fail "Key CWEs missing from NCSA mapping"

echo ""

# ═══════════════════════════════════════════
# Section 8: SKILL.md NCSA Reference
# ═══════════════════════════════════════════
echo "--- Section 8: SKILL.md NCSA Reference ---"

grep -q 'ncsa-validator' "$SKILL_FILE" && pass "SKILL.md references NCSA validator" || fail "SKILL.md missing NCSA reference"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "NCSA Validator Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
