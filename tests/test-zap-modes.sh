#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — ZAP Multi-Mode Tests
# Tests ZAP scan mode support in job-dispatcher.sh, SKILL.md, and agent docs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — ZAP Multi-Mode Tests"
echo "============================================"
echo ""

DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
SKILL_FILE="$ROOT_DIR/skills/dast-scan/SKILL.md"
AGENT_FILE="$ROOT_DIR/agents/specialists/dast-specialist.md"
FIXTURE_BASELINE="$ROOT_DIR/tests/fixtures/sample-zap-baseline.json"
FIXTURE_FULL="$ROOT_DIR/tests/fixtures/sample-zap-full.json"

# ═══════════════════════════════════════════
# Section 1: run_zap() Function Structure
# ═══════════════════════════════════════════
echo "--- Section 1: run_zap() Function ---"

grep -q 'run_zap()' "$DISPATCHER" && pass "run_zap() function exists" || fail "run_zap() function missing"
grep -q 'ZAP_MODE' "$DISPATCHER" && pass "ZAP_MODE variable used in dispatcher" || fail "ZAP_MODE variable missing"

echo ""

# ═══════════════════════════════════════════
# Section 2: Mode Argument Parsing
# ═══════════════════════════════════════════
echo "--- Section 2: Mode Argument Parsing ---"

grep -q '\-\-mode)' "$DISPATCHER" && pass "--mode argument accepted" || fail "--mode argument not parsed"
grep -q 'ZAP_MODE="baseline"' "$DISPATCHER" && pass "Default mode is baseline" || fail "Default mode should be baseline"

# Verify all 3 modes are handled in case statement
grep -q 'baseline)' "$DISPATCHER" && pass "baseline mode handled in case" || fail "baseline mode not in case"
grep -q 'full)' "$DISPATCHER" && pass "full mode handled in case" || fail "full mode not in case"
grep -q 'api)' "$DISPATCHER" && pass "api mode handled in case" || fail "api mode not in case"

echo ""

# ═══════════════════════════════════════════
# Section 3: Auth Token Parameter
# ═══════════════════════════════════════════
echo "--- Section 3: Auth Token Support ---"

grep -q '\-\-auth-token)' "$DISPATCHER" && pass "--auth-token argument accepted" || fail "--auth-token argument not parsed"
grep -q 'AUTH_TOKEN' "$DISPATCHER" && pass "AUTH_TOKEN variable used" || fail "AUTH_TOKEN variable missing"
grep -q 'Bearer' "$DISPATCHER" && pass "Bearer token injection configured" || fail "Bearer token injection missing"

echo ""

# ═══════════════════════════════════════════
# Section 4: API Spec Parameter
# ═══════════════════════════════════════════
echo "--- Section 4: API Spec Support ---"

grep -q '\-\-api-spec)' "$DISPATCHER" && pass "--api-spec argument accepted" || fail "--api-spec argument not parsed"
grep -q 'API_SPEC' "$DISPATCHER" && pass "API_SPEC variable used" || fail "API_SPEC variable missing"
grep -q 'openapi' "$DISPATCHER" && pass "OpenAPI format flag present" || fail "OpenAPI format flag missing"

echo ""

# ═══════════════════════════════════════════
# Section 5: Timeout Values Per Mode
# ═══════════════════════════════════════════
echo "--- Section 5: Timeout Configuration ---"

# Check timeout values in dispatcher
grep -q 'ZAP_TIMEOUT=120' "$DISPATCHER" && pass "Baseline timeout: 120s" || fail "Baseline timeout should be 120s"
grep -q 'ZAP_TIMEOUT=1800' "$DISPATCHER" && pass "Full timeout: 1800s" || fail "Full timeout should be 1800s"
grep -q 'ZAP_TIMEOUT=600' "$DISPATCHER" && pass "API timeout: 600s" || fail "API timeout should be 600s"

echo ""

# ═══════════════════════════════════════════
# Section 6: Docker Command Construction
# ═══════════════════════════════════════════
echo "--- Section 6: Docker Command Construction ---"

# Verify correct ZAP scripts are used per mode
grep -q 'zap-baseline.py' "$DISPATCHER" && pass "zap-baseline.py script referenced" || fail "zap-baseline.py missing"
grep -q 'zap-full-scan.py' "$DISPATCHER" && pass "zap-full-scan.py script referenced" || fail "zap-full-scan.py missing"
grep -q 'zap-api-scan.py' "$DISPATCHER" && pass "zap-api-scan.py script referenced" || fail "zap-api-scan.py missing"

# Verify ZAP image
grep -q 'ghcr.io/zaproxy/zaproxy:stable' "$DISPATCHER" && pass "ZAP Docker image correct" || fail "ZAP Docker image incorrect"

echo ""

# ═══════════════════════════════════════════
# Section 7: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Section 7: Fixture Validation ---"

[ -f "$FIXTURE_BASELINE" ] && pass "sample-zap-baseline.json exists" || fail "sample-zap-baseline.json missing"
[ -f "$FIXTURE_FULL" ] && pass "sample-zap-full.json exists" || fail "sample-zap-full.json missing"

# Validate full-scan fixture has HIGH severity alerts (riskcode 3)
python3 -c "
import json, sys
with open('$FIXTURE_FULL') as f:
    data = json.load(f)
alerts = data['site'][0]['alerts']
high_alerts = [a for a in alerts if int(a['riskcode']) >= 3]
if len(high_alerts) < 1:
    print('No HIGH severity alerts in full-scan fixture', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Full-scan fixture has HIGH severity alerts" || fail "Full-scan fixture missing HIGH severity"

# Verify full-scan has more alerts than baseline
python3 -c "
import json, sys
with open('$FIXTURE_BASELINE') as f:
    baseline = json.load(f)
with open('$FIXTURE_FULL') as f:
    full = json.load(f)
b_count = len(baseline['site'][0]['alerts'])
f_count = len(full['site'][0]['alerts'])
if f_count <= b_count:
    print(f'Full ({f_count}) should have more alerts than baseline ({b_count})', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Full-scan has more alerts than baseline ($FIXTURE_FULL)" || fail "Full-scan should have more alerts"

echo ""

# ═══════════════════════════════════════════
# Section 8: SKILL.md Mode Documentation
# ═══════════════════════════════════════════
echo "--- Section 8: SKILL.md Documentation ---"

grep -q 'baseline' "$SKILL_FILE" && pass "SKILL.md documents baseline mode" || fail "SKILL.md missing baseline"
grep -q 'full' "$SKILL_FILE" && pass "SKILL.md documents full mode" || fail "SKILL.md missing full"
grep -q 'api' "$SKILL_FILE" && pass "SKILL.md documents api mode" || fail "SKILL.md missing api"
grep -q '\-\-mode' "$SKILL_FILE" && pass "SKILL.md shows --mode flag" || fail "SKILL.md missing --mode usage"
grep -q '\-\-auth-token' "$SKILL_FILE" && pass "SKILL.md shows --auth-token flag" || fail "SKILL.md missing --auth-token"
grep -q '\-\-api-spec' "$SKILL_FILE" && pass "SKILL.md shows --api-spec flag" || fail "SKILL.md missing --api-spec"

echo ""

# ═══════════════════════════════════════════
# Section 9: Agent Mode References
# ═══════════════════════════════════════════
echo "--- Section 9: Agent Documentation ---"

grep -q 'baseline' "$AGENT_FILE" && pass "dast-specialist references baseline mode" || fail "dast-specialist missing baseline"
grep -q 'full' "$AGENT_FILE" && pass "dast-specialist references full mode" || fail "dast-specialist missing full"
grep -q 'api' "$AGENT_FILE" && pass "dast-specialist references api mode" || fail "dast-specialist missing api"
grep -q '\-\-mode' "$AGENT_FILE" && pass "dast-specialist shows --mode usage" || fail "dast-specialist missing --mode"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "ZAP Multi-Mode Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
