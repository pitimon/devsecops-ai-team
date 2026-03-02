#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — DAST Integration Tests
# Tests ZAP fixture parsing, normalizer integration, and DAST skill structure
# Docker-based live scan tests are skipped unless DAST_TARGET is set

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — DAST Integration Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: DAST Skill Structure
# ═══════════════════════════════════════════
echo "--- Section 1: DAST Skill Structure ---"

SKILL_FILE="$ROOT_DIR/skills/dast-scan/SKILL.md"
AGENT_FILE="$ROOT_DIR/agents/specialists/dast-specialist.md"

[ -f "$SKILL_FILE" ] && pass "dast-scan SKILL.md exists" || fail "dast-scan SKILL.md missing"
[ -f "$AGENT_FILE" ] && pass "dast-specialist agent exists" || fail "dast-specialist agent missing"
grep -q 'In-the-Loop' "$SKILL_FILE" && pass "DAST Decision Loop: In-the-Loop" || fail "DAST should be In-the-Loop"
grep -q 'zap' "$SKILL_FILE" && pass "DAST skill references ZAP" || fail "DAST skill should reference ZAP"

# ═══════════════════════════════════════════
# Section 2: ZAP Fixture Validation
# ═══════════════════════════════════════════
echo ""
echo "--- Section 2: ZAP Fixture Validation ---"

FIXTURE="$ROOT_DIR/tests/fixtures/sample-zap.json"
BASELINE="$ROOT_DIR/tests/fixtures/sample-zap-baseline.json"

[ -f "$FIXTURE" ] && pass "sample-zap.json fixture exists" || fail "sample-zap.json fixture missing"
[ -f "$BASELINE" ] && pass "sample-zap-baseline.json fixture exists" || fail "sample-zap-baseline.json fixture missing"

# Validate fixture JSON structure
python3 -c "
import json, sys
d = json.load(open('$FIXTURE'))
assert '@version' in d, 'missing @version'
assert 'site' in d, 'missing site'
assert len(d['site']) > 0, 'empty site array'
assert 'alerts' in d['site'][0], 'missing alerts'
print('OK')
" 2>/dev/null && pass "sample-zap.json: valid ZAP structure" || fail "sample-zap.json: invalid structure"

# Validate baseline fixture
python3 -c "
import json, sys
d = json.load(open('$BASELINE'))
alerts = d['site'][0]['alerts']
assert len(alerts) >= 3, f'expected >=3 alerts, got {len(alerts)}'
risk_codes = set(a['riskcode'] for a in alerts)
assert '2' in risk_codes, 'baseline should have Medium alerts (riskcode 2)'
cwe_ids = [a['cweid'] for a in alerts]
assert any(c != '0' for c in cwe_ids), 'at least one alert should have CWE ID'
print('OK')
" 2>/dev/null && pass "sample-zap-baseline.json: valid baseline (>=3 alerts, has Medium)" || fail "sample-zap-baseline.json: invalid baseline"

# Check baseline has multiple severity levels
python3 -c "
import json
d = json.load(open('$BASELINE'))
alerts = d['site'][0]['alerts']
risk_codes = set(a['riskcode'] for a in alerts)
assert len(risk_codes) >= 2, 'baseline should have at least 2 severity levels'
print('OK')
" 2>/dev/null && pass "baseline has multiple severity levels" || fail "baseline should have multiple severity levels"

# ═══════════════════════════════════════════
# Section 3: ZAP Normalizer Integration
# ═══════════════════════════════════════════
echo ""
echo "--- Section 3: ZAP Normalizer Integration ---"

NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"

[ -f "$NORMALIZER" ] && pass "json-normalizer.sh exists" || fail "json-normalizer.sh missing"

# Test normalizer with ZAP fixture (uses --tool --input --output flags)
if [ -f "$NORMALIZER" ] && command -v python3 &>/dev/null; then
  NORM_FILE="$TMPDIR/zap-normalized.json"
  bash "$NORMALIZER" --tool zap --input "$FIXTURE" --output "$NORM_FILE" 2>/dev/null || true

  if [ -f "$NORM_FILE" ]; then
    python3 -c "
import json, sys
d = json.load(open('$NORM_FILE'))
assert 'findings' in d, 'missing findings'
assert 'summary' in d, 'missing summary'
assert d['summary']['total'] > 0, 'should have findings'
assert d['findings'][0]['source_tool'] == 'zap', f'source_tool should be zap'
print('OK')
" 2>/dev/null && pass "normalizer produces valid ZAP output" || fail "normalizer output invalid for ZAP"

    # Check severity mapping (riskcode 1 maps to a valid severity)
    python3 -c "
import json, sys
d = json.load(open('$NORM_FILE'))
findings = d['findings']
severities = set(f['severity'] for f in findings)
valid = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
assert severities.issubset(valid), f'invalid severities: {severities - valid}'
assert len(severities) > 0, 'should have at least one severity'
print('OK')
" 2>/dev/null && pass "normalizer maps ZAP riskcode to valid severity" || fail "ZAP severity mapping failed"

    # Check CWE extraction
    python3 -c "
import json, sys
d = json.load(open('$NORM_FILE'))
findings = d['findings']
cwe_ids = [f.get('cwe_id', '') for f in findings if f.get('cwe_id')]
assert len(cwe_ids) > 0, 'should extract CWE IDs from ZAP alerts'
assert all(c.startswith('CWE-') for c in cwe_ids), 'CWE IDs should be CWE-NNN format'
print('OK')
" 2>/dev/null && pass "normalizer extracts CWE IDs from ZAP" || fail "CWE extraction from ZAP failed"
  else
    fail "normalizer produced no output file for ZAP"
    fail "normalizer severity mapping (skipped)"
    fail "normalizer CWE extraction (skipped)"
  fi

  # Test normalizer with baseline fixture
  NORM_BASE="$TMPDIR/zap-baseline-normalized.json"
  bash "$NORMALIZER" --tool zap --input "$BASELINE" --output "$NORM_BASE" 2>/dev/null || true
  if [ -f "$NORM_BASE" ]; then
    python3 -c "
import json, sys
d = json.load(open('$NORM_BASE'))
assert d['summary']['total'] >= 3, f'baseline should produce >=3 findings, got {d[\"summary\"][\"total\"]}'
severities = set(f['severity'] for f in d['findings'])
assert 'MEDIUM' in severities, 'baseline should have MEDIUM findings'
print('OK')
" 2>/dev/null && pass "normalizer handles baseline fixture (>=3 findings, has MEDIUM)" || fail "normalizer baseline handling failed"
  else
    fail "normalizer produced no output for baseline"
  fi
else
  for i in 1 2 3 4; do fail "normalizer test $i (skipped — python3 required)"; done
fi

# ═══════════════════════════════════════════
# Section 4: Job Dispatcher ZAP Configuration
# ═══════════════════════════════════════════
echo ""
echo "--- Section 4: Job Dispatcher ZAP Configuration ---"

DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"

[ -f "$DISPATCHER" ] && pass "job-dispatcher.sh exists" || fail "job-dispatcher.sh missing"
grep -q 'zaproxy' "$DISPATCHER" && pass "dispatcher references ZAP image" || fail "dispatcher should reference ZAP image"
grep -q 'zap-baseline' "$DISPATCHER" && pass "dispatcher uses zap-baseline.py" || fail "dispatcher should use zap-baseline.py"
grep -q '\-\-network host' "$DISPATCHER" && pass "dispatcher uses --network host for ZAP" || fail "ZAP needs --network host"

# ═══════════════════════════════════════════
# Section 5: DAST Reference Files
# ═══════════════════════════════════════════
echo ""
echo "--- Section 5: DAST Reference Files ---"

REF_FILE="$ROOT_DIR/skills/references/dast-methodology.md"
[ -f "$REF_FILE" ] && pass "dast-methodology.md reference exists" || fail "dast-methodology.md missing"
grep -q 'ZAP' "$REF_FILE" && pass "reference covers ZAP" || fail "reference should cover ZAP"
grep -q 'baseline' "$REF_FILE" && pass "reference covers baseline scan" || fail "reference should cover baseline scan"

# ═══════════════════════════════════════════
# Section 6: Docker Live Scan (conditional)
# ═══════════════════════════════════════════
echo ""
echo "--- Section 6: Docker Live Scan (conditional) ---"

if [ -n "${DAST_TARGET:-}" ] && command -v docker &>/dev/null; then
  echo "  DAST_TARGET=$DAST_TARGET — running live scan tests"

  # Check ZAP image availability
  if docker images --format '{{.Repository}}' | grep -q zaproxy; then
    pass "ZAP Docker image available"

    # Run ZAP baseline scan
    JOB_OUT=$(bash "$DISPATCHER" --tool zap --target "$DAST_TARGET" --format json 2>"$TMPDIR/zap-stderr.log" || true)
    if echo "$JOB_OUT" | grep -q 'job-'; then
      JOB_ID=$(echo "$JOB_OUT" | grep -o 'job-[a-zA-Z0-9_-]*')
      pass "ZAP scan produced job ID: $JOB_ID"

      # Check results file exists
      RESULTS_DIR="$ROOT_DIR/runner/results/$JOB_ID"
      [ -f "$RESULTS_DIR/zap-results.json" ] && pass "ZAP results file created" || fail "ZAP results file missing"
    else
      fail "ZAP scan did not produce job ID"
      fail "ZAP results file (skipped)"
    fi
  else
    fail "ZAP Docker image not available (pull ghcr.io/zaproxy/zaproxy:stable)"
    fail "ZAP scan (skipped)"
    fail "ZAP results (skipped)"
  fi
else
  echo "  DAST_TARGET not set — skipping live scan (set DAST_TARGET=http://... to enable)"
  pass "live scan tests skipped (no DAST_TARGET)"
fi

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "DAST Integration Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL tests failed"
  exit 1
else
  echo "ALL TESTS PASSED"
fi
