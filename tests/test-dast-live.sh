#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — DAST Live Testing
# Conditional tests that run only when DAST_TARGET is set
# Tests ZAP baseline/full scans against a real target
#
# Usage: DAST_TARGET=http://example.com bash tests/test-dast-live.sh
# Full scan: DAST_TARGET=http://example.com DAST_FULL=1 bash tests/test-dast-live.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
skip() { SKIP=$((SKIP + 1)); echo "  [SKIP] $1"; }

echo "============================================"
echo "DevSecOps AI Team — DAST Live Tests"
echo "============================================"
echo ""

# ═══════════════════════════════════════════
# Guard: Skip all if DAST_TARGET not set
# ═══════════════════════════════════════════
if [ -z "${DAST_TARGET:-}" ]; then
  echo "DAST_TARGET not set — skipping all live DAST tests."
  echo "Usage: DAST_TARGET=http://example.com bash $0"
  echo ""
  echo "============================================"
  echo "DAST Live Tests: 0/0 passed (15 skipped)"
  echo "RESULT: SKIPPED (no DAST_TARGET)"
  echo "============================================"
  exit 0
fi

echo "DAST_TARGET: $DAST_TARGET"
echo ""

# Guard: Skip if Docker not available
if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
  echo "Docker not available — skipping all live DAST tests."
  echo ""
  echo "============================================"
  echo "DAST Live Tests: 0/0 passed (15 skipped)"
  echo "RESULT: SKIPPED (no Docker)"
  echo "============================================"
  exit 0
fi

DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Target Reachability
# ═══════════════════════════════════════════
echo "--- Section 1: Target Reachability ---"

HTTP_CODE=$(curl -sI -o /dev/null -w "%{http_code}" --max-time 10 "$DAST_TARGET" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "000" ]; then
  pass "Target reachable (HTTP $HTTP_CODE)"
else
  fail "Target unreachable"
  echo "Cannot proceed without reachable target."
  exit 1
fi

echo ""

# ═══════════════════════════════════════════
# Section 2: ZAP Baseline Scan
# ═══════════════════════════════════════════
echo "--- Section 2: ZAP Baseline Scan ---"

BASELINE_DIR="$TMPDIR/baseline"
mkdir -p "$BASELINE_DIR"

# Run baseline scan with short timeout
timeout 180 docker run --rm \
  -v "$BASELINE_DIR:/results" --network host \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t "$DAST_TARGET" -J /results/zap-results.json 2>/dev/null \
  && BASELINE_EXIT=0 || BASELINE_EXIT=$?

# ZAP baseline returns 0 (pass), 1 (warnings), 2 (fail) — all are valid
if [ "$BASELINE_EXIT" -le 2 ]; then
  pass "ZAP baseline scan completed (exit: $BASELINE_EXIT)"
else
  fail "ZAP baseline scan failed (exit: $BASELINE_EXIT)"
fi

# Check results file generated
if [ -f "$BASELINE_DIR/zap-results.json" ]; then
  pass "Baseline results file generated"

  # Validate JSON structure
  python3 -c "
import json, sys
with open('$BASELINE_DIR/zap-results.json') as f:
    data = json.load(f)
if 'site' in data:
    sys.exit(0)
sys.exit(1)
" && pass "Baseline results valid JSON with site key" || fail "Baseline results invalid JSON"

  # Check severity distribution
  python3 -c "
import json
with open('$BASELINE_DIR/zap-results.json') as f:
    data = json.load(f)
total_alerts = 0
for site in data.get('site', []):
    total_alerts += len(site.get('alerts', []))
print(f'  [INFO] Baseline found {total_alerts} alert(s)')
" 2>/dev/null
  pass "Baseline severity distribution analyzed"
else
  fail "Baseline results file not generated"
  skip "Baseline JSON validation (no file)"
  skip "Baseline severity distribution (no file)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 3: NCSA Validator Against Live Target
# ═══════════════════════════════════════════
echo "--- Section 3: NCSA Validation ---"

NCSA_OUTPUT="$TMPDIR/ncsa-report.json"
bash "$ROOT_DIR/scripts/dast-ncsa-validator.sh" \
  --target "$DAST_TARGET" \
  --output "$NCSA_OUTPUT" 2>/dev/null \
  && NCSA_EXIT=0 || NCSA_EXIT=$?

# Validator exits 1 if any checks fail — that's expected for many targets
if [ -f "$NCSA_OUTPUT" ]; then
  pass "NCSA validator produced report"

  python3 -c "
import json, sys
with open('$NCSA_OUTPUT') as f:
    data = json.load(f)
s = data['summary']
print(f'  [INFO] NCSA: {s[\"pass\"]} pass, {s[\"fail\"]} fail, {s[\"warning\"]} warn')
cats = data.get('categories_validated', [])
if '1.x' in cats and '2.x' in cats and '4.x' in cats:
    sys.exit(0)
sys.exit(1)
" && pass "NCSA report covers categories 1.x, 2.x, 4.x" || fail "NCSA report missing categories"
else
  fail "NCSA validator did not produce report"
  skip "NCSA category coverage (no report)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 4: ZAP Full Scan (conditional on DAST_FULL=1)
# ═══════════════════════════════════════════
echo "--- Section 4: ZAP Full Scan (conditional) ---"

if [ "${DAST_FULL:-}" = "1" ]; then
  FULL_DIR="$TMPDIR/full"
  mkdir -p "$FULL_DIR"

  echo "  Running full scan (this may take 10-30 minutes)..."
  timeout 1800 docker run --rm \
    -v "$FULL_DIR:/results" --network host \
    ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t "$DAST_TARGET" -J /results/zap-results.json -a -j 2>/dev/null \
    && FULL_EXIT=0 || FULL_EXIT=$?

  if [ "$FULL_EXIT" -le 2 ]; then
    pass "ZAP full scan completed (exit: $FULL_EXIT)"
  else
    fail "ZAP full scan failed (exit: $FULL_EXIT)"
  fi

  if [ -f "$FULL_DIR/zap-results.json" ]; then
    pass "Full scan results file generated"

    python3 -c "
import json
with open('$FULL_DIR/zap-results.json') as f:
    data = json.load(f)
total = 0
for site in data.get('site', []):
    total += len(site.get('alerts', []))
print(f'  [INFO] Full scan found {total} alert(s)')
"
    pass "Full scan results analyzed"
  else
    fail "Full scan results file not generated"
    skip "Full scan analysis (no file)"
  fi
else
  skip "Full scan (set DAST_FULL=1 to enable)"
  skip "Full scan results (skipped)"
  skip "Full scan analysis (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 5: Normalizer Integration
# ═══════════════════════════════════════════
echo "--- Section 5: Normalizer Integration ---"

NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
if [ -f "$BASELINE_DIR/zap-results.json" ] && [ -f "$NORMALIZER" ]; then
  bash "$NORMALIZER" --tool zap --input "$BASELINE_DIR/zap-results.json" --output "$TMPDIR/normalized.json" 2>/dev/null \
    && pass "Normalizer processed live ZAP output" \
    || fail "Normalizer failed on live ZAP output"
else
  skip "Normalizer integration (missing files)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 6: Gate Evaluation
# ═══════════════════════════════════════════
echo "--- Section 6: Gate Evaluation ---"

if [ -f "$TMPDIR/normalized.json" ]; then
  python3 -c "
import json, sys
with open('$TMPDIR/normalized.json') as f:
    data = json.load(f)
findings = data.get('findings', [])
critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
high = sum(1 for f in findings if f.get('severity') == 'HIGH')
print(f'  [INFO] Gate input: {len(findings)} findings ({critical} CRITICAL, {high} HIGH)')
" && pass "Gate evaluation data available" || fail "Gate evaluation failed"
else
  skip "Gate evaluation (no normalized data)"
fi

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "DAST Live Tests: $PASS/$TOTAL passed ($SKIP skipped)"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
