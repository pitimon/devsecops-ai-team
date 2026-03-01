#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Runner Integration Tests
# Tests the json-normalizer with sample fixtures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { ((PASS++)); echo "  [PASS] $1"; }
fail() { ((FAIL++)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Runner Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ─── Test JSON Normalizer ───
echo "--- JSON Normalizer Tests ---"

for TOOL in semgrep gitleaks grype trivy checkov zap; do
  FIXTURE="$ROOT_DIR/tests/fixtures/sample-${TOOL}.json"
  OUTPUT="$TMPDIR/normalized-${TOOL}.json"

  if [ ! -f "$FIXTURE" ]; then
    fail "Fixture missing: sample-${TOOL}.json"
    continue
  fi

  if bash "$ROOT_DIR/formatters/json-normalizer.sh" --tool "$TOOL" --input "$FIXTURE" --output "$OUTPUT" 2>/dev/null; then
    if [ -f "$OUTPUT" ]; then
      # Verify it's valid JSON
      if python3 -c "import json; json.load(open('$OUTPUT'))" 2>/dev/null; then
        pass "$TOOL normalizer produces valid JSON"

        # Check for required fields
        HAS_FINDINGS=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print('yes' if 'findings' in d else 'no')" 2>/dev/null)
        [ "$HAS_FINDINGS" = "yes" ] && pass "$TOOL output has 'findings' field" || fail "$TOOL output missing 'findings'"

        HAS_SUMMARY=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print('yes' if 'summary' in d else 'no')" 2>/dev/null)
        [ "$HAS_SUMMARY" = "yes" ] && pass "$TOOL output has 'summary' field" || fail "$TOOL output missing 'summary'"

        FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT')).get('findings', [])))" 2>/dev/null)
        [ "$FINDING_COUNT" -gt 0 ] && pass "$TOOL has $FINDING_COUNT findings" || fail "$TOOL has 0 findings"
      else
        fail "$TOOL normalizer produces invalid JSON"
      fi
    else
      fail "$TOOL normalizer did not create output file"
    fi
  else
    fail "$TOOL normalizer failed"
  fi
done

# ─── Test Job Dispatcher (syntax only) ───
echo ""
echo "--- Job Dispatcher Tests ---"

[ -f "$ROOT_DIR/runner/job-dispatcher.sh" ] && pass "job-dispatcher.sh exists" || fail "job-dispatcher.sh missing"
bash -n "$ROOT_DIR/runner/job-dispatcher.sh" 2>/dev/null && pass "job-dispatcher.sh syntax valid" || fail "job-dispatcher.sh syntax error"

# ─── Test Result Collector (syntax only) ───
echo ""
echo "--- Result Collector Tests ---"

[ -f "$ROOT_DIR/runner/result-collector.sh" ] && pass "result-collector.sh exists" || fail "result-collector.sh missing"
bash -n "$ROOT_DIR/runner/result-collector.sh" 2>/dev/null && pass "result-collector.sh syntax valid" || fail "result-collector.sh syntax error"

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
