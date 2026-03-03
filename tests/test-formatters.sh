#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Formatter Unit Tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Formatter Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# First normalize a fixture to get input for formatters
FIXTURE="$ROOT_DIR/tests/fixtures/sample-semgrep.json"
NORMALIZED="$TMPDIR/normalized.json"

echo "--- Normalizer Baseline ---"
if bash "$ROOT_DIR/formatters/json-normalizer.sh" --tool semgrep --input "$FIXTURE" --output "$NORMALIZED" 2>/dev/null; then
  pass "Normalizer produced output"
else
  fail "Normalizer failed — cannot test formatters"
  echo "Results: $PASS passed / $FAIL failed"
  exit 1
fi

# ─── SARIF Formatter ───
echo ""
echo "--- SARIF Formatter ---"

SARIF_OUT="$TMPDIR/results.sarif"
if bash "$ROOT_DIR/formatters/sarif-formatter.sh" --input "$NORMALIZED" --output "$SARIF_OUT" 2>/dev/null; then
  pass "SARIF formatter executed"
  if python3 -c "import json; d=json.load(open('$SARIF_OUT')); assert d['version']=='2.1.0'" 2>/dev/null; then
    pass "SARIF version is 2.1.0"
  else
    fail "SARIF version incorrect"
  fi
  if python3 -c "import json; d=json.load(open('$SARIF_OUT')); assert len(d['runs'][0]['results'])>0" 2>/dev/null; then
    pass "SARIF has results"
  else
    fail "SARIF has no results"
  fi
else
  fail "SARIF formatter failed"
fi

# ─── Markdown Formatter ───
echo ""
echo "--- Markdown Formatter ---"

MD_OUT="$TMPDIR/results.md"
if bash "$ROOT_DIR/formatters/markdown-formatter.sh" --input "$NORMALIZED" --output "$MD_OUT" 2>/dev/null; then
  pass "Markdown formatter executed"
  [ -s "$MD_OUT" ] && pass "Markdown output not empty" || fail "Markdown output empty"
  grep -q "Security Scan Results" "$MD_OUT" && pass "Markdown has header" || fail "Markdown missing header"
else
  fail "Markdown formatter failed"
fi

# ─── HTML Formatter ───
echo ""
echo "--- HTML Formatter ---"

HTML_OUT="$TMPDIR/results.html"
if bash "$ROOT_DIR/formatters/html-formatter.sh" --input "$NORMALIZED" --output "$HTML_OUT" 2>/dev/null; then
  pass "HTML formatter executed"
  [ -s "$HTML_OUT" ] && pass "HTML output not empty" || fail "HTML output empty"
  grep -q "<!DOCTYPE html>" "$HTML_OUT" && pass "HTML has doctype" || fail "HTML missing doctype"
  grep -q "DevSecOps" "$HTML_OUT" && pass "HTML has branding" || fail "HTML missing branding"
else
  fail "HTML formatter failed"
fi

# ─── CSV Formatter ───
echo ""
echo "--- CSV Formatter ---"

CSV_OUT="$TMPDIR/results.csv"
if bash "$ROOT_DIR/formatters/csv-formatter.sh" --input "$NORMALIZED" --output "$CSV_OUT" 2>/dev/null; then
  pass "CSV formatter executed"
  [ -s "$CSV_OUT" ] && pass "CSV output not empty" || fail "CSV output empty"
  head -1 "$CSV_OUT" | grep -q "id,source_tool" && pass "CSV has correct headers" || fail "CSV missing headers"
  # Count data rows (total lines minus header)
  CSV_ROWS=$(( $(wc -l < "$CSV_OUT") - 1 ))
  [ "$CSV_ROWS" -gt 0 ] && pass "CSV has $CSV_ROWS data rows" || fail "CSV has no data rows"
else
  fail "CSV formatter failed"
fi

# ─── PDF Formatter ───
echo ""
echo "--- PDF Formatter ---"

# PDF requires pandoc — test conditionally
if command -v pandoc &>/dev/null; then
  PDF_OUT="$TMPDIR/results.pdf"
  if bash "$ROOT_DIR/formatters/pdf-formatter.sh" --input "$NORMALIZED" --output "$PDF_OUT" 2>/dev/null; then
    pass "PDF formatter executed"
    [ -s "$PDF_OUT" ] && pass "PDF output not empty" || fail "PDF output empty"
  else
    fail "PDF formatter failed"
  fi
else
  echo "  [SKIP] pandoc not available — skipping PDF formatter test"
  # Still verify the script exists and handles missing pandoc gracefully
  [ -f "$ROOT_DIR/formatters/pdf-formatter.sh" ] && pass "PDF formatter script exists" || fail "PDF formatter script missing"
fi

# ─── SARIF Per-Tool Output ───
echo ""
echo "--- SARIF Per-Tool Output ---"

MIXED_FIXTURE="$ROOT_DIR/tests/fixtures/sample-mixed-normalized.json"
SARIF_MULTI="$TMPDIR/results-multi.sarif"

if bash "$ROOT_DIR/formatters/sarif-formatter.sh" --input "$MIXED_FIXTURE" --output "$SARIF_MULTI" 2>/dev/null; then
  pass "SARIF per-tool formatter executed"

  # Verify multiple runs
  MULTI_RUN_COUNT=$(python3 -c "import json; d=json.load(open('$SARIF_MULTI')); print(len(d['runs']))" 2>/dev/null)
  [ "$MULTI_RUN_COUNT" -gt 1 ] && pass "SARIF has multiple runs ($MULTI_RUN_COUNT)" || fail "SARIF should have multiple runs, got $MULTI_RUN_COUNT"

  # Verify Semgrep run has 2 results
  SEMGREP_COUNT=$(python3 -c "
import json
d = json.load(open('$SARIF_MULTI'))
for run in d['runs']:
    if run['tool']['driver']['name'] == 'Semgrep':
        print(len(run['results']))
        break
else:
    print(0)
" 2>/dev/null)
  [ "$SEMGREP_COUNT" = "2" ] && pass "Semgrep run has 2 results" || fail "Semgrep run expected 2 results, got $SEMGREP_COUNT"

  # Verify Grype run has 1 result
  GRYPE_COUNT=$(python3 -c "
import json
d = json.load(open('$SARIF_MULTI'))
for run in d['runs']:
    if run['tool']['driver']['name'] == 'Grype':
        print(len(run['results']))
        break
else:
    print(0)
" 2>/dev/null)
  [ "$GRYPE_COUNT" = "1" ] && pass "Grype run has 1 result" || fail "Grype run expected 1 result, got $GRYPE_COUNT"

  # Verify default "DevSecOps AI Team" run has 1 result (finding without source_tool)
  DEFAULT_COUNT=$(python3 -c "
import json
d = json.load(open('$SARIF_MULTI'))
for run in d['runs']:
    if run['tool']['driver']['name'] == 'DevSecOps AI Team':
        print(len(run['results']))
        break
else:
    print(0)
" 2>/dev/null)
  [ "$DEFAULT_COUNT" = "1" ] && pass "Default run has 1 result (no source_tool)" || fail "Default run expected 1 result, got $DEFAULT_COUNT"

  # Verify tool names are proper (not raw tool IDs)
  TOOL_NAMES=$(python3 -c "
import json
d = json.load(open('$SARIF_MULTI'))
names = [run['tool']['driver']['name'] for run in d['runs']]
print(' '.join(names))
" 2>/dev/null)
  echo "$TOOL_NAMES" | grep -q "Semgrep" && pass "Tool name 'Semgrep' is proper (not 'semgrep')" || fail "Tool name not proper: expected 'Semgrep'"
  echo "$TOOL_NAMES" | grep -q "Grype" && pass "Tool name 'Grype' is proper (not 'grype')" || fail "Tool name not proper: expected 'Grype'"
  echo "$TOOL_NAMES" | grep -q "GitLeaks" && pass "Tool name 'GitLeaks' is proper (not 'gitleaks')" || fail "Tool name not proper: expected 'GitLeaks'"
else
  fail "SARIF per-tool formatter failed"
fi

# ─── SARIF --combined flag (backwards compatible) ───
echo ""
echo "--- SARIF Combined Mode ---"

SARIF_COMBINED="$TMPDIR/results-combined.sarif"

if bash "$ROOT_DIR/formatters/sarif-formatter.sh" --input "$MIXED_FIXTURE" --output "$SARIF_COMBINED" --combined 2>/dev/null; then
  pass "SARIF --combined formatter executed"

  COMBINED_RUN_COUNT=$(python3 -c "import json; d=json.load(open('$SARIF_COMBINED')); print(len(d['runs']))" 2>/dev/null)
  [ "$COMBINED_RUN_COUNT" = "1" ] && pass "SARIF --combined produces single run" || fail "SARIF --combined expected 1 run, got $COMBINED_RUN_COUNT"

  COMBINED_RESULT_COUNT=$(python3 -c "import json; d=json.load(open('$SARIF_COMBINED')); print(len(d['runs'][0]['results']))" 2>/dev/null)
  [ "$COMBINED_RESULT_COUNT" = "5" ] && pass "SARIF --combined has all 5 results" || fail "SARIF --combined expected 5 results, got $COMBINED_RESULT_COUNT"

  COMBINED_TOOL_NAME=$(python3 -c "import json; d=json.load(open('$SARIF_COMBINED')); print(d['runs'][0]['tool']['driver']['name'])" 2>/dev/null)
  [ "$COMBINED_TOOL_NAME" = "DevSecOps AI Team" ] && pass "SARIF --combined uses 'DevSecOps AI Team' name" || fail "SARIF --combined wrong tool name: $COMBINED_TOOL_NAME"
else
  fail "SARIF --combined formatter failed"
fi

echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
