#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Formatter Unit Tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { ((PASS++)); echo "  [PASS] $1"; }
fail() { ((FAIL++)); echo "  [FAIL] $1"; }

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

echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
