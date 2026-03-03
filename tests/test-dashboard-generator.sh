#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Dashboard Generator Tests
# Tests templates/dashboard.html and formatters/dashboard-generator.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "================================================="
echo "DevSecOps AI Team — Dashboard Generator Tests"
echo "================================================="
echo ""

TEMPLATE="$ROOT_DIR/templates/dashboard.html"
GENERATOR="$ROOT_DIR/formatters/dashboard-generator.sh"
SCAN_DB_SCRIPT="$ROOT_DIR/scripts/scan-db.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a06-findings.json"

# Temp dir for test artifacts
TMPDIR_TEST=$(mktemp -d)
trap "rm -rf $TMPDIR_TEST" EXIT

# ═══════════════════════════════════════════
# Section 1: Template (5 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Template ---"

[ -f "$TEMPLATE" ] \
  && pass "templates/dashboard.html exists" \
  || fail "templates/dashboard.html missing"

grep -q "alpinejs" "$TEMPLATE" \
  && pass "Has Alpine.js CDN link" \
  || fail "Missing Alpine.js CDN link"

grep -q "chart.js" "$TEMPLATE" \
  && pass "Has Chart.js CDN link" \
  || fail "Missing Chart.js CDN link"

grep -q "__SCAN_DATA__" "$TEMPLATE" \
  && pass "Has __SCAN_DATA__ placeholder" \
  || fail "Missing __SCAN_DATA__ placeholder"

grep -q "__PIPELINE__" "$TEMPLATE" \
  && pass "Has __PIPELINE__ placeholder" \
  || fail "Missing __PIPELINE__ placeholder"

echo ""

# ═══════════════════════════════════════════
# Section 2: Generator Script (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Generator Script ---"

[ -f "$GENERATOR" ] \
  && pass "formatters/dashboard-generator.sh exists" \
  || fail "formatters/dashboard-generator.sh missing"

[ -x "$GENERATOR" ] \
  && pass "dashboard-generator.sh is executable" \
  || fail "dashboard-generator.sh is not executable"

HELP_OUTPUT=$(bash "$GENERATOR" --help 2>&1 || true)
echo "$HELP_OUTPUT" | grep -qi "Usage" \
  && pass "Shows help with Usage text" \
  || fail "Help output missing Usage text"

echo ""

# ═══════════════════════════════════════════
# Section 3: Generation (5 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Generation ---"

TEST_DB="$TMPDIR_TEST/test-dashboard.db"
TEST_OUTPUT="$TMPDIR_TEST/dashboard-output.html"

# Set up: init DB and store sample findings
SCAN_DB="$TEST_DB" bash "$SCAN_DB_SCRIPT" init >/dev/null 2>&1
SCAN_DB="$TEST_DB" bash "$SCAN_DB_SCRIPT" store "$FIXTURE" >/dev/null 2>&1

# Generate dashboard
GEN_RESULT=0
bash "$GENERATOR" --db "$TEST_DB" --output "$TEST_OUTPUT" >/dev/null 2>&1 || GEN_RESULT=$?

[ "$GEN_RESULT" -eq 0 ] \
  && pass "Generator exits successfully (exit 0)" \
  || fail "Generator failed with exit code $GEN_RESULT"

if [ "$GEN_RESULT" -eq 0 ]; then
  [ -f "$TEST_OUTPUT" ] \
    && pass "Output HTML file exists" \
    || fail "Output HTML file not created"

  grep -q "<html" "$TEST_OUTPUT" \
    && pass "Output contains valid HTML (<html tag)" \
    || fail "Output missing <html tag"

  # Check for scan data — look for severity or findings content
  if grep -qE "severity|findings|semgrep|rule_id" "$TEST_OUTPUT"; then
    pass "Output contains scan data"
  else
    fail "Output missing scan data"
  fi

  grep -q "alpinejs" "$TEST_OUTPUT" \
    && pass "Output contains Alpine.js reference" \
    || fail "Output missing Alpine.js reference"
else
  fail "Output HTML file exists (skipped)"
  fail "Output contains valid HTML (skipped)"
  fail "Output contains scan data (skipped)"
  fail "Output contains Alpine.js reference (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 4: Dark Mode (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Dark Mode ---"

grep -q "\-\-bg-primary" "$TEMPLATE" \
  && pass "Template has CSS variable --bg-primary" \
  || fail "Template missing CSS variable --bg-primary"

grep -qE '\.dark|dark \{' "$TEMPLATE" \
  && pass "Template has dark mode class" \
  || fail "Template missing dark mode class"

echo ""

# ═══════════════════════════════════════════
# Section 5: Panels (6 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: Panels ---"

grep -qiE "pipeline|Pipeline" "$TEMPLATE" \
  && pass "Template has pipeline panel" \
  || fail "Template missing pipeline panel"

grep -qiE "severity|Severity|doughnut|Doughnut" "$TEMPLATE" \
  && pass "Template has severity chart" \
  || fail "Template missing severity chart"

grep -qiE "owasp|OWASP" "$TEMPLATE" \
  && pass "Template has OWASP chart" \
  || fail "Template missing OWASP chart"

grep -qiE "tool|Tool.*Results|toolSummary" "$TEMPLATE" \
  && pass "Template has tool results" \
  || fail "Template missing tool results"

grep -qiE "compliance|Compliance|heatmap" "$TEMPLATE" \
  && pass "Template has compliance section" \
  || fail "Template missing compliance section"

grep -qiE "trend|Trend" "$TEMPLATE" \
  && pass "Template has trend chart" \
  || fail "Template missing trend chart"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "================================================="
TOTAL=$((PASS + FAIL))
echo "Dashboard Generator Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
