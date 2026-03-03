#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — CI Adapter Tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — CI Adapter Tests"
echo "============================================"
echo ""

# Source the adapter
source "$ROOT_DIR/runner/ci-adapter.sh"

# ─── Platform Detection Tests ───
echo "--- Platform Detection ---"

# Test 1: Local detection (no CI env vars)
unset GITHUB_ACTIONS 2>/dev/null || true
unset GITLAB_CI 2>/dev/null || true
RESULT=$(ci_detect_platform)
[ "$RESULT" = "local" ] && pass "detects local platform" || fail "expected 'local', got '$RESULT'"

# Test 2: GitHub detection
export GITHUB_ACTIONS=true
RESULT=$(ci_detect_platform)
[ "$RESULT" = "github" ] && pass "detects github platform" || fail "expected 'github', got '$RESULT'"
unset GITHUB_ACTIONS

# Test 3: GitLab detection
export GITLAB_CI=true
RESULT=$(ci_detect_platform)
[ "$RESULT" = "gitlab" ] && pass "detects gitlab platform" || fail "expected 'gitlab', got '$RESULT'"
unset GITLAB_CI

# ─── Output Tests ───
echo ""
echo "--- CI Output Functions ---"

# Test 4: Local output format
unset GITHUB_ACTIONS GITLAB_CI 2>/dev/null || true
RESULT=$(ci_set_output "test_key" "test_value")
echo "$RESULT" | grep -q "test_key=test_value" && pass "local output format correct" || fail "local output format wrong"

# Test 5: GitHub output format
export GITHUB_ACTIONS=true
GITHUB_OUTPUT=$(mktemp)
export GITHUB_OUTPUT
ci_set_output "scan_result" "pass"
grep -q "scan_result=pass" "$GITHUB_OUTPUT" && pass "github output written to GITHUB_OUTPUT" || fail "github output not written"
rm -f "$GITHUB_OUTPUT"
unset GITHUB_ACTIONS GITHUB_OUTPUT

# Test 6: GitLab output format
export GITLAB_CI=true
CI_PROJECT_DIR=$(mktemp -d)
export CI_PROJECT_DIR
ci_set_output "scan_result" "pass"
grep -q "scan_result" "$CI_PROJECT_DIR/ci_outputs.env" && pass "gitlab output written to env file" || fail "gitlab output not written"
rm -rf "$CI_PROJECT_DIR"
unset GITLAB_CI CI_PROJECT_DIR

# ─── Artifact Tests ───
echo ""
echo "--- Artifact Upload ---"

# Test 7: Local artifact reporting
unset GITHUB_ACTIONS GITLAB_CI 2>/dev/null || true
RESULT=$(ci_upload_artifact "scan-results" "/tmp/results.json")
echo "$RESULT" | grep -q "scan-results" && pass "local artifact reports name" || fail "local artifact missing name"

# Test 8: GitHub artifact notice
export GITHUB_ACTIONS=true
RESULT=$(ci_upload_artifact "sarif-output" "/tmp/results.sarif")
echo "$RESULT" | grep -q "::notice::" && pass "github artifact uses notice annotation" || fail "github artifact missing notice"
unset GITHUB_ACTIONS

# ─── Failure Tests ───
echo ""
echo "--- Failure Handling ---"

# Test 9: Local failure format
unset GITHUB_ACTIONS GITLAB_CI 2>/dev/null || true
RESULT=$(ci_fail_step "scan failed" 2>&1 || true)
echo "$RESULT" | grep -q "FAIL" && pass "local failure format correct" || fail "local failure format wrong"

# Test 10: GitHub failure annotation
export GITHUB_ACTIONS=true
RESULT=$(ci_fail_step "critical vulnerability found" 2>&1 || true)
echo "$RESULT" | grep -q "::error::" && pass "github failure uses error annotation" || fail "github failure missing error annotation"
unset GITHUB_ACTIONS

# ─── Log Grouping Tests ───
echo ""
echo "--- Log Grouping ---"

# Test 11: Local group format
unset GITHUB_ACTIONS GITLAB_CI 2>/dev/null || true
RESULT=$(ci_group_start "SAST Scan")
echo "$RESULT" | grep -q "SAST Scan" && pass "local group start format" || fail "local group start wrong"

# Test 12: GitHub group format
export GITHUB_ACTIONS=true
RESULT=$(ci_group_start "SCA Scan")
echo "$RESULT" | grep -q "::group::" && pass "github group uses ::group::" || fail "github group wrong"
RESULT=$(ci_group_end)
echo "$RESULT" | grep -q "::endgroup::" && pass "github endgroup correct" || fail "github endgroup wrong"
unset GITHUB_ACTIONS

# ─── Summary Tests ───
echo ""
echo "--- Job Summary ---"

# Test 13: Local summary output
unset GITHUB_ACTIONS GITLAB_CI 2>/dev/null || true
RESULT=$(ci_summary "## Scan Results\n| Tool | Status |\n|------|--------|\n| semgrep | pass |")
echo "$RESULT" | grep -q "Scan Results" && pass "local summary outputs markdown" || fail "local summary wrong"

# Test 14: GitHub summary writes to GITHUB_STEP_SUMMARY
export GITHUB_ACTIONS=true
GITHUB_STEP_SUMMARY=$(mktemp)
export GITHUB_STEP_SUMMARY
ci_summary "## Test Summary"
grep -q "Test Summary" "$GITHUB_STEP_SUMMARY" && pass "github summary written" || fail "github summary not written"
rm -f "$GITHUB_STEP_SUMMARY"
unset GITHUB_ACTIONS GITHUB_STEP_SUMMARY

# ─── Concurrency Groups Tests ───
echo ""
echo "--- Concurrency Groups ---"

# Test 15: Concurrency config is valid JSON
python3 -c "import json; json.load(open('$ROOT_DIR/runner/concurrency-groups.json'))" 2>/dev/null && pass "concurrency-groups.json is valid JSON" || fail "concurrency-groups.json invalid"

# Test 16: Has all 3 groups
GROUP_COUNT=$(python3 -c "import json; d=json.load(open('$ROOT_DIR/runner/concurrency-groups.json')); print(len(d['groups']))" 2>/dev/null)
[ "$GROUP_COUNT" = "3" ] && pass "has 3 concurrency groups" || fail "expected 3 groups, got $GROUP_COUNT"

# Test 17: ZAP is in heavy group
python3 -c "import json; d=json.load(open('$ROOT_DIR/runner/concurrency-groups.json')); assert 'zap' in d['groups']['heavy']['tools']" 2>/dev/null && pass "zap in heavy group" || fail "zap not in heavy group"

# Test 18: Semgrep is in light group
python3 -c "import json; d=json.load(open('$ROOT_DIR/runner/concurrency-groups.json')); assert 'semgrep' in d['groups']['light']['tools']" 2>/dev/null && pass "semgrep in light group" || fail "semgrep not in light group"

# Test 19: All 7 tools covered
TOTAL_TOOLS=$(python3 -c "
import json
d = json.load(open('$ROOT_DIR/runner/concurrency-groups.json'))
tools = []
for g in d['groups'].values():
    tools.extend(g['tools'])
print(len(tools))
" 2>/dev/null)
[ "$TOTAL_TOOLS" = "7" ] && pass "all 7 tools in concurrency groups" || fail "expected 7 tools, got $TOTAL_TOOLS"

# ─── Pipeline Runner Tests ───
echo ""
echo "--- Pipeline Runner ---"

# Test 20: run-pipeline.sh exists and is executable
[ -f "$ROOT_DIR/runner/run-pipeline.sh" ] && pass "run-pipeline.sh exists" || fail "run-pipeline.sh missing"
[ -x "$ROOT_DIR/runner/run-pipeline.sh" ] && pass "run-pipeline.sh is executable" || fail "run-pipeline.sh not executable"

# Test 21: ci-adapter.sh exists and is executable
[ -f "$ROOT_DIR/runner/ci-adapter.sh" ] && pass "ci-adapter.sh exists" || fail "ci-adapter.sh missing"
[ -x "$ROOT_DIR/runner/ci-adapter.sh" ] && pass "ci-adapter.sh is executable" || fail "ci-adapter.sh not executable"

# Test 22: run-pipeline.sh requires --tools
RESULT=$(bash "$ROOT_DIR/runner/run-pipeline.sh" 2>&1 || true)
echo "$RESULT" | grep -qi "usage\|tools\|required" && pass "run-pipeline.sh shows usage without args" || fail "run-pipeline.sh no usage message"

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Results: $PASS passed / $FAIL failed (total $TOTAL checks)"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
