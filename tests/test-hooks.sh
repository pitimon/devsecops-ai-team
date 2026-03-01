#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Hook Functional Tests
# Tests session-start.sh, scan-on-write.sh, pre-commit-gate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Hook Functional Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# session-start.sh tests
# ═══════════════════════════════════════════
echo "--- session-start.sh: Project Detection ---"

SESSION_START="$ROOT_DIR/hooks/session-start.sh"

# Helper: run session-start in a temp project dir and capture output
run_session() {
  local dir="$1"
  (cd "$dir" && bash "$SESSION_START" 2>/dev/null)
}

# Test: package.json → SCA scan recommended
PROJ="$TMPDIR/proj-node"
mkdir -p "$PROJ" && echo '{}' > "$PROJ/package.json"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "sca-scan" && pass "session-start: package.json → /sca-scan recommended" || fail "session-start: package.json should recommend /sca-scan"

# Test: requirements.txt → SCA scan recommended
PROJ="$TMPDIR/proj-python"
mkdir -p "$PROJ" && touch "$PROJ/requirements.txt"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "sca-scan" && pass "session-start: requirements.txt → /sca-scan recommended" || fail "session-start: requirements.txt should recommend /sca-scan"

# Test: Dockerfile → container scan recommended
PROJ="$TMPDIR/proj-docker"
mkdir -p "$PROJ" && touch "$PROJ/Dockerfile"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "container-scan" && pass "session-start: Dockerfile → /container-scan recommended" || fail "session-start: Dockerfile should recommend /container-scan"

# Test: Cargo.toml → SAST scan with Rust rules
PROJ="$TMPDIR/proj-rust"
mkdir -p "$PROJ" && touch "$PROJ/Cargo.toml"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "Rust" && pass "session-start: Cargo.toml → Rust SAST recommended" || fail "session-start: Cargo.toml should recommend Rust SAST"

# Test: .csproj → C# SAST (BUG-9 fix verification)
PROJ="$TMPDIR/proj-csharp"
mkdir -p "$PROJ" && touch "$PROJ/MyApp.csproj"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "C#" && pass "session-start: *.csproj → C# SAST recommended (BUG-9 fix)" || fail "session-start: *.csproj should recommend C# SAST"

# Test: No .csproj → should NOT recommend C#
PROJ="$TMPDIR/proj-empty"
mkdir -p "$PROJ"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "C#" && fail "session-start: empty dir should NOT recommend C# SAST" || pass "session-start: empty dir correctly skips C# detection"

# Test: composer.json → PHP SAST
PROJ="$TMPDIR/proj-php"
mkdir -p "$PROJ" && echo '{}' > "$PROJ/composer.json"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "PHP" && pass "session-start: composer.json → PHP SAST recommended" || fail "session-start: composer.json should recommend PHP SAST"

# Test: .git directory → secret scan
PROJ="$TMPDIR/proj-git"
mkdir -p "$PROJ/.git"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "secret-scan" && pass "session-start: .git → /secret-scan recommended" || fail "session-start: .git should recommend /secret-scan"

# Test: *.tf → IaC scan
PROJ="$TMPDIR/proj-terraform"
mkdir -p "$PROJ" && touch "$PROJ/main.tf"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | grep -q "iac-scan" && pass "session-start: *.tf → /iac-scan recommended" || fail "session-start: *.tf should recommend /iac-scan"

# Test: Output is valid JSON
PROJ="$TMPDIR/proj-json"
mkdir -p "$PROJ"
OUTPUT=$(run_session "$PROJ")
echo "$OUTPUT" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null && pass "session-start: output is valid JSON" || fail "session-start: output is not valid JSON"

# Test: Output contains hookSpecificOutput
echo "$OUTPUT" | python3 -c "
import sys,json
d = json.load(sys.stdin)
assert 'hookSpecificOutput' in d
assert 'additionalContext' in d['hookSpecificOutput']
print('PASS')
" 2>/dev/null | grep -q "PASS" && pass "session-start: output has hookSpecificOutput structure" || fail "session-start: missing hookSpecificOutput structure"

# Test: Runner status in output
echo "$OUTPUT" | grep -q "Runner Status" && pass "session-start: runner status section present" || fail "session-start: runner status section missing"

# ═══════════════════════════════════════════
# scan-on-write.sh tests
# ═══════════════════════════════════════════
echo ""
echo "--- scan-on-write.sh: Secret Detection ---"

SCAN_ON_WRITE="$ROOT_DIR/hooks/scan-on-write.sh"

# Helper: build JSON input for Write tool (compact JSON — no spaces after colons,
# matching the format scan-on-write.sh grep expects)
build_write_input() {
  local content="$1"
  python3 -c "
import json, sys
d = {'tool_name': 'Write', 'tool_input': {'file_path': '/tmp/test.txt', 'content': sys.argv[1]}}
print(json.dumps(d, separators=(',', ':')))
" "$content"
}

# Test: AWS access key blocks (construct pattern at runtime to avoid hook)
AWS_PREFIX="AKIA"
AWS_SUFFIX="IOSFODNN7EXAMPLE"
INPUT=$(build_write_input "const key = \"${AWS_PREFIX}${AWS_SUFFIX}\";")
EXIT_CODE=0
echo "$INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "scan-on-write: AWS key (AKIA...) blocked (exit 2)" || fail "scan-on-write: AWS key should exit 2, got $EXIT_CODE"

# Test: GitHub token blocks (construct at runtime)
GHP_PREFIX="ghp_"
GHP_SUFFIX="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
INPUT=$(build_write_input "const token = \"${GHP_PREFIX}${GHP_SUFFIX}\";")
EXIT_CODE=0
echo "$INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "scan-on-write: GitHub token (ghp_) blocked (exit 2)" || fail "scan-on-write: ghp_ should exit 2, got $EXIT_CODE"

# Test: Slack token blocks (construct at runtime)
SLACK_PREFIX="xoxb-"
SLACK_SUFFIX="1234567890-abcdefghij"
INPUT=$(build_write_input "const token = \"${SLACK_PREFIX}${SLACK_SUFFIX}\";")
EXIT_CODE=0
echo "$INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "scan-on-write: Slack token (xoxb-) blocked (exit 2)" || fail "scan-on-write: xoxb- should exit 2, got $EXIT_CODE"

# Test: Clean code allows
INPUT=$(build_write_input 'const greeting = "Hello, World!";')
EXIT_CODE=0
echo "$INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "scan-on-write: clean code allowed (exit 0)" || fail "scan-on-write: clean code should exit 0, got $EXIT_CODE"

# Test: Edit tool input works (construct at runtime)
EDIT_INPUT=$(python3 -c "
import json
d = {'tool_name': 'Edit', 'tool_input': {'file_path': '/tmp/test.txt', 'old_string': 'x', 'new_string': 'AKIA' + 'IOSFODNN7EXAMPLE'}}
print(json.dumps(d, separators=(',', ':')))
")
EXIT_CODE=0
echo "$EDIT_INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "scan-on-write: Edit tool — AWS key in new_string blocked" || fail "scan-on-write: Edit tool AWS key should exit 2, got $EXIT_CODE"

# Test: Unknown tool passes through
UNKNOWN_INPUT='{"tool_name":"Bash","tool_input":{"command":"ls"}}'
EXIT_CODE=0
echo "$UNKNOWN_INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "scan-on-write: unknown tool name passes (exit 0)" || fail "scan-on-write: unknown tool should exit 0, got $EXIT_CODE"

# Test: Empty content passes
EMPTY_INPUT='{"tool_name":"Write","tool_input":{"file_path":"/tmp/test.txt","content":""}}'
EXIT_CODE=0
echo "$EMPTY_INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "scan-on-write: empty content passes (exit 0)" || fail "scan-on-write: empty content should exit 0, got $EXIT_CODE"

# Test: Injection patterns warn but don't block
INPUT=$(build_write_input 'result = eval(user_input)')
EXIT_CODE=0
echo "$INPUT" | bash "$SCAN_ON_WRITE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "scan-on-write: injection pattern warns but allows (exit 0)" || fail "scan-on-write: injection should warn not block, got $EXIT_CODE"

# ═══════════════════════════════════════════
# pre-commit-gate.sh tests
# ═══════════════════════════════════════════
echo ""
echo "--- pre-commit-gate.sh: Commit Gate ---"

PRE_COMMIT_GATE="$ROOT_DIR/hooks/pre-commit-gate.sh"

# Helper: build JSON input for git commit
build_commit_input() {
  python3 -c "
import json
d = {'tool_name': 'Bash', 'tool_input': {'command': 'git commit -m \"test\"'}}
print(json.dumps(d, separators=(',', ':')))
"
}

# Test: No results dir — allows commit
PROJ="$TMPDIR/gate-no-results"
mkdir -p "$PROJ"
INPUT=$(build_commit_input)
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "pre-commit-gate: no results dir → allow commit" || fail "pre-commit-gate: no results should allow, got $EXIT_CODE"

# Test: Empty results dir — allows commit
PROJ="$TMPDIR/gate-empty-results"
mkdir -p "$PROJ/.devsecops/results"
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "pre-commit-gate: empty results dir → allow commit" || fail "pre-commit-gate: empty results should allow, got $EXIT_CODE"

# Test: CRITICAL findings — blocks commit
PROJ="$TMPDIR/gate-critical"
mkdir -p "$PROJ/.devsecops/results"
cat > "$PROJ/.devsecops/results/scan.json" << 'FIXTURE'
{"findings": [{"severity": "CRITICAL"}], "summary": {"critical": 2, "high": 1}}
FIXTURE
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "pre-commit-gate: CRITICAL findings → block commit (exit 2)" || fail "pre-commit-gate: CRITICAL should block, got $EXIT_CODE"

# Test: No CRITICAL findings — allows commit
PROJ="$TMPDIR/gate-high-only"
mkdir -p "$PROJ/.devsecops/results"
cat > "$PROJ/.devsecops/results/scan.json" << 'FIXTURE'
{"findings": [{"severity": "HIGH"}], "summary": {"critical": 0, "high": 3}}
FIXTURE
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "pre-commit-gate: HIGH-only findings → allow commit" || fail "pre-commit-gate: HIGH-only should allow, got $EXIT_CODE"

# Test: Non-commit command — passes through
NON_COMMIT='{"tool_name":"Bash","tool_input":{"command":"git status"}}'
EXIT_CODE=0
echo "$NON_COMMIT" | bash "$PRE_COMMIT_GATE" 2>/dev/null || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "pre-commit-gate: git status → pass through (exit 0)" || fail "pre-commit-gate: git status should pass, got $EXIT_CODE"

# Test: Multiple result files — accumulates critical count
PROJ="$TMPDIR/gate-multi"
mkdir -p "$PROJ/.devsecops/results"
echo '{"summary": {"critical": 1}}' > "$PROJ/.devsecops/results/scan1.json"
echo '{"summary": {"critical": 2}}' > "$PROJ/.devsecops/results/scan2.json"
INPUT=$(build_commit_input)
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "2" ] && pass "pre-commit-gate: multiple files accumulate CRITICAL count" || fail "pre-commit-gate: multi-file should accumulate, got $EXIT_CODE"

# Test: Malformed JSON in results — doesn't crash
PROJ="$TMPDIR/gate-malformed"
mkdir -p "$PROJ/.devsecops/results"
echo 'not-json' > "$PROJ/.devsecops/results/bad.json"
INPUT=$(build_commit_input)
EXIT_CODE=0
(cd "$PROJ" && echo "$INPUT" | bash "$PRE_COMMIT_GATE" 2>/dev/null) || EXIT_CODE=$?
[ "$EXIT_CODE" = "0" ] && pass "pre-commit-gate: malformed JSON → allow (graceful)" || fail "pre-commit-gate: malformed JSON should not crash, got $EXIT_CODE"

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
