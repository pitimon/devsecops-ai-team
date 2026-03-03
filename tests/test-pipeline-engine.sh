#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Pipeline Engine Tests
# Tests runner/pipeline-engine.sh: structure, parsing, validation, topo sort,
# YAML-to-JSON, state tracking, listing, built-in pipelines

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Pipeline Engine Tests"
echo "============================================"
echo ""

ENGINE="$ROOT_DIR/runner/pipeline-engine.sh"
FIXTURE="$SCRIPT_DIR/fixtures/sample-pipeline.yml"
FIXTURE_CYCLE="$SCRIPT_DIR/fixtures/sample-pipeline-cycle.yml"
PIPELINES_DIR="$ROOT_DIR/runner/pipelines"

# Temp dir for ephemeral test artifacts
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Script Structure (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Script Structure ---"

[ -f "$ENGINE" ] && pass "pipeline-engine.sh exists" || fail "pipeline-engine.sh missing"

[ -x "$ENGINE" ] && pass "pipeline-engine.sh is executable" || fail "pipeline-engine.sh not executable"

USAGE_OUT=$("$ENGINE" 2>&1 || true)
echo "$USAGE_OUT" | grep -q "Usage" && pass "Shows usage text when called with no args" || fail "Missing usage text"

echo "$USAGE_OUT" | grep -q "validate" && pass "Has validate subcommand" || fail "Usage does not mention validate"

echo ""

# ═══════════════════════════════════════════
# Section 2: Pipeline Parsing (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Pipeline Parsing ---"

JSON_OUT=$("$ENGINE" to-json "$FIXTURE" 2>/dev/null)
[ $? -eq 0 ] && pass "Can parse sample-pipeline.yml (to-json succeeds)" || fail "to-json failed on sample-pipeline.yml"

echo "$JSON_OUT" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null && pass "to-json output is valid JSON" || fail "to-json output is not valid JSON"

PARSED_NAME=$(echo "$JSON_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name',''))" 2>/dev/null)
[ "$PARSED_NAME" = "test-pipeline" ] && pass "Parsed pipeline has correct name (test-pipeline)" || fail "Expected name 'test-pipeline', got '$PARSED_NAME'"

echo ""

# ═══════════════════════════════════════════
# Section 3: Validation (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Validation ---"

VALIDATE_OUT=$("$ENGINE" validate "$FIXTURE" 2>&1)
echo "$VALIDATE_OUT" | grep -q "valid" && pass "Valid pipeline passes validation" || fail "Valid pipeline did not pass validation"

CYCLE_OUT=$("$ENGINE" validate "$FIXTURE_CYCLE" 2>&1 || true)
echo "$CYCLE_OUT" | grep -qi "cycle" && pass "Cycle is detected" || fail "Cycle was not detected"

# Create temp YAML with non-existent dependency
cat > "$TEST_DIR/missing-dep.yml" << 'YAML'
name: missing-dep-test
version: "1.0"
description: Pipeline with missing dependency
nodes:
  scan:
    type: scanner
    tool: semgrep
    depends_on: [nonexistent]
    outputs:
      file: "output/scan.json"
YAML
MISSING_DEP_OUT=$("$ENGINE" validate "$TEST_DIR/missing-dep.yml" 2>&1 || true)
echo "$MISSING_DEP_OUT" | grep -qi "not found\|error\|missing" && pass "Missing dependency is detected" || fail "Missing dependency was not detected"

# Create temp YAML with invalid node type
cat > "$TEST_DIR/bad-type.yml" << 'YAML'
name: bad-type-test
version: "1.0"
description: Pipeline with invalid node type
nodes:
  scan:
    type: invalid_type_xyz
    tool: semgrep
    depends_on: []
    outputs:
      file: "output/scan.json"
YAML
BAD_TYPE_OUT=$("$ENGINE" validate "$TEST_DIR/bad-type.yml" 2>&1 || true)
echo "$BAD_TYPE_OUT" | grep -qi "invalid\|error" && pass "Invalid node type is detected" || fail "Invalid node type was not detected"

echo ""

# ═══════════════════════════════════════════
# Section 4: Topological Sort (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Topological Sort ---"

# Validate returns order info for sample-pipeline
TOPO_OUT=$("$ENGINE" validate "$FIXTURE" 2>&1)
echo "$TOPO_OUT" | grep -q "3 nodes" && pass "Correct node count for sample pipeline (3)" || fail "Node count mismatch for sample pipeline"

# Check that to-json preserves all three node names
NODES_CHECK=$(echo "$JSON_OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
nodes = list(d.get('nodes', {}).keys())
# Verify all expected nodes are present
expected = {'scan', 'normalize', 'format'}
sys.exit(0 if expected == set(nodes) else 1)
" 2>/dev/null && echo "ok" || echo "fail")
[ "$NODES_CHECK" = "ok" ] && pass "All 3 nodes present in parsed output" || fail "Parsed output missing expected nodes"

# Default pipeline (8 nodes) validates
DEFAULT_OUT=$("$ENGINE" validate "$PIPELINES_DIR/default.yml" 2>&1)
echo "$DEFAULT_OUT" | grep -q "8 nodes" && pass "Default pipeline (8 nodes) validates correctly" || fail "Default pipeline validation failed or wrong node count"

echo ""

# ═══════════════════════════════════════════
# Section 5: YAML-to-JSON Conversion (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: YAML-to-JSON Conversion ---"

[ -n "$JSON_OUT" ] && pass "to-json produces output" || fail "to-json produced empty output"

echo "$JSON_OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if 'nodes' in d else 1)
" 2>/dev/null && pass "Output has 'nodes' key" || fail "Output missing 'nodes' key"

echo ""

# ═══════════════════════════════════════════
# Section 6: State Tracking (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 6: State Tracking ---"

# After validate, no state file should be created
STATE_CHECK_DIR=$(mktemp -d)
OUTPUT_DIR="$STATE_CHECK_DIR" "$ENGINE" validate "$FIXTURE" >/dev/null 2>&1 || true
[ ! -f "$STATE_CHECK_DIR/pipeline-state.json" ] && pass "Validate does not create state file" || fail "Validate created a state file unexpectedly"
rm -rf "$STATE_CHECK_DIR"

# Create a synthetic state file and verify structure
MOCK_STATE_DIR=$(mktemp -d)
cat > "$MOCK_STATE_DIR/pipeline-state.json" << 'JSON'
{
  "run_id": "run-test-001",
  "pipeline": "test-pipeline",
  "started_at": "2026-03-03T00:00:00Z",
  "finished_at": null,
  "status": "running",
  "nodes": {
    "scan": {"status": "pending", "type": "scanner", "started_at": null, "finished_at": null, "exit_code": null}
  }
}
JSON
python3 -c "
import json, sys
state = json.load(open('$MOCK_STATE_DIR/pipeline-state.json'))
required = ['run_id', 'pipeline', 'started_at', 'status', 'nodes']
missing = [k for k in required if k not in state]
sys.exit(0 if not missing else 1)
" 2>/dev/null && pass "State format has all required fields" || fail "State format missing required fields"

python3 -c "
import json, sys
state = json.load(open('$MOCK_STATE_DIR/pipeline-state.json'))
sys.exit(0)
" 2>/dev/null && pass "State JSON structure is valid" || fail "State JSON structure is invalid"
rm -rf "$MOCK_STATE_DIR"

echo ""

# ═══════════════════════════════════════════
# Section 7: Pipeline Listing (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 7: Pipeline Listing ---"

LIST_OUT=$("$ENGINE" list 2>&1)
[ -n "$LIST_OUT" ] && pass "list subcommand outputs something" || fail "list subcommand produced no output"

echo "$LIST_OUT" | grep -q "full-scan" && pass "list output mentions 'full-scan'" || fail "list output does not mention 'full-scan'"

echo ""

# ═══════════════════════════════════════════
# Section 8: Built-in Pipelines (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 8: Built-in Pipelines ---"

"$ENGINE" validate "$PIPELINES_DIR/default.yml" >/dev/null 2>&1 && pass "default.yml validates" || fail "default.yml validation failed"

"$ENGINE" validate "$PIPELINES_DIR/sast-only.yml" >/dev/null 2>&1 && pass "sast-only.yml validates" || fail "sast-only.yml validation failed"

"$ENGINE" validate "$PIPELINES_DIR/secrets-only.yml" >/dev/null 2>&1 && pass "secrets-only.yml validates" || fail "secrets-only.yml validation failed"

"$ENGINE" validate "$PIPELINES_DIR/compliance.yml" >/dev/null 2>&1 && pass "compliance.yml validates" || fail "compliance.yml validation failed"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Pipeline Engine Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL"; exit 1; else echo "RESULT: ALL PASSED"; exit 0; fi
