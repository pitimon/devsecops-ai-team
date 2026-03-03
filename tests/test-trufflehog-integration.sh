#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — TruffleHog Integration Tests
# Tests TruffleHog Docker service, job dispatcher, normalizer, and skill integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "================================================="
echo "DevSecOps AI Team — TruffleHog Integration Tests"
echo "================================================="
echo ""

COMPOSE="$ROOT_DIR/runner/docker-compose.yml"
DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-trufflehog.json"
SKILL="$ROOT_DIR/skills/secret-scan/SKILL.md"

# ═══════════════════════════════════════════
# Section 1: Docker Compose (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Docker Compose ---"

grep -q "trufflehog:" "$COMPOSE" \
  && pass "trufflehog service exists in docker-compose.yml" \
  || fail "trufflehog service missing from docker-compose.yml"

grep -A5 "trufflehog:" "$COMPOSE" | grep -q "trufflesecurity/trufflehog" \
  && pass "trufflehog uses trufflesecurity/trufflehog image" \
  || fail "trufflehog has wrong image"

grep -A10 "trufflehog:" "$COMPOSE" | grep -q "trufflehog" | head -1
# Check the profiles line contains trufflehog
python3 -c "
import sys
with open('$COMPOSE') as f:
    content = f.read()
# Find the trufflehog service block
start = content.find('trufflehog:')
if start < 0:
    sys.exit(1)
section = content[start:start+300]
if 'trufflehog' in section and 'profiles' in section:
    sys.exit(0)
sys.exit(1)
" && pass "trufflehog has correct profile" \
  || fail "trufflehog missing profile configuration"

echo ""

# ═══════════════════════════════════════════
# Section 2: Job Dispatcher (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Job Dispatcher ---"

grep -q "run_trufflehog" "$DISPATCHER" \
  && pass "run_trufflehog function exists in job-dispatcher.sh" \
  || fail "run_trufflehog function missing from job-dispatcher.sh"

grep -q "TRUFFLEHOG_MODE.*git\|git)" "$DISPATCHER" \
  && pass "run_trufflehog supports git mode" \
  || fail "run_trufflehog missing git mode"

grep -q "filesystem)" "$DISPATCHER" \
  && pass "run_trufflehog supports filesystem mode" \
  || fail "run_trufflehog missing filesystem mode"

grep -q "trufflehog).*run_trufflehog\|trufflehog) " "$DISPATCHER" \
  && pass "trufflehog in run_tool() case statement" \
  || fail "trufflehog missing from run_tool() case statement"

echo ""

# ═══════════════════════════════════════════
# Section 3: Normalizer (5 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Normalizer ---"

grep -q "trufflehog)" "$NORMALIZER" \
  && pass "trufflehog case exists in json-normalizer.sh" \
  || fail "trufflehog case missing from json-normalizer.sh"

# Run normalizer against fixture
TMPDIR_TEST=$(mktemp -d)
trap "rm -rf $TMPDIR_TEST" EXIT
OUTPUT="$TMPDIR_TEST/trufflehog-normalized.json"

if bash "$NORMALIZER" --tool trufflehog --input "$FIXTURE" --output "$OUTPUT" 2>/dev/null; then
  # Test: output is valid JSON
  if python3 -c "import json; json.load(open('$OUTPUT'))" 2>/dev/null; then
    pass "Normalizer produces valid JSON output"
  else
    fail "Normalizer produces invalid JSON output"
  fi

  # Test: has findings array
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
if 'findings' not in data or not isinstance(data['findings'], list):
    sys.exit(1)
sys.exit(0)
" 2>/dev/null \
    && pass "Output has findings array" \
    || fail "Output missing findings array"

  # Test: has 3 findings
  FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT')).get('findings', [])))" 2>/dev/null)
  [ "$FINDING_COUNT" -eq 3 ] \
    && pass "Output has 3 findings (got $FINDING_COUNT)" \
    || fail "Expected 3 findings, got ${FINDING_COUNT:-0}"

  # Test: first finding has source_tool=trufflehog
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
if data['findings'][0].get('source_tool') != 'trufflehog':
    sys.exit(1)
sys.exit(0)
" 2>/dev/null \
    && pass "First finding has source_tool=trufflehog" \
    || fail "First finding source_tool is not trufflehog"

  # Test: findings have verified field
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
for f in data['findings']:
    if 'verified' not in f:
        sys.exit(1)
sys.exit(0)
" 2>/dev/null \
    && pass "Findings have verified field" \
    || fail "Findings missing verified field"

else
  fail "Normalizer failed on fixture"
  fail "Output has findings array (skipped)"
  fail "Output has 3 findings (skipped)"
  fail "First finding has source_tool=trufflehog (skipped)"
  fail "Findings have verified field (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 4: Skill Definition (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Skill Definition ---"

grep -qi "trufflehog" "$SKILL" \
  && pass "secret-scan/SKILL.md mentions trufflehog" \
  || fail "secret-scan/SKILL.md does not mention trufflehog"

grep -q "\-\-tool" "$SKILL" \
  && pass "SKILL.md has --tool option" \
  || fail "SKILL.md missing --tool option"

grep -qi "dedup" "$SKILL" \
  && pass "SKILL.md mentions dedup" \
  || fail "SKILL.md does not mention dedup"

echo ""

# ═══════════════════════════════════════════
# Section 5: Fixture Validation (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: Fixture Validation ---"

[ -f "$FIXTURE" ] \
  && pass "sample-trufflehog.json fixture exists" \
  || fail "sample-trufflehog.json fixture missing"

# Validate each line is valid JSON
python3 -c "
import json, sys
errors = []
with open('$FIXTURE') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f'Line {i}: {e}')
if errors:
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Each line is valid JSON (JSONL format)" \
  || fail "Some lines are invalid JSON"

# Validate DetectorName field exists in each line
python3 -c "
import json, sys
with open('$FIXTURE') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if 'DetectorName' not in obj:
            print(f'Line {i}: missing DetectorName', file=sys.stderr)
            sys.exit(1)
sys.exit(0)
" && pass "Each line has DetectorName field" \
  || fail "Some lines missing DetectorName field"

echo ""

# ═══════════════════════════════════════════
# Section 6: Dedup Compatibility (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 6: Dedup Compatibility ---"

if [ -f "$OUTPUT" ]; then
  # Test: findings have rule_id field
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
for f in data['findings']:
    if 'rule_id' not in f or not f['rule_id']:
        print(f'Finding {f.get(\"id\",\"?\")} missing rule_id', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" 2>/dev/null \
    && pass "Findings have rule_id (needed by dedup)" \
    || fail "Findings missing rule_id"

  # Test: findings have location.file and location.line_start
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
for f in data['findings']:
    loc = f.get('location', {})
    if 'file' not in loc:
        print(f'Finding {f.get(\"id\",\"?\")} missing location.file', file=sys.stderr)
        sys.exit(1)
    if 'line_start' not in loc:
        print(f'Finding {f.get(\"id\",\"?\")} missing location.line_start', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" 2>/dev/null \
    && pass "Findings have location.file and location.line_start (needed by dedup)" \
    || fail "Findings missing location.file or location.line_start"
else
  fail "Findings have rule_id (normalizer output not available)"
  fail "Findings have location.file and location.line_start (normalizer output not available)"
fi

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "================================================="
TOTAL=$((PASS + FAIL))
echo "TruffleHog Integration Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
