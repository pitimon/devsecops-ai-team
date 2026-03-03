#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Nuclei Integration Tests
# Validates Docker Compose config, job dispatcher, normalizer,
# skill definition, and JSONL fixture for Nuclei DAST scanning

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
warn() { WARN=$((WARN + 1)); echo "  [WARN] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Nuclei Integration Tests"
echo "============================================"
echo ""

COMPOSE="$ROOT_DIR/runner/docker-compose.yml"
DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-nuclei.jsonl"
SKILL="$ROOT_DIR/skills/dast-scan/SKILL.md"

# ═══════════════════════════════════════════
# Section 1: Docker Compose
# ═══════════════════════════════════════════
echo "--- Section 1: Docker Compose ---"

grep -q "nuclei:" "$COMPOSE" \
  && pass "nuclei service exists in docker-compose.yml" \
  || fail "nuclei service missing from docker-compose.yml"

grep -A5 "nuclei:" "$COMPOSE" | grep -q "dast" \
  && pass "nuclei has dast profile" \
  || fail "nuclei missing dast profile"

grep -A5 "nuclei:" "$COMPOSE" | grep -q "projectdiscovery/nuclei" \
  && pass "nuclei uses projectdiscovery/nuclei image" \
  || fail "nuclei has wrong image"

echo ""

# ═══════════════════════════════════════════
# Section 2: Job Dispatcher
# ═══════════════════════════════════════════
echo "--- Section 2: Job Dispatcher ---"

grep -q "run_nuclei" "$DISPATCHER" \
  && pass "run_nuclei function exists in job-dispatcher.sh" \
  || fail "run_nuclei function missing from job-dispatcher.sh"

grep -q "nuclei.*run_nuclei\|nuclei).*run_nuclei" "$DISPATCHER" \
  && pass "nuclei added to run_tool() switch" \
  || fail "nuclei missing from run_tool() switch"

grep -q "cve)" "$DISPATCHER" \
  && pass "cve mode supported" \
  || fail "cve mode missing"

grep -q "full)" "$DISPATCHER" \
  && pass "full mode supported" \
  || fail "full mode missing"

grep -q "custom)" "$DISPATCHER" \
  && pass "custom mode supported" \
  || fail "custom mode missing"

# Verify timeout values
python3 -c "
import sys
with open('$DISPATCHER') as f:
    content = f.read()

# Find run_nuclei function
start = content.find('run_nuclei()')
if start < 0:
    print('run_nuclei function not found', file=sys.stderr)
    sys.exit(1)

# Extract run_nuclei section (up to next function or end)
section = content[start:]
# Find the end of the function (next ^run_ or ^} at col 0)
end = section.find('\nrun_tool()')
if end > 0:
    section = section[:end]

# Check timeouts
ok = True
if 'NUCLEI_TIMEOUT=120' not in section:
    print('cve timeout not 120', file=sys.stderr)
    ok = False
if 'NUCLEI_TIMEOUT=600' not in section:
    print('full timeout not 600', file=sys.stderr)
    ok = False
if 'NUCLEI_TIMEOUT=300' not in section:
    print('custom timeout not 300', file=sys.stderr)
    ok = False
sys.exit(0 if ok else 1)
" && pass "Timeout values correct (cve=120, full=600, custom=300)" \
  || fail "Timeout values incorrect"

echo ""

# ═══════════════════════════════════════════
# Section 3: Normalizer
# ═══════════════════════════════════════════
echo "--- Section 3: Normalizer ---"

grep -q "nuclei)" "$NORMALIZER" \
  && pass "nuclei case exists in json-normalizer.sh" \
  || fail "nuclei case missing from json-normalizer.sh"

# Run normalizer against fixture
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
OUTPUT="$TMPDIR/nuclei-normalized.json"

if bash "$NORMALIZER" --tool nuclei --input "$FIXTURE" --output "$OUTPUT" 2>/dev/null; then
  pass "Normalizer runs successfully on JSONL fixture"

  # Validate output is valid JSON
  if python3 -c "import json; json.load(open('$OUTPUT'))" 2>/dev/null; then
    pass "Normalizer produces valid JSON output"
  else
    fail "Normalizer produces invalid JSON output"
  fi

  # Check finding count
  FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT')).get('findings', [])))" 2>/dev/null)
  [ "$FINDING_COUNT" -eq 4 ] \
    && pass "Output has 4 findings (got $FINDING_COUNT)" \
    || fail "Expected 4 findings, got $FINDING_COUNT"

  # Check severity mapping
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
sevs = [f['severity'] for f in data['findings']]
counts = {}
for s in sevs:
    counts[s] = counts.get(s, 0) + 1
expected = {'CRITICAL': 1, 'HIGH': 1, 'MEDIUM': 1, 'LOW': 1}
if counts != expected:
    print(f'Expected {expected}, got {counts}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Severity mapping correct (1 CRITICAL, 1 HIGH, 1 MEDIUM, 1 LOW)" \
  || fail "Severity mapping incorrect"

  # Check source_tool
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
tools = set(f['source_tool'] for f in data['findings'])
if tools != {'nuclei'}:
    print(f'source_tool should be nuclei, got {tools}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "source_tool is 'nuclei' for all findings" \
  || fail "source_tool incorrect"

  # Check CWE extraction
  python3 -c "
import json, sys
data = json.load(open('$OUTPUT'))
cwes = [f['cwe_id'] for f in data['findings']]
expected = ['CWE-502', 'CWE-400', 'CWE-523', 'CWE-601']
if cwes != expected:
    print(f'Expected CWEs {expected}, got {cwes}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "CWE IDs extracted correctly (CWE-502, CWE-400, CWE-523, CWE-601)" \
  || fail "CWE extraction incorrect"

else
  fail "Normalizer failed on JSONL fixture"
  fail "Normalizer produces valid JSON output (skipped)"
  fail "Output has 4 findings (skipped)"
  fail "Severity mapping correct (skipped)"
  fail "source_tool is 'nuclei' (skipped)"
  fail "CWE IDs extracted correctly (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Section 4: Skill Definition
# ═══════════════════════════════════════════
echo "--- Section 4: Skill Definition ---"

[ -f "$SKILL" ] \
  && pass "skills/dast-scan/SKILL.md exists" \
  || fail "skills/dast-scan/SKILL.md missing"

# Nuclei reference will be added in C5, so warn instead of fail
grep -qi "nuclei" "$SKILL" 2>/dev/null \
  && pass "SKILL.md references nuclei" \
  || warn "SKILL.md does not reference nuclei yet (expected — will be added in C5)"

echo ""

# ═══════════════════════════════════════════
# Section 5: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Section 5: Fixture Validation ---"

[ -f "$FIXTURE" ] \
  && pass "sample-nuclei.jsonl fixture exists" \
  || fail "sample-nuclei.jsonl fixture missing"

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
" && pass "Each line is valid JSON" \
  || fail "Some lines are invalid JSON"

# Validate required fields
python3 -c "
import json, sys
required = ['template-id', 'matched-at']
required_info = ['name', 'severity']
errors = []
with open('$FIXTURE') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        for field in required:
            if field not in obj:
                errors.append(f'Line {i}: missing {field}')
        info = obj.get('info', {})
        for field in required_info:
            if field not in info:
                errors.append(f'Line {i}: missing info.{field}')
if errors:
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All lines have required fields (template-id, info.name, info.severity, matched-at)" \
  || fail "Some lines missing required fields"

# Count lines
LINE_COUNT=$(python3 -c "
count = 0
with open('$FIXTURE') as f:
    for line in f:
        if line.strip():
            count += 1
print(count)
")
[ "$LINE_COUNT" -eq 4 ] \
  && pass "Fixture has 4 lines (got $LINE_COUNT)" \
  || fail "Expected 4 lines, got $LINE_COUNT"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "============================================"
TOTAL=$((PASS + FAIL + WARN))
echo "Nuclei Integration Tests: $PASS passed, $FAIL failed, $WARN warnings / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
