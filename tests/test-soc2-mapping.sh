#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — SOC 2 Mapping Tests
# Tests cwe-to-soc2.json structure, required fields, CWE format,
# cross-reference spot checks, and MCP integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — SOC 2 Mapping Tests"
echo "============================================"
echo ""

SOC2_MAP="$ROOT_DIR/mappings/cwe-to-soc2.json"
MCP_SERVER="$ROOT_DIR/mcp/server.mjs"

# ═══════════════════════════════════════════
# Section 1: File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: File Structure ---"

[ -f "$SOC2_MAP" ] && pass "cwe-to-soc2.json exists" || fail "cwe-to-soc2.json missing"

python3 -c "
import json, sys
try:
    with open('$SOC2_MAP') as f:
        json.load(f)
    sys.exit(0)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" && pass "Valid JSON" || fail "Invalid JSON"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
sys.exit(0 if '_meta' in data else 1)
" && pass "Has _meta key" || fail "Missing _meta key"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'mappings' in data else 1)
" && pass "Has mappings key" || fail "Missing mappings key"

echo ""

# ═══════════════════════════════════════════
# Section 2: Meta Section
# ═══════════════════════════════════════════
echo "--- Section 2: Meta Section ---"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'description' in data['_meta'] else 1)
" && pass "_meta has description" || fail "_meta missing description"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'source' in data['_meta'] else 1)
" && pass "_meta has source" || fail "_meta missing source"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'soc2_version' in data['_meta'] else 1)
" && pass "_meta has soc2_version" || fail "_meta missing soc2_version"

echo ""

# ═══════════════════════════════════════════
# Section 3: Required Fields
# ═══════════════════════════════════════════
echo "--- Section 3: Required Fields ---"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if not isinstance(entry.get('soc2'), list):
        print(f'{cwe} missing soc2 array', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has soc2 field (array)" || fail "Some entries missing soc2 array"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if 'category' not in entry:
        print(f'{cwe} missing category', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has category field" || fail "Some entries missing category"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if 'name' not in entry:
        print(f'{cwe} missing name', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has name field" || fail "Some entries missing name"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if 'requirement' not in entry:
        print(f'{cwe} missing requirement', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has requirement field" || fail "Some entries missing requirement"

echo ""

# ═══════════════════════════════════════════
# Section 4: CWE Format
# ═══════════════════════════════════════════
echo "--- Section 4: CWE Format ---"

python3 -c "
import json, re, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
pattern = re.compile(r'^CWE-\d+$')
for key in m:
    if not pattern.match(key):
        print(f'Bad key format: {key}', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "All keys match CWE-NNN pattern" || fail "Some keys have bad format"

MAPPING_COUNT=$(python3 -c "
import json
with open('$SOC2_MAP') as f:
    data = json.load(f)
print(len(data['mappings']))
")
[ "$MAPPING_COUNT" -ge 35 ] && pass "At least 35 mappings (got $MAPPING_COUNT)" || fail "Expected >= 35 mappings, got $MAPPING_COUNT"

echo ""

# ═══════════════════════════════════════════
# Section 5: Cross-Reference
# ═══════════════════════════════════════════
echo "--- Section 5: Cross-Reference ---"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-89', {})
if 'CC6.1' in entry.get('soc2', []):
    sys.exit(0)
print('CWE-89 does not map to CC6.1', file=sys.stderr)
sys.exit(1)
" && pass "CWE-89 maps to CC6.1 (access controls)" || fail "CWE-89 mapping incorrect"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-312', {})
cats = entry.get('soc2', [])
if any(c.startswith('C1') for c in cats):
    sys.exit(0)
print('CWE-312 does not map to C1 category', file=sys.stderr)
sys.exit(1)
" && pass "CWE-312 maps to C1 category (confidentiality)" || fail "CWE-312 mapping incorrect"

python3 -c "
import json, sys
with open('$SOC2_MAP') as f:
    data = json.load(f)
m = data['mappings']
sys.exit(0 if 'CWE-79' in m else 1)
" && pass "CWE-79 exists in mappings" || fail "CWE-79 missing from mappings"

echo ""

# ═══════════════════════════════════════════
# Section 6: MCP Integration
# ═══════════════════════════════════════════
echo "--- Section 6: MCP Integration ---"

grep -q '"soc2"' "$MCP_SERVER" && pass "mcp/server.mjs frameworks array includes soc2" || fail "mcp/server.mjs missing soc2 in frameworks"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "SOC 2 Mapping Tests: $PASS passed / $FAIL failed (total $TOTAL)"
echo "============================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
