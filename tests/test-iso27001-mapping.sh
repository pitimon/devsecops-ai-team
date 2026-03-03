#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — ISO 27001 Mapping Tests
# Tests cwe-to-iso27001.json structure, required fields, CWE format,
# cross-reference spot checks, and MCP integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — ISO 27001 Mapping Tests"
echo "============================================"
echo ""

ISO_MAP="$ROOT_DIR/mappings/cwe-to-iso27001.json"
MCP_SERVER="$ROOT_DIR/mcp/server.mjs"

# ═══════════════════════════════════════════
# Section 1: File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: File Structure ---"

[ -f "$ISO_MAP" ] && pass "cwe-to-iso27001.json exists" || fail "cwe-to-iso27001.json missing"

python3 -c "
import json, sys
try:
    with open('$ISO_MAP') as f:
        json.load(f)
    sys.exit(0)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" && pass "Valid JSON" || fail "Invalid JSON"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
sys.exit(0 if '_meta' in data else 1)
" && pass "Has _meta key" || fail "Missing _meta key"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'description' in data['_meta'] else 1)
" && pass "_meta has description" || fail "_meta missing description"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'source' in data['_meta'] else 1)
" && pass "_meta has source" || fail "_meta missing source"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'iso27001_version' in data['_meta'] else 1)
" && pass "_meta has iso27001_version" || fail "_meta missing iso27001_version"

echo ""

# ═══════════════════════════════════════════
# Section 3: Required Fields
# ═══════════════════════════════════════════
echo "--- Section 3: Required Fields ---"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if not isinstance(entry.get('iso27001'), list):
        print(f'{cwe} missing iso27001 array', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has iso27001 field (array)" || fail "Some entries missing iso27001 array"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
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
with open('$ISO_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-89', {})
if 'A.8.28' in entry.get('iso27001', []):
    sys.exit(0)
print('CWE-89 does not map to A.8.28', file=sys.stderr)
sys.exit(1)
" && pass "CWE-89 maps to A.8.28 (secure coding)" || fail "CWE-89 mapping incorrect"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
m = data['mappings']
sys.exit(0 if 'CWE-287' in m else 1)
" && pass "CWE-287 exists in mappings" || fail "CWE-287 missing from mappings"

python3 -c "
import json, sys
with open('$ISO_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-312', {})
if entry.get('category') == 'Technological Controls':
    sys.exit(0)
print('CWE-312 not in Technological Controls category', file=sys.stderr)
sys.exit(1)
" && pass "CWE-312 exists in Technological Controls category" || fail "CWE-312 category incorrect"

echo ""

# ═══════════════════════════════════════════
# Section 6: MCP Integration
# ═══════════════════════════════════════════
echo "--- Section 6: MCP Integration ---"

grep -q '"iso27001"' "$MCP_SERVER" && pass "mcp/server.mjs frameworks array includes iso27001" || fail "mcp/server.mjs missing iso27001 in frameworks"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "ISO 27001 Mapping Tests: $PASS passed / $FAIL failed (total $TOTAL)"
echo "============================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
