#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — PDPA Mapping Tests
# Tests cwe-to-pdpa.json structure, required fields, CWE format,
# cross-reference spot checks, and MCP integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — PDPA Mapping Tests"
echo "============================================"
echo ""

PDPA_MAP="$ROOT_DIR/mappings/cwe-to-pdpa.json"
MCP_SERVER="$ROOT_DIR/mcp/server.mjs"

# ═══════════════════════════════════════════
# Section 1: File Structure
# ═══════════════════════════════════════════
echo "--- Section 1: File Structure ---"

[ -f "$PDPA_MAP" ] && pass "cwe-to-pdpa.json exists" || fail "cwe-to-pdpa.json missing"

python3 -c "
import json, sys
try:
    with open('$PDPA_MAP') as f:
        json.load(f)
    sys.exit(0)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" && pass "Valid JSON" || fail "Invalid JSON"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
sys.exit(0 if '_meta' in data else 1)
" && pass "Has _meta key" || fail "Missing _meta key"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
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
with open('$PDPA_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'pdpa_version' in data['_meta'] else 1)
" && pass "_meta has pdpa_version" || fail "_meta missing pdpa_version"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'effective_date' in data['_meta'] else 1)
" && pass "_meta has effective_date" || fail "_meta missing effective_date"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
sys.exit(0 if 'last_updated' in data['_meta'] else 1)
" && pass "_meta has last_updated" || fail "_meta missing last_updated"

echo ""

# ═══════════════════════════════════════════
# Section 3: Required Fields
# ═══════════════════════════════════════════
echo "--- Section 3: Required Fields ---"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
m = data['mappings']
for cwe, entry in m.items():
    if not isinstance(entry.get('pdpa'), list):
        print(f'{cwe} missing pdpa array', file=sys.stderr)
        sys.exit(1)
sys.exit(0)
" && pass "Every entry has pdpa field (array)" || fail "Some entries missing pdpa array"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
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
with open('$PDPA_MAP') as f:
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
with open('$PDPA_MAP') as f:
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
with open('$PDPA_MAP') as f:
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
with open('$PDPA_MAP') as f:
    data = json.load(f)
print(len(data['mappings']))
")
[ "$MAPPING_COUNT" -ge 25 ] && pass "At least 25 mappings (got $MAPPING_COUNT)" || fail "Expected >= 25 mappings, got $MAPPING_COUNT"

echo ""

# ═══════════════════════════════════════════
# Section 5: Cross-Reference
# ═══════════════════════════════════════════
echo "--- Section 5: Cross-Reference ---"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-312', {})
if 'Section 37(1)' in entry.get('pdpa', []):
    sys.exit(0)
print('CWE-312 does not map to Section 37(1)', file=sys.stderr)
sys.exit(1)
" && pass "CWE-312 maps to Section 37(1) (data protection)" || fail "CWE-312 mapping incorrect"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-89', {})
if 'Section 37(1)' in entry.get('pdpa', []):
    sys.exit(0)
print('CWE-89 does not map to Section 37(1)', file=sys.stderr)
sys.exit(1)
" && pass "CWE-89 maps to Section 37(1) (injection)" || fail "CWE-89 mapping incorrect"

python3 -c "
import json, sys
with open('$PDPA_MAP') as f:
    data = json.load(f)
m = data['mappings']
entry = m.get('CWE-778', {})
if 'Section 77' in entry.get('pdpa', []):
    sys.exit(0)
print('CWE-778 does not map to Section 77', file=sys.stderr)
sys.exit(1)
" && pass "CWE-778 maps to Section 77 (breach notification)" || fail "CWE-778 mapping incorrect"

echo ""

# ═══════════════════════════════════════════
# Section 6: MCP Integration
# ═══════════════════════════════════════════
echo "--- Section 6: MCP Integration ---"

grep -q '"pdpa"' "$MCP_SERVER" && pass "mcp/server.mjs frameworks array includes pdpa" || fail "mcp/server.mjs missing pdpa in frameworks"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "PDPA Mapping Tests: $PASS passed / $FAIL failed (total $TOTAL)"
echo "============================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
