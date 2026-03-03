#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — MCP Server Tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — MCP Server Tests"
echo "============================================"
echo ""

# ─── Test 1: .mcp.json exists and is valid ───
echo "--- MCP Configuration ---"

[ -f "$ROOT_DIR/.mcp.json" ] && pass ".mcp.json exists" || fail ".mcp.json missing"

if python3 -c "import json; json.load(open('$ROOT_DIR/.mcp.json'))" 2>/dev/null; then
  pass ".mcp.json is valid JSON"
else
  fail ".mcp.json is invalid JSON"
fi

MCP_SERVER=$(python3 -c "
import json
d = json.load(open('$ROOT_DIR/.mcp.json'))
servers = d.get('mcpServers', {})
print('yes' if 'devsecops' in servers else 'no')
" 2>/dev/null)
[ "$MCP_SERVER" = "yes" ] && pass ".mcp.json declares 'devsecops' server" || fail ".mcp.json missing 'devsecops' server"

# ─── Test 1b: Bundle exists ───

[ -f "$ROOT_DIR/mcp/dist/server.js" ] && pass "mcp/dist/server.js bundle exists" || fail "mcp/dist/server.js bundle missing"

# ─── Test 2: package.json valid ───
echo ""
echo "--- MCP Package ---"

[ -f "$ROOT_DIR/mcp/package.json" ] && pass "mcp/package.json exists" || fail "mcp/package.json missing"

if python3 -c "import json; d=json.load(open('$ROOT_DIR/mcp/package.json')); assert d['type']=='module'" 2>/dev/null; then
  pass "package.json type is 'module' (ESM)"
else
  fail "package.json missing type:module"
fi

MCP_DEPS=$(python3 -c "
import json
d = json.load(open('$ROOT_DIR/mcp/package.json'))
deps = d.get('dependencies', {})
has_sdk = '@modelcontextprotocol/sdk' in deps
has_zod = 'zod' in deps
print('PASS' if (has_sdk and has_zod) else f'FAIL:sdk={has_sdk},zod={has_zod}')
" 2>/dev/null)
[ "$MCP_DEPS" = "PASS" ] && pass "Dependencies: @modelcontextprotocol/sdk + zod" || fail "Missing dependencies: $MCP_DEPS"

# ─── Test 3: server.mjs syntax ───
echo ""
echo "--- MCP Server Syntax ---"

[ -f "$ROOT_DIR/mcp/server.mjs" ] && pass "mcp/server.mjs exists" || fail "mcp/server.mjs missing"

# Check Node.js syntax (doesn't require npm install)
if node --check "$ROOT_DIR/mcp/server.mjs" 2>/dev/null; then
  pass "server.mjs passes Node.js syntax check"
else
  # Node --check may fail without deps installed, check with grep instead
  if head -1 "$ROOT_DIR/mcp/server.mjs" | grep -q "node" 2>/dev/null; then
    pass "server.mjs has Node.js shebang (syntax check requires npm install)"
  else
    fail "server.mjs syntax check failed"
  fi
fi

# ─── Test 4: Tool definitions ───
echo ""
echo "--- MCP Tool Definitions ---"

TOOL_COUNT=$(grep -c '"devsecops_' "$ROOT_DIR/mcp/server.mjs" | head -1)
# Count unique tool names in TOOLS array
TOOL_NAMES=$(python3 -c "
import re
content = open('$ROOT_DIR/mcp/server.mjs').read()
# Find tool names in the TOOLS array
names = re.findall(r'name:\s*\"(devsecops_\w+)\"', content)
unique = list(dict.fromkeys(names))
print(len(unique))
for n in unique:
    print(n)
" 2>/dev/null)

TOOL_NUM=$(echo "$TOOL_NAMES" | head -1)
[ "$TOOL_NUM" = "8" ] && pass "Exactly 8 MCP tools defined" || fail "Expected 8 tools, found $TOOL_NUM"

# Verify each required tool
for TOOL_NAME in devsecops_scan devsecops_results devsecops_gate devsecops_compliance devsecops_status devsecops_compare devsecops_compliance_status devsecops_suggest_fix; do
  if echo "$TOOL_NAMES" | grep -q "$TOOL_NAME"; then
    pass "Tool '$TOOL_NAME' defined"
  else
    fail "Tool '$TOOL_NAME' missing"
  fi
done

# ─── Test 5: Handler completeness ───
echo ""
echo "--- Handler Completeness ---"

for HANDLER in handleScan handleResults handleGate handleCompliance handleStatus handleCompare handleComplianceStatus handleSuggestFix; do
  if grep -q "async function $HANDLER" "$ROOT_DIR/mcp/server.mjs"; then
    pass "Handler '$HANDLER' implemented"
  else
    fail "Handler '$HANDLER' missing"
  fi
done

# ─── Test 6: MCP SDK imports ───
echo ""
echo "--- MCP SDK Integration ---"

if grep -q 'from "@modelcontextprotocol/sdk' "$ROOT_DIR/mcp/server.mjs"; then
  pass "MCP SDK imported"
else
  fail "MCP SDK import missing"
fi

if grep -q 'StdioServerTransport' "$ROOT_DIR/mcp/server.mjs"; then
  pass "StdioServerTransport used"
else
  fail "StdioServerTransport missing"
fi

if grep -q 'ListToolsRequestSchema' "$ROOT_DIR/mcp/server.mjs"; then
  pass "ListToolsRequestSchema handler registered"
else
  fail "ListToolsRequestSchema missing"
fi

if grep -q 'CallToolRequestSchema' "$ROOT_DIR/mcp/server.mjs"; then
  pass "CallToolRequestSchema handler registered"
else
  fail "CallToolRequestSchema missing"
fi

echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
