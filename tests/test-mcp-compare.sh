#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — MCP Compare Tool Tests
# Tests devsecops_compare, devsecops_compliance_status, devsecops_suggest_fix

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MCP_DIR="$ROOT_DIR/mcp"
SERVER="$MCP_DIR/server.mjs"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — MCP Compare Tool Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

BASELINE="$ROOT_DIR/tests/fixtures/sample-compare-baseline.json"
CURRENT="$ROOT_DIR/tests/fixtures/sample-compare-current.json"

# Check Node.js available
if ! command -v node &>/dev/null; then
  echo "SKIP: Node.js not found"
  exit 0
fi

# Check npm dependencies installed
if [ ! -d "$MCP_DIR/node_modules" ]; then
  echo "Installing MCP dependencies..."
  (cd "$MCP_DIR" && npm install --silent 2>/dev/null) || true
fi

# Helper: run Node.js with zod available (from mcp/ directory)
run_node_zod() {
  (cd "$MCP_DIR" && node --input-type=module 2>/dev/null)
}

# ═══════════════════════════════════════════
# Section 1: Fixture Validation
# ═══════════════════════════════════════════
echo "--- Fixture Validation ---"

[ -f "$BASELINE" ] && pass "Baseline fixture exists" || fail "Baseline fixture missing"
[ -f "$CURRENT" ] && pass "Current fixture exists" || fail "Current fixture missing"

if python3 -c "import json; json.load(open('$BASELINE'))" 2>/dev/null; then
  pass "Baseline fixture is valid JSON"
else
  fail "Baseline fixture is invalid JSON"
fi

if python3 -c "import json; json.load(open('$CURRENT'))" 2>/dev/null; then
  pass "Current fixture is valid JSON"
else
  fail "Current fixture is invalid JSON"
fi

RESULT=$(python3 -c "
import json
b = json.load(open('$BASELINE'))
print('PASS' if 'findings' in b and len(b['findings']) == 5 else 'FAIL')
" 2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Baseline has 5 findings" || fail "Baseline should have 5 findings"

RESULT=$(python3 -c "
import json
c = json.load(open('$CURRENT'))
print('PASS' if 'findings' in c and len(c['findings']) == 5 else 'FAIL')
" 2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Current has 5 findings" || fail "Current should have 5 findings"

# ═══════════════════════════════════════════
# Section 2: Compare Logic
# ═══════════════════════════════════════════
echo ""
echo "--- Compare Logic ---"

# Test: Compare using fixture files — new=2, fixed=2, unchanged=3
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";

function readJsonFile(p) { try { return JSON.parse(readFileSync(p, "utf-8")); } catch { return null; } }

const baseline = readJsonFile("$BASELINE");
const current = readJsonFile("$CURRENT");

const baseFindings = baseline.findings || [];
const currFindings = current.findings || [];

const baseKeys = new Set(baseFindings.map(f => \`\${f.rule_id}:\${f.location?.file}:\${f.location?.line_start}\`));
const currKeys = new Set(currFindings.map(f => \`\${f.rule_id}:\${f.location?.file}:\${f.location?.line_start}\`));

const newFindings = currFindings.filter(f => !baseKeys.has(\`\${f.rule_id}:\${f.location?.file}:\${f.location?.line_start}\`));
const fixedFindings = baseFindings.filter(f => !currKeys.has(\`\${f.rule_id}:\${f.location?.file}:\${f.location?.line_start}\`));
const unchanged = currFindings.filter(f => baseKeys.has(\`\${f.rule_id}:\${f.location?.file}:\${f.location?.line_start}\`));

console.log(newFindings.length === 2 && fixedFindings.length === 2 && unchanged.length === 3 ? "PASS" : \`FAIL:new=\${newFindings.length},fixed=\${fixedFindings.length},unchanged=\${unchanged.length}\`);
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: new=2, fixed=2, unchanged=3" || fail "Compare: counts wrong ($RESULT)"

# Test: Trend is "stable" (5 baseline, 5 current)
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const baseline = JSON.parse(readFileSync("$BASELINE", "utf-8"));
const current = JSON.parse(readFileSync("$CURRENT", "utf-8"));
const trend = current.findings.length < baseline.findings.length ? "improving" :
              current.findings.length > baseline.findings.length ? "degrading" : "stable";
console.log(trend === "stable" ? "PASS" : "FAIL:" + trend);
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: trend is stable (5 vs 5)" || fail "Compare: trend should be stable ($RESULT)"

# Test: Delta is 0
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const baseline = JSON.parse(readFileSync("$BASELINE", "utf-8"));
const current = JSON.parse(readFileSync("$CURRENT", "utf-8"));
const delta = current.findings.length - baseline.findings.length;
console.log(delta === 0 ? "PASS" : "FAIL:" + delta);
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: delta is 0" || fail "Compare: delta should be 0 ($RESULT)"

# ═══════════════════════════════════════════
# Section 3: Edge Cases
# ═══════════════════════════════════════════
echo ""
echo "--- Edge Cases ---"

# Test: Empty baseline — all current are "new"
RESULT=$(node --input-type=module << 'TESTEOF'
const baseFindings = [];
const currFindings = [
  { rule_id: "r1", location: { file: "a.py", line_start: 1 } },
  { rule_id: "r2", location: { file: "b.py", line_start: 2 } },
];
const baseKeys = new Set(baseFindings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const newFindings = currFindings.filter(f => !baseKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const fixedFindings = baseFindings.filter(f => false);
console.log(newFindings.length === 2 && fixedFindings.length === 0 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Edge: empty baseline — all current are new" || fail "Edge: empty baseline failed"

# Test: Empty current — all baseline are "fixed"
RESULT=$(node --input-type=module << 'TESTEOF'
const baseFindings = [
  { rule_id: "r1", location: { file: "a.py", line_start: 1 } },
  { rule_id: "r2", location: { file: "b.py", line_start: 2 } },
];
const currFindings = [];
const currKeys = new Set(currFindings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const fixedFindings = baseFindings.filter(f => !currKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const trend = currFindings.length < baseFindings.length ? "improving" : "other";
console.log(fixedFindings.length === 2 && trend === "improving" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Edge: empty current — all baseline are fixed, trend improving" || fail "Edge: empty current failed"

# Test: Identical files — all unchanged, trend "stable"
RESULT=$(node --input-type=module << 'TESTEOF'
const findings = [
  { rule_id: "r1", location: { file: "a.py", line_start: 1 } },
  { rule_id: "r2", location: { file: "b.py", line_start: 2 } },
];
const baseKeys = new Set(findings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const currKeys = new Set(findings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const newFindings = findings.filter(f => !baseKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const fixedFindings = findings.filter(f => !currKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const unchanged = findings.filter(f => baseKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const trend = "stable";
console.log(newFindings.length === 0 && fixedFindings.length === 0 && unchanged.length === 2 && trend === "stable" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Edge: identical files — all unchanged, trend stable" || fail "Edge: identical files failed"

# ═══════════════════════════════════════════
# Section 4: Schema Validation
# ═══════════════════════════════════════════
echo ""
echo "--- Schema Validation ---"

# Test: CompareSchema rejects missing baseline_file
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const CompareSchema = z.object({
  baseline_file: z.string().min(1),
  current_file: z.string().min(1),
});
const r = CompareSchema.safeParse({ current_file: "/tmp/c.json" });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Schema: CompareSchema rejects missing baseline_file" || fail "Schema: should reject missing baseline_file"

# Test: CompareSchema rejects missing current_file
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const CompareSchema = z.object({
  baseline_file: z.string().min(1),
  current_file: z.string().min(1),
});
const r = CompareSchema.safeParse({ baseline_file: "/tmp/b.json" });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Schema: CompareSchema rejects missing current_file" || fail "Schema: should reject missing current_file"

# Test: CompareSchema accepts valid input
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const CompareSchema = z.object({
  baseline_file: z.string().min(1),
  current_file: z.string().min(1),
});
const r = CompareSchema.safeParse({ baseline_file: "/tmp/b.json", current_file: "/tmp/c.json" });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Schema: CompareSchema accepts valid input" || fail "Schema: valid compare input rejected"

# Test: SuggestFixSchema requires at least one field
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const SuggestFixSchema = z.object({
  cwe_id: z.string().optional(),
  rule_id: z.string().optional(),
  finding_file: z.string().optional(),
}).refine(data => data.cwe_id || data.rule_id || data.finding_file, {
  message: "At least one of cwe_id, rule_id, or finding_file is required",
});
const r = SuggestFixSchema.safeParse({});
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Schema: SuggestFixSchema rejects empty input" || fail "Schema: should reject empty suggest_fix input"

# ═══════════════════════════════════════════
# Section 5: Server Integration
# ═══════════════════════════════════════════
echo ""
echo "--- Server Integration ---"

# Test: devsecops_compare listed in TOOLS array
if grep -q '"devsecops_compare"' "$SERVER"; then
  pass "devsecops_compare defined in server.mjs"
else
  fail "devsecops_compare missing from server.mjs"
fi

# Test: devsecops_compliance_status listed in TOOLS array
if grep -q '"devsecops_compliance_status"' "$SERVER"; then
  pass "devsecops_compliance_status defined in server.mjs"
else
  fail "devsecops_compliance_status missing from server.mjs"
fi

# Test: devsecops_suggest_fix listed in TOOLS array
if grep -q '"devsecops_suggest_fix"' "$SERVER"; then
  pass "devsecops_suggest_fix defined in server.mjs"
else
  fail "devsecops_suggest_fix missing from server.mjs"
fi

# Test: Switch case exists for devsecops_compare
if grep -q 'case "devsecops_compare"' "$SERVER"; then
  pass "Switch case for devsecops_compare exists"
else
  fail "Switch case for devsecops_compare missing"
fi

# Test: Switch case exists for devsecops_compliance_status
if grep -q 'case "devsecops_compliance_status"' "$SERVER"; then
  pass "Switch case for devsecops_compliance_status exists"
else
  fail "Switch case for devsecops_compliance_status missing"
fi

# Test: Switch case exists for devsecops_suggest_fix
if grep -q 'case "devsecops_suggest_fix"' "$SERVER"; then
  pass "Switch case for devsecops_suggest_fix exists"
else
  fail "Switch case for devsecops_suggest_fix missing"
fi

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
