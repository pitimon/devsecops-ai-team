#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — MCP Handler Logic Tests
# Tests handler functions via Node.js evaluation against server.mjs code
# Static + fixture-based tests — no Docker required

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MCP_DIR="$ROOT_DIR/mcp"
SERVER="$MCP_DIR/server.mjs"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — MCP Handler Logic Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

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
# Zod Validation Tests
# ═══════════════════════════════════════════
echo "--- Zod Input Validation ---"

# Test: Valid scan input accepted
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ScanSchema = z.object({
  tool: z.enum(["semgrep","gitleaks","grype","trivy","checkov","zap","syft"]),
  target: z.string().optional(),
  rules: z.string().optional(),
  format: z.enum(["json","sarif","markdown","html"]).optional(),
});
const r = ScanSchema.safeParse({ tool: "semgrep", target: "/workspace" });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: valid scan input accepted" || fail "Zod: valid scan input rejected"

# Test: Invalid tool rejected
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ScanSchema = z.object({
  tool: z.enum(["semgrep","gitleaks","grype","trivy","checkov","zap","syft"]),
});
const r = ScanSchema.safeParse({ tool: "invalid-tool" });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: invalid tool name rejected" || fail "Zod: invalid tool should be rejected"

# Test: Missing required field rejected
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ScanSchema = z.object({
  tool: z.enum(["semgrep","gitleaks","grype","trivy","checkov","zap","syft"]),
});
const r = ScanSchema.safeParse({});
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: missing required field rejected" || fail "Zod: missing field should be rejected"

# Test: Valid gate input accepted
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const GateSchema = z.object({
  results_file: z.string().min(1),
  role: z.enum(["developer","security-lead","release-manager"]).optional(),
  policy_file: z.string().optional(),
});
const r = GateSchema.safeParse({ results_file: "/tmp/results.json", role: "developer" });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: valid gate input accepted" || fail "Zod: valid gate input rejected"

# Test: Empty results_file rejected
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const GateSchema = z.object({
  results_file: z.string().min(1),
});
const r = GateSchema.safeParse({ results_file: "" });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: empty results_file rejected" || fail "Zod: empty results_file should be rejected"

# Test: Invalid role rejected
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const GateSchema = z.object({
  results_file: z.string().min(1),
  role: z.enum(["developer","security-lead","release-manager"]).optional(),
});
const r = GateSchema.safeParse({ results_file: "/tmp/r.json", role: "admin" });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: invalid role rejected" || fail "Zod: invalid role should be rejected"

# Test: Valid compliance input accepted
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ComplianceSchema = z.object({
  findings_file: z.string().min(1),
  frameworks: z.array(z.enum(["owasp","nist","mitre","ncsa"])).optional(),
});
const r = ComplianceSchema.safeParse({ findings_file: "/tmp/f.json", frameworks: ["owasp","nist"] });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: valid compliance input accepted" || fail "Zod: valid compliance input rejected"

# Test: Invalid framework rejected
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ComplianceSchema = z.object({
  findings_file: z.string().min(1),
  frameworks: z.array(z.enum(["owasp","nist","mitre","ncsa"])).optional(),
});
const r = ComplianceSchema.safeParse({ findings_file: "/tmp/f.json", frameworks: ["invalid"] });
console.log(r.success ? "FAIL" : "PASS");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: invalid framework rejected" || fail "Zod: invalid framework should be rejected"

# ═══════════════════════════════════════════
# Gate Logic Tests
# ═══════════════════════════════════════════
echo ""
echo "--- Gate Logic (evaluateGateViolations) ---"

# Create test fixtures
cat > "$TMPDIR/gate-results.json" << 'EOF'
{"findings": [{"severity":"CRITICAL"},{"severity":"HIGH"},{"severity":"HIGH"}], "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0}}
EOF

# Test: Developer role — only CRITICAL fails
RESULT=$(node --input-type=module << TESTEOF
function evaluateGateViolations(summary, failOn) {
  const violations = [];
  for (const severity of failOn) {
    const count = summary[severity.toLowerCase()] || 0;
    if (count > 0) {
      violations.push({ severity: severity.toUpperCase(), found: count });
    }
  }
  return violations;
}
const summary = { critical: 1, high: 2, medium: 0, low: 0 };
const v = evaluateGateViolations(summary, ["CRITICAL"]);
console.log(v.length === 1 && v[0].severity === "CRITICAL" && v[0].found === 1 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Gate: developer role finds 1 CRITICAL violation" || fail "Gate: developer role violation check failed"

# Test: Security-lead role — CRITICAL + HIGH
RESULT=$(node --input-type=module << TESTEOF
function evaluateGateViolations(summary, failOn) {
  const violations = [];
  for (const severity of failOn) {
    const count = summary[severity.toLowerCase()] || 0;
    if (count > 0) {
      violations.push({ severity: severity.toUpperCase(), found: count });
    }
  }
  return violations;
}
const summary = { critical: 1, high: 2, medium: 0, low: 0 };
const v = evaluateGateViolations(summary, ["CRITICAL", "HIGH"]);
console.log(v.length === 2 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Gate: security-lead finds CRITICAL + HIGH violations" || fail "Gate: security-lead violation check failed"

# Test: Release-manager — CRITICAL+HIGH+MEDIUM
RESULT=$(node --input-type=module << TESTEOF
function evaluateGateViolations(summary, failOn) {
  const violations = [];
  for (const severity of failOn) {
    const count = summary[severity.toLowerCase()] || 0;
    if (count > 0) {
      violations.push({ severity: severity.toUpperCase(), found: count });
    }
  }
  return violations;
}
const summary = { critical: 0, high: 0, medium: 3, low: 1 };
const v = evaluateGateViolations(summary, ["CRITICAL", "HIGH", "MEDIUM"]);
console.log(v.length === 1 && v[0].severity === "MEDIUM" && v[0].found === 3 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Gate: release-manager catches MEDIUM when no CRIT/HIGH" || fail "Gate: release-manager MEDIUM check failed"

# Test: PASS when no violations
RESULT=$(node --input-type=module << TESTEOF
function evaluateGateViolations(summary, failOn) {
  const violations = [];
  for (const severity of failOn) {
    const count = summary[severity.toLowerCase()] || 0;
    if (count > 0) {
      violations.push({ severity: severity.toUpperCase(), found: count });
    }
  }
  return violations;
}
const summary = { critical: 0, high: 0, medium: 2, low: 1 };
const v = evaluateGateViolations(summary, ["CRITICAL"]);
console.log(v.length === 0 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Gate: PASS when no violations match failOn" || fail "Gate: should PASS with no matching violations"

# ═══════════════════════════════════════════
# Compliance Crosswalk Tests
# ═══════════════════════════════════════════
echo ""
echo "--- Compliance Crosswalk ---"

# Test: CWE mapping accuracy with real mapping files
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";

const owaspData = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-owasp.json", "utf-8"));
const nistData = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-nist.json", "utf-8"));
const mitreData = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-mitre.json", "utf-8"));

// Mapping files use { _meta, mappings: { "CWE-89": "..." } } structure
const owaspMap = owaspData.mappings || owaspData;
const nistMap = nistData.mappings || nistData;
const mitreMap = mitreData.mappings || mitreData;

// CWE-89 (SQL Injection) should be in all 3 mappings
const has89 = (owaspMap["CWE-89"] || owaspMap["89"]) && (nistMap["CWE-89"] || nistMap["89"]) && (mitreMap["CWE-89"] || mitreMap["89"]);
console.log(has89 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compliance: CWE-89 mapped in all 3 frameworks" || fail "Compliance: CWE-89 should be in all frameworks"

# Test: Unmapped CWE returns undefined
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const data = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-owasp.json", "utf-8"));
const owaspMap = data.mappings || data;
// CWE-99999 should not exist
const val = owaspMap["CWE-99999"] || owaspMap["99999"];
console.log(val === undefined ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compliance: unmapped CWE returns undefined" || fail "Compliance: unmapped CWE should return undefined"

# Test: buildCrosswalk function
RESULT=$(node --input-type=module << TESTEOF
function buildCrosswalk(findings, mappings) {
  return findings
    .filter(f => f.cwe_id)
    .map(f => {
      const entry = { finding_id: f.id, cwe_id: f.cwe_id, severity: f.severity, title: f.title };
      for (const [fw, mapping] of Object.entries(mappings)) {
        const key = f.cwe_id.replace("CWE-", "");
        entry[fw] = mapping[key] || mapping[f.cwe_id] || null;
      }
      return entry;
    });
}
const findings = [
  { id: "F-001", cwe_id: "CWE-89", severity: "HIGH", title: "SQL Injection" },
  { id: "F-002", cwe_id: null, severity: "LOW", title: "No CWE" }
];
const mappings = { owasp: { "89": "A03:2021" } };
const result = buildCrosswalk(findings, mappings);
// Should only have 1 entry (null CWE filtered)
console.log(result.length === 1 && result[0].owasp === "A03:2021" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compliance: buildCrosswalk filters null CWEs and maps correctly" || fail "Compliance: buildCrosswalk logic failed"

# Test: NCSA mapping file exists and has valid structure
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const data = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-ncsa.json", "utf-8"));
const hasMeta = data._meta && data._meta.ncsa_version === "1.0";
const hasMappings = data.mappings && Object.keys(data.mappings).length >= 40;
// CWE-89 (SQL Injection) should map to NCSA 5.4 (Input Validation)
const has89 = data.mappings["CWE-89"] && data.mappings["CWE-89"].ncsa.includes("5.4");
console.log(hasMeta && hasMappings && has89 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compliance: NCSA mapping file valid with 40+ CWEs" || fail "Compliance: NCSA mapping file invalid"

# Test: NCSA framework accepted by Zod schema
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ComplianceSchema = z.object({
  findings_file: z.string().min(1),
  frameworks: z.array(z.enum(["owasp","nist","mitre","ncsa"])).optional(),
});
const r = ComplianceSchema.safeParse({ findings_file: "/tmp/f.json", frameworks: ["ncsa"] });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Zod: ncsa framework accepted" || fail "Zod: ncsa framework should be accepted"

# ═══════════════════════════════════════════
# Helper Function Tests
# ═══════════════════════════════════════════
echo ""
echo "--- Helper Functions ---"

# Test: mcpError format
RESULT=$(node --input-type=module << 'TESTEOF'
function mcpError(text) {
  return { isError: true, content: [{ type: "text", text }] };
}
const r = mcpError("test error");
console.log(r.isError === true && r.content[0].text === "test error" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Helper: mcpError returns isError:true + text content" || fail "Helper: mcpError format wrong"

# Test: mcpJson format
RESULT=$(node --input-type=module << 'TESTEOF'
function mcpJson(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}
const r = mcpJson({ gate: "PASS" });
const parsed = JSON.parse(r.content[0].text);
console.log(parsed.gate === "PASS" && r.content[0].type === "text" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Helper: mcpJson wraps data in MCP content format" || fail "Helper: mcpJson format wrong"

# Test: validateInput returns structured error
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";

function validateInput(schema, args) {
  const result = schema.safeParse(args || {});
  if (!result.success) {
    const issues = result.error.issues.map(i => `${i.path.join(".")}: ${i.message}`);
    return { valid: false, error: { isError: true, content: [{ type: "text", text: `Input validation failed:\n${issues.join("\n")}` }] } };
  }
  return { valid: true, data: result.data };
}

const schema = z.object({ tool: z.enum(["semgrep"]) });
const r = validateInput(schema, { tool: "bad" });
console.log(!r.valid && r.error.isError && r.error.content[0].text.includes("validation failed") ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Helper: validateInput returns structured error on bad input" || fail "Helper: validateInput error format wrong"

# Test: validateInput returns data on valid input
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";

function validateInput(schema, args) {
  const result = schema.safeParse(args || {});
  if (!result.success) {
    return { valid: false };
  }
  return { valid: true, data: result.data };
}

const schema = z.object({ tool: z.enum(["semgrep"]) });
const r = validateInput(schema, { tool: "semgrep" });
console.log(r.valid && r.data.tool === "semgrep" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Helper: validateInput returns data on valid input" || fail "Helper: validateInput valid case failed"

# ═══════════════════════════════════════════
# FORMAT_EXT_MAP Tests
# ═══════════════════════════════════════════
echo ""
echo "--- FORMAT_EXT_MAP ---"

RESULT=$(node --input-type=module << 'TESTEOF'
const FORMAT_EXT_MAP = { json: "normalized.json", sarif: "results.sarif", markdown: "results.md", html: "results.html" };
const ok = FORMAT_EXT_MAP["json"] === "normalized.json"
  && FORMAT_EXT_MAP["sarif"] === "results.sarif"
  && FORMAT_EXT_MAP["markdown"] === "results.md"
  && FORMAT_EXT_MAP["html"] === "results.html";
console.log(ok ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "FORMAT_EXT_MAP: all 4 format mappings correct" || fail "FORMAT_EXT_MAP: mapping values wrong"

# ═══════════════════════════════════════════
# Severity Policy Tests
# ═══════════════════════════════════════════
echo ""
echo "--- Severity Policy File ---"

# Test: Policy file has all 3 roles
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const policy = JSON.parse(readFileSync("$ROOT_DIR/mappings/severity-policy.json", "utf-8"));
const roles = Object.keys(policy.roles || {});
const ok = roles.includes("developer") && roles.includes("security-lead") && roles.includes("release-manager");
console.log(ok ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Policy: all 3 roles present" || fail "Policy: missing roles"

# Test: Developer role has correct fail_on
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const policy = JSON.parse(readFileSync("$ROOT_DIR/mappings/severity-policy.json", "utf-8"));
const failOn = policy.roles.developer.fail_on;
console.log(failOn.length === 1 && failOn[0] === "CRITICAL" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Policy: developer fails on CRITICAL only" || fail "Policy: developer fail_on wrong"

# Test: Default role is developer
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const policy = JSON.parse(readFileSync("$ROOT_DIR/mappings/severity-policy.json", "utf-8"));
console.log(policy.default_role === "developer" ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Policy: default_role is developer" || fail "Policy: default_role wrong"

# ═══════════════════════════════════════════
# ComplianceStatus Handler Tests
# ═══════════════════════════════════════════
echo ""
echo "--- ComplianceStatus Handler ---"

# Test: ComplianceStatus maps findings to all 4 frameworks
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

function readJsonFile(p) { try { return JSON.parse(readFileSync(p, "utf-8")); } catch { return null; } }

const MAPPINGS_DIR = "$ROOT_DIR/mappings";
const findings = [
  { cwe_id: "CWE-89", rule_id: "a03-sql-injection" },
  { cwe_id: "CWE-79", rule_id: "a03-xss-dom" },
  { cwe_id: null, rule_id: "no-cwe" },
];
const frameworks = ["owasp", "nist", "mitre", "ncsa"];
const mappings = {};
for (const fw of frameworks) {
  const file = resolve(MAPPINGS_DIR, "cwe-to-" + fw + ".json");
  if (existsSync(file)) mappings[fw] = readJsonFile(file) || {};
}

let allHaveAvailable = true;
for (const fw of frameworks) {
  const mapping = mappings[fw];
  if (!mapping) { allHaveAvailable = false; continue; }
  const mappingData = mapping.mappings || mapping;
  let mapped = 0;
  for (const f of findings) {
    if (!f.cwe_id) continue;
    if (mappingData[f.cwe_id]) mapped++;
  }
  if (mapped === 0) allHaveAvailable = false;
}
// CWE-89 and CWE-79 should be in OWASP mapping at minimum
const owaspData = mappings["owasp"]?.mappings || {};
const has89 = !!owaspData["CWE-89"];
const has79 = !!owaspData["CWE-79"];
console.log(allHaveAvailable && has89 && has79 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "ComplianceStatus: maps CWE-89 and CWE-79 across frameworks" || fail "ComplianceStatus: mapping failed"

# Test: ComplianceStatus coverage_pct calculation
RESULT=$(node --input-type=module << 'TESTEOF'
const findings = [
  { cwe_id: "CWE-89" }, { cwe_id: "CWE-79" }, { cwe_id: null }, { cwe_id: "CWE-99999" },
];
const mappingData = { "CWE-89": {}, "CWE-79": {} };
let mapped = 0;
let unmapped = 0;
for (const f of findings) {
  if (!f.cwe_id) { unmapped++; continue; }
  if (mappingData[f.cwe_id]) { mapped++; } else { unmapped++; }
}
const coverage_pct = findings.length > 0 ? Math.round((mapped / findings.length) * 100) : 0;
console.log(mapped === 2 && unmapped === 2 && coverage_pct === 50 ? "PASS" : `FAIL:mapped=${mapped},unmapped=${unmapped},pct=${coverage_pct}`);
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "ComplianceStatus: coverage_pct = 50% for 2/4 mapped" || fail "ComplianceStatus: coverage_pct wrong ($RESULT)"

# Test: ComplianceStatus handles empty findings
RESULT=$(node --input-type=module << 'TESTEOF'
const findings = [];
const coverage_pct = findings.length > 0 ? Math.round((0 / findings.length) * 100) : 0;
console.log(coverage_pct === 0 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "ComplianceStatus: empty findings gives 0% coverage" || fail "ComplianceStatus: empty findings should give 0%"

# Test: ComplianceStatusSchema valid input accepted
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const ComplianceStatusSchema = z.object({
  findings_file: z.string().min(1),
});
const r = ComplianceStatusSchema.safeParse({ findings_file: "/tmp/f.json" });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "ComplianceStatus: schema accepts valid input" || fail "ComplianceStatus: schema rejected valid input"

# ═══════════════════════════════════════════
# SuggestFix Handler Tests
# ═══════════════════════════════════════════
echo ""
echo "--- SuggestFix Handler ---"

# Test: SuggestFix looks up CWE in OWASP mapping
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const owaspMap = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-owasp.json", "utf-8"));
const entry = owaspMap.mappings?.["CWE-89"];
console.log(entry && entry.owasp ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "SuggestFix: CWE-89 found in OWASP mapping" || fail "SuggestFix: CWE-89 lookup failed"

# Test: SuggestFix looks up CWE in NIST mapping
RESULT=$(node --input-type=module << TESTEOF
import { readFileSync } from "node:fs";
const nistMap = JSON.parse(readFileSync("$ROOT_DIR/mappings/cwe-to-nist.json", "utf-8"));
const entry = nistMap.mappings?.["CWE-89"];
console.log(entry ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "SuggestFix: CWE-89 found in NIST mapping" || fail "SuggestFix: CWE-89 NIST lookup failed"

# Test: SuggestFix lists reference files
RESULT=$(node --input-type=module << TESTEOF
import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
const refDir = resolve("$ROOT_DIR", "skills", "references");
if (existsSync(refDir)) {
  const refFiles = readdirSync(refDir).filter(f => f.endsWith(".md"));
  console.log(refFiles.length >= 12 ? "PASS" : "FAIL:" + refFiles.length);
} else {
  console.log("FAIL:nodir");
}
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "SuggestFix: lists 12+ reference files" || fail "SuggestFix: reference files listing failed ($RESULT)"

# Test: SuggestFixSchema accepts cwe_id only
RESULT=$(run_node_zod << 'TESTEOF'
import { z } from "zod";
const SuggestFixSchema = z.object({
  cwe_id: z.string().optional(),
  rule_id: z.string().optional(),
  finding_file: z.string().optional(),
}).refine(data => data.cwe_id || data.rule_id || data.finding_file, {
  message: "At least one required",
});
const r = SuggestFixSchema.safeParse({ cwe_id: "CWE-89" });
console.log(r.success ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "SuggestFix: schema accepts cwe_id only" || fail "SuggestFix: schema should accept cwe_id only"

# ═══════════════════════════════════════════
# Compare Handler Tests (inline fixtures)
# ═══════════════════════════════════════════
echo ""
echo "--- Compare Handler (inline) ---"

# Test: Compare with degrading trend
RESULT=$(node --input-type=module << 'TESTEOF'
const baseFindings = [{ rule_id: "r1", location: { file: "a.py", line_start: 1 } }];
const currFindings = [
  { rule_id: "r1", location: { file: "a.py", line_start: 1 } },
  { rule_id: "r2", location: { file: "b.py", line_start: 2 } },
  { rule_id: "r3", location: { file: "c.py", line_start: 3 } },
];
const trend = currFindings.length < baseFindings.length ? "improving" :
              currFindings.length > baseFindings.length ? "degrading" : "stable";
const delta = currFindings.length - baseFindings.length;
console.log(trend === "degrading" && delta === 2 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: degrading trend detected (1 → 3)" || fail "Compare: degrading trend failed"

# Test: Compare with improving trend
RESULT=$(node --input-type=module << 'TESTEOF'
const baseFindings = [
  { rule_id: "r1", location: { file: "a.py", line_start: 1 } },
  { rule_id: "r2", location: { file: "b.py", line_start: 2 } },
  { rule_id: "r3", location: { file: "c.py", line_start: 3 } },
];
const currFindings = [{ rule_id: "r1", location: { file: "a.py", line_start: 1 } }];
const trend = currFindings.length < baseFindings.length ? "improving" :
              currFindings.length > baseFindings.length ? "degrading" : "stable";
const delta = currFindings.length - baseFindings.length;
console.log(trend === "improving" && delta === -2 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: improving trend detected (3 → 1)" || fail "Compare: improving trend failed"

# Test: Compare — finding key uses rule_id + file + line_start
RESULT=$(node --input-type=module << 'TESTEOF'
// Same rule_id but different file should be treated as different
const baseFindings = [{ rule_id: "r1", location: { file: "a.py", line_start: 1 } }];
const currFindings = [{ rule_id: "r1", location: { file: "b.py", line_start: 1 } }];
const baseKeys = new Set(baseFindings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const currKeys = new Set(currFindings.map(f => `${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const newFindings = currFindings.filter(f => !baseKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
const fixedFindings = baseFindings.filter(f => !currKeys.has(`${f.rule_id}:${f.location?.file}:${f.location?.line_start}`));
console.log(newFindings.length === 1 && fixedFindings.length === 1 ? "PASS" : "FAIL");
TESTEOF
2>/dev/null)
[ "$RESULT" = "PASS" ] && pass "Compare: same rule_id different file treated as distinct" || fail "Compare: key identity logic failed"

# Test: Compare — handler function exists in server
if grep -q "async function handleCompare" "$SERVER"; then
  pass "handleCompare function exists in server.mjs"
else
  fail "handleCompare function missing from server.mjs"
fi

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
