#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Kubernetes Scan Tests
# Tests K8s skill definition, reference file, Semgrep rules, Docker compose,
# job dispatcher, and normalizer integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "================================================="
echo "DevSecOps AI Team — Kubernetes Scan Tests"
echo "================================================="
echo ""

SKILL="$ROOT_DIR/skills/k8s-scan/SKILL.md"
REFERENCE="$ROOT_DIR/skills/references/k8s-security-reference.md"
RULES="$ROOT_DIR/rules/k8s-manifest-rules.yml"
COMPOSE="$ROOT_DIR/runner/docker-compose.yml"
DISPATCHER="$ROOT_DIR/runner/job-dispatcher.sh"
NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-kube-bench.json"

# ═══════════════════════════════════════════
# Section 1: Skill Definition (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Skill Definition ---"

[ -f "$SKILL" ] \
  && pass "skills/k8s-scan/SKILL.md exists" \
  || fail "skills/k8s-scan/SKILL.md missing"

grep -qi "kubernetes\|k8s\|kube-bench" "$SKILL" \
  && pass "SKILL.md has trigger keywords (kubernetes/k8s/kube-bench)" \
  || fail "SKILL.md missing trigger keywords"

grep -q "In-the-Loop\|On-the-Loop" "$SKILL" \
  && pass "SKILL.md has decision loop classification" \
  || fail "SKILL.md missing decision loop classification"

grep -q "allowed-tools\|Bash" "$SKILL" \
  && pass "SKILL.md has allowed-tools" \
  || fail "SKILL.md missing allowed-tools"

echo ""

# ═══════════════════════════════════════════
# Section 2: Reference File (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Reference File ---"

[ -f "$REFERENCE" ] \
  && pass "skills/references/k8s-security-reference.md exists" \
  || fail "skills/references/k8s-security-reference.md missing"

grep -q "CIS" "$REFERENCE" \
  && pass "Reference mentions CIS Benchmark" \
  || fail "Reference missing CIS Benchmark"

grep -q "Pod Security\|PSS" "$REFERENCE" \
  && pass "Reference mentions Pod Security Standards" \
  || fail "Reference missing Pod Security Standards"

grep -q "RBAC" "$REFERENCE" \
  && pass "Reference mentions RBAC" \
  || fail "Reference missing RBAC"

echo ""

# ═══════════════════════════════════════════
# Section 3: Semgrep Rules (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Semgrep Rules ---"

[ -f "$RULES" ] \
  && pass "rules/k8s-manifest-rules.yml exists" \
  || fail "rules/k8s-manifest-rules.yml missing"

RULE_COUNT=$(grep -c "id: k8s-" "$RULES" 2>/dev/null || echo 0)
[ "$RULE_COUNT" -eq 8 ] \
  && pass "Has 8 rules (got $RULE_COUNT)" \
  || fail "Expected 8 rules, got $RULE_COUNT"

grep -q "k8s-privileged-container" "$RULES" \
  && pass "Has k8s-privileged-container rule" \
  || fail "Missing k8s-privileged-container rule"

grep -q "k8s-wildcard-rbac" "$RULES" \
  && pass "Has k8s-wildcard-rbac rule" \
  || fail "Missing k8s-wildcard-rbac rule"

echo ""

# ═══════════════════════════════════════════
# Section 4: Docker Compose (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Docker Compose ---"

grep -q "kube-bench:" "$COMPOSE" \
  && pass "docker-compose.yml has kube-bench service" \
  || fail "docker-compose.yml missing kube-bench service"

grep -A5 "kube-bench:" "$COMPOSE" | grep -q "aquasec/kube-bench" \
  && pass "kube-bench uses aquasec/kube-bench image" \
  || fail "kube-bench has wrong image"

python3 -c "
import sys
with open('$COMPOSE') as f:
    content = f.read()
start = content.find('kube-bench:')
if start < 0:
    sys.exit(1)
section = content[start:start+300]
if 'kube-bench' in section and 'profiles' in section:
    sys.exit(0)
sys.exit(1)
" && pass "kube-bench has profile configuration" \
  || fail "kube-bench missing profile configuration"

echo ""

# ═══════════════════════════════════════════
# Section 5: Job Dispatcher (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: Job Dispatcher ---"

grep -q "run_kube_bench" "$DISPATCHER" \
  && pass "run_kube_bench function exists in job-dispatcher.sh" \
  || fail "run_kube_bench function missing from job-dispatcher.sh"

grep -A20 "run_kube_bench" "$DISPATCHER" | grep -q "cis)" \
  && pass "run_kube_bench supports cis mode" \
  || fail "run_kube_bench missing cis mode"

grep -A20 "run_kube_bench" "$DISPATCHER" | grep -q "node)" \
  && pass "run_kube_bench supports node mode" \
  || fail "run_kube_bench missing node mode"

grep -q "kube-bench).*run_kube_bench\|kube-bench) " "$DISPATCHER" \
  && pass "kube-bench in run_tool() case statement" \
  || fail "kube-bench missing from run_tool() case statement"

echo ""

# ═══════════════════════════════════════════
# Section 6: Normalizer (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 6: Normalizer ---"

grep -q "kube-bench)" "$NORMALIZER" \
  && pass "kube-bench case exists in json-normalizer.sh" \
  || fail "kube-bench case missing from json-normalizer.sh"

# Run normalizer against fixture
TMPDIR_TEST=$(mktemp -d)
trap "rm -rf $TMPDIR_TEST" EXIT
OUTPUT="$TMPDIR_TEST/kube-bench-normalized.json"

if bash "$NORMALIZER" --tool kube-bench --input "$FIXTURE" --output "$OUTPUT" 2>/dev/null; then
  pass "Normalizer runs successfully on kube-bench fixture"

  # Test: output is valid JSON
  if python3 -c "import json; json.load(open('$OUTPUT'))" 2>/dev/null; then
    pass "Normalizer produces valid JSON output"
  else
    fail "Normalizer produces invalid JSON output"
  fi

  # Test: has 3 findings
  FINDING_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT')).get('findings', [])))" 2>/dev/null)
  [ "$FINDING_COUNT" -eq 3 ] \
    && pass "Output has 3 findings (got $FINDING_COUNT)" \
    || fail "Expected 3 findings, got ${FINDING_COUNT:-0}"

else
  fail "Normalizer runs successfully on kube-bench fixture"
  fail "Normalizer produces valid JSON output (skipped)"
  fail "Output has 3 findings (skipped)"
fi

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo "================================================="
TOTAL=$((PASS + FAIL))
echo "Kubernetes Scan Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL ($FAIL failures)"
    exit 1
else
    echo "RESULT: ALL PASSED"
    exit 0
fi
