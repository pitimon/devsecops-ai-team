#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — CI Templates Validation Tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — CI Templates Tests"
echo "============================================"
echo ""

# ─── Section 1: GitHub Actions Templates ───
echo "--- Section 1: GitHub Actions Templates ---"

GH_TEMPLATES="devsecops-sast.yml devsecops-sca.yml devsecops-container-scan.yml devsecops-full-pipeline.yml"
for tmpl in $GH_TEMPLATES; do
  [ -f "$ROOT_DIR/.github/workflows/templates/$tmpl" ] && pass "$tmpl exists" || fail "$tmpl missing"
done

# Validate YAML syntax (python3 can parse YAML via a simple check)
for tmpl in $GH_TEMPLATES; do
  FILE="$ROOT_DIR/.github/workflows/templates/$tmpl"
  if [ -f "$FILE" ]; then
    # Check basic YAML structure — must have 'on:' and 'jobs:'
    grep -q "^on:" "$FILE" && pass "$tmpl has 'on:' key" || fail "$tmpl missing 'on:' key"
    grep -q "^jobs:" "$FILE" && pass "$tmpl has 'jobs:' key" || fail "$tmpl missing 'jobs:' key"
  fi
done

# Reusable workflow checks
for tmpl in $GH_TEMPLATES; do
  FILE="$ROOT_DIR/.github/workflows/templates/$tmpl"
  if [ -f "$FILE" ]; then
    grep -q "workflow_call" "$FILE" && pass "$tmpl is reusable (workflow_call)" || fail "$tmpl not reusable"
  fi
done

# SARIF upload checks
for tmpl in devsecops-sast.yml devsecops-sca.yml devsecops-container-scan.yml; do
  FILE="$ROOT_DIR/.github/workflows/templates/$tmpl"
  if [ -f "$FILE" ]; then
    grep -q "upload-sarif" "$FILE" && pass "$tmpl has SARIF upload" || fail "$tmpl missing SARIF upload"
    grep -q "security-events: write" "$FILE" && pass "$tmpl has security-events permission" || fail "$tmpl missing security-events permission"
  fi
done

# Full pipeline specific checks
FULL="$ROOT_DIR/.github/workflows/templates/devsecops-full-pipeline.yml"
if [ -f "$FULL" ]; then
  grep -q "strategy" "$FULL" && pass "full-pipeline has matrix strategy" || fail "full-pipeline missing strategy"
  grep -q "max-parallel" "$FULL" && pass "full-pipeline has max-parallel for heavy tools" || fail "full-pipeline missing max-parallel"
fi

# ─── Section 2: GitHub Copy-Paste Templates ───
echo ""
echo "--- Section 2: GitHub Copy-Paste Templates (ci-templates/github/) ---"

GH_COPY_TEMPLATES="devsecops-sast.yml devsecops-sca.yml devsecops-container-scan.yml devsecops-full-pipeline.yml"
for tmpl in $GH_COPY_TEMPLATES; do
  [ -f "$ROOT_DIR/ci-templates/github/$tmpl" ] && pass "ci-templates/github/$tmpl exists" || fail "ci-templates/github/$tmpl missing"
done

# Validate workflow_call trigger
for tmpl in $GH_COPY_TEMPLATES; do
  FILE="$ROOT_DIR/ci-templates/github/$tmpl"
  if [ -f "$FILE" ]; then
    grep -q "workflow_call" "$FILE" && pass "ci-templates/github/$tmpl has workflow_call trigger" || fail "ci-templates/github/$tmpl missing workflow_call"
  fi
done

# Validate inputs section
for tmpl in $GH_COPY_TEMPLATES; do
  FILE="$ROOT_DIR/ci-templates/github/$tmpl"
  if [ -f "$FILE" ]; then
    grep -q "inputs:" "$FILE" && pass "ci-templates/github/$tmpl has inputs" || fail "ci-templates/github/$tmpl missing inputs"
  fi
done

# Validate consumption pattern header
for tmpl in $GH_COPY_TEMPLATES; do
  FILE="$ROOT_DIR/ci-templates/github/$tmpl"
  if [ -f "$FILE" ]; then
    grep -q "Copy-paste" "$FILE" && pass "ci-templates/github/$tmpl has copy-paste usage header" || fail "ci-templates/github/$tmpl missing usage header"
  fi
done

# Content parity with source templates
for tmpl in $GH_COPY_TEMPLATES; do
  SRC="$ROOT_DIR/.github/workflows/templates/$tmpl"
  DST="$ROOT_DIR/ci-templates/github/$tmpl"
  if [ -f "$SRC" ] && [ -f "$DST" ]; then
    # Compare from the 'name:' line onward (skip header comments)
    SRC_BODY=$(sed -n '/^name:/,$p' "$SRC")
    DST_BODY=$(sed -n '/^name:/,$p' "$DST")
    [ "$SRC_BODY" = "$DST_BODY" ] && pass "ci-templates/github/$tmpl content matches source" || fail "ci-templates/github/$tmpl content diverged from source"
  fi
done

# ─── Section 3: GitLab CI Templates ───
echo ""
echo "--- Section 3: GitLab CI Templates ---"

GL_TEMPLATES="devsecops.gitlab-ci.yml sast.gitlab-ci.yml sca.gitlab-ci.yml container-scan.gitlab-ci.yml"
for tmpl in $GL_TEMPLATES; do
  [ -f "$ROOT_DIR/ci-templates/$tmpl" ] && pass "$tmpl exists" || fail "$tmpl missing"
done

# Check main template has includes
MAIN_GL="$ROOT_DIR/ci-templates/devsecops.gitlab-ci.yml"
if [ -f "$MAIN_GL" ]; then
  grep -q "include:" "$MAIN_GL" && pass "main gitlab template has includes" || fail "main gitlab template missing includes"
  grep -q "stages:" "$MAIN_GL" && pass "main gitlab template has stages" || fail "main gitlab template missing stages"
fi

# GitLab report artifact types
grep -q "reports:" "$ROOT_DIR/ci-templates/sast.gitlab-ci.yml" && pass "sast template has reports artifact" || fail "sast template missing reports"
grep -q "sast:" "$ROOT_DIR/ci-templates/sast.gitlab-ci.yml" && pass "sast template uses sast report type" || fail "sast template wrong report type"
grep -q "dependency_scanning:" "$ROOT_DIR/ci-templates/sca.gitlab-ci.yml" && pass "sca template uses dependency_scanning report" || fail "sca template wrong report type"
grep -q "container_scanning:" "$ROOT_DIR/ci-templates/container-scan.gitlab-ci.yml" && pass "container template uses container_scanning report" || fail "container template wrong report type"

# Resource group for heavy tools
grep -q "resource_group" "$ROOT_DIR/ci-templates/container-scan.gitlab-ci.yml" && pass "container template uses resource_group" || fail "container template missing resource_group"

# ─── Section 4: Converter Script ───
echo ""
echo "--- Section 4: Converter Script ---"

CONVERTER="$ROOT_DIR/ci-templates/converters/gitlab-sast-converter.sh"
[ -f "$CONVERTER" ] && pass "gitlab-sast-converter.sh exists" || fail "converter missing"
[ -x "$CONVERTER" ] && pass "converter is executable" || fail "converter not executable"

# Test converter with sample data
if [ -f "$CONVERTER" ] && [ -f "$ROOT_DIR/tests/fixtures/sample-mixed-normalized.json" ]; then
  TMPOUT=$(mktemp)
  bash "$CONVERTER" --input "$ROOT_DIR/tests/fixtures/sample-mixed-normalized.json" --output "$TMPOUT" 2>/dev/null
  python3 -c "import json; d=json.load(open('$TMPOUT')); assert d['version']=='15.0.7'" 2>/dev/null && pass "converter produces v15.0.7 schema" || fail "converter wrong schema version"
  python3 -c "import json; d=json.load(open('$TMPOUT')); assert len(d['vulnerabilities'])>0" 2>/dev/null && pass "converter produces vulnerabilities" || fail "converter no vulnerabilities"
  python3 -c "import json; d=json.load(open('$TMPOUT')); assert d['scan']['type']=='sast'" 2>/dev/null && pass "converter scan type is sast" || fail "converter wrong scan type"
  rm -f "$TMPOUT"
fi

# ─── Section 5: Documentation ───
echo ""
echo "--- Section 5: CI Documentation ---"

[ -f "$ROOT_DIR/docs/CI-INTEGRATION.md" ] && pass "CI-INTEGRATION.md exists" || fail "CI-INTEGRATION.md missing"
if [ -f "$ROOT_DIR/docs/CI-INTEGRATION.md" ]; then
  grep -q "GitHub Actions" "$ROOT_DIR/docs/CI-INTEGRATION.md" && pass "docs cover GitHub Actions" || fail "docs missing GitHub Actions"
  grep -q "GitLab CI" "$ROOT_DIR/docs/CI-INTEGRATION.md" && pass "docs cover GitLab CI" || fail "docs missing GitLab CI"
  grep -q "workflow_call" "$ROOT_DIR/docs/CI-INTEGRATION.md" && pass "docs mention reusable workflows" || fail "docs missing reusable workflow info"
  grep -q "concurrency" "$ROOT_DIR/docs/CI-INTEGRATION.md" && pass "docs cover concurrency groups" || fail "docs missing concurrency info"
fi

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Results: $PASS passed / $FAIL failed (total $TOTAL checks)"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
