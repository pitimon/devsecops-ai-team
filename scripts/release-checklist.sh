#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Release Checklist Validator
# Standalone doc validator — checks everything that can go stale at release time.
#
# Usage:
#   bash scripts/release-checklist.sh [version]
#   If version omitted, reads from plugin.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
warn() { WARN=$((WARN + 1)); echo "  [WARN] $1"; }

# ─── Resolve version ───
VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(python3 -c "import json; print(json.load(open('$ROOT_DIR/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "")
  if [ -z "$VERSION" ]; then
    echo "ERROR: Cannot read version from plugin.json and no version argument provided" >&2
    exit 1
  fi
fi

echo "============================================"
echo "DevSecOps AI Team — Release Checklist"
echo "============================================"
echo ""
echo "Checking version: $VERSION"
echo ""

# ─── Section 1: CHANGELOG ───
echo "--- Section 1: CHANGELOG ---"

if [ -f "$ROOT_DIR/CHANGELOG.md" ]; then
  grep -q "## \[$VERSION\]" "$ROOT_DIR/CHANGELOG.md" \
    && pass "CHANGELOG has ## [$VERSION] entry" \
    || fail "CHANGELOG missing ## [$VERSION] entry"

  # Check entry has a date
  CHANGELOG_LINE=$(grep "## \[$VERSION\]" "$ROOT_DIR/CHANGELOG.md" | head -1)
  echo "$CHANGELOG_LINE" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}' \
    && pass "CHANGELOG [$VERSION] entry has date" \
    || fail "CHANGELOG [$VERSION] entry missing date"
else
  fail "CHANGELOG.md not found"
fi

# ─── Section 2: README Badges ───
echo ""
echo "--- Section 2: README Badges ---"

if [ -f "$ROOT_DIR/README.md" ]; then
  grep -q "Version-$VERSION" "$ROOT_DIR/README.md" \
    && pass "README badge matches Version-$VERSION" \
    || fail "README badge does not match Version-$VERSION"

  # Check test count badge vs actual test count (warn only)
  BADGE_TESTS=$(grep -oE 'Tests-[0-9]+' "$ROOT_DIR/README.md" | head -1 | grep -oE '[0-9]+' || echo "0")
  if [ "$BADGE_TESTS" -gt 0 ]; then
    pass "README has test count badge ($BADGE_TESTS)"
  else
    warn "README missing test count badge"
  fi

  # Check roadmap table shows version
  grep -q "v$VERSION" "$ROOT_DIR/README.md" \
    && pass "README references v$VERSION" \
    || warn "README does not reference v$VERSION in content"
else
  fail "README.md not found"
fi

# ─── Section 3: Version File Sync (7/7) ───
echo ""
echo "--- Section 3: Version File Sync ---"

VERSION_FILES=(
  ".claude-plugin/plugin.json"
  ".claude-plugin/marketplace.json"
  "mcp/package.json"
  "README.md"
  "docs/INSTALL.md"
  "docs/MANDAY-ESTIMATION.md"
  "mcp/server.mjs"
)
SYNC_COUNT=0
for vf in "${VERSION_FILES[@]}"; do
  if [ -f "$ROOT_DIR/$vf" ]; then
    if grep -q "$VERSION" "$ROOT_DIR/$vf"; then
      pass "$vf contains $VERSION"
      SYNC_COUNT=$((SYNC_COUNT + 1))
    else
      fail "$vf does NOT contain $VERSION"
    fi
  else
    fail "$vf not found"
  fi
done
[ "$SYNC_COUNT" -eq 7 ] \
  && pass "7/7 version files synced" \
  || fail "$SYNC_COUNT/7 version files synced"

# ─── Section 4: MCP Bundle ───
echo ""
echo "--- Section 4: MCP Bundle ---"

if [ -f "$ROOT_DIR/mcp/dist/server.js" ]; then
  pass "MCP bundle exists (mcp/dist/server.js)"

  BUNDLE_SIZE=$(wc -c < "$ROOT_DIR/mcp/dist/server.js" | tr -d ' ')
  [ "$BUNDLE_SIZE" -gt 1000 ] \
    && pass "MCP bundle has content ($BUNDLE_SIZE bytes)" \
    || fail "MCP bundle too small ($BUNDLE_SIZE bytes)"

  grep -q "$VERSION" "$ROOT_DIR/mcp/dist/server.js" \
    && pass "MCP bundle contains version $VERSION" \
    || warn "MCP bundle does not contain version $VERSION (may need rebuild)"
else
  fail "MCP bundle missing (mcp/dist/server.js)"
fi

# ─── Section 5: Required Scripts ───
echo ""
echo "--- Section 5: Required Scripts ---"

for script in scripts/version-bump.sh scripts/release.sh scripts/release-checklist.sh; do
  if [ -f "$ROOT_DIR/$script" ]; then
    pass "$script exists"
    [ -x "$ROOT_DIR/$script" ] \
      && pass "$script is executable" \
      || warn "$script not executable"
  else
    fail "$script missing"
  fi
done

# ─── Section 6: Syntax Validation ───
echo ""
echo "--- Section 6: Syntax Validation ---"

# Shell scripts
SHELL_PASS=0
SHELL_FAIL=0
while IFS= read -r sh_file; do
  if bash -n "$sh_file" 2>/dev/null; then
    SHELL_PASS=$((SHELL_PASS + 1))
  else
    fail "bash -n failed: $sh_file"
    SHELL_FAIL=$((SHELL_FAIL + 1))
  fi
done < <(find "$ROOT_DIR" -name '*.sh' -not -path '*/.git/*' -not -path '*/node_modules/*')

[ "$SHELL_FAIL" -eq 0 ] \
  && pass "All $SHELL_PASS shell scripts pass syntax check" \
  || fail "$SHELL_FAIL/$((SHELL_PASS + SHELL_FAIL)) shell scripts have syntax errors"

# JSON files
JSON_PASS=0
JSON_FAIL=0
while IFS= read -r json_file; do
  if python3 -c "import json; json.load(open('$json_file'))" 2>/dev/null; then
    JSON_PASS=$((JSON_PASS + 1))
  elif python3 -c "
import json, sys
with open('$json_file') as f:
    lines = [l.strip() for l in f if l.strip()]
if not lines:
    sys.exit(1)
for l in lines:
    json.loads(l)
" 2>/dev/null; then
    # Valid JSONL (one JSON object per line) — e.g. TruffleHog output
    JSON_PASS=$((JSON_PASS + 1))
  else
    fail "invalid JSON: $json_file"
    JSON_FAIL=$((JSON_FAIL + 1))
  fi
done < <(find "$ROOT_DIR" -name '*.json' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/dist/*')

[ "$JSON_FAIL" -eq 0 ] \
  && pass "All $JSON_PASS JSON files valid" \
  || fail "$JSON_FAIL/$((JSON_PASS + JSON_FAIL)) JSON files invalid"

# ─── Section 7: Documentation ───
echo ""
echo "--- Section 7: Documentation ---"

[ -f "$ROOT_DIR/docs/CI-INTEGRATION.md" ] \
  && pass "docs/CI-INTEGRATION.md exists" \
  || fail "docs/CI-INTEGRATION.md missing"

[ -f "$ROOT_DIR/docs/PRD.md" ] \
  && pass "docs/PRD.md exists" \
  || warn "docs/PRD.md missing"

[ -f "$ROOT_DIR/DOMAIN.md" ] \
  && pass "DOMAIN.md exists" \
  || warn "DOMAIN.md missing"

# ─── Section 8: Content Accuracy ───
echo ""
echo "--- Section 8: Content Accuracy ---"

# Skill count consistency
ACTUAL_SKILLS=$(find "$ROOT_DIR/skills" -name 'SKILL.md' -type f | wc -l | tr -d ' ')

# Check plugin.json description
grep -q "$ACTUAL_SKILLS skills" "$ROOT_DIR/.claude-plugin/plugin.json" \
  && pass "plugin.json description matches $ACTUAL_SKILLS skills" \
  || fail "plugin.json description has wrong skill count (expected $ACTUAL_SKILLS)"

# Check marketplace.json descriptions (2 occurrences)
MKT_COUNT=$(grep -c "$ACTUAL_SKILLS skills" "$ROOT_DIR/.claude-plugin/marketplace.json" 2>/dev/null || echo 0)
[ "$MKT_COUNT" -ge 2 ] \
  && pass "marketplace.json descriptions match $ACTUAL_SKILLS skills ($MKT_COUNT occurrences)" \
  || fail "marketplace.json has wrong skill count (found $MKT_COUNT matches for '$ACTUAL_SKILLS skills')"

# Check README project structure test count
README_STRUCT_TESTS=$(grep -oE '[0-9]+\+ tests across [0-9]+ suites' "$ROOT_DIR/README.md" | head -1 || echo "")
[ -n "$README_STRUCT_TESTS" ] \
  && pass "README project structure has test info ($README_STRUCT_TESTS)" \
  || warn "README project structure missing test count"

# Check PRD current state references release version (not older)
PRD_STATE=$(grep -oE 'Current State \(v[0-9.]+\)' "$ROOT_DIR/docs/PRD.md" 2>/dev/null | head -1 || echo "")
[ -n "$PRD_STATE" ] \
  && pass "PRD has current state section ($PRD_STATE)" \
  || warn "PRD missing current state section"

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL + WARN))
echo "Release Checklist: $PASS passed / $FAIL failed / $WARN warnings (total $TOTAL)"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "STATUS: FAILED — fix $FAIL issue(s) before release"
  exit 1
else
  if [ "$WARN" -gt 0 ]; then
    echo "STATUS: PASSED with $WARN warning(s)"
  else
    echo "STATUS: PASSED"
  fi
  exit 0
fi
