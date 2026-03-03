#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Version Bump Script Tests
# ~15 tests covering semver validation, dry-run, actual bump, and verification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUMP_SCRIPT="$ROOT_DIR/scripts/version-bump.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Version Bump Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Semver Validation
# ═══════════════════════════════════════════
echo "--- Section 1: Semver Validation ---"

# Test 1: Valid semver accepted
OUTPUT=$(bash "$BUMP_SCRIPT" 99.99.99 --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -eq 0 ] && pass "valid semver 99.99.99 accepted" || fail "valid semver 99.99.99 rejected (exit $EXITCODE)"

# Test 2: Simple valid semver
OUTPUT=$(bash "$BUMP_SCRIPT" 1.0.0 --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -eq 0 ] && pass "valid semver 1.0.0 accepted" || fail "valid semver 1.0.0 rejected (exit $EXITCODE)"

# Test 3: Invalid — missing patch
OUTPUT=$(bash "$BUMP_SCRIPT" 2.5 --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && pass "invalid semver '2.5' rejected" || fail "invalid semver '2.5' should be rejected"

# Test 4: Invalid — has v prefix
OUTPUT=$(bash "$BUMP_SCRIPT" v2.6.0 --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && pass "invalid semver 'v2.6.0' rejected (v prefix)" || fail "invalid semver 'v2.6.0' should be rejected"

# Test 5: Invalid — has pre-release suffix
OUTPUT=$(bash "$BUMP_SCRIPT" 2.6.0-beta --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && pass "invalid semver '2.6.0-beta' rejected (suffix)" || fail "invalid semver '2.6.0-beta' should be rejected"

# Test 6: Invalid — not a version
OUTPUT=$(bash "$BUMP_SCRIPT" abc --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && pass "invalid semver 'abc' rejected" || fail "invalid semver 'abc' should be rejected"

# Test 7: No argument provided
OUTPUT=$(bash "$BUMP_SCRIPT" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && pass "no argument → error" || fail "no argument should produce error"

# ═══════════════════════════════════════════
# Section 2: Dry-Run Mode
# ═══════════════════════════════════════════
echo ""
echo "--- Section 2: Dry-Run Mode ---"

# Test 8: Dry-run does not modify files
# Save checksums of all 7 files before
BEFORE_CHECKSUMS=$(cat \
  "$ROOT_DIR/.claude-plugin/plugin.json" \
  "$ROOT_DIR/.claude-plugin/marketplace.json" \
  "$ROOT_DIR/mcp/package.json" \
  "$ROOT_DIR/README.md" \
  "$ROOT_DIR/docs/INSTALL.md" \
  "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" \
  "$ROOT_DIR/mcp/server.mjs" | md5 2>/dev/null || md5sum 2>/dev/null | cut -d' ' -f1)

bash "$BUMP_SCRIPT" 99.99.99 --dry-run >/dev/null 2>&1

AFTER_CHECKSUMS=$(cat \
  "$ROOT_DIR/.claude-plugin/plugin.json" \
  "$ROOT_DIR/.claude-plugin/marketplace.json" \
  "$ROOT_DIR/mcp/package.json" \
  "$ROOT_DIR/README.md" \
  "$ROOT_DIR/docs/INSTALL.md" \
  "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" \
  "$ROOT_DIR/mcp/server.mjs" | md5 2>/dev/null || md5sum 2>/dev/null | cut -d' ' -f1)

[ "$BEFORE_CHECKSUMS" = "$AFTER_CHECKSUMS" ] && pass "dry-run: no files modified" || fail "dry-run: files were modified"

# Test 9: Dry-run output contains DRY-RUN markers
OUTPUT=$(bash "$BUMP_SCRIPT" 99.99.99 --dry-run 2>&1)
echo "$OUTPUT" | grep -q "DRY-RUN" && pass "dry-run: output contains DRY-RUN markers" || fail "dry-run: missing DRY-RUN markers"

# ═══════════════════════════════════════════
# Section 3: Actual Bump on Temp Copies
# ═══════════════════════════════════════════
echo ""
echo "--- Section 3: Actual Bump (temp copies) ---"

# Create a temp copy of the repo structure with just the 7 files
FAKE_ROOT="$TMPDIR/fake-repo"
mkdir -p "$FAKE_ROOT/.claude-plugin" "$FAKE_ROOT/mcp" "$FAKE_ROOT/docs"

cp "$ROOT_DIR/.claude-plugin/plugin.json" "$FAKE_ROOT/.claude-plugin/"
cp "$ROOT_DIR/.claude-plugin/marketplace.json" "$FAKE_ROOT/.claude-plugin/"
cp "$ROOT_DIR/mcp/package.json" "$FAKE_ROOT/mcp/"
cp "$ROOT_DIR/README.md" "$FAKE_ROOT/"
cp "$ROOT_DIR/docs/INSTALL.md" "$FAKE_ROOT/docs/"
cp "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" "$FAKE_ROOT/docs/"
cp "$ROOT_DIR/mcp/server.mjs" "$FAKE_ROOT/mcp/"

# Copy the bump script into the fake repo
mkdir -p "$FAKE_ROOT/scripts"
cp "$BUMP_SCRIPT" "$FAKE_ROOT/scripts/"

# Test 10: Actual bump updates plugin.json
bash "$FAKE_ROOT/scripts/version-bump.sh" 3.0.0 >/dev/null 2>&1
grep -q '"version": "3.0.0"' "$FAKE_ROOT/.claude-plugin/plugin.json" && pass "bump: plugin.json updated to 3.0.0" || fail "bump: plugin.json not updated"

# Test 11: marketplace.json updated
grep -q '"version": "3.0.0"' "$FAKE_ROOT/.claude-plugin/marketplace.json" && pass "bump: marketplace.json updated to 3.0.0" || fail "bump: marketplace.json not updated"

# Test 12: mcp/package.json updated
grep -q '"version": "3.0.0"' "$FAKE_ROOT/mcp/package.json" && pass "bump: mcp/package.json updated to 3.0.0" || fail "bump: mcp/package.json not updated"

# Test 13: README.md badge updated
grep -q "Version-3.0.0" "$FAKE_ROOT/README.md" && pass "bump: README.md badge updated" || fail "bump: README.md badge not updated"

# Test 14: mcp/server.mjs Server constructor updated
grep -q 'version: "3.0.0"' "$FAKE_ROOT/mcp/server.mjs" && pass "bump: mcp/server.mjs Server version updated" || fail "bump: mcp/server.mjs not updated"

# Test 15: All 7 files contain new version
ALL_MATCH=true
for f in \
  "$FAKE_ROOT/.claude-plugin/plugin.json" \
  "$FAKE_ROOT/.claude-plugin/marketplace.json" \
  "$FAKE_ROOT/mcp/package.json" \
  "$FAKE_ROOT/README.md" \
  "$FAKE_ROOT/docs/INSTALL.md" \
  "$FAKE_ROOT/docs/MANDAY-ESTIMATION.md" \
  "$FAKE_ROOT/mcp/server.mjs"; do
  if ! grep -q "3.0.0" "$f" 2>/dev/null; then
    ALL_MATCH=false
  fi
done
$ALL_MATCH && pass "bump: all 7 files contain 3.0.0" || fail "bump: some files missing 3.0.0"

# ═══════════════════════════════════════════
# Section 4: Verification Output
# ═══════════════════════════════════════════
echo ""
echo "--- Section 4: Verification Output ---"

# Test 16: Bump script prints verification summary
FAKE_ROOT2="$TMPDIR/fake-repo2"
mkdir -p "$FAKE_ROOT2/.claude-plugin" "$FAKE_ROOT2/mcp" "$FAKE_ROOT2/docs" "$FAKE_ROOT2/scripts"
cp "$ROOT_DIR/.claude-plugin/plugin.json" "$FAKE_ROOT2/.claude-plugin/"
cp "$ROOT_DIR/.claude-plugin/marketplace.json" "$FAKE_ROOT2/.claude-plugin/"
cp "$ROOT_DIR/mcp/package.json" "$FAKE_ROOT2/mcp/"
cp "$ROOT_DIR/README.md" "$FAKE_ROOT2/"
cp "$ROOT_DIR/docs/INSTALL.md" "$FAKE_ROOT2/docs/"
cp "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" "$FAKE_ROOT2/docs/"
cp "$ROOT_DIR/mcp/server.mjs" "$FAKE_ROOT2/mcp/"
cp "$BUMP_SCRIPT" "$FAKE_ROOT2/scripts/"

OUTPUT=$(bash "$FAKE_ROOT2/scripts/version-bump.sh" 4.0.0 2>&1)
echo "$OUTPUT" | grep -q "7/7 files updated" && pass "verification: shows 7/7 files updated" || fail "verification: missing 7/7 summary"
echo "$OUTPUT" | grep -q "7/7 files confirmed" && pass "verification: shows 7/7 files confirmed" || fail "verification: missing 7/7 confirmed"

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "Results: $PASS passed / $FAIL failed (total $TOTAL checks)"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "STATUS: FAILED"
  exit 1
else
  echo "STATUS: PASSED"
  exit 0
fi
