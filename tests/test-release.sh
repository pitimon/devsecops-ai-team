#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Release Script Tests
# ~12 tests covering release-checklist.sh and release.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECKLIST_SCRIPT="$ROOT_DIR/scripts/release-checklist.sh"
RELEASE_SCRIPT="$ROOT_DIR/scripts/release.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Release Script Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Release Checklist — Detection
# ═══════════════════════════════════════════
echo "--- Section 1: Checklist Detection ---"

# Test 1: Checklist detects missing CHANGELOG entry
FAKE_ROOT="$TMPDIR/fake-missing-changelog"
mkdir -p "$FAKE_ROOT/.claude-plugin" "$FAKE_ROOT/mcp/dist" "$FAKE_ROOT/docs" "$FAKE_ROOT/scripts"
echo '{"version": "9.9.9", "name": "devsecops-ai-team", "skills": "./skills/"}' > "$FAKE_ROOT/.claude-plugin/plugin.json"
echo '{"version": "9.9.9"}' > "$FAKE_ROOT/.claude-plugin/marketplace.json"
echo '{"version": "9.9.9", "type": "module", "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}' > "$FAKE_ROOT/mcp/package.json"
echo 'version: "9.9.9"' > "$FAKE_ROOT/mcp/server.mjs"
echo 'Version-9.9.9 v9.9.9' > "$FAKE_ROOT/README.md"
echo 'v9.9.9' > "$FAKE_ROOT/docs/INSTALL.md"
echo 'v9.9.9' > "$FAKE_ROOT/docs/MANDAY-ESTIMATION.md"
echo '// bundle 9.9.9' > "$FAKE_ROOT/mcp/dist/server.js"
# CHANGELOG without the target version
cat > "$FAKE_ROOT/CHANGELOG.md" <<'EOCHANGELOG'
# Changelog
## [1.0.0] — 2026-01-01
### Added
- Initial release
EOCHANGELOG
# Copy scripts
cp "$CHECKLIST_SCRIPT" "$FAKE_ROOT/scripts/"
cp "$RELEASE_SCRIPT" "$FAKE_ROOT/scripts/"
chmod +x "$FAKE_ROOT/scripts/"*.sh

OUTPUT=$(bash "$FAKE_ROOT/scripts/release-checklist.sh" 9.9.9 2>&1) && EXITCODE=$? || EXITCODE=$?
echo "$OUTPUT" | grep -q '\[FAIL\].*CHANGELOG.*9.9.9' \
  && pass "checklist detects missing CHANGELOG entry" \
  || fail "checklist should detect missing CHANGELOG entry"

# Test 2: Checklist detects stale README badge
FAKE_ROOT2="$TMPDIR/fake-stale-badge"
mkdir -p "$FAKE_ROOT2/.claude-plugin" "$FAKE_ROOT2/mcp/dist" "$FAKE_ROOT2/docs" "$FAKE_ROOT2/scripts"
echo '{"version": "9.9.9", "name": "devsecops-ai-team", "skills": "./skills/"}' > "$FAKE_ROOT2/.claude-plugin/plugin.json"
echo '{"version": "9.9.9"}' > "$FAKE_ROOT2/.claude-plugin/marketplace.json"
echo '{"version": "9.9.9", "type": "module", "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}' > "$FAKE_ROOT2/mcp/package.json"
echo 'version: "9.9.9"' > "$FAKE_ROOT2/mcp/server.mjs"
echo 'Version-1.0.0 v1.0.0' > "$FAKE_ROOT2/README.md"  # stale badge
echo 'v9.9.9' > "$FAKE_ROOT2/docs/INSTALL.md"
echo 'v9.9.9' > "$FAKE_ROOT2/docs/MANDAY-ESTIMATION.md"
echo '// bundle 9.9.9' > "$FAKE_ROOT2/mcp/dist/server.js"
cat > "$FAKE_ROOT2/CHANGELOG.md" <<'EOCHANGELOG'
# Changelog
## [9.9.9] — 2026-03-03
### Added
- Test release
EOCHANGELOG
cp "$CHECKLIST_SCRIPT" "$FAKE_ROOT2/scripts/"
chmod +x "$FAKE_ROOT2/scripts/"*.sh

OUTPUT=$(bash "$FAKE_ROOT2/scripts/release-checklist.sh" 9.9.9 2>&1) && EXITCODE=$? || EXITCODE=$?
echo "$OUTPUT" | grep -q '\[FAIL\].*README.*badge.*9.9.9' \
  && pass "checklist detects stale README badge" \
  || fail "checklist should detect stale README badge"

# Test 3: Checklist detects version mismatch in JSON files
FAKE_ROOT3="$TMPDIR/fake-json-mismatch"
mkdir -p "$FAKE_ROOT3/.claude-plugin" "$FAKE_ROOT3/mcp/dist" "$FAKE_ROOT3/docs" "$FAKE_ROOT3/scripts"
echo '{"version": "9.9.9", "name": "devsecops-ai-team", "skills": "./skills/"}' > "$FAKE_ROOT3/.claude-plugin/plugin.json"
echo '{"version": "1.0.0"}' > "$FAKE_ROOT3/.claude-plugin/marketplace.json"  # mismatch
echo '{"version": "9.9.9", "type": "module", "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}' > "$FAKE_ROOT3/mcp/package.json"
echo 'version: "9.9.9"' > "$FAKE_ROOT3/mcp/server.mjs"
echo 'Version-9.9.9 v9.9.9' > "$FAKE_ROOT3/README.md"
echo 'v9.9.9' > "$FAKE_ROOT3/docs/INSTALL.md"
echo 'v9.9.9' > "$FAKE_ROOT3/docs/MANDAY-ESTIMATION.md"
echo '// bundle 9.9.9' > "$FAKE_ROOT3/mcp/dist/server.js"
cat > "$FAKE_ROOT3/CHANGELOG.md" <<'EOCHANGELOG'
# Changelog
## [9.9.9] — 2026-03-03
### Added
- Test release
EOCHANGELOG
cp "$CHECKLIST_SCRIPT" "$FAKE_ROOT3/scripts/"
chmod +x "$FAKE_ROOT3/scripts/"*.sh

OUTPUT=$(bash "$FAKE_ROOT3/scripts/release-checklist.sh" 9.9.9 2>&1) && EXITCODE=$? || EXITCODE=$?
echo "$OUTPUT" | grep -q '\[FAIL\].*marketplace.json.*NOT.*9.9.9' \
  && pass "checklist detects version mismatch in marketplace.json" \
  || fail "checklist should detect marketplace.json mismatch"

# Test 4: Checklist detects MCP bundle missing
FAKE_ROOT4="$TMPDIR/fake-no-bundle"
mkdir -p "$FAKE_ROOT4/.claude-plugin" "$FAKE_ROOT4/mcp" "$FAKE_ROOT4/docs" "$FAKE_ROOT4/scripts"
echo '{"version": "9.9.9", "name": "devsecops-ai-team", "skills": "./skills/"}' > "$FAKE_ROOT4/.claude-plugin/plugin.json"
echo '{"version": "9.9.9"}' > "$FAKE_ROOT4/.claude-plugin/marketplace.json"
echo '{"version": "9.9.9", "type": "module", "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}' > "$FAKE_ROOT4/mcp/package.json"
echo 'version: "9.9.9"' > "$FAKE_ROOT4/mcp/server.mjs"
echo 'Version-9.9.9 v9.9.9' > "$FAKE_ROOT4/README.md"
echo 'v9.9.9' > "$FAKE_ROOT4/docs/INSTALL.md"
echo 'v9.9.9' > "$FAKE_ROOT4/docs/MANDAY-ESTIMATION.md"
# No mcp/dist/server.js
cat > "$FAKE_ROOT4/CHANGELOG.md" <<'EOCHANGELOG'
# Changelog
## [9.9.9] — 2026-03-03
### Added
- Test release
EOCHANGELOG
cp "$CHECKLIST_SCRIPT" "$FAKE_ROOT4/scripts/"
chmod +x "$FAKE_ROOT4/scripts/"*.sh

OUTPUT=$(bash "$FAKE_ROOT4/scripts/release-checklist.sh" 9.9.9 2>&1) && EXITCODE=$? || EXITCODE=$?
echo "$OUTPUT" | grep -q '\[FAIL\].*MCP.*bundle.*missing' \
  && pass "checklist detects MCP bundle missing" \
  || fail "checklist should detect missing MCP bundle"

# Test 5: Checklist passes on current repo state
OUTPUT=$(bash "$CHECKLIST_SCRIPT" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -eq 0 ] \
  && pass "checklist passes on current repo state" \
  || fail "checklist should pass on current repo (exit $EXITCODE)"

# ═══════════════════════════════════════════
# Section 2: Release Script — Validation
# ═══════════════════════════════════════════
echo ""
echo "--- Section 2: Release Script Validation ---"

# Test 6: Rejects invalid semver
OUTPUT=$(bash "$RELEASE_SCRIPT" "abc" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] \
  && pass "release rejects invalid semver 'abc'" \
  || fail "release should reject 'abc'"

# Test 7: Rejects semver with v prefix
OUTPUT=$(bash "$RELEASE_SCRIPT" "v2.7.0" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] \
  && pass "release rejects 'v2.7.0' (v prefix)" \
  || fail "release should reject v-prefixed version"

# Test 8: Rejects missing patch version
OUTPUT=$(bash "$RELEASE_SCRIPT" "2.7" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] \
  && pass "release rejects incomplete semver '2.7'" \
  || fail "release should reject '2.7'"

# Test 9: Shows usage without arguments
OUTPUT=$(bash "$RELEASE_SCRIPT" 2>&1) && EXITCODE=$? || EXITCODE=$?
[ "$EXITCODE" -ne 0 ] && echo "$OUTPUT" | grep -qi "usage" \
  && pass "release shows usage with no args" \
  || fail "release should show usage when no args"

# ═══════════════════════════════════════════
# Section 3: Release Script — Dry Run
# ═══════════════════════════════════════════
echo ""
echo "--- Section 3: Dry Run Safety ---"

# Test 10: Dry-run makes no git changes
BEFORE_HEAD=$(cd "$ROOT_DIR" && git rev-parse HEAD 2>/dev/null || echo "none")
OUTPUT=$(bash "$RELEASE_SCRIPT" 2.6.0 --dry-run 2>&1) && EXITCODE=$? || EXITCODE=$?
AFTER_HEAD=$(cd "$ROOT_DIR" && git rev-parse HEAD 2>/dev/null || echo "none")

[ "$BEFORE_HEAD" = "$AFTER_HEAD" ] \
  && pass "dry-run: HEAD unchanged" \
  || fail "dry-run: HEAD changed (was $BEFORE_HEAD, now $AFTER_HEAD)"

# Test 11: Dry-run output contains DRY-RUN markers
echo "$OUTPUT" | grep -q "DRY.RUN" \
  && pass "dry-run: output contains DRY-RUN markers" \
  || fail "dry-run: missing DRY-RUN markers"

# Test 12: Dry-run does not create tag
TAG_EXISTS=$(cd "$ROOT_DIR" && git tag -l "v99.99.99" 2>/dev/null || echo "")
bash "$RELEASE_SCRIPT" 99.99.99 --dry-run >/dev/null 2>&1 || true
TAG_AFTER=$(cd "$ROOT_DIR" && git tag -l "v99.99.99" 2>/dev/null || echo "")
[ "$TAG_EXISTS" = "$TAG_AFTER" ] \
  && pass "dry-run: no tag created for v99.99.99" \
  || fail "dry-run: tag v99.99.99 was created"

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
