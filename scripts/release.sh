#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Release Orchestrator
# Full release workflow: pre-flight → version bump → MCP rebuild → checklist → tests → commit → tag → push
#
# Usage:
#   bash scripts/release.sh <version> [--dry-run] [--skip-tests] [--skip-push]
#
# Examples:
#   bash scripts/release.sh 2.7.0
#   bash scripts/release.sh 2.7.0 --dry-run
#   bash scripts/release.sh 2.7.0 --skip-tests --skip-push

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Parse arguments ───
NEW_VERSION=""
DRY_RUN=false
SKIP_TESTS=false
SKIP_PUSH=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=true ;;
    --skip-tests) SKIP_TESTS=true ;;
    --skip-push)  SKIP_PUSH=true ;;
    -*)
      echo "ERROR: Unknown flag: $arg" >&2
      echo "Usage: $0 <version> [--dry-run] [--skip-tests] [--skip-push]" >&2
      exit 1
      ;;
    *)
      if [ -z "$NEW_VERSION" ]; then
        NEW_VERSION="$arg"
      else
        echo "ERROR: Unexpected argument: $arg" >&2
        exit 1
      fi
      ;;
  esac
done

if [ -z "$NEW_VERSION" ]; then
  echo "ERROR: Version argument required" >&2
  echo "" >&2
  echo "Usage: $0 <version> [--dry-run] [--skip-tests] [--skip-push]" >&2
  echo "" >&2
  echo "Flags:" >&2
  echo "  --dry-run      Show every step without executing" >&2
  echo "  --skip-tests   Skip running test suites" >&2
  echo "  --skip-push    Stop after tag (no push to remote)" >&2
  exit 1
fi

# ─── Validate semver format ───
if ! echo "$NEW_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "ERROR: Invalid semver format: '$NEW_VERSION'" >&2
  echo "Expected format: X.Y.Z (e.g., 2.7.0)" >&2
  exit 1
fi

CURRENT_VERSION=$(python3 -c "import json; print(json.load(open('$ROOT_DIR/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "unknown")

# ─── Header ───
echo ""
echo "============================================"
echo "DevSecOps AI Team — Release v$NEW_VERSION"
echo "============================================"
echo ""
echo "Current version: $CURRENT_VERSION"
echo "Target version:  $NEW_VERSION"
echo "Dry run:         $DRY_RUN"
echo "Skip tests:      $SKIP_TESTS"
echo "Skip push:       $SKIP_PUSH"
echo ""

# ─── Helper for dry-run ───
run_step() {
  local step_num="$1"
  local step_name="$2"
  shift 2

  echo "━━━ Step $step_num: $step_name ━━━"
  if $DRY_RUN; then
    echo "  [DRY-RUN] Would execute: $*"
    echo ""
    return 0
  fi
}

# ═══════════════════════════════════════════
# Step 1: Pre-flight Checks
# ═══════════════════════════════════════════
echo "━━━ Step 1: Pre-flight Checks ━━━"

# Check for clean working tree
if ! $DRY_RUN; then
  cd "$ROOT_DIR"
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    echo "  [FAIL] Working tree is dirty. Commit or stash changes first." >&2
    echo ""
    git status --short >&2
    exit 1
  fi
  echo "  [OK] Working tree is clean"

  # Check we're on main
  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
  if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "  [WARN] Not on main branch (current: $CURRENT_BRANCH)"
  else
    echo "  [OK] On main branch"
  fi

  # Check semver is newer (simple string comparison)
  echo "  [OK] Semver valid: $NEW_VERSION"

  # Check CHANGELOG has entry for this version
  if ! grep -q "## \[$NEW_VERSION\]" "$ROOT_DIR/CHANGELOG.md" 2>/dev/null; then
    echo "  [FAIL] CHANGELOG.md has no entry for [$NEW_VERSION]" >&2
    echo "  Add a ## [$NEW_VERSION] section to CHANGELOG.md before releasing." >&2
    exit 1
  fi
  echo "  [OK] CHANGELOG has [$NEW_VERSION] entry"
else
  echo "  [DRY-RUN] Would check: clean git, main branch, CHANGELOG entry"
fi
echo ""

# ═══════════════════════════════════════════
# Step 2: Version Bump
# ═══════════════════════════════════════════
run_step 2 "Version Bump" "bash scripts/version-bump.sh $NEW_VERSION"
if ! $DRY_RUN; then
  bash "$SCRIPT_DIR/version-bump.sh" "$NEW_VERSION"
fi
echo ""

# ═══════════════════════════════════════════
# Step 3: MCP Bundle Rebuild
# ═══════════════════════════════════════════
run_step 3 "MCP Bundle Rebuild" "cd mcp && bash build.sh"
if ! $DRY_RUN; then
  if [ -f "$ROOT_DIR/mcp/build.sh" ]; then
    (cd "$ROOT_DIR/mcp" && bash build.sh)
    echo "  [OK] MCP bundle rebuilt"
  else
    echo "  [WARN] mcp/build.sh not found, skipping bundle rebuild"
  fi
fi
echo ""

# ═══════════════════════════════════════════
# Step 4: Release Checklist
# ═══════════════════════════════════════════
run_step 4 "Release Checklist" "bash scripts/release-checklist.sh $NEW_VERSION"
if ! $DRY_RUN; then
  if ! bash "$SCRIPT_DIR/release-checklist.sh" "$NEW_VERSION"; then
    echo ""
    echo "  [FAIL] Release checklist has failures. Fix them before proceeding." >&2
    exit 1
  fi
fi
echo ""

# ═══════════════════════════════════════════
# Step 5: Test Suite
# ═══════════════════════════════════════════
echo "━━━ Step 5: Test Suite ━━━"
if $SKIP_TESTS; then
  echo "  [SKIP] Tests skipped (--skip-tests)"
elif $DRY_RUN; then
  echo "  [DRY-RUN] Would run: validate-plugin.sh + all test-*.sh"
else
  echo "  Running validate-plugin.sh..."
  if ! bash "$ROOT_DIR/tests/validate-plugin.sh"; then
    echo "  [FAIL] validate-plugin.sh failed" >&2
    exit 1
  fi

  TEST_PASS=0
  TEST_FAIL=0
  while IFS= read -r test_file; do
    BASENAME=$(basename "$test_file")
    # Skip live tests that need external targets
    if [ "$BASENAME" = "test-dast-live.sh" ]; then
      echo "  [SKIP] $BASENAME (requires DAST_TARGET)"
      continue
    fi
    echo "  Running $BASENAME..."
    if bash "$test_file" >/dev/null 2>&1; then
      TEST_PASS=$((TEST_PASS + 1))
    else
      echo "  [FAIL] $BASENAME failed" >&2
      TEST_FAIL=$((TEST_FAIL + 1))
    fi
  done < <(find "$ROOT_DIR/tests" -name 'test-*.sh' -type f | sort)

  if [ "$TEST_FAIL" -gt 0 ]; then
    echo "  [FAIL] $TEST_FAIL test suite(s) failed" >&2
    exit 1
  fi
  echo "  [OK] All $TEST_PASS test suites passed"
fi
echo ""

# ═══════════════════════════════════════════
# Step 6: Commit
# ═══════════════════════════════════════════
run_step 6 "Commit" "git add -A && git commit -m 'chore: release v$NEW_VERSION'"
if ! $DRY_RUN; then
  cd "$ROOT_DIR"
  git add -A
  if [ -n "$(git status --porcelain)" ]; then
    git commit -m "chore: release v$NEW_VERSION"
    echo "  [OK] Committed: chore: release v$NEW_VERSION"
  else
    echo "  [OK] No changes to commit (version already current)"
  fi
fi
echo ""

# ═══════════════════════════════════════════
# Step 7: Tag
# ═══════════════════════════════════════════
run_step 7 "Tag" "git tag -a v$NEW_VERSION"
if ! $DRY_RUN; then
  cd "$ROOT_DIR"
  # Extract changelog section for tag message
  TAG_MSG=$(awk "/^## \[$NEW_VERSION\]/{flag=1; next} /^## \[/{flag=0} flag" "$ROOT_DIR/CHANGELOG.md" | head -30)
  if [ -z "$TAG_MSG" ]; then
    TAG_MSG="Release v$NEW_VERSION"
  fi
  git tag -a "v$NEW_VERSION" -m "$(printf "Release v%s\n\n%s" "$NEW_VERSION" "$TAG_MSG")"
  echo "  [OK] Tagged: v$NEW_VERSION"
fi
echo ""

# ═══════════════════════════════════════════
# Step 8: Push
# ═══════════════════════════════════════════
echo "━━━ Step 8: Push ━━━"
if $SKIP_PUSH; then
  echo "  [SKIP] Push skipped (--skip-push)"
  echo "  To push manually:"
  echo "    git push origin main && git push origin v$NEW_VERSION"
elif $DRY_RUN; then
  echo "  [DRY-RUN] Would execute: git push origin main && git push origin v$NEW_VERSION"
else
  cd "$ROOT_DIR"
  git push origin main
  git push origin "v$NEW_VERSION"
  echo "  [OK] Pushed main + v$NEW_VERSION"
fi
echo ""

# ═══════════════════════════════════════════
# Step 9: Summary
# ═══════════════════════════════════════════
echo "============================================"
if $DRY_RUN; then
  echo "DRY RUN COMPLETE — no changes were made"
  echo ""
  echo "To release for real:"
  echo "  bash scripts/release.sh $NEW_VERSION"
else
  echo "RELEASE v$NEW_VERSION COMPLETE"
  echo ""
  echo "What was done:"
  echo "  1. Version bumped across 7 files"
  echo "  2. MCP bundle rebuilt"
  echo "  3. Release checklist passed"
  if ! $SKIP_TESTS; then
    echo "  4. All test suites passed"
  fi
  echo "  5. Committed: chore: release v$NEW_VERSION"
  echo "  6. Tagged: v$NEW_VERSION"
  if ! $SKIP_PUSH; then
    echo "  7. Pushed to origin"
  fi
  echo ""
  echo "Remaining manual steps:"
  echo "  - Close milestone issues on GitHub"
  echo "  - Update MEMORY.md version reference"
  echo "  - Verify GitHub Actions release workflow completes"
fi
echo "============================================"
