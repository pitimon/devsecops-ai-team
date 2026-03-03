#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Version Bump Script
# Bumps version across all 7 files that track the plugin version.
#
# Usage:
#   bash scripts/version-bump.sh <new-version> [--dry-run]
#
# Examples:
#   bash scripts/version-bump.sh 2.6.0
#   bash scripts/version-bump.sh 2.6.0 --dry-run

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Parse arguments ───
NEW_VERSION=""
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=true
      ;;
    -*)
      echo "ERROR: Unknown flag: $arg" >&2
      echo "Usage: $0 <new-version> [--dry-run]" >&2
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
  echo "Usage: $0 <new-version> [--dry-run]" >&2
  exit 1
fi

# ─── Validate semver format ───
if ! echo "$NEW_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "ERROR: Invalid semver format: '$NEW_VERSION'" >&2
  echo "Expected format: X.Y.Z (e.g., 2.6.0)" >&2
  exit 1
fi

# ─── Read current version from plugin.json ───
CURRENT_VERSION=$(python3 -c "import json; print(json.load(open('$ROOT_DIR/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "unknown")

echo "============================================"
echo "DevSecOps AI Team — Version Bump"
echo "============================================"
echo ""
echo "Current version: $CURRENT_VERSION"
echo "New version:     $NEW_VERSION"
echo "Dry run:         $DRY_RUN"
echo ""

if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
  echo "WARNING: New version is the same as current version ($CURRENT_VERSION)" >&2
fi

# ─── Helper: bump version in a file ───
# Usage: bump_file <file> <sed-pattern> <description>
bump_file() {
  local file="$1"
  local pattern="$2"
  local desc="$3"

  if [ ! -f "$file" ]; then
    echo "  [SKIP] $desc — file not found: $file"
    return 1
  fi

  if $DRY_RUN; then
    echo "  [DRY-RUN] Would update $desc"
    return 0
  fi

  sed -i '' "$pattern" "$file" 2>/dev/null || sed -i "$pattern" "$file"
  echo "  [UPDATED] $desc"
}

BUMP_COUNT=0
BUMP_ERRORS=0

# ─── 1. .claude-plugin/plugin.json ───
echo "--- Updating 7 version files ---"
if bump_file "$ROOT_DIR/.claude-plugin/plugin.json" \
  "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" \
  "plugin.json — \"version\": \"$NEW_VERSION\""; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 2. .claude-plugin/marketplace.json ───
if bump_file "$ROOT_DIR/.claude-plugin/marketplace.json" \
  "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" \
  "marketplace.json — \"version\": \"$NEW_VERSION\""; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 3. mcp/package.json ───
if bump_file "$ROOT_DIR/mcp/package.json" \
  "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" \
  "mcp/package.json — \"version\": \"$NEW_VERSION\""; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 4. README.md — badge + table rows ───
if bump_file "$ROOT_DIR/README.md" \
  "s/Version-$CURRENT_VERSION/Version-$NEW_VERSION/g; s/v$CURRENT_VERSION/v$NEW_VERSION/g" \
  "README.md — badge Version-$NEW_VERSION + vX.Y.Z references"; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 5. docs/INSTALL.md — vX.Y.Z references ───
if bump_file "$ROOT_DIR/docs/INSTALL.md" \
  "s/v$CURRENT_VERSION/v$NEW_VERSION/g; s/$CURRENT_VERSION/$NEW_VERSION/g" \
  "docs/INSTALL.md — v$NEW_VERSION references"; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 6. docs/MANDAY-ESTIMATION.md — version references ───
if bump_file "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" \
  "s/v$CURRENT_VERSION/v$NEW_VERSION/g; s/$CURRENT_VERSION/$NEW_VERSION/g" \
  "docs/MANDAY-ESTIMATION.md — v$NEW_VERSION references"; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

# ─── 7. mcp/server.mjs — version in Server constructor ───
if bump_file "$ROOT_DIR/mcp/server.mjs" \
  "s/version: \"$CURRENT_VERSION\"/version: \"$NEW_VERSION\"/" \
  "mcp/server.mjs — version: \"$NEW_VERSION\" (Server constructor)"; then
  BUMP_COUNT=$((BUMP_COUNT + 1))
else
  BUMP_ERRORS=$((BUMP_ERRORS + 1))
fi

echo ""

# ─── Verification (grep check) ───
echo "--- Verification ---"
if ! $DRY_RUN; then
  VERIFY_PASS=0
  VERIFY_FAIL=0

  check_version() {
    local file="$1"
    local desc="$2"
    if grep -q "$NEW_VERSION" "$file" 2>/dev/null; then
      echo "  [OK] $desc contains $NEW_VERSION"
      VERIFY_PASS=$((VERIFY_PASS + 1))
    else
      echo "  [FAIL] $desc does NOT contain $NEW_VERSION"
      VERIFY_FAIL=$((VERIFY_FAIL + 1))
    fi
  }

  check_version "$ROOT_DIR/.claude-plugin/plugin.json" "plugin.json"
  check_version "$ROOT_DIR/.claude-plugin/marketplace.json" "marketplace.json"
  check_version "$ROOT_DIR/mcp/package.json" "mcp/package.json"
  check_version "$ROOT_DIR/README.md" "README.md"
  check_version "$ROOT_DIR/docs/INSTALL.md" "docs/INSTALL.md"
  check_version "$ROOT_DIR/docs/MANDAY-ESTIMATION.md" "docs/MANDAY-ESTIMATION.md"
  check_version "$ROOT_DIR/mcp/server.mjs" "mcp/server.mjs"

  echo ""
  echo "============================================"
  echo "Bump: $BUMP_COUNT/7 files updated ($BUMP_ERRORS errors)"
  echo "Verify: $VERIFY_PASS/7 files confirmed"
  echo "============================================"

  if [ "$VERIFY_FAIL" -gt 0 ]; then
    echo "STATUS: FAILED — some files not updated"
    exit 1
  fi
else
  echo "  [DRY-RUN] Skipping verification (no files modified)"
  echo ""
  echo "============================================"
  echo "Dry run complete — no files were modified"
  echo "============================================"
fi

echo "STATUS: OK"
exit 0
