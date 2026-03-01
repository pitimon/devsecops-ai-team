#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Rules Installer
# Installs DevSecOps rules to ~/.claude/rules/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RULES_DIR="${HOME}/.claude/rules"

echo "DevSecOps AI Team — Rules Installation"
echo "======================================="

mkdir -p "$RULES_DIR"

for rule in "$ROOT_DIR/examples/rules/"*.md; do
  [ -f "$rule" ] || continue
  BASENAME=$(basename "$rule")
  if [ -f "$RULES_DIR/$BASENAME" ]; then
    echo "  [SKIP] $BASENAME already exists"
  else
    cp "$rule" "$RULES_DIR/$BASENAME"
    echo "  [OK] Installed $BASENAME"
  fi
done

echo ""
echo "Rules installed to $RULES_DIR"
echo "These rules will be active in all Claude Code sessions."
