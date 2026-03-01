#!/usr/bin/env bash

# DevSecOps AI Team — Pre-Commit Gate Hook
# Blocks git commits when CRITICAL findings exist
# Runs as PreToolUse hook on Bash (matches git commit commands)
# Exit 0 = allow, Exit 2 = block

# Read tool input from stdin
INPUT=$(cat)

# Check if this is a git commit command
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null)

# Only act on git commit commands
if ! echo "$COMMAND" | grep -qE "^git\s+commit"; then
  exit 0
fi

# Look for recent scan results with CRITICAL findings
RESULTS_DIR=".devsecops/results"
if [ ! -d "$RESULTS_DIR" ]; then
  # No scan results — allow (scans may not have been run yet)
  exit 0
fi

# Check for CRITICAL findings in any recent result file
CRITICAL_COUNT=0
for result in "$RESULTS_DIR"/*.json; do
  [ -f "$result" ] || continue
  COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$result'))
    summary = d.get('summary', {})
    print(summary.get('critical', 0))
except:
    print(0)
" 2>/dev/null || echo 0)
  CRITICAL_COUNT=$((CRITICAL_COUNT + COUNT))
done

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "DevSecOps: Blocked — $CRITICAL_COUNT CRITICAL finding(s) detected." >&2
  echo "" >&2
  echo "Fix CRITICAL findings before committing:" >&2
  echo "  1. Run /security-gate to see all findings" >&2
  echo "  2. Fix the CRITICAL issues" >&2
  echo "  3. Re-run the scan to verify" >&2
  echo "" >&2
  echo "To override (requires security-lead role):" >&2
  echo "  Set DEVSECOPS_OVERRIDE=1 in environment" >&2
  exit 2
fi

exit 0
