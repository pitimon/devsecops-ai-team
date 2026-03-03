#!/usr/bin/env bash

# DevSecOps AI Team — Scan on Write Hook
# Lightweight secret + injection pattern scan on file writes
# Runs as PreToolUse hook on Edit|Write|MultiEdit
# Exit 0 = allow, Exit 2 = block

# Require python3 for JSON parsing
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 required but not found. Install Python 3.8+" >&2
  exit 1
fi

# Read tool input from stdin
INPUT=$(cat)

# Extract content to scan based on tool type
TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_name',''))" 2>/dev/null || echo "")

CONTENT=""
case "$TOOL_NAME" in
  Write)
    CONTENT=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('content',''))" 2>/dev/null)
    ;;
  Edit)
    CONTENT=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('new_string',''))" 2>/dev/null)
    ;;
  MultiEdit)
    CONTENT=$(echo "$INPUT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
edits=d.get('tool_input',{}).get('edits',[])
print(' '.join(e.get('new_string','') for e in edits))
" 2>/dev/null)
    ;;
  *)
    exit 0
    ;;
esac

# If no content extracted, allow
if [ -z "$CONTENT" ]; then
  exit 0
fi

# Secret patterns (extends governance secret-scanner)
SECRET_PATTERNS=(
  'AKIA[A-Z0-9]{16}:AWS access key ID'
  'sk-[A-Za-z0-9]{20,}:API secret key'
  'sk-proj-[A-Za-z0-9]{20,}:Project secret key'
  'ghp_[A-Za-z0-9]{36,}:GitHub personal access token'
  'gho_[A-Za-z0-9]{36,}:GitHub OAuth token'
  'ghs_[A-Za-z0-9]{36,}:GitHub server token'
  'xox[bpsar]-[A-Za-z0-9\-]{10,}:Slack token'
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}:JWT token'
)

# Injection patterns (DevSecOps-specific)
INJECTION_PATTERNS=(
  'eval\s*\([^)]*\$:Potential code injection via eval()'
  'exec\s*\([^)]*\+:Potential command injection via exec()'
  'child_process.*exec\s*\(:Potential command injection via child_process'
  'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True:Shell injection risk'
)

for ENTRY in "${SECRET_PATTERNS[@]}"; do
  PATTERN="${ENTRY%%:*}"
  DESC="${ENTRY##*:}"
  if echo "$CONTENT" | grep -qE "$PATTERN"; then
    echo "DevSecOps: Blocked — $DESC detected in file content." >&2
    echo "" >&2
    echo "Use environment variables or a secret manager instead." >&2
    exit 2
  fi
done

for ENTRY in "${INJECTION_PATTERNS[@]}"; do
  PATTERN="${ENTRY%%:*}"
  DESC="${ENTRY##*:}"
  if echo "$CONTENT" | grep -qE "$PATTERN"; then
    echo "DevSecOps: Warning — $DESC" >&2
    echo "Review this code for potential injection vulnerabilities." >&2
    # Warning only, don't block
  fi
done

exit 0
