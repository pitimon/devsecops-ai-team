#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Markdown Formatter
# Converts normalized JSON to PR-comment-ready Markdown

INPUT=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$INPUT" ] || [ -z "$OUTPUT" ] && { echo "Usage: $0 --input <file> --output <file>"; exit 1; }

python3 -c "
import json

data = json.load(open('$INPUT'))
findings = data.get('findings', [])
summary = data.get('summary', {})

lines = []
lines.append('## Security Scan Results')
lines.append('')
lines.append(f\"Total findings: **{summary.get('total', len(findings))}** | \")
lines.append(f\"CRITICAL: {summary.get('critical', 0)} | HIGH: {summary.get('high', 0)} | \")
lines.append(f\"MEDIUM: {summary.get('medium', 0)} | LOW: {summary.get('low', 0)}\")
lines.append('')

for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
    sev_findings = [f for f in findings if f.get('severity') == sev]
    if not sev_findings:
        continue
    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '⚪'}.get(sev, '')
    lines.append(f'### {emoji} {sev} ({len(sev_findings)})')
    lines.append('')
    lines.append('| Tool | Finding | Location |')
    lines.append('|------|---------|----------|')
    for f in sev_findings:
        tool = f.get('source_tool', 'unknown')
        title = f.get('title', '')[:80]
        loc = f.get('location', {})
        location = loc.get('file', loc.get('package', loc.get('url', '')))
        if loc.get('line_start'):
            location += f\":{loc['line_start']}\"
        lines.append(f'| {tool} | {title} | \`{location}\` |')
    lines.append('')

with open('$OUTPUT', 'w') as f:
    f.write('\n'.join(lines))
"

echo "[markdown] Output: $OUTPUT"
