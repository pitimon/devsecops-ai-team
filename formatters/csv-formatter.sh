#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — CSV Formatter
# Converts normalized JSON scan results to CSV
#
# Usage: csv-formatter.sh --input <json> --output <csv>
# Headers: id,source_tool,rule_id,severity,title,cwe_id,owasp,file,line_start,message

INPUT=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Usage: $0 --input <json> --output <csv>"; exit 1 ;;
  esac
done

[ -z "$INPUT" ] || [ -z "$OUTPUT" ] && { echo "Usage: $0 --input <json> --output <csv>"; exit 1; }
[ ! -f "$INPUT" ] && { echo "[csv-formatter] ERROR: Input file not found: $INPUT"; exit 1; }

python3 -c "
import csv, json, sys

with open('$INPUT') as f:
    data = json.load(f)

findings = data.get('findings', [])

with open('$OUTPUT', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['id', 'source_tool', 'rule_id', 'severity', 'title', 'cwe_id', 'owasp', 'file', 'line_start', 'message'])
    for f in findings:
        loc = f.get('location', {})
        writer.writerow([
            f.get('id', ''),
            f.get('source_tool', ''),
            f.get('rule_id', ''),
            f.get('severity', ''),
            f.get('title', ''),
            f.get('cwe_id', ''),
            f.get('owasp', ''),
            loc.get('file', ''),
            loc.get('line_start', ''),
            f.get('message', '')
        ])

print(f'[csv-formatter] Wrote {len(findings)} findings to $OUTPUT')
" || { echo "[csv-formatter] ERROR: CSV conversion failed (requires python3)"; exit 1; }

echo "[csv-formatter] CSV output: $OUTPUT"
