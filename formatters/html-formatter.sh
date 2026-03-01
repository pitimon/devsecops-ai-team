#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — HTML Dashboard Formatter
# Converts normalized JSON to executive dashboard HTML

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

TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../templates" 2>/dev/null && pwd || echo "")"

python3 -c "
import json, html
from datetime import datetime

data = json.load(open('$INPUT'))
findings = data.get('findings', [])
summary = data.get('summary', {})

sev_colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#0dcaf0', 'INFO': '#6c757d'}

rows = ''
for f in findings:
    sev = f.get('severity', 'MEDIUM')
    color = sev_colors.get(sev, '#6c757d')
    tool = html.escape(f.get('source_tool', ''))
    title = html.escape(f.get('title', '')[:100])
    loc = f.get('location', {})
    location = html.escape(loc.get('file', loc.get('package', loc.get('url', ''))))
    cwe = html.escape(f.get('cwe_id', '') or '')
    rows += f'<tr><td><span style=\"color:{color};font-weight:bold\">{sev}</span></td><td>{tool}</td><td>{title}</td><td><code>{location}</code></td><td>{cwe}</td></tr>\n'

doc = f'''<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\">
<title>DevSecOps Security Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2em; background: #f8f9fa; }}
.dashboard {{ max-width: 1200px; margin: 0 auto; }}
.summary {{ display: flex; gap: 1em; margin-bottom: 2em; }}
.card {{ background: white; border-radius: 8px; padding: 1.5em; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
.card h3 {{ margin: 0; font-size: 2em; }}
.card p {{ margin: 0.5em 0 0; color: #6c757d; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
th {{ background: #343a40; color: white; padding: 0.75em; text-align: left; }}
td {{ padding: 0.75em; border-bottom: 1px solid #dee2e6; }}
code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
</style>
</head>
<body>
<div class=\"dashboard\">
<h1>DevSecOps Security Report</h1>
<p>Generated: {datetime.utcnow().strftime(\"%Y-%m-%d %H:%M UTC\")}</p>
<div class=\"summary\">
<div class=\"card\"><h3 style=\"color:#dc3545\">{summary.get(\"critical\", 0)}</h3><p>Critical</p></div>
<div class=\"card\"><h3 style=\"color:#fd7e14\">{summary.get(\"high\", 0)}</h3><p>High</p></div>
<div class=\"card\"><h3 style=\"color:#ffc107\">{summary.get(\"medium\", 0)}</h3><p>Medium</p></div>
<div class=\"card\"><h3 style=\"color:#0dcaf0\">{summary.get(\"low\", 0)}</h3><p>Low</p></div>
<div class=\"card\"><h3>{summary.get(\"total\", len(findings))}</h3><p>Total</p></div>
</div>
<table>
<tr><th>Severity</th><th>Tool</th><th>Finding</th><th>Location</th><th>CWE</th></tr>
{rows}
</table>
</div>
</body>
</html>'''

with open('$OUTPUT', 'w') as f:
    f.write(doc)
"

echo "[html] Output: $OUTPUT"
