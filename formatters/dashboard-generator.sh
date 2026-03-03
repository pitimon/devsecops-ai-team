#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Dashboard Generator
# Generates self-contained HTML dashboard from SQLite scan data
# Uses templates/dashboard.html with Alpine.js + Chart.js

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DB_PATH="${SCAN_DB:-$ROOT_DIR/output/devsecops.db}"
SCAN_ID=""
INCLUDE_TREND=false
TREND_DAYS=30
OUTPUT_PATH="$ROOT_DIR/output/dashboard.html"
PIPELINE_FILE=""
TEMPLATE_PATH="$ROOT_DIR/templates/dashboard.html"

EMPTY_SCAN='{"scan_id":"no-data","target":"N/A","started_at":"","finished_at":"","status":"no-data","findings":[],"compliance":[]}'

usage() {
  cat <<EOF
Usage: dashboard-generator.sh [options]

Generates a self-contained HTML security dashboard from SQLite data.

Options:
  --db <path>         SQLite database path (default: output/devsecops.db)
  --scan-id <id>      Show results for specific scan
  --trend             Include trend data
  --days <n>          Trend period in days (default: 30)
  --output <path>     Output HTML path (default: output/dashboard.html)
  --pipeline <file>   Include pipeline state from JSON file
  --help              Show this help

Examples:
  dashboard-generator.sh
  dashboard-generator.sh --db output/devsecops.db --trend --days 14
  dashboard-generator.sh --scan-id abc123 --output report.html
  dashboard-generator.sh --pipeline output/pipeline-state.json
EOF
  exit 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db)       DB_PATH="$2"; shift 2 ;;
      --scan-id)  SCAN_ID="$2"; shift 2 ;;
      --trend)    INCLUDE_TREND=true; shift ;;
      --days)     TREND_DAYS="$2"; INCLUDE_TREND=true; shift 2 ;;
      --output)   OUTPUT_PATH="$2"; shift 2 ;;
      --pipeline) PIPELINE_FILE="$2"; shift 2 ;;
      --help)     usage ;;
      *)          echo "[dashboard] ERROR: Unknown option: $1" >&2; exit 1 ;;
    esac
  done
}

# Query scan metadata — returns scan_id or empty string
query_scan_id() {
  local db="$1" scan_id="${2:-}"
  python3 -c "
import sqlite3, sys, os
db_path, scan_id = '$db', '$scan_id'
if not os.path.exists(db_path):
    sys.exit(0)
db = sqlite3.connect(db_path)
c = db.cursor()
if scan_id:
    r = c.execute('SELECT scan_id FROM scans WHERE scan_id=? LIMIT 1', (scan_id,)).fetchone()
else:
    r = c.execute('SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1').fetchone()
db.close()
print(r[0] if r else '')
"
}

# Build scan JSON with findings + compliance for a known scan_id
query_scan_json() {
  local db="$1" sid="$2"
  python3 -c "
import sqlite3, json
db = sqlite3.connect('$db')
db.row_factory = sqlite3.Row
c = db.cursor()
row = c.execute(
    'SELECT scan_id,target,started_at,finished_at,status FROM scans WHERE scan_id=?', ('$sid',)
).fetchone()
scan = {k: (row[k] or '') for k in ['scan_id','target','started_at','finished_at','status']}
findings = []
for f in c.execute(
    'SELECT rule_id,severity,file,line_start,source_tool,cwe,owasp,'
    'raw_finding,first_seen,last_seen,triage,fingerprint '
    'FROM findings WHERE scan_id=? ORDER BY severity,rule_id', ('$sid',)
).fetchall():
    owasp = f['owasp']
    try: owasp = json.loads(owasp) if owasp else []
    except Exception: owasp = [owasp] if owasp else []
    raw = f['raw_finding']
    try: raw = json.loads(raw) if raw else None
    except Exception: pass
    findings.append({
        'rule_id': f['rule_id'], 'severity': f['severity'].lower(),
        'file': f['file'], 'line_start': f['line_start'],
        'source_tool': f['source_tool'], 'cwe': f['cwe'],
        'owasp': owasp, 'raw_finding': raw,
        'first_seen': f['first_seen'], 'last_seen': f['last_seen'],
        'triage': f['triage'], 'fingerprint': f['fingerprint'],
    })
scan['findings'] = findings
comps = []
for cs in c.execute(
    'SELECT framework,coverage FROM compliance_snapshots WHERE scan_id=? ORDER BY framework', ('$sid',)
).fetchall():
    comps.append({'framework': cs['framework'], 'coverage': cs['coverage'] or 0.0})
scan['compliance'] = comps
db.close()
print(json.dumps(scan))
"
}

# Orchestrate scan data: resolve scan_id then query full JSON
generate_scan_data() {
  local db="$1" scan_id="${2:-}"
  local sid
  sid="$(query_scan_id "$db" "$scan_id")"
  if [ -z "$sid" ]; then
    echo "$EMPTY_SCAN"
    return
  fi
  query_scan_json "$db" "$sid"
}

generate_pipeline_data() {
  local pipeline_file="${1:-}"
  python3 -c "
import json, sys, os
pf = '$pipeline_file'
default = {'name': '', 'nodes': []}
if not pf or not os.path.exists(pf):
    print(json.dumps(default)); sys.exit(0)
try:
    data = json.load(open(pf))
    print(json.dumps({'name': data.get('name',''), 'nodes': data.get('nodes',[])}))
except Exception:
    print(json.dumps(default))
"
}

generate_trend_data() {
  local db="$1" days="${2:-7}"
  python3 -c "
import sqlite3, json, sys, os
from datetime import datetime, timedelta
db_path, days = '$db', int('$days')
empty = {'dates':[],'critical':[],'high':[],'medium':[],'low':[]}
if not os.path.exists(db_path):
    print(json.dumps(empty)); sys.exit(0)
db = sqlite3.connect(db_path)
start = (datetime.utcnow() - timedelta(days=days)).isoformat()
rows = db.execute(
    'SELECT date(first_seen) as day,severity,COUNT(*) as cnt '
    'FROM findings WHERE first_seen>=? GROUP BY day,severity ORDER BY day',
    (start,)).fetchall()
db.close()
if not rows:
    print(json.dumps(empty)); sys.exit(0)
trend = {}
for day, sev, cnt in rows:
    trend.setdefault(day, {'critical':0,'high':0,'medium':0,'low':0})
    s = (sev or '').lower()
    if s in trend[day]: trend[day][s] = cnt
dates = sorted(trend)
print(json.dumps({
    'dates': dates,
    'critical': [trend[d]['critical'] for d in dates],
    'high': [trend[d]['high'] for d in dates],
    'medium': [trend[d]['medium'] for d in dates],
    'low': [trend[d]['low'] for d in dates],
}))
"
}

inject_data() {
  local template="$1" scan_json="$2" pipeline_json="$3"
  local trend_json="$4" output="$5"

  # Write JSON to temp files to avoid shell quoting/escape issues
  local tmp_scan tmp_pipeline tmp_trend
  tmp_scan="$(mktemp)"
  tmp_pipeline="$(mktemp)"
  tmp_trend="$(mktemp)"
  printf '%s' "$scan_json" > "$tmp_scan"
  printf '%s' "$pipeline_json" > "$tmp_pipeline"
  printf '%s' "$trend_json" > "$tmp_trend"

  python3 -c "
import re, sys

template_path = sys.argv[1]
output_path = sys.argv[2]
scan_json = open(sys.argv[3]).read().strip()
pipeline_json = open(sys.argv[4]).read().strip()
trend_json = open(sys.argv[5]).read().strip()

content = open(template_path).read()

replacements = [
    ('__SCAN_DATA__', 'SCAN_DATA', scan_json),
    ('__PIPELINE__', 'PIPELINE_DATA', pipeline_json),
    ('__TREND__', 'TREND_DATA', trend_json),
]
for marker, var_name, data_json in replacements:
    pattern = (r'const\s+' + var_name +
               r'\s*=\s*/\*' + marker + r'\*/\s*\{[^;]*\};')
    replacement = 'const ' + var_name + ' = ' + data_json + ';'
    content = re.sub(
        pattern, lambda m: replacement, content, flags=re.DOTALL)

open(output_path, 'w').write(content)
" "$template" "$output" "$tmp_scan" "$tmp_pipeline" "$tmp_trend"

  rm -f "$tmp_scan" "$tmp_pipeline" "$tmp_trend"
}

main() {
  parse_args "$@"

  # Validate template exists
  if [ ! -f "$TEMPLATE_PATH" ]; then
    echo "[dashboard] ERROR: Template not found: $TEMPLATE_PATH" >&2
    exit 1
  fi

  # Ensure output directory exists
  local output_dir
  output_dir="$(dirname "$OUTPUT_PATH")"
  [ -d "$output_dir" ] || mkdir -p "$output_dir"

  # Auto-detect pipeline state if not specified
  if [ -z "$PIPELINE_FILE" ]; then
    local default_pipeline="$ROOT_DIR/output/pipeline-state.json"
    [ -f "$default_pipeline" ] && PIPELINE_FILE="$default_pipeline"
  fi

  # Determine trend days (default 7 even without --trend flag)
  local trend_days=7
  if [ "$INCLUDE_TREND" = true ]; then
    trend_days="$TREND_DAYS"
  fi

  # Generate data
  local scan_data pipeline_data trend_data
  scan_data="$(generate_scan_data "$DB_PATH" "$SCAN_ID")"
  pipeline_data="$(generate_pipeline_data "$PIPELINE_FILE")"
  trend_data="$(generate_trend_data "$DB_PATH" "$trend_days")"

  # Inject into template and write output
  inject_data "$TEMPLATE_PATH" "$scan_data" "$pipeline_data" \
    "$trend_data" "$OUTPUT_PATH"

  echo "[dashboard] Generated: $OUTPUT_PATH"
}

main "$@"
