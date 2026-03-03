#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Scan Database Manager
# SQLite-based historical scan storage with provenance tracking

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="${SCAN_DB:-$ROOT_DIR/output/devsecops.db}"

usage() {
  cat <<EOF
Usage: scan-db.sh <command> [options]

Commands:
  init                          Create database and tables
  store <normalized.json>       Import findings from a scan
  query [--severity S] [--tool T] [--cwe C]  Query findings
  trend [--days N]              Findings over time (default: 30)
  lifecycle --fingerprint FP    Show finding lifecycle
  export [--format json|csv]    Export database
  stats                         Summary statistics

Options:
  --db <path>                   Database path (default: output/devsecops.db)
EOF
  exit 1
}

# Parse --db flag from any position
prev_arg=""
for arg in "$@"; do
  if [ "$prev_arg" = "--db" ]; then
    DB_PATH="$arg"
  fi
  prev_arg="$arg"
done

ensure_db_dir() {
  local db_dir
  db_dir="$(dirname "$DB_PATH")"
  [ -d "$db_dir" ] || mkdir -p "$db_dir"
}

cmd_init() {
  ensure_db_dir
  python3 -c "
import sqlite3, sys

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT UNIQUE NOT NULL,
    target      TEXT NOT NULL,
    tools       TEXT NOT NULL,
    pipeline    TEXT,
    config      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT DEFAULT 'running'
)''')

c.execute('''CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id),
    fingerprint  TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    file         TEXT,
    line_start   INTEGER,
    source_tool  TEXT NOT NULL,
    cwe          TEXT,
    owasp        TEXT,
    raw_finding  TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    fixed_at     TEXT,
    triage       TEXT DEFAULT 'open'
)''')

c.execute('''CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
    framework   TEXT NOT NULL,
    coverage    REAL,
    details     TEXT,
    captured_at TEXT NOT NULL
)''')

c.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(source_tool)')

db.commit()
db.close()
print('[scan-db] Database initialized: $DB_PATH')
"
}

cmd_store() {
  local input_file="$1"
  [ -f "$input_file" ] || { echo "[scan-db] ERROR: File not found: $input_file"; exit 1; }

  python3 -c "
import json, sqlite3, uuid, sys
from datetime import datetime

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

with open('$input_file') as f:
    data = json.load(f)

findings = data.get('findings', [])
if not findings:
    print('[scan-db] No findings to store')
    sys.exit(0)

scan_id = str(uuid.uuid4())[:8]
now = datetime.utcnow().isoformat() + 'Z'
tools = list(set(f.get('source_tool', 'unknown') for f in findings))

c.execute('''INSERT INTO scans (scan_id, target, tools, started_at, finished_at, status)
             VALUES (?, ?, ?, ?, ?, ?)''',
          (scan_id, '$input_file', json.dumps(tools), now, now, 'completed'))

stored = 0
updated = 0
for f in findings:
    fp = f'{f.get(\"rule_id\",\"\")}:{f.get(\"location\",{}).get(\"file\",\"\")}:{f.get(\"location\",{}).get(\"line_start\",0)}'

    # Check if finding already exists (by fingerprint)
    c.execute('SELECT id, last_seen FROM findings WHERE fingerprint = ? AND fixed_at IS NULL', (fp,))
    existing = c.fetchone()

    if existing:
        # Update last_seen
        c.execute('UPDATE findings SET last_seen = ?, scan_id = ? WHERE id = ?', (now, scan_id, existing[0]))
        updated += 1
    else:
        # New finding
        loc = f.get('location', {})
        owasp = json.dumps(f.get('owasp', [])) if f.get('owasp') else None
        c.execute('''INSERT INTO findings
                     (scan_id, fingerprint, rule_id, severity, file, line_start, source_tool, cwe, owasp, raw_finding, first_seen, last_seen)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (scan_id, fp, f.get('rule_id',''), f.get('severity',''),
                   loc.get('file',''), loc.get('line_start',0),
                   f.get('source_tool',''), f.get('cwe_id'), owasp,
                   json.dumps(f), now, now))
        stored += 1

# Mark findings not in this scan as fixed
all_fps = set()
for f in findings:
    fp = f'{f.get(\"rule_id\",\"\")}:{f.get(\"location\",{}).get(\"file\",\"\")}:{f.get(\"location\",{}).get(\"line_start\",0)}'
    all_fps.add(fp)

c.execute('SELECT id, fingerprint FROM findings WHERE fixed_at IS NULL AND scan_id != ?', (scan_id,))
for row in c.fetchall():
    if row[1] not in all_fps:
        c.execute('UPDATE findings SET fixed_at = ?, triage = ? WHERE id = ?', (now, 'fixed', row[0]))

db.commit()
db.close()
print(f'[scan-db] Stored: scan={scan_id}, new={stored}, updated={updated}, tools={\",\".join(tools)}')
"
  # Post-store enrichment: OWASP tags + compliance snapshots
  enrich_owasp "$DB_PATH" "$input_file"
  generate_compliance "$DB_PATH" "$input_file"
}

# Enrich findings with OWASP tags from CWE→OWASP mapping
enrich_owasp() {
  local db="$1" input_file="$2"
  local mapping_file="$ROOT_DIR/mappings/cwe-to-owasp.json"
  [ -f "$mapping_file" ] || return 0

  python3 -c "
import sqlite3, json, sys

db = sqlite3.connect(sys.argv[1])
mapping = json.load(open(sys.argv[2])).get('mappings', {})

# Get latest scan_id
scan_id = db.execute(
    'SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1'
).fetchone()
if not scan_id:
    db.close(); sys.exit(0)
scan_id = scan_id[0]

enriched = 0
rows = db.execute(
    'SELECT id, cwe FROM findings WHERE scan_id = ? AND cwe IS NOT NULL',
    (scan_id,)
).fetchall()
for fid, cwe in rows:
    key = cwe if cwe.startswith('CWE-') else f'CWE-{cwe}'
    entry = mapping.get(key)
    if entry and entry.get('owasp'):
        db.execute('UPDATE findings SET owasp = ? WHERE id = ?',
                   (json.dumps(entry['owasp']), fid))
        enriched += 1

db.commit()
db.close()
if enriched:
    print(f'[scan-db] Enriched: {enriched} findings with OWASP tags')
" "$db" "$mapping_file"
}

# Generate compliance snapshots from 7 framework mappings
generate_compliance() {
  local db="$1" input_file="$2"
  local mappings_dir="$ROOT_DIR/mappings"
  [ -d "$mappings_dir" ] || return 0

  python3 -c "
import sqlite3, json, glob, os, sys
from datetime import datetime

db = sqlite3.connect(sys.argv[1])
mappings_dir = sys.argv[2]

scan_id = db.execute(
    'SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1'
).fetchone()
if not scan_id:
    db.close(); sys.exit(0)
scan_id = scan_id[0]
now = datetime.utcnow().isoformat() + 'Z'

# Collect CWEs from this scan
scan_cwes = set()
for row in db.execute(
    'SELECT cwe FROM findings WHERE scan_id = ? AND cwe IS NOT NULL',
    (scan_id,)
).fetchall():
    cwe = row[0]
    scan_cwes.add(cwe if cwe.startswith('CWE-') else f'CWE-{cwe}')

frameworks = 0
for mfile in sorted(glob.glob(os.path.join(mappings_dir, 'cwe-to-*.json'))):
    fname = os.path.basename(mfile)
    framework = fname.replace('cwe-to-', '').replace('.json', '')
    mapping = json.load(open(mfile)).get('mappings', {})
    if not mapping:
        continue
    matched = len(scan_cwes & set(mapping.keys()))
    coverage = round(matched / len(mapping) * 100, 1)
    details = json.dumps({'matched': matched, 'total': len(mapping)})
    db.execute(
        'INSERT INTO compliance_snapshots '
        '(scan_id, framework, coverage, details, captured_at) '
        'VALUES (?, ?, ?, ?, ?)',
        (scan_id, framework, coverage, details, now))
    frameworks += 1

db.commit()
db.close()
if frameworks:
    print(f'[scan-db] Compliance: {frameworks} framework snapshots generated')
" "$db" "$mappings_dir"
}

cmd_query() {
  local severity="" tool="" cwe="" limit="50"
  while [ $# -gt 0 ]; do
    case "$1" in
      --severity) severity="$2"; shift 2 ;;
      --tool) tool="$2"; shift 2 ;;
      --cwe) cwe="$2"; shift 2 ;;
      --limit) limit="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

where = ['fixed_at IS NULL']
params = []
if '$severity':
    where.append('severity = ?')
    params.append('$severity'.upper())
if '$tool':
    where.append('source_tool = ?')
    params.append('$tool')
if '$cwe':
    where.append('cwe = ?')
    params.append('$cwe')

sql = f'SELECT rule_id, severity, file, line_start, source_tool, cwe, first_seen, last_seen, triage FROM findings WHERE {\" AND \".join(where)} ORDER BY severity, rule_id LIMIT $limit'
rows = c.execute(sql, params).fetchall()

results = []
for r in rows:
    results.append({
        'rule_id': r[0], 'severity': r[1], 'file': r[2], 'line_start': r[3],
        'source_tool': r[4], 'cwe': r[5], 'first_seen': r[6], 'last_seen': r[7], 'triage': r[8]
    })

db.close()
print(json.dumps({'count': len(results), 'findings': results}, indent=2))
"
}

cmd_trend() {
  local days="${1:-30}"
  python3 -c "
import sqlite3, json
from datetime import datetime, timedelta

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

end = datetime.utcnow()
start = end - timedelta(days=$days)

rows = c.execute('''
    SELECT date(first_seen) as day, severity, COUNT(*) as cnt
    FROM findings
    WHERE first_seen >= ?
    GROUP BY day, severity
    ORDER BY day
''', (start.isoformat(),)).fetchall()

trend = {}
for day, sev, cnt in rows:
    if day not in trend:
        trend[day] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    trend[day][sev.lower()] = cnt

db.close()
print(json.dumps({'days': $days, 'trend': trend}, indent=2))
"
}

cmd_lifecycle() {
  local fingerprint="$1"
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

rows = c.execute('''
    SELECT scan_id, first_seen, last_seen, fixed_at, triage, severity, rule_id
    FROM findings WHERE fingerprint = ?
    ORDER BY first_seen
''', ('$fingerprint',)).fetchall()

history = []
for r in rows:
    history.append({
        'scan_id': r[0], 'first_seen': r[1], 'last_seen': r[2],
        'fixed_at': r[3], 'triage': r[4], 'severity': r[5], 'rule_id': r[6]
    })

db.close()
print(json.dumps({'fingerprint': '$fingerprint', 'history': history}, indent=2))
"
}

cmd_export() {
  local format="${1:-json}"
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

scans = [dict(zip(['scan_id','target','tools','pipeline','started_at','finished_at','status'], r))
         for r in c.execute('SELECT scan_id,target,tools,pipeline,started_at,finished_at,status FROM scans').fetchall()]
findings = [dict(zip(['fingerprint','rule_id','severity','file','line_start','source_tool','cwe','first_seen','last_seen','fixed_at','triage'], r))
            for r in c.execute('SELECT fingerprint,rule_id,severity,file,line_start,source_tool,cwe,first_seen,last_seen,fixed_at,triage FROM findings').fetchall()]

db.close()
print(json.dumps({'scans': scans, 'findings': findings}, indent=2))
"
}

cmd_stats() {
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

scan_count = c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
finding_count = c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
open_count = c.execute('SELECT COUNT(*) FROM findings WHERE fixed_at IS NULL').fetchone()[0]
fixed_count = c.execute('SELECT COUNT(*) FROM findings WHERE fixed_at IS NOT NULL').fetchone()[0]

by_severity = {}
for sev, cnt in c.execute('SELECT severity, COUNT(*) FROM findings WHERE fixed_at IS NULL GROUP BY severity').fetchall():
    by_severity[sev.lower()] = cnt

by_tool = {}
for tool, cnt in c.execute('SELECT source_tool, COUNT(*) FROM findings WHERE fixed_at IS NULL GROUP BY source_tool').fetchall():
    by_tool[tool] = cnt

db.close()
print(json.dumps({
    'scans': scan_count, 'total_findings': finding_count,
    'open': open_count, 'fixed': fixed_count,
    'by_severity': by_severity, 'by_tool': by_tool
}, indent=2))
"
}

# ─── Main ───
[ $# -lt 1 ] && usage

CMD="$1"; shift
case "$CMD" in
  init)      cmd_init ;;
  store)     cmd_store "$@" ;;
  query)     cmd_query "$@" ;;
  trend)     cmd_trend "$@" ;;
  lifecycle) cmd_lifecycle "$@" ;;
  export)    cmd_export "$@" ;;
  stats)     cmd_stats ;;
  *)         usage ;;
esac
