#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Scan Database Tests
# Tests scripts/scan-db.sh: init, store, query, trend, lifecycle, export, stats

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Scan Database Tests"
echo "============================================"
echo ""

SCAN_DB_SCRIPT="$ROOT_DIR/scripts/scan-db.sh"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a06-findings.json"

# Fresh temp database for each test run
TEST_DIR=$(mktemp -d)
TEST_DB="$TEST_DIR/test.db"
trap "rm -rf $TEST_DIR" EXIT

# ═══════════════════════════════════════════
# Section 1: Script Structure (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 1: Script Structure ---"

[ -f "$SCAN_DB_SCRIPT" ] && pass "scan-db.sh exists" || fail "scan-db.sh missing"

[ -x "$SCAN_DB_SCRIPT" ] && pass "scan-db.sh is executable" || fail "scan-db.sh not executable"

USAGE_OUT=$("$SCAN_DB_SCRIPT" 2>&1 || true)
echo "$USAGE_OUT" | grep -q "Usage:" && pass "Shows usage text when called with no args" || fail "Missing usage text"

echo ""

# ═══════════════════════════════════════════
# Section 2: Init Command (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 2: Init Command ---"

SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" init >/dev/null 2>&1
[ -f "$TEST_DB" ] && pass "init creates DB file" || fail "init did not create DB file"

python3 -c "
import sqlite3, sys
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='scans'\")
sys.exit(0 if c.fetchone() else 1)
" && pass "scans table exists" || fail "scans table missing"

python3 -c "
import sqlite3, sys
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
c.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='findings'\")
sys.exit(0 if c.fetchone() else 1)
" && pass "findings table exists" || fail "findings table missing"

python3 -c "
import sqlite3, sys
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
c.execute(\"SELECT name FROM sqlite_master WHERE type='index'\")
indexes = [r[0] for r in c.fetchall()]
expected = ['idx_findings_scan', 'idx_findings_fp', 'idx_findings_severity', 'idx_findings_tool']
missing = [i for i in expected if i not in indexes]
if missing:
    print(f'Missing indexes: {missing}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "All 4 indexes exist" || fail "Some indexes missing"

echo ""

# ═══════════════════════════════════════════
# Section 3: Store Command (5 tests)
# ═══════════════════════════════════════════
echo "--- Section 3: Store Command ---"

SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" store "$FIXTURE" >/dev/null 2>&1
FINDING_COUNT=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
print(c.execute('SELECT COUNT(*) FROM findings').fetchone()[0])
db.close()
")
[ "$FINDING_COUNT" -gt 0 ] && pass "Store imports findings from fixture" || fail "Store did not import findings"

[ "$FINDING_COUNT" -eq 3 ] && pass "Finding count matches fixture (3)" || fail "Expected 3 findings, got $FINDING_COUNT"

# Re-import same fixture — dedup should keep count at 3
SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" store "$FIXTURE" >/dev/null 2>&1
FINDING_COUNT_AFTER=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
# Count only open (non-fixed) findings — dedup updates existing, doesn't create duplicates
print(c.execute('SELECT COUNT(*) FROM findings WHERE fixed_at IS NULL').fetchone()[0])
db.close()
")
[ "$FINDING_COUNT_AFTER" -eq 3 ] && pass "Dedup on re-import (open count unchanged at 3)" || fail "Dedup failed: expected 3 open findings, got $FINDING_COUNT_AFTER"

TOOLS_RECORDED=$(python3 -c "
import sqlite3, json
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
row = c.execute('SELECT tools FROM scans LIMIT 1').fetchone()
tools = json.loads(row[0])
print(','.join(sorted(tools)))
db.close()
")
echo "$TOOLS_RECORDED" | grep -q "semgrep" && pass "Tools recorded (contains semgrep)" || fail "Tools not recorded correctly"

SCAN_COUNT=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
c = db.cursor()
print(c.execute('SELECT COUNT(*) FROM scans').fetchone()[0])
db.close()
")
[ "$SCAN_COUNT" -ge 1 ] && pass "Scan record exists" || fail "No scan record found"

echo ""

# ═══════════════════════════════════════════
# Section 4: Query Command (4 tests)
# ═══════════════════════════════════════════
echo "--- Section 4: Query Command ---"

ALL_QUERY=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" query 2>/dev/null)
ALL_COUNT=$(echo "$ALL_QUERY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['count'])")
[ "$ALL_COUNT" -eq 3 ] && pass "Query all returns 3 findings" || fail "Query all expected 3, got $ALL_COUNT"

SEV_QUERY=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" query --severity ERROR 2>/dev/null)
SEV_COUNT=$(echo "$SEV_QUERY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['count'])")
[ "$SEV_COUNT" -eq 1 ] && pass "Query --severity ERROR returns 1" || fail "Query severity filter expected 1, got $SEV_COUNT"

TOOL_QUERY=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" query --tool semgrep 2>/dev/null)
TOOL_COUNT=$(echo "$TOOL_QUERY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['count'])")
[ "$TOOL_COUNT" -eq 3 ] && pass "Query --tool semgrep returns 3" || fail "Query tool filter expected 3, got $TOOL_COUNT"

echo "$ALL_QUERY" | python3 -c "import json,sys; json.load(sys.stdin)" && pass "Query output is valid JSON" || fail "Query output is not valid JSON"

echo ""

# ═══════════════════════════════════════════
# Section 5: Trend Command (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 5: Trend Command ---"

TREND_OUT=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" trend 2>/dev/null)
echo "$TREND_OUT" | python3 -c "import json,sys; json.load(sys.stdin)" && pass "Trend returns valid JSON" || fail "Trend output is not valid JSON"

echo "$TREND_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
sys.exit(0 if 'trend' in d else 1)
" && pass "Trend output has 'trend' key" || fail "Trend output missing 'trend' key"

echo "$TREND_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
trend = d.get('trend', {})
sys.exit(0 if len(trend) > 0 else 1)
" && pass "Trend has day entries" || fail "Trend has no day entries"

echo ""

# ═══════════════════════════════════════════
# Section 6: Lifecycle Command (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 6: Lifecycle Command ---"

# Use a known fingerprint from the fixture
# Fingerprint format: rule_id:file:line_start
FP="a06-unpinned-pip:requirements.txt:3"

LIFECYCLE_OUT=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" lifecycle "$FP" 2>/dev/null)
HISTORY_LEN=$(echo "$LIFECYCLE_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('history',[])))")
[ "$HISTORY_LEN" -ge 1 ] && pass "Lifecycle fingerprint lookup returns history" || fail "Lifecycle returned no history for known fingerprint"

echo "$LIFECYCLE_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
h = d['history'][0]
required = ['scan_id', 'first_seen', 'last_seen', 'triage', 'severity', 'rule_id']
missing = [k for k in required if k not in h]
if missing:
    print(f'Missing fields: {missing}', file=sys.stderr)
    sys.exit(1)
sys.exit(0)
" && pass "Lifecycle history has correct fields" || fail "Lifecycle history missing required fields"

echo ""

# ═══════════════════════════════════════════
# Section 7: Export Command (3 tests)
# ═══════════════════════════════════════════
echo "--- Section 7: Export Command ---"

EXPORT_OUT=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" export 2>/dev/null)
echo "$EXPORT_OUT" | python3 -c "import json,sys; json.load(sys.stdin)" && pass "Export output is valid JSON" || fail "Export output is not valid JSON"

echo "$EXPORT_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
sys.exit(0 if 'scans' in d and isinstance(d['scans'], list) else 1)
" && pass "Export has scans array" || fail "Export missing scans array"

echo "$EXPORT_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
sys.exit(0 if 'findings' in d and isinstance(d['findings'], list) else 1)
" && pass "Export has findings array" || fail "Export missing findings array"

echo ""

# ═══════════════════════════════════════════
# Section 8: Stats Command (2 tests)
# ═══════════════════════════════════════════
echo "--- Section 8: Stats Command ---"

STATS_OUT=$(SCAN_DB="$TEST_DB" "$SCAN_DB_SCRIPT" stats 2>/dev/null)
STATS_OPEN=$(echo "$STATS_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('open',0))")
[ "$STATS_OPEN" -eq 3 ] && pass "Stats counts match (3 open)" || fail "Stats open count expected 3, got $STATS_OPEN"

echo "$STATS_OUT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
sys.exit(0 if 'by_severity' in d and isinstance(d['by_severity'], dict) else 1)
" && pass "Stats has by_severity" || fail "Stats missing by_severity"

echo ""

# ═══════════════════════════════════════════
# Section 9: OWASP Enrichment (3 tests) — #70
# ═══════════════════════════════════════════
echo "--- Section 9: OWASP Enrichment ---"

OWASP_COUNT=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT owasp FROM findings WHERE owasp IS NOT NULL').fetchall()
db.close()
print(len(rows))
" 2>/dev/null)
[ "$OWASP_COUNT" -gt 0 ] \
  && pass "Findings enriched with OWASP tags ($OWASP_COUNT)" \
  || fail "No findings have OWASP tags"

OWASP_VALID=$(python3 -c "
import sqlite3, json
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT owasp FROM findings WHERE owasp IS NOT NULL').fetchall()
db.close()
valid = all(isinstance(json.loads(r[0]), list) for r in rows)
print('yes' if valid else 'no')
" 2>/dev/null)
[ "$OWASP_VALID" = "yes" ] \
  && pass "OWASP tags are valid JSON arrays" \
  || fail "OWASP tags are not valid JSON arrays"

OWASP_DUAL=$(python3 -c "
import sqlite3, json
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT owasp FROM findings WHERE owasp IS NOT NULL').fetchall()
db.close()
for r in rows:
    tags = json.loads(r[0])
    if any(':2021' in t for t in tags) and any(':2025' in t for t in tags):
        print('yes'); exit()
print('no')
" 2>/dev/null)
[ "$OWASP_DUAL" = "yes" ] \
  && pass "OWASP tags include dual-version (2021+2025)" \
  || fail "OWASP tags missing dual-version"

echo ""

# ═══════════════════════════════════════════
# Section 10: Compliance Snapshots (4 tests) — #70
# ═══════════════════════════════════════════
echo "--- Section 10: Compliance Snapshots ---"

# Get latest scan_id for compliance queries
LATEST_SID=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
r = db.execute('SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1').fetchone()
db.close()
print(r[0] if r else '')
" 2>/dev/null)

COMP_COUNT=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
count = db.execute('SELECT COUNT(*) FROM compliance_snapshots WHERE scan_id = ?', ('$LATEST_SID',)).fetchone()[0]
db.close()
print(count)
" 2>/dev/null)
[ "$COMP_COUNT" -eq 7 ] \
  && pass "7 compliance framework snapshots for latest scan" \
  || fail "Expected 7 compliance snapshots, got $COMP_COUNT"

COMP_FRAMEWORKS=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT framework FROM compliance_snapshots WHERE scan_id = ? ORDER BY framework', ('$LATEST_SID',)).fetchall()
db.close()
print(','.join(r[0] for r in rows))
" 2>/dev/null)
[ "$COMP_FRAMEWORKS" = "iso27001,mitre,ncsa,nist,owasp,pdpa,soc2" ] \
  && pass "All 7 frameworks present: $COMP_FRAMEWORKS" \
  || fail "Framework list mismatch: $COMP_FRAMEWORKS"

COMP_COVERAGE=$(python3 -c "
import sqlite3
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT coverage FROM compliance_snapshots WHERE scan_id = ? AND coverage > 0', ('$LATEST_SID',)).fetchall()
db.close()
print(len(rows))
" 2>/dev/null)
[ "$COMP_COVERAGE" -gt 0 ] \
  && pass "At least one framework has non-zero coverage" \
  || fail "All frameworks have zero coverage"

COMP_DETAILS=$(python3 -c "
import sqlite3, json
db = sqlite3.connect('$TEST_DB')
rows = db.execute('SELECT details FROM compliance_snapshots WHERE scan_id = ? AND details IS NOT NULL', ('$LATEST_SID',)).fetchall()
db.close()
valid = all('matched' in json.loads(r[0]) and 'total' in json.loads(r[0]) for r in rows)
print('yes' if valid and rows else 'no')
" 2>/dev/null)
[ "$COMP_DETAILS" = "yes" ] \
  && pass "Compliance details have matched/total fields" \
  || fail "Compliance details malformed"

echo ""

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "scan-db Tests: $PASS passed, $FAIL failed / $TOTAL total"
if [ "$FAIL" -gt 0 ]; then echo "RESULT: FAIL"; exit 1; else echo "RESULT: ALL PASSED"; exit 0; fi
