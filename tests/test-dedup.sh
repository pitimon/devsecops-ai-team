#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Dedup Findings Logic Tests
# Tests dedup-findings.sh: dedup keys, severity promotion, source concatenation, re-indexing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEDUP="$ROOT_DIR/formatters/dedup-findings.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Dedup Logic Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ─── Test 1: File+line dedup key ───
echo "--- Dedup by File+Line Key ---"

cat > "$TMPDIR/file1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "HIGH", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "src/auth.ts", "line_start": 45}, "rule_id": "sql-injection", "title": "SQL Injection"}
]}
EOF
cat > "$TMPDIR/file2.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "MEDIUM", "cwe_id": "CWE-89", "source_tool": "grype",
   "location": {"file": "src/auth.ts", "line_start": 45}, "rule_id": "sql-injection", "title": "SQL Injection"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/file1.json,$TMPDIR/file2.json" --output "$TMPDIR/out1.json" 2>/dev/null

COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out1.json'))['findings']))")
[ "$COUNT" = "1" ] && pass "File+line: 2 identical findings → 1 merged" || fail "File+line: expected 1 finding, got $COUNT"

# ─── Test 2: Severity promotion ───
echo ""
echo "--- Severity Promotion ---"

SEV=$(python3 -c "import json; print(json.load(open('$TMPDIR/out1.json'))['findings'][0]['severity'])")
[ "$SEV" = "HIGH" ] && pass "Severity promotion: MEDIUM + HIGH → HIGH kept" || fail "Severity promotion: expected HIGH, got $SEV"

# ─── Test 3: Source tool concatenation ───
echo ""
echo "--- Source Tool Concatenation ---"

TOOLS=$(python3 -c "import json; print(json.load(open('$TMPDIR/out1.json'))['findings'][0]['source_tool'])")
echo "$TOOLS" | grep -q "semgrep" && echo "$TOOLS" | grep -q "grype" && pass "Source concatenation: semgrep,grype both present" || fail "Source concatenation: expected semgrep+grype, got $TOOLS"

# ─── Test 4: Package dedup key ───
echo ""
echo "--- Dedup by Package Key ---"

cat > "$TMPDIR/pkg1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "HIGH", "cwe_id": "CWE-400", "source_tool": "grype",
   "location": {"package": "lodash", "version": "4.17.15"}, "rule_id": "CVE-2021-23337", "title": "Prototype Pollution"}
]}
EOF
cat > "$TMPDIR/pkg2.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "CRITICAL", "cwe_id": "CWE-400", "source_tool": "trivy",
   "location": {"package": "lodash", "version": "4.17.15"}, "rule_id": "CVE-2021-23337", "title": "Prototype Pollution"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/pkg1.json,$TMPDIR/pkg2.json" --output "$TMPDIR/out-pkg.json" 2>/dev/null

PKG_COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out-pkg.json'))['findings']))")
[ "$PKG_COUNT" = "1" ] && pass "Package key: 2 identical package findings → 1 merged" || fail "Package key: expected 1, got $PKG_COUNT"

PKG_SEV=$(python3 -c "import json; print(json.load(open('$TMPDIR/out-pkg.json'))['findings'][0]['severity'])")
[ "$PKG_SEV" = "CRITICAL" ] && pass "Package key: HIGH → CRITICAL promoted" || fail "Package key: expected CRITICAL, got $PKG_SEV"

# ─── Test 5: URL dedup key ───
echo ""
echo "--- Dedup by URL Key ---"

cat > "$TMPDIR/url1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "MEDIUM", "cwe_id": "CWE-79", "source_tool": "zap",
   "location": {"url": "https://example.com/api/v1"}, "rule_id": "10012", "title": "XSS"}
]}
EOF
cat > "$TMPDIR/url2.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "MEDIUM", "cwe_id": "CWE-79", "source_tool": "zap-custom",
   "location": {"url": "https://example.com/api/v1"}, "rule_id": "10012", "title": "XSS"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/url1.json,$TMPDIR/url2.json" --output "$TMPDIR/out-url.json" 2>/dev/null

URL_COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out-url.json'))['findings']))")
[ "$URL_COUNT" = "1" ] && pass "URL key: 2 identical URL findings → 1 merged" || fail "URL key: expected 1, got $URL_COUNT"

# ─── Test 6: Finding re-indexing ───
echo ""
echo "--- Finding Re-Indexing ---"

cat > "$TMPDIR/reindex1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "HIGH", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "a.ts", "line_start": 1}, "rule_id": "r1", "title": "T1"},
  {"id": "F-002", "severity": "MEDIUM", "cwe_id": "CWE-79", "source_tool": "semgrep",
   "location": {"file": "b.ts", "line_start": 2}, "rule_id": "r2", "title": "T2"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/reindex1.json" --output "$TMPDIR/out-reindex.json" 2>/dev/null

REINDEX_IDS=$(python3 -c "
import json
d = json.load(open('$TMPDIR/out-reindex.json'))
ids = [f['id'] for f in d['findings']]
print('PASS' if ids == ['FINDING-MERGED-001', 'FINDING-MERGED-002'] else f'FAIL:{ids}')
")
[ "$REINDEX_IDS" = "PASS" ] && pass "Re-index: IDs renumbered to FINDING-MERGED-NNN" || fail "Re-index: wrong IDs: $REINDEX_IDS"

# ─── Test 7: Empty input ───
echo ""
echo "--- Empty Input ---"

cat > "$TMPDIR/empty.json" << 'EOF'
{"findings": []}
EOF

bash "$DEDUP" --inputs "$TMPDIR/empty.json" --output "$TMPDIR/out-empty.json" 2>/dev/null

EMPTY_COUNT=$(python3 -c "import json; print(json.load(open('$TMPDIR/out-empty.json'))['summary']['total'])")
[ "$EMPTY_COUNT" = "0" ] && pass "Empty input: 0 findings produces 0 merged" || fail "Empty input: expected 0, got $EMPTY_COUNT"

# ─── Test 8: Single finding passthrough ───
echo ""
echo "--- Single Finding Passthrough ---"

cat > "$TMPDIR/single.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "CRITICAL", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "a.ts", "line_start": 1}, "rule_id": "r1", "title": "T1"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/single.json" --output "$TMPDIR/out-single.json" 2>/dev/null

SINGLE_COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out-single.json'))['findings']))")
[ "$SINGLE_COUNT" = "1" ] && pass "Single finding: passes through as 1 merged finding" || fail "Single finding: expected 1, got $SINGLE_COUNT"

# ─── Test 9: Summary counts correct ───
echo ""
echo "--- Summary Counts ---"

cat > "$TMPDIR/mix1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "CRITICAL", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "a.ts", "line_start": 1}, "rule_id": "r1", "title": "T1"},
  {"id": "F-002", "severity": "HIGH", "cwe_id": "CWE-79", "source_tool": "semgrep",
   "location": {"file": "b.ts", "line_start": 2}, "rule_id": "r2", "title": "T2"}
]}
EOF
cat > "$TMPDIR/mix2.json" << 'EOF'
{"findings": [
  {"id": "F-003", "severity": "MEDIUM", "cwe_id": "CWE-327", "source_tool": "grype",
   "location": {"package": "openssl", "version": "1.0.2"}, "rule_id": "r3", "title": "T3"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/mix1.json,$TMPDIR/mix2.json" --output "$TMPDIR/out-mix.json" 2>/dev/null

SUMMARY_CHECK=$(python3 -c "
import json
d = json.load(open('$TMPDIR/out-mix.json'))
s = d['summary']
ok = s['total'] == 3 and s['critical'] == 1 and s['high'] == 1 and s['medium'] == 1
print('PASS' if ok else f'FAIL:{s}')
")
[ "$SUMMARY_CHECK" = "PASS" ] && pass "Summary: total=3, critical=1, high=1, medium=1" || fail "Summary: $SUMMARY_CHECK"

# ─── Test 10: deduplicated_from count ───
DEDUP_FROM=$(python3 -c "import json; print(json.load(open('$TMPDIR/out1.json'))['summary']['deduplicated_from'])")
[ "$DEDUP_FROM" = "2" ] && pass "Dedup from: shows original count before merge" || fail "Dedup from: expected 2, got $DEDUP_FROM"

# ─── Test 11: Cross-tool duplicates ───
echo ""
echo "--- Cross-Tool Duplicates ---"

cat > "$TMPDIR/cross1.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "HIGH", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "app.py", "line_start": 10}, "rule_id": "sql-inject", "title": "SQL Injection"},
  {"id": "F-002", "severity": "LOW", "cwe_id": "CWE-200", "source_tool": "semgrep",
   "location": {"file": "app.py", "line_start": 20}, "rule_id": "info-leak", "title": "Info Leak"}
]}
EOF
cat > "$TMPDIR/cross2.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "CRITICAL", "cwe_id": "CWE-89", "source_tool": "checkov",
   "location": {"file": "app.py", "line_start": 10}, "rule_id": "sql-inject", "title": "SQL Injection"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/cross1.json,$TMPDIR/cross2.json" --output "$TMPDIR/out-cross.json" 2>/dev/null

CROSS_COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out-cross.json'))['findings']))")
[ "$CROSS_COUNT" = "2" ] && pass "Cross-tool: 3 findings (1 dup) → 2 merged" || fail "Cross-tool: expected 2, got $CROSS_COUNT"

CROSS_SEV=$(python3 -c "
import json
d = json.load(open('$TMPDIR/out-cross.json'))
sql_finding = [f for f in d['findings'] if 'SQL' in f.get('title','')][0]
print(sql_finding['severity'])
")
[ "$CROSS_SEV" = "CRITICAL" ] && pass "Cross-tool: SQL finding promoted HIGH → CRITICAL" || fail "Cross-tool: expected CRITICAL, got $CROSS_SEV"

# ─── Test 12: Malformed file skipped gracefully ───
echo ""
echo "--- Malformed File Handling ---"

echo 'not-json' > "$TMPDIR/bad.json"
cat > "$TMPDIR/good.json" << 'EOF'
{"findings": [
  {"id": "F-001", "severity": "HIGH", "cwe_id": "CWE-89", "source_tool": "semgrep",
   "location": {"file": "a.ts", "line_start": 1}, "rule_id": "r1", "title": "T1"}
]}
EOF

bash "$DEDUP" --inputs "$TMPDIR/bad.json,$TMPDIR/good.json" --output "$TMPDIR/out-bad.json" 2>/dev/null

BAD_COUNT=$(python3 -c "import json; print(len(json.load(open('$TMPDIR/out-bad.json'))['findings']))")
[ "$BAD_COUNT" = "1" ] && pass "Malformed: bad file skipped, good file processed" || fail "Malformed: expected 1 finding, got $BAD_COUNT"

# ─── Test 13: Sources list in summary ───
echo ""
echo "--- Sources List ---"

SOURCES=$(python3 -c "
import json
d = json.load(open('$TMPDIR/out-mix.json'))
src = sorted(d['summary']['sources'])
print(','.join(src))
")
[ "$SOURCES" = "grype,semgrep" ] && pass "Sources: lists unique source tools in summary" || fail "Sources: expected grype,semgrep, got $SOURCES"

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
