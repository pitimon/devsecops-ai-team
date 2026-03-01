#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Normalizer Unit Tests
# Tests severity mapping, multi-array handling, null safety, and data integrity

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NORMALIZER="$ROOT_DIR/formatters/json-normalizer.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Normalizer Unit Tests"
echo "============================================"
echo ""

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ─── Test 1: Semgrep severity mapping (BUG-1) ───
echo "--- Semgrep Severity Mapping ---"

bash "$NORMALIZER" --tool semgrep --input "$ROOT_DIR/tests/fixtures/sample-semgrep.json" --output "$TMPDIR/semgrep.json" 2>/dev/null

SEV_CHECK=$(python3 -c "
import json
d = json.load(open('$TMPDIR/semgrep.json'))
findings = d['findings']
# ERROR should map to HIGH, WARNING should map to MEDIUM
sevs = [f['severity'] for f in findings]
# Verify no ERROR or WARNING in output
invalid = [s for s in sevs if s in ('ERROR', 'WARNING')]
print('PASS' if not invalid else 'FAIL:' + ','.join(invalid))
" 2>/dev/null)
[ "$SEV_CHECK" = "PASS" ] && pass "Semgrep: no raw ERROR/WARNING severities in output" || fail "Semgrep: raw tool severities leaked: $SEV_CHECK"

SEV_HIGH=$(python3 -c "
import json
d = json.load(open('$TMPDIR/semgrep.json'))
has_high = any(f['severity'] == 'HIGH' for f in d['findings'])
print('yes' if has_high else 'no')
" 2>/dev/null)
[ "$SEV_HIGH" = "yes" ] && pass "Semgrep: ERROR mapped to HIGH" || fail "Semgrep: ERROR not mapped to HIGH"

SEV_MED=$(python3 -c "
import json
d = json.load(open('$TMPDIR/semgrep.json'))
has_med = any(f['severity'] == 'MEDIUM' for f in d['findings'])
print('yes' if has_med else 'no')
" 2>/dev/null)
[ "$SEV_MED" = "yes" ] && pass "Semgrep: WARNING mapped to MEDIUM" || fail "Semgrep: WARNING not mapped to MEDIUM"

# ─── Test 2: Checkov multi-array (BUG-2) ───
echo ""
echo "--- Checkov Multi-Array Handling ---"

bash "$NORMALIZER" --tool checkov --input "$ROOT_DIR/tests/fixtures/sample-checkov-multi.json" --output "$TMPDIR/checkov-multi.json" 2>/dev/null

CHECKOV_COUNT=$(python3 -c "
import json
d = json.load(open('$TMPDIR/checkov-multi.json'))
print(len(d['findings']))
" 2>/dev/null)
[ "$CHECKOV_COUNT" = "5" ] && pass "Checkov multi-array: all 5 findings from 3 check types merged" || fail "Checkov multi-array: expected 5 findings, got $CHECKOV_COUNT"

CHECKOV_TYPES=$(python3 -c "
import json
d = json.load(open('$TMPDIR/checkov-multi.json'))
files = set(f['location']['file'] for f in d['findings'])
has_tf = any('/main.tf' in f for f in files)
has_k8s = any('deployment.yaml' in f for f in files)
has_docker = any('Dockerfile' in f for f in files)
print('PASS' if (has_tf and has_k8s and has_docker) else f'FAIL:tf={has_tf},k8s={has_k8s},docker={has_docker}')
" 2>/dev/null)
[ "$CHECKOV_TYPES" = "PASS" ] && pass "Checkov multi-array: terraform + kubernetes + dockerfile all present" || fail "Checkov multi-array: missing check types: $CHECKOV_TYPES"

# ─── Test 3: Checkov null severity (BUG-3) ───
echo ""
echo "--- Checkov Null Severity ---"

NULL_SEV=$(python3 -c "
import json
d = json.load(open('$TMPDIR/checkov-multi.json'))
null_sevs = [f['severity'] for f in d['findings'] if f['severity'] is None]
print(len(null_sevs))
" 2>/dev/null)
[ "$NULL_SEV" = "0" ] && pass "Checkov: no null severity values" || fail "Checkov: found $NULL_SEV null severity values"

DEFAULT_SEV=$(python3 -c "
import json
d = json.load(open('$TMPDIR/checkov-multi.json'))
# The second check (CKV_AWS_19) has severity: null in fixture
s19 = [f for f in d['findings'] if f['rule_id'] == 'CKV_AWS_19']
print(s19[0]['severity'] if s19 else 'NOT_FOUND')
" 2>/dev/null)
[ "$DEFAULT_SEV" = "MEDIUM" ] && pass "Checkov: null severity defaults to MEDIUM" || fail "Checkov: null severity got '$DEFAULT_SEV' instead of MEDIUM"

# ─── Test 4: Trivy Misconfigurations (BUG-4) ───
echo ""
echo "--- Trivy Misconfigurations ---"

bash "$NORMALIZER" --tool trivy --input "$ROOT_DIR/tests/fixtures/sample-trivy-misconfig.json" --output "$TMPDIR/trivy-misconfig.json" 2>/dev/null

TRIVY_TOTAL=$(python3 -c "
import json
d = json.load(open('$TMPDIR/trivy-misconfig.json'))
print(len(d['findings']))
" 2>/dev/null)
[ "$TRIVY_TOTAL" = "4" ] && pass "Trivy: 1 vuln + 3 misconfigs = 4 total findings" || fail "Trivy: expected 4 findings, got $TRIVY_TOTAL"

TRIVY_TYPES=$(python3 -c "
import json
d = json.load(open('$TMPDIR/trivy-misconfig.json'))
scan_types = set(f['scan_type'] for f in d['findings'])
has_container = 'container' in scan_types
has_config = 'config' in scan_types
print('PASS' if (has_container and has_config) else f'FAIL:container={has_container},config={has_config}')
" 2>/dev/null)
[ "$TRIVY_TYPES" = "PASS" ] && pass "Trivy: both 'container' and 'config' scan types present" || fail "Trivy: missing scan types: $TRIVY_TYPES"

TRIVY_MISCONF_RULE=$(python3 -c "
import json
d = json.load(open('$TMPDIR/trivy-misconfig.json'))
misconf_ids = [f['rule_id'] for f in d['findings'] if f['scan_type'] == 'config']
print('PASS' if 'DS002' in misconf_ids and 'DS026' in misconf_ids else f'FAIL:{misconf_ids}')
" 2>/dev/null)
[ "$TRIVY_MISCONF_RULE" = "PASS" ] && pass "Trivy: misconfiguration rule IDs preserved (DS002, DS026)" || fail "Trivy: misconfiguration rule IDs missing: $TRIVY_MISCONF_RULE"

# ─── Test 5: All tools — severity values valid ───
echo ""
echo "--- Severity Validation (All Tools) ---"

VALID_SEVERITIES="CRITICAL HIGH MEDIUM LOW INFO"

for TOOL in semgrep gitleaks grype trivy checkov zap; do
  FIXTURE="$ROOT_DIR/tests/fixtures/sample-${TOOL}.json"
  OUTPUT="$TMPDIR/sev-${TOOL}.json"

  bash "$NORMALIZER" --tool "$TOOL" --input "$FIXTURE" --output "$OUTPUT" 2>/dev/null

  SEV_VALID=$(python3 -c "
import json
d = json.load(open('$OUTPUT'))
valid = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
invalid = [f['severity'] for f in d['findings'] if f['severity'] not in valid]
print('PASS' if not invalid else 'FAIL:' + ','.join(str(s) for s in invalid))
" 2>/dev/null)
  [ "$SEV_VALID" = "PASS" ] && pass "$TOOL: all severities in {CRITICAL,HIGH,MEDIUM,LOW,INFO}" || fail "$TOOL: invalid severities: $SEV_VALID"
done

# ─── Test 6: All tools — summary.total == len(findings) ───
echo ""
echo "--- Summary Count Validation (All Tools) ---"

for TOOL in semgrep gitleaks grype trivy checkov zap; do
  OUTPUT="$TMPDIR/sev-${TOOL}.json"

  COUNT_MATCH=$(python3 -c "
import json
d = json.load(open('$OUTPUT'))
total = d['summary']['total']
actual = len(d['findings'])
print('PASS' if total == actual else f'FAIL:summary={total},actual={actual}')
" 2>/dev/null)
  [ "$COUNT_MATCH" = "PASS" ] && pass "$TOOL: summary.total matches findings count" || fail "$TOOL: count mismatch: $COUNT_MATCH"
done

# ─── Test 7: All tools — no null severity ───
echo ""
echo "--- Null Severity Check (All Tools) ---"

for TOOL in semgrep gitleaks grype trivy checkov zap; do
  OUTPUT="$TMPDIR/sev-${TOOL}.json"

  NULL_CHECK=$(python3 -c "
import json
d = json.load(open('$OUTPUT'))
nulls = [i for i, f in enumerate(d['findings']) if f.get('severity') is None]
print('PASS' if not nulls else f'FAIL:indices={nulls}')
" 2>/dev/null)
  [ "$NULL_CHECK" = "PASS" ] && pass "$TOOL: no null severity values" || fail "$TOOL: null severity found: $NULL_CHECK"
done

# ─── Test 8: Empty input — no crash ───
echo ""
echo "--- Empty Input Handling ---"

for TOOL in semgrep gitleaks grype trivy checkov zap; do
  EMPTY_FILE="$TMPDIR/empty-${TOOL}.json"
  EMPTY_OUT="$TMPDIR/empty-out-${TOOL}.json"

  case "$TOOL" in
    semgrep) echo '{"results": []}' > "$EMPTY_FILE" ;;
    gitleaks) echo '[]' > "$EMPTY_FILE" ;;
    grype) echo '{"matches": []}' > "$EMPTY_FILE" ;;
    trivy) echo '{"Results": []}' > "$EMPTY_FILE" ;;
    checkov) echo '[{"results": {"failed_checks": []}}]' > "$EMPTY_FILE" ;;
    zap) echo '{"site": []}' > "$EMPTY_FILE" ;;
  esac

  if bash "$NORMALIZER" --tool "$TOOL" --input "$EMPTY_FILE" --output "$EMPTY_OUT" 2>/dev/null; then
    EMPTY_COUNT=$(python3 -c "
import json
d = json.load(open('$EMPTY_OUT'))
print(d['summary']['total'])
" 2>/dev/null)
    [ "$EMPTY_COUNT" = "0" ] && pass "$TOOL: empty input produces 0 findings" || fail "$TOOL: empty input produced $EMPTY_COUNT findings"
  else
    fail "$TOOL: crashed on empty input"
  fi
done

# ─── Summary ───
echo ""
echo "============================================"
echo "Results: $PASS passed / $FAIL failed"
echo "============================================"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
