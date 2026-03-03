#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — NCSA Website Security Standard Validator
# Checks HTTP security headers, TLS, and session management against NCSA v1.0
#
# Usage: dast-ncsa-validator.sh --target <url> [--zap-results <path>] [--output <path>]
#
# NCSA Categories validated:
#   1.x — HTTP Security Headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP,
#          Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy)
#   2.x — Transport Security (TLS version >= 1.2, TLS 1.3 preference, certificate validity)
#   4.x — Session Management (Cookie Secure, HttpOnly, SameSite flags)

TARGET=""
ZAP_RESULTS=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --target) TARGET="$2"; shift 2 ;;
    --zap-results) ZAP_RESULTS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Usage: $0 --target <url> [--zap-results <path>] [--output <path>]"; exit 1 ;;
  esac
done

[ -z "$TARGET" ] && { echo "ERROR: --target is required"; exit 1; }

# JSON output builder
CHECKS="[]"
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

add_check() {
  local category="$1"
  local ncsa_ref="$2"
  local name="$3"
  local status="$4"  # pass, fail, warning
  local detail="$5"

  case "$status" in
    pass) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    fail) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    warning) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  esac

  CHECKS=$(python3 -c "
import json, sys
checks = json.loads(sys.stdin.read())
checks.append({
    'category': '$category',
    'ncsa_ref': '$ncsa_ref',
    'name': '$name',
    'status': '$status',
    'detail': '$detail'
})
print(json.dumps(checks))
" <<< "$CHECKS")
}

echo "[ncsa-validator] Target: $TARGET"
echo "[ncsa-validator] Validating NCSA Website Security Standard v1.0..."
echo ""

# ═══════════════════════════════════════════
# Category 1.x — HTTP Security Headers
# ═══════════════════════════════════════════
echo "--- NCSA 1.x: HTTP Security Headers ---"

# Fetch headers (follow redirects, max 10s timeout)
HEADERS=$(curl -sI -L --max-time 10 "$TARGET" 2>/dev/null || echo "CURL_FAILED")

if [ "$HEADERS" = "CURL_FAILED" ]; then
  echo "  [WARN] Could not reach target — skipping live header checks"
  add_check "1.x" "1.1" "HTTP Security Headers" "warning" "Target unreachable"
else
  # 1.1 Strict-Transport-Security (HSTS)
  if echo "$HEADERS" | grep -qi 'Strict-Transport-Security'; then
    echo "  [PASS] HSTS header present"
    add_check "1.x" "1.1" "Strict-Transport-Security" "pass" "HSTS header set"
  else
    echo "  [FAIL] HSTS header missing"
    add_check "1.x" "1.1" "Strict-Transport-Security" "fail" "Missing Strict-Transport-Security header"
  fi

  # 1.1 X-Frame-Options
  if echo "$HEADERS" | grep -qi 'X-Frame-Options'; then
    echo "  [PASS] X-Frame-Options header present"
    add_check "1.x" "1.1" "X-Frame-Options" "pass" "X-Frame-Options header set"
  else
    echo "  [FAIL] X-Frame-Options header missing"
    add_check "1.x" "1.1" "X-Frame-Options" "fail" "Missing X-Frame-Options header"
  fi

  # 1.1 X-Content-Type-Options
  if echo "$HEADERS" | grep -qi 'X-Content-Type-Options'; then
    echo "  [PASS] X-Content-Type-Options header present"
    add_check "1.x" "1.1" "X-Content-Type-Options" "pass" "X-Content-Type-Options header set"
  else
    echo "  [FAIL] X-Content-Type-Options header missing"
    add_check "1.x" "1.1" "X-Content-Type-Options" "fail" "Missing X-Content-Type-Options header"
  fi

  # 1.2 Content-Security-Policy
  if echo "$HEADERS" | grep -qi 'Content-Security-Policy'; then
    echo "  [PASS] CSP header present"
    add_check "1.x" "1.2" "Content-Security-Policy" "pass" "CSP header set"
  else
    echo "  [FAIL] CSP header missing"
    add_check "1.x" "1.2" "Content-Security-Policy" "fail" "Missing Content-Security-Policy header"
  fi

  # 1.2 Referrer-Policy
  if echo "$HEADERS" | grep -qi 'Referrer-Policy'; then
    echo "  [PASS] Referrer-Policy header present"
    add_check "1.x" "1.2" "Referrer-Policy" "pass" "Referrer-Policy header set"
  else
    echo "  [WARN] Referrer-Policy header missing"
    add_check "1.x" "1.2" "Referrer-Policy" "warning" "Missing Referrer-Policy header"
  fi

  # 1.3 Permissions-Policy (formerly Feature-Policy)
  if echo "$HEADERS" | grep -qi 'Permissions-Policy'; then
    echo "  [PASS] Permissions-Policy header present"
    add_check "1.x" "1.3" "Permissions-Policy" "pass" "Permissions-Policy header set"
  else
    echo "  [WARN] Permissions-Policy header missing"
    add_check "1.x" "1.3" "Permissions-Policy" "warning" "Missing Permissions-Policy header (formerly Feature-Policy)"
  fi

  # 1.3 Cross-Origin-Opener-Policy (COOP)
  if echo "$HEADERS" | grep -qi 'Cross-Origin-Opener-Policy'; then
    echo "  [PASS] Cross-Origin-Opener-Policy header present"
    add_check "1.x" "1.3" "Cross-Origin-Opener-Policy" "pass" "COOP header set"
  else
    echo "  [WARN] Cross-Origin-Opener-Policy header missing"
    add_check "1.x" "1.3" "Cross-Origin-Opener-Policy" "warning" "Missing Cross-Origin-Opener-Policy header"
  fi

  # 1.3 Cross-Origin-Embedder-Policy (COEP)
  if echo "$HEADERS" | grep -qi 'Cross-Origin-Embedder-Policy'; then
    echo "  [PASS] Cross-Origin-Embedder-Policy header present"
    add_check "1.x" "1.3" "Cross-Origin-Embedder-Policy" "pass" "COEP header set"
  else
    echo "  [WARN] Cross-Origin-Embedder-Policy header missing"
    add_check "1.x" "1.3" "Cross-Origin-Embedder-Policy" "warning" "Missing Cross-Origin-Embedder-Policy header"
  fi
fi

echo ""

# ═══════════════════════════════════════════
# Category 2.x — Transport Security
# ═══════════════════════════════════════════
echo "--- NCSA 2.x: Transport Security ---"

# Check if target uses HTTPS
if [[ "$TARGET" == https://* ]]; then
  echo "  [PASS] Target uses HTTPS"
  add_check "2.x" "2.1" "HTTPS" "pass" "Target uses HTTPS"

  # Check TLS version (extract from curl verbose output)
  TLS_INFO=$(curl -svI --max-time 10 "$TARGET" 2>&1 | grep -i 'SSL connection using TLS' || echo "")
  if [ -n "$TLS_INFO" ]; then
    if echo "$TLS_INFO" | grep -qiE 'TLSv1\.[23]|TLSv1\.3'; then
      echo "  [PASS] TLS >= 1.2 supported"
      add_check "2.x" "2.1" "TLS Version" "pass" "TLS 1.2+ in use"
    else
      echo "  [FAIL] TLS version below 1.2"
      add_check "2.x" "2.1" "TLS Version" "fail" "TLS version below 1.2"
    fi

    # 2.1 TLS 1.3 preference (recommended by NCSA, not mandatory)
    if echo "$TLS_INFO" | grep -qi 'TLSv1\.3'; then
      echo "  [PASS] TLS 1.3 supported"
      add_check "2.x" "2.1" "TLS 1.3 Preference" "pass" "TLS 1.3 in use"
    else
      echo "  [WARN] TLS 1.3 not detected (1.2 is minimum, 1.3 recommended)"
      add_check "2.x" "2.1" "TLS 1.3 Preference" "warning" "TLS 1.3 not detected — 1.2 meets minimum but 1.3 is recommended"
    fi
  else
    echo "  [WARN] Could not determine TLS version"
    add_check "2.x" "2.1" "TLS Version" "warning" "TLS version undetermined"
  fi

  # Check certificate validity
  CERT_INFO=$(curl -svI --max-time 10 "$TARGET" 2>&1 | grep -i 'SSL certificate verify ok' || echo "")
  if [ -n "$CERT_INFO" ]; then
    echo "  [PASS] SSL certificate valid"
    add_check "2.x" "2.2" "Certificate Validity" "pass" "SSL certificate verified"
  else
    echo "  [WARN] SSL certificate could not be verified"
    add_check "2.x" "2.2" "Certificate Validity" "warning" "Certificate verification inconclusive"
  fi
else
  echo "  [FAIL] Target does not use HTTPS"
  add_check "2.x" "2.1" "HTTPS" "fail" "Target is not using HTTPS"
fi

echo ""

# ═══════════════════════════════════════════
# Category 4.x — Session Management
# ═══════════════════════════════════════════
echo "--- NCSA 4.x: Session Management ---"

# Check Set-Cookie headers for security flags
COOKIES=$(echo "$HEADERS" | grep -i 'Set-Cookie' || echo "")

if [ -n "$COOKIES" ]; then
  # Check Secure flag
  if echo "$COOKIES" | grep -qi 'Secure'; then
    echo "  [PASS] Cookie Secure flag present"
    add_check "4.x" "4.1" "Cookie Secure Flag" "pass" "Secure flag set on cookies"
  else
    echo "  [FAIL] Cookie Secure flag missing"
    add_check "4.x" "4.1" "Cookie Secure Flag" "fail" "Missing Secure flag on cookies"
  fi

  # Check HttpOnly flag
  if echo "$COOKIES" | grep -qi 'HttpOnly'; then
    echo "  [PASS] Cookie HttpOnly flag present"
    add_check "4.x" "4.1" "Cookie HttpOnly Flag" "pass" "HttpOnly flag set on cookies"
  else
    echo "  [FAIL] Cookie HttpOnly flag missing"
    add_check "4.x" "4.1" "Cookie HttpOnly Flag" "fail" "Missing HttpOnly flag on cookies"
  fi

  # Check SameSite flag
  if echo "$COOKIES" | grep -qi 'SameSite'; then
    echo "  [PASS] Cookie SameSite flag present"
    add_check "4.x" "4.2" "Cookie SameSite Flag" "pass" "SameSite flag set on cookies"
  else
    echo "  [WARN] Cookie SameSite flag missing"
    add_check "4.x" "4.2" "Cookie SameSite Flag" "warning" "Missing SameSite flag on cookies"
  fi
else
  echo "  [INFO] No Set-Cookie headers found (no session cookies to validate)"
  add_check "4.x" "4.1" "Session Cookies" "pass" "No session cookies set (stateless)"
fi

echo ""

# ═══════════════════════════════════════════
# ZAP Results Cross-Reference (if provided)
# ═══════════════════════════════════════════
if [ -n "$ZAP_RESULTS" ] && [ -f "$ZAP_RESULTS" ]; then
  echo "--- ZAP Results Cross-Reference ---"
  python3 -c "
import json, sys
with open('$ZAP_RESULTS') as f:
    data = json.load(f)
ncsa_cwes = {
    '693': '1.2',   # CSP
    '319': '2.1',   # TLS
    '352': '4.2',   # CSRF
    '565': '4.1',   # Cookie
    '16': '1.1',    # Config/Headers
    '614': '4.1',   # Cookie Secure
}
for site in data.get('site', []):
    for alert in site.get('alerts', []):
        cwe = alert.get('cweid', '')
        if cwe in ncsa_cwes:
            print(f'  [ZAP→NCSA] CWE-{cwe} → NCSA {ncsa_cwes[cwe]}: {alert[\"name\"]}')
" 2>/dev/null || echo "  [WARN] Could not parse ZAP results"
  echo ""
fi

# ═══════════════════════════════════════════
# Generate JSON Report
# ═══════════════════════════════════════════
REPORT=$(python3 -c "
import json, sys
checks = json.loads(sys.stdin.read())
report = {
    'ncsa_version': '1.0',
    'target': '$TARGET',
    'categories_validated': ['1.x', '2.x', '4.x'],
    'summary': {
        'total': len(checks),
        'pass': $PASS_COUNT,
        'fail': $FAIL_COUNT,
        'warning': $WARN_COUNT
    },
    'checks': checks
}
print(json.dumps(report, indent=2))
" <<< "$CHECKS")

if [ -n "$OUTPUT" ]; then
  echo "$REPORT" > "$OUTPUT"
  echo "[ncsa-validator] Report written to: $OUTPUT"
else
  echo "--- NCSA Validation Report (JSON) ---"
  echo "$REPORT"
fi

echo ""
echo "============================================"
echo "NCSA Validation: $PASS_COUNT passed, $FAIL_COUNT failed, $WARN_COUNT warnings"
echo "============================================"

# Exit with error if any critical checks failed
[ "$FAIL_COUNT" -gt 0 ] && exit 1
exit 0
