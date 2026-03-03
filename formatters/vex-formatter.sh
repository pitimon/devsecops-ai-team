#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — VEX (Vulnerability Exploitability eXchange) Formatter
# Generates CycloneDX VEX or OpenVEX format from normalized findings.
# Usage: vex-formatter.sh --input <findings.json> --output <output.json> [--format cdx|openvex]
#
# Formats:
#   cdx     — CycloneDX VEX (bomFormat: CycloneDX, specVersion: 1.6)
#   openvex — OpenVEX (@context: https://openvex.dev/ns/v0.2.0)
#
# Status mapping:
#   critical/high severity → exploitable (cdx) / affected (openvex)
#   medium severity → under_investigation
#   low/info severity → not_affected

INPUT=""
OUTPUT=""
FORMAT="cdx"

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$INPUT" ] || [ -z "$OUTPUT" ] && { echo "Usage: $0 --input <file> --output <file> [--format cdx|openvex]"; exit 1; }
[ ! -f "$INPUT" ] && { echo "Error: input file not found: $INPUT"; exit 1; }

python3 -c "
import json, sys, uuid
from datetime import datetime, timezone

data = json.load(open('$INPUT'))
findings = data.get('findings', [])
fmt = '$FORMAT'
timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# Severity to CycloneDX VEX analysis state
CDX_STATE_MAP = {
    'CRITICAL': 'exploitable',
    'HIGH': 'exploitable',
    'ERROR': 'exploitable',
    'MEDIUM': 'in_triage',
    'WARNING': 'in_triage',
    'LOW': 'not_affected',
    'INFO': 'not_affected',
}

# Severity to OpenVEX status
OPENVEX_STATUS_MAP = {
    'CRITICAL': 'affected',
    'HIGH': 'affected',
    'ERROR': 'affected',
    'MEDIUM': 'under_investigation',
    'WARNING': 'under_investigation',
    'LOW': 'not_affected',
    'INFO': 'not_affected',
}

def build_ref(f):
    loc = f.get('location', {})
    file_path = loc.get('file', loc.get('url', loc.get('package', 'unknown')))
    line = loc.get('line_start')
    if line:
        return f'{file_path}:{line}'
    return file_path

def vuln_id(f):
    return f.get('cwe_id') or f.get('rule_id') or f.get('id', 'unknown')

if fmt == 'cdx':
    vulns = []
    for f in findings:
        severity = f.get('severity', 'MEDIUM').upper()
        state = CDX_STATE_MAP.get(severity, 'in_triage')
        vuln = {
            'id': vuln_id(f),
            'source': {'name': f.get('source_tool', 'unknown')},
            'analysis': {
                'state': state,
                'detail': f.get('message', f.get('title', ''))
            },
            'affects': [
                {'ref': build_ref(f)}
            ]
        }
        vulns.append(vuln)

    output = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': [{'name': 'devsecops-ai-team', 'version': '2.8.0'}]
        },
        'vulnerabilities': vulns
    }

elif fmt == 'openvex':
    statements = []
    for f in findings:
        severity = f.get('severity', 'MEDIUM').upper()
        status = OPENVEX_STATUS_MAP.get(severity, 'under_investigation')
        justification = ''
        if status == 'not_affected':
            justification = 'inline_mitigations_already_exist'
        stmt = {
            'vulnerability': {'@id': vuln_id(f)},
            'products': [{'@id': build_ref(f)}],
            'status': status,
        }
        if justification:
            stmt['justification'] = justification
        statements.append(stmt)

    output = {
        '@context': 'https://openvex.dev/ns/v0.2.0',
        '@id': f'urn:uuid:{uuid.uuid4()}',
        'author': 'devsecops-ai-team',
        'timestamp': timestamp,
        'statements': statements
    }
else:
    print(f'Error: unknown format: {fmt} (expected cdx or openvex)', file=sys.stderr)
    sys.exit(1)

json.dump(output, open('$OUTPUT', 'w'), indent=2)
"

# Print summary
if [ "$FORMAT" = "cdx" ]; then
  COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d['vulnerabilities']))" 2>/dev/null)
  echo "[vex] Format: CycloneDX VEX — $COUNT vulnerabilities → $OUTPUT"
elif [ "$FORMAT" = "openvex" ]; then
  COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d['statements']))" 2>/dev/null)
  echo "[vex] Format: OpenVEX — $COUNT statements → $OUTPUT"
fi
