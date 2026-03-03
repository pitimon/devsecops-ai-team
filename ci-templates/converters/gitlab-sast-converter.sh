#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — GitLab SAST Report Converter
# Converts normalized JSON findings to GitLab SAST schema v15.0.7
#
# Usage: gitlab-sast-converter.sh --input <normalized.json> --output <gl-sast-report.json>

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
import json, sys

data = json.load(open('$INPUT'))
findings = data.get('findings', [])

severity_map = {
    'CRITICAL': 'Critical',
    'HIGH': 'High',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
    'INFO': 'Info'
}

gl_report = {
    'version': '15.0.7',
    'vulnerabilities': [],
    'scan': {
        'analyzer': {
            'id': 'devsecops-ai-team',
            'name': 'DevSecOps AI Team',
            'vendor': {'name': 'DevSecOps AI Team'}
        },
        'scanner': {
            'id': 'devsecops-multi',
            'name': 'DevSecOps Multi-Scanner',
            'vendor': {'name': 'DevSecOps AI Team'}
        },
        'type': 'sast',
        'status': 'success'
    }
}

for f in findings:
    loc = f.get('location', {})
    vuln = {
        'id': f.get('rule_id', f.get('id', '')),
        'name': f.get('title', ''),
        'description': f.get('description', f.get('title', '')),
        'severity': severity_map.get(f.get('severity', 'MEDIUM'), 'Medium'),
        'location': {
            'file': loc.get('file', loc.get('package', '')),
            'start_line': loc.get('line_start', 0),
            'end_line': loc.get('line_end', 0)
        }
    }
    if f.get('cwe_id'):
        vuln['identifiers'] = [{'type': 'cwe', 'name': f['cwe_id'], 'value': f['cwe_id']}]
    if f.get('source_tool'):
        vuln['scanner'] = {'id': f['source_tool'], 'name': f['source_tool']}
    gl_report['vulnerabilities'].append(vuln)

json.dump(gl_report, open('$OUTPUT', 'w'), indent=2)
print(f'Converted {len(findings)} findings to GitLab SAST format')
"

echo "[gitlab-sast] Output: $OUTPUT"
