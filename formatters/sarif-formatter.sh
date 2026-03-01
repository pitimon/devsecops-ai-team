#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — SARIF v2.1.0 Formatter
# Converts normalized JSON to SARIF format for GitHub Security tab

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

sarif = {
    '\$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    'version': '2.1.0',
    'runs': [{
        'tool': {
            'driver': {
                'name': 'DevSecOps AI Team',
                'version': '1.0.0',
                'informationUri': 'https://github.com/pitimon/devsecops-ai-team',
                'rules': []
            }
        },
        'results': []
    }]
}

level_map = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note', 'INFO': 'note'}
rules_seen = set()

for f in findings:
    rule_id = f.get('rule_id', f.get('id', ''))
    if rule_id not in rules_seen:
        rules_seen.add(rule_id)
        sarif['runs'][0]['tool']['driver']['rules'].append({
            'id': rule_id,
            'shortDescription': {'text': f.get('title', '')},
            'properties': {'severity': f.get('severity', 'MEDIUM')}
        })

    loc = f.get('location', {})
    result = {
        'ruleId': rule_id,
        'level': level_map.get(f.get('severity', 'MEDIUM'), 'warning'),
        'message': {'text': f.get('title', '')},
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {'uri': loc.get('file', loc.get('url', loc.get('package', '')))},
                'region': {'startLine': loc.get('line_start', 1)} if loc.get('line_start') else {}
            }
        }]
    }
    if f.get('cwe_id'):
        result['taxa'] = [{'id': f['cwe_id'], 'toolComponent': {'name': 'CWE'}}]
    sarif['runs'][0]['results'].append(result)

json.dump(sarif, open('$OUTPUT', 'w'), indent=2)
"

echo "[sarif] Output: $OUTPUT ($(python3 -c "import json; print(len(json.load(open('$OUTPUT'))['runs'][0]['results']))" 2>/dev/null) results)"
