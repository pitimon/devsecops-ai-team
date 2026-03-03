#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — SARIF v2.1.0 Formatter
# Converts normalized JSON to SARIF format for GitHub Security tab
# Supports per-tool runs (default) or --combined for legacy single-run mode

INPUT=""
OUTPUT=""
COMBINED=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --combined) COMBINED=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$INPUT" ] || [ -z "$OUTPUT" ] && { echo "Usage: $0 --input <file> --output <file> [--combined]"; exit 1; }

python3 -c "
import json, sys
from collections import defaultdict

data = json.load(open('$INPUT'))
findings = data.get('findings', [])
combined = $( [ "$COMBINED" = "true" ] && echo "True" || echo "False" )

TOOL_META = {
    'semgrep': {'name': 'Semgrep', 'version': '1.0.0', 'uri': 'https://semgrep.dev'},
    'zap': {'name': 'ZAP', 'version': '1.0.0', 'uri': 'https://www.zaproxy.org'},
    'grype': {'name': 'Grype', 'version': '1.0.0', 'uri': 'https://github.com/anchore/grype'},
    'trivy': {'name': 'Trivy', 'version': '1.0.0', 'uri': 'https://trivy.dev'},
    'checkov': {'name': 'Checkov', 'version': '1.0.0', 'uri': 'https://www.checkov.io'},
    'gitleaks': {'name': 'GitLeaks', 'version': '1.0.0', 'uri': 'https://gitleaks.io'},
    'syft': {'name': 'Syft', 'version': '1.0.0', 'uri': 'https://github.com/anchore/syft'},
}

DEFAULT_META = {'name': 'DevSecOps AI Team', 'version': '1.0.0', 'uri': 'https://github.com/pitimon/devsecops-ai-team'}

level_map = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note', 'INFO': 'note'}

def make_result(f):
    rule_id = f.get('rule_id', f.get('id', ''))
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
    return result

def make_rule(f):
    rule_id = f.get('rule_id', f.get('id', ''))
    return {
        'id': rule_id,
        'shortDescription': {'text': f.get('title', '')},
        'properties': {'severity': f.get('severity', 'MEDIUM')}
    }

sarif = {
    '\$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    'version': '2.1.0',
    'runs': []
}

if combined:
    # Legacy single-run mode
    rules_seen = set()
    rules = []
    results = []
    for f in findings:
        rule_id = f.get('rule_id', f.get('id', ''))
        if rule_id not in rules_seen:
            rules_seen.add(rule_id)
            rules.append(make_rule(f))
        results.append(make_result(f))
    sarif['runs'].append({
        'tool': {
            'driver': {
                'name': DEFAULT_META['name'],
                'version': DEFAULT_META['version'],
                'informationUri': DEFAULT_META['uri'],
                'rules': rules
            }
        },
        'results': results
    })
else:
    # Per-tool mode: group findings by source_tool
    grouped = defaultdict(list)
    for f in findings:
        tool_key = f.get('source_tool', '')
        grouped[tool_key].append(f)

    # Process each tool group — known tools first (sorted), then default
    tool_keys = sorted([k for k in grouped if k and k in TOOL_META])
    unknown_keys = sorted([k for k in grouped if k and k not in TOOL_META])
    tool_keys.extend(unknown_keys)
    if '' in grouped:
        tool_keys.append('')

    for tool_key in tool_keys:
        tool_findings = grouped[tool_key]
        meta = TOOL_META.get(tool_key, DEFAULT_META) if tool_key else DEFAULT_META
        rules_seen = set()
        rules = []
        results = []
        for f in tool_findings:
            rule_id = f.get('rule_id', f.get('id', ''))
            if rule_id not in rules_seen:
                rules_seen.add(rule_id)
                rules.append(make_rule(f))
            results.append(make_result(f))
        sarif['runs'].append({
            'tool': {
                'driver': {
                    'name': meta['name'],
                    'version': meta['version'],
                    'informationUri': meta['uri'],
                    'rules': rules
                }
            },
            'results': results
        })

json.dump(sarif, open('$OUTPUT', 'w'), indent=2)
"

TOTAL_RESULTS=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(sum(len(r['results']) for r in d['runs']))" 2>/dev/null)
RUN_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d['runs']))" 2>/dev/null)
echo "[sarif] Output: $OUTPUT ($TOTAL_RESULTS results in $RUN_COUNT runs)"
