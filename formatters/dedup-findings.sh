#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Cross-Tool Finding Deduplicator
# Merges multiple normalized JSON files and removes duplicate findings
#
# Dedup key:
#   File findings:  (cve_id, file, line_start)
#   Dep findings:   (cve_id, package)
#
# On merge: keep highest severity, concatenate source_tool
#
# Usage: dedup-findings.sh --inputs <file1,file2,...> --output <file>

INPUTS=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --inputs) INPUTS="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$INPUTS" ] || [ -z "$OUTPUT" ] && {
  echo "Usage: $0 --inputs <file1,file2,...> --output <file>"
  exit 1
}

python3 -c "
import json, sys

severity_rank = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
input_files = '$INPUTS'.split(',')

all_findings = []
for f in input_files:
    try:
        data = json.load(open(f.strip()))
        all_findings.extend(data.get('findings', []))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f'[dedup] WARNING: Skipping {f}: {e}', file=sys.stderr)

# Build dedup map
dedup = {}
for finding in all_findings:
    loc = finding.get('location', {})
    cve = finding.get('cwe_id') or finding.get('rule_id', '')

    # Choose dedup key based on finding type
    if loc.get('file'):
        key = (cve, loc.get('file', ''), loc.get('line_start', 0))
    elif loc.get('package'):
        key = (cve, loc.get('package', ''), 'pkg')
    elif loc.get('url'):
        key = (cve, loc.get('url', ''), 'url')
    else:
        key = (cve, finding.get('id', ''), 'unique')

    if key in dedup:
        existing = dedup[key]
        # Keep highest severity
        if severity_rank.get(finding['severity'], 0) > severity_rank.get(existing['severity'], 0):
            existing['severity'] = finding['severity']
        # Concatenate source tools
        tools = existing.get('source_tool', '').split(',')
        new_tool = finding.get('source_tool', '')
        if new_tool and new_tool not in tools:
            existing['source_tool'] = ','.join(tools + [new_tool])
    else:
        dedup[key] = finding.copy()

# Re-index findings
findings = list(dedup.values())
for i, f in enumerate(findings, 1):
    f['id'] = f'FINDING-MERGED-{i:03d}'

result = {
    'findings': findings,
    'summary': {
        'total': len(findings),
        'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'low': sum(1 for f in findings if f['severity'] == 'LOW'),
        'info': sum(1 for f in findings if f['severity'] == 'INFO'),
        'deduplicated_from': len(all_findings),
        'sources': list(set(f.get('source_tool', '').split(',')[0] for f in findings))
    }
}

json.dump(result, open('$OUTPUT', 'w'), indent=2)
print(f'[dedup] Merged {len(all_findings)} → {len(findings)} findings ({len(all_findings) - len(findings)} duplicates removed)')
"

echo "[dedup] Output: $OUTPUT"
