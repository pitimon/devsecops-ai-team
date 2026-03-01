#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — JSON Normalizer
# Converts tool-specific JSON output to Unified Finding Schema
#
# Usage: json-normalizer.sh --tool <tool> --input <file> --output <file>

TOOL=""
INPUT=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --tool) TOOL="$2"; shift 2 ;;
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$TOOL" ] || [ -z "$INPUT" ] || [ -z "$OUTPUT" ] && {
  echo "Usage: $0 --tool <tool> --input <file> --output <file>"
  exit 1
}

[ ! -f "$INPUT" ] && { echo "Input file not found: $INPUT"; exit 1; }

DATE_PREFIX=$(date +%Y%m%d)

case "$TOOL" in
  semgrep)
    python3 -c "
import json, sys
data = json.load(open('$INPUT'))
findings = []
for i, r in enumerate(data.get('results', []), 1):
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'semgrep',
        'scan_type': 'sast',
        'severity': r.get('extra', {}).get('severity', 'MEDIUM').upper(),
        'confidence': r.get('extra', {}).get('metadata', {}).get('confidence', 'MEDIUM').upper(),
        'title': r.get('extra', {}).get('message', r.get('check_id', '')),
        'cwe_id': next((c for c in r.get('extra', {}).get('metadata', {}).get('cwe', []) if c.startswith('CWE-')), None),
        'location': {
            'file': r.get('path', ''),
            'line_start': r.get('start', {}).get('line', 0),
            'line_end': r.get('end', {}).get('line', 0),
            'snippet': r.get('extra', {}).get('lines', '')[:500]
        },
        'rule_id': r.get('check_id', ''),
        'status': 'open'
    })
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
    'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
    'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
    'low': sum(1 for f in findings if f['severity'] == 'LOW'),
    'info': sum(1 for f in findings if f['severity'] == 'INFO')
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  gitleaks)
    python3 -c "
import json
data = json.load(open('$INPUT'))
if not isinstance(data, list): data = []
findings = []
for i, r in enumerate(data, 1):
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'gitleaks',
        'scan_type': 'secret',
        'severity': 'CRITICAL',
        'confidence': 'HIGH',
        'title': f\"Secret detected: {r.get('Description', 'Unknown')}\",
        'cwe_id': 'CWE-798',
        'location': {
            'file': r.get('File', ''),
            'line_start': r.get('StartLine', 0),
            'line_end': r.get('EndLine', 0),
            'snippet': r.get('Match', '')[:500]
        },
        'rule_id': r.get('RuleID', ''),
        'status': 'open'
    })
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': len(findings),
    'high': 0, 'medium': 0, 'low': 0, 'info': 0
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  grype)
    python3 -c "
import json
data = json.load(open('$INPUT'))
matches = data.get('matches', [])
findings = []
severity_map = {'Critical': 'CRITICAL', 'High': 'HIGH', 'Medium': 'MEDIUM', 'Low': 'LOW', 'Negligible': 'INFO'}
for i, m in enumerate(matches, 1):
    vuln = m.get('vulnerability', {})
    artifact = m.get('artifact', {})
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'grype',
        'scan_type': 'sca',
        'severity': severity_map.get(vuln.get('severity', ''), 'MEDIUM'),
        'confidence': 'HIGH',
        'title': f\"{vuln.get('id', '')}: {artifact.get('name', '')}@{artifact.get('version', '')}\",
        'cwe_id': None,
        'cvss_score': vuln.get('cvss', [{}])[0].get('metrics', {}).get('baseScore') if vuln.get('cvss') else None,
        'location': {
            'package': f\"{artifact.get('name', '')}@{artifact.get('version', '')}\",
            'file': ','.join(l.get('path', '') for l in artifact.get('locations', []))
        },
        'rule_id': vuln.get('id', ''),
        'status': 'open',
        'fix_versions': vuln.get('fix', {}).get('versions', [])
    })
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
    'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
    'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
    'low': sum(1 for f in findings if f['severity'] == 'LOW'),
    'info': sum(1 for f in findings if f['severity'] == 'INFO')
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  trivy)
    python3 -c "
import json
data = json.load(open('$INPUT'))
findings = []
severity_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW', 'UNKNOWN': 'INFO'}
idx = 1
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        findings.append({
            'id': f'FINDING-${DATE_PREFIX}-{idx:03d}',
            'source_tool': 'trivy',
            'scan_type': 'container',
            'severity': severity_map.get(vuln.get('Severity', ''), 'MEDIUM'),
            'confidence': 'HIGH',
            'title': f\"{vuln.get('VulnerabilityID', '')}: {vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}\",
            'cwe_id': (vuln.get('CweIDs') or [None])[0],
            'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score'),
            'location': {
                'package': f\"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}\",
                'image': result.get('Target', '')
            },
            'rule_id': vuln.get('VulnerabilityID', ''),
            'status': 'open',
            'fix_versions': [vuln.get('FixedVersion', '')] if vuln.get('FixedVersion') else []
        })
        idx += 1
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
    'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
    'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
    'low': sum(1 for f in findings if f['severity'] == 'LOW'),
    'info': sum(1 for f in findings if f['severity'] == 'INFO')
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  checkov)
    python3 -c "
import json
data = json.load(open('$INPUT'))
if isinstance(data, list): data = data[0] if data else {}
findings = []
for i, check in enumerate(data.get('results', {}).get('failed_checks', []), 1):
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'checkov',
        'scan_type': 'iac',
        'severity': check.get('severity', 'MEDIUM'),
        'confidence': 'HIGH',
        'title': check.get('check_id', '') + ': ' + check.get('name', ''),
        'cwe_id': None,
        'location': {
            'file': check.get('file_path', ''),
            'line_start': check.get('file_line_range', [0, 0])[0],
            'line_end': check.get('file_line_range', [0, 0])[1],
            'resource': check.get('resource', '')
        },
        'rule_id': check.get('check_id', ''),
        'guideline': check.get('guideline', ''),
        'status': 'open'
    })
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
    'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
    'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
    'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
    'info': sum(1 for f in findings if f.get('severity') == 'INFO')
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  zap)
    python3 -c "
import json
data = json.load(open('$INPUT'))
findings = []
risk_map = {'3': 'CRITICAL', '2': 'HIGH', '1': 'MEDIUM', '0': 'LOW'}
confidence_map = {'3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'LOW'}
idx = 1
for site in data.get('site', []):
    for alert in site.get('alerts', []):
        findings.append({
            'id': f'FINDING-${DATE_PREFIX}-{idx:03d}',
            'source_tool': 'zap',
            'scan_type': 'dast',
            'severity': risk_map.get(str(alert.get('riskcode', 0)), 'MEDIUM'),
            'confidence': confidence_map.get(str(alert.get('confidence', 0)), 'MEDIUM'),
            'title': alert.get('name', ''),
            'cwe_id': f\"CWE-{alert.get('cweid', '')}\" if alert.get('cweid') else None,
            'location': {
                'url': alert.get('instances', [{}])[0].get('uri', '') if alert.get('instances') else ''
            },
            'rule_id': str(alert.get('pluginid', '')),
            'description': alert.get('desc', ''),
            'solution': alert.get('solution', ''),
            'status': 'open'
        })
        idx += 1
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
    'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
    'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
    'low': sum(1 for f in findings if f['severity'] == 'LOW'),
    'info': sum(1 for f in findings if f['severity'] == 'INFO')
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  *)
    echo "[normalizer] WARNING: Unknown tool '$TOOL', copying raw output"
    cp "$INPUT" "$OUTPUT"
    ;;
esac

echo "[normalizer] Normalized: $OUTPUT"
