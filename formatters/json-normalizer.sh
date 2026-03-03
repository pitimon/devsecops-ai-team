#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — JSON Normalizer
# Converts tool-specific JSON output to Unified Finding Schema
# Supports 10 tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft, nuclei, trufflehog, kube-bench
#
# Usage: json-normalizer.sh --tool <tool> --input <file> --output <file>

# Require python3 for JSON parsing
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 required but not found. Install Python 3.8+" >&2
  exit 1
fi

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
        'severity': {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'INFO',
                     'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW'
                    }.get((r.get('extra', {}).get('severity') or 'MEDIUM').upper(), 'MEDIUM'),
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
    for vuln in (result.get('Vulnerabilities') or []):
        findings.append({
            'id': f'FINDING-${DATE_PREFIX}-{idx:03d}',
            'source_tool': 'trivy',
            'scan_type': 'container',
            'severity': severity_map.get(vuln.get('Severity', ''), 'MEDIUM'),
            'confidence': 'HIGH',
            'title': f\"{vuln.get('VulnerabilityID', '')}: {vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}\",
            'cwe_id': ((vuln.get('CweIDs') or [None])[0] or '').split(':')[0] or None,
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
    for misconf in (result.get('Misconfigurations') or []):
        findings.append({
            'id': f'FINDING-${DATE_PREFIX}-{idx:03d}',
            'source_tool': 'trivy',
            'scan_type': 'config',
            'severity': severity_map.get(misconf.get('Severity', ''), 'MEDIUM'),
            'confidence': 'HIGH',
            'title': f\"{misconf.get('ID', '')}: {misconf.get('Title', '')}\",
            'cwe_id': None,
            'location': {
                'file': misconf.get('CauseMetadata', {}).get('Resource', result.get('Target', '')),
                'line_start': misconf.get('CauseMetadata', {}).get('StartLine', 0),
                'line_end': misconf.get('CauseMetadata', {}).get('EndLine', 0),
                'image': result.get('Target', '')
            },
            'rule_id': misconf.get('ID', ''),
            'resolution': misconf.get('Resolution', ''),
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

  checkov)
    python3 -c "
import json
data = json.load(open('$INPUT'))
all_failed = []
if isinstance(data, list):
    for item in data:
        all_failed.extend(item.get('results', {}).get('failed_checks', []))
else:
    all_failed = data.get('results', {}).get('failed_checks', [])
findings = []
for i, check in enumerate(all_failed, 1):
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'checkov',
        'scan_type': 'iac',
        'severity': check.get('severity') or 'MEDIUM',
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

  syft)
    python3 -c "
import json
data = json.load(open('$INPUT'))
findings = []
idx = 1
for comp in data.get('components', []):
    if comp.get('type') == 'operating-system':
        continue
    licenses = []
    for lic in comp.get('licenses', []):
        lid = lic.get('license', {}).get('id', '')
        if lid:
            licenses.append(lid)
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{idx:03d}',
        'source_tool': 'syft',
        'scan_type': 'sbom',
        'severity': 'INFO',
        'title': f\"{comp.get('name', '')}@{comp.get('version', '')}\",
        'cwe_id': None,
        'location': {
            'package': comp.get('name', ''),
            'version': comp.get('version', ''),
            'purl': comp.get('purl', ''),
        },
        'rule_id': comp.get('purl', ''),
        'description': f\"Component {comp.get('name', '')} version {comp.get('version', '')} ({', '.join(licenses) if licenses else 'unknown license'})\",
        'status': 'open'
    })
    idx += 1
json.dump({'findings': findings, 'summary': {
    'total': len(findings),
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
    'info': len(findings)
}}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  nuclei)
    python3 -c "
import json, sys

findings = []
i = 0
with open('$INPUT') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        i += 1
        info = item.get('info', {})
        classification = info.get('classification', {})
        cwe_ids = classification.get('cwe-id', [])
        cwe_id = cwe_ids[0] if cwe_ids else None

        sev_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO'}
        severity = sev_map.get(info.get('severity', 'info').lower(), 'INFO')

        findings.append({
            'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
            'source_tool': 'nuclei',
            'scan_type': 'dast',
            'severity': severity,
            'confidence': 'HIGH' if classification.get('cvss-score', 0) >= 7.0 else 'MEDIUM',
            'title': info.get('name', item.get('template-id', 'Unknown')),
            'cwe_id': cwe_id,
            'rule_id': item.get('template-id', ''),
            'location': {'url': item.get('matched-at', ''), 'file': '', 'line': 0},
            'status': 'open'
        })

summary = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
for f in findings:
    key = f['severity'].lower()
    if key in summary:
        summary[key] += 1

json.dump({'findings': findings, 'summary': summary}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  trufflehog)
    python3 -c "
import json, sys

findings = []
with open('$INPUT') as f:
    for line_num, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        raw = obj.get('Raw', '')
        redacted = raw[:4] + '***' if len(raw) > 4 else '***'
        detector = obj.get('DetectorName', 'unknown')
        verified = obj.get('Verified', False)

        source = obj.get('SourceMetadata', {}).get('Data', {})
        file_path = ''
        line_start = 0
        if 'Filesystem' in source:
            file_path = source['Filesystem'].get('file', '')
            line_start = source['Filesystem'].get('line', 0)
        elif 'Git' in source:
            file_path = source['Git'].get('file', '')
            line_start = source['Git'].get('line', 0)

        findings.append({
            'id': f'TRUFFLEHOG-{line_num:03d}',
            'source_tool': 'trufflehog',
            'scan_type': 'secret',
            'rule_id': f'trufflehog-{detector.lower()}',
            'severity': 'CRITICAL' if verified else 'HIGH',
            'confidence': 'HIGH' if verified else 'MEDIUM',
            'title': f'{detector} secret detected',
            'location': {
                'file': file_path,
                'line_start': line_start,
                'line_end': line_start
            },
            'message': f'{\"Verified\" if verified else \"Unverified\"} {detector} secret found (redacted: {redacted})',
            'verified': verified,
            'status': 'open'
        })

summary = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
for f in findings:
    key = f['severity'].lower()
    if key in summary:
        summary[key] += 1

json.dump({'findings': findings, 'summary': summary}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  kube-bench)
    python3 -c "
import json, sys

data = json.load(open('$INPUT'))
if not isinstance(data, list): data = []
findings = []
status_severity = {'FAIL': 'HIGH', 'WARN': 'MEDIUM', 'PASS': 'LOW', 'INFO': 'INFO'}

for i, test in enumerate(data, 1):
    status = test.get('status', 'INFO').upper()
    severity = status_severity.get(status, 'INFO')
    findings.append({
        'id': f'FINDING-${DATE_PREFIX}-{i:03d}',
        'source_tool': 'kube-bench',
        'scan_type': 'kubernetes',
        'severity': severity,
        'confidence': 'HIGH',
        'title': test.get('test_desc', ''),
        'cwe_id': None,
        'location': {
            'benchmark': test.get('test_number', ''),
            'audit': test.get('audit', '')
        },
        'rule_id': test.get('test_number', ''),
        'message': f\"CIS Benchmark {test.get('test_number', '')}: {test.get('test_desc', '')} [{status}]\",
        'remediation': test.get('remediation', ''),
        'status': 'open'
    })

summary = {'total': len(findings), 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
for f in findings:
    key = f['severity'].lower()
    if key in summary:
        summary[key] += 1

json.dump({'findings': findings, 'summary': summary}, open('$OUTPUT', 'w'), indent=2)
" 2>/dev/null
    ;;

  *)
    echo "[normalizer] WARNING: Unknown tool '$TOOL', copying raw output"
    cp "$INPUT" "$OUTPUT"
    ;;
esac

echo "[normalizer] Normalized: $OUTPUT"
