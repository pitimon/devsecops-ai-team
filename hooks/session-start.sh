#!/usr/bin/env bash

# Inject DevSecOps AI Team context at session start (~400 tokens)
# Pattern: explanatory-output-style plugin (same as claude-governance)

# Check runner status
RUNNER_STATUS="not running"
if docker ps --filter "name=devsecops-runner" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
  RUNNER_STATUS="running"
fi

cat << EOF
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "## DevSecOps AI Team Active\n\nYou have the **devsecops-ai-team** plugin installed. 18 AI agents + 12 skills for full-pipeline security scanning.\n\n### Runner Status: ${RUNNER_STATUS}\n\n### Available Security Skills\n- \`/devsecops-setup\` — Initialize DevSecOps for this project\n- \`/sast-scan\` — Static analysis (Semgrep)\n- \`/dast-scan\` — Dynamic testing (ZAP)\n- \`/sca-scan\` — Dependency scan (Grype)\n- \`/container-scan\` — Container security (Trivy)\n- \`/iac-scan\` — IaC scanning (Checkov)\n- \`/secret-scan\` — Secret detection (GitLeaks)\n- \`/sbom-generate\` — SBOM generation (Syft)\n- \`/full-pipeline\` — Run all scans\n- \`/compliance-report\` — Framework compliance mapping\n- \`/incident-response\` — IR playbook generation\n- \`/security-gate\` — Pass/fail gate decision\n\n### Three Loops (DevSecOps)\n- **Out-of-Loop**: Secret scan on write, format results, SBOM, lint-level SAST\n- **On-the-Loop**: New scan rules, severity policy changes, scan config\n- **In-the-Loop**: Gate override, IR escalation, vuln suppression, DAST target approval\n\n### Tools (Docker containers)\nSemgrep | ZAP | Grype | Trivy | Checkov | GitLeaks | Syft"
  }
}
EOF

exit 0
