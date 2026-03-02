# Smoke Test Prompts — DevSecOps AI Team

Manual functional test scenarios for each skill and agent.

## Skills

### /devsecops-setup

1. "Set up security scanning for this project"
2. "Initialize DevSecOps" (with a Node.js project)
3. "Initialize DevSecOps" (with a Python + Docker project)

### /sast-scan

1. "Run a SAST scan on this project"
2. "Scan my code for security vulnerabilities"
3. "Run Semgrep with OWASP rules"

### /dast-scan

1. "Run a DAST scan against http://localhost:3000"
2. "Test my web app for vulnerabilities"
3. "Run ZAP baseline scan"

### /sca-scan

1. "Check my dependencies for known CVEs"
2. "Run a supply chain security scan"
3. "Scan package.json for vulnerabilities"

### /container-scan

1. "Scan my Docker image for vulnerabilities"
2. "Check my Dockerfile for security issues"
3. "Run Trivy on myapp:latest"

### /iac-scan

1. "Scan my Terraform files for misconfigurations"
2. "Check my Kubernetes manifests for security"
3. "Run Checkov on my IaC"

### /secret-scan

1. "Scan for leaked secrets in this repo"
2. "Check for hardcoded API keys"
3. "Run GitLeaks on the git history"

### /sbom-generate

1. "Generate an SBOM for this project"
2. "Create a software bill of materials"
3. "List all dependencies with licenses"

### /full-pipeline

1. "Run a complete security scan"
2. "Full DevSecOps pipeline check"
3. "Run all security tools"

### /compliance-report

1. "Generate a NIST 800-53 compliance report"
2. "Map our findings to OWASP Top 10"
3. "Create an audit-ready compliance report"

### /incident-response

1. "We found a critical SQL injection — create an IR playbook"
2. "Generate an incident response plan for this vulnerability"
3. "Security breach detected — coordinate response"

### /security-gate

1. "Are we ready to deploy?"
2. "Run the security gate check"
3. "Pass/fail decision for production release"

### /auto-fix

1. "Fix all critical vulnerabilities automatically"
2. "Auto-fix the SAST findings"
3. "Apply security patches --dry-run"

## Agents (trigger keywords)

### Orchestrators

- "I need a comprehensive security review of this project" → devsecops-lead
- "What tech stack is this project using?" → security-stack-analyst
- "Configure the security team for this project" → team-configurator

### Specialists

- "Deep dive into the SAST results" → sast-specialist
- "Explain the DAST findings" → dast-specialist
- "Analyze dependency risks" → sca-specialist
- "Harden this Docker image" → container-security-specialist
- "Review Terraform security" → iac-security-specialist
- "Investigate this credential leak" → secret-scanner-specialist
- "Analyze the SBOM for license issues" → sbom-analyst

### Experts

- "Map findings to compliance frameworks" → compliance-officer
- "Threat model this architecture" → threat-modeler
- "Prioritize these vulnerabilities" → vuln-triager
- "How do I fix this vulnerability?" → remediation-advisor

### Core Team

- "Security review this PR" → security-code-reviewer
- "We have a critical security incident" → incident-responder
- "Generate an executive security report" → report-generator
- "Should we block this deployment?" → pipeline-guardian
