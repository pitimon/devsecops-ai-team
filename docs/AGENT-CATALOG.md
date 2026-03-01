# Agent Catalog — DevSecOps AI Team (18 Agents)

## Orchestrators (ผู้ประสานงาน)

### devsecops-lead

- **Model**: sonnet
- **Auto-trigger**: Complex multi-step security tasks
- **Decision Loop**: On-the-Loop
- **Role**: Senior DevSecOps lead who analyzes projects and coordinates multi-step security workflows. Routes tasks to appropriate specialists.

### security-stack-analyst

- **Model**: sonnet
- **Auto-trigger**: Session start, `/devsecops-setup`
- **Decision Loop**: Out-of-Loop
- **Role**: Detects technology stack (languages, frameworks, containers, IaC) and enables intelligent agent routing to the right specialists.

### team-configurator

- **Model**: sonnet
- **Auto-trigger**: `/devsecops-setup`, new project detected
- **Decision Loop**: On-the-Loop
- **Role**: Scans project dependencies and available tools, configures optimal agent mappings, updates configuration.

## Security Specialists (ผู้เชี่ยวชาญเฉพาะทาง)

### sast-specialist

- **Model**: sonnet
- **Tool**: Semgrep
- **Auto-trigger**: `/sast-scan`, code quality concerns
- **Decision Loop**: Out-of-Loop (scan), On-the-Loop (new rules)
- **Role**: Deep static analysis expertise. Custom rule creation, false positive triage, code pattern analysis.

### dast-specialist

- **Model**: sonnet
- **Tool**: ZAP
- **Auto-trigger**: `/dast-scan`, web app testing
- **Decision Loop**: In-the-Loop (target approval required)
- **Role**: Dynamic security testing. Authenticated scanning, API fuzzing, crawl strategy optimization.

### sca-specialist

- **Model**: sonnet
- **Tool**: Grype
- **Auto-trigger**: `/sca-scan`, dependency updates
- **Decision Loop**: Out-of-Loop
- **Role**: Supply chain security. Dependency risk assessment, license compliance, upgrade path recommendations.

### container-security-specialist

- **Model**: sonnet
- **Tool**: Trivy
- **Auto-trigger**: `/container-scan`, Dockerfile changes
- **Decision Loop**: Out-of-Loop (scan), On-the-Loop (policy)
- **Role**: Container hardening. Image optimization, layer analysis, runtime security, pod security policies.

### iac-security-specialist

- **Model**: sonnet
- **Tool**: Checkov
- **Auto-trigger**: `/iac-scan`, Terraform/K8s changes
- **Decision Loop**: Out-of-Loop
- **Role**: IaC security. CIS benchmarks, misconfig detection, drift analysis, policy-as-code.

### secret-scanner-specialist

- **Model**: sonnet
- **Tool**: GitLeaks
- **Auto-trigger**: `/secret-scan`, credential patterns
- **Decision Loop**: Out-of-Loop
- **Role**: Secret detection. Git history analysis, entropy detection, custom regex patterns, rotation guidance.

### sbom-analyst

- **Model**: sonnet
- **Tool**: Syft
- **Auto-trigger**: `/sbom-generate`, license questions
- **Decision Loop**: Out-of-Loop
- **Role**: SBOM generation. CycloneDX/SPDX formats, license compatibility analysis, component inventory.

## Universal Experts (ผู้เชี่ยวชาญข้ามสาขา)

### compliance-officer

- **Model**: sonnet
- **Auto-trigger**: After any scan completes
- **Decision Loop**: On-the-Loop
- **Role**: Maps findings to NIST 800-53, OWASP Top 10, MITRE ATT&CK, CIS Benchmarks. Generates compliance gap analysis.

### threat-modeler

- **Model**: sonnet
- **Auto-trigger**: Architecture changes, new features
- **Decision Loop**: On-the-Loop
- **Role**: STRIDE/PASTA threat modeling. Attack surface analysis, data flow diagrams, trust boundary identification.

### vuln-triager

- **Model**: sonnet
- **Auto-trigger**: When new findings detected
- **Decision Loop**: On-the-Loop
- **Role**: Severity assessment and prioritization. CVSS scoring, exploitability analysis, business impact mapping, deduplication.

### remediation-advisor

- **Model**: sonnet
- **Auto-trigger**: After triage, when fixes needed
- **Decision Loop**: On-the-Loop
- **Role**: Fix suggestions with code examples. Patch guidance, version upgrade paths, workaround strategies, effort estimation.

## Core Team (ทีมหลัก)

### security-code-reviewer

- **Model**: sonnet
- **Auto-trigger**: On code changes, before PR
- **Decision Loop**: Out-of-Loop
- **Role**: Rigorous security-aware code reviews with OWASP-tagged findings. Checks injection, auth bypass, data exposure, crypto.

### incident-responder

- **Model**: sonnet
- **Auto-trigger**: CRITICAL findings detected
- **Decision Loop**: In-the-Loop
- **Role**: Creates IR playbooks, assigns severity, coordinates containment, tracks remediation timeline, post-incident reports.

### report-generator

- **Model**: sonnet
- **Auto-trigger**: After `/full-pipeline`, `/compliance-report`
- **Decision Loop**: Out-of-Loop
- **Role**: Produces executive dashboards (HTML), PR comments (MD), GitHub Security (SARIF), machine-readable (JSON).

### pipeline-guardian

- **Model**: sonnet
- **Auto-trigger**: Before deploy, `/security-gate`
- **Decision Loop**: On-the-Loop (gate decision), In-the-Loop (override)
- **Role**: CI/CD security gate enforcement. Pass/fail decisions against policy, blocking deploys with critical findings.
