# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in the DevSecOps AI Team plugin, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub Issue
2. Email: pitimon@users.noreply.github.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix release**: Within 30 days for critical issues

### Scope

This plugin runs security tools in Docker containers on the user's local machine. The following are in scope:

- Container escape vulnerabilities
- Secret leakage through scan results
- Command injection in job-dispatcher.sh or hooks
- Privilege escalation in runner containers
- Insecure volume mount configurations

### Out of Scope

- Vulnerabilities in upstream tools (Semgrep, Trivy, etc.) — report to their maintainers
- Issues requiring physical access to the host machine
- Social engineering attacks
