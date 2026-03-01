# DevSecOps Fitness Functions (extends governance.md)

These rules extend the base governance fitness functions with security-specific checks.

## Pre-Commit (extends governance.md)

Base governance checks still apply:

- No hardcoded secrets (API*KEY=, password=, sk-, ghp*, AKIA, token=)
- Input validation on all new endpoints
- Parameterized database queries
- File size < 800 lines, functions < 50 lines
- Immutable patterns, no console.log

DevSecOps additions:

- Secret scan via GitLeaks container (deep scan, beyond regex)
- SAST quick-check on changed files via Semgrep (p/security-audit)
- No new dependencies with known CRITICAL CVEs
- Container images must not use :latest tag

## Pre-PR (extends governance.md)

Base governance checks still apply:

- Conventional commits
- DOMAIN.md updated if schema changed
- Test coverage >= 80%

DevSecOps additions:

- Full pipeline scan results exist and are < 24h old
- Security gate PASS with active policy
- No CRITICAL findings unsuppressed
- SBOM generated for release branches
- All new API endpoints have authentication checks

## Architecture (extends governance.md)

Base governance checks still apply:

- Service boundaries, auth, rate limiting, error safety

DevSecOps additions:

- Container images scanned (Trivy) — no CRITICAL CVEs
- IaC manifests validated (Checkov) — CIS benchmark pass
- Dependency vulnerabilities assessed (Grype) — no known exploits
- DAST scan for public endpoints (ZAP baseline)
- Threat model updated for new attack surfaces
