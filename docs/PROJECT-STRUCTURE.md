# Project Structure

> Full project structure reference for the `devsecops-ai-team` plugin.
> See also: [README.md](../README.md) | [CLAUDE.md](../CLAUDE.md)

---

```
devsecops-ai-team/
+-- .claude-plugin/          # Plugin metadata (plugin.json, marketplace.json)
+-- .mcp.json                # MCP server declaration
+-- .github/workflows/       # CI/CD (validate, security-scan, framework-review, release)
+-- ci-templates/            # CI templates (GitHub Actions + GitLab CI copy-paste)
+-- agents/                  # 18 AI agents (4 subdirectories)
|   +-- orchestrators/       #   3 orchestrator agents
|   +-- specialists/         #   7 specialist agents
|   +-- experts/             #   4 expert agents
|   +-- core-team/           #   4 core team agents
+-- skills/                  # 16 skill definitions (SKILL.md)
|   +-- references/          # 19 domain knowledge files (~500-800 lines each)
+-- runner/                  # Sidecar Runner (Dockerfile, compose, dispatcher, collector)
|   +-- pipelines/           #   DAG pipeline definitions (YAML)
|   +-- pipeline-engine.sh   #   DAG execution engine with topological sort
|   +-- nuclei-templates/    #   Custom Nuclei templates (GraphQL)
+-- formatters/              # SARIF, Markdown, HTML, PDF, CSV, VEX, JSON normalizer, dedup, dashboard
+-- mcp/                     # MCP server -- 10 tools
|   +-- server.mjs           #   ESM module, stdio transport
|   +-- package.json         #   @modelcontextprotocol/sdk + zod
+-- mappings/                # CWE->OWASP, CWE->NIST, CWE->MITRE, CWE->NCSA, CWE->PDPA, CWE->SOC2, CWE->ISO27001, severity policy
+-- rules/                   # Custom Semgrep rules (A01-A10, K8s, GraphQL) — 84 rules
+-- templates/               # Report templates (HTML, Markdown, dashboard.html)
+-- hooks/                   # 3 hooks (session-start, scan-on-write, pre-commit-gate)
+-- scripts/                 # install-runner, install-rules, check-prerequisites, NCSA validator, scan-db.sh
+-- tests/                   # 1,302+ tests across 42 suites
+-- docs/                    # INSTALL, TROUBLESHOOTING, AGENT-CATALOG, RUNBOOK, MANDAY
+-- examples/                # Rules, policies, DOMAIN.md, Semgrep rules
+-- frameworks.json          # 19 tracked security frameworks with version info
```

---

## Documentation

| Document                                                      | Description                                            |
| ------------------------------------------------------------- | ------------------------------------------------------ |
| [**Wiki**](https://github.com/pitimon/devsecops-ai-team/wiki) | Comprehensive documentation with ASCII diagrams        |
| [INSTALL.md](INSTALL.md)                                      | Installation guide (standard, manual, air-gapped, MCP) |
| [AGENT-CATALOG.md](AGENT-CATALOG.md)                          | 18 agents with routing cues + triggers                 |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md)                      | Common issues (8 scenarios)                            |
| [FRAMEWORK-UPDATE-RUNBOOK.md](FRAMEWORK-UPDATE-RUNBOOK.md)    | Framework version update procedure                     |
| [MANDAY-ESTIMATION.md](MANDAY-ESTIMATION.md)                  | ROI analysis + cost comparison (10,222% ROI)           |
| [CLAUDE.md](../CLAUDE.md)                                     | Architecture + contributing guidelines                 |
| [CHANGELOG.md](../CHANGELOG.md)                               | Version history (v1.0.0 - v3.0.4)                      |
| [SECURITY.md](../SECURITY.md)                                 | Vulnerability reporting policy                         |
