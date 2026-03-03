# v3.0.0 Design — Platform (daggr-inspired)

> **Date**: 2026-03-03
> **Status**: Approved
> **Issues**: #51, #52, #53, #54, #55
> **Theme**: Transform from tool collection to platform with DAG orchestration, data persistence, and visual dashboard
> **Regulatory Driver**: EU CRA full SBOM requirement Dec 11, 2027

## Decisions

| Decision          | Choice                                                        | Rationale                                                    |
| ----------------- | ------------------------------------------------------------- | ------------------------------------------------------------ |
| Scope             | All 5 features in v3.0.0                                      | Complete platform transformation in one release              |
| Storage           | SQLite via python3 sqlite3                                    | Zero new dependency, query-capable, built into every Python3 |
| DAG format        | YAML primary + JSON generated                                 | Familiar to DevOps, machine-readable for execution           |
| Dashboard         | Alpine.js + Chart.js CDN                                      | No build step, single HTML file, open-in-browser             |
| K8s scanning      | Static manifests + Live cluster                               | Maximum coverage with In-the-Loop safety gate                |
| GraphQL scanning  | Semgrep rules + Nuclei templates                              | Reuses existing infrastructure                               |
| Pipeline executor | Extend run-pipeline.sh pattern                                | Built on v2.6.0 concurrency group foundation                 |
| Build order       | SQLite → DAG + K8s + GraphQL (parallel) → Dashboard → Release | Respects data dependency chain                               |

## Phase A: SQLite Historical Database (#51)

### Schema

```sql
CREATE TABLE scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT UNIQUE NOT NULL,
    target      TEXT NOT NULL,
    tools       TEXT NOT NULL,         -- JSON array: ["semgrep","grype"]
    pipeline    TEXT,                  -- pipeline name if DAG-executed
    config      TEXT,                  -- JSON: full scan config for replay
    started_at  TEXT NOT NULL,         -- ISO 8601
    finished_at TEXT,
    status      TEXT DEFAULT 'running' -- running|completed|failed
);

CREATE TABLE findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id),
    fingerprint  TEXT NOT NULL,        -- rule_id:file:line_start (dedup key)
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    file         TEXT,
    line_start   INTEGER,
    source_tool  TEXT NOT NULL,
    cwe          TEXT,
    owasp        TEXT,                 -- JSON array
    raw_finding  TEXT,                 -- full JSON for drill-down
    first_seen   TEXT NOT NULL,        -- ISO 8601
    last_seen    TEXT NOT NULL,
    fixed_at     TEXT,                 -- set when finding disappears
    triage       TEXT DEFAULT 'open'   -- open|suppressed|fixed|false_positive
);

CREATE TABLE compliance_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
    framework   TEXT NOT NULL,         -- owasp|nist|soc2|iso27001|...
    coverage    REAL,                  -- 0.0-1.0
    details     TEXT,                  -- JSON
    captured_at TEXT NOT NULL
);
```

### API (`scripts/scan-db.sh`)

```bash
scan-db.sh init                          # Create DB + tables
scan-db.sh store <normalized.json>       # Import findings from scan
scan-db.sh query --severity critical     # Query findings
scan-db.sh trend --days 30              # Findings over time
scan-db.sh lifecycle --fingerprint X    # first_seen -> last_seen -> fixed_at
scan-db.sh export --format json         # Full DB export
scan-db.sh replay --scan-id UUID        # Re-execute scan with stored config
```

### Finding Lifecycle

- New finding: `first_seen = now`, `last_seen = now`
- Same finding in next scan: `last_seen = updated`
- Finding absent in next scan: `fixed_at = now`, `triage = 'fixed'`
- Fingerprint = `rule_id:file:line_start` (same composite key as MCP compare)

### MCP Integration

New tool: `devsecops_history` — query historical data, trend analysis, finding lifecycle

DB location: `$SCAN_DATA_DIR/devsecops.db` (default: `./output/devsecops.db`)

## Phase B: DAG Pipeline Orchestration (#52)

### Pipeline Definition (YAML)

```yaml
# runner/pipelines/default.yml
name: full-scan
version: "1.0"
description: "Full security scan pipeline"

nodes:
  semgrep:
    type: scanner
    tool: semgrep
    inputs: { target: "$SCAN_TARGET" }
    outputs: { findings: "semgrep-raw.json" }
    concurrency_group: light

  grype:
    type: scanner
    tool: grype
    inputs: { target: "$SCAN_TARGET" }
    outputs: { findings: "grype-raw.json" }
    concurrency_group: light

  zap:
    type: scanner
    tool: zap
    inputs: { target: "$DAST_TARGET", mode: "baseline" }
    outputs: { findings: "zap-raw.json" }
    concurrency_group: heavy

  normalize:
    type: normalizer
    depends_on: [semgrep, grype, zap]
    inputs: { findings: "$DEPS_OUTPUTS" }
    outputs: { normalized: "all-normalized.json" }

  dedup:
    type: deduplicator
    depends_on: [normalize]
    inputs: { findings: "all-normalized.json" }
    outputs: { deduplicated: "deduped.json" }

  gate:
    type: gate
    depends_on: [dedup]
    inputs: { findings: "deduped.json", policy: "severity-policy.json" }
    outputs: { result: "gate-result.json" }

  report:
    type: formatter
    depends_on: [dedup]
    inputs: { findings: "deduped.json", format: "sarif" }
    outputs: { report: "report.sarif" }

  store:
    type: storage
    depends_on: [dedup]
    inputs: { findings: "deduped.json" }
    outputs: { db: "$SCAN_DB" }
```

### Node Types

| Type           | Input               | Output                | Example                    |
| -------------- | ------------------- | --------------------- | -------------------------- |
| `scanner`      | target path/URL     | raw findings JSON     | semgrep, grype, zap, trivy |
| `normalizer`   | raw findings        | normalized findings   | json-normalizer.sh         |
| `deduplicator` | normalized findings | deduplicated findings | dedup-findings.sh          |
| `enricher`     | findings            | enriched findings     | CWE/OWASP tagging          |
| `gate`         | findings + policy   | pass/fail result      | severity gate              |
| `formatter`    | findings + format   | report file           | sarif, markdown, vex       |
| `storage`      | findings            | DB record             | scan-db.sh store           |

### Pipeline Engine (`runner/pipeline-engine.sh`)

```bash
pipeline-engine.sh run pipelines/default.yml       # Execute full pipeline
pipeline-engine.sh run pipelines/default.yml \
  --only semgrep,normalize                          # Run subset of nodes
pipeline-engine.sh rerun --node grype               # Re-execute single node
pipeline-engine.sh validate pipelines/custom.yml    # Check: cycles, types, deps
pipeline-engine.sh to-json pipelines/default.yml    # YAML -> JSON conversion
pipeline-engine.sh list                             # List available pipelines
pipeline-engine.sh status                           # Show last run status per node
```

### Execution Logic

1. **Parse** YAML -> JSON (python3 yaml/json)
2. **Validate** — cycle detection (topological sort), type checking
3. **Resolve** — topological sort -> execution order
4. **Execute** — run nodes respecting `depends_on` + `concurrency_group`
5. **Track** — per-node status in `output/pipeline-state.json`

### Built-in Pipelines

| Pipeline           | Nodes                                               | Use Case         |
| ------------------ | --------------------------------------------------- | ---------------- |
| `default.yml`      | all tools -> normalize -> dedup -> gate -> report   | Full scan        |
| `sast-only.yml`    | semgrep -> normalize -> gate                        | Quick SAST check |
| `secrets-only.yml` | gitleaks + trufflehog -> normalize -> dedup -> gate | Secret scan      |
| `compliance.yml`   | scan -> normalize -> compliance_status -> report    | Compliance audit |

### Relationship to Existing Code

- `run-pipeline.sh` (v2.6.0) -> becomes wrapper calling `pipeline-engine.sh run pipelines/default.yml`
- `concurrency-groups.json` -> reused directly by engine
- `job-dispatcher.sh` -> called by scanner nodes (no change)
- `json-normalizer.sh` -> called by normalizer node (no change)

### MCP Integration

New tool: `devsecops_pipeline` — define, execute, and query custom pipelines

## Phase C: Security Dashboard (#53)

### Architecture

```
scan-db.sh query -> JSON data -> dashboard-generator.sh -> dashboard.html
                                       |
                         templates/dashboard.html (Alpine.js template)
                         + Chart.js CDN (graphs)
                         + pipeline-state.json (DAG visualization)
```

Single HTML file — no server, no build step, open in browser.

### Generator (`formatters/dashboard-generator.sh`)

```bash
dashboard-generator.sh generate                    # Generate from latest scan
dashboard-generator.sh generate --scan-id UUID     # Specific scan
dashboard-generator.sh generate --trend --days 30  # Include trend data
dashboard-generator.sh generate --output report.html
```

Uses python3 to read SQLite + inject JSON data into HTML template.

### Dashboard Panels (6 panels)

| Panel              | Type                              | Data Source                            |
| ------------------ | --------------------------------- | -------------------------------------- |
| Pipeline Flow      | DAG graph (CSS grid + SVG arrows) | pipeline-state.json                    |
| Severity Breakdown | Doughnut chart (Chart.js)         | findings grouped by severity           |
| OWASP Coverage     | Horizontal bar chart              | findings per A01-A10 category          |
| Tool Results       | Table with status badges          | per-tool finding counts + pass/fail    |
| Compliance Heatmap | Grid cells with color intensity   | coverage % per framework (7)           |
| Trend              | Line chart (Chart.js)             | findings over time from SQLite history |

### Interactivity (Alpine.js)

- **Filter bar**: severity, tool, OWASP category, framework
- **Drill-down**: click Pipeline node -> tool findings -> finding detail + remediation
- **Sort**: click column headers on findings table
- **Dark mode**: toggle via CSS variables

### Template Structure

```html
<!-- templates/dashboard.html -->
<html>
  <head>
    <script
      src="https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"
      defer
    ></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <style>
      /* inline CSS with :root variables for dark mode */
    </style>
  </head>
  <body x-data="dashboard()" :class="{ 'dark': dark }">
    <!-- Header, Filter bar, 6 panels in CSS grid, Finding detail modal -->
    <script>
      function dashboard() {
        return {
          dark: false,
          scanData: /*__SCAN_DATA__*/,
          pipelineState: /*__PIPELINE__*/,
          trendData: /*__TREND__*/,
          filters: { severity: 'all', tool: 'all', category: 'all' },
        }
      }
    </script>
  </body>
</html>
```

Generator replaces `/*__SCAN_DATA__*/` placeholders with actual JSON from SQLite.

### Skill Integration

Extend existing `/report` skill with `--format dashboard` flag.

## Phase D: Kubernetes Security Scanning (#54)

### New Skill: `/k8s-scan` (15th skill)

- Triggers: k8s, kubernetes, cluster security, pod security, kube-bench
- Decision Loop: In-the-Loop (live cluster), On-the-Loop (static manifests)
- Allowed tools: Bash, Read, Glob, Grep

### Two Modes

| Mode   | Tool                   | Input                       | Requires                   |
| ------ | ---------------------- | --------------------------- | -------------------------- |
| Static | Trivy fs + Checkov     | YAML manifests, Helm charts | No cluster access          |
| Live   | kube-bench + Trivy k8s | Running cluster             | kubeconfig + user approval |

### Docker Services

```yaml
kube-bench:
  image: aquasec/kube-bench:latest
  profiles: ["kube-bench", "k8s", "all"]
  volumes:
    - ${KUBECONFIG:-~/.kube/config}:/root/.kube/config:ro
    - ./output:/output
  mem_limit: 512m
```

Trivy: add `"k8s"` to existing profiles.

### Job Dispatcher

`run_kube_bench()` with 3 modes: `cis` (full CIS Benchmark), `node` (node-level), `policies` (Pod Security Standards)

### Normalizer

kube-bench JSON -> Unified Finding Schema:

- `test_number` -> `rule_id` (e.g., `kube-bench-1.1.1`)
- `status` -> `severity` (FAIL=high, WARN=medium, INFO=low)
- `remediation` -> `suggestion`

### Custom Semgrep Rules (~8 rules)

`rules/k8s-manifest-rules.yml`:

| Rule ID                    | Pattern                                  | Severity |
| -------------------------- | ---------------------------------------- | -------- |
| `k8s-privileged-container` | `privileged: true`                       | high     |
| `k8s-run-as-root`          | `runAsUser: 0` or missing `runAsNonRoot` | high     |
| `k8s-host-network`         | `hostNetwork: true`                      | high     |
| `k8s-no-resource-limits`   | missing `resources.limits`               | medium   |
| `k8s-latest-tag`           | image with `:latest` or no tag           | medium   |
| `k8s-no-readiness-probe`   | missing `readinessProbe`                 | low      |
| `k8s-wildcard-rbac`        | `verbs: ["*"]` in Role/ClusterRole       | high     |
| `k8s-default-namespace`    | `namespace: default` in production       | medium   |

### Reference File

`skills/references/k8s-security-reference.md`: CIS Benchmark v1.9, Pod Security Standards, RBAC misconfigs, Network Policy patterns, common K8s CVEs.

### Safety Controls

- Live mode: interactive prompt, In-the-Loop approval required
- Read-only: kube-bench + Trivy only read cluster state
- kubeconfig mounted `:ro`

## Phase E: GraphQL Security Scanning (#55)

### New Skill: `/graphql-scan` (16th skill)

- Triggers: graphql, gql, introspection, query depth, batch query
- Decision Loop: On-the-Loop (static), In-the-Loop (live endpoint)
- Allowed tools: Bash, Read, Glob, Grep

### Two Modes

| Mode   | Approach                | Input                           |
| ------ | ----------------------- | ------------------------------- |
| Static | Semgrep custom rules    | Source code (resolvers, schema) |
| Live   | Nuclei templates + curl | GraphQL endpoint URL            |

### Custom Semgrep Rules (~8 rules)

`rules/graphql-rules.yml`:

| Rule ID                     | CWE     | Pattern                                  | Severity |
| --------------------------- | ------- | ---------------------------------------- | -------- |
| `gql-introspection-enabled` | CWE-200 | Introspection not disabled in production | medium   |
| `gql-no-depth-limit`        | CWE-400 | Missing depthLimit/maxDepth              | high     |
| `gql-no-cost-limit`         | CWE-400 | Missing query cost analysis              | medium   |
| `gql-batch-no-limit`        | CWE-770 | Batch operations without limit           | high     |
| `gql-resolver-no-auth`      | CWE-862 | Resolver without auth check              | high     |
| `gql-sql-in-resolver`       | CWE-89  | Raw SQL in resolver                      | critical |
| `gql-verbose-errors`        | CWE-209 | Error exposing internals                 | medium   |
| `gql-no-rate-limit`         | CWE-770 | Endpoint without rate limiting           | medium   |

### Live Scan (Nuclei templates)

`runner/nuclei-templates/graphql/`:

- `graphql-introspection.yaml` — detect open introspection
- `graphql-field-suggestion.yaml` — schema leak via field suggestions
- `graphql-batch-query.yaml` — unlimited batch detection
- `graphql-depth-attack.yaml` — depth limit check

### Job Dispatcher

`run_graphql_scan()` with 3 modes: `static` (Semgrep), `live` (Nuclei + curl), `both`

### Reference File

`skills/references/graphql-security-reference.md`: OWASP GraphQL Cheat Sheet, attack patterns, framework-specific guidance (Apollo, graphql-yoga, Strawberry, graphql-java).

### Safety Controls

- Live mode: requires `GRAPHQL_TARGET` env var (same pattern as `DAST_TARGET`)

## Expected Metrics

| Metric                | v2.8.0 | v3.0.0 Target                   |
| --------------------- | ------ | ------------------------------- |
| Custom Semgrep rules  | 68     | ~84 (+8 K8s, +8 GraphQL)        |
| OWASP coverage        | 10/10  | 10/10                           |
| Security tools        | 9      | 10 (+kube-bench)                |
| Compliance frameworks | 7      | 7                               |
| Output formats        | 7      | 8 (+Dashboard HTML)             |
| Skills                | 14     | 16 (+/k8s-scan, +/graphql-scan) |
| Reference files       | 17     | 19 (+k8s, +graphql)             |
| MCP tools             | 8      | 10 (+history, +pipeline)        |
| Test suites           | 37     | ~42                             |
| Total tests           | 1,174  | ~1,400+                         |

## Files Summary

| Action | Files                                                                                                                         |
| ------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Create | `scripts/scan-db.sh`                                                                                                          |
| Create | `runner/pipeline-engine.sh`, `runner/pipelines/{default,sast-only,secrets-only,compliance}.yml`                               |
| Create | `formatters/dashboard-generator.sh`, `templates/dashboard.html`                                                               |
| Create | `skills/k8s-scan/SKILL.md`, `skills/references/k8s-security-reference.md`                                                     |
| Create | `skills/graphql-scan/SKILL.md`, `skills/references/graphql-security-reference.md`                                             |
| Create | `rules/k8s-manifest-rules.yml`, `rules/graphql-rules.yml`                                                                     |
| Create | `runner/nuclei-templates/graphql/*.yaml` (4 templates)                                                                        |
| Create | `tests/test-scan-db.sh`, `test-pipeline-engine.sh`, `test-dashboard-generator.sh`, `test-k8s-scan.sh`, `test-graphql-scan.sh` |
| Create | `tests/fixtures/sample-kube-bench.json`, `sample-graphql-findings.json`, `sample-pipeline.yml`                                |
| Modify | `runner/docker-compose.yml` (+kube-bench service, trivy k8s profile)                                                          |
| Modify | `runner/job-dispatcher.sh` (+run_kube_bench, +run_graphql_scan)                                                               |
| Modify | `formatters/json-normalizer.sh` (+kube-bench case, 10 tools)                                                                  |
| Modify | `mcp/server.mjs` (+devsecops_history, +devsecops_pipeline)                                                                    |
| Modify | `mappings/cwe-to-owasp.json` (+CWE-400, +CWE-770 if missing)                                                                  |
| Modify | `CHANGELOG.md`, `README.md`, `docs/PRD.md`, `CLAUDE.md`                                                                       |
| Modify | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`                                                               |
| Modify | `tests/validate-plugin.sh` (16 skills, 19 refs)                                                                               |
