---
name: graphql-scan
description: GraphQL API security scanning and vulnerability assessment. Performs static analysis on resolvers/schema and live scanning on GraphQL endpoints to detect introspection abuse, depth bombing, batch DoS, missing authorization, and injection vulnerabilities.
argument-hint: "[--target <path|url>] [--mode static|live|both]"
user-invocable: true
allowed-tools: ["Bash", "Read", "Glob", "Grep", "Agent"]
---

# GraphQL Security Scanning

Scan GraphQL APIs for security vulnerabilities using static code analysis (Semgrep custom rules on resolvers and schema definitions) and live endpoint scanning (Nuclei templates and curl-based probes).

**Decision Loop**: In-the-Loop for live API scanning (requires user approval before sending requests to endpoints), On-the-Loop for static code scanning (AI proposes findings, human reviews)

## Agent Delegation

This skill delegates to `@agent-dast-specialist` for live endpoint scanning and `@agent-sast-specialist` for static code analysis of resolvers.

## Reference

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/graphql-security-reference.md` for OWASP GraphQL Cheat Sheet, attack patterns, framework-specific guidance, and defense patterns.

## Scan Workflow

### 1. Project Discovery

Detect GraphQL usage and determine scan mode:

```bash
# GraphQL schema files
Glob: **/*.graphql, **/*.gql, **/schema.graphql, **/schema.gql

# Framework-specific configuration
Grep: "ApolloServer", "graphql-yoga", "makeExecutableSchema" in **/*.{js,ts,jsx,tsx}
Grep: "strawberry.Schema", "graphene.Schema", "ariadne" in **/*.py
Grep: "GraphQLSchema", "SchemaParser" in **/*.java
Grep: "type Query", "type Mutation", "type Subscription" in **/*.graphql

# Resolver files
Glob: **/resolvers/**/*.{js,ts,py,java}, **/graphql/**/*.{js,ts,py,java}
Grep: "resolver", "Query:", "Mutation:", "fieldResolver" in source files

# GraphQL endpoint configuration
Grep: "/graphql", "graphqlHTTP", "graphql_view", "GraphQLModule" in source files

# Security configuration (depth limit, cost analysis)
Grep: "depthLimit", "maxDepth", "costAnalysis", "queryComplexity", "validationRules" in source files

# Environment / config for live endpoint
Grep: "GRAPHQL_TARGET", "GRAPHQL_ENDPOINT", "graphql" in .env*, docker-compose*.yml
```

### 2. Static Analysis (Semgrep Custom Rules)

Run Semgrep with GraphQL-specific rules on resolver source code:

```bash
# Run custom GraphQL security rules
docker run --rm -v "${SCAN_TARGET}:/src" returntocorp/semgrep:latest \
  semgrep --config /src/rules/graphql-rules.yml \
  --json --output /src/output/graphql-semgrep.json /src

# Key rules checked:
# gql-introspection-enabled  (CWE-200) — Introspection not disabled in production
# gql-no-depth-limit         (CWE-400) — Missing depthLimit/maxDepth config
# gql-no-cost-limit          (CWE-400) — Missing query cost analysis
# gql-batch-no-limit         (CWE-770) — Batch operations without limit
# gql-resolver-no-auth       (CWE-862) — Resolver without authentication check
# gql-sql-in-resolver        (CWE-89)  — Raw SQL in resolver function
# gql-verbose-errors         (CWE-209) — Error messages exposing internals
# gql-no-rate-limit          (CWE-770) — Endpoint without rate limiting
```

### 3. Live Endpoint Scanning (Nuclei + curl)

**Requires user approval** — In-the-Loop safety gate before sending any requests.

```bash
# Prerequisite: GRAPHQL_TARGET must be set
if [ -z "$GRAPHQL_TARGET" ]; then
  echo "ERROR: Set GRAPHQL_TARGET env var for live scanning"
  exit 1
fi

# 3a. Introspection probe
curl -s -X POST "$GRAPHQL_TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' \
  -o output/introspection-check.json

# 3b. Depth attack probe (nested query)
curl -s -X POST "$GRAPHQL_TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a: __typename @repeat(count: 50) }"}' \
  -o output/depth-check.json

# 3c. Batch query probe
curl -s -X POST "$GRAPHQL_TARGET" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]' \
  -o output/batch-check.json

# 3d. Field suggestion probe (schema leak)
curl -s -X POST "$GRAPHQL_TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typ }"}' \
  -o output/suggestion-check.json

# 3e. Nuclei templates for comprehensive scanning
docker run --rm -v "$(pwd)/runner/nuclei-templates:/templates" \
  -v "$(pwd)/output:/output" \
  projectdiscovery/nuclei:latest \
  -u "$GRAPHQL_TARGET" \
  -t /templates/graphql/ \
  -sarif-output /output/graphql-nuclei.sarif \
  -rate-limit 10
```

### 4. Results Normalization

Normalize findings from both static and live scans into the unified finding schema:

```bash
# Normalize Semgrep GraphQL findings
runner/json-normalizer.sh output/graphql-semgrep.json semgrep > output/graphql-static-normalized.json

# Normalize Nuclei findings (if live scan performed)
runner/json-normalizer.sh output/graphql-nuclei.sarif nuclei > output/graphql-live-normalized.json

# Merge and deduplicate
runner/dedup-findings.sh output/graphql-*-normalized.json > output/graphql-deduped.json
```

### 5. Output

Present findings using the bilingual template:

```markdown
## ผลการสแกน GraphQL (GraphQL Security Scan Results)

### สรุป (Summary)

- **Target**: <path or endpoint URL>
- **Scan mode**: Static / Live / Both
- **Total findings**: N (Critical: X, High: Y, Medium: Z, Low: W)
- **Introspection status**: Enabled / Disabled
- **Depth limit**: Configured (max: N) / Not configured
- **Cost analysis**: Enabled / Not enabled
- **Batch query limit**: Configured (max: N) / Not configured

### ผลการสแกน Static (Static Analysis Findings)

| Rule ID | Severity | File | Line | Description | CWE |
| ------- | -------- | ---- | ---- | ----------- | --- |
| ...     | ...      | ...  | ...  | ...         | ... |

### ผลการสแกน Live (Live Endpoint Findings)

| Check                 | Result    | Details                | Severity |
| --------------------- | --------- | ---------------------- | -------- |
| Introspection enabled | PASS/FAIL | <schema types exposed> | medium   |
| Depth limit bypass    | PASS/FAIL | <max depth reached>    | high     |
| Batch query unlimited | PASS/FAIL | <batch size accepted>  | high     |
| Field suggestion leak | PASS/FAIL | <suggestions returned> | low      |

### การป้องกันที่แนะนำ (Recommended Defenses)

1. **Disable introspection in production** — framework-specific guidance
2. **Configure depth limiting** — max depth 10-15 for typical APIs
3. **Enable query cost analysis** — prevent resource-intensive queries
4. **Limit batch operations** — max 10-20 operations per request
5. **Add resolver-level authorization** — check permissions per field
6. **Implement rate limiting** — per-client query rate enforcement

### การจับคู่ OWASP / CWE (OWASP / CWE Mapping)

| Finding               | CWE     | OWASP 2021 | OWASP API 2023 |
| --------------------- | ------- | ---------- | -------------- |
| Introspection abuse   | CWE-200 | A01        | API3           |
| Depth bombing         | CWE-400 | A05        | API4           |
| Missing authorization | CWE-862 | A01        | API1           |
| SQL in resolver       | CWE-89  | A03        | API8           |
```

## Safety Controls

- **Live mode**: requires `GRAPHQL_TARGET` environment variable (same pattern as `DAST_TARGET`)
- **Live mode**: In-the-Loop — always prompt user for approval before sending requests to endpoints
- **Static mode**: On-the-Loop — safe to run without approval (read-only file analysis)
- **Rate limiting**: Nuclei capped at 10 requests/second to avoid overloading target

## Regulatory Notes

OWASP API Security Top 10 (2023) directly covers GraphQL attack patterns:

- **API1**: Broken Object Level Authorization — resolver-level authz bypass
- **API3**: Broken Object Property Level Authorization — field-level access
- **API4**: Unrestricted Resource Consumption — depth bombing, batch DoS
- **API8**: Security Misconfiguration — introspection in production

Thailand NCSA (effective **Sep 16, 2026**) requires API security assessment for critical infrastructure.
EU CRA (effective **Sep 11, 2026**) requires vulnerability handling for all digital product APIs.

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/graphql-security-reference.md` for OWASP GraphQL Cheat Sheet, attack patterns, and framework-specific remediation.
Load `${CLAUDE_PLUGIN_ROOT}/skills/references/dast-methodology.md` for general DAST scanning context and Nuclei template integration.
