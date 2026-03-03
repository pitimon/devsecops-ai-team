# v3.0.0 Platform Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform devsecops-ai-team from a tool collection into a platform with DAG orchestration, SQLite persistence, Alpine.js dashboard, K8s scanning, and GraphQL scanning.

**Architecture:** SQLite database stores all scan results with provenance tracking. DAG pipeline engine (YAML→JSON→topological sort→execute) replaces linear run-pipeline.sh. Alpine.js + Chart.js dashboard generates self-contained HTML from SQLite data. K8s and GraphQL add 2 new skills with static + live scanning modes.

**Tech Stack:** bash, python3 (sqlite3, json, yaml), Alpine.js 3, Chart.js 4, Docker, Semgrep, Nuclei, kube-bench

**Design Doc:** `docs/plans/2026-03-03-v300-platform-design.md`

---

## Phase Dependency Graph

```
Phase A: SQLite Database ──────────────────────────┐
Phase B: DAG Pipeline ────────────── (parallel) ───┤──→ Phase F: Dashboard
Phase C: K8s Scanning ────────────── (parallel) ───┤
Phase D: GraphQL Scanning ────────── (parallel) ───┘
Phase E: MCP Integration (after A+B)
Phase G: Release (after all)
```

## Reference: Existing Patterns

- **Rule YAML**: follow `rules/a06-component-rules.yml` pattern (dual OWASP tags, CWE, pattern-regex for generic)
- **Test suite**: follow `tests/test-a06-rules.sh` pattern (pass/fail helpers, sections, summary)
- **Normalizer**: follow `trufflehog)` case in `formatters/json-normalizer.sh` (python3 inline, unified finding schema)
- **Job dispatcher**: follow `run_trufflehog()` in `runner/job-dispatcher.sh` (mode case, timeout, docker exec/run)
- **Docker compose**: follow trufflehog service in `runner/docker-compose.yml` (profiles, mem_limit, volumes)
- **SKILL.md**: follow `skills/slsa-assess/SKILL.md` pattern (YAML frontmatter, triggers, allowed-tools)
- **MCP tool**: follow `devsecops_compliance_status` in `mcp/server.mjs` (TOOLS entry, Zod schema, handler, switch case)
- **Fixture JSON**: follow `tests/fixtures/sample-a06-findings.json` (unified finding schema, 3 findings)

---

## Phase A: SQLite Historical Database (#51)

### Task A1: Create scan-db.sh with init command

**Files:**

- Create: `scripts/scan-db.sh`

**Context:** First runtime dependency in the project. Uses `python3 -c "import sqlite3"` which is available everywhere. DB path defaults to `./output/devsecops.db`.

**Step 1: Create `scripts/scan-db.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Scan Database Manager
# SQLite-based historical scan storage with provenance tracking

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="${SCAN_DB:-$ROOT_DIR/output/devsecops.db}"

usage() {
  cat <<EOF
Usage: scan-db.sh <command> [options]

Commands:
  init                          Create database and tables
  store <normalized.json>       Import findings from a scan
  query [--severity S] [--tool T] [--cwe C]  Query findings
  trend [--days N]              Findings over time (default: 30)
  lifecycle --fingerprint FP    Show finding lifecycle
  export [--format json|csv]    Export database
  stats                         Summary statistics

Options:
  --db <path>                   Database path (default: output/devsecops.db)
EOF
  exit 1
}

# Parse --db flag from any position
for arg in "$@"; do
  if [ "$prev_arg" = "--db" ]; then
    DB_PATH="$arg"
  fi
  prev_arg="$arg"
done

ensure_db_dir() {
  local db_dir
  db_dir="$(dirname "$DB_PATH")"
  [ -d "$db_dir" ] || mkdir -p "$db_dir"
}

cmd_init() {
  ensure_db_dir
  python3 -c "
import sqlite3, sys

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT UNIQUE NOT NULL,
    target      TEXT NOT NULL,
    tools       TEXT NOT NULL,
    pipeline    TEXT,
    config      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT DEFAULT 'running'
)''')

c.execute('''CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL REFERENCES scans(scan_id),
    fingerprint  TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    file         TEXT,
    line_start   INTEGER,
    source_tool  TEXT NOT NULL,
    cwe          TEXT,
    owasp        TEXT,
    raw_finding  TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    fixed_at     TEXT,
    triage       TEXT DEFAULT 'open'
)''')

c.execute('''CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id),
    framework   TEXT NOT NULL,
    coverage    REAL,
    details     TEXT,
    captured_at TEXT NOT NULL
)''')

c.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
c.execute('CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(source_tool)')

db.commit()
db.close()
print('[scan-db] Database initialized: $DB_PATH')
"
}

cmd_store() {
  local input_file="$1"
  [ -f "$input_file" ] || { echo "[scan-db] ERROR: File not found: $input_file"; exit 1; }

  python3 -c "
import json, sqlite3, uuid, sys
from datetime import datetime

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

with open('$input_file') as f:
    data = json.load(f)

findings = data.get('findings', [])
if not findings:
    print('[scan-db] No findings to store')
    sys.exit(0)

scan_id = str(uuid.uuid4())[:8]
now = datetime.utcnow().isoformat() + 'Z'
tools = list(set(f.get('source_tool', 'unknown') for f in findings))

c.execute('''INSERT INTO scans (scan_id, target, tools, started_at, finished_at, status)
             VALUES (?, ?, ?, ?, ?, ?)''',
          (scan_id, '$input_file', json.dumps(tools), now, now, 'completed'))

stored = 0
updated = 0
for f in findings:
    fp = f'{f.get(\"rule_id\",\"\")}:{f.get(\"location\",{}).get(\"file\",\"\")}:{f.get(\"location\",{}).get(\"line_start\",0)}'

    # Check if finding already exists (by fingerprint)
    c.execute('SELECT id, last_seen FROM findings WHERE fingerprint = ? AND fixed_at IS NULL', (fp,))
    existing = c.fetchone()

    if existing:
        # Update last_seen
        c.execute('UPDATE findings SET last_seen = ?, scan_id = ? WHERE id = ?', (now, scan_id, existing[0]))
        updated += 1
    else:
        # New finding
        loc = f.get('location', {})
        owasp = json.dumps(f.get('owasp', [])) if f.get('owasp') else None
        c.execute('''INSERT INTO findings
                     (scan_id, fingerprint, rule_id, severity, file, line_start, source_tool, cwe, owasp, raw_finding, first_seen, last_seen)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (scan_id, fp, f.get('rule_id',''), f.get('severity',''),
                   loc.get('file',''), loc.get('line_start',0),
                   f.get('source_tool',''), f.get('cwe_id'), owasp,
                   json.dumps(f), now, now))
        stored += 1

# Mark findings not in this scan as fixed
all_fps = set()
for f in findings:
    fp = f'{f.get(\"rule_id\",\"\")}:{f.get(\"location\",{}).get(\"file\",\"\")}:{f.get(\"location\",{}).get(\"line_start\",0)}'
    all_fps.add(fp)

c.execute('SELECT id, fingerprint FROM findings WHERE fixed_at IS NULL AND scan_id != ?', (scan_id,))
for row in c.fetchall():
    if row[1] not in all_fps:
        c.execute('UPDATE findings SET fixed_at = ?, triage = ? WHERE id = ?', (now, 'fixed', row[0]))

db.commit()
db.close()
print(f'[scan-db] Stored: scan={scan_id}, new={stored}, updated={updated}, tools={\",\".join(tools)}')
"
}

cmd_query() {
  local severity="" tool="" cwe="" limit="50"
  while [ $# -gt 0 ]; do
    case "$1" in
      --severity) severity="$2"; shift 2 ;;
      --tool) tool="$2"; shift 2 ;;
      --cwe) cwe="$2"; shift 2 ;;
      --limit) limit="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

where = ['fixed_at IS NULL']
params = []
if '$severity':
    where.append('severity = ?')
    params.append('$severity'.upper())
if '$tool':
    where.append('source_tool = ?')
    params.append('$tool')
if '$cwe':
    where.append('cwe = ?')
    params.append('$cwe')

sql = f'SELECT rule_id, severity, file, line_start, source_tool, cwe, first_seen, last_seen, triage FROM findings WHERE {\" AND \".join(where)} ORDER BY severity, rule_id LIMIT $limit'
rows = c.execute(sql, params).fetchall()

results = []
for r in rows:
    results.append({
        'rule_id': r[0], 'severity': r[1], 'file': r[2], 'line_start': r[3],
        'source_tool': r[4], 'cwe': r[5], 'first_seen': r[6], 'last_seen': r[7], 'triage': r[8]
    })

db.close()
print(json.dumps({'count': len(results), 'findings': results}, indent=2))
"
}

cmd_trend() {
  local days="${1:-30}"
  python3 -c "
import sqlite3, json
from datetime import datetime, timedelta

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

end = datetime.utcnow()
start = end - timedelta(days=$days)

rows = c.execute('''
    SELECT date(first_seen) as day, severity, COUNT(*) as cnt
    FROM findings
    WHERE first_seen >= ?
    GROUP BY day, severity
    ORDER BY day
''', (start.isoformat(),)).fetchall()

trend = {}
for day, sev, cnt in rows:
    if day not in trend:
        trend[day] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    trend[day][sev.lower()] = cnt

db.close()
print(json.dumps({'days': $days, 'trend': trend}, indent=2))
"
}

cmd_lifecycle() {
  local fingerprint="$1"
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

rows = c.execute('''
    SELECT scan_id, first_seen, last_seen, fixed_at, triage, severity, rule_id
    FROM findings WHERE fingerprint = ?
    ORDER BY first_seen
''', ('$fingerprint',)).fetchall()

history = []
for r in rows:
    history.append({
        'scan_id': r[0], 'first_seen': r[1], 'last_seen': r[2],
        'fixed_at': r[3], 'triage': r[4], 'severity': r[5], 'rule_id': r[6]
    })

db.close()
print(json.dumps({'fingerprint': '$fingerprint', 'history': history}, indent=2))
"
}

cmd_export() {
  local format="${1:-json}"
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

scans = [dict(zip(['scan_id','target','tools','pipeline','started_at','finished_at','status'], r))
         for r in c.execute('SELECT scan_id,target,tools,pipeline,started_at,finished_at,status FROM scans').fetchall()]
findings = [dict(zip(['fingerprint','rule_id','severity','file','line_start','source_tool','cwe','first_seen','last_seen','fixed_at','triage'], r))
            for r in c.execute('SELECT fingerprint,rule_id,severity,file,line_start,source_tool,cwe,first_seen,last_seen,fixed_at,triage FROM findings').fetchall()]

db.close()
print(json.dumps({'scans': scans, 'findings': findings}, indent=2))
"
}

cmd_stats() {
  python3 -c "
import sqlite3, json

db = sqlite3.connect('$DB_PATH')
c = db.cursor()

scan_count = c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
finding_count = c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
open_count = c.execute('SELECT COUNT(*) FROM findings WHERE fixed_at IS NULL').fetchone()[0]
fixed_count = c.execute('SELECT COUNT(*) FROM findings WHERE fixed_at IS NOT NULL').fetchone()[0]

by_severity = {}
for sev, cnt in c.execute('SELECT severity, COUNT(*) FROM findings WHERE fixed_at IS NULL GROUP BY severity').fetchall():
    by_severity[sev.lower()] = cnt

by_tool = {}
for tool, cnt in c.execute('SELECT source_tool, COUNT(*) FROM findings WHERE fixed_at IS NULL GROUP BY source_tool').fetchall():
    by_tool[tool] = cnt

db.close()
print(json.dumps({
    'scans': scan_count, 'total_findings': finding_count,
    'open': open_count, 'fixed': fixed_count,
    'by_severity': by_severity, 'by_tool': by_tool
}, indent=2))
"
}

# ─── Main ───
[ $# -lt 1 ] && usage

CMD="$1"; shift
case "$CMD" in
  init)      cmd_init ;;
  store)     cmd_store "$@" ;;
  query)     cmd_query "$@" ;;
  trend)     cmd_trend "$@" ;;
  lifecycle) cmd_lifecycle "$@" ;;
  export)    cmd_export "$@" ;;
  stats)     cmd_stats ;;
  *)         usage ;;
esac
```

**Step 2: Make executable and verify**

Run: `chmod +x scripts/scan-db.sh && bash scripts/scan-db.sh init`
Expected: `[scan-db] Database initialized: .../output/devsecops.db`

**Step 3: Commit**

```bash
git add scripts/scan-db.sh
git commit -m "feat: add scan-db.sh — SQLite historical scan database"
```

### Task A2: Create scan-db test suite

**Files:**

- Create: `tests/test-scan-db.sh`

**Context:** Follow `test-pdpa-mapping.sh` pattern (pass/fail helpers, sections, summary). Test init, store, query, trend, lifecycle, export, stats. Use `tests/fixtures/sample-a06-findings.json` as test input for store.

**Sections:**

1. Script structure (exists, executable, usage) — 3 tests
2. Init command (creates DB, tables exist, indexes) — 4 tests
3. Store command (import fixture, finding count, dedup on re-import) — 5 tests
4. Query command (all, by severity, by tool) — 4 tests
5. Trend command (returns JSON, has trend key) — 3 tests
6. Lifecycle command (fingerprint lookup) — 2 tests
7. Export command (JSON output, has scans + findings) — 3 tests
8. Stats command (counts match) — 2 tests

Target: ~26 tests

Run: `bash tests/test-scan-db.sh`
Expected: `26/26 passed`

**Step 1: Create the test file with all sections**

**Step 2: Run and verify all pass**

**Step 3: Commit**

```bash
git add tests/test-scan-db.sh
git commit -m "test: add scan-db.sh test suite (26 tests)"
```

### Task A3: Add scan-db.sh to output/.gitignore

**Files:**

- Create: `output/.gitignore`

**Step 1: Create `output/.gitignore`**

```
# SQLite database (runtime data, not committed)
*.db
*.db-journal
*.db-wal
```

**Step 2: Commit**

```bash
git add output/.gitignore
git commit -m "chore: add output/.gitignore for SQLite database files"
```

---

## Phase B: DAG Pipeline Orchestration (#52)

### Task B1: Create pipeline YAML definitions

**Files:**

- Create: `runner/pipelines/default.yml`
- Create: `runner/pipelines/sast-only.yml`
- Create: `runner/pipelines/secrets-only.yml`
- Create: `runner/pipelines/compliance.yml`

**Context:** YAML format as defined in design doc. Each pipeline defines `name`, `version`, `description`, and `nodes` map. Each node has `type`, optional `tool`, `depends_on`, `inputs`, `outputs`, `concurrency_group`.

**Step 1: Create all 4 pipeline files** per the design doc Section B.

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('runner/pipelines/default.yml'))"`
Expected: No error

**Step 3: Commit**

```bash
git add runner/pipelines/
git commit -m "feat: add 4 built-in DAG pipeline definitions"
```

### Task B2: Create pipeline-engine.sh

**Files:**

- Create: `runner/pipeline-engine.sh`

**Context:** Core engine with subcommands: `run`, `validate`, `rerun`, `to-json`, `list`, `status`. Uses python3 for YAML parsing, topological sort, cycle detection. Calls `job-dispatcher.sh` for scanner nodes, `json-normalizer.sh` for normalizer, `dedup-findings.sh` for dedup, formatters for output. Tracks state in `output/pipeline-state.json`.

**Key implementation details:**

- `run` — parse YAML, validate, topological sort, execute nodes by concurrency group
- `validate` — cycle detection, dependency resolution, type checking
- `rerun --node X` — load state, re-execute single node with cached inputs
- `to-json` — python3 yaml→json conversion
- `status` — read `output/pipeline-state.json`
- Node execution: each node type maps to existing script (scanner→job-dispatcher.sh, normalizer→json-normalizer.sh, etc.)
- State tracking: `output/pipeline-state.json` with `{ nodes: { name: { status, started_at, finished_at, exit_code } } }`

**Step 1: Create `runner/pipeline-engine.sh`** with all subcommands

**Step 2: Make executable, validate default pipeline**

Run: `chmod +x runner/pipeline-engine.sh && bash runner/pipeline-engine.sh validate runner/pipelines/default.yml`
Expected: `[pipeline] Pipeline 'full-scan' is valid (8 nodes, 0 cycles)`

**Step 3: Commit**

```bash
git add runner/pipeline-engine.sh
git commit -m "feat: add DAG pipeline engine with topological sort execution"
```

### Task B3: Create pipeline engine test suite

**Files:**

- Create: `tests/test-pipeline-engine.sh`
- Create: `tests/fixtures/sample-pipeline.yml`
- Create: `tests/fixtures/sample-pipeline-cycle.yml`

**Sections:**

1. Script structure (exists, executable, subcommands) — 4 tests
2. Pipeline parsing (YAML valid, nodes extracted) — 3 tests
3. Validation (valid pipeline passes, cycle detected, missing dep detected) — 4 tests
4. Topological sort (correct execution order) — 3 tests
5. YAML-to-JSON conversion — 2 tests
6. State tracking (pipeline-state.json written) — 3 tests
7. Pipeline listing — 2 tests
8. Built-in pipelines (all 4 validate) — 4 tests

Target: ~25 tests

**Step 1: Create fixture pipeline files (valid + cyclic)**

**Step 2: Create test suite**

**Step 3: Run and verify**

Run: `bash tests/test-pipeline-engine.sh`
Expected: `25/25 passed`

**Step 4: Commit**

```bash
git add tests/test-pipeline-engine.sh tests/fixtures/sample-pipeline.yml tests/fixtures/sample-pipeline-cycle.yml
git commit -m "test: add pipeline engine test suite (25 tests)"
```

### Task B4: Update run-pipeline.sh to wrap pipeline-engine

**Files:**

- Modify: `runner/run-pipeline.sh`

**Context:** Make `run-pipeline.sh` a thin wrapper that calls `pipeline-engine.sh run pipelines/default.yml` when no custom pipeline specified. Keep backward compatibility — existing `--tools` and `--format` flags still work.

**Step 1: Add pipeline-engine delegation at top of run_pipeline logic**

**Step 2: Verify existing behavior unchanged**

Run: `bash runner/run-pipeline.sh --help`

**Step 3: Commit**

```bash
git add runner/run-pipeline.sh
git commit -m "refactor: wrap run-pipeline.sh around pipeline-engine for DAG support"
```

---

## Phase C: Kubernetes Security Scanning (#54)

### Task C1: Create K8s skill and reference file

**Files:**

- Create: `skills/k8s-scan/SKILL.md`
- Create: `skills/references/k8s-security-reference.md`

**Context:** Follow `skills/slsa-assess/SKILL.md` pattern. K8s-scan is the 15th skill. Reference covers CIS Benchmark v1.9, Pod Security Standards (Privileged/Baseline/Restricted), RBAC misconfigs, Network Policy patterns.

**Step 1: Create SKILL.md** with triggers (k8s, kubernetes, cluster security, pod security, kube-bench), allowed-tools (Bash, Read, Glob, Grep), decision loop (In-the-Loop for live, On-the-Loop for static).

**Step 2: Create reference file** (~200 lines) covering CIS categories, PSS levels, RBAC patterns, Network Policy.

**Step 3: Commit**

```bash
git add skills/k8s-scan/ skills/references/k8s-security-reference.md
git commit -m "feat: add /k8s-scan skill and K8s security reference"
```

### Task C2: Create K8s manifest Semgrep rules

**Files:**

- Create: `rules/k8s-manifest-rules.yml`
- Create: `tests/fixtures/sample-kube-bench.json`

**Context:** 8 rules per design doc (k8s-privileged-container, k8s-run-as-root, k8s-host-network, k8s-no-resource-limits, k8s-latest-tag, k8s-no-readiness-probe, k8s-wildcard-rbac, k8s-default-namespace). All use `languages: [generic]` with `pattern-regex` since they target YAML manifests. CWE mappings: CWE-250 (privilege), CWE-269 (permissions), CWE-770 (resource limits).

Also create kube-bench fixture JSON (3 sample results) for normalizer testing.

**Step 1: Create rules file** following `a06-component-rules.yml` pattern

**Step 2: Create kube-bench fixture**

**Step 3: Commit**

```bash
git add rules/k8s-manifest-rules.yml tests/fixtures/sample-kube-bench.json
git commit -m "feat: add 8 K8s manifest Semgrep rules + kube-bench fixture"
```

### Task C3: Add kube-bench to Docker, dispatcher, normalizer

**Files:**

- Modify: `runner/docker-compose.yml` (add kube-bench service)
- Modify: `runner/job-dispatcher.sh` (add `run_kube_bench()` + register in `run_tool()`)
- Modify: `formatters/json-normalizer.sh` (add `kube-bench)` case block)
- Modify: `runner/concurrency-groups.json` (add kube-bench to heavy group)

**Context:** kube-bench is a heavy tool (needs cluster access). Docker image: `aquasec/kube-bench:latest`. Normalizer maps: `test_number`→`rule_id`, `status`→`severity` (FAIL=high, WARN=medium, INFO=low). 10th normalizer tool.

**Step 1: Add kube-bench service to docker-compose.yml**

**Step 2: Add `run_kube_bench()` to job-dispatcher.sh** with 3 modes (cis/node/policies)

**Step 3: Add kube-bench case to json-normalizer.sh**

**Step 4: Add kube-bench to heavy group in concurrency-groups.json**

**Step 5: Commit**

```bash
git add runner/docker-compose.yml runner/job-dispatcher.sh formatters/json-normalizer.sh runner/concurrency-groups.json
git commit -m "feat: add kube-bench Docker, dispatcher, normalizer (10th tool)"
```

### Task C4: Create K8s scan test suite

**Files:**

- Create: `tests/test-k8s-scan.sh`

**Sections:**

1. Skill definition (SKILL.md exists, triggers, decision loop) — 4 tests
2. Reference file (exists, CIS Benchmark, PSS, RBAC) — 4 tests
3. Semgrep rules (file exists, 8 rules, key rule IDs) — 4 tests
4. Docker compose (kube-bench service, profile, image) — 3 tests
5. Job dispatcher (run_kube_bench function, modes, run_tool case) — 4 tests
6. Normalizer (kube-bench case exists, fixture produces output, 3 findings) — 4 tests

Target: ~23 tests

**Step 1: Create test file**

**Step 2: Run and verify**

Run: `bash tests/test-k8s-scan.sh`

**Step 3: Commit**

```bash
git add tests/test-k8s-scan.sh
git commit -m "test: add K8s scan test suite (23 tests)"
```

---

## Phase D: GraphQL Security Scanning (#55)

### Task D1: Create GraphQL skill and reference file

**Files:**

- Create: `skills/graphql-scan/SKILL.md`
- Create: `skills/references/graphql-security-reference.md`

**Context:** 16th skill. Reference covers OWASP GraphQL Cheat Sheet, attack patterns (introspection abuse, depth bombing, batch DoS, alias bypass), framework guidance (Apollo, graphql-yoga, Strawberry, graphql-java).

**Step 1: Create SKILL.md** with triggers (graphql, gql, introspection, query depth, batch query)

**Step 2: Create reference file** (~180 lines)

**Step 3: Commit**

```bash
git add skills/graphql-scan/ skills/references/graphql-security-reference.md
git commit -m "feat: add /graphql-scan skill and GraphQL security reference"
```

### Task D2: Create GraphQL Semgrep rules

**Files:**

- Create: `rules/graphql-rules.yml`
- Create: `tests/fixtures/sample-graphql-findings.json`

**Context:** 8 rules per design doc (gql-introspection-enabled, gql-no-depth-limit, gql-no-cost-limit, gql-batch-no-limit, gql-resolver-no-auth, gql-sql-in-resolver, gql-verbose-errors, gql-no-rate-limit). Use `languages: [generic]` + `pattern-regex` for framework-agnostic detection, plus `languages: [python]` and `languages: [javascript]` for resolver-specific rules.

**Step 1: Create rules file**

**Step 2: Create fixture** (3 sample GraphQL findings in unified schema)

**Step 3: Commit**

```bash
git add rules/graphql-rules.yml tests/fixtures/sample-graphql-findings.json
git commit -m "feat: add 8 GraphQL security Semgrep rules + fixture"
```

### Task D3: Create Nuclei templates for GraphQL

**Files:**

- Create: `runner/nuclei-templates/graphql/graphql-introspection.yaml`
- Create: `runner/nuclei-templates/graphql/graphql-field-suggestion.yaml`
- Create: `runner/nuclei-templates/graphql/graphql-batch-query.yaml`
- Create: `runner/nuclei-templates/graphql/graphql-depth-attack.yaml`

**Context:** Follow Nuclei template v3 format. Each template: `id`, `info` (name, author, severity, tags), `http` (method, path, body, matchers).

**Step 1: Create all 4 Nuclei templates**

**Step 2: Commit**

```bash
git add runner/nuclei-templates/graphql/
git commit -m "feat: add 4 Nuclei templates for GraphQL security scanning"
```

### Task D4: Add GraphQL scan to job dispatcher

**Files:**

- Modify: `runner/job-dispatcher.sh` (add `run_graphql_scan()` + register in `run_tool()`)

**Context:** `run_graphql_scan()` with 3 modes: `static` (run_semgrep with graphql-rules.yml), `live` (run_nuclei with graphql/ templates + curl introspection), `both`. Requires `GRAPHQL_TARGET` env var for live mode (same pattern as `DAST_TARGET`).

**Step 1: Add `run_graphql_scan()` function**

**Step 2: Register in `run_tool()` case**

**Step 3: Commit**

```bash
git add runner/job-dispatcher.sh
git commit -m "feat: add run_graphql_scan() to job dispatcher (static + live modes)"
```

### Task D5: Create GraphQL scan test suite

**Files:**

- Create: `tests/test-graphql-scan.sh`

**Sections:**

1. Skill definition (SKILL.md exists, triggers) — 4 tests
2. Reference file (exists, OWASP, frameworks) — 4 tests
3. Semgrep rules (8 rules, CWEs) — 4 tests
4. Nuclei templates (4 files exist, valid YAML) — 5 tests
5. Job dispatcher (run_graphql_scan function, modes, GRAPHQL_TARGET) — 4 tests
6. Fixture validation — 2 tests

Target: ~23 tests

**Step 1: Create test file**

**Step 2: Run and verify**

Run: `bash tests/test-graphql-scan.sh`

**Step 3: Commit**

```bash
git add tests/test-graphql-scan.sh
git commit -m "test: add GraphQL scan test suite (23 tests)"
```

---

## Phase E: MCP Integration

### Task E1: Add devsecops_history and devsecops_pipeline MCP tools

**Files:**

- Modify: `mcp/server.mjs`

**Context:** Add 2 new MCP tools following `devsecops_compliance_status` pattern:

- `devsecops_history`: query scan-db.sh (stats, query by severity/tool, trend)
- `devsecops_pipeline`: validate, list, and get status of DAG pipelines

Each needs: TOOLS entry, Zod schema, handler function, switch case registration. Also update description line (~226) to "10 MCP tools" and compliance_status frameworks to still show 7.

**Step 1: Add both tools to TOOLS array**

**Step 2: Add Zod schemas**

**Step 3: Add handler functions** (shell out to scan-db.sh and pipeline-engine.sh)

**Step 4: Register in switch case**

**Step 5: Rebuild MCP bundle**

Run: `cd mcp && bash build.sh`

**Step 6: Commit**

```bash
git add mcp/server.mjs mcp/dist/server.js
git commit -m "feat: add devsecops_history + devsecops_pipeline MCP tools (10 total)"
```

---

## Phase F: Security Dashboard (#53)

### Task F1: Create dashboard HTML template

**Files:**

- Create: `templates/dashboard.html`

**Context:** Alpine.js 3 + Chart.js 4 from CDN. Single file with inline CSS (dark mode via CSS variables). 6 panels in CSS grid. Placeholder markers `/*__SCAN_DATA__*/`, `/*__PIPELINE__*/`, `/*__TREND__*/` for data injection. ~300 lines.

**Step 1: Create `templates/dashboard.html`** with:

- Alpine.js `x-data="dashboard()"` root
- Filter bar (severity, tool, category dropdowns)
- Pipeline flow panel (CSS grid + status badges)
- Severity doughnut chart (Chart.js)
- OWASP horizontal bar chart
- Tool results table
- Compliance heatmap grid
- Trend line chart
- Finding detail modal (`x-show`)
- Dark mode toggle

**Step 2: Commit**

```bash
git add templates/dashboard.html
git commit -m "feat: add Alpine.js + Chart.js dashboard template"
```

### Task F2: Create dashboard generator

**Files:**

- Create: `formatters/dashboard-generator.sh`

**Context:** Shell script that reads SQLite data via python3, loads `templates/dashboard.html`, replaces placeholder markers with real JSON, outputs self-contained HTML file.

Subcommands: `generate` (default), options: `--scan-id UUID`, `--trend`, `--days N`, `--output path`.

**Step 1: Create `formatters/dashboard-generator.sh`**

**Step 2: Make executable**

**Step 3: Commit**

```bash
git add formatters/dashboard-generator.sh
git commit -m "feat: add dashboard generator (SQLite → self-contained HTML)"
```

### Task F3: Create dashboard test suite

**Files:**

- Create: `tests/test-dashboard-generator.sh`

**Sections:**

1. Template (exists, Alpine.js CDN, Chart.js CDN, placeholders) — 5 tests
2. Generator script (exists, executable, --help) — 3 tests
3. Generation (produces HTML, contains scan data, valid HTML structure) — 5 tests
4. Dark mode (CSS variables present, toggle element) — 2 tests
5. Panels (6 panel sections present in template) — 6 tests

Target: ~21 tests

**Step 1: Create test file**

**Step 2: Run and verify**

**Step 3: Commit**

```bash
git add tests/test-dashboard-generator.sh
git commit -m "test: add dashboard generator test suite (21 tests)"
```

---

## Phase G: Release (#51-#55)

### Task G1: Update validate-plugin.sh

**Files:**

- Modify: `tests/validate-plugin.sh`

**Context:** Update EXPECTED_SKILLS to 16 (add k8s-scan, graphql-scan), EXPECTED_REFS to 19 (add k8s-security-reference.md, graphql-security-reference.md).

**Step 1: Update skill and reference counts**

**Step 2: Run validate-plugin.sh**

Run: `bash tests/validate-plugin.sh`
Expected: All checks pass

**Step 3: Commit**

```bash
git add tests/validate-plugin.sh
git commit -m "chore: update validate-plugin.sh for 16 skills, 19 references"
```

### Task G2: Update CWE mappings

**Files:**

- Modify: `mappings/cwe-to-owasp.json`

**Context:** Add CWE-400 (Uncontrolled Resource Consumption) and CWE-770 (Allocation without Limits) if not already present. These support GraphQL DoS rules.

**Step 1: Check and add missing CWEs**

**Step 2: Commit**

```bash
git add mappings/cwe-to-owasp.json
git commit -m "feat: add CWE-400 and CWE-770 to OWASP mapping for GraphQL rules"
```

### Task G3: Version bump to 3.0.0

**Files:**

- Modify: 7 files via `scripts/version-bump.sh`
- Rebuild: `mcp/dist/server.js`

**Step 1: Bump version**

Run: `bash scripts/version-bump.sh 3.0.0`

**Step 2: Rebuild MCP bundle**

Run: `cd mcp && bash build.sh`

**Step 3: Commit**

```bash
git add -A
git commit -m "chore: bump version to 3.0.0"
```

### Task G4: Update documentation

**Files:**

- Modify: `CHANGELOG.md` (add [3.0.0] section)
- Modify: `README.md` (badges, tools table, skills, formats, roadmap, project structure)
- Modify: `docs/PRD.md` (current state → v3.0.0 metrics)
- Modify: `CLAUDE.md` (Key Files table, Tools table, skill/reference counts)
- Modify: `.claude-plugin/plugin.json` (description → "16 skills")
- Modify: `.claude-plugin/marketplace.json` (descriptions → "16 skills")
- Modify: `frameworks.json` (if new framework entries needed)

**Step 1: Update all docs** per v2.8.0 pattern

**Step 2: Run release-checklist.sh**

Run: `bash scripts/release-checklist.sh 3.0.0`
Expected: All checks pass

**Step 3: Commit**

```bash
git add -A
git commit -m "docs: update documentation for v3.0.0 release"
```

### Task G5: QA round

**Step 1: Run validate-plugin.sh**

Run: `bash tests/validate-plugin.sh`
Expected: All checks pass (should be ~270+)

**Step 2: Run release-checklist.sh**

Run: `bash scripts/release-checklist.sh 3.0.0`
Expected: All checks pass

**Step 3: Run all test suites and count**

Run: `for f in tests/test-*.sh; do bash "$f" 2>&1; done | grep -c '\[PASS\]'`
Expected: ~1,400+

**Step 4: Fix any failures, re-run, confirm all green**

---

## Task Summary

| Phase | Tasks | New Files           | Description                             |
| ----- | ----- | ------------------- | --------------------------------------- |
| A     | A1-A3 | 2 + test            | SQLite database (scan-db.sh)            |
| B     | B1-B4 | 6 + test + fixtures | DAG pipeline engine                     |
| C     | C1-C4 | 4 + test + fixture  | K8s scanning (skill, rules, Docker)     |
| D     | D1-D5 | 8 + test + fixture  | GraphQL scanning (skill, rules, Nuclei) |
| E     | E1    | 0 (modify only)     | MCP integration (2 new tools)           |
| F     | F1-F3 | 2 + test            | Dashboard (template + generator)        |
| G     | G1-G5 | 0 (modify only)     | Release (version, docs, QA)             |

**Total: ~27 tasks, ~20 new files, ~42 test suites, ~1,400+ tests**

## Execution Order (with parallelism)

```
A1 → A2 → A3                          (sequential — foundation)
B1 → B2 → B3 → B4                    (sequential — engine depends on pipelines)
C1 + C2 → C3 → C4                    (C1/C2 parallel, then Docker/tests)
D1 + D2 + D3 → D4 → D5              (D1/D2/D3 parallel, then dispatcher/tests)
E1                                     (after A + B complete)
F1 → F2 → F3                          (sequential — after A + B complete)
G1 → G2 → G3 → G4 → G5              (sequential — release)
```

**Maximum parallelism:** After A3 completes, B1 + C1 + C2 + D1 + D2 + D3 can all run in parallel.
