# v2.7.0 Implementation Plan — OWASP 2025 + DAST + Regulatory

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate to OWASP 2025 dual-version mapping, add Nuclei DAST, expand custom rules to 8/10 OWASP categories, and add Thai regulatory compliance (NCSA 1.0 + PDPA).

**Architecture:** Six sequential phases (A-F). Phase A (OWASP mapping) is foundation for B/E (rules). Phase C (Nuclei) and D (regulatory) are independent. Phase F (release) depends on all.

**Tech Stack:** Bash, YAML (Semgrep rules), JSON (mappings), Docker Compose, Node.js/Zod (MCP server)

**Design doc:** `docs/plans/2026-03-03-v270-owasp2025-dast-regulatory-design.md`

---

## Phase A: OWASP 2025 Mapping Foundation (#39)

### Task A1: Add OWASP 2025 entry to frameworks.json

**Files:**

- Modify: `frameworks.json` (add entry after existing `owasp-top-10` block, ~line 17)

**Step 1: Add OWASP 2025 framework entry**

Add new entry after the existing `owasp-top-10` entry (which ends around line 17). Follow exact structure of existing entries:

```json
{
  "id": "owasp-top-10-2025",
  "name": "OWASP Top 10 2025",
  "version": "2025",
  "released": "2025-06",
  "source_url": "https://owasp.org/Top10/",
  "last_checked": "2026-03-03",
  "grep_patterns": ["A0[1-9]:2025", "A10:2025", "OWASP.*2025"],
  "used_in": [
    "mappings/cwe-to-owasp.json",
    "rules/a01-access-control-rules.yml",
    "rules/a02-crypto-rules.yml",
    "rules/a03-injection-rules.yml",
    "rules/a04-insecure-design-rules.yml",
    "rules/a05-misconfig-rules.yml",
    "rules/a09-logging-rules.yml",
    "rules/a10-exception-rules.yml"
  ],
  "update_frequency": "rare",
  "notes": "2025 edition. Key changes: A03 now Supply Chain (was Injection), A05 now Injection (was Misconfiguration), A10 now Exception Handling (was SSRF which merged into A01)"
}
```

Also update the existing `owasp-top-10` entry's `notes` field to:

```
"notes": "2021 edition. Superseded by 2025 edition. Kept for dual-version compatibility."
```

**Step 2: Validate JSON**

Run: `python3 -c "import json; json.load(open('frameworks.json')); print('OK')"`
Expected: `OK`

**Step 3: Commit**

```bash
git add frameworks.json
git commit -m "feat: add OWASP Top 10 2025 framework entry"
```

---

### Task A2: Migrate cwe-to-owasp.json to dual-version format

**Files:**

- Modify: `mappings/cwe-to-owasp.json`

**Context:** Current format has `"owasp": ["A03:2021"]`. We add the 2025 tag alongside: `"owasp": ["A03:2021", "A05:2025"]`. The OWASP 2025 category changes are:

| CWEs currently mapped to | 2021 Category             | 2025 Category                    | Action       |
| ------------------------ | ------------------------- | -------------------------------- | ------------ |
| A01:2021                 | Broken Access Control     | A01:2025 (now includes SSRF)     | Add A01:2025 |
| A02:2021                 | Cryptographic Failures    | A02:2025                         | Add A02:2025 |
| A03:2021                 | Injection                 | A05:2025 (Injection moved)       | Add A05:2025 |
| A04:2021                 | Insecure Design           | A04:2025                         | Add A04:2025 |
| A05:2021                 | Security Misconfiguration | A05:2025 (merged with Injection) | Add A05:2025 |
| A06:2021                 | Vulnerable Components     | A06:2025                         | Add A06:2025 |
| A07:2021                 | ID & Auth Failures        | A07:2025                         | Add A07:2025 |
| A08:2021                 | Data Integrity Failures   | A08:2025                         | Add A08:2025 |
| A09:2021                 | Security Logging          | A09:2025                         | Add A09:2025 |
| A10:2021                 | SSRF                      | A01:2025 (merged into A01)       | Add A01:2025 |

**Step 1: Update `_meta` section**

Change:

```json
"_meta": {
  "description": "CWE to OWASP Top 10 2021 mapping",
  "source": "https://cwe.mitre.org/data/definitions/1344.html",
  "owasp_version": "2021",
  "last_updated": "2026-03-02"
}
```

To:

```json
"_meta": {
  "description": "CWE to OWASP Top 10 mapping (dual-version 2021+2025)",
  "source": "https://cwe.mitre.org/data/definitions/1344.html",
  "owasp_version": ["2021", "2025"],
  "migration_date": "2026-03-XX",
  "last_updated": "2026-03-XX"
}
```

**Step 2: Add 2025 tags to all existing 105 CWE entries**

Use a Python script to batch-update. The mapping logic:

- `A01:2021` → add `A01:2025`
- `A02:2021` → add `A02:2025`
- `A03:2021` (Injection) → add `A05:2025` (Injection moved to A05)
- `A04:2021` → add `A04:2025`
- `A05:2021` (Misconfiguration) → add `A05:2025` (merged with Injection)
- `A06:2021` → add `A06:2025`
- `A07:2021` → add `A07:2025`
- `A08:2021` → add `A08:2025`
- `A09:2021` → add `A09:2025`
- `A10:2021` (SSRF) → add `A01:2025` (SSRF merged into A01)

Write and run a migration script:

```bash
python3 -c "
import json

MIGRATION = {
    'A01:2021': 'A01:2025',
    'A02:2021': 'A02:2025',
    'A03:2021': 'A05:2025',  # Injection moved to A05
    'A04:2021': 'A04:2025',
    'A05:2021': 'A05:2025',  # Misconfiguration merged into A05
    'A06:2021': 'A06:2025',
    'A07:2021': 'A07:2025',
    'A08:2021': 'A08:2025',
    'A09:2021': 'A09:2025',
    'A10:2021': 'A01:2025',  # SSRF merged into A01
}

with open('mappings/cwe-to-owasp.json') as f:
    data = json.load(f)

for cwe, entry in data['mappings'].items():
    new_tags = []
    for tag in entry['owasp']:
        if tag in MIGRATION:
            new_tag = MIGRATION[tag]
            if new_tag not in entry['owasp'] and new_tag not in new_tags:
                new_tags.append(new_tag)
    entry['owasp'].extend(new_tags)

with open('mappings/cwe-to-owasp.json', 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write('\n')

print(f'Migrated {len(data[\"mappings\"])} CWE entries')
"
```

**Step 3: Add ~15 new CWE entries for new 2025 categories**

Add CWEs for A03:2025 (Supply Chain) — these are NEW to OWASP 2025:

```json
"CWE-1104": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Use of Unmaintained Third-Party Components" },
"CWE-829": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Inclusion of Functionality from Untrusted Control Sphere" },
"CWE-494": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Download of Code Without Integrity Check" },
"CWE-1357": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Reliance on Insufficiently Trustworthy Component" },
"CWE-506": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Embedded Malicious Code" },
"CWE-511": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Logic/Time Bomb" },
"CWE-830": { "owasp": ["A03:2025"], "category": "Supply Chain", "name": "Inclusion of Web Functionality from Untrusted Source" }
```

Add CWEs for A10:2025 (Exception Handling):

```json
"CWE-396": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Declaration of Catch for Generic Exception" },
"CWE-397": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Declaration of Throws for Generic Exception" },
"CWE-755": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Improper Handling of Exceptional Conditions" },
"CWE-248": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Uncaught Exception" },
"CWE-390": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Detection of Error Condition Without Action" },
"CWE-754": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Improper Check for Unusual or Exceptional Conditions" },
"CWE-391": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Unchecked Error Condition" },
"CWE-584": { "owasp": ["A10:2025"], "category": "Exception Handling", "name": "Return Inside Finally Block" }
```

**Step 4: Validate**

```bash
python3 -c "
import json
with open('mappings/cwe-to-owasp.json') as f:
    data = json.load(f)
total = len(data['mappings'])
has_2025 = sum(1 for e in data['mappings'].values() if any('2025' in t for t in e['owasp']))
print(f'Total CWEs: {total}, with 2025 tags: {has_2025}')
assert has_2025 >= total - 5, f'Most entries should have 2025 tags'
print('OK')
"
```

**Step 5: Commit**

```bash
git add mappings/cwe-to-owasp.json
git commit -m "feat: migrate cwe-to-owasp.json to dual-version 2021+2025 format"
```

---

### Task A3: Update existing custom rules with 2025 OWASP tags

**Files:**

- Modify: `rules/a01-access-control-rules.yml`
- Modify: `rules/a03-injection-rules.yml`
- Modify: `rules/a09-logging-rules.yml`
- Modify: `rules/a10-ssrf-rules.yml`

**Step 1: Add 2025 tags to each rule file's metadata**

For each rule in each file, add the 2025 OWASP tag alongside the existing 2021 tag:

- `a01-access-control-rules.yml`: Add `"A01:2025"` to every rule's `owasp` array
- `a03-injection-rules.yml`: Add `"A05:2025"` (Injection moved to A05 in 2025)
- `a09-logging-rules.yml`: Add `"A09:2025"` to every rule's `owasp` array
- `a10-ssrf-rules.yml`: Add `"A01:2025"` (SSRF merged into A01 in 2025)

Also update header comment in each file from `v2.5.0` to `v2.7.0`.

**Step 2: Validate YAML**

```bash
for f in rules/*.yml; do
  python3 -c "import yaml; yaml.safe_load(open('$f')); print(f'OK: $f')"
done
```

**Step 3: Commit**

```bash
git add rules/a01-access-control-rules.yml rules/a03-injection-rules.yml rules/a09-logging-rules.yml rules/a10-ssrf-rules.yml
git commit -m "feat: add OWASP 2025 dual-tags to all existing custom rules"
```

---

### Task A4: Add OWASP 2025 dual-tag validation to tests

**Files:**

- Modify: `tests/test-a01-rules.sh`
- Modify: `tests/test-a03-rules.sh`
- Modify: `tests/test-a10-rules.sh`

**Step 1: Add dual-tag checks to each test file**

Add after existing OWASP validation section in each test file:

```bash
# Check OWASP 2025 dual-tagging
HAS_2025=$(python3 -c "
import yaml
with open('$RULES_FILE') as f:
    data = yaml.safe_load(f)
count = 0
for r in data['rules']:
    owasp = r.get('metadata', {}).get('owasp', [])
    if any('2025' in t for t in owasp):
        count += 1
print(count)
")
[ "$HAS_2025" -eq "$RULE_COUNT" ] \
  && pass "All $RULE_COUNT rules have OWASP 2025 tags" \
  || fail "Only $HAS_2025/$RULE_COUNT rules have OWASP 2025 tags"
```

**Step 2: Run tests**

```bash
bash tests/test-a01-rules.sh && bash tests/test-a03-rules.sh && bash tests/test-a10-rules.sh
```

Expected: All PASS

**Step 3: Commit**

```bash
git add tests/test-a01-rules.sh tests/test-a03-rules.sh tests/test-a10-rules.sh
git commit -m "test: add OWASP 2025 dual-tag validation to rule tests"
```

---

## Phase B: Custom Rules Wave 1 — A02/A05:2025 (#40)

### Task B1: Create A02 Cryptographic Failures rules

**Files:**

- Create: `rules/a02-crypto-rules.yml`
- Create: `tests/fixtures/sample-a02-findings.json`

**Step 1: Create the rule file**

Create `rules/a02-crypto-rules.yml` with 6 rules. Follow exact structure from `rules/a01-access-control-rules.yml`:

```yaml
rules:
  # ==========================================================================
  # A02:2025 Cryptographic Failures — Custom Semgrep Rules
  # DevSecOps AI Team v2.7.0
  #
  # 6 rules targeting A02 anti-patterns
  # Languages: Python (3 rules), JavaScript/TypeScript (3 rules)
  # Reference: skills/references/sast-patterns.md
  # ==========================================================================

  - id: a02-weak-hash-python
    patterns:
      - pattern-either:
          - pattern: hashlib.md5(...)
          - pattern: hashlib.sha1(...)
    message: >
      Weak hash algorithm (MD5/SHA1) detected. These algorithms are
      cryptographically broken and MUST NOT be used for security purposes.
      Use SHA-256 or SHA-3 instead per OWASP A02:2025.
    fix: |
      # Use SHA-256 instead:
      hashlib.sha256(data).hexdigest()
    languages:
      - python
    severity: ERROR
    metadata:
      cwe:
        - "CWE-328"
      owasp:
        - "A02:2021"
        - "A02:2025"
      nist:
        - "SC-13"
      mitre:
        - "T1557"
      confidence: HIGH
      impact: HIGH
      likelihood: HIGH
      technology:
        - python

  - id: a02-weak-hash-javascript
    patterns:
      - pattern-either:
          - pattern: crypto.createHash('md5')
          - pattern: crypto.createHash('sha1')
          - pattern: CryptoJS.MD5(...)
          - pattern: CryptoJS.SHA1(...)
    message: >
      Weak hash algorithm (MD5/SHA1) detected. Use SHA-256 or SHA-3
      instead per OWASP A02:2025.
    fix: |
      // Use SHA-256 instead:
      crypto.createHash('sha256').update(data).digest('hex')
    languages:
      - javascript
      - typescript
    severity: ERROR
    metadata:
      cwe:
        - "CWE-328"
      owasp:
        - "A02:2021"
        - "A02:2025"
      nist:
        - "SC-13"
      confidence: HIGH
      impact: HIGH
      technology:
        - javascript
        - typescript

  - id: a02-hardcoded-key
    pattern-regex: '(?i)(secret_key|api_key|private_key|encryption_key)\s*=\s*["\x27][a-zA-Z0-9+/=]{16,}["\x27]'
    message: >
      Hardcoded cryptographic key detected. Keys MUST be loaded from
      environment variables or a secure vault, never hardcoded in source.
    fix: |
      # Use environment variable:
      import os
      SECRET_KEY = os.environ['SECRET_KEY']
    languages:
      - python
      - javascript
      - typescript
      - java
    severity: ERROR
    metadata:
      cwe:
        - "CWE-321"
      owasp:
        - "A02:2021"
        - "A02:2025"
      nist:
        - "SC-12"
      confidence: MEDIUM
      impact: HIGH
      technology:
        - python
        - javascript
        - java

  - id: a02-insecure-random-python
    patterns:
      - pattern-either:
          - pattern: random.random()
          - pattern: random.randint(...)
          - pattern: random.choice(...)
    message: >
      Insecure random number generator used. For security-sensitive
      operations (tokens, keys, nonces), use secrets module instead.
    fix: |
      import secrets
      token = secrets.token_hex(32)
    languages:
      - python
    severity: WARNING
    metadata:
      cwe:
        - "CWE-338"
      owasp:
        - "A02:2021"
        - "A02:2025"
      nist:
        - "SC-13"
      confidence: MEDIUM
      impact: MEDIUM
      technology:
        - python

  - id: a02-insecure-random-javascript
    patterns:
      - pattern: Math.random()
    message: >
      Math.random() is not cryptographically secure. For security-sensitive
      operations, use crypto.randomBytes() or crypto.getRandomValues().
    fix: |
      // Use crypto module:
      const crypto = require('crypto');
      const token = crypto.randomBytes(32).toString('hex');
    languages:
      - javascript
      - typescript
    severity: WARNING
    metadata:
      cwe:
        - "CWE-338"
      owasp:
        - "A02:2021"
        - "A02:2025"
      confidence: MEDIUM
      impact: MEDIUM
      technology:
        - javascript
        - typescript

  - id: a02-weak-tls
    pattern-regex: '(?i)(ssl_version|PROTOCOL_TLSv1[^2-9]|TLSv1_METHOD|TLSv1\.0|TLSv1\.1|SSLv[23])'
    message: >
      Weak TLS/SSL version detected. Use TLS 1.2 or higher.
      TLS 1.0 and 1.1 are deprecated per RFC 8996.
    fix: |
      # Use TLS 1.2+:
      ssl.PROTOCOL_TLS_CLIENT  # Python
      # or: tls.createSecureContext({ minVersion: 'TLSv1.2' })  // Node.js
    languages:
      - python
      - javascript
      - typescript
    severity: ERROR
    metadata:
      cwe:
        - "CWE-327"
      owasp:
        - "A02:2021"
        - "A02:2025"
      nist:
        - "SC-8"
      confidence: HIGH
      impact: HIGH
      technology:
        - python
        - javascript
```

**Step 2: Create test fixture**

Create `tests/fixtures/sample-a02-findings.json`:

```json
{
  "findings": [
    {
      "id": "A02-001",
      "source_tool": "semgrep",
      "scan_type": "sast",
      "severity": "HIGH",
      "confidence": "HIGH",
      "title": "Weak hash algorithm (MD5) detected",
      "cwe_id": "CWE-328",
      "rule_id": "a02-weak-hash-python",
      "location": { "file": "auth/utils.py", "line": 45 },
      "status": "open"
    },
    {
      "id": "A02-002",
      "source_tool": "semgrep",
      "scan_type": "sast",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "title": "Hardcoded encryption key",
      "cwe_id": "CWE-321",
      "rule_id": "a02-hardcoded-key",
      "location": { "file": "config/settings.py", "line": 12 },
      "status": "open"
    },
    {
      "id": "A02-003",
      "source_tool": "semgrep",
      "scan_type": "sast",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "title": "Insecure random number generator",
      "cwe_id": "CWE-338",
      "rule_id": "a02-insecure-random-python",
      "location": { "file": "auth/tokens.py", "line": 23 },
      "status": "open"
    }
  ],
  "summary": {
    "total": 3,
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0,
    "info": 0
  }
}
```

**Step 3: Validate YAML**

Run: `python3 -c "import yaml; data=yaml.safe_load(open('rules/a02-crypto-rules.yml')); print(f'{len(data[\"rules\"])} rules'); assert len(data['rules']) == 6"`
Expected: `6 rules`

**Step 4: Commit**

```bash
git add rules/a02-crypto-rules.yml tests/fixtures/sample-a02-findings.json
git commit -m "feat: add A02 Cryptographic Failures custom Semgrep rules (6 rules)"
```

---

### Task B2: Create A05 Security Misconfiguration rules

**Files:**

- Create: `rules/a05-misconfig-rules.yml`
- Create: `tests/fixtures/sample-a05-findings.json`

**Step 1: Create the rule file**

Create `rules/a05-misconfig-rules.yml` with 6 rules following same structure as B1. Rules:

1. `a05-debug-mode-python` — `DEBUG = True` in Django/Flask settings (CWE-489)
2. `a05-debug-mode-javascript` — `NODE_ENV` not production checks (CWE-489)
3. `a05-default-credentials` — Hardcoded admin/password/root patterns (CWE-798)
4. `a05-permissive-cors` — `Access-Control-Allow-Origin: *` (CWE-942)
5. `a05-verbose-errors` — Stack trace in response (CWE-209)
6. `a05-missing-security-headers` — Missing X-Frame-Options/CSP setup (CWE-1021)

Each rule must include: `owasp: ["A05:2021", "A05:2025"]` in metadata.

**Step 2: Create test fixture** `tests/fixtures/sample-a05-findings.json` (same pattern as A02)

**Step 3: Validate** `python3 -c "import yaml; data=yaml.safe_load(open('rules/a05-misconfig-rules.yml')); assert len(data['rules']) == 6"`

**Step 4: Commit**

```bash
git add rules/a05-misconfig-rules.yml tests/fixtures/sample-a05-findings.json
git commit -m "feat: add A05 Security Misconfiguration custom Semgrep rules (6 rules)"
```

---

### Task B3: Create test suites for A02 and A05 rules

**Files:**

- Create: `tests/test-a02-rules.sh`
- Create: `tests/test-a05-rules.sh`

**Step 1: Create test files**

Follow exact pattern from `tests/test-a01-rules.sh`. Each test file has:

1. **Section 1: Rules File Structure** — file exists, YAML valid, rule count correct (6)
2. **Section 2: Rule Metadata** — every rule has cwe, owasp (with 2025 tag), severity, message
3. **Section 3: CWE Mapping Cross-Reference** — all CWEs exist in `mappings/cwe-to-owasp.json`
4. **Section 4: Language Coverage** — at least 2 languages covered
5. **Summary** — pass/fail/warn counts

Key variables for `test-a02-rules.sh`:

```bash
RULES_FILE="$ROOT_DIR/rules/a02-crypto-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a02-findings.json"
EXPECTED_RULES=6
```

Key variables for `test-a05-rules.sh`:

```bash
RULES_FILE="$ROOT_DIR/rules/a05-misconfig-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a05-findings.json"
EXPECTED_RULES=6
```

**Step 2: Run tests**

```bash
bash tests/test-a02-rules.sh && echo "A02 PASS" && bash tests/test-a05-rules.sh && echo "A05 PASS"
```

Expected: Both PASS

**Step 3: Commit**

```bash
git add tests/test-a02-rules.sh tests/test-a05-rules.sh
git commit -m "test: add test suites for A02 and A05 custom rules"
```

---

## Phase C: Nuclei DAST Full Integration (#41)

### Task C1: Add Nuclei to Docker Compose

**Files:**

- Modify: `runner/docker-compose.yml` (add service after `zap` block, ~line 57)

**Step 1: Add nuclei service**

Add after the `zap` service block. Follow exact pattern:

```yaml
nuclei:
  image: projectdiscovery/nuclei:latest
  container_name: devsecops-nuclei
  entrypoint: ["sleep", "infinity"]
  profiles: ["nuclei", "dast", "all"]
  mem_limit: 1g
  memswap_limit: 1g
  volumes:
    - results:/results
    - config:/config:ro
  networks:
    - devsecops
    - devsecops-dast
  restart: unless-stopped
```

**Step 2: Validate YAML**

```bash
docker compose -f runner/docker-compose.yml config --quiet && echo "OK"
```

Expected: `OK` (or validate with `python3 -c "import yaml; yaml.safe_load(open('runner/docker-compose.yml'))"`)

**Step 3: Commit**

```bash
git add runner/docker-compose.yml
git commit -m "feat: add Nuclei DAST tool to docker-compose"
```

---

### Task C2: Add run_nuclei() to job-dispatcher.sh

**Files:**

- Modify: `runner/job-dispatcher.sh` (add function before `run_tool()` at ~line 237, add case at ~line 244)

**Step 1: Add run_nuclei() function**

Add before the `run_tool()` function. Follow exact pattern of `run_zap()` (lines 171-221):

```bash
# ─── Nuclei DAST ───
run_nuclei() {
  local NUCLEI_TEMPLATES="cves"
  local NUCLEI_TIMEOUT=120
  local NUCLEI_EXTRA_ARGS=""

  case "$NUCLEI_MODE" in
    cve)
      NUCLEI_TEMPLATES="cves"
      NUCLEI_TIMEOUT=120
      ;;
    full)
      NUCLEI_TEMPLATES=""
      NUCLEI_TIMEOUT=600
      ;;
    custom)
      NUCLEI_TEMPLATES=""
      NUCLEI_TIMEOUT=300
      if [ -n "$CUSTOM_TEMPLATES" ]; then
        NUCLEI_EXTRA_ARGS="-t $CUSTOM_TEMPLATES"
      fi
      ;;
    *)
      echo "[dispatcher] ERROR: Unknown Nuclei mode: $NUCLEI_MODE (use cve|full|custom)"
      exit 1
      ;;
  esac

  # Add auth header if provided
  if [ -n "$AUTH_TOKEN" ]; then
    NUCLEI_EXTRA_ARGS="$NUCLEI_EXTRA_ARGS -H \"Authorization: Bearer ${AUTH_TOKEN}\""
  fi

  echo "[dispatcher] Nuclei mode: $NUCLEI_MODE, templates: ${NUCLEI_TEMPLATES:-all}..." >>"$LOG"

  local NUCLEI_ARGS="-u $TARGET -jsonl -o /results/${JOB_ID}/nuclei-results.jsonl -silent"
  [ -n "$NUCLEI_TEMPLATES" ] && NUCLEI_ARGS="$NUCLEI_ARGS -tags $NUCLEI_TEMPLATES"
  [ -n "$NUCLEI_EXTRA_ARGS" ] && NUCLEI_ARGS="$NUCLEI_ARGS $NUCLEI_EXTRA_ARGS"

  if [ "$RUNNER_MODE" = "full" ]; then
    timeout "$NUCLEI_TIMEOUT" docker exec devsecops-nuclei \
      nuclei $NUCLEI_ARGS 2>>"$LOG"
  else
    timeout "$NUCLEI_TIMEOUT" docker run --rm \
      -v "${RESULTS_DIR}:/results" --network host \
      projectdiscovery/nuclei:latest \
      nuclei $NUCLEI_ARGS 2>>"$LOG"
  fi
}
```

**Step 2: Add to run_tool() switch**

Find the `run_tool()` function's case statement (~line 244) and add:

```bash
    nuclei)  run_nuclei ;;
```

**Step 3: Validate syntax**

```bash
bash -n runner/job-dispatcher.sh && echo "OK"
```

Expected: `OK`

**Step 4: Commit**

```bash
git add runner/job-dispatcher.sh
git commit -m "feat: add Nuclei routing to job-dispatcher"
```

---

### Task C3: Add Nuclei parser to normalizer

**Files:**

- Modify: `formatters/json-normalizer.sh` (add nuclei case block after zap, ~line 279)

**Step 1: Add nuclei case block**

Nuclei JSONL format (one finding per line):

```json
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Log4j RCE",
    "severity": "critical",
    "tags": ["cve"],
    "classification": { "cwe-id": ["CWE-502"], "cvss-score": 10.0 }
  },
  "matched-at": "http://target:8080/api",
  "curl-command": "..."
}
```

Add the nuclei parser case block following existing tool patterns:

```bash
nuclei)
  python3 -c "
import json, sys

findings = []
i = 0
with open('$INPUT_FILE') as f:
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
            'id': f'$DATE_PREFIX-{i:03d}',
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
    summary[f['severity'].lower()] = summary.get(f['severity'].lower(), 0) + 1

json.dump({'findings': findings, 'summary': summary}, sys.stdout, indent=2)
" > "$OUTPUT_FILE"
  ;;
```

**Step 2: Validate syntax**

```bash
bash -n formatters/json-normalizer.sh && echo "OK"
```

**Step 3: Commit**

```bash
git add formatters/json-normalizer.sh
git commit -m "feat: add Nuclei JSONL parser to normalizer"
```

---

### Task C4: Create Nuclei test fixtures and integration tests

**Files:**

- Create: `tests/fixtures/sample-nuclei.jsonl`
- Create: `tests/fixtures/sample-nuclei-normalized.json`
- Create: `tests/test-nuclei-integration.sh`

**Step 1: Create JSONL fixture**

Create `tests/fixtures/sample-nuclei.jsonl` (one JSON object per line):

```jsonl
{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical","tags":["cve","rce"],"classification":{"cwe-id":["CWE-502"],"cvss-score":10.0}},"matched-at":"http://target:8080/api","timestamp":"2026-03-03T10:00:00Z"}
{"template-id":"CVE-2023-44487","info":{"name":"HTTP/2 Rapid Reset","severity":"high","tags":["cve","dos"],"classification":{"cwe-id":["CWE-400"],"cvss-score":7.5}},"matched-at":"http://target:8080","timestamp":"2026-03-03T10:01:00Z"}
{"template-id":"missing-hsts","info":{"name":"Missing HSTS Header","severity":"medium","tags":["misconfiguration"],"classification":{"cwe-id":["CWE-523"]}},"matched-at":"http://target:8080","timestamp":"2026-03-03T10:02:00Z"}
{"template-id":"open-redirect","info":{"name":"Open Redirect Detected","severity":"low","tags":["redirect"],"classification":{"cwe-id":["CWE-601"]}},"matched-at":"http://target:8080/redirect?url=evil.com","timestamp":"2026-03-03T10:03:00Z"}
```

**Step 2: Create test file**

Create `tests/test-nuclei-integration.sh` following pattern from `tests/test-a01-rules.sh`:

Sections:

1. **Docker Compose** — nuclei service exists in docker-compose.yml, has correct profile
2. **Job Dispatcher** — `run_nuclei` function exists, added to `run_tool()` switch, 3 modes supported
3. **Normalizer** — nuclei case exists, parses JSONL fixture correctly (4 findings, severity mapping)
4. **Skill Definition** — dast-scan SKILL.md mentions nuclei
5. **Summary**

Target: ~20 tests

**Step 3: Run tests**

```bash
bash tests/test-nuclei-integration.sh
```

Expected: All PASS

**Step 4: Commit**

```bash
git add tests/fixtures/sample-nuclei.jsonl tests/test-nuclei-integration.sh
git commit -m "test: add Nuclei integration test suite"
```

---

### Task C5: Extend DAST skill to support Nuclei

**Files:**

- Modify: `skills/dast-scan/SKILL.md`

**Step 1: Update frontmatter**

Change description to include Nuclei:

```yaml
description: Run Dynamic Application Security Testing using OWASP ZAP or Nuclei in Docker containers. Supports multiple scan modes. REQUIRES explicit user approval for target URL.
argument-hint: "<target-url> [--tool zap|nuclei] [--mode baseline|full|api|cve|custom] [--auth-token <token>] [--api-spec <path>]"
```

**Step 2: Add Nuclei scan modes table**

After existing ZAP modes table, add:

```markdown
### Nuclei Scan Modes

| Mode   | Templates     | Timeout | Use Case                         |
| ------ | ------------- | ------- | -------------------------------- |
| cve    | CVE/NVD only  | 120s    | Known vulnerability detection    |
| full   | All templates | 600s    | Comprehensive vulnerability scan |
| custom | User-provided | 300s    | Targeted template scanning       |
```

**Step 3: Add Nuclei output section to template**

Add Nuclei-specific output format description alongside ZAP output.

**Step 4: Commit**

```bash
git add skills/dast-scan/SKILL.md
git commit -m "feat: extend DAST skill to support Nuclei alongside ZAP"
```

---

## Phase D: Regulatory — NCSA 1.0 + PDPA (#42, #44)

### Task D1: Review and update NCSA validator

**Files:**

- Modify: `scripts/dast-ncsa-validator.sh`
- Modify: `tests/test-ncsa-validator.sh`

**Step 1: Review NCSA 1.0 checks**

Read the current validator and compare against NCSA Website Security Standards 1.0 published requirements. The validator currently checks:

- 1.x: HTTP Security Headers
- 2.x: Transport Security
- 4.x: Session Management

Verify completeness, add any missing checks (e.g., 3.x Access Control if in final spec, TLS 1.3 preference, Permissions-Policy header).

**Step 2: Add any missing checks**

If the published NCSA 1.0 standard includes additional requirements not currently covered, add them. Common additions:

- `Permissions-Policy` header (was Feature-Policy)
- TLS 1.3 as preferred (not just >= 1.2)
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy`

**Step 3: Update tests if checks changed**

```bash
bash tests/test-ncsa-validator.sh
```

Expected: All PASS

**Step 4: Commit**

```bash
git add scripts/dast-ncsa-validator.sh tests/test-ncsa-validator.sh
git commit -m "feat: review and update NCSA 1.0 validator against published standard"
```

---

### Task D2: Create PDPA compliance mapping

**Files:**

- Create: `mappings/cwe-to-pdpa.json`

**Step 1: Create the mapping file**

Follow exact structure from `mappings/cwe-to-owasp.json`:

```json
{
  "_meta": {
    "description": "CWE to Thailand PDPA (Personal Data Protection Act B.E. 2562) mapping",
    "source": "https://www.pdpc.or.th",
    "pdpa_version": "B.E. 2562 (2019)",
    "effective_date": "2022-06-01",
    "last_updated": "2026-03-XX"
  },
  "mappings": {
    "CWE-312": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Cleartext Storage of Sensitive Information",
      "requirement": "Appropriate security measures for personal data"
    },
    "CWE-311": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Missing Encryption of Sensitive Data",
      "requirement": "Appropriate security measures for personal data"
    },
    "CWE-359": {
      "pdpa": ["Section 23", "Section 26"],
      "category": "Consent & Sensitive Data",
      "name": "Exposure of Private Personal Information",
      "requirement": "Consent for collection, explicit consent for sensitive data"
    },
    "CWE-532": {
      "pdpa": ["Section 37(1)", "Section 37(4)"],
      "category": "Data Protection",
      "name": "Insertion of Sensitive Information into Log File",
      "requirement": "Prevent unauthorized access, maintain confidentiality"
    },
    "CWE-200": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Exposure of Sensitive Information to Unauthorized Actor",
      "requirement": "Appropriate security measures"
    },
    "CWE-209": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Generation of Error Message Containing Sensitive Information",
      "requirement": "Prevent information leakage"
    },
    "CWE-256": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Plaintext Storage of Password",
      "requirement": "Appropriate security measures for credentials"
    },
    "CWE-522": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Insufficiently Protected Credentials",
      "requirement": "Appropriate security measures for credentials"
    },
    "CWE-862": {
      "pdpa": ["Section 37(1)", "Section 37(3)"],
      "category": "Access Control",
      "name": "Missing Authorization",
      "requirement": "Access control for personal data"
    },
    "CWE-863": {
      "pdpa": ["Section 37(1)", "Section 37(3)"],
      "category": "Access Control",
      "name": "Incorrect Authorization",
      "requirement": "Correct access control for personal data"
    },
    "CWE-284": {
      "pdpa": ["Section 37(1)", "Section 37(3)"],
      "category": "Access Control",
      "name": "Improper Access Control",
      "requirement": "Restrict access to personal data"
    },
    "CWE-306": {
      "pdpa": ["Section 37(1)"],
      "category": "Authentication",
      "name": "Missing Authentication for Critical Function",
      "requirement": "Authentication before accessing personal data"
    },
    "CWE-287": {
      "pdpa": ["Section 37(1)"],
      "category": "Authentication",
      "name": "Improper Authentication",
      "requirement": "Proper authentication for personal data systems"
    },
    "CWE-319": {
      "pdpa": ["Section 37(1)", "Section 27"],
      "category": "Transport Security",
      "name": "Cleartext Transmission of Sensitive Information",
      "requirement": "Encryption for data transfer, cross-border protection"
    },
    "CWE-523": {
      "pdpa": ["Section 37(1)"],
      "category": "Transport Security",
      "name": "Unprotected Transport of Credentials",
      "requirement": "Secure transmission of authentication data"
    },
    "CWE-614": {
      "pdpa": ["Section 37(1)"],
      "category": "Session Security",
      "name": "Sensitive Cookie in HTTPS Session Without Secure Attribute",
      "requirement": "Session security for personal data access"
    },
    "CWE-384": {
      "pdpa": ["Section 37(1)"],
      "category": "Session Security",
      "name": "Session Fixation",
      "requirement": "Secure session management"
    },
    "CWE-778": {
      "pdpa": ["Section 37(4)", "Section 77"],
      "category": "Logging & Breach Detection",
      "name": "Insufficient Logging",
      "requirement": "Audit trail for breach detection, 72-hour notification"
    },
    "CWE-117": {
      "pdpa": ["Section 37(4)"],
      "category": "Logging & Breach Detection",
      "name": "Improper Output Neutralization for Logs",
      "requirement": "Log integrity for audit and breach investigation"
    },
    "CWE-89": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "SQL Injection",
      "requirement": "Prevent unauthorized data access"
    },
    "CWE-79": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Cross-site Scripting (XSS)",
      "requirement": "Prevent personal data theft via injection"
    },
    "CWE-918": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Server-Side Request Forgery (SSRF)",
      "requirement": "Prevent unauthorized access to internal personal data"
    },
    "CWE-502": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Deserialization of Untrusted Data",
      "requirement": "Prevent remote code execution accessing personal data"
    },
    "CWE-434": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Unrestricted Upload of File with Dangerous Type",
      "requirement": "Prevent malicious file upload compromising data"
    },
    "CWE-327": {
      "pdpa": ["Section 37(1)"],
      "category": "Cryptography",
      "name": "Use of a Broken or Risky Cryptographic Algorithm",
      "requirement": "Appropriate security measures including encryption"
    },
    "CWE-328": {
      "pdpa": ["Section 37(1)"],
      "category": "Cryptography",
      "name": "Use of Weak Hash",
      "requirement": "Strong cryptographic algorithms for personal data"
    },
    "CWE-321": {
      "pdpa": ["Section 37(1)"],
      "category": "Cryptography",
      "name": "Use of Hard-coded Cryptographic Key",
      "requirement": "Proper key management for personal data encryption"
    },
    "CWE-338": {
      "pdpa": ["Section 37(1)"],
      "category": "Cryptography",
      "name": "Use of Cryptographically Weak PRNG",
      "requirement": "Strong randomness for security-sensitive operations"
    },
    "CWE-601": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "URL Redirection to Untrusted Site (Open Redirect)",
      "requirement": "Prevent phishing of personal data via redirect"
    },
    "CWE-352": {
      "pdpa": ["Section 37(1)"],
      "category": "Data Protection",
      "name": "Cross-Site Request Forgery (CSRF)",
      "requirement": "Prevent unauthorized actions on personal data"
    }
  }
}
```

**Step 2: Validate JSON**

```bash
python3 -c "
import json
with open('mappings/cwe-to-pdpa.json') as f:
    data = json.load(f)
count = len(data['mappings'])
print(f'{count} CWE-to-PDPA mappings')
assert count >= 25, f'Expected at least 25 mappings, got {count}'
for key in data['mappings']:
    assert key.startswith('CWE-'), f'Invalid key: {key}'
    entry = data['mappings'][key]
    assert 'pdpa' in entry, f'{key} missing pdpa field'
    assert 'category' in entry, f'{key} missing category'
print('OK')
"
```

**Step 3: Commit**

```bash
git add mappings/cwe-to-pdpa.json
git commit -m "feat: add CWE-to-PDPA compliance mapping (30 CWEs)"
```

---

### Task D3: Add PDPA to MCP compliance_status tool

**Files:**

- Modify: `mcp/server.mjs` (~line 542 — frameworks array)

**Step 1: Add pdpa to frameworks array**

Find line 542:

```javascript
const frameworks = ["owasp", "nist", "mitre", "ncsa"];
```

Change to:

```javascript
const frameworks = ["owasp", "nist", "mitre", "ncsa", "pdpa"];
```

Also update tool description (~line 226):

```javascript
description: "Aggregate compliance status across all 5 frameworks (OWASP, NIST, MITRE, NCSA, PDPA) for a findings file.",
```

**Step 2: Rebuild MCP bundle**

```bash
cd mcp && bash build.sh && cd ..
```

**Step 3: Verify bundle**

```bash
grep -c "pdpa" mcp/dist/server.js
```

Expected: At least 2 matches

**Step 4: Commit**

```bash
git add mcp/server.mjs mcp/dist/server.js
git commit -m "feat: add PDPA framework to MCP compliance_status tool"
```

---

### Task D4: Create PDPA mapping tests

**Files:**

- Create: `tests/test-pdpa-mapping.sh`

**Step 1: Create test file**

Follow pattern from existing mapping tests. Sections:

1. **File Structure** — file exists, valid JSON, has `_meta` and `mappings`
2. **Required Fields** — every entry has `pdpa`, `category`, `name`
3. **CWE Format** — all keys match `CWE-\d+` pattern
4. **PDPA Section Format** — all pdpa values reference valid sections
5. **Cross-Reference** — spot-check key CWEs (CWE-312, CWE-89, CWE-79)
6. **MCP Integration** — pdpa appears in mcp/server.mjs frameworks array

Target: ~15 tests

**Step 2: Run**

```bash
bash tests/test-pdpa-mapping.sh
```

Expected: All PASS

**Step 3: Commit**

```bash
git add tests/test-pdpa-mapping.sh
git commit -m "test: add PDPA mapping validation test suite"
```

---

## Phase E: Custom Rules Wave 2 — A04/A10:2025 (#43)

### Task E1: Create A04 Insecure Design rules

**Files:**

- Create: `rules/a04-insecure-design-rules.yml`
- Create: `tests/fixtures/sample-a04-findings.json`

**Step 1: Create rule file with 4 rules**

Rules:

1. `a04-missing-rate-limit` — Auth endpoints without rate limiting (CWE-770)
2. `a04-unrestricted-upload` — File upload without type/size check (CWE-434)
3. `a04-trust-boundary` — User input used without validation in security context (CWE-501)
4. `a04-no-account-lockout` — Login without failed attempt tracking (CWE-307)

Each rule: `owasp: ["A04:2021", "A04:2025"]`

**Step 2: Create fixture, validate YAML**

**Step 3: Commit**

```bash
git add rules/a04-insecure-design-rules.yml tests/fixtures/sample-a04-findings.json
git commit -m "feat: add A04 Insecure Design custom Semgrep rules (4 rules)"
```

---

### Task E2: Create A10 Exception Handling rules

**Files:**

- Create: `rules/a10-exception-rules.yml`
- Create: `tests/fixtures/sample-a10-exception-findings.json`

**Step 1: Create rule file with 4 rules**

Rules:

1. `a10-generic-catch-python` — Bare `except:` without exception type (CWE-396)
2. `a10-generic-catch-javascript` — Empty `catch(e)` block (CWE-396)
3. `a10-stack-exposure` — Stack trace returned in HTTP response (CWE-209)
4. `a10-unhandled-promise` — Missing `.catch()` on promises (CWE-755)

Each rule: `owasp: ["A10:2025"]` (this is a NEW 2025 category — no 2021 equivalent)

**Note:** Existing `rules/a10-ssrf-rules.yml` stays as-is (A10:2021 SSRF, now also A01:2025). The new `a10-exception-rules.yml` covers A10:2025 (Exception Handling).

**Step 2: Create fixture, validate YAML**

**Step 3: Commit**

```bash
git add rules/a10-exception-rules.yml tests/fixtures/sample-a10-exception-findings.json
git commit -m "feat: add A10 Exception Handling custom Semgrep rules (4 rules)"
```

---

### Task E3: Create test suites for A04 and A10 Exception rules

**Files:**

- Create: `tests/test-a04-rules.sh`
- Modify: `tests/test-a10-rules.sh` (add section for exception handling rules)

**Step 1: Create A04 test file**

Follow exact pattern from Task B3. Key variables:

```bash
RULES_FILE="$ROOT_DIR/rules/a04-insecure-design-rules.yml"
FIXTURE="$ROOT_DIR/tests/fixtures/sample-a04-findings.json"
EXPECTED_RULES=4
```

**Step 2: Extend A10 test file**

Add new section to existing `tests/test-a10-rules.sh` for exception handling rules:

```bash
# ─── Section N: A10:2025 Exception Handling Rules ───
echo ""
echo "--- Section N: A10:2025 Exception Handling Rules ---"

EXCEPTION_RULES="$ROOT_DIR/rules/a10-exception-rules.yml"
[ -f "$EXCEPTION_RULES" ] && pass "a10-exception-rules.yml exists" || fail "..."

EXCEPTION_COUNT=$(python3 -c "
import yaml
with open('$EXCEPTION_RULES') as f:
    data = yaml.safe_load(f)
print(len(data.get('rules', [])))
")
[ "$EXCEPTION_COUNT" -eq 4 ] && pass "Contains 4 exception rules" || fail "..."
```

**Step 3: Run tests**

```bash
bash tests/test-a04-rules.sh && bash tests/test-a10-rules.sh
```

Expected: Both PASS

**Step 4: Commit**

```bash
git add tests/test-a04-rules.sh tests/test-a10-rules.sh
git commit -m "test: add A04 and A10:2025 Exception Handling test suites"
```

---

## Phase F: Release

### Task F1: Update validate-plugin.sh if needed

**Files:**

- Modify: `tests/validate-plugin.sh` (if hardcoded counts exist)

**Step 1: Check for hardcoded counts**

```bash
grep -n "13 skills\|EXPECTED.*=.*13\|rule.*count" tests/validate-plugin.sh
```

Update any hardcoded values that changed (e.g., skills count stays 13, but tools count goes from 7 to 8 if Nuclei counted).

**Step 2: Run full validation**

```bash
bash tests/validate-plugin.sh
```

Expected: All 258+ checks PASS

**Step 3: Commit if changed**

```bash
git add tests/validate-plugin.sh
git commit -m "chore: update validate-plugin.sh for v2.7.0 metrics"
```

---

### Task F2: Version bump and MCP rebuild

**Step 1: Bump version**

```bash
bash scripts/version-bump.sh 2.7.0
```

**Step 2: Rebuild MCP bundle**

```bash
cd mcp && bash build.sh && cd ..
```

**Step 3: Run release checklist**

```bash
bash scripts/release-checklist.sh 2.7.0
```

Expected: 31+ checks PASS (including Section 8 content accuracy)

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: release v2.7.0 — OWASP 2025 + Nuclei DAST + PDPA"
```

---

### Task F3: Update documentation

**Files:**

- Modify: `CHANGELOG.md` (add v2.7.0 entry)
- Modify: `README.md` (badges, test count, OWASP coverage)
- Modify: `docs/PRD.md` (current state → v2.7.0)

**Step 1: Add CHANGELOG entry**

```markdown
## [2.7.0] - 2026-XX-XX

### Added

- OWASP Top 10 2025 dual-version mapping (2021+2025) in cwe-to-owasp.json
- Custom Semgrep rules: A02 Cryptographic Failures (6 rules)
- Custom Semgrep rules: A05 Security Misconfiguration (6 rules)
- Custom Semgrep rules: A04 Insecure Design (4 rules)
- Custom Semgrep rules: A10 Exception Handling (4 rules)
- Nuclei DAST integration (Docker + dispatcher + normalizer)
- PDPA compliance mapping (30 CWEs, mappings/cwe-to-pdpa.json)
- PDPA support in MCP compliance_status tool
- 6 new test suites: test-a02, test-a04, test-a05, test-nuclei-integration, test-pdpa-mapping

### Changed

- OWASP 2025 tags added to all existing custom rules (a01, a03, a09, a10)
- DAST skill extended to support Nuclei alongside ZAP
- NCSA validator reviewed against published 1.0 standard
- frameworks.json: added owasp-top-10-2025 entry
```

**Step 2: Update README badges**

- Test count badge: update to actual count
- OWASP coverage: 8/10 (was 4/10)
- Tools: 8 (was 7)
- Frameworks: 5 (was 4)

**Step 3: Update PRD current state**

- Section header: v2.6.1 → v2.7.0
- Custom rules: 33 → ~53
- DAST tools: 1 → 2
- Compliance frameworks: 4 → 5
- Test suites: 22 → ~28
- CI/CD platforms: 3 (unchanged)

**Step 4: Commit**

```bash
git add CHANGELOG.md README.md docs/PRD.md
git commit -m "docs: update documentation for v2.7.0 release"
```

---

### Task F4: QA round and release

**Step 1: Run all tests**

```bash
bash tests/validate-plugin.sh
bash scripts/release-checklist.sh 2.7.0
```

Both must PASS.

**Step 2: Tag and release**

```bash
git tag -a v2.7.0 -m "v2.7.0 — OWASP 2025 Migration + Nuclei DAST + Thai Regulatory"
git push origin main --tags
gh release create v2.7.0 --title "v2.7.0 — OWASP 2025 + Nuclei DAST + PDPA" --notes-file RELEASE_NOTES.md
```

**Step 3: Create QA issue**

```bash
gh issue create --title "QA Round 11: v2.7.0" --milestone "v2.7.0"
```

**Step 4: Close milestone**

After QA passes, close milestone #2.

---

## Task Summary

| Phase     | Tasks  | Files Created | Files Modified | Tests Added |
| --------- | ------ | ------------- | -------------- | ----------- |
| A         | 4      | 0             | 6              | ~10         |
| B         | 3      | 6             | 0              | ~30         |
| C         | 5      | 3             | 4              | ~20         |
| D         | 4      | 2             | 2              | ~15         |
| E         | 3      | 4             | 1              | ~20         |
| F         | 4      | 0             | 5+             | 0           |
| **Total** | **23** | **15**        | **18+**        | **~95**     |

Expected final test count: ~900+ (793 existing + ~95 new + extended)
