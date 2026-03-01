# Secret Detection & Management Reference

# การตรวจจับและจัดการ Secrets

## Purpose / วัตถุประสงค์

This reference provides domain knowledge for DevSecOps agents performing secret detection,
rotation, and remediation. It covers common secret patterns, detection rules, vault integration,
and Git history cleanup procedures. Agents load this file on-demand when handling secret-related
findings from tools like Gitleaks, TruffleHog, or detect-secrets.

---

## 1. Common Secret Patterns / รูปแบบ Secret ที่พบบ่อย

### 1.1 API Keys & Tokens

| Provider         | Pattern (Regex)                               | Prefix Format      | Entropy |
| ---------------- | --------------------------------------------- | ------------------ | ------- |
| AWS Access Key   | `AKIA` followed by 16 uppercase alphanumerics | AKIA + 16 chars    | High    |
| AWS Secret Key   | 40-char base64 adjacent to Access Key         | base64-like 40char | High    |
| GCP Service Acct | JSON with `type: service_account`             | JSON key file      | N/A     |
| GCP API Key      | `AIza` followed by 35 mixed chars             | AIza + 35 chars    | High    |
| Azure Client Sec | GUID format 8-4-4-4-12 hex segments           | GUID pattern       | Medium  |
| GitHub PAT (new) | `ghp_` followed by 36 alphanumerics           | ghp\_ prefix       | High    |
| GitHub OAuth     | `gho_` followed by 36 alphanumerics           | gho\_ prefix       | High    |
| GitHub App Token | `ghu_` or `ghs_` followed by 36 chars         | ghu*/ghs* prefix   | High    |
| GitLab PAT       | `glpat-` followed by 20 mixed chars           | glpat- prefix      | High    |
| Slack Bot Token  | `xoxb-` followed by numeric + alphanumeric    | xoxb- prefix       | High    |
| Slack Webhook    | hooks.slack.com/services/T.../B.../...        | URL format         | Medium  |
| Stripe Live Key  | `sk_live_` followed by 24+ alphanumerics      | sk*live* prefix    | High    |
| Stripe Test Key  | `sk_test_` followed by 24+ alphanumerics      | sk*test* prefix    | High    |
| SendGrid Key     | `SG.` followed by base64 segments             | SG. prefix         | High    |
| Twilio Key       | `SK` followed by 32 hex characters            | SK + 32 hex        | High    |
| npm Token        | `npm_` followed by 36 alphanumerics           | npm\_ prefix       | High    |
| PyPI Token       | `pypi-` followed by 100+ mixed chars          | pypi- prefix       | High    |

### 1.2 Certificates & Private Keys

| Type                  | Detection Header (BEGIN marker) | Risk Level |
| --------------------- | ------------------------------- | ---------- |
| RSA Private Key       | BEGIN RSA PRIVATE KEY           | Critical   |
| EC Private Key        | BEGIN EC PRIVATE KEY            | Critical   |
| OpenSSH Private Key   | BEGIN OPENSSH PRIVATE KEY       | Critical   |
| PGP Private Key Block | BEGIN PGP PRIVATE KEY BLOCK     | Critical   |
| PKCS8 Private Key     | BEGIN PRIVATE KEY               | Critical   |
| Certificate (public)  | BEGIN CERTIFICATE               | Low        |
| X.509 CRL             | BEGIN X509 CRL                  | Info       |

### 1.3 Database & Connection Strings

| Type       | URI Scheme Pattern                             |
| ---------- | ---------------------------------------------- |
| PostgreSQL | `postgres(ql)://USER:PASS@HOST/DB`             |
| MySQL      | `mysql://USER:PASS@HOST/DB`                    |
| MongoDB    | `mongodb(+srv)://USER:PASS@HOST`               |
| Redis      | `redis://:PASS@HOST:PORT`                      |
| JDBC       | `jdbc:driver://HOST;user=...;password=...`     |
| ODBC       | `Pwd=... or Password=...` in connection string |

### 1.4 Generic High-Entropy Variable Patterns

Agents should flag variable assignments where:

- Name contains: `passwd`, `pwd`, `secret`, `token`, `access_key`, `auth`
- Value is a quoted string longer than 8 characters
- Entropy exceeds 3.5 bits per character (Shannon entropy)

Also flag environment variable exports and `.env` file entries with secret-like names.

---

## 2. Detection Rules & Configuration / กฎการตรวจจับ

### 2.1 Gitleaks v8.x Configuration

```toml
# .gitleaks.toml — Custom rules extending default ruleset
title = "Custom Secret Detection Rules"

[extend]
useDefault = true

[[rules]]
id = "custom-internal-token"
description = "Internal token pattern"
regex = '''MYAPP_KEY_[0-9a-f]{32}'''
secretGroup = 0
entropy = 3.5
keywords = ["MYAPP_KEY_"]

[allowlist]
description = "Global allowlist"
paths = [
    '''(^|/)vendor/''',
    '''(^|/)node_modules/''',
    '''\.gitleaks\.toml$''',
    '''(^|/)test(s)?/fixtures/''',
    '''\.md$''',
]
regexTarget = "match"
regexes = [
    '''EXAMPLE_''',
    '''REDACTED''',
    '''<YOUR_.*_HERE>''',
    '''(?i)placeholder''',
]
```

### 2.2 TruffleHog v3.x Usage

```bash
# Scan entire repository history
trufflehog git file://. --only-verified --json > findings.json

# Scan specific branch from a commit
trufflehog git file://. --branch=main --since-commit=COMMIT_SHA

# Scan filesystem (no git history)
trufflehog filesystem ./src --json

# Scan a GitHub organization
trufflehog github --org=mycompany --only-verified
```

### 2.3 detect-secrets v1.x Baseline

```bash
# Generate initial baseline
detect-secrets scan --all-files > .secrets.baseline

# Audit baseline (interactive review)
detect-secrets audit .secrets.baseline

# Update baseline after fixing
detect-secrets scan --baseline .secrets.baseline

# List all available plugins
detect-secrets scan --list-all-plugins
```

### 2.4 Pre-commit Hook Integration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]
```

---

## 3. Severity Classification / การจัดระดับความรุนแรง

| Severity | Criteria                                      | SLA      | Examples                            |
| -------- | --------------------------------------------- | -------- | ----------------------------------- |
| P0-Crit  | Active production credential exposed publicly | 1 hour   | Cloud root key on public repository |
| P1-High  | Valid credential in code, limited exposure    | 4 hours  | DB credential in private repository |
| P2-Med   | Expired/revoked credential still in history   | 24 hours | Old token in git log                |
| P3-Low   | Test/development credential in non-prod       | 1 week   | Test payment key in staging env     |
| P4-Info  | Potential false positive or placeholder       | Backlog  | Sample key in documentation         |

---

## 4. Rotation Procedures / ขั้นตอนการหมุนเวียน Secret

### 4.1 Rotation Checklist

```text
1. [ ] Identify all locations where the secret is consumed (code, CI/CD, config, infra)
2. [ ] Generate a new secret/credential through the provider console or API
3. [ ] Update the secret in the vault or secrets manager
4. [ ] Deploy applications that consume the secret
5. [ ] Verify applications function correctly with the new secret
6. [ ] Revoke/invalidate the old secret at the provider
7. [ ] Confirm the old secret no longer works (test revocation)
8. [ ] Update the secret detection baseline if applicable
9. [ ] Document the rotation in the incident log
```

### 4.2 Provider-Specific Rotation

**AWS IAM Access Keys:**

```bash
# Step 1: Create new key pair
aws iam create-access-key --user-name svc-myapp

# Step 2: Store new credentials in secrets manager
aws secretsmanager update-secret \
    --secret-id myapp/aws-creds \
    --secret-string '{"key_id":"NEW_VALUE","key_secret":"NEW_VALUE"}'

# Step 3: Deactivate old key (grace period for propagation)
aws iam update-access-key --user-name svc-myapp \
    --access-key-id OLD_KEY_ID --status Inactive

# Step 4: Delete old key after validation
aws iam delete-access-key --user-name svc-myapp \
    --access-key-id OLD_KEY_ID
```

**GitHub Personal Access Token:**

```bash
# Generate new token via GitHub Settings > Developer settings > PAT
# Then update CI/CD secrets:
gh secret set MY_TOKEN --body "$NEW_TOKEN_VALUE" --repo myorg/myrepo
# Revoke old token via GitHub Settings UI
```

**Database Credentials:**

```sql
-- PostgreSQL: Create new role, migrate, drop old
CREATE ROLE app_user_v2 WITH LOGIN;
ALTER ROLE app_user_v2 WITH ENCRYPTED PASSWORD 'ROTATED_VIA_VAULT';
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user_v2;
-- After migration verified:
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM app_user_v1;
DROP ROLE app_user_v1;
```

---

## 5. Vault Integration Patterns / รูปแบบการใช้งาน Vault

### 5.1 HashiCorp Vault

```hcl
# Policy for application secret access
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

path "database/creds/myapp-db" {
  capabilities = ["read"]
}
```

```bash
# Application reads secrets at runtime (never hardcoded)
vault kv get -format=json secret/data/myapp/config

# Dynamic database credentials (auto-rotated, TTL-based)
vault read database/creds/myapp-db
# Returns temporary username + credential with configurable TTL (e.g., 1h)
```

### 5.2 AWS Secrets Manager

```python
import boto3
import json

def get_secret(secret_name: str, region: str = "ap-southeast-1") -> dict:
    """Retrieve secret from AWS Secrets Manager at runtime."""
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])

# Enable automatic rotation with Lambda:
# aws secretsmanager rotate-secret --secret-id myapp/db-creds \
#     --rotation-lambda-arn arn:aws:lambda:REGION:ACCOUNT:function:rotate \
#     --rotation-rules AutomaticallyAfterDays=30
```

### 5.3 Kubernetes Secrets with External Secrets Operator (ESO v0.10+)

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: myapp-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: myapp-secrets
    creationPolicy: Owner
  data:
    - secretKey: db-credential
      remoteRef:
        key: myapp/database
        property: credential
    - secretKey: service-token
      remoteRef:
        key: myapp/api
        property: token
```

### 5.4 SOPS (Secrets OPerationS) for GitOps

```bash
# Encrypt a secrets file using age
sops --encrypt --age RECIPIENT_PUBLIC_KEY secrets.yaml > secrets.enc.yaml

# Decrypt at deploy time
sops --decrypt secrets.enc.yaml | kubectl apply -f -
```

```yaml
# .sops.yaml configuration
creation_rules:
  - path_regex: .*\.enc\.yaml$
    age: RECIPIENT_PUBLIC_KEY_VALUE
```

---

## 6. Git History Cleanup / การล้าง Secret จาก Git History

### 6.1 Using git-filter-repo (Recommended over BFG)

```bash
# Install
pip install git-filter-repo

# Remove a specific file from all history
git filter-repo --invert-paths --path config/secrets.yml

# Replace text patterns across all history using a replacements file
# Format per line: regex:PATTERN==>REPLACEMENT
git filter-repo --replace-text replacements.txt

# After cleanup: force-push and notify all contributors
git push --force --all
git push --force --tags
```

### 6.2 Using BFG Repo-Cleaner

```bash
# Remove files containing secrets
bfg --delete-files credentials.json

# Replace known secret values listed in a text file
bfg --replace-text known-values.txt

# Cleanup reflog and garbage collect
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### 6.3 Post-Cleanup Checklist / รายการตรวจสอบหลังล้าง History

```text
1. [ ] Force-push all affected branches
2. [ ] Delete and re-create all tags
3. [ ] Rotate the exposed credential immediately (MANDATORY — cleanup alone is NOT enough)
4. [ ] Contact GitHub/GitLab support to clear server-side caches
5. [ ] Notify all collaborators to re-clone (rebase will fail on rewritten history)
6. [ ] Run secret scan on cleaned history to verify complete removal
7. [ ] Update branch protection rules if force-push was temporarily allowed
8. [ ] Document the incident and timeline
```

---

## 7. False Positive Management / การจัดการ False Positive

### 7.1 Inline Suppression

```python
# Reading from vault — not a hardcoded secret
connection_url = get_from_vault("myapp/db")  # gitleaks:allow

# Sourced from environment variable at runtime
credential = os.environ["DB_CREDENTIAL"]  # nosec B105
```

### 7.2 Baseline Management

```bash
# Mark finding as false positive in detect-secrets baseline
detect-secrets audit .secrets.baseline
# Interactive: press 'n' for false positive, 'y' for true positive

# Gitleaks: use allowlist in .gitleaks.toml (see Section 2.1)
```

### 7.3 Common False Positive Categories

| Category                   | Example                       | Mitigation                     |
| -------------------------- | ----------------------------- | ------------------------------ |
| Example/placeholder values | `token: "YOUR_TOKEN_HERE"`    | Allowlist regex `YOUR_.*_HERE` |
| Test fixtures              | `test_value: "test_abc123"`   | Exclude `test/fixtures/` path  |
| Hash values (non-secret)   | `sha256: "a1b2c3d4..."`       | Adjust entropy threshold       |
| Package lock hashes        | Integrity hashes in lockfiles | Exclude `*lock*` files         |
| Documentation examples     | Docs with sample tokens       | Exclude `*.md`, `docs/` paths  |
| UUIDs                      | Standard GUID identifiers     | Tune GUID detection rule       |

---

## 8. CI/CD Pipeline Integration / การรวมเข้า CI/CD Pipeline

### 8.1 GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .gitleaks.toml
```

### 8.2 GitLab CI

```yaml
secret_detection:
  stage: test
  image: registry.gitlab.com/security-products/secrets:5
  variables:
    SECRET_DETECTION_HISTORIC_SCAN: "true"
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
```

### 8.3 Gate Decision Logic

```text
IF findings with severity >= HIGH exist:
    BLOCK pipeline
    NOTIFY security team via PagerDuty / Slack
    CREATE incident ticket automatically

ELIF findings with severity == MEDIUM exist:
    POST warning as PR comment
    REQUIRE manual approval from security reviewer

ELSE:
    PASS — log findings for audit trail
```

---

## 9. Metrics & KPIs / ตัวชี้วัด

| Metric                     | Target               | Measurement                       |
| -------------------------- | -------------------- | --------------------------------- |
| Mean Time to Detect (MTTD) | < 5 minutes          | Time from commit to scan alert    |
| Mean Time to Rotate (MTTR) | < 4 hours (P1)       | Time from detection to revocation |
| False Positive Rate        | < 10%                | FP findings / total findings      |
| Pre-commit Block Rate      | > 95% of new secrets | Secrets blocked before push       |
| Rotation Coverage          | 100% of P0/P1        | Rotated within SLA / total P0+P1  |

---

## References / แหล่งอ้างอิง

- Gitleaks v8: https://github.com/gitleaks/gitleaks
- TruffleHog v3: https://github.com/trufflesecurity/trufflehog
- detect-secrets v1.5: https://github.com/Yelp/detect-secrets
- git-filter-repo: https://github.com/newren/git-filter-repo
- BFG Repo-Cleaner: https://rtyley.github.io/bfg-repo-cleaner/
- HashiCorp Vault: https://developer.hashicorp.com/vault/docs
- AWS Secrets Manager: https://docs.aws.amazon.com/secretsmanager/
- External Secrets Operator: https://external-secrets.io/latest/
- SOPS: https://github.com/getsops/sops
- NIST SP 800-57 Rev.5 (Key Management): https://csrc.nist.gov/pubs/sp/800-57-pt1/r5/final
