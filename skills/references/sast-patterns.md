# SAST Domain Knowledge Reference

# ความรู้อ้างอิงด้าน Static Application Security Testing

> **Purpose / วัตถุประสงค์**: Domain knowledge for the SAST agent to identify vulnerabilities through static code analysis. Covers CWE Top 25, Semgrep rule categories, language-specific vulnerability patterns, false positive identification, and severity classification.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: Semgrep v1.67+, CodeQL v2.16+, CWE v4.14

---

## 1. CWE Top 25 Most Dangerous Software Weaknesses (2024)

## รายการ CWE Top 25 ช่องโหว่ซอฟต์แวร์อันตรายที่สุด

| Rank | CWE ID  | Name                                         | CVSS Avg | Category       |
| ---- | ------- | -------------------------------------------- | -------- | -------------- |
| 1    | CWE-787 | Out-of-bounds Write                          | 8.2      | Memory Safety  |
| 2    | CWE-79  | Cross-site Scripting (XSS)                   | 6.1      | Injection      |
| 3    | CWE-89  | SQL Injection                                | 9.8      | Injection      |
| 4    | CWE-416 | Use After Free                               | 8.8      | Memory Safety  |
| 5    | CWE-78  | OS Command Injection                         | 9.8      | Injection      |
| 6    | CWE-20  | Improper Input Validation                    | 7.5      | Input Handling |
| 7    | CWE-125 | Out-of-bounds Read                           | 7.1      | Memory Safety  |
| 8    | CWE-22  | Path Traversal                               | 7.5      | File Handling  |
| 9    | CWE-352 | Cross-Site Request Forgery                   | 8.0      | Session Mgmt   |
| 10   | CWE-434 | Unrestricted File Upload                     | 9.8      | File Handling  |
| 11   | CWE-862 | Missing Authorization                        | 8.2      | Access Control |
| 12   | CWE-476 | NULL Pointer Dereference                     | 7.5      | Memory Safety  |
| 13   | CWE-287 | Improper Authentication                      | 9.8      | AuthN          |
| 14   | CWE-190 | Integer Overflow                             | 7.8      | Memory Safety  |
| 15   | CWE-502 | Deserialization of Untrusted Data            | 9.8      | Data Handling  |
| 16   | CWE-77  | Command Injection                            | 9.8      | Injection      |
| 17   | CWE-119 | Buffer Overflow                              | 9.8      | Memory Safety  |
| 18   | CWE-798 | Hard-coded Credentials                       | 9.8      | Secrets        |
| 19   | CWE-918 | Server-Side Request Forgery                  | 7.5      | Injection      |
| 20   | CWE-306 | Missing Authentication for Critical Function | 9.8      | AuthN          |
| 21   | CWE-362 | Race Condition                               | 7.0      | Concurrency    |
| 22   | CWE-269 | Improper Privilege Management                | 8.8      | Access Control |
| 23   | CWE-94  | Code Injection                               | 9.8      | Injection      |
| 24   | CWE-863 | Incorrect Authorization                      | 8.2      | Access Control |
| 25   | CWE-276 | Incorrect Default Permissions                | 7.8      | Access Control |

---

## 2. Semgrep Rule Categories and Configuration

## หมวดหมู่กฎ Semgrep และการตั้งค่า

### Rule Registry Structure (semgrep.dev/r)

```yaml
# .semgrep.yml - Recommended SAST configuration
rules:
  # Auto registry rules (curated rulesets)
  - p/default # General-purpose security
  - p/owasp-top-ten # OWASP Top 10 2021
  - p/cwe-top-25 # CWE Top 25
  - p/security-audit # Deeper audit checks
  - p/secrets # Secret detection
  - p/supply-chain # Dependency checks

  # Language-specific rulesets
  - p/python # Python security + best practices
  - p/javascript # JS/TS security
  - p/java # Java security
  - p/golang # Go security
  - p/rust # Rust security patterns
```

### Semgrep Severity Mapping

| Semgrep Level | CVSS Range | Action Required           | SLA      |
| ------------- | ---------- | ------------------------- | -------- |
| ERROR         | 7.0 - 10.0 | Block PR, mandatory fix   | 24 hours |
| WARNING       | 4.0 - 6.9  | Flag for review           | 7 days   |
| INFO          | 0.1 - 3.9  | Track, fix in next sprint | 30 days  |

### Custom Rule Example — Detecting Unsafe Deserialization

```yaml
rules:
  - id: unsafe-pickle-load
    patterns:
      - pattern: pickle.loads($DATA)
      - pattern-not-inside: |
          if is_trusted_source($DATA):
              ...
    message: >
      Unsafe deserialization via pickle.loads(). Use json.loads()
      or implement allowlist-based deserialization. CWE-502.
    severity: ERROR
    metadata:
      cwe: ["CWE-502"]
      owasp: ["A08:2021"]
      confidence: HIGH
```

---

## 3. Vulnerability Patterns by Language

## รูปแบบช่องโหว่แยกตามภาษา

### 3.1 SQL Injection (CWE-89)

**Python (SQLAlchemy / raw SQL)**

```python
# VULNERABLE - String concatenation in query
query = f"SELECT * FROM users WHERE id = {user_input}"
cursor.execute(query)

# SAFE - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# SAFE - SQLAlchemy ORM
User.query.filter_by(id=user_input).first()
```

**JavaScript/TypeScript (Prisma / Knex / raw)**

```javascript
// VULNERABLE - Template literal in query
const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);

// SAFE - Parameterized
const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

// SAFE - Prisma ORM
const user = await prisma.user.findUnique({ where: { id: userId } });
```

**Go (database/sql)**

```go
// VULNERABLE - fmt.Sprintf in query
query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
db.Query(query)

// SAFE - Parameterized
db.Query("SELECT * FROM users WHERE id = $1", userID)
```

### 3.2 Cross-Site Scripting / XSS (CWE-79)

**React/JSX**

```jsx
// VULNERABLE - dangerouslySetInnerHTML with user input
<div dangerouslySetInnerHTML={{ __html: userComment }} />

// SAFE - React auto-escapes by default
<div>{userComment}</div>

// SAFE - DOMPurify sanitization when HTML is needed
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userComment) }} />
```

**Python (Jinja2)**

```python
# VULNERABLE - Markup.safe() or |safe filter on user data
return Markup(f"<p>{user_input}</p>")

# SAFE - Jinja2 auto-escaping (enabled by default)
return render_template("page.html", content=user_input)
```

### 3.3 Server-Side Request Forgery / SSRF (CWE-918)

```python
# VULNERABLE - Unvalidated URL from user
response = requests.get(user_provided_url)

# SAFE - URL allowlist validation
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def safe_fetch(url: str):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS allowed")
    # Block private IP ranges
    ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Private IP not allowed")
    return requests.get(url, timeout=10)
```

### 3.4 Path Traversal (CWE-22)

```python
# VULNERABLE
file_path = os.path.join("/uploads", user_filename)
with open(file_path) as f: ...

# SAFE - Resolve and verify prefix
base = Path("/uploads").resolve()
target = (base / user_filename).resolve()
if not str(target).startswith(str(base)):
    raise ValueError("Path traversal detected")
```

### 3.5 Hard-coded Credentials (CWE-798)

```python
# VULNERABLE - Patterns to detect (examples use placeholder format)
# Pattern: variable_name = "<prefix>-<random-looking-string>"
# Examples the scanner looks for:
#   API_KEY = "sk-proj-..." (OpenAI-style key pattern)
#   DATABASE_URL = "postgresql://user:pass@host/db"
#   AWS_SECRET_ACCESS_KEY = "wJalrX..." (AWS key pattern)

# SAFE - Environment variables or secret manager
API_KEY = os.environ["API_KEY"]
DATABASE_URL = os.environ.get("DATABASE_URL")
secret = boto3.client("secretsmanager").get_secret_value(SecretId="myapp/prod")
```

### 3.6 Detection Regex Patterns for Secret Scanning

```
High-confidence patterns:
  AWS Access Key ID:        AKIA[0-9A-Z]{16}
  AWS Secret Key:           [A-Za-z0-9/+=]{40} (near AWS context)
  GitHub Token:             gh[ps]_[A-Za-z0-9_]{36,}
  GitLab Token:             glpat-[A-Za-z0-9\-_]{20,}
  Google API Key:           AIza[0-9A-Za-z\-_]{35}
  Slack Bot Token:          xoxb-[0-9]{10,}-[A-Za-z0-9]{24,}
  Stripe Key:               [rs]k_(live|test)_[A-Za-z0-9]{24,}
  Generic high-entropy:     [A-Za-z0-9+/]{40,}= (Base64, near key context)
  Private Key header:       -----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----
  Connection string:        (mysql|postgresql|mongodb)://[^:]+:[^@]+@
```

---

## 4. False Positive Identification Guidelines

## แนวทางการระบุ False Positive

### Common False Positive Categories

| Category                 | Description                          | Example                                   | Resolution                                     |
| ------------------------ | ------------------------------------ | ----------------------------------------- | ---------------------------------------------- |
| **Test Code**            | Vulnerability in test fixtures       | Hardcoded test credentials in `test_*.py` | Suppress with `# nosemgrep` + comment          |
| **Dead Code**            | Vulnerable code in unreachable paths | Deprecated function with SQL concat       | Verify unreachability, then suppress or remove |
| **Framework Protection** | Framework auto-sanitizes             | React JSX auto-escaping                   | Confirm framework version, suppress            |
| **Validated Input**      | Input is validated upstream          | SQL with pre-validated enum               | Trace data flow, suppress with evidence        |
| **Documentation**        | Code samples in docs/comments        | SQL injection example in docstring        | Exclude doc paths in config                    |

### Suppression Best Practices

```python
# Correct suppression with justification
password_hash = bcrypt.hash(password)  # nosemgrep: hardcoded-credential
# Reason: variable named 'password' but contains hash, not plaintext

# Semgrep ignore file (.semgrepignore)
# Test fixtures
tests/fixtures/
test_data/

# Generated code
*_generated.py
*.pb.go

# Documentation
docs/examples/
```

### Data Flow Analysis Checklist

1. **Source identification**: Where does the tainted data originate? (request params, headers, body, env vars)
2. **Propagation tracking**: Does the data pass through sanitizers or validators?
3. **Sink analysis**: Is the sink actually exploitable with the data that reaches it?
4. **Context sensitivity**: Does the framework or library provide automatic protection?
5. **Reachability**: Can the vulnerable code path actually be triggered in production?

---

## 5. Severity Classification Guidelines

## แนวทางการจัดระดับความรุนแรง

### Classification Matrix

```
CRITICAL (CVSS 9.0-10.0):
  - Remote Code Execution (RCE) via deserialization, eval, command injection
  - SQL injection on authentication or admin endpoints
  - Hard-coded production credentials or private keys
  - Authentication bypass affecting all users

HIGH (CVSS 7.0-8.9):
  - SQL injection on non-auth endpoints
  - Stored XSS in shared contexts
  - SSRF with internal network access
  - Path traversal with file read
  - Missing authorization on sensitive operations

MEDIUM (CVSS 4.0-6.9):
  - Reflected XSS requiring social engineering
  - CSRF on state-changing non-critical operations
  - Information disclosure (stack traces, version info)
  - Weak cryptographic algorithms (SHA1 for signatures)

LOW (CVSS 0.1-3.9):
  - Self-XSS (affects only the attacker)
  - Verbose error messages in non-production
  - Missing security headers (non-critical)
  - Outdated dependency with no known exploit
```

### Context Modifiers

| Factor                      | Severity Adjustment | Rationale                |
| --------------------------- | ------------------- | ------------------------ |
| Internet-facing             | +1 level            | Larger attack surface    |
| Handles PII/financial       | +1 level            | Higher impact            |
| Behind VPN/auth             | -1 level            | Reduced exposure         |
| Test/dev environment        | -1 level            | Non-production           |
| Compensating control exists | -1 level            | Mitigated risk           |
| Proof of exploit available  | +1 level            | Confirmed exploitability |

---

## 6. SAST Tool Integration Matrix

## เมทริกซ์การผสมผสานเครื่องมือ SAST

| Tool                  | Languages     | Speed | Depth           | Best For                  |
| --------------------- | ------------- | ----- | --------------- | ------------------------- |
| Semgrep v1.67+        | 30+ languages | Fast  | Pattern-based   | CI/CD gates, custom rules |
| CodeQL v2.16+         | 12 languages  | Slow  | Deep data flow  | Complex vuln chains       |
| Bandit v1.7+          | Python only   | Fast  | AST-based       | Python-specific checks    |
| ESLint Security v2.1+ | JS/TS         | Fast  | AST-based       | JS/TS in existing ESLint  |
| Gosec v2.19+          | Go only       | Fast  | AST-based       | Go-specific patterns      |
| Brakeman v6.1+        | Ruby/Rails    | Fast  | Framework-aware | Rails applications        |

### Recommended Multi-Tool Strategy

```
Phase 1 (PR Gate — <2 min): Semgrep with p/default + p/secrets
Phase 2 (Nightly — <30 min): CodeQL full analysis + Semgrep p/security-audit
Phase 3 (Release — <60 min): All tools + manual review of CRITICAL/HIGH
```

---

## 7. SARIF Output and Integration

## รูปแบบผลลัพธ์ SARIF และการเชื่อมต่อ

### Standard SARIF v2.1.0 Fields for Triage

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "semgrep", "version": "1.67.0" } },
      "results": [
        {
          "ruleId": "python.lang.security.audit.dangerous-system-call",
          "level": "error",
          "message": { "text": "OS command injection via subprocess" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/api/handler.py" },
                "region": { "startLine": 42, "startColumn": 5 }
              }
            }
          ],
          "fingerprints": { "matchBasedId/v1": "abc123..." }
        }
      ]
    }
  ]
}
```

### GitHub Code Scanning Integration

```yaml
# .github/workflows/sast.yml
- name: Run Semgrep
  uses: semgrep/semgrep-action@v1
  with:
    config: >-
      p/default
      p/owasp-top-ten
    generateSarif: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: semgrep.sarif
```

---

## 8. Custom OWASP Detection Rules

## กฎตรวจจับ OWASP แบบกำหนดเอง

### A01:2021 Broken Access Control — Custom Rules

The plugin includes 8 custom Semgrep rules targeting A01 anti-patterns:

| Rule ID                          | CWE     | Severity | Languages | Description                      |
| -------------------------------- | ------- | -------- | --------- | -------------------------------- |
| a01-missing-auth-decorator       | CWE-862 | ERROR    | Python    | Missing authentication decorator |
| a01-missing-auth-middleware-js   | CWE-862 | ERROR    | JS/TS     | Missing auth middleware          |
| a01-missing-auth-annotation-java | CWE-862 | ERROR    | Java      | Missing @PreAuthorize            |
| a01-direct-object-reference      | CWE-639 | WARNING  | Python    | IDOR without ownership check     |
| a01-direct-object-reference-js   | CWE-639 | WARNING  | JS/TS     | IDOR without ownership check     |
| a01-path-traversal               | CWE-22  | ERROR    | Python    | User input in file paths         |
| a01-cors-wildcard                | CWE-942 | WARNING  | Python    | CORS origin: \*                  |
| a01-privilege-escalation         | CWE-269 | ERROR    | Python    | Unprotected role modification    |

Rules file: `rules/a01-access-control-rules.yml`

### A03:2021 Injection — Custom Rules

11 custom Semgrep rules targeting A03 injection patterns:

| Rule ID                   | CWE      | Severity | Languages | Description                 |
| ------------------------- | -------- | -------- | --------- | --------------------------- |
| a03-sql-injection         | CWE-89   | ERROR    | Python    | SQL with f-strings          |
| a03-sql-injection-js      | CWE-89   | ERROR    | JS/TS     | SQL with template literals  |
| a03-sql-injection-java    | CWE-89   | ERROR    | Java      | SQL string concatenation    |
| a03-command-injection     | CWE-78   | ERROR    | Python    | os.system/subprocess        |
| a03-command-injection-js  | CWE-78   | ERROR    | JS/TS     | child_process.exec          |
| a03-xss-dom               | CWE-79   | ERROR    | JS/TS     | innerHTML from user input   |
| a03-xss-reflected         | CWE-79   | WARNING  | Python    | Jinja2 Markup/safe          |
| a03-xss-reflected-java    | CWE-79   | WARNING  | Java      | Direct response.write       |
| a03-ldap-injection        | CWE-90   | ERROR    | Python    | LDAP filter with user input |
| a03-template-injection    | CWE-1336 | ERROR    | Python    | Jinja2/Mako SSTI            |
| a03-template-injection-js | CWE-1336 | ERROR    | JS/TS     | eval/Function constructor   |

Rules file: `rules/a03-injection-rules.yml`

---

## 9. Quick Reference — Detection Rule Priority

## อ้างอิงด่วน — ลำดับความสำคัญกฎตรวจจับ

```
Priority 1 (Always Block):
  - CWE-78/77  Command Injection
  - CWE-89     SQL Injection
  - CWE-502    Unsafe Deserialization
  - CWE-798    Hard-coded Credentials
  - CWE-287    Authentication Bypass

Priority 2 (Block if internet-facing):
  - CWE-79     XSS (Stored)
  - CWE-918    SSRF
  - CWE-22     Path Traversal
  - CWE-434    Unrestricted Upload
  - CWE-862    Missing Authorization

Priority 3 (Warn and Track):
  - CWE-352    CSRF
  - CWE-79     XSS (Reflected)
  - CWE-200    Information Disclosure
  - CWE-327    Weak Cryptography
  - CWE-611    XXE
```

---

## 9. A10:2021 Server-Side Request Forgery — Custom Rules

## กฎตรวจจับ SSRF แบบกำหนดเอง

7 custom Semgrep rules targeting SSRF anti-patterns:

| Rule ID                    | CWE     | Severity | Languages | Description                    |
| -------------------------- | ------- | -------- | --------- | ------------------------------ |
| a10-ssrf-user-url-python   | CWE-918 | ERROR    | Python    | Unvalidated URL in requests    |
| a10-ssrf-user-url-js       | CWE-918 | ERROR    | JS/TS     | Unvalidated URL in fetch/axios |
| a10-ssrf-user-url-java     | CWE-918 | ERROR    | Java      | Unvalidated URL in HttpClient  |
| a10-ssrf-metadata-endpoint | CWE-918 | ERROR    | Multi     | Cloud metadata endpoint access |
| a10-ssrf-redirect-follow   | CWE-918 | WARNING  | Python    | Missing redirect control       |
| a10-ssrf-dns-rebinding     | CWE-918 | WARNING  | Multi     | DNS rebinding risk             |
| a10-ssrf-internal-ip       | CWE-918 | WARNING  | Multi     | Private IP range in URLs       |

Rules file: `rules/a10-ssrf-rules.yml`

### SSRF Mitigation Checklist

- URL allowlist validation (hostname + scheme)
- Block private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
- Disable HTTP redirects or validate redirect targets
- DNS resolution pinning (resolve once, connect to resolved IP)
- Network segmentation (outbound firewall rules)
