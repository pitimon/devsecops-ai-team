# Demo Vulnerable Project

**WARNING: This project contains INTENTIONAL security vulnerabilities for demonstration and testing purposes. DO NOT deploy or use in production.**

## Purpose

This demo project serves as a scanning target for the `devsecops-ai-team` plugin. It contains realistic (but obviously fake) vulnerabilities across multiple categories so users can see how each security tool detects and reports findings.

## Expected Findings

### SAST (Semgrep) — `app.py`

| Finding                | CWE     | Severity | Line  | Description                           |
| ---------------------- | ------- | -------- | ----- | ------------------------------------- |
| SQL Injection          | CWE-89  | HIGH     | 41    | f-string interpolation in SQL query   |
| SQL Injection          | CWE-89  | HIGH     | 51    | String concatenation in SQL query     |
| Weak Crypto (MD5)      | CWE-327 | MEDIUM   | 58    | hashlib.md5 usage                     |
| Command Injection      | CWE-78  | HIGH     | 65    | os.system with user input             |
| Command Injection      | CWE-78  | HIGH     | 73    | os.popen with user input              |
| Sensitive Data in Logs | CWE-532 | MEDIUM   | 81    | Password logged in plaintext          |
| Hard-coded Credentials | CWE-798 | MEDIUM   | 30-31 | Connection string and token in source |
| Path Traversal         | CWE-22  | HIGH     | 90    | Unvalidated file path from user input |
| Debug Mode Enabled     | CWE-489 | LOW      | 95    | Flask debug=True in production        |

### SCA (Grype) — `package.json`

| Package              | Version | Known CVEs                     | Severity |
| -------------------- | ------- | ------------------------------ | -------- |
| lodash               | 4.17.15 | CVE-2020-28500, CVE-2021-23337 | HIGH     |
| express              | 4.16.0  | Multiple                       | MEDIUM   |
| jsonwebtoken         | 8.5.0   | CVE-2022-23529                 | HIGH     |
| minimist             | 1.2.0   | CVE-2021-44906                 | CRITICAL |
| node-fetch           | 2.6.0   | CVE-2022-0235                  | MEDIUM   |
| serialize-javascript | 2.1.0   | CVE-2020-7660                  | HIGH     |
| ejs                  | 3.1.5   | CVE-2022-29078                 | CRITICAL |

### Container (Trivy) — `Dockerfile`

| Finding             | Severity | Description                                |
| ------------------- | -------- | ------------------------------------------ |
| Outdated base image | CRITICAL | node:14 is EOL with known CVEs             |
| Running as root     | HIGH     | No USER directive — container runs as root |
| No HEALTHCHECK      | LOW      | Missing HEALTHCHECK instruction            |
| Unrestricted COPY   | MEDIUM   | COPY . . without .dockerignore             |

### Secrets (GitLeaks / TruffleHog) — `.env.example`

| Finding                      | File           | Description                                |
| ---------------------------- | -------------- | ------------------------------------------ |
| Database credential          | `.env.example` | DB_PASS with placeholder value             |
| SMTP credential              | `.env.example` | SMTP_PASS with placeholder value           |
| Cloud secret                 | `.env.example` | CLOUD_SECRET with placeholder value        |
| Hard-coded connection string | `app.py`       | PostgreSQL connection URI with credentials |

## Usage

### Quick scan with the plugin

```
Scan this project for SAST vulnerabilities: tests/fixtures/demo-project/
```

### Multi-tool pipeline

```
Run a full security pipeline on tests/fixtures/demo-project/
```

### Individual tool scans

```
Run SCA scan on tests/fixtures/demo-project/package.json
Scan the Dockerfile at tests/fixtures/demo-project/Dockerfile for container security issues
Check tests/fixtures/demo-project/ for hardcoded secrets
```

## File Structure

```
demo-project/
  README.md          — This file
  app.py             — Python Flask app with SAST vulnerabilities
  package.json       — Node.js dependencies with known CVEs
  Dockerfile         — Container config with security issues
  .env.example       — Environment config with credential patterns
```
