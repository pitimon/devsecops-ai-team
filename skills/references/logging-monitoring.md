# Security Logging & Monitoring Patterns

> **วัตถุประสงค์**: แนวทางป้องกัน Security Logging & Monitoring Failures (OWASP A09:2021) — ครอบคลุม structured logging, security event taxonomy, log injection prevention, audit trail requirements, และ alerting patterns
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: OWASP A09:2021, NIST 800-53 AU family, CWE-117/223/390/532/778/779

---

## 1. ภาพรวม A09 (Overview)

A09:2021 Security Logging and Monitoring Failures เป็น OWASP category ที่มี tool coverage ต่ำที่สุด เนื่องจากต้องอาศัย runtime analysis และ code review ร่วมกัน ปัญหาหลัก:

- ไม่มี logging สำหรับ security-relevant events (CWE-778)
- Log injection ทำให้ log data ถูก tamper (CWE-117)
- Log เก็บข้อมูลมากเกินไป รวมถึง PII/secrets (CWE-532, CWE-779)
- ไม่ตรวจจับ error conditions (CWE-390)
- ละเว้น security-relevant information จาก log (CWE-223)

### CWE Coverage

| CWE     | ชื่อ                                        | Detection    | Severity |
| ------- | ------------------------------------------- | ------------ | -------- |
| CWE-117 | Improper Output Neutralization for Logs     | SAST         | MEDIUM   |
| CWE-223 | Omission of Security-relevant Information   | Code review  | MEDIUM   |
| CWE-390 | Detection of Error Condition Without Action | SAST         | MEDIUM   |
| CWE-532 | Information Exposure Through Log Files      | SAST, Secret | HIGH     |
| CWE-778 | Insufficient Logging                        | Code review  | MEDIUM   |
| CWE-779 | Logging of Excessive Data                   | SAST, DAST   | MEDIUM   |

---

## 2. Security Event Taxonomy

### 2.1 Events ที่ต้อง Log เสมอ (MUST Log)

| Category             | Events                                              | NIST Control |
| -------------------- | --------------------------------------------------- | ------------ |
| Authentication       | Login success/failure, password reset, MFA events   | AU-2, IA-5   |
| Authorization        | Access denied, privilege escalation, role change    | AU-2, AC-6   |
| Input validation     | Rejected input, SQL injection attempt, XSS attempt  | AU-2, SI-10  |
| Data access          | Sensitive data read/write/delete, bulk export       | AU-3, AU-12  |
| Configuration change | Admin actions, policy changes, feature toggle       | AU-3, CM-3   |
| Session management   | Session creation, invalidation, timeout, hijack     | AU-2, SC-23  |
| Error conditions     | Unhandled exceptions, service failures, rate limits | AU-6, SI-4   |

### 2.2 Structured Log Format

```json
{
  "timestamp": "2026-03-02T10:15:30.123Z",
  "level": "WARN",
  "event": "AUTH_FAILURE",
  "source": "auth-service",
  "actor": {
    "user_id": "usr_abc123",
    "ip": "203.0.113.42",
    "user_agent": "Mozilla/5.0..."
  },
  "action": "login",
  "outcome": "failure",
  "reason": "invalid_password",
  "metadata": {
    "attempt_count": 3,
    "account_locked": false
  }
}
```

**Key fields ที่ต้องมี:**

- `timestamp` — ISO 8601 with timezone
- `level` — DEBUG/INFO/WARN/ERROR/CRITICAL
- `event` — machine-readable event type
- `actor` — who performed the action (user, service, IP)
- `action` — what was attempted
- `outcome` — success/failure/error

---

## 3. Log Injection Prevention (CWE-117)

### 3.1 Attack Pattern

```python
# Attacker sends username containing newline + fake log entry
username = "admin\n2026-03-02 INFO Login successful for admin"

# Vulnerable logging
logger.info(f"Login attempt for {username}")
# Output:
#   2026-03-02 INFO Login attempt for admin
#   2026-03-02 INFO Login successful for admin  <-- INJECTED
```

### 3.2 Prevention Patterns

**Python:**

```python
import logging
import re

# Option 1: Sanitize input before logging
def sanitize_log(value):
    return re.sub(r'[\n\r\t]', '_', str(value))

logger.info("Login attempt for %s", sanitize_log(username))

# Option 2: Use structured logging (preferred)
import structlog
logger = structlog.get_logger()
logger.info("login_attempt", username=username)  # Auto-escaped
```

**Java:**

```java
// Vulnerable
logger.info("Login attempt for " + username);

// Fixed: use parameterized logging (SLF4J)
logger.info("Login attempt for {}", username);

// Fixed: use OWASP encoder for extra safety
import org.owasp.encoder.Encode;
logger.info("Login attempt for {}", Encode.forJava(username));
```

**Node.js:**

```javascript
// Vulnerable
console.log(`Login attempt for ${username}`);

// Fixed: use structured logger (pino/winston)
const pino = require("pino");
const logger = pino();
logger.info({ username }, "login_attempt");
```

### 3.3 Semgrep Rule for Detection

```yaml
rules:
  - id: log-injection
    patterns:
      - pattern-either:
          - pattern: logger.info(f"...$VAR...")
          - pattern: logger.warning(f"...$VAR...")
          - pattern: console.log(`...${{...}}...`)
    message: "Potential log injection: use structured logging or sanitize input"
    severity: WARNING
    metadata:
      cwe: ["CWE-117"]
      owasp: ["A09:2021"]
```

---

## 4. Sensitive Data in Logs (CWE-532)

### 4.1 Data ที่ห้าม Log

| Category        | Examples                                    | Risk                     |
| --------------- | ------------------------------------------- | ------------------------ |
| Credentials     | Passwords, API keys, tokens, session IDs    | Account takeover         |
| PII             | SSN, passport, credit card, phone number    | Privacy violation        |
| PHI             | Medical records, health status              | HIPAA/PDPA violation     |
| Secrets         | Encryption keys, private keys, certificates | Cryptographic compromise |
| Security tokens | JWT, OAuth tokens, CSRF tokens              | Session hijack           |

### 4.2 Prevention Patterns

```python
# Bad: logging sensitive data
logger.info(f"User {email} authenticated with token {auth_token}")

# Good: mask sensitive fields
logger.info("User %s authenticated", email)

# Good: use redaction middleware
import structlog
def redact_processor(logger, method_name, event_dict):
    for key in ('password', 'token', 'secret', 'api_key', 'authorization'):
        if key in event_dict:
            event_dict[key] = '***REDACTED***'
    return event_dict

structlog.configure(processors=[redact_processor, structlog.dev.ConsoleRenderer()])
```

### 4.3 GitLeaks Integration

Secret scanning tools (GitLeaks) can detect credentials in log files:

```bash
# Scan log directory for leaked secrets
docker run --rm -v /var/log/app:/scan \
  zricethezav/gitleaks:latest detect --source /scan --no-git
```

---

## 5. Insufficient Logging Detection (CWE-778)

### 5.1 Audit Checklist

| Area                  | Check                                  | Status |
| --------------------- | -------------------------------------- | ------ |
| Authentication events | Login, logout, failed attempts logged? |        |
| Authorization denials | 403/401 responses logged with context? |        |
| Input validation      | Rejected inputs logged?                |        |
| Admin actions         | Configuration changes tracked?         |        |
| Data access           | Sensitive data access audited?         |        |
| Error handling        | Exceptions logged with stack trace?    |        |
| Rate limiting         | Throttled requests logged?             |        |

### 5.2 Framework-Specific Patterns

**Django:**

```python
# settings.py — enable security logging
LOGGING = {
    'version': 1,
    'loggers': {
        'django.security': {
            'handlers': ['security_file'],
            'level': 'WARNING',
        },
        'django.request': {
            'handlers': ['security_file'],
            'level': 'WARNING',
        },
    }
}
```

**Express:**

```javascript
// Middleware: log security events
const morgan = require("morgan");
app.use(morgan(":method :url :status :response-time ms - :remote-addr"));

// Custom security event logger
app.use((req, res, next) => {
  res.on("finish", () => {
    if (res.statusCode === 401 || res.statusCode === 403) {
      logger.warn({
        event: "AUTH_DENIAL",
        method: req.method,
        url: req.url,
        ip: req.ip,
        status: res.statusCode,
      });
    }
  });
  next();
});
```

**Spring:**

```java
// Enable Spring Security event logging
@Configuration
public class SecurityAuditConfig {
    @Bean
    public AuthenticationEventPublisher authEventPublisher(
            ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }
}

@EventListener
public void onAuthFailure(AbstractAuthenticationFailureEvent event) {
    logger.warn("AUTH_FAILURE: {} - {}",
        event.getAuthentication().getName(),
        event.getException().getMessage());
}
```

---

## 6. Error Handling Without Action (CWE-390)

```python
# Vulnerable: silently ignoring errors
try:
    process_payment(order)
except Exception:
    pass  # CWE-390: error swallowed silently

# Fixed: log and handle
try:
    process_payment(order)
except PaymentError as e:
    logger.error("Payment failed", order_id=order.id, error=str(e))
    notify_ops_team(order, e)
    raise
```

```javascript
// Vulnerable: empty catch
try {
  await processPayment(order);
} catch (e) {
  /* ignore */
} // CWE-390

// Fixed: log and propagate
try {
  await processPayment(order);
} catch (e) {
  logger.error({ orderId: order.id, error: e.message }, "payment_failed");
  throw e;
}
```

---

## 7. Log Retention & SIEM Integration

### 7.1 Retention Requirements

| Standard   | Minimum Retention | Recommended     |
| ---------- | ----------------- | --------------- |
| NIST AU-11 | 90 days online    | 1 year archived |
| PCI-DSS    | 1 year            | 1 year online   |
| PDPA       | As needed         | Follow policy   |
| SOC 2      | 1 year            | 1 year          |

### 7.2 SIEM Correlation Rules

```yaml
# Example: brute force detection rule
name: brute_force_login
condition: count(event="AUTH_FAILURE" AND same(actor.user_id)) > 5 within 5m
severity: HIGH
action:
  - alert: security-team
  - block: actor.ip for 30m
```

### 7.3 Alerting Thresholds

| Event                        | Threshold          | Alert Level |
| ---------------------------- | ------------------ | ----------- |
| Failed logins (same user)    | > 5 in 5 minutes   | HIGH        |
| Failed logins (same IP)      | > 20 in 10 minutes | CRITICAL    |
| Privilege escalation attempt | Any                | CRITICAL    |
| Bulk data export             | > 1000 records     | HIGH        |
| Admin action outside hours   | Any                | MEDIUM      |
| Error rate spike             | > 5x baseline      | HIGH        |

---

## 8. Custom Semgrep Rules for A09 Detection

The DevSecOps AI Team includes custom Semgrep rules targeting A09 anti-patterns at `rules/a09-logging-rules.yml`. These rules are automatically loaded by `job-dispatcher.sh` when running SAST scans.

### Rule Inventory (7 rules, 5 categories)

| Rule ID                          | CWE     | Severity | Languages | Pattern                                |
| -------------------------------- | ------- | -------- | --------- | -------------------------------------- |
| `a09-missing-auth-logging`       | CWE-778 | WARNING  | Python    | Auth functions without audit log calls |
| `a09-catch-without-logging`      | CWE-390 | WARNING  | Python    | try/except that swallow errors         |
| `a09-catch-without-logging-js`   | CWE-390 | WARNING  | JS/TS     | Empty try/catch blocks                 |
| `a09-sensitive-data-in-log`      | CWE-532 | ERROR    | Python    | PII/secrets in f-string/% logs         |
| `a09-sensitive-data-in-log-js`   | CWE-532 | ERROR    | JS/TS     | PII/secrets in template literal logs   |
| `a09-log-injection`              | CWE-117 | WARNING  | Python    | Request data in f-string logs          |
| `a09-missing-rate-limit-logging` | CWE-778 | INFO     | Python    | Rate limit events without logging      |

### Languages Covered

- **Python** — 5 rules (structlog, logging module patterns)
- **JavaScript/TypeScript** — 2 rules (catch-without-logging, sensitive-data-in-log)

### Running A09 Rules Only

```bash
# Run only A09 custom rules
bash runner/job-dispatcher.sh --tool semgrep --target /path/to/code --rules /rules/a09-logging-rules.yml

# A09 rules are also included automatically with default SAST scans
bash runner/job-dispatcher.sh --tool semgrep --target /path/to/code
```

---

## 9. Remediation Priority Matrix

| CWE     | Effort | Auto-fixable? | Priority |
| ------- | ------ | ------------- | -------- |
| CWE-532 | Small  | Partial       | P1       |
| CWE-117 | Small  | Yes           | P1       |
| CWE-390 | Small  | Yes           | P2       |
| CWE-778 | Medium | No            | P2       |
| CWE-223 | Medium | No            | P2       |
| CWE-779 | Small  | Partial       | P3       |
