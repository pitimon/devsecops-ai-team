# Remediation Patterns Reference

# คู่มือรูปแบบการแก้ไขช่องโหว่

> **Purpose / วัตถุประสงค์**: Fix patterns organized by CWE category for DevSecOps agents
> performing automated and guided vulnerability remediation. Covers injection, authentication,
> cryptography, access control, and other common vulnerability classes with language-specific
> fix examples (Python, JavaScript/TypeScript, Go, Java), version upgrade strategies, workaround
> patterns, breaking change mitigation, and effort estimation guidelines.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: CWE v4.14, OWASP Top 10 (2021), OWASP ASVS v4.0.3, Semgrep v1.67+

---

## 1. Injection Vulnerabilities / ช่องโหว่ Injection

### 1.1 SQL Injection (CWE-89)

### การฉีดคำสั่ง SQL

**OWASP:** A03:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Low-Medium

**Root Cause:** Untrusted input concatenated into SQL queries.

**Fix Pattern -- Parameterized Queries:**

```python
# VULNERABLE: String concatenation
query = f"SELECT * FROM users WHERE name = '{user_input}'"
cursor.execute(query)

# FIXED: Parameterized query
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (user_input,))
```

```javascript
// VULNERABLE: String interpolation
const query = `SELECT * FROM users WHERE id = ${userId}`;
await db.query(query);

// FIXED: Parameterized query (node-postgres)
const query = "SELECT * FROM users WHERE id = $1";
await db.query(query, [userId]);
```

```go
// VULNERABLE: String concatenation
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
rows, err := db.Query(query)

// FIXED: Parameterized query (database/sql)
query := "SELECT * FROM users WHERE id = $1"
rows, err := db.Query(query, userID)

// FIXED: Using sqlx (jmoiron/sqlx v1.4+)
user := User{}
err := db.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
```

```java
// VULNERABLE: String concatenation
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// FIXED: PreparedStatement
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();

// FIXED: Spring Data JPA (Spring Boot 3.4+)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = :name")
    List<User> findByName(@Param("name") String name);
}
```

**ORM-Level Protection:**

```python
# Django ORM (5.x) — safe by default
User.objects.filter(name=user_input)

# SQLAlchemy (2.0+) — use bound parameters
session.query(User).filter(User.name == user_input).all()
```

**Additional Defenses:**

- Input validation (allowlist where possible)
- Stored procedures with parameterized calls
- Least-privilege database accounts
- WAF SQL injection rules as defense-in-depth

### 1.2 Cross-Site Scripting / XSS (CWE-79)

### การโจมตี Cross-Site Scripting

**OWASP:** A03:2021 | **CVSS Range:** 4.3-8.1 | **Effort:** Low-Medium

**Fix Pattern -- Output Encoding:**

```javascript
// VULNERABLE: Direct insertion of user content
element.innerHTML = userContent;

// FIXED: Use textContent for plain text
element.textContent = userContent;

// FIXED: Use DOMPurify for rich content (v3.x)
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userContent);
```

```python
# Jinja2 (3.x) — auto-escaping enabled by default
from markupsafe import escape
# Templates auto-escape: {{ user_input }} is safe
# Manual: escape(user_input)
```

```go
// Go html/template — auto-escaping by default
import "html/template"

// SAFE: html/template auto-escapes by context
tmpl := template.Must(template.New("page").Parse(`
    <div>{{ .UserInput }}</div>
`))
tmpl.Execute(w, data)

// VULNERABLE: text/template does NOT auto-escape
// import "text/template"  // DO NOT use for HTML output

// FIXED: Manual encoding when not using templates
import "html"
safeOutput := html.EscapeString(userInput)
```

```java
// VULNERABLE: Direct output in JSP
<%= request.getParameter("name") %>

// FIXED: JSTL escaping (Jakarta EE 10+)
<c:out value="${param.name}" />

// FIXED: Thymeleaf (3.x) — auto-escapes by default
<span th:text="${userInput}">safe</span>

// FIXED: OWASP Java Encoder (1.3+)
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);
String safeAttr = Encode.forHtmlAttribute(userInput);
String safeJs = Encode.forJavaScript(userInput);
```

**Content Security Policy:**

```text
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-{random}';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    connect-src 'self' https://api.example.com;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
```

### 1.3 Command Injection (CWE-78)

**OWASP:** A03:2021 | **CVSS Range:** 8.1-9.8 | **Effort:** Medium

**Fix Pattern -- Avoid Shell Execution:**

```python
# VULNERABLE: Shell=True with user input
import subprocess
subprocess.run(f"ping {host}", shell=True)

# FIXED: Use argument list, no shell
import subprocess
subprocess.run(["ping", "-c", "4", host], shell=False)

# FIXED: Use dedicated library instead of shell commands
import socket
socket.gethostbyname(host)
```

```javascript
// VULNERABLE: exec with string interpolation
const { exec } = require("child_process");
exec(`ls ${userPath}`, callback);

// FIXED: execFile with argument array
const { execFile } = require("child_process");
execFile("ls", [userPath], callback);
```

```go
// VULNERABLE: Shell execution with user input
cmd := exec.Command("sh", "-c", "ping " + host)

// FIXED: Direct command with argument array
cmd := exec.Command("ping", "-c", "4", host)
output, err := cmd.Output()

// FIXED: Validate input before use
import "regexp"
hostRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
if !hostRegex.MatchString(host) {
    return fmt.Errorf("invalid hostname: %s", host)
}
cmd := exec.Command("ping", "-c", "4", host)
```

```java
// VULNERABLE: Runtime.exec with concatenation
Runtime.getRuntime().exec("ping " + host);

// FIXED: ProcessBuilder with argument array
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
pb.redirectErrorStream(true);
Process process = pb.start();
```

### 1.4 Path Traversal (CWE-22)

### การเข้าถึงไฟล์นอกขอบเขต

**OWASP:** A01:2021 | **CVSS Range:** 5.3-7.5 | **Effort:** Low

```python
# VULNERABLE: Direct path concatenation
file_path = os.path.join(BASE_DIR, user_filename)
with open(file_path) as f:
    return f.read()

# FIXED: Resolve and validate against base directory
import os
requested_path = os.path.realpath(os.path.join(BASE_DIR, user_filename))
if not requested_path.startswith(os.path.realpath(BASE_DIR)):
    raise PermissionError("Path traversal attempt detected")
with open(requested_path) as f:
    return f.read()
```

```go
// VULNERABLE: Direct path join
filePath := filepath.Join(baseDir, userFilename)
data, err := os.ReadFile(filePath)

// FIXED: Canonicalize and validate
import "path/filepath"

cleanPath := filepath.Clean(userFilename)
if strings.Contains(cleanPath, "..") {
    return fmt.Errorf("path traversal attempt detected")
}
absPath, err := filepath.Abs(filepath.Join(baseDir, cleanPath))
if err != nil || !strings.HasPrefix(absPath, filepath.Clean(baseDir)) {
    return fmt.Errorf("path traversal attempt detected")
}
data, err := os.ReadFile(absPath)
```

```java
// VULNERABLE: Direct concatenation
Path filePath = Path.of(baseDir, userFilename);
byte[] data = Files.readAllBytes(filePath);

// FIXED: Normalize and validate (Java 11+)
Path basePath = Path.of(baseDir).toRealPath();
Path requestedPath = basePath.resolve(userFilename).normalize().toRealPath();
if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal attempt detected");
}
byte[] data = Files.readAllBytes(requestedPath);
```

### 1.5 Server-Side Request Forgery / SSRF (CWE-918)

### การปลอมแปลงคำขอจากฝั่งเซิร์ฟเวอร์

**OWASP:** A10:2021 | **CVSS Range:** 5.3-9.1 | **Effort:** Medium

```python
# VULNERABLE: Unrestricted URL fetch
import requests
def fetch_url(url: str):
    return requests.get(url).text

# FIXED: URL validation + allowlist + network controls
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https"}
BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (metadata)
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
]

def fetch_url_safe(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTPS URLs are allowed")

    import socket
    ip = socket.gethostbyname(parsed.hostname)
    ip_addr = ipaddress.ip_address(ip)

    for blocked in BLOCKED_RANGES:
        if ip_addr in blocked:
            raise ValueError("Internal network access is not allowed")

    return requests.get(url, timeout=10, allow_redirects=False).text
```

```go
// FIXED: SSRF protection in Go
import (
    "fmt"
    "net"
    "net/http"
    "net/url"
    "time"
)

var blockedCIDRs = []string{
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "127.0.0.0/8",
}

func fetchURLSafe(rawURL string) ([]byte, error) {
    parsed, err := url.Parse(rawURL)
    if err != nil || parsed.Scheme != "https" {
        return nil, fmt.Errorf("only HTTPS URLs allowed")
    }

    ips, err := net.LookupIP(parsed.Hostname())
    if err != nil {
        return nil, err
    }

    for _, ip := range ips {
        for _, cidr := range blockedCIDRs {
            _, network, _ := net.ParseCIDR(cidr)
            if network.Contains(ip) {
                return nil, fmt.Errorf("internal network access blocked")
            }
        }
    }

    client := &http.Client{
        Timeout: 10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // disable redirects
        },
    }
    resp, err := client.Get(rawURL)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}
```

---

## 2. Authentication & Session Management / การยืนยันตัวตนและ Session

### 2.1 Broken Authentication (CWE-287)

**OWASP:** A07:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Medium-High

**Fix Patterns -- Credential Hashing:**

```python
# Argon2id — preferred for new implementations (OWASP recommended)
from argon2 import PasswordHasher  # argon2-cffi v23.x

ph = PasswordHasher(
    time_cost=3,       # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
hashed = ph.hash(plain_text)
ph.verify(hashed, plain_text)  # raises VerifyMismatchError on failure

# bcrypt — also acceptable
import bcrypt
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(plain_text.encode('utf-8'), salt)
```

```go
// Go: bcrypt (golang.org/x/crypto v0.31+)
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    return string(bytes), err
}

func verifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// Go: argon2 (golang.org/x/crypto v0.31+)
import "golang.org/x/crypto/argon2"

func hashArgon2(password string) []byte {
    salt := make([]byte, 16)
    rand.Read(salt)
    return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}
```

```java
// Java: bcrypt via Spring Security (6.x)
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashed = encoder.encode(plainText);
boolean matches = encoder.matches(plainText, hashed);

// Java: Argon2 via Bouncy Castle (1.78+)
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
    .withSalt(salt)
    .withParallelism(4)
    .withMemoryAsKB(65536)
    .withIterations(3)
    .build();
```

**Session Management Best Practices:**

```text
1. Generate cryptographically random session IDs (>= 128 bits entropy)
2. Set session cookies with: Secure, HttpOnly, SameSite=Strict
3. Implement session timeout (idle: 15-30 min, absolute: 8-24 hours)
4. Regenerate session ID after authentication
5. Invalidate session on logout (server-side)
6. Limit concurrent sessions per user
```

### 2.2 Insecure Direct Object Reference / IDOR (CWE-639)

**OWASP:** A01:2021 | **CVSS Range:** 5.3-7.5 | **Effort:** Low-Medium

```python
# VULNERABLE: No authorization check on resource access
@app.get("/api/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).get(order_id)

# FIXED: Verify resource belongs to authenticated user (FastAPI 0.115+)
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = db.query(Order).get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return order
```

```go
// FIXED: Go + Chi router — ownership check
func GetOrder(w http.ResponseWriter, r *http.Request) {
    orderID := chi.URLParam(r, "orderID")
    currentUser := r.Context().Value("user").(*User)

    order, err := db.GetOrder(orderID)
    if err != nil {
        http.Error(w, "Not found", http.StatusNotFound)
        return
    }
    if order.UserID != currentUser.ID {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    json.NewEncoder(w).Encode(order)
}
```

### 2.3 Missing Multi-Factor Authentication (CWE-308)

**OWASP:** A07:2021 | **Effort:** Medium

```text
MFA Implementation Checklist:
1. [ ] Support TOTP (RFC 6238) — Google Authenticator, Authy
2. [ ] Support WebAuthn/FIDO2 for passwordless (preferred)
3. [ ] Implement backup codes (10 single-use codes)
4. [ ] Require MFA for: admin access, sensitive operations, credential changes
5. [ ] Rate-limit MFA verification attempts
6. [ ] Log all MFA events for audit
7. [ ] Provide MFA recovery process with identity verification
```

---

## 3. Cryptographic Issues / ปัญหาด้านการเข้ารหัส

### 3.1 Weak Cryptography (CWE-327)

**OWASP:** A02:2021 | **CVSS Range:** 5.3-7.5 | **Effort:** Medium

**Deprecated vs. Recommended Algorithms:**

| Purpose               | Deprecated (DO NOT USE)      | Recommended (2026)         |
| --------------------- | ---------------------------- | -------------------------- |
| Hashing               | MD5, SHA-1                   | SHA-256, SHA-3, BLAKE3     |
| Credential hashing    | MD5, SHA-1, plain SHA-256    | Argon2id, bcrypt, scrypt   |
| Symmetric encryption  | DES, 3DES, RC4, Blowfish     | AES-256-GCM, ChaCha20-Poly |
| Asymmetric encryption | RSA-1024                     | RSA-2048+, Ed25519, X25519 |
| TLS version           | SSL 3.0, TLS 1.0, TLS 1.1    | TLS 1.2 (min), TLS 1.3     |
| Key exchange          | Static DH, RSA key transport | ECDHE, X25519              |

**Fix Pattern -- Encryption:**

```python
# VULNERABLE: ECB mode, no authentication
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # INSECURE

# FIXED: AES-GCM (cryptography v43.x)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)
nonce = os.urandom(12)  # 96-bit nonce
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
decrypted = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

```go
// FIXED: AES-GCM in Go (crypto/aes, crypto/cipher)
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
)

func encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) // key must be 32 bytes for AES-256
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
```

```java
// FIXED: AES-GCM in Java (JDK 17+)
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

KeyGenerator keyGen = KeyGenerator.getInstance("AES");
keyGen.init(256);
SecretKey key = keyGen.generateKey();

byte[] nonce = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(nonce);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);
byte[] ciphertext = cipher.doFinal(plaintext);
```

### 3.2 Insufficient Transport Layer Protection (CWE-319)

**OWASP:** A02:2021 | **Effort:** Low

```nginx
# Nginx TLS configuration (recommended, nginx 1.27+)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### 3.3 Hardcoded Credentials (CWE-798)

**OWASP:** A07:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Low

```python
# VULNERABLE: Credential hardcoded in source
DB_PASS = "NEVER_DO_THIS_123"  # VULNERABLE

# FIXED: Read from environment
import os
DB_PASS = os.environ["DB_PASS"]

# BETTER: Use a secrets manager (HashiCorp Vault v1.18+)
from app.secrets import vault_client
db_creds = vault_client.read("database/creds/myapp")
```

```go
// VULNERABLE: Hardcoded credential
const dbPassword = "secret123" // VULNERABLE

// FIXED: Environment variable
dbPassword := os.Getenv("DB_PASSWORD")
if dbPassword == "" {
    log.Fatal("DB_PASSWORD environment variable is required")
}

// BETTER: AWS Secrets Manager (aws-sdk-go-v2)
import "github.com/aws/aws-sdk-go-v2/service/secretsmanager"

result, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
    SecretId: aws.String("prod/db/credentials"),
})
```

---

## 4. Access Control / การควบคุมการเข้าถึง

### 4.1 Missing Authorization (CWE-862)

**OWASP:** A01:2021 | **CVSS Range:** 5.3-9.8 | **Effort:** Medium

```python
# VULNERABLE: No authorization middleware
@app.delete("/api/users/{user_id}")
def delete_user(user_id: int):
    db.delete(User, user_id)

# FIXED: Role-based authorization (FastAPI 0.115+)
@app.delete("/api/users/{user_id}")
@require_role("admin")
def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    if not current_user.has_permission("user:delete"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    db.delete(User, user_id)
```

```go
// FIXED: Middleware-based authorization in Go
func RequireRole(role string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := r.Context().Value("user").(*User)
            if !user.HasRole(role) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// Usage with Chi router (v5.x)
r.With(RequireRole("admin")).Delete("/api/users/{id}", DeleteUser)
```

```java
// FIXED: Spring Security method-level authorization (Spring Boot 3.4+)
@RestController
@RequestMapping("/api/users")
public class UserController {

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}
```

### 4.2 CORS Misconfiguration (CWE-942)

**OWASP:** A05:2021 | **Effort:** Low

```python
# VULNERABLE: Allow all origins
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# FIXED: Explicit allowed origins (FastAPI 0.115+)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com", "https://admin.example.com"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
    max_age=3600,
)
```

```go
// FIXED: CORS in Go with rs/cors (v1.11+)
import "github.com/rs/cors"

c := cors.New(cors.Options{
    AllowedOrigins:   []string{"https://app.example.com"},
    AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
    AllowedHeaders:   []string{"Authorization", "Content-Type"},
    AllowCredentials: true,
    MaxAge:           3600,
})
handler := c.Handler(router)
```

---

## 5. Vulnerable Dependencies / Dependencies ที่มีช่องโหว่

### 5.1 Known Vulnerable Components (CWE-1035)

### ส่วนประกอบที่มีช่องโหว่

**OWASP:** A06:2021 | **Effort:** Low-High (varies)

**Version Upgrade Strategies:**

| Strategy           | Risk   | When to Use                                        |
| ------------------ | ------ | -------------------------------------------------- |
| Patch version bump | Low    | Bug fix only (e.g., 2.1.3 -> 2.1.4)                |
| Minor version bump | Medium | New features, backward compatible (2.1.x -> 2.2.0) |
| Major version bump | High   | Breaking changes (2.x -> 3.0.0)                    |
| Fork and patch     | Medium | Maintainer unresponsive, critical CVE              |
| Replace dependency | High   | Abandoned project, frequent vulnerabilities        |

**Upgrade Process:**

```text
1. Review changelog for breaking changes
2. Check dependency compatibility matrix
3. Update in a feature branch
4. Run full test suite
5. Review for API changes in your code
6. Test in staging environment
7. Deploy with canary/rolling strategy
8. Monitor for regressions (48 hours minimum)
```

### 5.2 Breaking Change Mitigation Patterns

**Adapter Pattern (for API changes):**

```python
# When upgrading library-v2 to library-v3 with breaking API change
class LibraryAdapter:
    """Adapter wrapping library-v3 with the v2-compatible interface."""

    def __init__(self):
        self._client = library_v3.NewClient()  # v3 API

    def old_method(self, param):
        """v2-compatible method wrapping v3 internals."""
        return self._client.new_method(param=param, mode="compat")
```

**Feature Flag for Gradual Migration:**

```python
# Roll out new dependency version behind feature flag
if feature_flags.is_enabled("use_new_auth_library"):
    from auth_v2 import authenticate  # New library
else:
    from auth_v1 import authenticate  # Legacy library

result = authenticate(credentials)
```

### 5.3 Workaround Patterns / รูปแบบการแก้ไขชั่วคราว

When a fix cannot be deployed immediately, apply workarounds:

| Workaround Type        | Thai Translation      | When to Use                        | Duration      |
| ---------------------- | --------------------- | ---------------------------------- | ------------- |
| WAF Virtual Patch      | แพตช์เสมือน WAF       | Known exploit pattern, no code fix | Until patched |
| Input Validation Layer | ชั้นตรวจสอบข้อมูลเข้า | Injection vulnerabilities          | Until patched |
| Network Segmentation   | แบ่งส่วนเครือข่าย     | Vulnerable internal service        | Until patched |
| Feature Disable        | ปิดฟีเจอร์            | Vulnerable feature, non-critical   | Until patched |
| Rate Limiting          | จำกัดอัตรา            | Brute force, DoS vulnerabilities   | Permanent     |
| IP Allowlisting        | อนุญาตเฉพาะ IP        | Admin panel, internal APIs         | Permanent     |

**WAF Virtual Patch Example (ModSecurity/NGINX):**

```nginx
# Virtual patch for SQL injection in /api/search
# Apply until code fix is deployed
location /api/search {
    # Block common SQL injection patterns
    if ($args ~* "(union|select|insert|update|delete|drop|alter)(\s|%20|%09|\+)") {
        return 403;
    }
    proxy_pass http://backend;
}
```

**Kubernetes NetworkPolicy Workaround:**

```yaml
# Restrict access to vulnerable service until patched
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-vulnerable-service
spec:
  podSelector:
    matchLabels:
      app: vulnerable-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway # Only allow traffic from gateway
      ports:
        - port: 8080
```

**Version Pinning Best Practices:**

```text
# Pin exact versions for direct dependencies
# Python: requirements.txt / pyproject.toml
fastapi==0.115.0
pydantic==2.10.0

# Node: package.json (use exact, not ^/~)
"dependencies": { "express": "4.21.0" }

# Go: go.mod (automatically pinned)
require github.com/gin-gonic/gin v1.10.0

# Java: Maven pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>3.4.0</version>
</dependency>

# Lock files are mandatory:
# Python: poetry.lock, pip-tools requirements.txt
# Node: package-lock.json, yarn.lock, pnpm-lock.yaml
# Go: go.sum
# Rust: Cargo.lock
# Java: Use Maven/Gradle dependency locking
```

---

## 6. Infrastructure & Configuration / โครงสร้างพื้นฐานและการกำหนดค่า

### 6.1 Security Misconfiguration (CWE-16)

**OWASP:** A05:2021 | **Effort:** Low-Medium

**Container Hardening:**

```dockerfile
# VULNERABLE: Running as root with full image
FROM ubuntu:latest
COPY app /app
CMD ["/app/server"]

# FIXED: Non-root, minimal base, read-only FS
FROM gcr.io/distroless/static-debian12:nonroot
COPY --chown=nonroot:nonroot app /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/server"]
```

```yaml
# Kubernetes Pod Security Context (K8s 1.31+)
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          memory: "256Mi"
          cpu: "500m"
```

### 6.2 Missing Security Headers (CWE-693)

**OWASP:** A05:2021 | **Effort:** Low

```nginx
# Essential security headers (nginx 1.27+)
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "0" always;  # Disabled: use CSP instead
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### 6.3 Terraform / IaC Remediation Patterns

```hcl
# VULNERABLE: S3 bucket with public access
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

# FIXED: Block all public access + encryption + versioning
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

---

## 7. Effort Estimation per Vulnerability Type / การประมาณค่าแรงงาน

### 7.1 Effort Matrix by CWE Category

### ตารางความพยายามตามหมวด CWE

| CWE Category                   | Typical Fix Effort | Dev Hours | Testing Hours | Notes                                   |
| ------------------------------ | ------------------ | --------- | ------------- | --------------------------------------- |
| SQL Injection (CWE-89)         | Low                | 1-4       | 1-2           | Parameterize queries                    |
| XSS (CWE-79)                   | Low-Medium         | 1-8       | 2-4           | Output encoding + CSP                   |
| Command Injection (CWE-78)     | Medium             | 2-8       | 2-4           | Replace shell calls                     |
| Path Traversal (CWE-22)        | Low                | 1-4       | 1-2           | Path validation                         |
| Auth Bypass (CWE-287)          | Medium-High        | 4-16      | 4-8           | Auth redesign may be needed             |
| IDOR (CWE-639)                 | Low-Medium         | 2-8       | 2-4           | Add authorization checks                |
| Weak Crypto (CWE-327)          | Medium             | 4-16      | 2-4           | Algorithm replacement + data re-encrypt |
| Hardcoded Creds (CWE-798)      | Low                | 1-4       | 1-2           | Move to env/vault                       |
| SSRF (CWE-918)                 | Medium             | 4-8       | 2-4           | URL validation + network controls       |
| Insecure Deserialization (502) | High               | 8-24      | 4-8           | Serialization redesign                  |
| Missing Access Control (862)   | Medium             | 4-16      | 4-8           | RBAC implementation                     |
| Security Misconfiguration (16) | Low                | 1-4       | 1-2           | Configuration change                    |
| Vulnerable Component (1035)    | Low-High           | 1-24      | 2-8           | Depends on breaking changes             |
| CORS Misconfiguration (942)    | Low                | 0.5-2     | 1             | Configuration change                    |
| Missing Security Headers (693) | Low                | 0.5-2     | 1             | Server/proxy configuration              |

### 7.2 Effort Multipliers

| Factor                          | Multiplier | Reason                                |
| ------------------------------- | ---------- | ------------------------------------- |
| Legacy codebase (no tests)      | 2-3x       | Must write tests before refactoring   |
| Multiple occurrence (>10)       | 0.5x each  | Pattern fix can be batched            |
| Database schema change required | 2x         | Migration + rollback plan needed      |
| Public API breaking change      | 3-5x       | Versioning + deprecation period       |
| Compliance-regulated system     | 1.5x       | Additional documentation and approval |
| Microservices (cross-service)   | 2x         | Coordinated deployment required       |
| No staging environment          | 1.5x       | Higher risk deployment, more testing  |

### 7.3 Language-Specific Effort Adjustments

| Language      | Framework          | SQLi Fix | XSS Fix | Crypto Fix | Notes                            |
| ------------- | ------------------ | -------- | ------- | ---------- | -------------------------------- |
| Python        | Django 5.x         | 1hr      | 1hr     | 4hr        | ORM safe by default              |
| Python        | FastAPI 0.115+     | 2hr      | 2hr     | 4hr        | Need explicit parameterization   |
| JavaScript/TS | Express 4.21+      | 2hr      | 2hr     | 4hr        | Use helmet.js for headers        |
| JavaScript/TS | Next.js 15+        | 1hr      | 1hr     | 2hr        | Server components auto-escape    |
| Go            | net/http + Chi 5.x | 1hr      | 1hr     | 2hr        | html/template auto-escapes       |
| Go            | Gin 1.10+          | 1hr      | 1hr     | 2hr        | Built-in parameter binding       |
| Java          | Spring Boot 3.4+   | 1hr      | 2hr     | 4hr        | JPA safe, Thymeleaf auto-escapes |
| Java          | Jakarta EE 10+     | 2hr      | 2hr     | 4hr        | PreparedStatement required       |

### 7.4 Prioritization Formula

```text
Priority Score = (CVSS_Score * Exploitability_Weight) / Effort_Hours

Where:
- CVSS_Score: 0.0 - 10.0 from vulnerability scanner
- Exploitability_Weight:
  - 3.0 = Known exploit in the wild (CISA KEV)
  - 2.0 = Proof of concept exists
  - 1.5 = Theoretically exploitable
  - 1.0 = Requires complex conditions
- Effort_Hours: Estimated total hours (dev + test)

Higher score = Fix first

Example:
  SQLi (CVSS 9.8, PoC exists, 4 hours effort)
  Score = (9.8 * 2.0) / 4 = 4.9  --> HIGH PRIORITY

  Weak cipher (CVSS 5.3, theoretical, 12 hours effort)
  Score = (5.3 * 1.5) / 12 = 0.66  --> LOWER PRIORITY
```

---

## 8. Remediation Verification / การตรวจสอบการแก้ไข

### 8.1 Verification Checklist

```text
For each remediated vulnerability:

1.  [ ] Unit test covering the specific vulnerability scenario
2.  [ ] Integration test verifying the fix in context
3.  [ ] Negative test confirming the attack vector no longer works
4.  [ ] SAST re-scan shows finding resolved (not suppressed)
5.  [ ] DAST re-scan confirms endpoint no longer vulnerable
6.  [ ] Peer review of the fix (security-focused)
7.  [ ] No regression in existing functionality
8.  [ ] Fix deployed to staging and verified
9.  [ ] Vulnerability ticket updated with fix commit reference
10. [ ] SCA findings resolved (if dependency-related)
```

### 8.2 Automated Verification in CI/CD

```yaml
# GitHub Actions: Verify remediation
name: Remediation Verification
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  verify-fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run targeted security tests
        run: |
          # Run only security-related test suite
          pytest tests/security/ -v --tb=short

      - name: SAST scan for specific CWE
        run: |
          semgrep scan --config "p/owasp-top-ten" \
            --error --json > sast-results.json

      - name: Verify no regression
        run: |
          # Full test suite to catch regressions
          pytest --tb=short -q
```

---

## 9. Common Fix Anti-Patterns / รูปแบบการแก้ไขที่ไม่ควรทำ

| Anti-Pattern                      | Why It Fails                             | Correct Approach                    |
| --------------------------------- | ---------------------------------------- | ----------------------------------- |
| Blocklist-only input validation   | Attackers find bypasses                  | Allowlist + parameterization        |
| Client-side validation only       | Trivially bypassed                       | Always validate server-side         |
| Encoding input instead of output  | Wrong context, still exploitable         | Encode at output point              |
| Suppressing scanner finding       | Vulnerability still exists               | Fix the root cause                  |
| Custom cryptography               | Almost certainly flawed                  | Use established libraries           |
| Logging sensitive data for debug  | Creates new data leak vulnerability      | Redact sensitive fields in logs     |
| Security through obscurity        | Not a valid control                      | Proper authentication/authorization |
| Disabling CSRF for convenience    | Opens cross-site attack vector           | Implement CSRF tokens properly      |
| Catch-all exception hiding errors | Masks vulnerabilities and aids attackers | Handle specific exceptions          |
| Hardcoded IP allowlist            | Brittle, bypassable with IP spoofing     | Proper authentication mechanism     |

---

## 10. Remediation SLA by Severity / SLA การแก้ไขตามความรุนแรง

| CVSS Score | Severity | Thai Level | Remediation SLA | Exceptions Process                      |
| ---------- | -------- | ---------- | --------------- | --------------------------------------- |
| 9.0 - 10.0 | Critical | วิกฤต      | 48 hours        | CISO approval, compensating controls    |
| 7.0 - 8.9  | High     | สูง        | 7 days          | Security manager approval               |
| 4.0 - 6.9  | Medium   | ปานกลาง    | 30 days         | Team lead approval                      |
| 0.1 - 3.9  | Low      | ต่ำ        | 90 days         | Standard backlog prioritization         |
| 0.0        | Info     | ข้อมูล     | Best effort     | No SLA, address during regular dev work |

**Exception Request Template:**

```text
Exception ID: EXC-YYYY-NNNN
Vulnerability: [CVE/CWE ID and description]
CVSS Score: [Score]
Affected System: [System name]
Standard SLA: [Original deadline]
Requested Extension: [New deadline]
Justification: [Why the fix cannot be completed within SLA]
Compensating Controls: [What controls mitigate risk during exception]
Risk Acceptance: [Residual risk during exception period]
Approver: [Required approval level based on severity]
```

---

## References / แหล่งอ้างอิง

- CWE Database: https://cwe.mitre.org/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- OWASP Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS v4.0.3: https://owasp.org/www-project-application-security-verification-standard/
- CVSS v4.0 Calculator: https://www.first.org/cvss/calculator/4.0
- Semgrep Rules Registry: https://semgrep.dev/explore
- Snyk Vulnerability DB: https://security.snyk.io/
- GitHub Advisory Database: https://github.com/advisories
- NIST NVD: https://nvd.nist.gov/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- Go crypto package: https://pkg.go.dev/golang.org/x/crypto
- Spring Security Reference: https://docs.spring.io/spring-security/reference/
- OWASP Java Encoder: https://owasp.org/www-project-java-encoder/
- DOMPurify: https://github.com/cure53/DOMPurify
