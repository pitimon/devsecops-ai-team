# Express & Node.js Remediation Patterns

# รูปแบบการแก้ไขช่องโหว่สำหรับ Express และ Node.js

> **Purpose / วัตถุประสงค์**: Framework-specific fix patterns for Express 4.x/5.x and Node.js 18+ projects.
> Extends generic `remediation-patterns.md` with Express middleware patterns, npm security,
> and Node.js-specific APIs.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: Express 4.21+/5.x, Node.js 18+

---

## 1. Security Headers (CWE-693)

### การตั้งค่า Security Headers ด้วย Helmet

**OWASP:** A05:2021 | **Effort:** Trivial

```javascript
// VULNERABLE: No security headers
const app = express();
app.get("/", (req, res) => res.send("Hello"));

// FIXED: Helmet sets 15+ security headers by default
const helmet = require("helmet");
const app = express();
app.use(helmet());

// Custom CSP
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  }),
);
```

**Helmet defaults (v7+):**

| Header                      | Default Value       | Protection        |
| --------------------------- | ------------------- | ----------------- |
| `Content-Security-Policy`   | Restrictive default | XSS, injection    |
| `Strict-Transport-Security` | max-age=15552000    | Downgrade attacks |
| `X-Content-Type-Options`    | nosniff             | MIME sniffing     |
| `X-Frame-Options`           | SAMEORIGIN          | Clickjacking      |
| `X-DNS-Prefetch-Control`    | off                 | DNS leaks         |

---

## 2. Input Validation (CWE-20)

### การ Validate Input ด้วย express-validator

**OWASP:** A03:2021 | **Effort:** Small

```javascript
// VULNERABLE: No input validation
app.post("/users", (req, res) => {
  const { email, name, age } = req.body;
  db.createUser({ email, name, age });
});

// FIXED: express-validator chains
const { body, validationResult } = require("express-validator");

app.post(
  "/users",
  [
    body("email").isEmail().normalizeEmail(),
    body("name").isString().trim().isLength({ min: 1, max: 100 }).escape(),
    body("age").isInt({ min: 0, max: 150 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, name, age } = req.body;
    db.createUser({ email, name, age });
  },
);
```

**Zod alternative (recommended for TypeScript):**

```typescript
import { z } from "zod";

const UserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100).trim(),
  age: z.number().int().min(0).max(150),
});

app.post("/users", (req, res) => {
  const parsed = UserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.issues });
  }
  db.createUser(parsed.data);
});
```

---

## 3. SQL / NoSQL Injection (CWE-89, CWE-943)

### การป้องกัน Injection

**OWASP:** A03:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Low-Medium

```javascript
// VULNERABLE: String interpolation in SQL
app.get("/users/:id", async (req, res) => {
  const result = await db.query(
    `SELECT * FROM users WHERE id = '${req.params.id}'`,
  );
  res.json(result.rows);
});

// FIXED: Parameterized query (pg / mysql2)
app.get("/users/:id", async (req, res) => {
  const result = await db.query("SELECT * FROM users WHERE id = $1", [
    req.params.id,
  ]);
  res.json(result.rows);
});

// FIXED: Knex.js query builder
const result = await knex("users").where("id", req.params.id).first();

// FIXED: Prisma ORM (auto-parameterized)
const user = await prisma.user.findUnique({ where: { id: req.params.id } });
```

**MongoDB NoSQL injection:**

```javascript
// VULNERABLE: User input directly in query
app.get("/users", async (req, res) => {
  const users = await User.find({ role: req.query.role }); // { role: { $ne: null } } bypasses
  res.json(users);
});

// FIXED: Sanitize with mongo-sanitize
const sanitize = require("mongo-sanitize");
app.get("/users", async (req, res) => {
  const users = await User.find({ role: sanitize(req.query.role) });
  res.json(users);
});

// FIXED: Explicit type casting
app.get("/users", async (req, res) => {
  const role = String(req.query.role || "");
  const users = await User.find({ role });
  res.json(users);
});
```

---

## 4. Prototype Pollution (CWE-1321)

### การป้องกัน Prototype Pollution

**OWASP:** A03:2021 | **Effort:** Small-Medium

```javascript
// VULNERABLE: Recursive merge with user input
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
// Attack: merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))

// FIXED Option 1: Null-prototype objects
function safeMerge(target, source) {
  const result = Object.create(null);
  Object.assign(result, target);
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype")
      continue;
    if (typeof source[key] === "object" && source[key] !== null) {
      result[key] = safeMerge(result[key] || Object.create(null), source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

// FIXED Option 2: Use Map for dynamic keys from user input
const userPrefs = new Map(Object.entries(req.body.preferences || {}));

// FIXED Option 3: Object.freeze to prevent mutation
const config = Object.freeze({
  defaultRole: "user",
  maxRetries: 3,
});
```

---

## 5. Rate Limiting (CWE-307, CWE-770)

### การจำกัด Rate Limiting

**OWASP:** A04:2021 | **Effort:** Trivial

```javascript
// VULNERABLE: No rate limiting
app.post("/login", authenticateHandler);

// FIXED: express-rate-limit
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: "Too many login attempts, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/login", loginLimiter, authenticateHandler);

// Global rate limit for all routes
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});
app.use(globalLimiter);
```

---

## 6. CSRF Protection (CWE-352)

### การป้องกัน CSRF

**OWASP:** A01:2021 | **Effort:** Small

```javascript
// csurf is deprecated — use csrf-csrf instead
// npm install csrf-csrf

const { doubleCsrf } = require("csrf-csrf");

const { doubleCsrfProtection, generateToken } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET,
  cookieName: "__csrf",
  cookieOptions: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  },
  getTokenFromRequest: (req) => req.headers["x-csrf-token"],
});

app.use(doubleCsrfProtection);

app.get("/csrf-token", (req, res) => {
  const token = generateToken(req, res);
  res.json({ token });
});
```

---

## 7. Command Injection (CWE-78)

### การป้องกัน Command Injection

**OWASP:** A03:2021 | **CVSS Range:** 9.0-10.0 | **Effort:** Small

```javascript
// VULNERABLE: execSync with string interpolation
const { execSync } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  const result = execSync(`ping -c 1 ${host}`); // host="; rm -rf /"
  res.send(result.toString());
});

// FIXED: execFileSync with argument array (no shell interpretation)
const { execFileSync } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  if (!/^[\w.-]+$/.test(host))
    return res.status(400).json({ error: "Invalid host" });
  const result = execFileSync("ping", ["-c", "1", host]);
  res.send(result.toString());
});

// PREFERRED: Avoid child_process entirely — use native Node.js APIs
const dns = require("dns").promises;
app.get("/ping", async (req, res) => {
  const host = req.query.host;
  try {
    const addresses = await dns.resolve(host);
    res.json({ host, addresses });
  } catch (err) {
    res.status(400).json({ error: "Could not resolve host" });
  }
});
```

---

## 8. Authentication & Session (CWE-287, CWE-384)

### การจัดการ Session อย่างปลอดภัย

**OWASP:** A07:2021 | **Effort:** Small

```javascript
// VULNERABLE: Default session config
app.use(session({ secret: "keyboard cat" }));

// FIXED: Secure session configuration
const session = require("express-session");
const RedisStore = require("connect-redis").default;

app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    name: "__sid", // Custom cookie name (not 'connect.sid')
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 3600000, // 1 hour
    },
  }),
);
```

---

## 9. File Upload (CWE-434)

### การจัดการ File Upload

**OWASP:** A04:2021 | **Effort:** Small

```javascript
// VULNERABLE: No file validation
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
app.post("/upload", upload.single("file"), (req, res) => {
  res.json({ file: req.file });
});

// FIXED: Validate file type, size, and store safely
const upload = multer({
  dest: "uploads/",
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ["image/jpeg", "image/png", "application/pdf"];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("File type not allowed"));
    }
  },
});
```

---

## 10. Error Handling (CWE-209)

### การจัดการ Error อย่างปลอดภัย

**OWASP:** A05:2021 | **Effort:** Small

```javascript
// VULNERABLE: Stack trace leaks to client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// FIXED: Generic message to client, detailed log server-side
app.use((err, req, res, next) => {
  console.error("[ERROR]", err); // Server log — full details
  res.status(err.status || 500).json({
    error:
      process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err.message,
  });
});

// Catch unhandled rejections
process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED_REJECTION]", reason);
});
```

---

## Quick Reference: Express Security Checklist

| Item              | Package/Config                    | Priority |
| ----------------- | --------------------------------- | -------- |
| Security headers  | `helmet`                          | Critical |
| Input validation  | `express-validator` or `zod`      | Critical |
| Rate limiting     | `express-rate-limit`              | High     |
| CSRF protection   | `csrf-csrf` (not `csurf`)         | High     |
| Session security  | `express-session` + secure config | High     |
| SQL injection     | Parameterized queries / ORM       | Critical |
| Command injection | `execFileSync` (not `execSync`)   | Critical |
| File upload       | `multer` with limits + filter     | Medium   |
| Error handling    | No stack traces in production     | Medium   |
| Dependencies      | `npm audit` regularly             | Medium   |
