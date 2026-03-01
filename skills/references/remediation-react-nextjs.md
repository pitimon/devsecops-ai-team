# React & Next.js Remediation Patterns

# รูปแบบการแก้ไขช่องโหว่สำหรับ React และ Next.js

> **Purpose / วัตถุประสงค์**: Framework-specific fix patterns for React 18+ / Next.js 14+ projects.
> Extends generic `remediation-patterns.md` with React-native APIs, Server Components boundaries,
> and Next.js-specific configuration.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: React 18/19, Next.js 14/15

---

## 1. Cross-Site Scripting / XSS (CWE-79)

### ช่องโหว่ XSS ใน React

**OWASP:** A03:2021 | **CVSS Range:** 6.1-7.5 | **Effort:** Low

React auto-escapes JSX expressions `{value}` by default. XSS occurs when bypassing this protection.

```jsx
// VULNERABLE: dangerouslySetInnerHTML with user content
function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// FIXED Option 1: Remove dangerouslySetInnerHTML (preferred)
function Comment({ body }) {
  return <div>{body}</div>;
}

// FIXED Option 2: Sanitize with DOMPurify when HTML is required
import DOMPurify from "dompurify";
function Comment({ body }) {
  const clean = DOMPurify.sanitize(body, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br"],
    ALLOWED_ATTR: ["href", "title"],
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// FIXED Option 3: Use a markdown renderer with sanitization
import ReactMarkdown from "react-markdown";
function Comment({ body }) {
  return <ReactMarkdown>{body}</ReactMarkdown>;
}
```

**URL-based XSS:**

```jsx
// VULNERABLE: User-controlled href
function Link({ url, label }) {
  return <a href={url}>{label}</a>; // javascript: protocol possible
}

// FIXED: Validate URL protocol
function Link({ url, label }) {
  const safeUrl = /^https?:\/\//.test(url) ? url : "#";
  return <a href={safeUrl}>{label}</a>;
}
```

---

## 2. Server Components Security (Next.js)

### ความปลอดภัยของ Server Components

**Effort:** Medium

Server Components run on the server — never expose secrets or internal logic to the client.

```jsx
// DANGEROUS: Importing server module in client component
'use client';
import { db } from '@/lib/database'; // DB connection leaks to client bundle

// FIXED: Keep DB access in Server Components only
// app/users/page.tsx (Server Component — no 'use client')
import { db } from '@/lib/database';
export default async function UsersPage() {
  const users = await db.user.findMany({ select: { id: true, name: true } });
  return <UserList users={users} />;
}

// app/users/user-list.tsx (Client Component — receives only safe data)
'use client';
export function UserList({ users }: { users: { id: string; name: string }[] }) {
  return <ul>{users.map(u => <li key={u.id}>{u.name}</li>)}</ul>;
}
```

**Server Actions validation:**

```typescript
// VULNERABLE: No input validation in Server Action
"use server";
export async function updateProfile(formData: FormData) {
  const name = formData.get("name") as string;
  await db.user.update({ where: { id: userId }, data: { name } });
}

// FIXED: Validate with Zod in Server Action
("use server");
import { z } from "zod";

const ProfileSchema = z.object({
  name: z.string().min(1).max(100).trim(),
});

export async function updateProfile(formData: FormData) {
  const parsed = ProfileSchema.safeParse({ name: formData.get("name") });
  if (!parsed.success) throw new Error("Invalid input");
  await db.user.update({ where: { id: userId }, data: parsed.data });
}
```

---

## 3. Content Security Policy (CWE-693)

### การตั้งค่า CSP สำหรับ Next.js

**OWASP:** A05:2021 | **Effort:** Small

```javascript
// next.config.js — Security headers
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'", // Remove 'unsafe-inline' when possible
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
};

module.exports = nextConfig;
```

**Nonce-based CSP (Next.js 14+ middleware):**

```typescript
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'`;

  const response = NextResponse.next();
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("x-nonce", nonce);
  return response;
}
```

---

## 4. Authentication & Session (CWE-287, CWE-384)

### การจัดการ Authentication

**OWASP:** A07:2021 | **Effort:** Small-Medium

```typescript
// VULNERABLE: Storing auth token in localStorage
localStorage.setItem("token", response.token);

// FIXED: Use httpOnly cookies via API route
// app/api/auth/login/route.ts
import { cookies } from "next/headers";

export async function POST(request: Request) {
  const { email, password } = await request.json();
  const token = await authenticate(email, password);

  (await cookies()).set("session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 3600,
    path: "/",
  });

  return Response.json({ success: true });
}
```

```typescript
// Middleware-based auth check (Next.js 14+)
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const protectedRoutes = ["/dashboard", "/settings", "/admin"];

export function middleware(request: NextRequest) {
  const session = request.cookies.get("session");
  const isProtected = protectedRoutes.some((r) =>
    request.nextUrl.pathname.startsWith(r),
  );

  if (isProtected && !session) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}
```

---

## 5. API Route Security (CWE-284, CWE-862)

### การรักษาความปลอดภัย API Routes

**OWASP:** A01:2021 | **Effort:** Small

```typescript
// VULNERABLE: No auth check on API route
// app/api/users/route.ts
export async function GET() {
  const users = await db.user.findMany();
  return Response.json(users);
}

// FIXED: Auth check + input validation
import { z } from "zod";
import { getSession } from "@/lib/auth";

const QuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

export async function GET(request: Request) {
  const session = await getSession();
  if (!session)
    return Response.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(request.url);
  const parsed = QuerySchema.safeParse(Object.fromEntries(searchParams));
  if (!parsed.success)
    return Response.json({ error: "Invalid query" }, { status: 400 });

  const { page, limit } = parsed.data;
  const users = await db.user.findMany({
    skip: (page - 1) * limit,
    take: limit,
  });
  return Response.json(users);
}
```

---

## 6. Environment Variable Exposure (CWE-200)

### การป้องกันการรั่วไหลของ Environment Variables

**Effort:** Trivial

```bash
# .env.local — Server-only secrets (never prefixed with NEXT_PUBLIC_)
DATABASE_URL=postgresql://...
JWT_SECRET=super-secret-key
STRIPE_SECRET_KEY=sk_live_...

# .env.local — Client-safe values only
NEXT_PUBLIC_API_URL=https://api.example.com
NEXT_PUBLIC_ANALYTICS_ID=G-XXXXXXX
```

```typescript
// VULNERABLE: Exposing secret to client
const secret = process.env.JWT_SECRET; // undefined on client, but build may inline

// FIXED: Server-only access pattern
// lib/config.server.ts (import only in Server Components / API routes)
export const config = {
  dbUrl: process.env.DATABASE_URL!,
  jwtSecret: process.env.JWT_SECRET!,
};
```

---

## 7. Data Fetching Sanitization (CWE-79, CWE-918)

### การ Sanitize ข้อมูลจาก External API

**Effort:** Small

```typescript
// VULNERABLE: Rendering external API data without sanitization
async function ExternalContent() {
  const res = await fetch('https://api.example.com/content');
  const data = await res.json();
  return <div dangerouslySetInnerHTML={{ __html: data.html }} />;
}

// FIXED: Sanitize + validate external data
import DOMPurify from 'isomorphic-dompurify';
import { z } from 'zod';

const ContentSchema = z.object({
  html: z.string().max(50000),
  title: z.string().max(200),
});

async function ExternalContent() {
  const res = await fetch('https://api.example.com/content');
  const raw = await res.json();
  const parsed = ContentSchema.parse(raw);
  const clean = DOMPurify.sanitize(parsed.html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

**SSRF protection in Server Components:**

```typescript
// VULNERABLE: User-controlled URL in server fetch
async function Proxy({ url }: { url: string }) {
  const res = await fetch(url); // SSRF — can hit internal services
  return <div>{await res.text()}</div>;
}

// FIXED: Allowlist-based URL validation
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

async function Proxy({ url }: { url: string }) {
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error('Host not allowed');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('HTTPS required');
  }
  const res = await fetch(parsed.toString());
  return <div>{await res.text()}</div>;
}
```

---

## 8. Dependency Security (SCA)

### ความปลอดภัยของ Dependencies

**Effort:** Trivial-Small

```bash
# Audit dependencies
npm audit
npx npm-audit-resolver

# Fix automatically (patch/minor only)
npm audit fix

# Check for outdated packages
npx npm-check-updates --target minor
```

```json
// package.json — Pin critical security dependencies
{
  "overrides": {
    "semver": ">=7.5.4"
  }
}
```

---

## Quick Reference: Next.js Security Checklist

| Item                    | Check                                 | File           |
| ----------------------- | ------------------------------------- | -------------- |
| Security headers        | CSP, X-Frame-Options, HSTS            | next.config.js |
| Auth cookies            | httpOnly, secure, sameSite            | API routes     |
| Server vs Client        | No secrets in 'use client' components | components     |
| NEXT*PUBLIC*            | Only safe values prefixed             | .env.local     |
| Server Actions          | Zod validation on all inputs          | actions.ts     |
| API routes              | Auth + validation middleware          | app/api/       |
| dangerouslySetInnerHTML | DOMPurify on all external content     | components     |
| URL validation          | Protocol allowlist for user URLs      | components     |
