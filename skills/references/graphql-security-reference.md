# GraphQL Security Reference

# ความรู้อ้างอิงด้านความปลอดภัย GraphQL

> **Purpose / วัตถุประสงค์**: Domain knowledge for GraphQL API security scanning. Covers OWASP GraphQL Cheat Sheet, attack patterns, framework-specific guidance, defense patterns, and common CWE mappings.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-03 | **Standards**: OWASP GraphQL Cheat Sheet 2025, OWASP API Security Top 10 2023

---

## 1. OWASP GraphQL Cheat Sheet Summary

## สรุป OWASP GraphQL Cheat Sheet

GraphQL introduces unique attack surfaces compared to REST APIs due to its flexible query language, type introspection system, and single-endpoint architecture. The OWASP GraphQL Cheat Sheet identifies these primary security concerns:

```
KEY SECURITY CONCERNS:
  1. Introspection and Schema Exposure — attackers discover full API surface
  2. Denial of Service via Query Complexity — deeply nested or aliased queries
  3. Authorization Bypass — field-level and resolver-level access control gaps
  4. Injection Attacks — SQL/NoSQL injection through resolver arguments
  5. Batching Attacks — authentication brute-force via query batching
  6. Information Disclosure — verbose errors, field suggestions, debug mode
```

### OWASP API Security Top 10 (2023) Mapping

| OWASP API | Category                            | GraphQL Relevance                                 |
| --------- | ----------------------------------- | ------------------------------------------------- |
| API1      | Broken Object Level Authorization   | Resolver-level authz bypass, IDOR via node IDs    |
| API2      | Broken Authentication               | Batch brute-force via query arrays                |
| API3      | Broken Object Property Level Authz  | Field-level access, unauthorized field access     |
| API4      | Unrestricted Resource Consumption   | Depth bombing, alias attack, batch DoS            |
| API5      | Broken Function Level Authorization | Mutation access without proper role checks        |
| API8      | Security Misconfiguration           | Introspection enabled, debug mode, verbose errors |

---

## 2. Attack Patterns

## รูปแบบการโจมตี GraphQL

### 2.1 Introspection Abuse (CWE-200)

```graphql
# Full schema extraction via introspection query
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
          ofType {
            name
          }
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
  }
}

# Targeted type discovery
{
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
      }
    }
  }
}
```

**Impact**: Attacker maps entire API surface — all types, fields, mutations, subscriptions. Discovers internal fields like `isAdmin`, `passwordHash`, `internalNotes`.

**Detection**: Check if introspection query returns valid `__schema` response in production.

### 2.2 Depth Bombing / Query Depth Attack (CWE-400)

```graphql
# Exponential resource consumption via deeply nested query
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  id
                  email
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Impact**: Server recursively resolves N levels deep, each potentially triggering database queries. A depth-20 query on a social graph can generate millions of DB calls.

**Detection**: Send query with depth > 15. If server processes it, depth limiting is absent.

### 2.3 Batch Query / Array-Based DoS (CWE-770)

```json
[
  { "query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass4\") { token } }" },
  { "query": "mutation { login(user:\"admin\", pass:\"pass5\") { token } }" }
]
```

**Impact**: Bypass rate limiting by sending hundreds of operations in a single HTTP request. Enables credential brute-force, OTP enumeration, or DoS.

**Detection**: Send array of 10+ queries in single POST. If all execute, batch limiting is absent.

### 2.4 Alias-Based Attack (CWE-400)

```graphql
# Resource multiplication via aliases — single request, N executions
{
  a1: user(id: 1) {
    email
  }
  a2: user(id: 2) {
    email
  }
  a3: user(id: 3) {
    email
  }
  a4: user(id: 4) {
    email
  }
  # ... repeat 1000 times
  a1000: user(id: 1000) {
    email
  }
}
```

**Impact**: Even with depth limiting, aliases let attackers multiply resolver execution within a single flat query. 1000 aliases = 1000 database lookups.

**Detection**: Send query with 100+ aliases. If all resolve, cost analysis is absent.

### 2.5 Field Suggestion Enumeration (CWE-200)

```graphql
# Intentional typo to trigger field suggestions
{
  usre {
    # typo: "usre" instead of "user"
    id
  }
}
```

```json
{
  "errors": [
    {
      "message": "Cannot query field \"usre\" on type \"Query\". Did you mean \"user\" or \"users\"?",
      "extensions": { "code": "GRAPHQL_VALIDATION_FAILED" }
    }
  ]
}
```

**Impact**: Even with introspection disabled, field suggestions leak schema information. Attackers enumerate valid field names by iterating through typos.

**Detection**: Send query with intentional typo. If response contains "Did you mean" suggestions, field suggestion is enabled.

### 2.6 Circular Fragment / Fragment Depth Attack (CWE-400)

```graphql
# Circular fragment reference (should be caught by parser)
fragment A on User {
  friends {
    ...B
  }
}
fragment B on User {
  friends {
    ...A
  }
}
{
  user(id: 1) {
    ...A
  }
}
```

**Impact**: If the GraphQL engine does not validate fragment cycles, this creates infinite recursion causing stack overflow or OOM.

---

## 3. Framework-Specific Guidance

## คำแนะนำเฉพาะ Framework

### 3.1 Apollo Server (JavaScript/TypeScript)

```typescript
import { ApolloServer } from "@apollo/server";
import depthLimit from "graphql-depth-limit";
import costAnalysis from "graphql-cost-analysis";
import { ApolloServerPluginLandingPageDisabled } from "@apollo/server/plugin/disabled";

const server = new ApolloServer({
  typeDefs,
  resolvers,
  // SECURITY: Disable introspection in production
  introspection: process.env.NODE_ENV !== "production",
  // SECURITY: Disable Apollo Sandbox/Explorer in production
  plugins: [
    process.env.NODE_ENV === "production"
      ? ApolloServerPluginLandingPageDisabled()
      : ApolloServerPluginLandingPageLocalDefault(),
  ],
  validationRules: [
    // SECURITY: Limit query depth
    depthLimit(10),
    // SECURITY: Limit query cost
    costAnalysis({
      maximumCost: 1000,
      defaultCost: 1,
      variables: req.body.variables,
      onComplete: (cost) => console.log(`Query cost: ${cost}`),
    }),
  ],
});

// SECURITY: Rate limiting (express-rate-limit or similar)
import rateLimit from "express-rate-limit";
app.use(
  "/graphql",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests",
  }),
);

// SECURITY: Disable batch queries
// Apollo Server 4.x does not support batching by default
// For Apollo Server 3.x, set allowBatchedHttpRequests: false
```

**Common Misconfigurations**:

- `introspection: true` in production (default in dev mode)
- No `depthLimit` validation rule
- Missing rate limiting on `/graphql` endpoint
- `formatError` leaking stack traces

### 3.2 graphql-yoga (JavaScript/TypeScript)

```typescript
import { createYoga, createSchema } from "graphql-yoga";
import { useDepthLimit } from "@graphql-yoga/plugin-depth-limit";
import { useDisableIntrospection } from "@graphql-yoga/plugin-disable-introspection";
import { useResponseCache } from "@graphql-yoga/plugin-response-cache";

const yoga = createYoga({
  schema: createSchema({ typeDefs, resolvers }),
  plugins: [
    // SECURITY: Disable introspection in production
    process.env.NODE_ENV === "production"
      ? useDisableIntrospection()
      : undefined,
    // SECURITY: Limit query depth
    useDepthLimit({ maxDepth: 10 }),
    // SECURITY: Response caching (reduces DoS impact)
    useResponseCache({ session: (req) => req.headers.get("authorization") }),
  ].filter(Boolean),
  // SECURITY: Disable batching
  batching: false,
  // SECURITY: Mask errors in production
  maskedErrors: process.env.NODE_ENV === "production",
});
```

### 3.3 Strawberry (Python)

```python
import strawberry
from strawberry.extensions import QueryDepthLimiter, MaxAliasesLimiter
from strawberry.extensions import DisableValidation
from strawberry.permission import BasePermission
from typing import Any, Union
import strawberry.django  # if using Django

# SECURITY: Custom permission class
class IsAuthenticated(BasePermission):
    message = "User is not authenticated"

    def has_permission(self, source: Any, info: strawberry.types.Info, **kwargs) -> bool:
        return info.context.request.user.is_authenticated

# SECURITY: Field-level authorization
@strawberry.type
class Query:
    @strawberry.field(permission_classes=[IsAuthenticated])
    def users(self) -> list[User]:
        return User.objects.all()

# Schema with security extensions
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[
        # SECURITY: Limit query depth
        QueryDepthLimiter(max_depth=10),
        # SECURITY: Limit aliases (Strawberry 0.220+)
        MaxAliasesLimiter(max_alias_count=20),
    ],
)

# SECURITY: Disable introspection in production (Django view)
from strawberry.django.views import GraphQLView

urlpatterns = [
    path("graphql/", GraphQLView.as_view(
        schema=schema,
        # Disable GraphiQL in production
        graphiql=settings.DEBUG,
        # Disable introspection in production
        allow_queries_via_get=False,
    )),
]

# For ASGI, pass introspection=False in production
# schema = strawberry.Schema(query=Query, introspection=not settings.PRODUCTION)
```

### 3.4 graphql-java

```java
import graphql.GraphQL;
import graphql.analysis.MaxQueryDepthInstrumentation;
import graphql.analysis.MaxQueryComplexityInstrumentation;
import graphql.execution.instrumentation.ChainedInstrumentation;

// SECURITY: Query depth and complexity limits
GraphQL graphQL = GraphQL.newGraphQL(schema)
    .instrumentation(new ChainedInstrumentation(
        // Max depth of 10
        new MaxQueryDepthInstrumentation(10),
        // Max complexity of 200
        new MaxQueryComplexityInstrumentation(200)
    ))
    .build();

// SECURITY: Disable introspection in production
// Option 1: Custom Instrumentation to block __schema and __type
// Option 2: Use graphql-java visibility
import graphql.schema.visibility.NoIntrospectionGraphqlFieldVisibility;

GraphQLSchema schema = GraphQLSchema.newSchema()
    .query(queryType)
    .fieldVisibility(
        env.equals("production")
            ? NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY
            : DefaultGraphqlFieldVisibility.DEFAULT_FIELD_VISIBILITY
    )
    .build();

// SECURITY: Error masking
GraphQL graphQL = GraphQL.newGraphQL(schema)
    .defaultDataFetcherExceptionHandler(new SimpleDataFetcherExceptionHandler() {
        @Override
        public DataFetcherExceptionHandlerResult onException(
            DataFetcherExceptionHandlerParameters params) {
            // Log full error internally, return generic message
            log.error("GraphQL error", params.getException());
            return DataFetcherExceptionHandlerResult.newResult()
                .error(GraphqlErrorBuilder.newError(params.getDataFetchingEnvironment())
                    .message("Internal server error")
                    .build())
                .build();
        }
    })
    .build();
```

---

## 4. Defense Patterns

## รูปแบบการป้องกัน

### 4.1 Depth Limiting

```
STRATEGY: Reject queries exceeding maximum nesting depth.

RECOMMENDED MAX DEPTH BY API TYPE:
  Simple CRUD API:      depth 5-7
  Relational data API:  depth 8-12
  Social graph API:     depth 10-15
  Public API:           depth 5-8 (more restrictive)

IMPLEMENTATION: Validation rule that traverses AST and counts nesting levels.
  - Count per-selection-set depth
  - Fragment spreads count toward depth
  - Inline fragments count toward depth
```

### 4.2 Query Cost Analysis

```
STRATEGY: Assign cost to each field/resolver based on estimated resource usage.
          Reject queries exceeding maximum total cost.

COST FACTORS:
  - Base cost per field: 1
  - List fields: cost * estimated list size (e.g., 10)
  - Database fields: cost * 5
  - Computed fields: cost based on complexity
  - Pagination: cost * page_size argument

EXAMPLE COST CALCULATION:
  { users(first: 100) { name friends(first: 50) { name } } }
  = 1 (users) + 100 * (1 (name) + 1 (friends) + 50 * 1 (name))
  = 1 + 100 * (1 + 1 + 50)
  = 5201

RECOMMENDED MAX COST:
  Internal API:   5000-10000
  Public API:     500-1000
```

### 4.3 Rate Limiting

```
STRATEGY: Limit requests per client per time window.

APPROACHES:
  1. HTTP-level: Standard rate limiting on /graphql endpoint
     - Simple but coarse (all operations same weight)

  2. Operation-level: Rate limit based on operation type
     - Mutations: stricter limit (50/min)
     - Queries: moderate limit (200/min)
     - Subscriptions: connection limit (5 concurrent)

  3. Cost-based: Rate limit based on query cost
     - Budget per client: 10000 cost units per minute
     - Each query deducts its computed cost
     - Fairest approach, prevents DoS via complex queries

IMPLEMENTATION:
  - Redis-backed sliding window counter
  - Include client ID (API key, JWT sub, IP) in rate limit key
  - Return 429 with Retry-After header
  - GraphQL-specific: return error in response body, not HTTP 429
```

### 4.4 Introspection Disabling

```
STRATEGY: Disable introspection in production while keeping it available in development.

APPROACHES:
  1. Server config: introspection: false (Apollo, Yoga)
  2. Validation rule: custom rule rejecting __schema/__type queries
  3. Schema visibility: hide introspection fields (graphql-java)
  4. WAF rule: block requests containing "__schema" or "__type"

ADDITIONAL MEASURES:
  - Disable field suggestions (prevent schema leak via typos)
  - Remove GraphiQL/Playground in production
  - Use persisted queries (allowlist known operations)
```

### 4.5 Query Allowlisting (Persisted Queries)

```
STRATEGY: Only allow pre-registered query operations. Reject arbitrary queries.

HOW IT WORKS:
  1. Build time: Extract all GraphQL operations from client code
  2. Generate hash (SHA256) for each operation
  3. Register hash -> query mapping on server
  4. Client sends hash instead of full query string
  5. Server looks up query by hash, rejects unknown hashes

BENEFITS:
  - Eliminates all query-based attacks (depth, cost, injection)
  - Reduces bandwidth (hash instead of full query)
  - Enables server-side query optimization

TOOLS:
  - Apollo: Automatic Persisted Queries (APQ)
  - Relay: relay-compiler generates persisted queries
  - graphql-codegen: persisted-operations plugin

LIMITATION:
  - Not suitable for public APIs where clients write arbitrary queries
  - Requires build-time coordination between client and server
```

### 4.6 Authorization Patterns

```
RESOLVER-LEVEL AUTHORIZATION:
  - Check permissions in every resolver, not just at gateway
  - Use middleware/directives for consistent enforcement
  - Never trust client-provided IDs without ownership verification

FIELD-LEVEL AUTHORIZATION:
  - Sensitive fields (email, SSN, salary) require additional checks
  - Use schema directives: @auth(requires: ADMIN)
  - Null out unauthorized fields rather than erroring

COMMON MISTAKES:
  - Checking auth only on Query/Mutation, not nested resolvers
  - Relying on introspection disabling as access control
  - Missing authorization on subscription resolvers
  - IDOR via GraphQL node/relay global IDs
```

---

## 5. Common CWEs for GraphQL

## CWE ที่พบบ่อยใน GraphQL

| CWE     | Name                                  | GraphQL Context                                       | Severity |
| ------- | ------------------------------------- | ----------------------------------------------------- | -------- |
| CWE-200 | Exposure of Sensitive Information     | Introspection leak, field suggestions, verbose errors | medium   |
| CWE-209 | Error Message Information Exposure    | Stack traces in GraphQL error responses               | medium   |
| CWE-400 | Uncontrolled Resource Consumption     | Depth bombing, alias multiplication, circular queries | high     |
| CWE-770 | Allocation Without Limits             | Unlimited batch queries, unbounded list pagination    | high     |
| CWE-862 | Missing Authorization                 | Resolvers without auth checks, field-level access     | high     |
| CWE-863 | Incorrect Authorization               | Broken object-level auth in nested resolvers          | high     |
| CWE-89  | SQL Injection                         | Raw SQL in resolvers with unsanitized arguments       | critical |
| CWE-943 | Improper Neutralization (NoSQL/Query) | NoSQL injection via GraphQL variables                 | high     |

### CWE to OWASP Mapping

```
CWE-200 (Info Exposure)         → OWASP A01 (Access Control), API8 (Misconfig)
CWE-209 (Error Info Exposure)   → OWASP A05 (Misconfig), API8 (Misconfig)
CWE-400 (Resource Consumption)  → OWASP A05 (Misconfig), API4 (Resource Consumption)
CWE-770 (Allocation No Limits)  → OWASP A05 (Misconfig), API4 (Resource Consumption)
CWE-862 (Missing Authorization) → OWASP A01 (Access Control), API1 (Object Level Authz)
CWE-863 (Incorrect Authorization)→ OWASP A01 (Access Control), API3 (Property Level Authz)
CWE-89  (SQL Injection)         → OWASP A03 (Injection), API8 (Misconfig)
CWE-943 (NoSQL Injection)       → OWASP A03 (Injection), API8 (Misconfig)
```

---

## 6. Scan Checklist

## รายการตรวจสอบการสแกน GraphQL

### Static Analysis Checks

```
CONFIGURATION:
  [ ] Introspection disabled in production config
  [ ] GraphiQL/Playground disabled in production
  [ ] Depth limit configured (max 10-15)
  [ ] Query cost/complexity analysis enabled
  [ ] Batch query limit configured
  [ ] Field suggestion disabled in production
  [ ] Error masking enabled (no stack traces)
  [ ] CORS properly configured for GraphQL endpoint

RESOLVER SECURITY:
  [ ] All resolvers have authentication checks
  [ ] Field-level authorization on sensitive fields
  [ ] No raw SQL/NoSQL in resolvers (use parameterized queries)
  [ ] Input validation on all resolver arguments
  [ ] Subscription resolvers require authentication
  [ ] Mutation resolvers check object ownership (no IDOR)

SCHEMA DESIGN:
  [ ] No sensitive fields exposed without authorization
  [ ] Pagination enforced on list fields (max page size)
  [ ] File upload size limits configured
  [ ] Rate limiting on mutations (especially auth-related)
```

### Live Endpoint Checks

```
INTROSPECTION:
  [ ] POST { __schema { types { name } } } returns error, not schema
  [ ] __type queries are blocked

DEPTH:
  [ ] Deeply nested query (depth 20+) is rejected
  [ ] Error message does not reveal depth limit value

BATCH:
  [ ] Array of 100+ queries is rejected or limited
  [ ] Individual queries in batch are still rate-limited

ALIAS:
  [ ] Query with 100+ aliases is rejected or cost-limited

FIELD SUGGESTION:
  [ ] Intentional typo does not return "Did you mean" suggestions

ERROR HANDLING:
  [ ] Invalid query returns generic error, not stack trace
  [ ] Server errors return generic message, not internal details

RATE LIMITING:
  [ ] 429 or GraphQL error returned after exceeding rate limit
  [ ] Rate limit applies per-client, not globally
```

---

## 7. Tool-Specific Integration

## การเชื่อมต่อเครื่องมือ

### Semgrep Custom Rules

Rules file: `rules/graphql-rules.yml` (8 rules targeting JavaScript/TypeScript, Python, and Java resolvers)

### Nuclei Templates

Templates directory: `runner/nuclei-templates/graphql/` (4 templates for live endpoint scanning):

- `graphql-introspection.yaml` — detect open introspection
- `graphql-field-suggestion.yaml` — schema leak via field suggestions
- `graphql-batch-query.yaml` — unlimited batch detection
- `graphql-depth-attack.yaml` — depth limit check

### ZAP GraphQL Scan

ZAP supports GraphQL scanning natively via `zap-api-scan.py -f graphql`. Use this for authenticated GraphQL scanning when the endpoint supports introspection:

```bash
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t https://api.example.com/graphql \
  -f graphql \
  -r graphql-report.html \
  -J graphql-report.json
```
