# Spring Remediation Patterns

# รูปแบบการแก้ไขช่องโหว่สำหรับ Spring

> **Purpose / วัตถุประสงค์**: Framework-specific fix patterns for Spring Boot 3.x / Spring Security 6.x projects.
> Extends generic `remediation-patterns.md` with Spring-native security configuration,
> JPA safety, and Thymeleaf template patterns.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: Spring Boot 3.4+, Spring Security 6.4+

---

## 1. Security Filter Chain (CWE-284, CWE-862)

### การตั้งค่า SecurityFilterChain

**OWASP:** A01:2021 | **Effort:** Medium

```java
// VULNERABLE: Permit all with no security
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}

// FIXED: Explicit route-level authorization
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**", "/health").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyAll()
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                .frameOptions(frame -> frame.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .preload(true)
                )
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        return http.build();
    }
}
```

**Method-level security:**

```java
// VULNERABLE: No method-level authorization
@RestController
public class UserController {
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}

// FIXED: @PreAuthorize with SpEL
@RestController
public class UserController {
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }

    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    @GetMapping("/users")
    public List<UserDTO> listUsers() {
        return userService.findAll();
    }
}
```

---

## 2. SQL / JPA Injection (CWE-89)

### การป้องกัน SQL Injection ใน JPA

**OWASP:** A03:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Low

```java
// VULNERABLE: String concatenation in @Query
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = '" + name + "'")
    List<User> findByName(String name);
}

// FIXED: Named parameters in JPQL
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.name = :name")
    List<User> findByName(@Param("name") String name);

    // Or use derived query methods (auto-parameterized)
    List<User> findByNameIgnoreCase(String name);
}
```

```java
// VULNERABLE: Native query with string interpolation
@Query(value = "SELECT * FROM users WHERE role = " + role, nativeQuery = true)
List<User> findByRole(String role);

// FIXED: Native query with positional parameters
@Query(value = "SELECT * FROM users WHERE role = ?1", nativeQuery = true)
List<User> findByRole(String role);
```

```java
// VULNERABLE: EntityManager with concatenation
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.email = '" + email + "'", User.class);

// FIXED: EntityManager with parameters
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.email = :email", User.class);
query.setParameter("email", email);
```

**Criteria API (always safe):**

```java
CriteriaBuilder cb = em.getCriteriaBuilder();
CriteriaQuery<User> cq = cb.createQuery(User.class);
Root<User> root = cq.from(User.class);
cq.where(cb.equal(root.get("email"), email)); // Auto-parameterized
```

---

## 3. Cross-Site Scripting / Thymeleaf (CWE-79)

### ช่องโหว่ XSS ใน Thymeleaf Templates

**OWASP:** A03:2021 | **CVSS Range:** 6.1-7.5 | **Effort:** Trivial

```html
<!-- VULNERABLE: th:utext renders raw HTML (unescaped) -->
<div th:utext="${userBio}"></div>

<!-- FIXED: th:text auto-escapes HTML entities -->
<div th:text="${userBio}"></div>
```

```html
<!-- VULNERABLE: Inline expression with raw HTML -->
<div>[(${userComment})]</div>

<!-- FIXED: Escaped inline expression -->
<div>[[${userComment}]]</div>
```

**When `th:utext` IS acceptable:**

```html
<!-- Admin-generated static HTML — no user input -->
<div th:utext="${@staticContentService.getFooterHtml()}"></div>
```

**URL attribute safety:**

```html
<!-- VULNERABLE: Direct string URL -->
<a th:href="'/redirect?url=' + ${userUrl}">Link</a>

<!-- FIXED: Use @{} syntax with validated URL -->
<a th:href="@{/redirect(url=${@urlValidator.sanitize(userUrl)})}">Link</a>
```

---

## 4. Password Encoding (CWE-327, CWE-916)

### การเข้ารหัส Password

**OWASP:** A02:2021 | **Effort:** Small

```java
// VULNERABLE: MD5 / SHA-1 password hashing
String hash = DigestUtils.md5Hex(password);

// FIXED: BCryptPasswordEncoder (Spring Security default)
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // Cost factor 12
}

// Usage
String encoded = passwordEncoder.encode(rawPassword);
boolean matches = passwordEncoder.matches(rawPassword, encoded);
```

```java
// For new projects — Argon2 (recommended)
@Bean
public PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
    // saltLength, hashLength, parallelism, memory(KB), iterations
}

// Or use DelegatingPasswordEncoder for migration
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    // Auto-detects {bcrypt}, {argon2}, {scrypt} prefixes
}
```

---

## 5. CSRF Protection (CWE-352)

### การป้องกัน CSRF

**OWASP:** A01:2021 | **Effort:** Trivial-Small

```java
// Spring Security 6.x CSRF configuration
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
        // Disable for stateless APIs using token auth
        .ignoringRequestMatchers("/api/webhooks/**")
    );
    return http.build();
}
```

```html
<!-- Thymeleaf form — CSRF token auto-included -->
<form th:action="@{/transfer}" method="post">
  <!-- Spring adds hidden _csrf field automatically -->
  <input type="text" name="amount" />
  <button type="submit">Transfer</button>
</form>
```

**For REST APIs with JWT (stateless — disable CSRF):**

```java
http.csrf(csrf -> csrf.disable())
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
```

---

## 6. Input Validation (CWE-20)

### การ Validate Input ด้วย Bean Validation

**OWASP:** A03:2021 | **Effort:** Small

```java
// VULNERABLE: No input validation
@PostMapping("/users")
public User createUser(@RequestBody User user) {
    return userService.save(user);
}

// FIXED: Bean Validation (Jakarta Validation)
public record CreateUserRequest(
    @NotBlank @Size(min = 1, max = 100) String name,
    @Email @NotBlank String email,
    @Min(0) @Max(150) Integer age,
    @Pattern(regexp = "^[a-z0-9]+$") String username
) {}

@PostMapping("/users")
public User createUser(@Valid @RequestBody CreateUserRequest request) {
    return userService.create(request);
}

// Global validation error handler
@RestControllerAdvice
public class ValidationHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(
            MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors()
            .forEach(e -> errors.put(e.getField(), e.getDefaultMessage()));
        return ResponseEntity.badRequest().body(errors);
    }
}
```

---

## 7. Secret Management (CWE-798)

### การจัดการ Secrets

**OWASP:** A07:2021 | **Effort:** Trivial-Small

```yaml
# VULNERABLE: Hardcoded credentials in application.yml
spring:
  datasource:
    password: myS3cretP@ss

# FIXED Option 1: Environment variables
spring:
  datasource:
    password: ${DB_PASSWORD}

# FIXED Option 2: Spring Cloud Vault
spring:
  cloud:
    vault:
      uri: https://vault.example.com
      authentication: TOKEN
      token: ${VAULT_TOKEN}
```

```java
// VULNERABLE: Hardcoded API key
private static final String API_KEY = "sk-abc123";

// FIXED: @Value from environment
@Value("${api.key}")
private String apiKey;
```

---

## 8. CORS Configuration (CWE-942)

### การตั้งค่า CORS

**OWASP:** A05:2021 | **Effort:** Trivial

```java
// VULNERABLE: Allow all origins
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOrigin("*");
    config.addAllowedMethod("*");
    config.addAllowedHeader("*");
    // ...
}

// FIXED: Explicit allowed origins
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(
        "https://app.example.com",
        "https://admin.example.com"
    ));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}
```

---

## 9. Error Handling (CWE-209)

### การจัดการ Error อย่างปลอดภัย

**OWASP:** A05:2021 | **Effort:** Small

```yaml
# application.yml — Disable stack traces in responses
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never
```

```java
// VULNERABLE: Leaking internal details
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleAll(Exception ex) {
    return ResponseEntity.status(500).body(ex.getMessage());
}

// FIXED: Generic response + server-side logging
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleAll(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(500)
            .body(Map.of("error", "Internal server error"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleForbidden(AccessDeniedException ex) {
        return ResponseEntity.status(403)
            .body(Map.of("error", "Access denied"));
    }
}
```

---

## 10. Actuator Security (CWE-200)

### การรักษาความปลอดภัย Spring Actuator

**OWASP:** A05:2021 | **Effort:** Trivial

```yaml
# VULNERABLE: All actuator endpoints exposed
management:
  endpoints:
    web:
      exposure:
        include: "*"

# FIXED: Expose only health and info
management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: when-authorized
```

```java
// Protect actuator with Spring Security
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/actuator/health", "/actuator/info").permitAll()
    .requestMatchers("/actuator/**").hasRole("ADMIN")
);
```

---

## Quick Reference: Spring Security Checklist

| Item                | Configuration                 | File                |
| ------------------- | ----------------------------- | ------------------- |
| SecurityFilterChain | Explicit route auth           | SecurityConfig.java |
| CSRF                | CookieCsrfTokenRepository     | SecurityConfig.java |
| CORS                | Explicit allowed origins      | SecurityConfig.java |
| Password encoder    | BCrypt (cost 12+) or Argon2   | SecurityConfig.java |
| @PreAuthorize       | Method-level auth             | Controllers         |
| JPA queries         | Named parameters only         | Repositories        |
| Thymeleaf           | `th:text` (not `th:utext`)    | Templates           |
| Secrets             | Environment variables / Vault | application.yml     |
| Actuator            | Restrict exposed endpoints    | application.yml     |
| Error handling      | No stack traces in response   | application.yml     |
