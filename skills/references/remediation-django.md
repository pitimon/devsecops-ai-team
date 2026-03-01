# Django Remediation Patterns

# รูปแบบการแก้ไขช่องโหว่สำหรับ Django

> **Purpose / วัตถุประสงค์**: Framework-specific fix patterns for Django (5.x / 4.x) projects.
> Extends generic `remediation-patterns.md` with Django-native APIs and idioms.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: Django 5.2, Django 4.2 LTS

---

## 1. Cross-Site Scripting / XSS (CWE-79)

### ช่องโหว่ XSS ใน Django Templates

**OWASP:** A03:2021 | **CVSS Range:** 6.1-7.5 | **Effort:** Low

**Decision Tree for `|safe` / `mark_safe()`:**

| Case                             | Safe? | Action                             |
| -------------------------------- | ----- | ---------------------------------- |
| Static HTML from developer code  | Yes   | `mark_safe()` acceptable           |
| User input displayed in template | No    | Use `{{ variable }}` auto-escaping |
| Mixed static + dynamic HTML      | No    | Use `format_html()` instead        |
| JSON data for `<script>` tag     | No    | Use `{{ data\|json_script:"id" }}` |

```python
# VULNERABLE: mark_safe() with user input
from django.utils.safestring import mark_safe
def render_name(request):
    name = request.GET.get('name', '')
    return HttpResponse(mark_safe(f'<b>{name}</b>'))

# FIXED: format_html() escapes dynamic parts
from django.utils.html import format_html
def render_name(request):
    name = request.GET.get('name', '')
    return HttpResponse(format_html('<b>{}</b>', name))
```

```html
<!-- VULNERABLE: |safe filter with user data -->
{{ user_bio|safe }}

<!-- FIXED: Auto-escaping (default) -->
{{ user_bio }}

<!-- FIXED: json_script for JavaScript data -->
{{ data|json_script:"config-data" }}
<script>
  const config = JSON.parse(document.getElementById("config-data").textContent);
</script>
```

**When `mark_safe()` IS acceptable:**

```python
# Static developer-controlled HTML — no user input
ICON_HTML = mark_safe('<svg viewBox="0 0 24 24"><path d="..."/></svg>')
```

---

## 2. SQL Injection (CWE-89)

### การฉีดคำสั่ง SQL ใน Django ORM

**OWASP:** A03:2021 | **CVSS Range:** 7.5-9.8 | **Effort:** Low-Medium

```python
# VULNERABLE: Raw SQL with string formatting
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")

# FIXED: Parameterized raw query
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])

# PREFERRED: ORM query (no raw SQL needed)
User.objects.filter(username=name)
```

```python
# VULNERABLE: extra() with string interpolation
queryset.extra(where=[f"name = '{user_input}'"])

# FIXED: extra() with params
queryset.extra(where=["name = %s"], params=[user_input])

# PREFERRED: Replace extra() with ORM
queryset.filter(name=user_input)
```

**RawSQL expressions:**

```python
# VULNERABLE
from django.db.models.expressions import RawSQL
queryset.annotate(val=RawSQL(f"field = {user_input}", []))

# FIXED: Use params argument
queryset.annotate(val=RawSQL("field = %s", [user_input]))
```

**Note:** Django's ORM (`filter()`, `exclude()`, `get()`, `annotate()`, `aggregate()`) auto-parameterizes. Only `raw()`, `extra()`, `RawSQL`, and `cursor.execute()` require manual parameterization.

---

## 3. CSRF Protection (CWE-352)

### การป้องกัน Cross-Site Request Forgery

**OWASP:** A01:2021 | **Effort:** Trivial

```python
# settings.py — Ensure CSRF middleware is active
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # MUST be present
    # ...
]
```

```html
<!-- VULNERABLE: Form without CSRF token -->
<form method="POST" action="/transfer/">
  <input name="amount" value="1000" />
</form>

<!-- FIXED: Add {% csrf_token %} -->
<form method="POST" action="/transfer/">
  {% csrf_token %}
  <input name="amount" value="1000" />
</form>
```

```python
# VULNERABLE: Blanket CSRF exemption
@csrf_exempt
def api_view(request):
    ...

# FIXED: Use DRF with token auth (inherently CSRF-safe for API clients)
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def api_view(request):
    ...
```

---

## 4. Authentication & Session (CWE-287, CWE-614)

### การตั้งค่า Authentication และ Session

**OWASP:** A07:2021 | **Effort:** Trivial-Small

```python
# settings.py — Production session security
SESSION_COOKIE_SECURE = True        # HTTPS only
SESSION_COOKIE_HTTPONLY = True       # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'     # CSRF protection
SESSION_COOKIE_AGE = 3600           # 1 hour timeout
CSRF_COOKIE_SECURE = True           # HTTPS only for CSRF cookie

# Password validation (Django 5.x)
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

```python
# VULNERABLE: Custom password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# FIXED: Django's built-in hasher (Argon2 preferred)
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

# Usage — never hash manually
from django.contrib.auth.hashers import make_password, check_password
hashed = make_password(raw_password)
is_valid = check_password(raw_password, hashed)
```

---

## 5. Security Headers (CWE-693)

### การตั้งค่า Security Headers

**OWASP:** A05:2021 | **Effort:** Trivial

```python
# settings.py — Django SecurityMiddleware settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000         # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True             # Force HTTPS
X_FRAME_OPTIONS = 'DENY'
```

```python
# CSP via django-csp (v4.0+)
# pip install django-csp
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    # ...
]
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
    }
}
```

---

## 6. Secret Management (CWE-798)

### การจัดการ Secret Keys

**OWASP:** A07:2021 | **Effort:** Trivial

```python
# VULNERABLE: Hardcoded secret in settings
SECRET_KEY = 'django-insecure-abc123xyz'

# FIXED: Environment variable
import os
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

# FIXED: django-environ (recommended for multiple settings)
import environ
env = environ.Env()
environ.Env.read_env('.env')
SECRET_KEY = env('DJANGO_SECRET_KEY')
DEBUG = env.bool('DEBUG', default=False)
DATABASES = {'default': env.db('DATABASE_URL')}
```

---

## 7. File Upload (CWE-434)

### การจัดการ File Upload อย่างปลอดภัย

**OWASP:** A04:2021 | **Effort:** Small

```python
# VULNERABLE: No file validation
def upload(request):
    f = request.FILES['file']
    with open(f'/uploads/{f.name}', 'wb') as dest:
        for chunk in f.chunks():
            dest.write(chunk)

# FIXED: Django model with FileField validation
from django.core.validators import FileExtensionValidator
from django.db import models

class Document(models.Model):
    file = models.FileField(
        upload_to='documents/%Y/%m/',
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'docx', 'txt'])],
    )

# settings.py
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
```

---

## 8. Debug & Error Disclosure (CWE-209, CWE-489)

### การป้องกันการเปิดเผยข้อมูล Debug

**OWASP:** A05:2021 | **Effort:** Trivial

```python
# CRITICAL: Never run DEBUG=True in production
# settings.py
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Restrict ALLOWED_HOSTS
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Custom error handlers to prevent info leakage
handler404 = 'myapp.views.custom_404'
handler500 = 'myapp.views.custom_500'
```

---

## 9. Django REST Framework Security (CWE-284, CWE-862)

### การรักษาความปลอดภัย DRF

**OWASP:** A01:2021 | **Effort:** Small

```python
# settings.py — Default authentication + permission
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
    },
}
```

```python
# VULNERABLE: No permission check on viewset
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()

# FIXED: Explicit permissions
from rest_framework.permissions import IsAuthenticated, IsAdminUser

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.action in ['destroy', 'update']:
            return [IsAdminUser()]
        return super().get_permissions()
```

---

## Quick Reference: Django Security Checklist

| Setting                    | Value                | File        |
| -------------------------- | -------------------- | ----------- |
| `DEBUG`                    | `False`              | settings.py |
| `SECRET_KEY`               | Environment variable | settings.py |
| `ALLOWED_HOSTS`            | Explicit list        | settings.py |
| `SESSION_COOKIE_SECURE`    | `True`               | settings.py |
| `CSRF_COOKIE_SECURE`       | `True`               | settings.py |
| `SECURE_SSL_REDIRECT`      | `True`               | settings.py |
| `SECURE_HSTS_SECONDS`      | `31536000`           | settings.py |
| `X_FRAME_OPTIONS`          | `DENY`               | settings.py |
| `{% csrf_token %}`         | All POST forms       | templates   |
| `AUTH_PASSWORD_VALIDATORS` | All 4 validators     | settings.py |
