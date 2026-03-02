# Software & Data Integrity Patterns

> **วัตถุประสงค์**: แนวทางป้องกัน Software and Data Integrity Failures (OWASP A08:2021) — ครอบคลุม CI/CD pipeline integrity, artifact signing, dependency verification, และ unsafe deserialization
>
> **Version**: 1.0 | **Last Updated**: 2026-03-02 | **Frameworks**: OWASP A08:2021, SLSA v1.0, Sigstore, CWE-345/353/494/502/829/915/1104

---

## 1. ภาพรวม A08 (Overview)

A08:2021 Software and Data Integrity Failures ครอบคลุมปัญหาที่ code และ infrastructure ไม่มี integrity verification เพียงพอ ทำให้ attacker สามารถ:

- แทรก malicious code ผ่าน CI/CD pipeline
- แก้ไข dependencies โดยไม่ถูกตรวจจับ (dependency confusion, typosquatting)
- Inject untrusted data ผ่าน deserialization
- โหลด code จาก untrusted sources โดยไม่ verify

### CWE Coverage

| CWE      | ชื่อ                                                     | Detection Tool | Severity |
| -------- | -------------------------------------------------------- | -------------- | -------- |
| CWE-345  | Insufficient Verification of Data Authenticity           | SCA, SBOM      | HIGH     |
| CWE-353  | Missing Support for Integrity Check                      | SCA, SBOM      | HIGH     |
| CWE-494  | Download of Code Without Integrity Check                 | SAST, SCA      | HIGH     |
| CWE-502  | Deserialization of Untrusted Data                        | SAST           | CRITICAL |
| CWE-829  | Inclusion of Functionality from Untrusted Control Sphere | SAST, SCA      | HIGH     |
| CWE-915  | Improperly Controlled Modification of Dynamic Objects    | SAST           | MEDIUM   |
| CWE-1104 | Use of Unmaintained Third Party Components               | SCA            | MEDIUM   |

---

## 2. CI/CD Pipeline Integrity

### 2.1 GitHub Actions Workflow Hardening

```yaml
# Bad: unpinned action (supply chain risk)
- uses: actions/checkout@v4

# Good: pinned to full SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

**Key practices:**

- Pin all actions to commit SHA, not tags (tags are mutable)
- Use `permissions:` block to limit GITHUB_TOKEN scope
- Enable Dependabot for action version updates
- Use `workflow_call` with strict input validation for reusable workflows

### 2.2 Artifact Signing with Sigstore/cosign

```bash
# Sign a container image
cosign sign --yes ghcr.io/org/app:v1.0.0

# Verify before deployment
cosign verify \
  --certificate-identity "https://github.com/org/app/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/org/app:v1.0.0
```

### 2.3 SLSA Build Provenance

| SLSA Level | Requirement                 | Implementation                   |
| ---------- | --------------------------- | -------------------------------- |
| 1          | Build process documented    | GitHub Actions workflow in repo  |
| 2          | Hosted build platform       | GitHub-hosted runners            |
| 3          | Hardened build platform     | Isolated runners, pinned deps    |
| 4          | Two-party review + hermetic | Branch protection + reproducible |

```bash
# Generate SLSA provenance with slsa-verifier
slsa-verifier verify-artifact myapp.tar.gz \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/org/app \
  --source-tag v1.0.0
```

---

## 3. Dependency Integrity

### 3.1 Lock File Verification

```bash
# npm: verify lockfile integrity
npm ci  # Uses package-lock.json exactly (fails on mismatch)

# pip: hash checking
pip install --require-hashes -r requirements.txt

# Go: verify module checksums
go mod verify
```

### 3.2 Dependency Confusion Prevention

| Attack Vector        | Mitigation                                    |
| -------------------- | --------------------------------------------- |
| Typosquatting        | Audit dependency names, use allowlists        |
| Dependency confusion | Configure scoped registries, namespace claims |
| Compromised package  | Pin versions + verify checksums               |
| Abandoned packages   | Monitor CWE-1104, check last update date      |

```bash
# npm: configure scoped registry
echo "@myorg:registry=https://npm.myorg.com/" >> .npmrc

# pip: configure extra-index-url with priority
pip install --index-url https://pypi.myorg.com/simple/ \
            --extra-index-url https://pypi.org/simple/ mypackage
```

### 3.3 Subresource Integrity (SRI)

```html
<!-- Bad: no integrity check (CWE-829) -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- Good: SRI hash verification -->
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
  crossorigin="anonymous"
></script>
```

---

## 4. Unsafe Deserialization (CWE-502)

### 4.1 Language-Specific Patterns

**Python:**

```python
# Vulnerable: pickle deserializes arbitrary objects
import pickle
data = pickle.loads(untrusted_bytes)  # CWE-502

# Fixed: use JSON or restrict classes
import json
data = json.loads(untrusted_string)

# If pickle is required, use restricted unpickler
import pickle, io
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in ("str", "int", "float", "list", "dict"):
            return getattr(__builtins__, name) if isinstance(__builtins__, dict) else getattr(__import__('builtins'), name)
        raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
```

**Java:**

```java
// Vulnerable: ObjectInputStream with no filter
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // CWE-502

// Fixed: ObjectInputFilter (Java 9+)
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*"  // allowlist only your classes
));
```

**Node.js:**

```javascript
// Vulnerable: node-serialize
const serialize = require("node-serialize");
serialize.unserialize(userInput); // CWE-502

// Fixed: use JSON.parse (no code execution)
const data = JSON.parse(userInput);
```

### 4.2 Framework-Specific Fixes

| Framework | Vulnerable Pattern           | Safe Alternative                   |
| --------- | ---------------------------- | ---------------------------------- |
| Django    | `pickle` in cache backend    | JSON serializer for cache          |
| Spring    | `ObjectMapper` without types | `@JsonTypeInfo` with allowlist     |
| Express   | `node-serialize`             | `JSON.parse()` + schema validation |
| Rails     | `Marshal.load`               | `JSON.parse` + `Oj` safe mode      |

---

## 5. Mass Assignment (CWE-915)

```python
# Vulnerable: accepts all fields from request (Django)
user = User(**request.POST.dict())  # CWE-915

# Fixed: explicit field allowlist
user = User(
    username=request.POST.get('username'),
    email=request.POST.get('email')
)
```

```javascript
// Vulnerable: spread all body params (Express)
const user = await User.create(req.body); // CWE-915

// Fixed: pick only allowed fields
const { name, email } = req.body;
const user = await User.create({ name, email });
```

---

## 6. Unmaintained Components (CWE-1104)

### Detection Criteria

| Signal               | Threshold           | Action                        |
| -------------------- | ------------------- | ----------------------------- |
| Last commit          | > 2 years ago       | Evaluate alternatives         |
| Open security issues | Unpatched > 90 days | Consider fork or replacement  |
| Maintainer count     | 1 (bus factor)      | Assess risk, identify backups |
| Downloads trend      | Declining > 50%     | Plan migration                |

### SBOM-Driven Detection

```bash
# Generate SBOM with Syft
syft dir:. -o cyclonedx-json > sbom.json

# Check component freshness with grype
grype sbom:sbom.json --only-fixed

# Flag unmaintained: components with no update in 2+ years
python3 -c "
import json, datetime
sbom = json.load(open('sbom.json'))
for comp in sbom.get('components', []):
    # Check against known unmaintained database
    print(f\"{comp['name']}@{comp.get('version', 'unknown')}\")
"
```

---

## 7. Remediation Priority Matrix

| CWE      | Effort  | Auto-fixable? | Priority |
| -------- | ------- | ------------- | -------- |
| CWE-502  | Medium  | Partial       | P1       |
| CWE-494  | Trivial | Yes           | P1       |
| CWE-829  | Trivial | Yes (SRI)     | P2       |
| CWE-345  | Small   | Yes           | P2       |
| CWE-353  | Small   | Yes           | P2       |
| CWE-915  | Small   | Yes           | P2       |
| CWE-1104 | Large   | No            | P3       |
