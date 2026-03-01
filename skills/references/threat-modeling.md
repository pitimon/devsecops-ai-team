# Threat Modeling Reference

# คู่มือการสร้างแบบจำลองภัยคุกคาม

> **Purpose / วัตถุประสงค์**: Domain knowledge for DevSecOps agents performing threat modeling
> activities. Covers the STRIDE methodology, PASTA framework, Data Flow Diagram (DFD)
> construction, trust boundary identification, risk scoring, attack tree examples, threat
> categorization, OWASP Threat Modeling Process, and data flow analysis. Agents load this
> file when conducting threat assessments, reviewing architecture for security risks, or
> generating threat models from system descriptions.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: STRIDE (Microsoft SDL), PASTA v2.0, OWASP Threat Modeling v4.2, MITRE ATT&CK v16, CVSS v4.0, NIST SP 800-154

---

## 1. STRIDE Methodology / วิธีการ STRIDE

STRIDE was developed by Microsoft and categorizes threats into six types.
Each category maps to a security property violation.

### 1.1 STRIDE Categories

### หมวดหมู่ STRIDE

| Category              | Thai Translation  | Security Property | CWE Examples     | Symbol |
| --------------------- | ----------------- | ----------------- | ---------------- | ------ |
| **S**poofing          | การปลอมแปลงตัวตน  | Authentication    | CWE-287, CWE-290 | S      |
| **T**ampering         | การดัดแปลงข้อมูล  | Integrity         | CWE-345, CWE-353 | T      |
| **R**epudiation       | การปฏิเสธการกระทำ | Non-repudiation   | CWE-778, CWE-223 | R      |
| **I**nformation Disc. | การรั่วไหลข้อมูล  | Confidentiality   | CWE-200, CWE-209 | I      |
| **D**enial of Service | การปฏิเสธบริการ   | Availability      | CWE-400, CWE-770 | D      |
| **E**levation of Priv | การยกระดับสิทธิ์  | Authorization     | CWE-269, CWE-862 | E      |

### 1.2 STRIDE per Element

### STRIDE ต่อองค์ประกอบ

Apply STRIDE selectively based on DFD element type:

| DFD Element     | S   | T   | R   | I   | D   | E   |
| --------------- | --- | --- | --- | --- | --- | --- |
| External Entity | X   |     |     |     |     |     |
| Process         | X   | X   | X   | X   | X   | X   |
| Data Store      |     | X   | X   | X   | X   |     |
| Data Flow       |     | X   |     | X   | X   |     |
| Trust Boundary  |     |     |     |     |     |     |

### 1.3 STRIDE Examples per Category / ตัวอย่างแต่ละประเภท

**Spoofing:**

```text
Threat:   Attacker forges JWT token to impersonate admin user
Element:  API Gateway (Process)
Impact:   Unauthorized access to admin endpoints
Mitigation: Token signature verification, short TTL, token binding
NIST:     IA-2 (Identification and Authentication)
OWASP:    A07:2021 Authentication Failures
```

**Tampering:**

```text
Threat:   Man-in-the-middle modifies API response data in transit
Element:  API Response (Data Flow)
Impact:   Client receives corrupted or malicious data
Mitigation: TLS 1.3, response signing, integrity headers
NIST:     SC-8 (Transmission Confidentiality and Integrity)
OWASP:    A02:2021 Cryptographic Failures
```

**Repudiation:**

```text
Threat:   User denies performing a financial transaction
Element:  Transaction Service (Process)
Impact:   Cannot prove user initiated the transaction
Mitigation: Audit logging, digital signatures, timestamps
NIST:     AU-2 (Event Logging), AU-10 (Non-repudiation)
OWASP:    A09:2021 Security Logging & Monitoring Failures
```

**Information Disclosure:**

```text
Threat:   Database backup exposed via misconfigured S3 bucket
Element:  Database Backup (Data Store)
Impact:   PII/PHI data breach, regulatory violation
Mitigation: Encryption at rest, bucket policies, access logging
NIST:     SC-28 (Protection of Information at Rest)
OWASP:    A01:2021 Broken Access Control
```

**Denial of Service:**

```text
Threat:   API endpoint overwhelmed by volumetric request flood
Element:  Public API (Process)
Impact:   Service unavailable for legitimate users
Mitigation: Rate limiting, CDN, auto-scaling, circuit breakers
NIST:     SC-5 (Denial-of-Service Protection)
CIS:      CIS-13 (Network Monitoring & Defense)
```

**Elevation of Privilege:**

```text
Threat:   Container escape via kernel vulnerability
Element:  Application Container (Process)
Impact:   Attacker gains host-level access
Mitigation: Seccomp profiles, non-root containers, read-only FS
NIST:     AC-6 (Least Privilege), CM-7 (Least Functionality)
ATT&CK:  T1611 (Escape to Host)
```

---

## 2. PASTA Framework / กรอบการทำงาน PASTA

## กระบวนการจำลองการโจมตีและวิเคราะห์ภัยคุกคาม

PASTA (Process for Attack Simulation and Threat Analysis) is a seven-stage,
risk-centric threat modeling framework.

### 2.1 Seven Stages

### เจ็ดขั้นตอน

| Stage | Name                              | Thai Translation              | Key Activities                               | Output                    |
| ----- | --------------------------------- | ----------------------------- | -------------------------------------------- | ------------------------- |
| I     | Define Objectives                 | กำหนดวัตถุประสงค์             | Business objectives, compliance requirements | Objectives document       |
| II    | Define Technical Scope            | กำหนดขอบเขตทางเทคนิค          | Architecture diagrams, technology stack      | Technical scope document  |
| III   | Application Decomposition         | แยกส่วนประกอบแอปพลิเคชัน      | DFDs, trust boundaries, entry points         | Decomposition diagrams    |
| IV    | Threat Analysis                   | วิเคราะห์ภัยคุกคาม            | Threat intelligence, attack libraries        | Threat list               |
| V     | Vulnerability & Weakness Analysis | วิเคราะห์ช่องโหว่และจุดอ่อน   | Vulnerability scanning, code review results  | Vulnerability inventory   |
| VI    | Attack Modeling & Simulation      | จำลองและทดสอบการโจมตี         | Attack trees, attack patterns                | Attack scenarios          |
| VII   | Risk & Impact Analysis            | วิเคราะห์ความเสี่ยงและผลกระทบ | Risk scoring, business impact assessment     | Prioritized risk register |

### 2.2 Stage-by-Stage Detail

**Stage I — Define Objectives:**

```text
Questions to answer:
- What are the business-critical assets?
- What compliance requirements apply (PDPA, PCI DSS, HIPAA)?
- What is the organization's risk appetite?
- What are the consequences of a breach (financial, reputational, legal)?

Deliverable: 1-page business context summary with risk appetite statement
```

**Stage II — Define Technical Scope:**

```text
Document:
- System architecture diagram (C4 model recommended: Context, Container, Component)
- Technology stack (languages, frameworks, databases, cloud services)
- Authentication/authorization mechanisms
- Network topology and deployment model
- Third-party integrations and APIs

Deliverable: Architecture Decision Records (ADRs) + C4 diagrams
```

**Stage III — Application Decomposition:**

```text
Create:
- Level 0 DFD (Context diagram)
- Level 1 DFD (Major processes and data stores)
- Level 2 DFD (Detailed sub-processes where needed)
- Trust boundary annotations
- Entry points catalog
- Asset inventory (data classification: public, internal, confidential, restricted)

Deliverable: DFD set with trust boundaries and asset classification
```

**Stage IV — Threat Analysis:**

```text
Activities:
- Review MITRE ATT&CK techniques relevant to the tech stack
- Check threat intelligence feeds for industry-specific threats
- Apply STRIDE per element from Stage III
- Reference known attack patterns (CAPEC database)

Deliverable: Threat catalog with ATT&CK mapping
```

**Stage V — Vulnerability & Weakness Analysis:**

```text
Inputs:
- SAST scan results (e.g., Semgrep v1.67+, CodeQL v2.16+)
- DAST scan results (e.g., ZAP v2.15+, Nuclei v3.x)
- SCA findings (e.g., Trivy v0.58+, Grype v0.85+)
- IaC scan results (e.g., Checkov v3.x, tfsec)
- Manual code review findings
- CWE classification for each finding

Deliverable: Vulnerability inventory with CWE mapping
```

**Stage VI — Attack Modeling & Simulation:**

```text
Create attack trees for top threats:
- Root: attacker goal (e.g., "Exfiltrate customer PII")
- Branches: alternative attack paths
- Leaves: specific techniques
- Annotations: probability, skill level, detection difficulty

Deliverable: Attack tree diagrams + simulated scenarios
```

**Stage VII — Risk & Impact Analysis:**

```text
For each threat-vulnerability pair:
- Calculate risk score (see Section 5)
- Assess business impact (CIA + financial + regulatory)
- Determine residual risk after mitigations
- Prioritize by risk score

Deliverable: Prioritized risk register with remediation recommendations
```

---

## 3. Data Flow Diagram Templates / แม่แบบ DFD

### 3.1 DFD Element Notation

### สัญลักษณ์องค์ประกอบ DFD

| Element         | Shape             | Description                               |
| --------------- | ----------------- | ----------------------------------------- |
| External Entity | Rectangle         | User, external system, or third-party API |
| Process         | Rounded Rectangle | Application component, service, function  |
| Data Store      | Parallel Lines    | Database, file system, cache, queue       |
| Data Flow       | Arrow (directed)  | Data movement between elements            |
| Trust Boundary  | Dashed Line/Box   | Security domain boundary                  |

### 3.2 Level 0 — Context Diagram Template

```text
┌─────────────────────────────────────────────────────────────┐
│                    TRUST BOUNDARY: Internet                  │
│                                                             │
│  ┌──────────┐                           ┌──────────────┐    │
│  │  End User │───(HTTPS/REST)──────────▶│  Application │    │
│  │ (Browser) │◀──(JSON Response)────────│   System     │    │
│  └──────────┘                           └──────┬───────┘    │
│                                                │            │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ TRUST BOUNDARY: DMZ ─ ─ ─ ─│─ ─ ─ ─ ─  │
│                                                │            │
│  ┌──────────┐                           ┌──────▼───────┐    │
│  │ Admin    │───(HTTPS/mTLS)───────────▶│  Backend     │    │
│  │ User     │◀──(Admin Response)────────│  Services    │    │
│  └──────────┘                           └──────┬───────┘    │
│                                                │            │
│ ─ ─ ─ ─ ─ ─ TRUST BOUNDARY: Internal ─ ─ ─ ─ ─│─ ─ ─ ─ ─  │
│                                                │            │
│                                         ┌──────▼───────┐    │
│  ┌──────────┐                           │  Database    │    │
│  │ Third-   │───(API Call)──────────────▶│ (PostgreSQL) │    │
│  │ Party API│◀──(Response)──────────────│              │    │
│  └──────────┘                           └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Level 1 — Application Components Template

```text
═══════════════════════ TRUST BOUNDARY: DMZ ═══════════════════════

┌──────────┐    HTTPS     ┌───────────┐    gRPC      ┌─────────────┐
│ End User │────────────▶ │ API       │────────────▶ │ Auth        │
│          │◀──────────── │ Gateway   │◀──────────── │ Service     │
└──────────┘  JSON resp   └───────────┘              └─────────────┘
                               │                           │
                          (Internal)                   (Internal)
                               │                           │
              ═══════════ TRUST BOUNDARY: INTERNAL ════════│════════
                               │                           │
                               ▼                           ▼
                          ┌───────────┐              ┌─────────────┐
                          │ Business  │              │ User Store  │
                          │ Logic Svc │              │ (PostgreSQL)│
                          └───────────┘              └─────────────┘
                               │
                          (SQL query)
                               │
                               ▼
                          ┌───────────┐
                          │ App DB    │
                          │ (Postgres)│
                          └───────────┘
```

### 3.4 Entry Points Catalog Template

| ID  | Entry Point            | Protocol | Auth Required | Trust Level  | Data Sensitivity |
| --- | ---------------------- | -------- | ------------- | ------------ | ---------------- |
| EP1 | Public API (REST)      | HTTPS    | Bearer Token  | Untrusted    | High             |
| EP2 | Admin Dashboard        | HTTPS    | MFA + RBAC    | Semi-trusted | Critical         |
| EP3 | Internal gRPC API      | mTLS     | Service cert  | Trusted      | High             |
| EP4 | Message Queue Consumer | AMQP/TLS | Cert-based    | Trusted      | Medium           |
| EP5 | Database Connection    | TLS      | Credential    | Trusted      | Critical         |
| EP6 | Health Check Endpoint  | HTTP     | None          | Untrusted    | Low              |

---

## 4. Trust Boundary Identification / การระบุขอบเขตความเชื่อถือ

### 4.1 Trust Boundary Types

### ประเภทขอบเขตความเชื่อถือ

| Boundary Type       | Thai Translation       | Description                                      | Examples                          |
| ------------------- | ---------------------- | ------------------------------------------------ | --------------------------------- |
| Network Perimeter   | ขอบเขตเครือข่าย        | Between internet and internal network            | Firewall, WAF, Load Balancer      |
| DMZ                 | เขตกันชน               | Between external-facing and internal services    | API Gateway, Reverse Proxy        |
| Service Mesh        | ตาข่ายบริการ           | Between microservices in different trust domains | Istio 1.24+/Linkerd sidecar       |
| Container Runtime   | สภาพแวดล้อมคอนเทนเนอร์ | Between container and host OS                    | Docker/containerd isolation       |
| Process             | กระบวนการ              | Between application processes                    | IPC, shared memory boundaries     |
| Data Classification | การจำแนกข้อมูล         | Between data of different sensitivity levels     | PII store vs. public data store   |
| Cloud Account       | บัญชีคลาวด์            | Between different cloud accounts or VPCs         | AWS account boundary, VPC peering |
| Third-Party         | บุคคลภายนอก            | Between your system and external services        | Payment gateway, IdP, CDN         |

### 4.2 Trust Boundary Assessment Checklist

```text
For each identified trust boundary, verify:

1.  [ ] Authentication mechanism at boundary crossing
2.  [ ] Authorization check after crossing (not just at boundary)
3.  [ ] Data validation/sanitization at boundary entry
4.  [ ] Encryption in transit across boundary
5.  [ ] Logging of all boundary-crossing events
6.  [ ] Rate limiting at boundary entry points
7.  [ ] Error handling that doesn't leak internal information
8.  [ ] Timeout and circuit breaker configuration
9.  [ ] Mutual authentication where applicable (mTLS)
10. [ ] Network policy enforcement (K8s NetworkPolicy, security groups)
```

---

## 5. Risk Scoring Methodology / วิธีการให้คะแนนความเสี่ยง

### 5.1 DREAD Model (Quick Assessment)

### โมเดล DREAD (การประเมินอย่างรวดเร็ว)

| Factor              | Score 1 (Low)          | Score 2 (Medium)          | Score 3 (High)             |
| ------------------- | ---------------------- | ------------------------- | -------------------------- |
| **D**amage          | Minimal impact         | Significant data exposure | Complete system compromise |
| **R**eproducibility | Difficult to reproduce | Requires specific setup   | Always reproducible        |
| **E**xploitability  | Requires expert skills | Moderate skill needed     | Trivially exploitable      |
| **A**ffected Users  | Few users affected     | Some users affected       | All users affected         |
| **D**iscoverability | Very hard to discover  | Requires effort           | Easily discoverable        |

```text
DREAD Score = (D + R + E + A + D) / 5
Range: 1.0 - 3.0
Severity: 1.0-1.5 = Low, 1.6-2.0 = Medium, 2.1-2.5 = High, 2.6-3.0 = Critical
```

### 5.2 CVSS v4.0 Base Score Components

| Metric Group        | Metrics                                                 |
| ------------------- | ------------------------------------------------------- |
| Exploitability      | Attack Vector (AV), Attack Complexity (AC),             |
|                     | Attack Requirements (AT), Privileges Required (PR),     |
|                     | User Interaction (UI)                                   |
| Impact (Vulnerable) | Confidentiality (VC), Integrity (VI), Availability (VA) |
| Impact (Subsequent) | Confidentiality (SC), Integrity (SI), Availability (SA) |

CVSS v4.0 scores range from 0.0 to 10.0:

| Score Range | Severity | Thai Level | Response SLA (Recommended) |
| ----------- | -------- | ---------- | -------------------------- |
| 0.0         | None     | ไม่มี      | No action required         |
| 0.1 - 3.9   | Low      | ต่ำ        | Fix within 90 days         |
| 4.0 - 6.9   | Medium   | ปานกลาง    | Fix within 30 days         |
| 7.0 - 8.9   | High     | สูง        | Fix within 7 days          |
| 9.0 - 10.0  | Critical | วิกฤต      | Fix within 24-48 hours     |

### 5.3 OWASP Risk Rating Methodology

```yaml
# OWASP Risk Rating: Likelihood x Impact
risk_rating:
  likelihood_factors:
    threat_agent:
      skill_level: 6 # 0-9
      motive: 9 # 0-9
      opportunity: 7 # 0-9
      size: 6 # 0-9 (size of threat agent group)
    vulnerability:
      ease_of_discovery: 7 # 0-9
      ease_of_exploit: 5 # 0-9
      awareness: 6 # 0-9
      intrusion_detection: 3 # 0-9
    likelihood_score: 6.1 # Average of above

  impact_factors:
    technical:
      loss_of_confidentiality: 9 # 0-9
      loss_of_integrity: 7 # 0-9
      loss_of_availability: 5 # 0-9
      loss_of_accountability: 7 # 0-9
    business:
      financial_damage: 9 # 0-9
      reputation_damage: 9 # 0-9
      non_compliance: 7 # 0-9
      privacy_violation: 9 # 0-9
    impact_score: 7.75 # Average of above
```

### 5.4 Risk Matrix (Likelihood vs. Impact)

```text
                        IMPACT
                 Low     Medium    High    Critical
            +--------+--------+--------+--------+
 Almost     | Medium | High   | Critical| Critical|
 Certain    |        |        |         |         |
L           +--------+--------+--------+---------+
I  Likely   | Low    | Medium | High    | Critical|
K           |        |        |         |         |
E           +--------+--------+--------+---------+
L  Possible | Low    | Medium | Medium  | High    |
I           |        |        |         |         |
H           +--------+--------+--------+---------+
O  Unlikely | Info   | Low    | Medium  | Medium  |
O           |        |        |         |         |
D           +--------+--------+--------+---------+
   Rare     | Info   | Info   | Low     | Low     |
            |        |        |         |         |
            +--------+--------+--------+---------+
```

### 5.5 Business Impact Assessment Template

```yaml
threat_id: "TM-2026-001"
threat_name: "SQL Injection in Search API"
stride_category: "Tampering / Information Disclosure"
attack_vector: "Network (unauthenticated)"

impact_assessment:
  confidentiality:
    rating: "High"
    detail: "Customer PII exposed (names, emails, addresses)"
  integrity:
    rating: "High"
    detail: "Database records can be modified or deleted"
  availability:
    rating: "Medium"
    detail: "Database can be corrupted, causing service outage"

business_impact:
  financial: "High — potential regulatory fine (PDPA: up to 5M THB)"
  reputational: "High — customer trust erosion, media coverage"
  operational: "Medium — service restoration within 4-8 hours"
  legal: "High — mandatory breach notification within 72 hours"

risk_score:
  likelihood: 4 # (1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain)
  impact: 4 # (1=Low, 2=Medium, 3=High, 4=Critical)
  inherent_risk: "Critical" # From risk matrix
  mitigations_planned:
    - "Parameterized queries (CWE-89 fix)"
    - "WAF SQL injection rules"
    - "Input validation middleware"
  residual_risk: "Low"
```

---

## 6. Attack Tree Examples / ตัวอย่างแผนภูมิการโจมตี

### 6.1 Attack Tree Notation

```text
Attack Tree Notation:
  [AND] = All child nodes must succeed for parent to succeed
  [OR]  = Any child node can succeed for parent to succeed
  (P)   = Probability (0.0-1.0)
  (C)   = Cost to attacker ($)
  (D)   = Difficulty (L=Low, M=Medium, H=High)
```

### 6.2 Attack Tree: Account Takeover

```text
Goal: Account Takeover [OR]
├── 1. Credential Theft [OR] (P=0.6)
│   ├── 1.1 Phishing (P=0.4, C=$100, D=L)
│   │   ├── 1.1.1 Spear phishing email
│   │   └── 1.1.2 Clone login page
│   ├── 1.2 Credential Stuffing (P=0.3, C=$50, D=L)
│   │   ├── 1.2.1 Obtain leaked credential database
│   │   └── 1.2.2 Automated login attempts
│   └── 1.3 Keylogger/Malware (P=0.1, C=$500, D=M)
│
├── 2. Session Hijacking [OR] (P=0.3)
│   ├── 2.1 XSS cookie theft (P=0.15, C=$200, D=M)
│   │   ├── 2.1.1 Find reflected XSS vulnerability
│   │   └── 2.1.2 Inject cookie-stealing payload
│   ├── 2.2 Session fixation (P=0.05, C=$100, D=M)
│   └── 2.3 Network sniffing (P=0.1, C=$300, D=H)
│       └── Requires HTTP (no TLS) [precondition]
│
├── 3. Authentication Bypass [OR] (P=0.15)
│   ├── 3.1 SQL Injection in login (P=0.05, C=$100, D=M)
│   ├── 3.2 JWT algorithm confusion (P=0.05, C=$50, D=M)
│   │   ├── 3.2.1 Set alg=none
│   │   └── 3.2.2 Switch RS256 to HS256
│   └── 3.3 Password reset flaw (P=0.05, C=$0, D=L)
│       ├── 3.3.1 Predictable reset token
│       └── 3.3.2 Host header injection
│
└── 4. Privilege Escalation [AND] (P=0.1)
    ├── 4.1 Obtain low-privilege account
    └── 4.2 Exploit IDOR/broken access control
```

### 6.3 Attack Tree: Data Exfiltration

```text
Goal: Exfiltrate Customer PII [OR]
├── 1. Direct Database Access [OR] (P=0.2)
│   ├── 1.1 SQL Injection [AND]
│   │   ├── 1.1.1 Find injectable parameter
│   │   ├── 1.1.2 Extract schema information
│   │   └── 1.1.3 Dump target tables
│   └── 1.2 Compromised DB Credentials [OR]
│       ├── 1.2.1 Hardcoded in source code (CWE-798)
│       ├── 1.2.2 Exposed in environment variables
│       └── 1.2.3 Leaked in CI/CD logs
│
├── 2. Application Layer [OR] (P=0.4)
│   ├── 2.1 IDOR on API endpoints (P=0.2, D=L)
│   ├── 2.2 GraphQL introspection + over-fetching (P=0.1, D=M)
│   ├── 2.3 Export functionality abuse (P=0.05, D=L)
│   └── 2.4 SSRF to internal services (P=0.05, D=H)
│
└── 3. Infrastructure [OR] (P=0.1)
    ├── 3.1 Container escape to host filesystem
    ├── 3.2 S3 bucket misconfiguration (public access)
    └── 3.3 Database backup file exposure
```

### 6.4 Attack Tree: Supply Chain Compromise

```text
Goal: Inject Malicious Code via Supply Chain [OR]
├── 1. Dependency Poisoning [OR] (P=0.15)
│   ├── 1.1 Typosquatting (P=0.05, C=$50, D=L)
│   ├── 1.2 Dependency confusion (P=0.05, C=$100, D=M)
│   └── 1.3 Maintainer account takeover (P=0.05, C=$500, D=H)
│
├── 2. Build System Compromise [AND] (P=0.1)
│   ├── 2.1 Access CI/CD pipeline credentials
│   └── 2.2 Inject malicious build step
│
└── 3. Infrastructure Compromise [OR] (P=0.05)
    ├── 3.1 Compromised container base image
    └── 3.2 Compromised artifact registry
```

---

## 7. Threat Categorization / การจำแนกหมวดหมู่ภัยคุกคาม

### 7.1 Threat Actor Profiles / โปรไฟล์ผู้คุกคาม

| Actor Type         | Thai Translation | Motivation     | Capability | Resources | Persistence | Examples                    |
| ------------------ | ---------------- | -------------- | ---------- | --------- | ----------- | --------------------------- |
| Nation State (APT) | รัฐชาติ (APT)    | Espionage      | Very High  | Very High | Very High   | APT28, APT41, Lazarus Group |
| Organized Crime    | อาชญากรรมองค์กร  | Financial      | High       | High      | High        | FIN7, Conti, LockBit        |
| Hacktivist         | แฮกทิวิสต์       | Ideology       | Medium     | Low       | Medium      | Anonymous, LulzSec          |
| Insider Threat     | ภัยจากภายใน      | Various        | Med-High   | Medium    | Variable    | Disgruntled employee        |
| Script Kiddie      | สคริปต์คิดดี้    | Notoriety      | Low        | Low       | Low         | Using automated tools       |
| Competitor         | คู่แข่ง          | Business intel | Medium     | Medium    | Medium      | Corporate espionage         |

### 7.2 MITRE ATT&CK Technique Mapping

| Threat Scenario               | ATT&CK Technique | Tactic               | Detection Method           |
| ----------------------------- | ---------------- | -------------------- | -------------------------- |
| Exploit public-facing app     | T1190            | Initial Access       | WAF logs, DAST findings    |
| Supply chain compromise       | T1195.002        | Initial Access       | SCA scanning, SBOM diff    |
| Valid accounts abuse          | T1078            | Persistence          | Anomaly detection, UBA     |
| Container escape              | T1611            | Privilege Escalation | Falco, runtime monitoring  |
| Data from cloud storage       | T1530            | Collection           | CloudTrail, bucket logging |
| Exfiltration over web service | T1567            | Exfiltration         | DLP, egress monitoring     |
| Credential dumping            | T1003            | Credential Access    | EDR, process monitoring    |
| API abuse                     | T1106            | Execution            | Rate limiting, API logging |

### 7.3 Threat Categories by Impact Area

| Category              | Thai Translation  | CIA Impact    | Business Impact             |
| --------------------- | ----------------- | ------------- | --------------------------- |
| Data Breach           | ข้อมูลรั่วไหล     | C: Critical   | Regulatory fines, lawsuits  |
| Service Disruption    | บริการหยุดชะงัก   | A: Critical   | Revenue loss, SLA breach    |
| Intellectual Property | ทรัพย์สินทางปัญญา | C: Critical   | Competitive disadvantage    |
| Fraud                 | การฉ้อโกง         | I: High       | Financial loss              |
| Reputation Damage     | เสียชื่อเสียง     | All: Variable | Customer churn, stock price |
| Compliance Violation  | ละเมิดกฎระเบียบ   | All: Variable | Fines, license revocation   |

---

## 8. OWASP Threat Modeling Process / กระบวนการจำลองภัยคุกคาม OWASP

Reference: https://owasp.org/www-community/Threat_Modeling_Process

### 8.1 Four-Question Framework / กรอบ 4 คำถาม

| Question                             | Thai Translation      | Activities                                    |
| ------------------------------------ | --------------------- | --------------------------------------------- |
| 1. What are we working on?           | เรากำลังทำงานกับอะไร? | Architecture diagrams, DFDs, asset inventory  |
| 2. What can go wrong?                | อะไรอาจผิดพลาดได้?    | STRIDE analysis, attack trees, misuse cases   |
| 3. What are we going to do about it? | เราจะจัดการอย่างไร?   | Mitigations, security requirements, controls  |
| 4. Did we do a good enough job?      | เราทำได้ดีพอหรือยัง?  | Validation, testing, residual risk assessment |

### 8.2 OWASP Threat Modeling Meeting Template

```markdown
# Threat Modeling Session — [Application Name]

**Date**: YYYY-MM-DD
**Participants**: [Security Lead, Dev Lead, Architect, PM]
**Scope**: [Feature / Component / System]

## Pre-requisites

- [ ] Architecture diagram (Level 1 DFD minimum)
- [ ] Data classification inventory
- [ ] User roles and access matrix
- [ ] Technology stack documentation
- [ ] Previous threat model (if updating)

## Session Agenda (90 minutes)

1. **Context Setting** (15 min) — Review architecture, scope, changes
2. **Threat Identification** (30 min) — STRIDE-per-element walkthrough
3. **Risk Assessment** (20 min) — Score each threat using DREAD/OWASP
4. **Mitigation Planning** (20 min) — Identify controls per threat
5. **Action Items** (5 min) — Assign owners and deadlines

## Identified Threats

| ID   | Category | Threat Description | Risk Score | Mitigation | Owner | Status |
| ---- | -------- | ------------------ | ---------- | ---------- | ----- | ------ |
| TM-1 |          |                    |            |            |       |        |

## Decisions & Assumptions

-

## Action Items

- [ ]

## Next Review Date: YYYY-MM-DD
```

### 8.3 Integrating Threat Modeling into SDLC

| SDLC Phase   | Threat Modeling Activity                       | Trigger                     |
| ------------ | ---------------------------------------------- | --------------------------- |
| Requirements | Identify security requirements from threats    | New feature/product         |
| Design       | Full STRIDE analysis, DFD creation             | Architecture review         |
| Development  | Update threat model for implementation changes | Significant code changes    |
| Testing      | Validate mitigations, security test cases      | Pre-release                 |
| Deployment   | Verify controls are operational                | Production deployment       |
| Operations   | Monitor for new threats, update model          | Quarterly or after incident |

---

## 9. Data Flow Analysis / การวิเคราะห์กระแสข้อมูล

### 9.1 Data Classification for Threat Modeling

### การจำแนกข้อมูลสำหรับ Threat Modeling

| Classification | Thai Translation | Examples                        | Required Controls                           |
| -------------- | ---------------- | ------------------------------- | ------------------------------------------- |
| Public         | สาธารณะ          | Marketing content, docs         | Integrity checks                            |
| Internal       | ภายใน            | Employee directory, internal KB | Authentication, access logging              |
| Confidential   | ลับ              | Customer PII, financial records | Encryption at rest/transit, RBAC, audit log |
| Restricted     | จำกัดเฉพาะ       | Cardholder data, health records | HSM, tokenization, strict access, DLP       |

### 9.2 Data Flow Security Requirements Template

```yaml
data_flow_analysis:
  flow_id: "DF-001"
  source: "Web Frontend"
  destination: "Payment Service"
  data_elements:
    - name: "credit_card_number"
      classification: "Restricted"
      pci_scope: true
    - name: "billing_address"
      classification: "Confidential"
      pci_scope: false

  security_requirements:
    transport:
      protocol: "TLS 1.3"
      cipher_suites:
        - "TLS_AES_256_GCM_SHA384"
        - "TLS_CHACHA20_POLY1305_SHA256"
      certificate_pinning: true
    authentication:
      mechanism: "mTLS + JWT"
      token_lifetime: "15 minutes"
    authorization:
      model: "ABAC"
      required_attributes: ["role=payment-processor", "env=production"]
    data_protection:
      tokenize_before_transmission: true
      field_level_encryption: ["credit_card_number"]
      mask_in_logs: ["credit_card_number", "billing_address"]
    monitoring:
      log_all_access: true
      alert_on_bulk_queries: true
      retention_period: "1 year"
```

### 9.3 Data Flow Audit Checklist

```text
For each data flow in the DFD, verify:

1. [ ] Data classification assigned to every data element
2. [ ] Transport encryption meets classification requirements
3. [ ] Source authentication verified at destination
4. [ ] Authorization enforced at the receiving component
5. [ ] Sensitive fields masked/tokenized before logging
6. [ ] Data retention policy defined and enforced
7. [ ] Cross-border data transfer compliance checked (PDPA, GDPR)
8. [ ] Backup/replication flows also secured
9. [ ] Error responses do not leak classified data
10.[ ] Data flow documented in threat model
```

---

## 10. Threat Model Output Template / แม่แบบผลลัพธ์

### 10.1 Summary Report Structure

```text
# Threat Model Report
## System: [System Name]
## Version: [Version/Date]
## Author: [DevSecOps Agent / Team]

### 1. Executive Summary
- Total threats identified: N
- Critical: X, High: Y, Medium: Z, Low: W
- Top 3 risks requiring immediate attention

### 2. System Overview
- Architecture diagram (C4 Context + Container)
- Technology stack summary
- Data classification summary

### 3. Trust Boundaries
- Boundary map with element placement
- Authentication/authorization at each boundary

### 4. Threat Catalog
- Per-element STRIDE analysis
- Each threat: ID, category, description, impact, likelihood, risk score

### 5. Attack Scenarios
- Top 5 attack trees
- Mapped to MITRE ATT&CK techniques

### 6. Risk Register
- Prioritized list of all threats
- Current mitigations
- Recommended additional mitigations
- Residual risk after mitigations

### 7. Recommendations
- Immediate actions (Critical/High risks)
- Short-term improvements (Medium risks)
- Long-term architectural changes

### 8. Appendices
- Full DFD diagrams (Level 0, 1, 2)
- STRIDE per element worksheet
- Scan results summary (SAST/DAST/SCA)
```

---

## 11. Integration with DevSecOps Pipeline / การบูรณาการกับ Pipeline

### 11.1 Threat Model as Code

```yaml
# threat-model.yaml — Version-controlled threat model
# Compatible with: Threagile v1.0+, pytm v1.3+
metadata:
  system: "payment-service"
  version: "2.1.0"
  last_reviewed: "2026-03-01"
  next_review: "2026-06-01"
  owner: "security-team"

components:
  - name: "API Gateway"
    type: "process"
    technology: "NGINX Plus R33"
    trust_zone: "dmz"
    threats:
      - id: "TM-001"
        stride: "Spoofing"
        description: "Forged authentication token"
        cvss: 8.1
        status: "mitigated"
        controls: ["jwt-validation", "token-rotation"]

  - name: "Payment DB"
    type: "data_store"
    technology: "PostgreSQL 17"
    trust_zone: "internal"
    data_classification: "restricted"
    threats:
      - id: "TM-002"
        stride: "Information Disclosure"
        description: "Unencrypted PII at rest"
        cvss: 7.5
        status: "open"
        remediation: "Enable TDE or application-level encryption"
```

### 11.2 CI/CD Threat Model Validation

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Validation
on:
  pull_request:
    paths:
      - "docs/threat-model/**"
      - "src/api/**"
      - "infrastructure/**"

jobs:
  validate-threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Threagile Analysis
        uses: threagile/threagile-action@v1
        with:
          model: docs/threat-model/threatmodel.yaml
          output: threat-report

      - name: Check for Unmitigated Critical Risks
        run: |
          CRITICAL=$(jq '.risks[] | select(.severity == "critical" and .status != "mitigated")' threat-report/risks.json)
          if [ -n "$CRITICAL" ]; then
            echo "::error::Unmitigated critical risks found!"
            echo "$CRITICAL" | jq .
            exit 1
          fi
```

### 11.3 Automated Threat Model Triggers

| Trigger Event                    | Action                                        |
| -------------------------------- | --------------------------------------------- |
| New microservice added           | Generate DFD, run STRIDE per element          |
| New external API integration     | Update trust boundaries, threat analysis      |
| Architecture change (ADR merged) | Review affected threat model sections         |
| Major version release            | Full threat model review                      |
| Compliance audit scheduled       | Generate threat model report + evidence       |
| Critical CVE in dependency       | Update vulnerability analysis (PASTA Stage V) |

---

## 12. Common Threat Patterns by Architecture / รูปแบบภัยคุกคามตามสถาปัตยกรรม

### 12.1 Microservices

| Threat                            | STRIDE | Mitigation                               |
| --------------------------------- | ------ | ---------------------------------------- |
| Service impersonation             | S      | mTLS via service mesh (Istio 1.24+)      |
| Inter-service data tampering      | T      | Message signing, TLS                     |
| Cascading failure (DoS)           | D      | Circuit breakers, bulkheads, rate limits |
| Lateral movement after compromise | E      | Network policies, zero trust, microseg   |
| Shared secret sprawl              | I      | Centralized vault, dynamic credentials   |

### 12.2 Serverless / FaaS

| Threat                             | STRIDE | Mitigation                                 |
| ---------------------------------- | ------ | ------------------------------------------ |
| Event injection (poisoned trigger) | T      | Input validation, schema enforcement       |
| Over-permissioned function role    | E      | Least-privilege IAM, per-function roles    |
| Cold start timing attacks          | I      | Provisioned concurrency, constant-time ops |
| Dependency confusion in layers     | T      | Dependency pinning, private registries     |
| Insufficient logging               | R      | Structured logging, centralized SIEM       |

### 12.3 Kubernetes / Container Orchestration

| Threat                      | STRIDE | Mitigation                                |
| --------------------------- | ------ | ----------------------------------------- |
| Container escape to host    | E      | Seccomp, AppArmor, non-root, read-only FS |
| Malicious image in registry | T      | Image signing (cosign), admission control |
| etcd data exposure          | I      | etcd encryption, RBAC, network isolation  |
| Kubelet API abuse           | E      | Kubelet authn/authz, node restriction     |
| Pod-to-pod network sniffing | I      | Network policies, CNI encryption, mTLS    |

---

## References / แหล่งอ้างอิง

- STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool
- PASTA: https://owasp.org/www-project-threat-model/
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
- OWASP Threat Modeling Process: https://owasp.org/www-community/Threat_Modeling_Process
- MITRE ATT&CK v16: https://attack.mitre.org/
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- CAPEC (Common Attack Pattern Enumeration): https://capec.mitre.org/
- Microsoft Threat Modeling Tool: https://aka.ms/threatmodelingtool
- Threagile (Threat Model as Code): https://threagile.io/
- pytm (Pythonic Threat Modeling): https://github.com/OWASP/pytm
- NIST SP 800-154 (Guide to Data-Centric Threat Modeling): https://csrc.nist.gov/pubs/sp/800-154/ipd
