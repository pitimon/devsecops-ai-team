# Threat Modeling Reference

# คู่มือการสร้างแบบจำลองภัยคุกคาม

## Purpose / วัตถุประสงค์

This reference provides domain knowledge for DevSecOps agents performing threat modeling
activities. It covers the STRIDE methodology, PASTA framework, Data Flow Diagram (DFD)
construction, trust boundary identification, and risk scoring. Agents load this file when
conducting threat assessments, reviewing architecture for security risks, or generating
threat models from system descriptions.

---

## 1. STRIDE Methodology / วิธีการ STRIDE

STRIDE was developed by Microsoft and categorizes threats into six types.
Each category maps to a security property violation.

### 1.1 STRIDE Categories

| Category              | Security Property | Description                                   | Symbol |
| --------------------- | ----------------- | --------------------------------------------- | ------ |
| **S**poofing          | Authentication    | Pretending to be another user or system       | S      |
| **T**ampering         | Integrity         | Modifying data or code without authorization  | T      |
| **R**epudiation       | Non-repudiation   | Denying having performed an action            | R      |
| **I**nformation Disc. | Confidentiality   | Exposing information to unauthorized parties  | I      |
| **D**enial of Service | Availability      | Making a system or resource unavailable       | D      |
| **E**levation of Priv | Authorization     | Gaining capabilities beyond what is permitted | E      |

### 1.2 STRIDE per Element

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

PASTA (Process for Attack Simulation and Threat Analysis) is a seven-stage,
risk-centric threat modeling framework.

### 2.1 Seven Stages

| Stage | Name                              | Key Activities                               | Output                    |
| ----- | --------------------------------- | -------------------------------------------- | ------------------------- |
| I     | Define Objectives                 | Business objectives, compliance requirements | Objectives document       |
| II    | Define Technical Scope            | Architecture diagrams, technology stack      | Technical scope document  |
| III   | Application Decomposition         | DFDs, trust boundaries, entry points         | Decomposition diagrams    |
| IV    | Threat Analysis                   | Threat intelligence, attack libraries        | Threat list               |
| V     | Vulnerability & Weakness Analysis | Vulnerability scanning, code review results  | Vulnerability inventory   |
| VI    | Attack Modeling & Simulation      | Attack trees, attack patterns                | Attack scenarios          |
| VII   | Risk & Impact Analysis            | Risk scoring, business impact assessment     | Prioritized risk register |

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
- SAST scan results (e.g., Semgrep, CodeQL)
- DAST scan results (e.g., ZAP, Nuclei)
- SCA findings (e.g., Trivy, Grype)
- IaC scan results (e.g., Checkov, tfsec)
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

| Element         | Shape             | Description                               |
| --------------- | ----------------- | ----------------------------------------- |
| External Entity | Rectangle         | User, external system, or third-party API |
| Process         | Rounded Rectangle | Application component, service, function  |
| Data Store      | Parallel Lines    | Database, file system, cache, queue       |
| Data Flow       | Arrow (directed)  | Data movement between elements            |
| Trust Boundary  | Dashed Line/Box   | Security domain boundary                  |

### 3.2 Level 0 — Context Diagram Template

```text
+-------------+                              +------------------+
|   End User  |----(HTTPS/REST)---->         |  Application     |
|  (Browser)  |<----(JSON Response)----      |  System          |
+-------------+                              |                  |
                                             |  [Trust Boundary |
+-------------+                              |   = Application] |
|  Admin User |----(HTTPS/mTLS)---->         |                  |
+-------------+                              +------------------+
                                                     |
                                             (Internal API)
                                                     |
                                                     v
                                             +------------------+
                                             | Third-Party      |
                                             | Payment Gateway  |
                                             +------------------+
```

### 3.3 Level 1 — Application Components Template

```text
=============================== TRUST BOUNDARY: DMZ ================================

+----------+    HTTPS     +-----------+    gRPC      +-------------+
| End User |----------->  | API       |----------->  | Auth        |
|          |<-----------  | Gateway   |<-----------  | Service     |
+----------+  JSON resp   +-----------+              +-------------+
                               |                           |
                          (Internal)                   (Internal)
                               |                           |
              ============ TRUST BOUNDARY: INTERNAL ========|========================
                               |                           |
                               v                           v
                          +-----------+              +-------------+
                          | Business  |              | User Store  |
                          | Logic Svc |              | (PostgreSQL)|
                          +-----------+              +-------------+
                               |
                          (SQL query)
                               |
                               v
                          +-----------+
                          | App DB    |
                          | (Postgres)|
                          +-----------+
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

| Boundary Type       | Description                                      | Examples                          |
| ------------------- | ------------------------------------------------ | --------------------------------- |
| Network Perimeter   | Between internet and internal network            | Firewall, WAF, Load Balancer      |
| DMZ                 | Between external-facing and internal services    | API Gateway, Reverse Proxy        |
| Service Mesh        | Between microservices in different trust domains | Istio/Linkerd sidecar boundaries  |
| Container Runtime   | Between container and host OS                    | Docker/containerd isolation       |
| Process             | Between application processes                    | IPC, shared memory boundaries     |
| Data Classification | Between data of different sensitivity levels     | PII store vs. public data store   |
| Cloud Account       | Between different cloud accounts or VPCs         | AWS account boundary, VPC peering |
| Third-Party         | Between your system and external services        | Payment gateway, IdP, CDN         |

### 4.2 Trust Boundary Assessment Checklist

```text
For each identified trust boundary, verify:

1. [ ] Authentication mechanism at boundary crossing
2. [ ] Authorization check after crossing (not just at boundary)
3. [ ] Data validation/sanitization at boundary entry
4. [ ] Encryption in transit across boundary
5. [ ] Logging of all boundary-crossing events
6. [ ] Rate limiting at boundary entry points
7. [ ] Error handling that doesn't leak internal information
8. [ ] Timeout and circuit breaker configuration
9. [ ] Mutual authentication where applicable (mTLS)
10.[ ] Network policy enforcement (K8s NetworkPolicy, security groups)
```

---

## 5. Risk Scoring Methodology / วิธีการให้คะแนนความเสี่ยง

### 5.1 DREAD Model (Quick Assessment)

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

| Score Range | Severity | Response SLA (Recommended) |
| ----------- | -------- | -------------------------- |
| 0.0         | None     | No action required         |
| 0.1 - 3.9   | Low      | Fix within 90 days         |
| 4.0 - 6.9   | Medium   | Fix within 30 days         |
| 7.0 - 8.9   | High     | Fix within 7 days          |
| 9.0 - 10.0  | Critical | Fix within 24-48 hours     |

### 5.3 Risk Matrix (Likelihood vs. Impact)

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

### 5.4 Business Impact Assessment Template

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

## 6. Threat Model Output Template / แม่แบบผลลัพธ์

### 6.1 Summary Report Structure

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

## 7. Integration with DevSecOps Pipeline / การบูรณาการกับ Pipeline

### 7.1 Threat Model as Code

```yaml
# threat-model.yaml — Version-controlled threat model
metadata:
  system: "payment-service"
  version: "2.1.0"
  last_reviewed: "2026-03-01"
  next_review: "2026-06-01"
  owner: "security-team"

components:
  - name: "API Gateway"
    type: "process"
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

### 7.2 Automated Threat Model Triggers

| Trigger Event                    | Action                                        |
| -------------------------------- | --------------------------------------------- |
| New microservice added           | Generate DFD, run STRIDE per element          |
| New external API integration     | Update trust boundaries, threat analysis      |
| Architecture change (ADR merged) | Review affected threat model sections         |
| Major version release            | Full threat model review                      |
| Compliance audit scheduled       | Generate threat model report + evidence       |
| Critical CVE in dependency       | Update vulnerability analysis (PASTA Stage V) |

---

## 8. Common Threat Patterns by Architecture / รูปแบบภัยคุกคามตามสถาปัตยกรรม

### 8.1 Microservices

| Threat                            | STRIDE | Mitigation                               |
| --------------------------------- | ------ | ---------------------------------------- |
| Service impersonation             | S      | mTLS via service mesh                    |
| Inter-service data tampering      | T      | Message signing, TLS                     |
| Cascading failure (DoS)           | D      | Circuit breakers, bulkheads, rate limits |
| Lateral movement after compromise | E      | Network policies, zero trust, microseg   |
| Shared secret sprawl              | I      | Centralized vault, dynamic credentials   |

### 8.2 Serverless / FaaS

| Threat                             | STRIDE | Mitigation                                 |
| ---------------------------------- | ------ | ------------------------------------------ |
| Event injection (poisoned trigger) | T      | Input validation, schema enforcement       |
| Over-permissioned function role    | E      | Least-privilege IAM, per-function roles    |
| Cold start timing attacks          | I      | Provisioned concurrency, constant-time ops |
| Dependency confusion in layers     | T      | Dependency pinning, private registries     |
| Insufficient logging               | R      | Structured logging, centralized SIEM       |

### 8.3 Kubernetes / Container Orchestration

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
- MITRE ATT&CK: https://attack.mitre.org/
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- CAPEC (Common Attack Pattern Enumeration): https://capec.mitre.org/
- Microsoft Threat Modeling Tool: https://aka.ms/threatmodelingtool
- Threagile (Threat Model as Code): https://threagile.io/
- NIST SP 800-154 (Guide to Data-Centric Threat Modeling): https://csrc.nist.gov/pubs/sp/800-154/ipd
