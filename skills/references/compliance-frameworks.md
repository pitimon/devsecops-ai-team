# Compliance Frameworks Cross-Walk Matrix

# เมทริกซ์การเทียบเคียงกรอบการปฏิบัติตามข้อกำหนด

## Purpose / วัตถุประสงค์

This reference provides a comprehensive cross-walk matrix across major security and compliance
frameworks. DevSecOps agents load this file when generating compliance reports, mapping findings
to regulatory requirements, or assessing control coverage. It covers NIST 800-53 Rev.5,
OWASP Top 10 (2021), MITRE ATT&CK v16, and CIS Controls v8.1 with mappings between them.

---

## 1. NIST SP 800-53 Rev.5 — Key Controls / การควบคุมหลัก

Reference: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

### 1.1 Access Control (AC) Family

| Control ID | Title                        | Priority | DevSecOps Relevance                       |
| ---------- | ---------------------------- | -------- | ----------------------------------------- |
| AC-2       | Account Management           | P1       | Service account lifecycle, RBAC in CI/CD  |
| AC-3       | Access Enforcement           | P1       | Branch protection, artifact registry ACL  |
| AC-4       | Information Flow Enforcement | P1       | Network policies, egress filtering        |
| AC-6       | Least Privilege              | P1       | Container non-root, minimal IAM policies  |
| AC-7       | Unsuccessful Logon Attempts  | P2       | API rate limiting, brute-force protection |
| AC-17      | Remote Access                | P1       | VPN/Zero Trust for admin access           |

### 1.2 Audit & Accountability (AU) Family

| Control ID | Title                    | Priority | DevSecOps Relevance                         |
| ---------- | ------------------------ | -------- | ------------------------------------------- |
| AU-2       | Event Logging            | P1       | Application logging, security event capture |
| AU-3       | Content of Audit Records | P1       | Structured logging with context             |
| AU-6       | Audit Record Review      | P1       | SIEM integration, automated alerting        |
| AU-8       | Time Stamps              | P1       | NTP sync, log timestamp consistency         |
| AU-12      | Audit Record Generation  | P1       | Pipeline audit trails, deployment logs      |

### 1.3 Configuration Management (CM) Family

| Control ID | Title                        | Priority | DevSecOps Relevance                         |
| ---------- | ---------------------------- | -------- | ------------------------------------------- |
| CM-2       | Baseline Configuration       | P1       | IaC templates, golden images                |
| CM-3       | Configuration Change Control | P1       | GitOps, PR reviews, change approval         |
| CM-6       | Configuration Settings       | P1       | CIS benchmarks, hardening scripts           |
| CM-7       | Least Functionality          | P1       | Minimal container images, disabled services |
| CM-8       | System Component Inventory   | P1       | SBOM generation, asset inventory            |

### 1.4 Risk Assessment (RA) Family

| Control ID | Title                    | Priority | DevSecOps Relevance                     |
| ---------- | ------------------------ | -------- | --------------------------------------- |
| RA-3       | Risk Assessment          | P1       | Threat modeling, vulnerability scanning |
| RA-5       | Vulnerability Monitoring | P1       | SAST/DAST/SCA continuous scanning       |
| RA-7       | Risk Response            | P1       | Automated remediation, risk acceptance  |

### 1.5 System & Information Integrity (SI) Family

| Control ID | Title                        | Priority | DevSecOps Relevance                       |
| ---------- | ---------------------------- | -------- | ----------------------------------------- |
| SI-2       | Flaw Remediation             | P1       | Patching SLA, vulnerability management    |
| SI-3       | Malicious Code Protection    | P1       | Container scanning, supply chain security |
| SI-4       | System Monitoring            | P1       | Runtime security, anomaly detection       |
| SI-7       | Software & Info Integrity    | P1       | Code signing, SBOM verification           |
| SI-10      | Information Input Validation | P1       | Input sanitization, WAF rules             |

---

## 2. OWASP Top 10 (2021) / ช่องโหว่เว็บ 10 อันดับแรก

Reference: https://owasp.org/Top10/ (2021 edition)

| Rank | ID     | Category                           | CWE Examples     | Detection Method          |
| ---- | ------ | ---------------------------------- | ---------------- | ------------------------- |
| A01  | A01:21 | Broken Access Control              | CWE-200, CWE-284 | DAST, code review         |
| A02  | A02:21 | Cryptographic Failures             | CWE-259, CWE-327 | SAST, config audit        |
| A03  | A03:21 | Injection                          | CWE-79, CWE-89   | SAST, DAST, IAST          |
| A04  | A04:21 | Insecure Design                    | CWE-209, CWE-256 | Threat modeling, review   |
| A05  | A05:21 | Security Misconfiguration          | CWE-16, CWE-611  | IaC scan, CIS benchmarks  |
| A06  | A06:21 | Vulnerable Components              | CWE-1035         | SCA, SBOM analysis        |
| A07  | A07:21 | Auth & Identification Failures     | CWE-287, CWE-384 | DAST, penetration testing |
| A08  | A08:21 | Software & Data Integrity Failures | CWE-502, CWE-829 | SCA, supply chain audit   |
| A09  | A09:21 | Security Logging & Monitoring Gaps | CWE-778          | Log audit, SIEM review    |
| A10  | A10:21 | Server-Side Request Forgery (SSRF) | CWE-918          | DAST, code review         |

### 2.1 OWASP Detection Coverage by Tool Type

| Tool Type | A01  | A02  | A03  | A04 | A05  | A06  | A07  | A08  | A09 | A10  |
| --------- | ---- | ---- | ---- | --- | ---- | ---- | ---- | ---- | --- | ---- |
| SAST      | Med  | High | High | Low | Med  | Low  | Med  | Med  | Low | Med  |
| DAST      | High | Med  | High | Low | High | Low  | High | Low  | Low | High |
| SCA       | Low  | Low  | Low  | Low | Low  | High | Low  | High | Low | Low  |
| IaC Scan  | Med  | Med  | Low  | Low | High | Low  | Med  | Low  | Med | Low  |
| IAST      | High | High | High | Low | Med  | Low  | High | Med  | Low | High |

---

## 3. MITRE ATT&CK v16 — Key Techniques / เทคนิคการโจมตีหลัก

Reference: https://attack.mitre.org/ (v16, Enterprise matrix)

### 3.1 Initial Access (TA0001)

| Technique ID | Name                              | DevSecOps Countermeasure        |
| ------------ | --------------------------------- | ------------------------------- |
| T1190        | Exploit Public-Facing Application | WAF, DAST, patch management     |
| T1195        | Supply Chain Compromise           | SCA, SBOM, dependency pinning   |
| T1199        | Trusted Relationship              | Zero Trust, service mesh mTLS   |
| T1566        | Phishing                          | Email security, MFA enforcement |

### 3.2 Execution (TA0002)

| Technique ID | Name                              | DevSecOps Countermeasure                |
| ------------ | --------------------------------- | --------------------------------------- |
| T1059        | Command & Scripting Interpreter   | SAST injection checks, input validation |
| T1203        | Exploitation for Client Execution | DAST, browser security headers          |
| T1204        | User Execution                    | Content security policy, sandboxing     |

### 3.3 Persistence (TA0003)

| Technique ID | Name                 | DevSecOps Countermeasure               |
| ------------ | -------------------- | -------------------------------------- |
| T1053        | Scheduled Task/Job   | IaC audit, cron monitoring             |
| T1078        | Valid Accounts       | Credential rotation, anomaly detection |
| T1098        | Account Manipulation | IAM audit, access review automation    |
| T1136        | Create Account       | Automated user provisioning audit      |

### 3.4 Privilege Escalation (TA0004)

| Technique ID | Name                             | DevSecOps Countermeasure             |
| ------------ | -------------------------------- | ------------------------------------ |
| T1068        | Exploitation for Priv Escalation | Container security, kernel hardening |
| T1078        | Valid Accounts                   | Least privilege, JIT access          |
| T1548        | Abuse Elevation Control          | sudo audit, RBAC enforcement         |
| T1611        | Escape to Host                   | Container runtime security, seccomp  |

### 3.5 Defense Evasion (TA0005)

| Technique ID | Name                            | DevSecOps Countermeasure                  |
| ------------ | ------------------------------- | ----------------------------------------- |
| T1027        | Obfuscated Files or Information | Malware scanning, behavioral analysis     |
| T1036        | Masquerading                    | File integrity monitoring, code signing   |
| T1070        | Indicator Removal               | Immutable logging, centralized SIEM       |
| T1562        | Impair Defenses                 | Tamper detection, agent health monitoring |

---

## 4. CIS Controls v8.1 / การควบคุม CIS

Reference: https://www.cisecurity.org/controls/v8 (v8.1, 2024)

### 4.1 Implementation Groups (IG)

| Group | Target Organization         | Controls Count | Focus                            |
| ----- | --------------------------- | -------------- | -------------------------------- |
| IG1   | Small, limited IT resources | 56 safeguards  | Essential cyber hygiene          |
| IG2   | Enterprise with IT staff    | 130 safeguards | Moderate complexity environments |
| IG3   | Mature security program     | 153 safeguards | Advanced threats, full coverage  |

### 4.2 Key Controls Relevant to DevSecOps

| CIS ID | Title                               | IG  | DevSecOps Implementation                    |
| ------ | ----------------------------------- | --- | ------------------------------------------- |
| 1      | Inventory of Enterprise Assets      | IG1 | Cloud asset discovery, CMDB automation      |
| 2      | Inventory of Software Assets        | IG1 | SBOM generation, container image catalog    |
| 3      | Data Protection                     | IG1 | Encryption at rest/transit, DLP rules       |
| 4      | Secure Configuration                | IG1 | CIS benchmarks, IaC scanning, hardening     |
| 5      | Account Management                  | IG1 | RBAC, service account lifecycle, MFA        |
| 6      | Access Control Management           | IG1 | Least privilege, JIT access, PAM            |
| 7      | Continuous Vulnerability Management | IG1 | SAST/DAST/SCA pipeline integration          |
| 8      | Audit Log Management                | IG1 | Centralized logging, SIEM, retention policy |
| 9      | Email & Web Browser Protections     | IG1 | CSP headers, email filtering, URL filtering |
| 10     | Malware Defenses                    | IG1 | Container scanning, EDR, runtime protection |
| 11     | Data Recovery                       | IG1 | Backup automation, DR testing               |
| 12     | Network Infrastructure Management   | IG1 | Network policies, segmentation, firewall    |
| 13     | Network Monitoring & Defense        | IG2 | IDS/IPS, network flow analysis, WAF         |
| 14     | Security Awareness Training         | IG1 | Secure coding training, phishing simulation |
| 15     | Service Provider Management         | IG1 | Third-party risk assessment, SLA monitoring |
| 16     | Application Software Security       | IG2 | SDLC integration, secure code review        |
| 17     | Incident Response Management        | IG1 | IR playbooks, tabletop exercises            |
| 18     | Penetration Testing                 | IG2 | Automated DAST, red team exercises          |

---

## 5. Cross-Walk Matrix: 20 Control Areas / ตารางเทียบเคียง 20 ด้าน

This table maps equivalent controls across all four frameworks for the 20 most
critical DevSecOps control areas.

| #   | Control Area                | NIST 800-53r5 | OWASP 2021 | MITRE ATT&CK | CIS v8.1 |
| --- | --------------------------- | ------------- | ---------- | ------------ | -------- |
| 1   | Input Validation            | SI-10         | A03        | T1059        | CIS-16   |
| 2   | Authentication              | IA-2, IA-5    | A07        | T1078        | CIS-5    |
| 3   | Authorization / Access Ctrl | AC-3, AC-6    | A01        | T1548        | CIS-6    |
| 4   | Cryptography                | SC-12, SC-13  | A02        | T1573        | CIS-3    |
| 5   | Secret Management           | IA-5, SC-28   | A02        | T1552        | CIS-3    |
| 6   | Dependency Management       | SI-2, CM-8    | A06        | T1195        | CIS-2    |
| 7   | Container Security          | CM-6, CM-7    | A05        | T1611        | CIS-4    |
| 8   | IaC Security                | CM-2, CM-3    | A05        | T1098        | CIS-4    |
| 9   | Logging & Monitoring        | AU-2, AU-6    | A09        | T1070        | CIS-8    |
| 10  | Vulnerability Management    | RA-5, SI-2    | A06        | T1190        | CIS-7    |
| 11  | Network Security            | AC-4, SC-7    | A10        | T1071        | CIS-12   |
| 12  | Data Protection             | SC-8, SC-28   | A02        | T1565        | CIS-3    |
| 13  | Supply Chain Security       | SA-12, SR-3   | A08        | T1195.002    | CIS-16   |
| 14  | Incident Response           | IR-4, IR-5    | A09        | —            | CIS-17   |
| 15  | Security Testing            | CA-8, RA-5    | A04        | —            | CIS-18   |
| 16  | Configuration Management    | CM-6, CM-7    | A05        | T1562        | CIS-4    |
| 17  | Identity & Account Mgmt     | AC-2, IA-4    | A07        | T1136        | CIS-5    |
| 18  | Code Integrity              | SI-7          | A08        | T1036        | CIS-2    |
| 19  | Malware Defense             | SI-3          | A08        | T1027        | CIS-10   |
| 20  | Backup & Recovery           | CP-9, CP-10   | —          | T1490        | CIS-11   |

---

## 6. Compliance Automation / การทำให้ Compliance เป็นอัตโนมัติ

### 6.1 Tool-to-Framework Mapping

| DevSecOps Tool         | NIST Controls Covered | OWASP Coverage | CIS Controls  |
| ---------------------- | --------------------- | -------------- | ------------- |
| SAST (Semgrep, etc)    | SI-10, RA-5           | A01-A04, A10   | CIS-16        |
| DAST (ZAP, Nuclei)     | RA-5, CA-8            | A01-A03, A05+  | CIS-18        |
| SCA (Trivy, Grype)     | CM-8, SI-2            | A06, A08       | CIS-2, CIS-7  |
| IaC Scan (Checkov)     | CM-2, CM-6, SC-7      | A05            | CIS-4         |
| Container Scan         | CM-7, SI-3            | A05, A06       | CIS-4, CIS-10 |
| Secret Scan            | IA-5, SC-28           | A02            | CIS-3         |
| SBOM (Syft, CycloneDX) | CM-8, SR-3            | A06, A08       | CIS-2         |

### 6.2 Evidence Collection Template

```yaml
# compliance-evidence.yaml — Auto-generated per pipeline run
framework: NIST-800-53r5
control_id: RA-5
control_name: "Vulnerability Monitoring and Scanning"
evidence:
  scan_tool: "trivy v0.58.0"
  scan_target: "myapp:v2.1.0"
  scan_date: "2026-03-01T10:00:00Z"
  total_findings: 12
  critical: 0
  high: 2
  medium: 7
  low: 3
  report_artifact: "s3://compliance-bucket/reports/trivy-2026-03-01.json"
  pipeline_url: "https://github.com/myorg/myapp/actions/runs/12345"
  remediation_sla: "HIGH=7d, MEDIUM=30d, LOW=90d"
  status: "COMPLIANT_WITH_EXCEPTIONS"
```

### 6.3 Continuous Compliance Dashboard Metrics

| Metric                     | Formula                                | Target |
| -------------------------- | -------------------------------------- | ------ |
| Control Coverage Rate      | Controls tested / Total controls       | > 80%  |
| Compliance Score           | Passing controls / Total assessed      | > 95%  |
| Evidence Freshness         | Controls with evidence < 30 days old   | > 90%  |
| Exception Rate             | Controls with accepted risk            | < 5%   |
| Remediation SLA Compliance | Fixed within SLA / Total findings      | > 90%  |
| Audit Finding Closure Rate | Closed findings / Total audit findings | > 95%  |

---

## 7. Framework Version History / ประวัติเวอร์ชัน

| Framework    | Current Version | Release Date | Previous Version | Key Changes                             |
| ------------ | --------------- | ------------ | ---------------- | --------------------------------------- |
| NIST 800-53  | Rev.5           | Sep 2020     | Rev.4 (2013)     | Supply chain controls (SR), privacy     |
| OWASP Top 10 | 2021            | Sep 2021     | 2017             | New: A04 Insecure Design, A08 Integrity |
| MITRE ATT&CK | v16             | Oct 2024     | v15 (Apr 2024)   | Cloud/container technique expansion     |
| CIS Controls | v8.1            | Jun 2024     | v8 (May 2021)    | Refined safeguards, updated mappings    |
| ISO 27001    | 2022            | Oct 2022     | 2013             | 93 controls (from 114), new themes      |
| PCI DSS      | 4.0.1           | Jun 2024     | 4.0 (Mar 2022)   | Targeted risk analysis requirements     |
| SOC 2        | 2017 (TSC)      | 2017         | 2016             | Additional criteria for availability    |

---

## 8. Regulatory Quick Reference / กฎระเบียบอ้างอิงด่วน

### 8.1 Region-Specific Regulations

| Regulation  | Region          | Key Requirement for DevSecOps                   | Penalty (Max)        |
| ----------- | --------------- | ----------------------------------------------- | -------------------- |
| GDPR        | EU/EEA          | Data protection by design (Art.25), breach 72h  | 4% annual revenue    |
| PDPA        | Thailand        | Data protection, consent management, breach 72h | 5M THB + criminal    |
| HIPAA       | US (Healthcare) | PHI encryption, access controls, audit trails   | $1.9M per violation  |
| PCI DSS 4.0 | Global (Cards)  | Continuous monitoring, WAF, quarterly ASV scans | $100K/month fines    |
| SOX         | US (Public Co)  | IT controls for financial reporting integrity   | Criminal penalties   |
| CCPA/CPRA   | US (California) | Consumer data rights, security requirements     | $7,500 per violation |

### 8.2 Thailand-Specific: PDPA Compliance Checklist / รายการตรวจสอบ PDPA

```text
1. [ ] Data Protection Impact Assessment (DPIA) completed
2. [ ] Lawful basis for processing documented (consent, legitimate interest, etc.)
3. [ ] Data Subject Rights API implemented (access, correction, deletion, portability)
4. [ ] Breach notification process established (72-hour window to PDPC)
5. [ ] Data Protection Officer (DPO) appointed if required
6. [ ] Cross-border transfer safeguards in place (adequacy, SCCs, BCRs)
7. [ ] Retention policy and automated data deletion implemented
8. [ ] Privacy-by-design review integrated into SDLC
9. [ ] Third-party processor agreements (DPA) signed
10.[ ] Annual PDPA compliance audit scheduled
```

---

## References / แหล่งอ้างอิง

- NIST SP 800-53 Rev.5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- OWASP Top 10 (2021): https://owasp.org/Top10/
- MITRE ATT&CK v16: https://attack.mitre.org/
- CIS Controls v8.1: https://www.cisecurity.org/controls/v8
- ISO/IEC 27001:2022: https://www.iso.org/standard/27001
- PCI DSS v4.0.1: https://www.pcisecuritystandards.org/
- Thailand PDPA: https://www.pdpc.or.th/
- GDPR: https://gdpr.eu/
- NIST Cybersecurity Framework v2.0: https://www.nist.gov/cyberframework
