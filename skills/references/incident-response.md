# Incident Response Reference

# คู่มือการตอบสนองต่อเหตุการณ์ด้านความปลอดภัย

## Purpose / วัตถุประสงค์

This reference provides domain knowledge for DevSecOps agents handling security incidents.
It covers the NIST SP 800-61 Rev.2 four-phase incident response lifecycle, playbook templates,
severity classification, escalation procedures, communication templates, and post-incident
review processes. Agents load this file when triaging security events, coordinating response
activities, or generating incident documentation.

---

## 1. NIST SP 800-61 Rev.2 — Four Phases / สี่ขั้นตอนตาม NIST

Reference: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

### 1.1 Phase Overview

```text
+------------------+    +------------------+    +------------------+    +------------------+
| 1. Preparation   |--->| 2. Detection &   |--->| 3. Containment,  |--->| 4. Post-Incident |
|                  |    |    Analysis      |    |    Eradication,  |    |    Activity      |
|                  |    |                  |    |    & Recovery     |    |                  |
+------------------+    +------------------+    +------------------+    +------------------+
        ^                                                                       |
        |                                                                       |
        +-----------------------------------------------------------------------+
                              Lessons Learned Feedback Loop
```

### 1.2 Phase 1: Preparation / การเตรียมความพร้อม

**Objective:** Establish IR capability before incidents occur.

```text
Preparation Checklist:
1. [ ] IR team roster with roles, contact info, and on-call rotation
2. [ ] IR policy and procedures documented and approved
3. [ ] Communication plan (internal + external + regulatory)
4. [ ] Tool inventory: SIEM, EDR, forensic tools, log aggregation
5. [ ] Playbooks for top 10 incident types (see Section 3)
6. [ ] Evidence collection and chain-of-custody procedures
7. [ ] Legal counsel and law enforcement contact information
8. [ ] Incident tracking system configured (Jira, ServiceNow, etc.)
9. [ ] Tabletop exercises conducted quarterly
10.[ ] Backup and recovery procedures tested
11.[ ] Network diagrams and asset inventory current
12.[ ] Forensic workstation ready (write-blocker, imaging tools)
```

**IR Team Roles:**

| Role                    | Responsibilities                                          |
| ----------------------- | --------------------------------------------------------- |
| Incident Commander (IC) | Overall coordination, decision authority                  |
| Security Analyst        | Triage, investigation, technical analysis                 |
| DevOps/SRE Lead         | System containment, service recovery, infrastructure      |
| Communications Lead     | Stakeholder updates, regulatory notifications             |
| Legal Counsel           | Legal obligations, evidence preservation, law enforcement |
| Executive Sponsor       | Business decisions, resource allocation, media            |
| Forensic Analyst        | Evidence collection, disk imaging, memory analysis        |

### 1.3 Phase 2: Detection & Analysis / การตรวจจับและวิเคราะห์

**Detection Sources:**

| Source                | Type      | Examples                                   |
| --------------------- | --------- | ------------------------------------------ |
| SIEM Alerts           | Automated | Correlation rules, anomaly detection       |
| EDR/XDR               | Automated | Behavioral detection, process monitoring   |
| WAF/IDS/IPS           | Automated | Signature matches, rate limit triggers     |
| Vulnerability Scanner | Automated | New critical CVE detected in production    |
| User Reports          | Manual    | Phishing reports, suspicious activity      |
| Threat Intelligence   | External  | IOC feeds, vendor advisories               |
| Bug Bounty            | External  | Researcher submissions                     |
| Log Analysis          | Semi-auto | Failed login patterns, unusual data access |

**Analysis Framework:**

```text
For each potential incident, determine:

1. WHAT happened?
   - What systems/data are affected?
   - What is the attack vector?
   - What indicators of compromise (IOCs) exist?

2. WHEN did it happen?
   - Initial compromise timestamp
   - Discovery timestamp
   - Timeline of attacker activities

3. HOW did it happen?
   - Vulnerability exploited (CVE, CWE)
   - Attack technique (MITRE ATT&CK mapping)
   - Tools used by attacker

4. WHO is affected?
   - Which users/customers are impacted?
   - Which systems are compromised?
   - Is data exfiltration confirmed?

5. WHY did defenses fail?
   - Which controls were bypassed?
   - Were there detection gaps?
   - Were patches missing?
```

### 1.4 Phase 3: Containment, Eradication & Recovery / การควบคุม กำจัด และกู้คืน

**Containment Strategies:**

| Strategy              | Speed  | Impact   | Use When                                 |
| --------------------- | ------ | -------- | ---------------------------------------- |
| Network Isolation     | Fast   | High     | Active data exfiltration confirmed       |
| Account Disable       | Fast   | Medium   | Compromised credentials confirmed        |
| Service Shutdown      | Fast   | Critical | Active exploitation of the service       |
| DNS Sinkhole          | Medium | Low      | C2 communication detected                |
| WAF Rule (block)      | Fast   | Low      | Known exploit pattern, targeted endpoint |
| IP Blocklist          | Fast   | Low      | Attack from specific IP ranges           |
| Certificate Revoke    | Medium | Medium   | Compromised TLS/mTLS certificate         |
| Patch Deploy (hotfix) | Slow   | Low      | Vulnerability without active exploit     |

**Eradication Steps:**

```text
1. [ ] Remove attacker access (revoke credentials, close backdoors)
2. [ ] Patch vulnerability that was exploited
3. [ ] Remove malware/web shells/persistence mechanisms
4. [ ] Reset all potentially compromised credentials
5. [ ] Rebuild compromised systems from known-good images
6. [ ] Verify no remaining attacker presence (threat hunt)
7. [ ] Update detection rules to catch this attack pattern
```

**Recovery Steps:**

```text
1. [ ] Restore services from verified clean backups if needed
2. [ ] Implement additional monitoring for affected systems
3. [ ] Gradually restore network connectivity
4. [ ] Verify system functionality and data integrity
5. [ ] Monitor for re-compromise indicators (48-72 hours minimum)
6. [ ] Communicate service restoration to stakeholders
```

### 1.5 Phase 4: Post-Incident Activity / กิจกรรมหลังเหตุการณ์

See Section 7 for the detailed Post-Incident Review checklist.

---

## 2. Severity Classification / การจัดระดับความรุนแรง

### 2.1 Severity Levels

| Level | Name     | Description                                               | Response Time | Examples                               |
| ----- | -------- | --------------------------------------------------------- | ------------- | -------------------------------------- |
| SEV-1 | Critical | Active breach with data exfiltration or system compromise | 15 min        | Ransomware, active APT, mass data leak |
| SEV-2 | High     | Confirmed compromise, contained but not eradicated        | 1 hour        | Compromised credential, malware found  |
| SEV-3 | Medium   | Potential incident requiring investigation                | 4 hours       | Suspicious activity, anomalous access  |
| SEV-4 | Low      | Minor security event, no confirmed compromise             | 24 hours      | Failed brute-force, policy violation   |
| SEV-5 | Info     | Security observation, no threat confirmed                 | Best effort   | Informational alerts, false positives  |

### 2.2 Severity Decision Tree

```text
START
  |
  v
Is there confirmed data exfiltration or system compromise?
  |-- YES --> Is it currently active/ongoing?
  |             |-- YES --> SEV-1 (Critical)
  |             |-- NO  --> SEV-2 (High)
  |
  |-- NO  --> Is there confirmed unauthorized access?
                |-- YES --> Is sensitive data at risk?
                |             |-- YES --> SEV-2 (High)
                |             |-- NO  --> SEV-3 (Medium)
                |
                |-- NO  --> Is there suspicious activity requiring investigation?
                              |-- YES --> SEV-3 (Medium) or SEV-4 (Low)
                              |-- NO  --> SEV-5 (Info)
```

---

## 3. IR Playbook Templates / แม่แบบ Playbook

### 3.1 Playbook: Exposed Credentials / การรั่วไหลของ Credential

```text
INCIDENT TYPE: Exposed Credential (Secret in Code/Public Repo)
SEVERITY: SEV-2 (High) — escalate to SEV-1 if active exploitation confirmed

DETECTION:
- Secret scanning alert (Gitleaks, TruffleHog)
- Threat intelligence report (credential on paste site)
- Anomalous API usage from credential

IMMEDIATE ACTIONS (< 15 minutes):
1. [ ] Identify the exposed credential type and scope
2. [ ] Rotate/revoke the credential at the provider immediately
3. [ ] Check access logs for unauthorized usage of the credential
4. [ ] If on public repo: remove from current branch (DO NOT rely on this alone)

INVESTIGATION (< 4 hours):
5. [ ] Determine when the credential was first exposed
6. [ ] Identify who committed it and from which device
7. [ ] Check all services that use this credential for unauthorized access
8. [ ] Review CloudTrail/audit logs for the exposure window
9. [ ] Determine if any data was accessed or modified

REMEDIATION (< 24 hours):
10.[ ] Clean git history using git-filter-repo
11.[ ] Deploy rotated credential to all consuming services
12.[ ] Add pre-commit hook to prevent recurrence
13.[ ] Update secrets baseline
14.[ ] Conduct brief team awareness session

DOCUMENTATION:
15.[ ] Update incident ticket with timeline and findings
16.[ ] File post-incident review if data was accessed
```

### 3.2 Playbook: Ransomware / Playbook แรนซัมแวร์

```text
INCIDENT TYPE: Ransomware
SEVERITY: SEV-1 (Critical)

IMMEDIATE ACTIONS (< 15 minutes):
1. [ ] Isolate affected systems from network IMMEDIATELY
2. [ ] DO NOT pay ransom (consult legal and executive team)
3. [ ] Preserve evidence (do not shut down — capture memory first)
4. [ ] Activate IR team and escalate to executive sponsor
5. [ ] Engage law enforcement if appropriate

INVESTIGATION (parallel with containment):
6. [ ] Identify ransomware variant (check ransom note, file extensions)
7. [ ] Determine initial access vector (phishing, RDP, vulnerability)
8. [ ] Map lateral movement and identify all affected systems
9. [ ] Check for data exfiltration (double extortion)
10.[ ] Determine encryption scope (files, volumes, databases)

CONTAINMENT:
11.[ ] Block C2 domains/IPs at firewall and DNS
12.[ ] Disable compromised accounts
13.[ ] Segment network to prevent spread
14.[ ] Patch the exploited vulnerability
15.[ ] Scan all systems for IOCs

RECOVERY:
16.[ ] Assess backup integrity (verify backups are not encrypted)
17.[ ] Rebuild affected systems from known-good images
18.[ ] Restore data from clean backups
19.[ ] Implement enhanced monitoring
20.[ ] Gradual service restoration with verification

NOTIFICATION:
21.[ ] Notify affected customers if data breach confirmed
22.[ ] File regulatory notification (72 hours for PDPA/GDPR)
23.[ ] Engage PR/communications for public statement if needed
```

### 3.3 Playbook: Supply Chain Attack

```text
INCIDENT TYPE: Compromised Dependency / Supply Chain Attack
SEVERITY: SEV-2 (High) — escalate if active exploitation confirmed

DETECTION:
- SCA alert on known malicious package version
- Unexpected behavior in dependency update
- Community advisory (GitHub Advisory, NVD)

IMMEDIATE ACTIONS (< 1 hour):
1. [ ] Pin/lock affected dependency to known-good version
2. [ ] Block the malicious version in artifact registry
3. [ ] Scan all environments for the affected version
4. [ ] Check build logs for any executed malicious code

INVESTIGATION:
5. [ ] Determine which builds included the compromised dependency
6. [ ] Review SBOM for all deployed artifacts
7. [ ] Check if malicious code executed during build or runtime
8. [ ] Assess data exposure (credentials, environment variables)

REMEDIATION:
9. [ ] Update to patched version or alternative package
10.[ ] Rebuild and redeploy all affected artifacts
11.[ ] Rotate any credentials potentially exposed during build
12.[ ] Update SCA policies to catch similar patterns
13.[ ] Review dependency update process (Dependabot, Renovate config)
```

---

## 4. Escalation Matrix / เมทริกซ์การยกระดับ

### 4.1 Escalation by Severity

| Severity | Initial Responder | Escalate To (15 min) | Escalate To (1 hr)  | Escalate To (4 hr) |
| -------- | ----------------- | -------------------- | ------------------- | ------------------ |
| SEV-1    | On-call Security  | IR Commander + CISO  | CEO + Legal Counsel | Board (if breach)  |
| SEV-2    | On-call Security  | IR Commander         | Security Manager    | CISO               |
| SEV-3    | Security Analyst  | Senior Analyst       | Security Manager    | IR Commander       |
| SEV-4    | Security Analyst  | Senior Analyst       | —                   | —                  |
| SEV-5    | Auto-triage       | Security Analyst     | —                   | —                  |

### 4.2 Escalation Triggers

```text
ESCALATE IMMEDIATELY to next level if:
- Scope expands beyond initial assessment
- New systems/data found to be compromised
- Data exfiltration confirmed
- Attacker activity is ongoing
- Media or external parties are aware
- Regulatory notification deadline approaching
- Containment measures are not effective
- Incident affects customer-facing services
```

---

## 5. Communication Templates / แม่แบบการสื่อสาร

### 5.1 Internal Notification (Initial)

```text
Subject: [SEV-X] Security Incident — [Brief Description] — INC-YYYY-NNNN

Status: ACTIVE
Severity: SEV-X
Incident Commander: [Name]
Opened: [Timestamp UTC]

Summary:
[2-3 sentence description of what happened and current impact]

Affected Systems:
- [System/service 1]
- [System/service 2]

Current Actions:
- [Action 1 — owner — status]
- [Action 2 — owner — status]

Next Update: [Timestamp, typically every 30 min for SEV-1, 2 hr for SEV-2]

Bridge/Channel: [War room link / Slack channel]
```

### 5.2 Internal Update

```text
Subject: [SEV-X] UPDATE #N — [Brief Description] — INC-YYYY-NNNN

Status: [ACTIVE / CONTAINED / RESOLVED]
Time Since Detection: [Duration]

What Changed:
- [Key updates since last communication]

Current Assessment:
- Impact: [Updated impact assessment]
- Root Cause: [If known, or "Under investigation"]
- Scope: [Updated scope]

Actions Completed:
- [Action — completed by — time]

Actions In Progress:
- [Action — owner — ETA]

Next Update: [Timestamp]
```

### 5.3 Customer Notification (Data Breach)

```text
Subject: Important Security Notice from [Company Name]

Dear [Customer/User],

We are writing to inform you of a security incident that may have affected
your personal information.

What Happened:
On [date], we detected [brief, non-technical description of the incident].

What Information Was Involved:
[Specific data types: name, email, etc. Be precise, not vague.]

What We Are Doing:
- We immediately [containment action taken]
- We have engaged [external forensic firm / law enforcement] to investigate
- We are implementing [additional security measures]

What You Can Do:
- Change your account credentials immediately at [URL]
- Enable multi-factor authentication on your account
- Monitor your accounts for suspicious activity
- [Additional specific guidance]

For More Information:
Contact our dedicated incident response team:
- Email: [incident-specific email]
- Phone: [dedicated phone line]
- FAQ: [URL to incident FAQ page]

We sincerely apologize for this incident and are committed to protecting
your information.

[Company Name] Security Team
```

### 5.4 Regulatory Notification (PDPA/GDPR)

```text
To: [PDPC / Supervisory Authority]
From: [Data Protection Officer]
Date: [Within 72 hours of discovery]
Reference: [Incident ID]

1. Nature of the breach:
   [Description of the breach, categories of data, approximate number of records]

2. Data Protection Officer contact:
   [Name, email, phone]

3. Likely consequences:
   [Assessment of potential impact on data subjects]

4. Measures taken:
   [Containment actions, remediation steps, notification to data subjects]

5. Timeline:
   - Breach occurred: [date/time]
   - Breach discovered: [date/time]
   - Containment completed: [date/time]
   - This notification: [date/time]

6. Number of affected data subjects:
   [Exact or approximate number]

7. Categories of personal data:
   [Specific data types involved]
```

---

## 6. Evidence Collection & Chain of Custody / การเก็บหลักฐาน

### 6.1 Evidence Collection Order (Volatility)

Collect evidence in order of volatility (most volatile first):

| Priority | Evidence Type          | Volatility | Collection Method                   |
| -------- | ---------------------- | ---------- | ----------------------------------- |
| 1        | Memory (RAM)           | Very High  | Memory dump tools (LiME, WinPMEM)   |
| 2        | Running processes      | Very High  | Process list, network connections   |
| 3        | Network connections    | High       | netstat, tcpdump, packet capture    |
| 4        | System logs (volatile) | High       | Journal export, syslog capture      |
| 5        | Disk images            | Medium     | dd, FTK Imager (with write-blocker) |
| 6        | Configuration files    | Medium     | Copy from live system or backup     |
| 7        | Application logs       | Low        | Export from logging system          |
| 8        | Backup data            | Very Low   | Retrieve from backup system         |

### 6.2 Chain of Custody Form

```text
CHAIN OF CUSTODY — Evidence ID: [EVD-YYYY-NNNN]

Evidence Description: [What is it]
Collection Date/Time: [UTC timestamp]
Collected By: [Name, role]
Collection Method: [Tool used, command executed]
Hash (SHA-256): [Hash of collected evidence]
Storage Location: [Secure storage path/location]

Transfer Log:
| Date/Time   | From          | To            | Purpose          | Signature |
|-------------|---------------|---------------|------------------|-----------|
| [timestamp] | [collector]   | [analyst]     | Analysis         | [sig]     |
| [timestamp] | [analyst]     | [storage]     | Secure storage   | [sig]     |
```

---

## 7. Post-Incident Review Checklist / รายการตรวจสอบหลังเหตุการณ์

### 7.1 Blameless Post-Mortem Structure

```text
Post-Incident Review — INC-YYYY-NNNN
Date of Review: [Within 5 business days of resolution]
Facilitator: [Name]
Attendees: [List all participants]

1. INCIDENT SUMMARY
   - Start time: [timestamp]
   - Detection time: [timestamp]
   - Containment time: [timestamp]
   - Resolution time: [timestamp]
   - Total duration: [hours/days]
   - Severity: [SEV-X]
   - Impact: [Brief impact statement]

2. TIMELINE
   [Detailed chronological timeline of events, decisions, and actions]

3. ROOT CAUSE ANALYSIS
   - Primary cause: [Technical root cause]
   - Contributing factors: [List all contributing factors]
   - 5 Whys analysis:
     1. Why? [First why]
     2. Why? [Second why]
     3. Why? [Third why]
     4. Why? [Fourth why]
     5. Why? [Root cause]

4. WHAT WENT WELL
   - [List positive aspects of the response]

5. WHAT COULD BE IMPROVED
   - [List areas for improvement — NO BLAME]

6. ACTION ITEMS
   | ID  | Action                  | Owner     | Priority | Due Date   | Status |
   |-----|-------------------------|-----------|----------|------------|--------|
   | AI1 | [Action description]    | [Name]    | P1       | [Date]     | Open   |
   | AI2 | [Action description]    | [Name]    | P2       | [Date]     | Open   |

7. DETECTION GAP ANALYSIS
   - Could we have detected this earlier? How?
   - What monitoring/alerting was missing?
   - What telemetry data was insufficient?

8. METRICS
   - MTTD (Mean Time to Detect): [duration]
   - MTTC (Mean Time to Contain): [duration]
   - MTTR (Mean Time to Recover): [duration]
   - MTTF (Mean Time to Fix root cause): [duration]
```

### 7.2 Post-Incident Review Checklist

```text
Before the Review:
[ ] Incident ticket fully documented with timeline
[ ] All evidence preserved and cataloged
[ ] All team members who participated are invited
[ ] Facilitator assigned (not the incident commander)
[ ] Draft timeline distributed 24 hours before meeting

During the Review:
[ ] Set blameless ground rules at the start
[ ] Walk through timeline chronologically
[ ] Identify each decision point and alternatives considered
[ ] Note what went well — celebrate effective responses
[ ] Identify improvement opportunities without assigning blame
[ ] Create specific, measurable, time-bound action items
[ ] Assign owners to every action item

After the Review:
[ ] Post-mortem document published to team/organization
[ ] Action items entered into tracking system
[ ] Detection rules updated based on lessons learned
[ ] Playbooks updated if procedures were inadequate
[ ] Training scheduled if skill gaps identified
[ ] Architecture changes proposed if systemic issues found
[ ] Follow-up review scheduled to verify action item completion
```

---

## 8. IR Metrics & KPIs / ตัวชี้วัด

| Metric                             | Formula                                     | Target        |
| ---------------------------------- | ------------------------------------------- | ------------- |
| Mean Time to Detect (MTTD)         | Detection time - Compromise time            | < 24 hours    |
| Mean Time to Contain (MTTC)        | Containment time - Detection time           | < 4 hours     |
| Mean Time to Recover (MTTR)        | Recovery time - Containment time            | < 24 hours    |
| Incidents per Month                | Count of confirmed incidents                | Trending down |
| SEV-1 Response SLA Compliance      | Responded within SLA / Total SEV-1          | > 95%         |
| Post-Mortem Completion Rate        | PIRs completed / Incidents requiring PIR    | 100%          |
| Action Item Closure Rate (30 days) | Closed within 30d / Total action items      | > 80%         |
| Recurring Incident Rate            | Same root cause incidents / Total incidents | < 10%         |
| Detection by Internal Tools        | Auto-detected / Total incidents             | > 70%         |
| Tabletop Exercise Frequency        | Exercises conducted per quarter             | >= 1          |

---

## 9. Regulatory Notification Requirements / ข้อกำหนดการแจ้งเตือน

| Regulation | Notification Window | Notify To                   | Threshold                       |
| ---------- | ------------------- | --------------------------- | ------------------------------- |
| PDPA (TH)  | 72 hours            | PDPC + Data Subjects        | Personal data breach            |
| GDPR (EU)  | 72 hours            | Supervisory Authority       | Risk to rights and freedoms     |
| HIPAA (US) | 60 days             | HHS + Individuals + Media\* | Unsecured PHI breach            |
| PCI DSS    | Immediately         | Card Brands + Acquirer      | Cardholder data compromise      |
| SEC (US)   | 4 business days     | SEC (Form 8-K)              | Material cybersecurity incident |
| NIS2 (EU)  | 24h (early) + 72h   | CSIRT + competent authority | Significant incident            |

\*HIPAA: Media notification required if > 500 individuals in a state

---

## References / แหล่งอ้างอิง

- NIST SP 800-61 Rev.2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST CSF 2.0 (Respond function): https://www.nist.gov/cyberframework
- SANS Incident Handler's Handbook: https://www.sans.org/white-papers/33901/
- FIRST CSIRT Framework: https://www.first.org/standards/frameworks/csirts/
- MITRE ATT&CK for IR: https://attack.mitre.org/
- Thailand PDPA Breach Notification: https://www.pdpc.or.th/
- GDPR Breach Notification (Art.33-34): https://gdpr.eu/article-33/
