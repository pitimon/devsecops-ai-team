# Incident Response Reference

# คู่มือการตอบสนองต่อเหตุการณ์ด้านความปลอดภัย

> **Purpose / วัตถุประสงค์**: Domain knowledge for DevSecOps agents handling security incidents.
> It covers the NIST SP 800-61 Rev.2 four-phase incident response lifecycle, playbook templates,
> severity classification, escalation matrices, evidence handling, communication templates,
> forensic analysis checklists, MITRE ATT&CK mapping for IR, and post-incident review processes.
> Agents load this file when triaging security events, coordinating response activities, or
> generating incident documentation.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: NIST SP 800-61 Rev.2, MITRE ATT&CK v16, FIRST CSIRT Services Framework v2.1, ISO/IEC 27035:2023, SANS IR Process

---

## 1. NIST SP 800-61 Rev.2 — Four Phases / สี่ขั้นตอนตาม NIST

## วงจรชีวิตการตอบสนองต่อเหตุการณ์ตาม NIST

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
1.  [ ] IR team roster with roles, contact info, and on-call rotation
2.  [ ] IR policy and procedures documented and approved
3.  [ ] Communication plan (internal + external + regulatory)
4.  [ ] Tool inventory: SIEM, EDR, forensic tools, log aggregation
5.  [ ] Playbooks for top 10 incident types (see Section 3)
6.  [ ] Evidence collection and chain-of-custody procedures
7.  [ ] Legal counsel and law enforcement contact information
8.  [ ] Incident tracking system configured (Jira, ServiceNow, etc.)
9.  [ ] Tabletop exercises conducted quarterly
10. [ ] Backup and recovery procedures tested
11. [ ] Network diagrams and asset inventory current
12. [ ] Forensic workstation ready (write-blocker, imaging tools)
```

**IR Team Roles / บทบาทในทีมตอบสนอง:**

| Role                    | Thai Translation         | Responsibilities                                          |
| ----------------------- | ------------------------ | --------------------------------------------------------- |
| Incident Commander (IC) | ผู้บัญชาการเหตุการณ์     | Overall coordination, decision authority                  |
| Security Analyst (L1)   | นักวิเคราะห์ระดับ 1      | Initial triage, alert monitoring, ticket creation         |
| Security Analyst (L2)   | นักวิเคราะห์ระดับ 2      | Deep investigation, malware analysis, forensics           |
| DevOps/SRE Lead         | หัวหน้า DevOps/SRE       | System containment, service recovery, infrastructure      |
| Communications Lead     | ผู้นำการสื่อสาร          | Stakeholder updates, regulatory notifications             |
| Legal Counsel           | ที่ปรึกษากฎหมาย          | Legal obligations, evidence preservation, law enforcement |
| Executive Sponsor       | ผู้บริหารสนับสนุน        | Business decisions, resource allocation, media            |
| Forensic Analyst        | ผู้ตรวจสอบหลักฐานดิจิทัล | Evidence collection, disk imaging, memory analysis        |

**Tool Stack Requirements / เครื่องมือที่จำเป็น:**

| Category          | Tool Examples                     | Version        | Purpose                              |
| ----------------- | --------------------------------- | -------------- | ------------------------------------ |
| SIEM              | Elastic SIEM, Splunk Enterprise   | 8.x, 9.x       | Log aggregation, correlation         |
| EDR               | CrowdStrike Falcon, SentinelOne   | Latest         | Endpoint detection and response      |
| SOAR              | Cortex XSOAR, Tines               | Latest         | Automated response orchestration     |
| Network Forensics | Zeek, Wireshark, Suricata         | 7.x, 4.x, 7.x  | Packet capture and analysis          |
| Disk Forensics    | Autopsy, FTK Imager, Velociraptor | 4.x, 4.x, 0.73 | Disk imaging and artifact extraction |
| Memory Forensics  | Volatility 3, Rekall              | 3.x            | RAM analysis, process inspection     |
| Malware Analysis  | Cuckoo Sandbox, ANY.RUN           | Latest         | Dynamic malware analysis             |
| Threat Intel      | MISP, OpenCTI                     | 2.4, 6.x       | IOC management, sharing              |

### 1.3 Phase 2: Detection & Analysis / การตรวจจับและวิเคราะห์

**Detection Sources / แหล่งตรวจจับ:**

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

**Analysis Framework / กรอบการวิเคราะห์:**

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

**Containment Strategies / กลยุทธ์การควบคุม:**

| Strategy              | Speed  | Impact   | When to Use                              |
| --------------------- | ------ | -------- | ---------------------------------------- |
| Network Isolation     | Fast   | High     | Active data exfiltration confirmed       |
| Account Disable       | Fast   | Medium   | Compromised credentials confirmed        |
| Service Shutdown      | Fast   | Critical | Active exploitation of the service       |
| DNS Sinkhole          | Medium | Low      | C2 communication detected                |
| WAF Rule (block)      | Fast   | Low      | Known exploit pattern, targeted endpoint |
| IP Blocklist          | Fast   | Low      | Attack from specific IP ranges           |
| Certificate Revoke    | Medium | Medium   | Compromised TLS/mTLS certificate         |
| Container Kill/Cordon | Fast   | Medium   | Compromised pod in Kubernetes            |
| API Key Revocation    | Fast   | Medium   | Leaked or compromised API credentials    |
| Patch Deploy (hotfix) | Slow   | Low      | Vulnerability without active exploit     |

**Eradication Steps / ขั้นตอนการกำจัด:**

```text
1. [ ] Remove attacker access (revoke credentials, close backdoors)
2. [ ] Patch vulnerability that was exploited
3. [ ] Remove malware/web shells/persistence mechanisms
4. [ ] Reset all potentially compromised credentials
5. [ ] Rebuild compromised systems from known-good images
6. [ ] Verify no remaining attacker presence (threat hunt)
7. [ ] Update detection rules to catch this attack pattern
```

**Recovery Steps / ขั้นตอนการกู้คืน:**

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

### ระดับความรุนแรง

| Level | Name     | Thai Level | Description                                               | Response Time | Examples                               |
| ----- | -------- | ---------- | --------------------------------------------------------- | ------------- | -------------------------------------- |
| SEV-1 | Critical | วิกฤต      | Active breach with data exfiltration or system compromise | 15 min        | Ransomware, active APT, mass data leak |
| SEV-2 | High     | สูง        | Confirmed compromise, contained but not eradicated        | 1 hour        | Compromised credential, malware found  |
| SEV-3 | Medium   | ปานกลาง    | Potential incident requiring investigation                | 4 hours       | Suspicious activity, anomalous access  |
| SEV-4 | Low      | ต่ำ        | Minor security event, no confirmed compromise             | 24 hours      | Failed brute-force, policy violation   |
| SEV-5 | Info     | ข้อมูล     | Security observation, no threat confirmed                 | Best effort   | Informational alerts, false positives  |

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
- Secret scanning alert (Gitleaks v8.x, TruffleHog v3.x)
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

### 3.4 Playbook: Compromised CI/CD Pipeline

```text
INCIDENT TYPE: CI/CD Pipeline Compromise
SEVERITY: SEV-1 (Critical)

IMMEDIATE ACTIONS (< 30 minutes):
1. [ ] HALT all deployments immediately
2. [ ] Revoke CI/CD service account tokens
3. [ ] Audit recent deployments (last 30 days)
4. [ ] Compare deployed artifacts against source (hash verification)

INVESTIGATION:
5. [ ] Review pipeline configuration changes (git log)
6. [ ] Check for injected build steps or modified scripts
7. [ ] Verify container image signatures (cosign/notation)
8. [ ] Audit secret access in pipeline (Vault audit log)
9. [ ] Check for dependency confusion or typosquatting

CONTAINMENT:
10.[ ] Rotate all secrets accessible to CI/CD
11.[ ] Regenerate and re-sign all container images
12.[ ] Redeploy from verified clean source
13.[ ] Enable mandatory code review for pipeline changes

PREVENTION:
14.[ ] Implement signed commits (GPG/SSH)
15.[ ] Require 2-person review for pipeline changes
16.[ ] Pin all dependencies to exact versions with checksums
17.[ ] Deploy SLSA Level 3 provenance
```

---

## 4. Escalation Matrix / เมทริกซ์การยกระดับ

### 4.1 Escalation by Severity / การยกระดับตามความรุนแรง

| Severity | Initial Responder | Escalate To (15 min) | Escalate To (1 hr)  | Escalate To (4 hr) |
| -------- | ----------------- | -------------------- | ------------------- | ------------------ |
| SEV-1    | On-call Security  | IR Commander + CISO  | CEO + Legal Counsel | Board (if breach)  |
| SEV-2    | On-call Security  | IR Commander         | Security Manager    | CISO               |
| SEV-3    | Security Analyst  | Senior Analyst       | Security Manager    | IR Commander       |
| SEV-4    | Security Analyst  | Senior Analyst       | --                  | --                 |
| SEV-5    | Auto-triage       | Security Analyst     | --                  | --                 |

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

### 4.3 Scenario-Based Escalation

| Trigger Condition                      | Immediate Action                        | Notify Within          |
| -------------------------------------- | --------------------------------------- | ---------------------- |
| Confirmed data breach (PII/PHI/PCI)    | Activate breach response plan           | Legal: 1 hour          |
| Active ransomware encryption           | Isolate network segment, activate BCP   | CISO: 15 min           |
| Nation-state attribution suspected     | Engage external IR firm                 | Law enforcement: 24 hr |
| Insider threat with ongoing access     | Disable account, preserve evidence      | HR + Legal: 1 hr       |
| Supply chain compromise (build/deploy) | Halt deployments, audit recent releases | CTO: 30 min            |
| Cloud root/admin account compromised   | Rotate all credentials, audit logs      | CISO: 30 min           |

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

## 6. Evidence Handling & Chain of Custody / การจัดการหลักฐานและสายโซ่ของหลักฐาน

### 6.1 Evidence Collection Order (Volatility)

### ลำดับการเก็บหลักฐาน (ตามความผันผวน)

Collect evidence in order of volatility (most volatile first):

| Priority | Evidence Type          | Thai Translation      | Volatility | Collection Method                    |
| -------- | ---------------------- | --------------------- | ---------- | ------------------------------------ |
| 1        | Memory (RAM)           | หน่วยความจำ           | Very High  | LiME, WinPMEM, Velociraptor v0.73+   |
| 2        | Running processes      | โปรเซสที่ทำงาน        | Very High  | Process list, network connections    |
| 3        | Network connections    | การเชื่อมต่อเครือข่าย | High       | netstat, ss, tcpdump, packet capture |
| 4        | System logs (volatile) | บันทึกระบบ (ชั่วคราว) | High       | Journal export, syslog capture       |
| 5        | Disk images            | อิมเมจดิสก์           | Medium     | dd, FTK Imager (with write-blocker)  |
| 6        | Configuration files    | ไฟล์การตั้งค่า        | Medium     | Copy from live system or backup      |
| 7        | Application logs       | บันทึกแอปพลิเคชัน     | Low        | Export from logging system           |
| 8        | Cloud audit logs       | บันทึกตรวจสอบคลาวด์   | Low        | CloudTrail, Azure Activity Log       |
| 9        | Backup data            | ข้อมูลสำรอง           | Very Low   | Retrieve from backup system          |

### 6.2 Chain of Custody Form

```text
CHAIN OF CUSTODY — Evidence ID: [EVD-YYYY-NNNN]

Evidence Description: [What is it]
Collection Date/Time: [UTC timestamp]
Collected By: [Name, role]
Collection Method: [Tool used, command executed]
Hash (SHA-256): [Hash of collected evidence]
Storage Location: [Secure storage path/location]
Encryption: [AES-256 at rest]
Access Control: [IR team only, logged access]

Transfer Log:
| Date/Time   | From          | To            | Purpose          | Hash Verified | Signature |
|-------------|---------------|---------------|------------------|---------------|-----------|
| [timestamp] | [collector]   | [analyst]     | Analysis         | Yes           | [sig]     |
| [timestamp] | [analyst]     | [storage]     | Secure storage   | Yes           | [sig]     |
```

### 6.3 Evidence Collection Commands

```bash
# Linux Memory Acquisition
sudo insmod /opt/lime/lime.ko "path=/evidence/mem.lime format=lime"

# Linux Disk Image (read-only, with hashing)
sudo dc3dd if=/dev/sda of=/evidence/disk.dd hash=sha256 log=/evidence/dd.log

# Volatile Data Collection Script
#!/bin/bash
EVIDENCE_DIR="/evidence/$(hostname)-$(date +%Y%m%d%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# Processes
ps auxef > "$EVIDENCE_DIR/ps.txt"
ls -la /proc/*/exe 2>/dev/null > "$EVIDENCE_DIR/proc_exe.txt"

# Network
ss -tulnp > "$EVIDENCE_DIR/ss.txt"
ip addr show > "$EVIDENCE_DIR/ip_addr.txt"
ip route show > "$EVIDENCE_DIR/ip_route.txt"
iptables -L -n -v > "$EVIDENCE_DIR/iptables.txt"

# Users and Auth
who > "$EVIDENCE_DIR/who.txt"
last -50 > "$EVIDENCE_DIR/last.txt"

# File System
find / -mtime -1 -type f 2>/dev/null > "$EVIDENCE_DIR/recent_files.txt"
find / -perm -4000 -type f 2>/dev/null > "$EVIDENCE_DIR/suid_files.txt"

# Hashes
sha256sum "$EVIDENCE_DIR"/* > "$EVIDENCE_DIR/evidence_hashes.txt"
```

### 6.4 Kubernetes / Container Evidence Collection

```bash
# Pod-level evidence
kubectl get pods -A -o wide > evidence/k8s_pods.txt
kubectl describe pod <pod-name> -n <namespace> > evidence/pod_describe.txt
kubectl logs <pod-name> -n <namespace> --all-containers > evidence/pod_logs.txt
kubectl logs <pod-name> -n <namespace> --previous > evidence/pod_logs_prev.txt

# Container filesystem snapshot
kubectl cp <namespace>/<pod-name>:/etc/passwd evidence/container_passwd.txt
kubectl exec <pod-name> -n <namespace> -- cat /proc/1/cmdline > evidence/init_cmd.txt

# Runtime security events (Falco)
kubectl logs -n falco -l app=falco --tail=1000 > evidence/falco_alerts.txt

# Network policies
kubectl get networkpolicies -A -o yaml > evidence/netpol.yaml

# Container image verification
cosign verify --key cosign.pub <image>:<tag> 2>&1 > evidence/image_sig.txt
```

### 6.5 Evidence Do's and Don'ts / สิ่งที่ควรและไม่ควรทำ

| DO                                         | DON'T                                          |
| ------------------------------------------ | ---------------------------------------------- |
| Capture memory before disk                 | Don't reboot the system                        |
| Photograph screens with timestamps         | Don't run antivirus (it modifies files)        |
| Use write-blockers for disk imaging        | Don't browse the filesystem carelessly         |
| Hash everything immediately                | Don't use the compromised system to analyze    |
| Document every action with time and person | Don't share findings outside secure channels   |
| Work on forensic copies, never originals   | Don't delete logs or "clean up" before imaging |

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

## 8. Forensic Analysis Checklist / รายการตรวจสอบการวิเคราะห์หลักฐานดิจิทัล

### 8.1 Memory Forensics / การวิเคราะห์หน่วยความจำ

```yaml
memory_analysis:
  tool: "Volatility 3.x"
  checks:
    - command: "vol -f mem.lime linux.pslist"
      purpose: "List all running processes"
    - command: "vol -f mem.lime linux.psaux"
      purpose: "Check for hidden processes"
    - command: "vol -f mem.lime linux.sockstat"
      purpose: "Analyze active network connections"
    - command: "vol -f mem.lime linux.bash"
      purpose: "Extract bash command history from memory"
    - command: "vol -f mem.lime linux.check_syscall"
      purpose: "Check for rootkit syscall hooks"
    - command: "vol -f mem.lime linux.malfind"
      purpose: "Find injected/suspicious memory regions"
    - command: "vol -f mem.lime linux.elfs"
      purpose: "List loaded ELF binaries"

  windows_checks:
    - command: "vol -f mem.dmp windows.pslist"
      purpose: "List running processes"
    - command: "vol -f mem.dmp windows.netscan"
      purpose: "Network connections and listening ports"
    - command: "vol -f mem.dmp windows.cmdline"
      purpose: "Command line arguments for each process"
    - command: "vol -f mem.dmp windows.malfind"
      purpose: "Detect code injection"
    - command: "vol -f mem.dmp windows.hashdump"
      purpose: "Extract password hashes (if applicable)"
```

### 8.2 Disk Forensics / การวิเคราะห์ดิสก์

```yaml
disk_analysis:
  tool: "Autopsy 4.x / Sleuth Kit / Velociraptor"
  checks:
    - "Timeline analysis of file system changes (MFT/inode timestamps)"
    - "Recover deleted files from unallocated space"
    - "Analyze /tmp, /dev/shm for dropped attacker tools"
    - "Check crontabs and systemd timers for persistence"
    - "Review .bash_history, .zsh_history, .python_history"
    - "Examine SSH authorized_keys for backdoor keys"
    - "Check for modified system binaries (rootkit indicators)"
    - "Analyze web server access/error logs"
    - "Review /etc/passwd, /etc/shadow for added accounts"
    - "Check /etc/sudoers for unauthorized privilege grants"
    - "Inspect Docker overlay filesystem for container artifacts"
```

### 8.3 Log Analysis / การวิเคราะห์บันทึก

```yaml
log_analysis:
  system_logs:
    - source: "/var/log/auth.log or /var/log/secure"
      look_for: "Failed/successful logins, sudo usage, SSH connections"
    - source: "journalctl"
      look_for: "Service starts/stops, kernel messages, security events"
    - source: "/var/log/syslog"
      look_for: "System-wide events, cron execution, service errors"

  application_logs:
    - source: "Application-specific paths"
      look_for: "Error spikes, unusual request patterns, auth failures"
    - source: "Web server access.log"
      look_for: "Unusual URIs, injection attempts, scanning patterns"
    - source: "Web server error.log"
      look_for: "Application errors indicating exploitation"

  database_logs:
    - source: "PostgreSQL pg_log / MySQL slow query log"
      look_for: "Unusual queries, data export patterns, schema changes"

  cloud_logs:
    - source: "AWS CloudTrail"
      look_for: "IAM changes, unusual API calls, root login"
    - source: "VPC Flow Logs"
      look_for: "Lateral movement, unusual traffic patterns"
    - source: "GuardDuty / Security Hub"
      look_for: "Automated threat detection findings"

  kubernetes_logs:
    - source: "API server audit logs"
      look_for: "Unauthorized API calls, RBAC bypasses"
    - source: "Pod logs"
      look_for: "Application-level attack indicators"
    - source: "Falco alerts"
      look_for: "Runtime security violations"

  correlation:
    - "Normalize all timestamps to UTC"
    - "Use correlation IDs to trace requests across services"
    - "Build timeline from earliest to latest event"
    - "Identify gaps in logging coverage"
```

### 8.4 Network Forensics / การวิเคราะห์เครือข่าย

```yaml
network_analysis:
  tool: "Zeek 7.x, Wireshark 4.x, Suricata 7.x"
  checks:
    - "Identify communication with known malicious IPs/domains"
    - "Look for DNS tunneling (unusually long subdomain queries)"
    - "Detect beaconing patterns (regular interval callbacks to C2)"
    - "Analyze volume and direction of outbound data transfers"
    - "Check for encrypted channels to unusual destinations"
    - "Review VPC Flow Logs for lateral movement between subnets"
    - "Identify unauthorized protocols (e.g., raw TCP where HTTPS expected)"
    - "Check for DNS queries to newly registered domains (< 30 days)"
```

---

## 9. MITRE ATT&CK Mapping for Incident Response

## การแมป MITRE ATT&CK สำหรับการตอบสนองต่อเหตุการณ์

Reference: https://attack.mitre.org/ (v16)

### 9.1 Detection-to-Tactic Mapping / การแมปการตรวจจับ

| ATT&CK Tactic        | Key Techniques                       | Detection Source                | IR Priority |
| -------------------- | ------------------------------------ | ------------------------------- | ----------- |
| Initial Access       | T1190 Exploit Public App             | WAF, IDS, application logs      | Immediate   |
|                      | T1566 Phishing                       | Email gateway, user reports     | High        |
|                      | T1195 Supply Chain Compromise        | SCA scanning, SBOM diff         | Critical    |
|                      | T1078 Valid Accounts                 | Anomaly detection, UBA          | High        |
| Execution            | T1059 Command/Script Interpreter     | EDR, process monitoring         | High        |
|                      | T1203 Exploitation for Client Exec   | EDR, sandbox analysis           | High        |
| Persistence          | T1053 Scheduled Task/Job             | crontab monitoring, EDR         | Medium      |
|                      | T1098 Account Manipulation           | IAM audit, AD monitoring        | High        |
|                      | T1136 Create Account                 | IAM alerts, provisioning logs   | High        |
| Privilege Escalation | T1068 Exploitation for Priv Esc      | EDR, vulnerability scanning     | Critical    |
|                      | T1611 Escape to Host (Container)     | Falco, container runtime sec    | Critical    |
| Defense Evasion      | T1070 Indicator Removal              | Log integrity monitoring, SIEM  | High        |
|                      | T1027 Obfuscated Files/Info          | EDR, sandbox analysis           | Medium      |
| Credential Access    | T1003 OS Credential Dumping          | EDR (mimikatz detection)        | Critical    |
|                      | T1110 Brute Force                    | Auth logs, rate limiting        | Medium      |
|                      | T1528 Steal Application Access Token | Token audit, session monitoring | High        |
| Discovery            | T1046 Network Service Discovery      | IDS, network monitoring         | Low         |
|                      | T1087 Account Discovery              | Audit logging, honeypot         | Low         |
| Lateral Movement     | T1021 Remote Services                | Network monitoring, EDR         | High        |
|                      | T1550 Use Alternate Auth Material    | Token audit, session monitoring | High        |
| Collection           | T1005 Data from Local System         | DLP, file integrity monitoring  | High        |
|                      | T1530 Data from Cloud Storage        | CloudTrail, bucket logging      | High        |
| Exfiltration         | T1041 Exfil Over C2 Channel          | Network monitoring, DLP         | Critical    |
|                      | T1567 Exfil Over Web Service         | Proxy logs, CASB                | Critical    |
| Impact               | T1486 Data Encrypted for Impact      | EDR (ransomware detection)      | Critical    |
|                      | T1489 Service Stop                   | Monitoring, availability checks | High        |

### 9.2 ATT&CK-Based Investigation Queries

```yaml
investigation_queries:
  initial_access_T1190:
    splunk: |
      index=web sourcetype=access_log status=200
      uri_path="/admin*" NOT src_ip IN (known_admin_ips)
    elastic: |
      {"query":{"bool":{"must":[
        {"match":{"http.response.status_code":"200"}},
        {"wildcard":{"url.path":"/admin*"}}
      ],"must_not":[
        {"terms":{"source.ip":["10.0.0.1"]}}
      ]}}}

  credential_access_T1110:
    splunk: |
      index=auth sourcetype=linux_secure "Failed password"
      | stats count by src_ip | where count > 10
    elastic: |
      {"query":{"bool":{"must":[
        {"match":{"event.action":"authentication_failure"}}
      ]}},"aggs":{"by_ip":{"terms":{"field":"source.ip","min_doc_count":10}}}}

  lateral_movement_T1021:
    splunk: |
      index=network sourcetype=zeek_conn id.resp_p IN (22,3389,5985,5986)
      | stats dc(id.resp_h) as targets by id.orig_h | where targets > 3

  exfiltration_T1567:
    splunk: |
      index=network sourcetype=proxy action=allowed bytes_out > 10000000
      | stats sum(bytes_out) as total by src_ip dest_host
      | where total > 100000000

  persistence_T1053:
    splunk: |
      index=os sourcetype=linux_audit type=SYSCALL
      comm IN ("crontab","at","systemctl")
      | where NOT user IN ("root","deploy")
```

### 9.3 ATT&CK-Based Containment Actions

| ATT&CK Tactic        | Containment Action                               | Automation        |
| -------------------- | ------------------------------------------------ | ----------------- |
| Initial Access       | WAF block rule, IP blocklist                     | SOAR playbook     |
| Execution            | Process kill, EDR isolation                      | EDR policy        |
| Persistence          | Remove cron/service, disable account             | Ansible/Salt      |
| Privilege Escalation | Revoke elevated permissions, patch vulnerability | Manual + SOAR     |
| Credential Access    | Force password reset, revoke tokens              | SOAR playbook     |
| Lateral Movement     | Network segmentation, firewall rules             | NSG/SecurityGroup |
| Exfiltration         | Block destination, DNS sinkhole                  | Firewall rule     |
| Impact               | Isolate system, activate BCP                     | Manual            |

---

## 10. IR Metrics & KPIs / ตัวชี้วัด

### 10.1 Key Metrics

| Metric                             | Thai Translation             | Formula                                     | Target        |
| ---------------------------------- | ---------------------------- | ------------------------------------------- | ------------- |
| Mean Time to Detect (MTTD)         | เวลาเฉลี่ยในการตรวจจับ       | Detection time - Compromise time            | < 24 hours    |
| Mean Time to Contain (MTTC)        | เวลาเฉลี่ยในการควบคุม        | Containment time - Detection time           | < 4 hours     |
| Mean Time to Recover (MTTR)        | เวลาเฉลี่ยในการกู้คืน        | Recovery time - Containment time            | < 24 hours    |
| Incidents per Month                | จำนวนเหตุการณ์ต่อเดือน       | Count of confirmed incidents                | Trending down |
| SEV-1 Response SLA Compliance      | การปฏิบัติตาม SLA ของ SEV-1  | Responded within SLA / Total SEV-1          | > 95%         |
| Post-Mortem Completion Rate        | อัตราการทำ Post-Mortem       | PIRs completed / Incidents requiring PIR    | 100%          |
| Action Item Closure Rate (30 days) | อัตราการปิด Action Item      | Closed within 30d / Total action items      | > 80%         |
| Recurring Incident Rate            | อัตราเหตุการณ์ซ้ำ            | Same root cause incidents / Total incidents | < 10%         |
| Detection by Internal Tools        | การตรวจจับโดยเครื่องมือภายใน | Auto-detected / Total incidents             | > 70%         |
| False Positive Rate                | อัตราการแจ้งเตือนผิดพลาด     | False alerts / Total alerts                 | < 20%         |
| Tabletop Exercise Frequency        | ความถี่ในการซ้อมแผน          | Exercises conducted per quarter             | >= 1          |

---

## 11. Regulatory Notification Requirements / ข้อกำหนดการแจ้งเตือนตามกฎหมาย

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

## 12. First Responder Quick Reference Card / การ์ดอ้างอิงสำหรับผู้ตอบสนองคนแรก

```text
+-------------------------------------------------------------+
|            INCIDENT FIRST RESPONDER CARD                     |
|            การ์ดผู้ตอบสนองคนแรก                                |
+-------------------------------------------------------------+
|  1. STAY CALM — DO NOT PANIC                                 |
|  2. DO NOT modify/delete evidence                            |
|  3. DOCUMENT everything with timestamps (UTC)                |
|  4. CREATE incident ticket: INC-YYYYMMDD-NNN                 |
|  5. CLASSIFY severity (SEV 1-5) using Section 2              |
|  6. ESCALATE per matrix (Section 4)                          |
|  7. CONTAIN only if authorized and safe to do so             |
|  8. PRESERVE evidence (memory -> disk -> logs)               |
|  9. COMMUNICATE via secure channel only                      |
| 10. HAND OFF to IR team with full notes                      |
+-------------------------------------------------------------+
|  Emergency Contacts:                                         |
|  IR Commander: [phone] | CISO: [phone]                       |
|  War Room: [Slack channel] | Bridge: [Zoom link]             |
+-------------------------------------------------------------+
```

---

## References / แหล่งอ้างอิง

- NIST SP 800-61 Rev.2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST CSF 2.0 (Respond function): https://www.nist.gov/cyberframework
- SANS Incident Handler's Handbook: https://www.sans.org/white-papers/33901/
- FIRST CSIRT Framework: https://www.first.org/standards/frameworks/csirts/
- MITRE ATT&CK v16: https://attack.mitre.org/
- Volatility 3 Documentation: https://volatility3.readthedocs.io/
- Velociraptor IR Tool: https://docs.velociraptor.app/
- Thailand PDPA Breach Notification: https://www.pdpc.or.th/
- GDPR Breach Notification (Art.33-34): https://gdpr.eu/article-33/
- ISO/IEC 27035:2023 Information Security Incident Management: https://www.iso.org/standard/78973.html
