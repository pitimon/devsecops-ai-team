---
name: incident-response
description: Generate incident response playbooks and coordinate response to critical security findings. Follows NIST SP 800-61 Rev.2 framework.
argument-hint: "[--severity critical|high] [--type injection|credential-leak|rce]"
user-invocable: true
allowed-tools: ["Read", "Write", "Glob", "Bash", "AskUserQuestion"]
---

# Incident Response

Generate an IR playbook and coordinate response to security findings.

**Decision Loop**: In-the-Loop (human decides on escalation and response actions)

## IR Process (NIST 800-61)

### Phase 1: Preparation

Review available scan results and identify the triggering finding(s).

### Phase 2: Detection & Analysis

Assess the finding:

- Confirm severity (CRITICAL/HIGH)
- Identify affected systems and data
- Determine blast radius
- Check for active exploitation indicators

### Phase 3: Containment, Eradication & Recovery

Generate playbook based on finding type:

**For credential leaks:**

1. Rotate affected credentials immediately
2. Revoke active sessions
3. Audit access logs for unauthorized use
4. Clean git history (BFG/git filter-branch)

**For injection vulnerabilities:**

1. Deploy WAF rules as temporary mitigation
2. Fix vulnerable code (parameterized queries, output encoding)
3. Review logs for exploitation attempts
4. Test fix with DAST scan

**For RCE/critical CVEs:**

1. Patch or upgrade affected component
2. Check for IOCs in system logs
3. Network isolation if actively exploited
4. Full incident forensics if compromise confirmed

### Phase 4: Post-Incident Activity

Generate post-incident report and lessons learned.

### Output Format

```markdown
## แผนรับมือเหตุการณ์ (Incident Response Playbook)

### Incident Summary

- Finding: [title]
- Severity: CRITICAL
- Type: Credential Leak
- Status: Active Response

### Immediate Actions (First 30 minutes)

1. [ ] Rotate compromised credentials
2. [ ] Revoke active sessions using compromised creds
3. [ ] Enable enhanced logging on affected systems

### Containment (First 4 hours)

1. [ ] Audit access logs for unauthorized activity
2. [ ] Clean credential from git history
3. [ ] Scan for lateral movement

### Recovery (24-48 hours)

1. [ ] Deploy fixed code
2. [ ] Verify fix with re-scan
3. [ ] Update secret management policy

### Post-Incident

1. [ ] Document timeline
2. [ ] Root cause analysis
3. [ ] Update detection rules
4. [ ] Share lessons learned
```

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/incident-response.md` for IR framework details.
