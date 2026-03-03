# Architecture Reference

> Detailed architecture documentation for the **devsecops-ai-team** plugin.
> For the full project overview, see the [README](../README.md).

---

## Architecture Overview

```
      You (Claude Code)
           |
           +--- Skill commands (/sast-scan, /full-pipeline, ...)
           |
           +--- MCP tools (devsecops_scan, devsecops_gate, ...)   <-- v2.0
           |
           v
+------------------------------------------------------------------+
|                      18 AI Agents                                 |
|                                                                   |
|  +---------------+  +---------------+  +------------------------+ |
|  | Orchestrators |  |  Specialists  |  |  Experts + Core Team   | |
|  |  (3 agents)   |  |  (7 agents)   |  |     (8 agents)         | |
|  |               |  |               |  |                        | |
|  | devsecops-    |  | sast          |  | compliance-officer     | |
|  |   lead <------+--+ dast          |  | threat-modeler         | |
|  |   (router)    |  | sca           |  | vuln-triager           | |
|  | stack-        |  | container     |  | remediation-advisor    | |
|  |   analyst     |  | iac           |  | code-reviewer          | |
|  | team-         |  | secret        |  | incident-responder     | |
|  |   configurator|  | sbom          |  | report-generator       | |
|  |               |  |               |  | pipeline-guardian      | |
|  +---------------+  +---------------+  +------------------------+ |
+----------------------------+--------------------------------------+
                             | bash -> job-dispatcher.sh
                             v
+------------------------------------------------------------------+
|              Sidecar Runner (Alpine + Docker CLI)                 |
|      job-dispatcher.sh -> result-collector.sh -> normalize        |
|                  -> dedup-findings.sh -> format                   |
+--+------+------+------+------+------+-------+-------+-------+-------+-------+
   |      |      |      |      |      |       |       |       |       |
 +-v-+ +--v--++--v--++--v--++--v--++--v--++--v--++---v---++--v---++---v----+
 |Sem| |Grype||Trivy||Chek ||GitL || ZAP ||Syft ||Truf   ||Nucl  ||kube-  |
 |gre| |     ||     ||ov   ||eaks ||     ||     ||fleHog ||ei    ||bench  |
 |p  | | SCA || Con || IaC || Sec ||DAST ||SBOM || Sec   ||DAST  ||K8sCIS |
 +---+ +-----++-----++-----++-----++-----++-----++-------++------++-------+
              All tools run locally in Docker containers (11 total)
```

### How It Works

1. **คุณพิมพ์คำสั่ง** เช่น `/sast-scan` ใน Claude Code (หรือเรียกผ่าน MCP tool)
2. **Orchestrator** (`devsecops-lead`) วิเคราะห์ request แล้ว **MUST delegate** ไปยัง specialist ตาม routing table
3. **Specialist agent** ส่งงานผ่าน `job-dispatcher.sh` ไปยัง Docker container
4. **Tool** (เช่น Semgrep) รันใน container แล้วส่งผลกลับ
5. **json-normalizer.sh** แปลงผลเป็น Unified Finding Schema (severity mapped ถูกต้อง)
6. **dedup-findings.sh** รวมผลจากหลาย tools แล้วตัด duplicate ออก
7. **Expert agents** วิเคราะห์: จัดลำดับความสำคัญ, map compliance, แนะนำการแก้ไข
8. **Report generator** สร้างรายงานในรูปแบบที่ต้องการ (SARIF/JSON/Markdown/HTML/PDF/CSV/VEX/Dashboard)

### Full Pipeline Delegation Chain

เมื่อเรียก `/full-pipeline` ระบบจะ delegate ตามลำดับนี้:

```
1. @security-stack-analyst   -> ตรวจจับ tech stack
2. Scan Specialists (parallel):
   +-- @sast-specialist      -> ถ้ามี source code
   +-- @secret-scanner       -> เสมอ
   +-- @sca-specialist       -> ถ้ามี dependency files
   +-- @container-specialist -> ถ้ามี Dockerfile
   +-- @iac-specialist       -> ถ้ามี Terraform/K8s
   +-- @sbom-analyst         -> เสมอ
3. @vuln-triager             -> deduplicate + prioritize
4. @compliance-officer       -> map to OWASP/NIST/MITRE/NCSA/PDPA/SOC2/ISO27001
5. @remediation-advisor      -> fix guidance (HIGH+)
6. @report-generator         -> unified report
7. @pipeline-guardian        -> gate decision (PASS/FAIL)
```

### Decision Loop Model

การตัดสินใจแบ่งเป็น 3 ระดับตามความเสี่ยง:

```
  Out-of-Loop           On-the-Loop           In-the-Loop
  (AI autonomous)       (AI proposes)         (Human decides)
  +-----------+         +-----------+         +-----------+
  | /sast-scan|         |/full-pipe |         | /dast-scan|
  | /sca-scan |         |/compliance|         | /security |
  | /secret-  |         |/auto-fix  |         |   -gate   |
  |   scan    |         |/devsecops-|         | /incident-|
  | /container|         |   setup   |         |  response |
  | /iac-scan |         |           |         |           |
  | /sbom-gen |         |           |         |           |
  +-----------+         +-----------+         +-----------+
  Low risk               Medium risk           High risk
  No approval            AI proposes,          Human must
  needed                 human approves        decide
```
