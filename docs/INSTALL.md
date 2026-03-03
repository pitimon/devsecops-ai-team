# Installation Guide / คู่มือการติดตั้ง

## Standard Installation (แนะนำ)

ติดตั้งผ่าน Claude Code marketplace:

```bash
# Step 1: ลงทะเบียน marketplace (ดึง repo จาก GitHub)
claude plugin marketplace add pitimon/devsecops-ai-team

# Step 2: ติดตั้ง plugin
claude plugin install devsecops-ai-team@pitimon-devsecops
```

เปิด Claude Code session ใหม่ → plugin จะ load อัตโนมัติ พร้อมแสดง DevSecOps context

### ตรวจสอบว่าติดตั้งสำเร็จ

เปิด Claude Code แล้วพิมพ์ `/devsecops-setup` — ถ้าเห็น skill prompt แสดงว่าติดตั้งสำเร็จ

## Manual Installation (จาก local directory)

```bash
# Clone repo
git clone https://github.com/pitimon/devsecops-ai-team.git

# ลงทะเบียน marketplace จาก local path
claude plugin marketplace add ./devsecops-ai-team

# ติดตั้ง plugin
claude plugin install devsecops-ai-team@pitimon-devsecops
```

## Air-Gapped Installation (ไม่มี internet)

สำหรับ environment ที่ไม่สามารถเข้าถึง GitHub ได้:

1. ดาวน์โหลด release tarball จาก [GitHub Releases](https://github.com/pitimon/devsecops-ai-team/releases) บนเครื่องที่มี internet
2. คัดลอกไฟล์ไปยังเครื่อง air-gapped
3. แตกไฟล์และติดตั้ง:

```bash
tar xzf devsecops-ai-team-v3.0.1.tar.gz
claude plugin marketplace add ./devsecops-ai-team
claude plugin install devsecops-ai-team@pitimon-devsecops
```

4. Pre-pull Docker images (ต้องทำบนเครื่องที่มี internet แล้ว `docker save` / `docker load`):

```bash
# บนเครื่องที่มี internet
docker pull returntocorp/semgrep:latest
docker pull zricethezav/gitleaks:latest
docker pull anchore/grype:latest
docker pull aquasec/trivy:latest
docker pull bridgecrew/checkov:latest
docker pull ghcr.io/zaproxy/zaproxy:stable
docker pull anchore/syft:latest

# Save เป็นไฟล์
docker save returntocorp/semgrep zricethezav/gitleaks anchore/grype \
  aquasec/trivy bridgecrew/checkov ghcr.io/zaproxy/zaproxy anchore/syft \
  -o devsecops-tools.tar

# บนเครื่อง air-gapped
docker load -i devsecops-tools.tar
```

## Prerequisites / ข้อกำหนดเบื้องต้น

### Required (จำเป็น)

| Requirement        | Minimum | ตรวจสอบด้วย              |
| ------------------ | ------- | ------------------------ |
| **Docker Engine**  | 20.10+  | `docker --version`       |
| **Docker Compose** | v2.0+   | `docker compose version` |
| **Disk Space**     | 2 GB+   | `df -h .`                |
| **Claude Code**    | Latest  | `claude --version`       |

### Optional (ไม่บังคับ)

- **[claude-governance](https://github.com/pitimon/claude-governance)** — extended fitness functions + governance hooks
- **Git** — สำหรับ secret scanning ใน git history
- **Python 3.8+** — สำหรับ formatters (json-normalizer, sarif-formatter)

### ตรวจสอบ Prerequisites อัตโนมัติ

```bash
bash scripts/check-prerequisites.sh

# ตรวจสอบเครื่องมือเฉพาะ
bash scripts/check-prerequisites.sh --tool semgrep
bash scripts/check-prerequisites.sh --tool gitleaks
```

## Setting Up the Runner / ตั้งค่า Runner

### Minimal Mode (แนะนำสำหรับ Development)

ใช้ `docker run --rm` สำหรับแต่ละ scan — ไม่มี persistent containers:

```bash
bash scripts/install-runner.sh --mode minimal
```

- ใช้ RAM/CPU น้อย
- เหมาะสำหรับ development และ CI/CD
- Pull images เฉพาะตัวที่ใช้บ่อย (Semgrep, GitLeaks)

### Full Mode (สำหรับ Production / Heavy Use)

Persistent sidecar container พร้อม tool profiles:

```bash
bash scripts/install-runner.sh --mode full

# เปิด profile ที่ต้องการ
docker compose -f runner/docker-compose.yml --profile sast up -d      # Semgrep only
docker compose -f runner/docker-compose.yml --profile secret up -d    # GitLeaks only
docker compose -f runner/docker-compose.yml --profile all up -d       # ทุกเครื่องมือ
```

- scan เร็วขึ้น (ไม่ต้อง pull image ทุกครั้ง)
- เหมาะสำหรับ production environment ที่ scan บ่อย

### Verify Installation / ตรวจสอบการติดตั้ง

```bash
# ตรวจสอบ prerequisites
bash scripts/check-prerequisites.sh

# ทดสอบ normalizer กับ test fixtures
bash tests/test-runner.sh

# ทดสอบ formatters
bash tests/test-formatters.sh

# ตรวจสอบ normalizer (v2.0)
bash tests/test-normalizer.sh

# ตรวจสอบ MCP server (v2.0)
bash tests/test-mcp-server.sh

# ตรวจสอบ plugin structure (223 checks)
bash tests/validate-plugin.sh
```

## MCP Server Setup (v2.0)

MCP server ช่วยให้ MCP-compatible clients เรียกใช้ security scanning ได้โดยตรง:

```bash
# ติดตั้ง dependencies
cd mcp && npm install

# MCP server จะถูก load อัตโนมัติผ่าน .mcp.json เมื่อเปิด Claude Code
```

MCP tools ที่พร้อมใช้: `devsecops_scan`, `devsecops_results`, `devsecops_gate`, `devsecops_compliance`, `devsecops_status`

### ตรวจสอบ MCP

```bash
# ตรวจสอบ syntax
node --check mcp/server.mjs

# รัน MCP tests
bash tests/test-mcp-server.sh
```

## Installing Rules (Optional)

ติดตั้ง DevSecOps rules เข้า `~/.claude/rules/` เพื่อให้ทำงานในทุก Claude Code session:

```bash
bash scripts/install-rules.sh
```

Rules ที่ติดตั้ง:

- `devsecops.md` — DevSecOps fitness functions (extends governance.md)
- `container-security.md` — Container security rules

## Uninstallation / ถอนการติดตั้ง

```bash
# ถอน plugin
claude plugin uninstall devsecops-ai-team@pitimon-devsecops

# หยุดและลบ runner containers (ถ้าใช้ full mode)
docker compose -f runner/docker-compose.yml down -v

# ลบ Docker images (optional — ประหยัดเนื้อที่)
docker rmi returntocorp/semgrep anchore/grype aquasec/trivy \
  bridgecrew/checkov zricethezav/gitleaks ghcr.io/zaproxy/zaproxy anchore/syft

# ลบ rules (optional)
rm -f ~/.claude/rules/devsecops.md ~/.claude/rules/container-security.md
```

## Troubleshooting / แก้ปัญหา

ดู [TROUBLESHOOTING.md](TROUBLESHOOTING.md) สำหรับปัญหาที่พบบ่อย
