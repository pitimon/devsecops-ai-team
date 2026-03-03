---
name: k8s-scan
description: Kubernetes cluster and manifest security scanning. Performs static analysis on K8s manifests (Deployments, Pods, RBAC, NetworkPolicy) and live CIS Benchmark assessment on running clusters using kube-bench, Trivy, Checkov, and custom Semgrep rules.
argument-hint: "[--target <path|cluster>] [--mode static|live|both]"
user-invocable: true
allowed-tools: ["Bash", "Read", "Glob", "Grep", "Agent"]
---

# Kubernetes Security Scanning

สแกนความปลอดภัยของ Kubernetes ทั้ง manifest แบบ static และ cluster แบบ live เพื่อตรวจหาปัญหาด้าน Pod Security, RBAC, Network Policy และ CIS Benchmark compliance

**Decision Loop**:

- **In-the-Loop** สำหรับ live cluster scanning — ต้องได้รับการอนุมัติจากผู้ใช้ก่อนเชื่อมต่อ cluster
- **On-the-Loop** สำหรับ static manifest scanning — AI วิเคราะห์อัตโนมัติ ผู้ใช้ตรวจสอบผลลัพธ์

## Agent Delegation

This skill delegates to `@agent-container-security` for Kubernetes analysis. For RBAC and access control findings, consult `@agent-access-control`.

## Reference

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/k8s-security-reference.md` for CIS Kubernetes Benchmark v1.9, Pod Security Standards, RBAC misconfiguration patterns, and Network Policy templates.

## Scanning Workflow

### 1. Target Discovery

ค้นหา Kubernetes manifest และ configuration files ในโปรเจกต์:

```bash
# Kubernetes manifests
Glob: **/deployment*.yml, **/deployment*.yaml, **/pod*.yml, **/pod*.yaml
Glob: **/service*.yml, **/service*.yaml, **/ingress*.yml, **/ingress*.yaml
Glob: **/statefulset*.yml, **/statefulset*.yaml, **/daemonset*.yml
Glob: **/cronjob*.yml, **/job*.yml

# RBAC definitions
Glob: **/role*.yml, **/role*.yaml, **/clusterrole*.yml
Glob: **/rolebinding*.yml, **/clusterrolebinding*.yml
Glob: **/serviceaccount*.yml

# Network and security policies
Glob: **/networkpolicy*.yml, **/podsecuritypolicy*.yml
Glob: **/poddisruptionbudget*.yml, **/limitrange*.yml
Glob: **/resourcequota*.yml

# Helm charts
Glob: **/Chart.yaml, **/values.yaml, **/templates/**/*.yaml

# Kustomize
Glob: **/kustomization.yaml, **/kustomization.yml

# Generic K8s directories
Glob: k8s/**/*.yaml, k8s/**/*.yml, kubernetes/**/*.yaml, manifests/**/*.yaml, deploy/**/*.yaml
```

### 2. Static Manifest Analysis (On-the-Loop)

วิเคราะห์ manifest โดยไม่ต้องเชื่อมต่อ cluster จริง:

#### 2.1 Custom Semgrep Rules

```bash
# Run custom K8s manifest rules
semgrep --config ${CLAUDE_PLUGIN_ROOT}/rules/k8s-manifest-rules.yml \
  --json --output k8s-semgrep.json <target_path>
```

ตรวจสอบ 8 patterns สำคัญ:

| Rule ID                    | Pattern                                  | Severity | CWE     |
| -------------------------- | ---------------------------------------- | -------- | ------- |
| `k8s-privileged-container` | `privileged: true`                       | high     | CWE-250 |
| `k8s-run-as-root`          | `runAsUser: 0` or missing `runAsNonRoot` | high     | CWE-250 |
| `k8s-host-network`         | `hostNetwork: true`                      | high     | CWE-269 |
| `k8s-no-resource-limits`   | missing `resources.limits`               | medium   | CWE-770 |
| `k8s-latest-tag`           | image with `:latest` or no tag           | medium   | CWE-829 |
| `k8s-no-readiness-probe`   | missing `readinessProbe`                 | low      | CWE-693 |
| `k8s-wildcard-rbac`        | `verbs: ["*"]` in Role/ClusterRole       | high     | CWE-269 |
| `k8s-default-namespace`    | `namespace: default` in production       | medium   | CWE-269 |

#### 2.2 Trivy Filesystem Scan

```bash
# Scan manifests for misconfigurations
trivy fs --scanners misconfig --severity HIGH,CRITICAL \
  --format json --output trivy-k8s.json <target_path>
```

#### 2.3 Checkov Scan

```bash
# Run Checkov on Kubernetes manifests
checkov -d <target_path> --framework kubernetes \
  --output json --output-file checkov-k8s.json

# Run Checkov on Helm charts
checkov -d <chart_path> --framework helm \
  --output json --output-file checkov-helm.json
```

### 3. Live Cluster Scanning (In-the-Loop)

สแกน cluster ที่กำลังรันอยู่ — **ต้องได้รับอนุมัติจากผู้ใช้ก่อนดำเนินการ**:

> **Safety Gate**: ก่อนรันคำสั่งใดๆ กับ live cluster ต้องแจ้งผู้ใช้ว่า:
>
> 1. จะเข้าถึง cluster ใด (context จาก kubeconfig)
> 2. จะรันเฉพาะคำสั่ง read-only เท่านั้น
> 3. ขอ confirmation จากผู้ใช้

#### 3.1 kube-bench (CIS Kubernetes Benchmark)

```bash
# Full CIS Benchmark assessment
docker run --rm --pid=host \
  -v ${KUBECONFIG:-~/.kube/config}:/root/.kube/config:ro \
  -v ./output:/output \
  aquasec/kube-bench:latest run --json > output/kube-bench.json

# Node-level checks only
docker run --rm --pid=host \
  aquasec/kube-bench:latest run --targets node --json > output/kube-bench-node.json

# Control plane checks
docker run --rm --pid=host \
  aquasec/kube-bench:latest run --targets master --json > output/kube-bench-master.json
```

#### 3.2 Trivy Kubernetes Scan

```bash
# Scan running cluster for vulnerabilities and misconfigurations
trivy k8s --report summary --severity HIGH,CRITICAL \
  --format json --output trivy-cluster.json cluster

# Scan specific namespace
trivy k8s --report summary --namespace production \
  --format json --output trivy-ns.json cluster
```

### 4. Finding Normalization

แปลงผลจากเครื่องมือต่างๆ ให้อยู่ในรูปแบบ Unified Finding Schema:

```bash
# kube-bench JSON -> normalized findings
# test_number -> rule_id (e.g., "kube-bench-1.1.1")
# status FAIL -> severity high, WARN -> severity medium, INFO -> severity low
# remediation -> suggestion

# Normalize all results
${CLAUDE_PLUGIN_ROOT}/runner/json-normalizer.sh k8s-semgrep.json > normalized-semgrep.json
${CLAUDE_PLUGIN_ROOT}/runner/json-normalizer.sh trivy-k8s.json > normalized-trivy.json
${CLAUDE_PLUGIN_ROOT}/runner/json-normalizer.sh checkov-k8s.json > normalized-checkov.json
```

### 5. Output

นำเสนอผลลัพธ์ในรูปแบบ bilingual template:

```markdown
## ผลการสแกน Kubernetes (Kubernetes Scan Results)

### สรุป (Summary)

- **Mode**: Static / Live / Both
- **Target**: <path or cluster context>
- **Manifests scanned**: N files
- **Total findings**: N (Critical: X, High: Y, Medium: Z, Low: W)
- **CIS Benchmark score**: X/Y checks passed (live mode only)

### ผลตามหมวดหมู่ (Findings by Category)

#### Pod Security

| Finding                 | Severity | File               | Line | CWE     |
| ----------------------- | -------- | ------------------ | ---- | ------- |
| Privileged container    | HIGH     | deploy/app.yaml    | 42   | CWE-250 |
| Missing resource limits | MEDIUM   | deploy/worker.yaml | 55   | CWE-770 |

#### RBAC

| Finding               | Severity | File              | Line | CWE     |
| --------------------- | -------- | ----------------- | ---- | ------- |
| Wildcard verbs        | HIGH     | rbac/role.yaml    | 12   | CWE-269 |
| cluster-admin binding | HIGH     | rbac/binding.yaml | 8    | CWE-269 |

#### Network Policy

| Finding              | Severity | Namespace  | CWE     |
| -------------------- | -------- | ---------- | ------- |
| No default deny      | MEDIUM   | production | CWE-269 |
| Missing egress rules | MEDIUM   | staging    | CWE-269 |

#### CIS Benchmark (Live Mode)

| Section       | Passed | Failed | Warn |
| ------------- | ------ | ------ | ---- |
| Control Plane | X      | Y      | Z    |
| etcd          | X      | Y      | Z    |
| Worker Nodes  | X      | Y      | Z    |
| Policies      | X      | Y      | Z    |

### คำแนะนำการแก้ไข (Remediation)

1. **Critical/High** — ต้องแก้ไขทันที พร้อมตัวอย่าง YAML ที่ถูกต้อง
2. **Medium** — วางแผนแก้ไขใน sprint ถัดไป
3. **Low** — ปรับปรุงตาม best practice
```

## Compliance Mapping

ผลการสแกน K8s สามารถ map กับ compliance frameworks ดังนี้:

- **CIS Kubernetes Benchmark v1.9** — โดยตรงจาก kube-bench
- **NIST SP 800-190** (Container Security) — Pod Security, image hardening
- **OWASP A05:2021** (Security Misconfiguration) — K8s misconfigs
- **OWASP A01:2021** (Broken Access Control) — RBAC issues
- **Thailand NCSA** (effective Sep 16, 2026) — infrastructure security controls

## Additional References

Load `${CLAUDE_PLUGIN_ROOT}/skills/references/container-hardening.md` for Docker and container-level security patterns.
Load `${CLAUDE_PLUGIN_ROOT}/skills/references/iac-security-patterns.md` for Infrastructure as Code scanning context.
Load `${CLAUDE_PLUGIN_ROOT}/skills/references/compliance-frameworks.md` for full compliance mapping details.
