# IaC Security Patterns Reference

# ความรู้อ้างอิงด้านรูปแบบความปลอดภัยของ Infrastructure as Code

> **Purpose / วัตถุประสงค์**: Domain knowledge for the IaC security agent to audit Terraform, CloudFormation, Kubernetes manifests, and cloud configurations. Covers CIS Benchmarks for major clouds, Terraform security patterns, Kubernetes hardening, common misconfigurations, and Checkov check categories.
>
> **Version**: 2.0 | **Last Updated**: 2026-03-01 | **Frameworks**: CIS Benchmark v3.0 (AWS), v2.1 (Azure), v2.0 (GCP), Checkov v3.2+, tfsec v1.28+

---

## 1. CIS Benchmarks for Cloud Providers

## CIS Benchmarks สำหรับผู้ให้บริการ Cloud

### 1.1 AWS CIS Benchmark v3.0.0 — Critical Controls

```
IDENTITY & ACCESS MANAGEMENT (Section 1):
  1.4   Ensure no root access key exists
  1.5   Ensure MFA enabled for root account
  1.7   Eliminate use of root for administrative tasks
  1.8   Ensure IAM password policy requires minimum 14 characters
  1.10  Ensure multi-factor authentication (MFA) for all IAM users with console access
  1.15  Ensure IAM users receive permissions only through groups/roles
  1.16  Ensure IAM policies are attached only to groups or roles
  1.17  Ensure a support role has been created for incident management
  1.20  Ensure access to AWSCloudShellFullAccess is restricted
  1.22  Ensure access keys unused for 45 days or more are disabled

STORAGE (Section 2):
  2.1.1  Ensure S3 bucket policy denies HTTP requests
  2.1.2  Ensure MFA Delete enabled on S3 buckets
  2.1.4  Ensure all S3 buckets have public access blocked
  2.2.1  Ensure EBS volume encryption is enabled by default
  2.3.1  Ensure RDS instances have encryption at rest enabled
  2.3.2  Ensure auto minor version upgrade is enabled for RDS
  2.3.3  Ensure RDS instances are not publicly accessible

LOGGING (Section 3):
  3.1   Ensure CloudTrail is enabled in all regions
  3.2   Ensure CloudTrail log file validation is enabled
  3.4   Ensure CloudTrail trails are integrated with CloudWatch Logs
  3.7   Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket
  3.9   Ensure VPC flow logging is enabled in all VPCs

NETWORKING (Section 4):
  4.1   Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
  4.2   Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
  4.3   Ensure default security group restricts all traffic
  4.4   Ensure routing tables for VPC peering are least-privilege
```

### 1.2 Azure CIS Benchmark v2.1.0 — Critical Controls

```
IDENTITY & ACCESS (Section 1):
  1.1.1  Ensure Security Defaults or Conditional Access is enabled
  1.1.4  Ensure MFA is enabled for all users
  1.2.1  Ensure trusted locations are defined for Conditional Access
  1.3    Ensure custom admin roles are used
  1.21   Ensure no custom subscription owner roles

SECURITY CENTER (Section 2):
  2.1.1  Ensure Microsoft Defender for Servers is set to On
  2.1.2  Ensure Microsoft Defender for App Services is set to On
  2.1.5  Ensure Microsoft Defender for Storage is set to On
  2.1.15 Ensure auto-provisioning of Log Analytics agent is enabled

STORAGE (Section 3):
  3.1   Ensure Storage Account requires HTTPS transport
  3.2   Ensure Storage Account default access is set to Deny
  3.7   Ensure public access level is disabled for storage accounts
  3.10  Ensure soft delete is enabled for Azure Storage
  3.15  Ensure Minimum TLS version is set to 1.2

NETWORKING (Section 4):
  4.1   Ensure Network Security Group flow logs are enabled
  4.2   Ensure NSG rules do not allow ingress from 0.0.0.0/0 to SSH (22)
  4.3   Ensure NSG rules do not allow ingress from 0.0.0.0/0 to RDP (3389)
  4.5   Ensure DDoS Protection is enabled
```

### 1.3 GCP CIS Benchmark v2.0.0 — Critical Controls

```
IDENTITY & ACCESS (Section 1):
  1.1   Ensure corporate login credentials are used
  1.4   Ensure service account has no admin privileges
  1.5   Ensure no service account has user-managed keys
  1.6   Ensure Cloud KMS keys are rotated within 90 days
  1.7   Ensure user-managed service account keys are rotated within 90 days
  1.15  Ensure API keys are restricted to specific APIs/hosts

LOGGING & MONITORING (Section 2):
  2.1   Ensure Cloud Audit Logging is configured properly
  2.2   Ensure log metric filter and alert for project ownership changes
  2.4   Ensure log metric filter and alert for IAM policy changes
  2.12  Ensure Cloud DNS logging is enabled for all VPC networks

NETWORKING (Section 3):
  3.1   Ensure default network does not exist
  3.6   Ensure SSH access is restricted from the internet
  3.7   Ensure RDP access is restricted from the internet
  3.8   Ensure VPC Flow Logs are enabled for every subnet
  3.10  Ensure firewall rules allow only specific ports

STORAGE (Section 5):
  5.1   Ensure Cloud Storage buckets are not publicly accessible
  5.2   Ensure Cloud Storage buckets have uniform access enabled
```

---

## 2. Terraform Security Patterns

## รูปแบบความปลอดภัยของ Terraform

### 2.1 Secure AWS S3 Bucket

```hcl
# Secure S3 bucket following CIS AWS Benchmark
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-${var.environment}"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Security    = "hardened"
  }
}

# Block all public access (CIS 2.1.4)
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption (CIS 2.1.1)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

# Enable versioning (CIS 2.1.2)
resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

# Enforce HTTPS only (CIS 2.1.1)
resource "aws_s3_bucket_policy" "enforce_https" {
  bucket = aws_s3_bucket.secure_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceHTTPS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.secure_bucket.arn,
        "${aws_s3_bucket.secure_bucket.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

# Enable access logging
resource "aws_s3_bucket_logging" "secure_bucket" {
  bucket        = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "s3-access-logs/${aws_s3_bucket.secure_bucket.id}/"
}

# Lifecycle policy
resource "aws_s3_bucket_lifecycle_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    id     = "transition-to-ia"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}
```

### 2.2 Secure AWS Security Group

```hcl
# Security group with least-privilege rules (CIS 4.1, 4.2)
resource "aws_security_group" "app_sg" {
  name_prefix = "app-sg-"
  description = "Security group for application tier"
  vpc_id      = var.vpc_id

  # No inline rules — use separate resources for clarity
  tags = {
    Name        = "app-security-group"
    Environment = var.environment
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Allow inbound HTTPS from ALB only
resource "aws_security_group_rule" "app_ingress_https" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb_sg.id
  security_group_id        = aws_security_group.app_sg.id
  description              = "Allow HTTPS from ALB"
}

# Allow outbound to specific endpoints only
resource "aws_security_group_rule" "app_egress_db" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.db_sg.id
  security_group_id        = aws_security_group.app_sg.id
  description              = "Allow PostgreSQL to database tier"
}

# ANTI-PATTERN: Never do this
# resource "aws_security_group_rule" "bad_rule" {
#   type              = "ingress"
#   from_port         = 0
#   to_port           = 65535
#   protocol          = "-1"
#   cidr_blocks       = ["0.0.0.0/0"]  # CIS VIOLATION
#   security_group_id = aws_security_group.app_sg.id
# }
```

### 2.3 Secure IAM Role (Least Privilege)

```hcl
# IAM role with least-privilege policy
resource "aws_iam_role" "app_role" {
  name = "app-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  max_session_duration = 3600  # 1 hour max

  tags = {
    Environment = var.environment
  }
}

# Scoped policy — only what the app needs
resource "aws_iam_role_policy" "app_policy" {
  name = "app-policy"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadS3"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      },
      {
        Sid      = "WriteCloudWatch"
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# ANTI-PATTERN: Never do this
# Action = ["*"]
# Resource = ["*"]
```

### 2.4 Terraform State Security

```hcl
# Secure remote state backend
terraform {
  backend "s3" {
    bucket         = "terraform-state-prod"
    key            = "infrastructure/terraform.tfstate"
    region         = "ap-southeast-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:ap-southeast-1:123456789:key/xxx"
    dynamodb_table = "terraform-locks"

    # Prevent accidental state exposure
    acl = "private"
  }
}

# State bucket security
resource "aws_s3_bucket_versioning" "state" {
  bucket = "terraform-state-prod"
  versioning_configuration { status = "Enabled" }
}
```

---

## 3. Kubernetes Security Manifests

## เทมเพลตความปลอดภัย Kubernetes

### 3.1 RBAC Least-Privilege Configuration

```yaml
# Service account with minimal permissions
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
  annotations:
    # EKS IRSA — map to AWS IAM role
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/app-role
automountServiceAccountToken: false
---
# Role with minimum required permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["app-secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io

# ANTI-PATTERNS to detect:
# - ClusterRoleBinding to cluster-admin
# - Wildcard verbs: ["*"] or resources: ["*"]
# - Binding to default service account
# - automountServiceAccountToken: true (default)
```

### 3.2 Admission Control — OPA Gatekeeper

```yaml
# Constraint template: require resource limits
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredresources
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredResources
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredresources
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container %v must have memory limits", [container.name])
        }
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container %v must have CPU limits", [container.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: require-resource-limits
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet", "DaemonSet"]
    namespaces: ["production", "staging"]
```

---

## 4. Common IaC Misconfigurations

## การตั้งค่าผิดพลาดที่พบบ่อยใน IaC

### 4.1 Severity-Ranked Misconfigurations

```
CRITICAL:
  - S3 bucket with public access enabled
  - Security group with 0.0.0.0/0 ingress on SSH/RDP
  - IAM policy with Action: "*", Resource: "*"
  - RDS instance publicly accessible
  - KMS key with open key policy
  - Terraform state stored unencrypted
  - Hard-coded secrets in Terraform variables
  - EKS/AKS/GKE cluster with public endpoint + no auth

HIGH:
  - S3 bucket without encryption at rest
  - CloudTrail not enabled in all regions
  - RDS without encryption at rest
  - EBS volumes not encrypted by default
  - VPC without flow logs
  - Security group with unrestricted egress
  - Missing WAF on public ALB/CloudFront
  - Container running as root in K8s
  - No network policies in K8s namespace

MEDIUM:
  - S3 bucket without versioning
  - CloudWatch log group without encryption
  - Missing backup configuration for databases
  - IAM users with inline policies (should use groups/roles)
  - Default VPC in use
  - Missing tags (Environment, Owner, CostCenter)
  - Pod without resource limits

LOW:
  - S3 bucket without lifecycle policy
  - Missing description on security group rules
  - EC2 instance without detailed monitoring
  - Missing log retention configuration
  - Terraform provider without version constraint
```

### 4.2 Detection Patterns for Each Cloud

```hcl
# AWS — Detect public S3 bucket
# Checkov: CKV_AWS_19, CKV_AWS_20, CKV_AWS_21, CKV_AWS_53, CKV_AWS_54, CKV_AWS_55
resource "aws_s3_bucket" "bad" {
  # ISSUE: Missing public access block
  # ISSUE: Missing encryption configuration
  # ISSUE: Missing versioning
}

# Azure — Detect insecure storage account
# Checkov: CKV_AZURE_2, CKV_AZURE_3, CKV_AZURE_33, CKV_AZURE_35, CKV_AZURE_36
resource "azurerm_storage_account" "bad" {
  # ISSUE: min_tls_version not set to "TLS1_2"
  # ISSUE: allow_nested_items_to_be_public = true
  # ISSUE: Missing network_rules block
  # ISSUE: enable_https_traffic_only not set to true (default changed in v3)
}

# GCP — Detect public bucket
# Checkov: CKV_GCP_28, CKV_GCP_29, CKV_GCP_62
resource "google_storage_bucket" "bad" {
  # ISSUE: uniform_bucket_level_access not enabled
  # ISSUE: Missing encryption (CMEK)
  # ISSUE: public_access_prevention not set to "enforced"
}
```

---

## 5. Checkov Check Categories

## หมวดหมู่การตรวจสอบของ Checkov

### 5.1 Checkov Overview (v3.2+)

```bash
# Run Checkov on Terraform
checkov -d . --framework terraform \
  --output sarif --output-file checkov.sarif \
  --compact --quiet

# Run on Kubernetes manifests
checkov -d ./k8s/ --framework kubernetes \
  --output sarif --output-file checkov-k8s.sarif

# Run on Dockerfile
checkov -f Dockerfile --framework dockerfile

# Run with custom policy
checkov -d . --external-checks-dir ./custom-policies/

# Skip specific checks
checkov -d . --skip-check CKV_AWS_18,CKV_AWS_21

# Check specific categories only
checkov -d . --check CKV_AWS_19,CKV_AWS_20,CKV_AWS_145
```

### 5.2 Key Check IDs by Category

```
AWS S3 Security:
  CKV_AWS_18  - S3 bucket access logging enabled
  CKV_AWS_19  - S3 bucket encryption enabled
  CKV_AWS_20  - S3 bucket not publicly readable
  CKV_AWS_21  - S3 bucket versioning enabled
  CKV_AWS_53  - S3 bucket public access block (BlockPublicAcls)
  CKV_AWS_54  - S3 bucket public access block (BlockPublicPolicy)
  CKV_AWS_55  - S3 bucket public access block (IgnorePublicAcls)
  CKV_AWS_56  - S3 bucket public access block (RestrictPublicBuckets)
  CKV_AWS_145 - S3 bucket KMS encryption

AWS IAM:
  CKV_AWS_40  - IAM policy not applied directly to users
  CKV_AWS_61  - IAM policy not overly permissive
  CKV_AWS_62  - IAM policy not allowing * actions
  CKV_AWS_63  - IAM policy not allowing * resources
  CKV_AWS_274 - IAM role trust policy restricts access
  CKV_AWS_288 - IAM policy does not use AWS managed AdministratorAccess

AWS Networking:
  CKV_AWS_23  - Security group has description
  CKV_AWS_24  - Security group does not allow ingress 0.0.0.0/0 to port 22
  CKV_AWS_25  - Security group does not allow ingress 0.0.0.0/0 to port 3389
  CKV_AWS_260 - Security group does not allow unrestricted ingress on all ports
  CKV_AWS_9   - VPC flow logging enabled

AWS Encryption:
  CKV_AWS_3   - EBS encryption enabled
  CKV_AWS_17  - RDS encryption enabled
  CKV_AWS_26  - SNS topic encrypted
  CKV_AWS_27  - SQS queue encrypted
  CKV_AWS_35  - CloudTrail log encryption enabled

Kubernetes:
  CKV_K8S_1   - Do not allow containers with added capabilities
  CKV_K8S_6   - Do not allow root containers
  CKV_K8S_8   - Liveness probe configured
  CKV_K8S_9   - Readiness probe configured
  CKV_K8S_10  - CPU requests set
  CKV_K8S_11  - CPU limits set
  CKV_K8S_12  - Memory requests set
  CKV_K8S_13  - Memory limits set
  CKV_K8S_14  - Image tag is fixed (not latest)
  CKV_K8S_20  - Containers run with AllowPrivilegeEscalation=false
  CKV_K8S_21  - Default namespace should not be used
  CKV_K8S_22  - Read-only filesystem for containers
  CKV_K8S_23  - Minimize admission of root containers
  CKV_K8S_28  - Minimize admission of containers with NET_RAW
  CKV_K8S_37  - Containers should not run with SYS_ADMIN capability
  CKV_K8S_38  - Service account token not auto-mounted
  CKV_K8S_43  - Image uses digest

Dockerfile:
  CKV_DOCKER_1  - Ensure non-root user
  CKV_DOCKER_2  - Ensure HEALTHCHECK exists
  CKV_DOCKER_3  - Do not use ADD
  CKV_DOCKER_4  - Do not use port 22
  CKV_DOCKER_5  - Do not use latest tag
  CKV_DOCKER_7  - Ensure FROM uses specific version
  CKV_DOCKER_8  - Ensure COPY --chown is used
  CKV_DOCKER_9  - Ensure APT is not used
  CKV_DOCKER_10 - Ensure secrets are not hardcoded
  CKV_DOCKER_11 - Ensure WORKDIR is set
```

### 5.3 Custom Checkov Policy Example

```python
# custom_policies/s3_lifecycle.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class S3LifecyclePolicy(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has lifecycle configuration"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_s3_bucket_lifecycle_configuration"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id,
                         categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        rules = conf.get("rule", [])
        if rules and len(rules) > 0:
            return CheckResult.PASSED
        return CheckResult.FAILED

check = S3LifecyclePolicy()
```

---

## 6. IaC Security Tool Comparison

## การเปรียบเทียบเครื่องมือตรวจสอบความปลอดภัย IaC

| Tool              | IaC Types                           | Cloud Coverage  | Custom Rules | Speed  |
| ----------------- | ----------------------------------- | --------------- | ------------ | ------ |
| Checkov v3.2+     | TF, CFN, K8s, ARM, Dockerfile, Helm | AWS, Azure, GCP | Python       | Fast   |
| tfsec v1.28+      | Terraform, CloudFormation           | AWS, Azure, GCP | Rego, YAML   | Fast   |
| Trivy v0.50+      | TF, CFN, K8s, Dockerfile, Helm      | AWS, Azure, GCP | Rego         | Fast   |
| KICS v2.0+        | TF, CFN, K8s, Docker, Ansible, ARM  | AWS, Azure, GCP | Rego         | Medium |
| Terrascan v1.19+  | TF, CFN, K8s, Dockerfile, Helm      | AWS, Azure, GCP | Rego         | Medium |
| Snyk IaC v1.1200+ | TF, CFN, K8s, ARM                   | AWS, Azure, GCP | Custom rules | Fast   |

### CI/CD Integration

```yaml
# .github/workflows/iac-security.yml
name: IaC Security
on:
  pull_request:
    paths:
      - "terraform/**"
      - "k8s/**"
      - "Dockerfile*"

jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Checkov scan
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: terraform/
          framework: terraform
          output_format: cli,sarif
          output_file_path: console,checkov.sarif
          soft_fail: false
          skip_check: CKV_AWS_18 # Suppress known exceptions

      - name: Trivy IaC scan
        uses: aquasecurity/trivy-action@0.20.0
        with:
          scan-type: config
          scan-ref: .
          format: sarif
          output: trivy-iac.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
```

---

## 7. Quick Reference — IaC Security Checklist

## อ้างอิงด่วน — รายการตรวจสอบความปลอดภัย IaC

```
TERRAFORM:
  [ ] Provider version pinned with ~> constraint
  [ ] State stored in encrypted remote backend with locking
  [ ] No secrets in .tf files or terraform.tfvars (use vault/SSM)
  [ ] All resources tagged (Environment, Owner, ManagedBy)
  [ ] Security groups use specific CIDR, not 0.0.0.0/0
  [ ] IAM policies follow least-privilege (no * actions/resources)
  [ ] Encryption enabled for all storage (S3, EBS, RDS, DynamoDB)
  [ ] Logging enabled (CloudTrail, VPC Flow, S3 access logs)
  [ ] Checkov/tfsec passes with 0 CRITICAL/HIGH findings

KUBERNETES:
  [ ] Pod Security Standards: restricted enforcement
  [ ] RBAC: No ClusterRoleBinding to cluster-admin for apps
  [ ] Network policies: default-deny + explicit allow
  [ ] Secrets: External secrets operator, not base64 in manifests
  [ ] Images: Pinned by digest, from trusted registry
  [ ] Resources: Limits set for CPU, memory, ephemeral-storage
  [ ] Security context: Non-root, read-only FS, drop ALL caps
  [ ] Service accounts: Dedicated per app, no auto-mount token

GENERAL:
  [ ] Git hooks run IaC scan pre-commit
  [ ] PR gate blocks merge on CRITICAL/HIGH findings
  [ ] Drift detection monitors deployed vs declared state
  [ ] Policy-as-code (OPA/Sentinel) enforces org standards
  [ ] Modules sourced from verified registry with pinned version
```
