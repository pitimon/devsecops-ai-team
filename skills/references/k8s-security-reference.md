# Kubernetes Security Reference

# ความรู้อ้างอิงด้านความปลอดภัย Kubernetes

> **Purpose / วัตถุประสงค์**: Domain knowledge for Kubernetes security scanning — CIS Benchmark assessment, Pod Security Standards enforcement, RBAC misconfiguration detection, and Network Policy validation. Used by the `/k8s-scan` skill for both static manifest analysis and live cluster scanning.
>
> **Version**: 1.0 | **Last Updated**: 2026-03-03 | **Standards**: CIS Kubernetes Benchmark v1.9, Kubernetes v1.30, Pod Security Standards v1.30

---

## 1. CIS Kubernetes Benchmark v1.9

## มาตรฐาน CIS Kubernetes Benchmark v1.9

### 1.1 Control Plane Components (Section 1)

| Control ID | Description                                           | Level | Severity |
| ---------- | ----------------------------------------------------- | ----- | -------- |
| 1.1.1      | Ensure API server pod spec permissions are set        | L1    | HIGH     |
| 1.1.2      | Ensure API server pod spec ownership is set           | L1    | HIGH     |
| 1.2.1      | Ensure anonymous-auth is not enabled                  | L1    | CRITICAL |
| 1.2.2      | Ensure --token-auth-file is not set                   | L1    | HIGH     |
| 1.2.3      | Ensure --DenyServiceExternalIPs is not set            | L1    | MEDIUM   |
| 1.2.5      | Ensure --kubelet-https is enabled                     | L1    | HIGH     |
| 1.2.6      | Ensure --kubelet-certificate-authority is set         | L1    | HIGH     |
| 1.2.7      | Ensure --authorization-mode includes Node,RBAC        | L1    | CRITICAL |
| 1.2.9      | Ensure admission control EventRateLimit is set        | L1    | MEDIUM   |
| 1.2.10     | Ensure AlwaysAdmit admission controller is disabled   | L1    | CRITICAL |
| 1.2.11     | Ensure AlwaysPullImages admission controller is set   | L2    | MEDIUM   |
| 1.2.13     | Ensure ServiceAccount admission controller is set     | L1    | HIGH     |
| 1.2.14     | Ensure NamespaceLifecycle admission controller is set | L1    | MEDIUM   |
| 1.2.16     | Ensure NodeRestriction admission controller is set    | L1    | HIGH     |
| 1.2.19     | Ensure --audit-log-path is set                        | L1    | HIGH     |
| 1.2.20     | Ensure --audit-log-maxage is set to 30 or more        | L1    | MEDIUM   |
| 1.2.22     | Ensure --audit-log-maxsize is set to 100 or more      | L1    | MEDIUM   |

### 1.2 etcd (Section 2)

| Control ID | Description                                   | Level | Severity |
| ---------- | --------------------------------------------- | ----- | -------- |
| 2.1        | Ensure --cert-file and --key-file are set     | L1    | CRITICAL |
| 2.2        | Ensure --client-cert-auth is set to true      | L1    | CRITICAL |
| 2.3        | Ensure --auto-tls is not set to true          | L1    | HIGH     |
| 2.4        | Ensure --peer-cert-file and --peer-key-file   | L1    | HIGH     |
| 2.5        | Ensure --peer-client-cert-auth is set to true | L1    | HIGH     |
| 2.6        | Ensure --peer-auto-tls is not set to true     | L1    | HIGH     |
| 2.7        | Ensure unique CA for etcd                     | L2    | MEDIUM   |

### 1.3 Worker Nodes (Section 4)

| Control ID | Description                                      | Level | Severity |
| ---------- | ------------------------------------------------ | ----- | -------- |
| 4.1.1      | Ensure kubelet service file permissions 600      | L1    | HIGH     |
| 4.1.2      | Ensure kubelet service file ownership root:root  | L1    | HIGH     |
| 4.2.1      | Ensure --anonymous-auth is set to false          | L1    | CRITICAL |
| 4.2.2      | Ensure --authorization-mode is not AlwaysAllow   | L1    | CRITICAL |
| 4.2.3      | Ensure --client-ca-file is set                   | L1    | HIGH     |
| 4.2.4      | Ensure --read-only-port is set to 0              | L1    | HIGH     |
| 4.2.6      | Ensure --protect-kernel-defaults is set to true  | L1    | MEDIUM   |
| 4.2.10     | Ensure --rotate-certificates is not set to false | L1    | MEDIUM   |
| 4.2.13     | Ensure TLS cipher suites are configured          | L1    | MEDIUM   |

### 1.4 Policies (Section 5)

| Control ID | Description                                           | Level | Severity |
| ---------- | ----------------------------------------------------- | ----- | -------- |
| 5.1.1      | Ensure cluster-admin role is only used when required  | L1    | CRITICAL |
| 5.1.2      | Minimize access to secrets                            | L1    | HIGH     |
| 5.1.3      | Minimize wildcard use in Roles and ClusterRoles       | L1    | HIGH     |
| 5.1.5      | Ensure default service accounts are not actively used | L1    | MEDIUM   |
| 5.1.6      | Ensure Service Account Tokens are not auto-mounted    | L1    | MEDIUM   |
| 5.2.1      | Ensure Privileged containers are not allowed          | L1    | CRITICAL |
| 5.2.2      | Ensure hostPID is not allowed                         | L1    | HIGH     |
| 5.2.3      | Ensure hostIPC is not allowed                         | L1    | HIGH     |
| 5.2.4      | Ensure hostNetwork is not allowed                     | L1    | HIGH     |
| 5.2.5      | Ensure allowPrivilegeEscalation is set to false       | L1    | HIGH     |
| 5.2.6      | Ensure root containers are not allowed                | L2    | HIGH     |
| 5.2.7      | Ensure NET_RAW capability is not allowed              | L1    | MEDIUM   |
| 5.2.8      | Ensure added capabilities are minimized               | L1    | MEDIUM   |
| 5.2.9      | Ensure assigned capabilities are limited              | L2    | MEDIUM   |
| 5.3.1      | Ensure default deny NetworkPolicy for all namespaces  | L1    | HIGH     |
| 5.7.1      | Create administrative boundaries between namespaces   | L1    | MEDIUM   |
| 5.7.4      | Ensure default namespace is not used                  | L2    | MEDIUM   |

---

## 2. Pod Security Standards (PSS)

## มาตรฐานความปลอดภัย Pod (PSS)

Kubernetes v1.25+ ใช้ Pod Security Admission แทน PodSecurityPolicy ที่ deprecated แล้ว โดยมี 3 ระดับ:

### 2.1 Privileged (ไม่จำกัด — หลีกเลี่ยงใน production)

ไม่มีข้อจำกัดใดๆ ใช้สำหรับ system-level workloads เช่น CNI, storage drivers, logging agents ที่ต้องการ host access

### 2.2 Baseline (จำกัดขั้นต่ำ — ป้องกัน known privilege escalations)

```yaml
# Controls enforced by Baseline profile:
# - No privileged containers
# - No hostProcess
# - No hostNetwork, hostPID, hostIPC
# - No hostPath volumes (specific paths only)
# - No hostPort (or limited range)
# - No ALL/SYS_ADMIN capabilities added
# - No /proc mount type other than Default
# - Seccomp profile not set to Unconfined
# - No Apparmor override to unconfined
# - No SELinux type other than allowed
# - No sysctls outside safe set
```

### 2.3 Restricted (Hardened — production best practices)

```yaml
# Restricted = Baseline + these additional controls:
# - Must run as non-root (runAsNonRoot: true)
# - Seccomp profile must be RuntimeDefault or Localhost
# - ALL capabilities must be dropped
# - Only NET_BIND_SERVICE may be added
# - Volume types limited to: configMap, csi, downwardAPI,
#   emptyDir, ephemeral, persistentVolumeClaim, projected, secret
# - allowPrivilegeEscalation must be false
```

### 2.4 Enforcement via Namespace Labels

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # enforce = reject pods that violate
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.30
    # audit = log violations
    pod-security.kubernetes.io/audit: restricted
    # warn = show warnings to users
    pod-security.kubernetes.io/warn: restricted
```

### 2.5 Compliant Pod Example (Restricted)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: registry.example.com/app:v1.0.0@sha256:abcdef...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: 500m
          memory: 256Mi
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
        initialDelaySeconds: 10
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
        initialDelaySeconds: 5
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 50Mi
```

---

## 3. RBAC Misconfigurations

## การกำหนดค่า RBAC ที่ผิดพลาด

### 3.1 Wildcard Verbs (CWE-269: Improper Privilege Management)

```yaml
# BAD — wildcard grants all permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-permissive
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]

# GOOD — least privilege principle
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
```

### 3.2 cluster-admin Binding (CWE-269)

```yaml
# BAD — binding cluster-admin to a service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default

# GOOD — minimal role with namespace scope
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: production
```

### 3.3 Default Service Account Misuse (CWE-269)

```yaml
# BAD — using default SA with auto-mounted token
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  # serviceAccountName defaults to "default"
  # automountServiceAccountToken defaults to true
  containers:
    - name: app
      image: myapp:latest

# GOOD — dedicated SA with token disabled
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false
  containers:
    - name: app
      image: registry.example.com/myapp:v1.0.0@sha256:abc123...
```

### 3.4 Common RBAC Anti-Patterns

```
CRITICAL:
  - ClusterRoleBinding to cluster-admin for application SA
  - Wildcard verbs ["*"] on any resource
  - Wildcard resources ["*"] on any verb
  - Secrets access (get/list) without justification
  - Impersonate permission on users/groups

HIGH:
  - RoleBinding in kube-system namespace for non-system accounts
  - create/update/patch on Roles/ClusterRoles (privilege escalation)
  - create on pods/exec (container escape risk)
  - create on serviceaccounts/token (token minting)

MEDIUM:
  - Using default service account for workloads
  - automountServiceAccountToken: true without need
  - Broad namespace access via ClusterRole instead of Role
```

---

## 4. Network Policy Patterns

## รูปแบบ Network Policy

### 4.1 Default Deny All (CWE-269)

ทุก namespace ควรเริ่มต้นด้วย default deny policy:

```yaml
# Default deny all ingress traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress

---
# Default deny all egress traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress

---
# Allow DNS egress (required for service discovery)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### 4.2 Namespace Isolation

```yaml
# Allow traffic only within same namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: namespace-isolation
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
```

### 4.3 Application-Specific Policy

```yaml
# Allow ingress from specific source + egress to specific destination
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress
        - podSelector:
            matchLabels:
              app: gateway
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    # DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

---

## 5. Common CWEs in Kubernetes

## CWE ที่พบบ่อยใน Kubernetes

| CWE     | Name                                   | K8s Context                                                  | Severity |
| ------- | -------------------------------------- | ------------------------------------------------------------ | -------- |
| CWE-250 | Execution with Unnecessary Privileges  | Privileged containers, running as root, excess capabilities  | HIGH     |
| CWE-269 | Improper Privilege Management          | Wildcard RBAC, cluster-admin binding, missing Network Policy | HIGH     |
| CWE-770 | Allocation of Resources Without Limits | Missing resource limits, no LimitRange, no ResourceQuota     | MEDIUM   |
| CWE-829 | Inclusion of Untrusted Functionality   | `:latest` image tag, unverified base images, unsigned images | MEDIUM   |
| CWE-693 | Protection Mechanism Failure           | Missing readiness/liveness probes, no seccomp, no AppArmor   | LOW      |
| CWE-284 | Improper Access Control                | Default SA token auto-mount, hostPath volumes, hostNetwork   | HIGH     |
| CWE-311 | Missing Encryption of Sensitive Data   | etcd unencrypted, Secrets not encrypted at rest              | HIGH     |
| CWE-778 | Insufficient Logging                   | Missing audit-log-path, audit policy not configured          | MEDIUM   |

---

## 6. Quick Reference — K8s Security Checklist

## อ้างอิงด่วน — รายการตรวจสอบความปลอดภัย Kubernetes

```
CLUSTER CONFIGURATION:
  [ ] API server anonymous-auth disabled
  [ ] API server authorization-mode includes Node,RBAC
  [ ] etcd encrypted with TLS (cert-file + key-file)
  [ ] Audit logging enabled (audit-log-path set)
  [ ] Admission controllers configured (NodeRestriction, PodSecurity)
  [ ] kubelet anonymous-auth disabled
  [ ] kubelet read-only-port set to 0

RBAC:
  [ ] No wildcard verbs or resources in Roles/ClusterRoles
  [ ] cluster-admin used only for break-glass scenarios
  [ ] Default service accounts not used by workloads
  [ ] automountServiceAccountToken: false where not needed
  [ ] Secrets access limited to required service accounts
  [ ] No cross-namespace ClusterRoleBindings for app accounts

POD SECURITY:
  [ ] Pod Security Standards enforced (Restricted for production)
  [ ] runAsNonRoot: true on all production workloads
  [ ] allowPrivilegeEscalation: false
  [ ] capabilities: drop ALL, add only NET_BIND_SERVICE if needed
  [ ] readOnlyRootFilesystem: true
  [ ] seccompProfile: RuntimeDefault or stricter
  [ ] No hostNetwork, hostPID, hostIPC
  [ ] Resource limits set (CPU, memory, ephemeral-storage)
  [ ] Images pinned by digest, no :latest tag
  [ ] Liveness and readiness probes defined

NETWORK:
  [ ] Default deny NetworkPolicy in every namespace
  [ ] Namespace isolation policies in place
  [ ] Application-specific ingress/egress policies
  [ ] DNS egress allowed explicitly
  [ ] No unnecessary external egress

SECRETS:
  [ ] Secrets encrypted at rest (EncryptionConfiguration)
  [ ] External secret manager integration (Vault, AWS SM, GCP SM)
  [ ] No secrets in environment variables (use volumes or CSI driver)
  [ ] Secret rotation policy in place
```
