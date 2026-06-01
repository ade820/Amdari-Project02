# Day 8 Notes — K8s Hardening (part 2), OPA Gatekeeper, Falco, Terraform IaC

## Summary
Day 8 completed four pieces in one session: Kubernetes manifest hardening,
OPA Gatekeeper admission control, Falco runtime detection, and Terraform IaC
remediation. OPA Gatekeeper install (originally Step 11) was folded in here
since it had not been done earlier.

---

## Piece 1 — Kubernetes hardening (CK-05, CK-07, CK-08)
- **Resource limits (CK-05):** requests/limits added to all 5 deployments
  (services: 100m/128Mi req, 500m/256Mi lim; DBs: 100m/256Mi, 500m/512Mi).
- **Labels (CK-07):** app + team labels on all deployments (metadata + pod template).
- **NetworkPolicy (CK-08):** infra/kubernetes/base/networkpolicy.yaml — 12 policies:
  default-deny-all, DNS egress, Vault egress (8200), frontend→auth(5001)/transaction(5002),
  transaction→auth, services→own DB, DB ingress from own service only, frontend external ingress.
- Applied via `kubectl apply -k infra/kubernetes/base/`. All pods Running after rollout.

### Decision: base/ applied directly, no overlays/dev/
The PDF references `kubectl apply -k infra/kubernetes/overlays/dev/`. We apply
`base/` directly. Kustomize overlays add value for multi-environment config
(dev/staging/prod); with a single local cluster, a passthrough overlay would be
ceremony with no override content. Documented as a deliberate simplification.

### Environment limitation: NetworkPolicy not enforced locally
Docker Desktop's built-in Kubernetes uses a CNI that does NOT enforce
NetworkPolicy. The 12 policies apply cleanly and are correct, and OPA can verify
their presence, but they do not actually block traffic on this local cluster.
Enforcement requires a policy-aware CNI (Calico/Cilium) as on real EKS. This is
an environment limitation, not a policy error. The Vault-egress allow (port 8200)
is included so the injector works on an enforcing cluster.

---

## Piece 2 — OPA Gatekeeper (CK-04, CK-05, CK-06, CK-07)
- Installed via Helm into gatekeeper-system (cluster install, not committed).
- infra/kubernetes/opa/constraint-templates.yaml — 4 Rego templates:
  k8snoprivileged, k8snolatesttag, k8srequireresources, k8srequirelabels.
- infra/kubernetes/opa/constraints.yaml — 4 constraints scoped to Deployments
  in the secureflow namespace.
- **Result:** no-privileged 0, require-labels 0, require-resources 0 violations.
  Enforcement proven: a deliberately bad deployment (privileged + no labels +
  no limits) was REJECTED at admission citing all three constraints.

### Decision: no-latest-tag in dryrun (audit) mode
Our 3 service images still use :latest (digest pinning depends on Cosign-signed
digests from Stage 6, not yet done). A deny-mode no-latest-tag constraint would
reject our own deployments. Set to enforcementAction: dryrun — it audits and
reports the 3 :latest violations without blocking. Enforcement activates once
Cosign digests exist (Stage 6 / later). The other 3 constraints enforce (deny).

### Reproduction
`helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace`
then `kubectl apply -f infra/kubernetes/opa/constraint-templates.yaml` (wait for
CRDs) then `kubectl apply -f infra/kubernetes/opa/constraints.yaml`.

---

## Piece 3 — Falco runtime detection
- Installed via Helm into falco namespace, driver.kind=modern_ebpf.
- infra/kubernetes/falco/secureflow-rules.yaml — 4 custom rules scoped to the
  secureflow namespace: Shell Spawned, Sensitive File Read, Unexpected Outbound
  Connection, Package Manager Run.
- **All four triggered and captured** via kubectl exec:
  shell (sh -c), package manager (pip --version), outbound (python socket to
  8.8.8.8:53), sensitive file (cat /etc/passwd).

### eBPF driver note
The PDF warns of eBPF driver issues on local clusters. The modern_ebpf driver
loaded fine on the WSL2 kernel (6.6) under Docker Desktop — no driver problem.
Initial crashes were rule-syntax errors (an undefined macro, an unsupported
string operator on an IP field, an indentation slip), not the driver.

### Defense-in-depth note: /etc/shadow vs /etc/passwd
The PDF's sensitive-file trigger is `cat /etc/shadow`. On our hardened containers
(non-root, UID 1000), that returns Permission denied — the OS-level least-privilege
hardening blocks the read before Falco's open_read condition matches. We
demonstrated the rule via /etc/passwd (world-readable, so the open succeeds and
the rule fires). /etc/passwd is itself a legitimate reconnaissance target. This
shows two layers: least-privilege PREVENTED the shadow read, and Falco DETECTS
sensitive-file access — exactly the layered defense the engagement teaches.

---

## Piece 4 — Terraform IaC (IV-08, IV-09, IV-10)
Scan-only (no real AWS apply). Goal: zero CRITICAL Checkov findings.
- **IV-08 (IAM):** AdministratorAccess replaced with 3 scoped managed policies
  (AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly);
  wildcard inline policy scoped to s3:GetObject on the artifacts bucket only.
- **IV-09 (S3):** SSE (aws:kms), versioning, logging, public-access-block all
  four flags true — on both artifacts and audit-logs buckets.
- **IV-10 (EKS/subnets):** private subnets + NAT gateway added; EKS endpoint
  public access false, private access true; nodes moved to private subnets;
  KMS secrets encryption + control-plane logging added; wide-open SG replaced
  with VPC-CIDR-scoped SG.
- **RDS:** moved to private subnets, publicly_accessible false, storage encrypted
  (KMS), backups + deletion protection + final snapshot, performance insights,
  CloudWatch logs, IAM auth, multi-AZ.

### Result: zero CRITICAL (success metric met)
Checkov: 106 passed, 35 failed, 0 parsing errors. All IV-08/09/10 high-severity
findings cleared (no AdministratorAccess, no wildcard IAM, no public S3, no
public EKS endpoint, no public RDS). The 35 remaining failures are all LOW/MEDIUM
best-practice checks accepted for a scan-only module that never deploys:
- S3: cross-region replication (CKV_AWS_144), lifecycle config (CKV2_AWS_61),
  event notifications (CKV2_AWS_62), access logging on the log bucket, KMS-key-ARN
  detail (CKV_AWS_145), and the split public-access-block resource pattern
  (CKV_AWS_53/54/55/56 — a Checkov false-positive; the four block flags ARE true).
- RDS: enhanced monitoring (CKV_AWS_118), query logging (CKV2_AWS_30).
- VPC/SG: flow logs (CKV2_AWS_11), default-SG restriction (CKV2_AWS_12),
  egress 0.0.0.0/0 (CKV_AWS_382 — standard accepted outbound), SG descriptions.
The success metric is "zero CRITICAL," not "zero total." A realistic Terraform
tree fails dozens of best-practice checks even when well-written; these are
documented and accepted.

---

## Pipeline state at end of Day 8
- Stage 1 Gitleaks: GREEN
- Stage 3 Trivy image: GREEN
- Stage 4 Checkov (Terraform): zero CRITICAL (LOW/MED documented)
- Stage 4 Trivy K8s: privileged/root/resource findings remediated; HIGH residue
- Stage 2 SonarQube: red (BLOCKERs, AppSec-adjacent)
- Stage 5 gate: still marks Trivy/K8s HIGH as BLOCK — needs alignment with the
  CRITICAL-only policy when pursuing full-green (carried to Day 9/10).

## Carried forward
- Service-image digest pinning + no-latest-tag enforcement → after Cosign (Stage 6).
- Stage 5 gate-script HIGH-blocking inconsistency (align with documented policy).
- Prometheus + Grafana dashboard (Day 9), Loki, Cosign+SBOM (Stage 6), ZAP (Stage 7).
- NetworkPolicy enforcement only verifiable on a policy-aware CNI (not local).