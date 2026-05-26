# SecureFlow — Master Findings Table (End of Week 1)

Aggregation of all detections produced by the four scanners in Stages 1–4.
Each finding maps to a vulnerability ID from VULNERABILITIES.md where possible.

Owner column distinguishes:
- **DevSecOps** — I remediate this in Week 2
- **AppSec** — Detected and routed via PR comment, not fixed by me

---

## Stage 1 — Gitleaks (secrets)

21 leaks across full git history.

| Finding | File | Line | Severity | Catalogued ID | Owner |
|---------|------|------|----------|---------------|-------|
| AWS_ACCESS_KEY_ID (***REMOVED***) | .env | 6 | CRITICAL | IV-04 | DevSecOps |
| AWS_SECRET_ACCESS_KEY (wJalrXUtnFEM...) | .env | 7 | CRITICAL | IV-04 | DevSecOps |
| SECRET_KEY=***REMOVED*** | .env | 11 | CRITICAL | IV-04, AV-07 | DevSecOps + AppSec |
| SESSION_SECRET=***REMOVED*** | .env | 12 | CRITICAL | IV-04, FV-03 | DevSecOps + AppSec |
| DB_PASSWORD=***REMOVED*** | .env | 15 | CRITICAL | IV-04 | DevSecOps |
| POSTGRES_PASSWORD=***REMOVED*** | .env | 16 | CRITICAL | IV-04 | DevSecOps |
| SONAR_TOKEN=squ_a1b2... | .env | 19 | CRITICAL | IV-04 | DevSecOps |
| POSTGRES_PASSWORD=***REMOVED*** | docker-compose.yml | 18 | CRITICAL | IV-01, IV-03 | DevSecOps |
| POSTGRES_PASSWORD=***REMOVED*** | docker-compose.yml | 30 | CRITICAL | IV-01, IV-03 | DevSecOps |
| DB_PASSWORD=***REMOVED*** | docker-compose.yml | 44 | CRITICAL | IV-01, IV-03 | DevSecOps |
| JWT_SECRET=***REMOVED*** | docker-compose.yml | 45 | CRITICAL | AV-07, IV-03 | DevSecOps + AppSec |
| DB_PASSWORD=***REMOVED*** | docker-compose.yml | 58 | CRITICAL | IV-01, IV-03 | DevSecOps |
| SESSION_SECRET=***REMOVED*** | docker-compose.yml | 69 | CRITICAL | FV-03, IV-03 | DevSecOps + AppSec |
| JWT_SECRET="***REMOVED***" | infra/kubernetes/base/configmap.yaml | 9 | CRITICAL | CK-09 | DevSecOps |
| SESSION_SECRET="***REMOVED***" | infra/kubernetes/base/configmap.yaml | 10 | CRITICAL | CK-09 | DevSecOps |
| AUTH_DB_PASSWORD="***REMOVED***" | infra/kubernetes/base/configmap.yaml | 11 | CRITICAL | CK-09 | DevSecOps |
| TX_DB_PASSWORD="***REMOVED***" | infra/kubernetes/base/configmap.yaml | 12 | CRITICAL | CK-09 | DevSecOps |
| db_password = "postgres" | infra/terraform/main.tf | 66 | CRITICAL | IV-01-adjacent | DevSecOps |
| SECRET_KEY hardcoded fallback | services/auth-service/app.py | 15 | CRITICAL | AV-07 | AppSec |
| app.secret_key hardcoded fallback | services/frontend/app.py | 14 | CRITICAL | FV-03-adjacent | AppSec |

**Gate behaviour:** All findings hard-fail Stage 1 (no severity gradient for secrets).

---

## Stage 2 — SonarQube SAST

17 issues total. 3 BLOCKER (hard-fail), 14 MAJOR (would route).

| Finding | File | Line | Severity | Catalogued ID | Owner |
|---------|------|------|----------|---------------|-------|
| App binds to 0.0.0.0 | services/auth-service/app.py | 162 | BLOCKER | NEW (not in index) | AppSec |
| App binds to 0.0.0.0 | services/frontend/app.py | 185 | BLOCKER | NEW | AppSec |
| App binds to 0.0.0.0 | services/transaction-service/app.py | 201 | BLOCKER | NEW | AppSec |
| Hardcoded credential ("password") | services/auth-service/app.py | 22 | MAJOR | AV-07 | AppSec |
| Hardcoded credential ("password") | services/transaction-service/app.py | 19 | MAJOR | IV-01-adjacent | AppSec |
| pip install without --only-binary :all: | services/*/Dockerfile (×3) | 7 | MAJOR | NEW | DevSecOps |
| Dependencies without locked versions | services/*/Dockerfile (×3) | 7 | MAJOR | NEW | DevSecOps |
| Specify HTTP methods on route (×5) | services/frontend/app.py + others | various | MAJOR | TV-06-adjacent | AppSec |
| MD5 weak hashing | services/auth-service/app.py | 32 | (Hotspot) | AV-05 | AppSec |

**Gate behaviour:** Hard-fail only on BLOCKER/CRITICAL; MAJOR/MINOR route to AppSec
via Day-5 PR comment. 3 BLOCKERs triggered hard-fail today.

**Not detected by SonarCloud free tier:** AV-01, AV-02 (SQLi taint analysis is commercial-only),
AV-04 (no SAST tool detects "missing rate limit"), AV-06 (no SAST tool detects
"missing role check"), AV-08 (error-leak rule not in free tier).

---

## Stage 3 — Trivy (container CVEs)

3 CRITICAL + ~32 HIGH per service image. All three services hard-fail.

| Service | CRITICAL | HIGH | Catalogued ID | Owner |
|---------|----------|------|---------------|-------|
| auth-service | 3 | 30 | CK-01 | DevSecOps |
| transaction-service | 3 | 33 | CK-01 | DevSecOps |
| frontend | 3 | 33 | CK-01 | DevSecOps |

The 3 CRITICALs are identical across services — all CVE-2026-31789 in OpenSSL,
inherited from python:3.9-slim base image. Variation in HIGH counts is due to
per-service pip dependencies (Werkzeug 2.2.2 pin, psycopg2-binary, PyJWT, requests).

**Gate behaviour:** Hard-fail on CRITICAL or HIGH. All 3 services failed.

---

## Stage 4 part 1 — Trivy K8s misconfiguration

16 HIGH findings, 0 CRITICAL.

| Trivy Rule | Description | Files affected | Catalogued ID | Owner |
|------------|-------------|----------------|---------------|-------|
| KSV-0017 | privileged: true | auth, frontend, transaction (×3) | CK-04 | DevSecOps |
| KSV-0014 | readOnlyRootFilesystem not set | All 5 deployment files (×5) | NEW | DevSecOps |
| KSV-0118 | default security context | All 5 deployment files (×7) | CK-04-adjacent | DevSecOps |
| KSV-0109 | secrets in ConfigMap | base/configmap.yaml | CK-09 | DevSecOps |

**Filtered out at LOW/MEDIUM (would soft-fail and route):**
- KSV-0011/15/16/18 (resource limits) — CK-05
- KSV-0013 (no image tag) — CK-06
- KSV-0020/21/105 (run as non-root) — CK-02
- KSV-0001 (allowPrivilegeEscalation) — CK-04
- KSV-0125 (untrusted registry)

**Not detected:** CK-07 (missing labels). Requires OPA Gatekeeper (Day-7) or
Polaris — Trivy doesn't enforce label policy.

---

## Stage 4 part 2 — Checkov Terraform IaC

72 failures, 0 passes.

| Catalogued | Checkov rules | Module | Count | Owner |
|------------|---------------|--------|-------|-------|
| IV-08 | CKV_AWS_274 (AdministratorAccess), CKV_AWS_62, CKV_AWS_63, CKV_AWS_286/7/8/9/90, CKV_AWS_355, CKV2_AWS_40 | iam, eks | 10 | DevSecOps |
| IV-09 | CKV_AWS_53/54/55/56 (public access blocks), CKV_AWS_18 (logging), CKV_AWS_21 (versioning), CKV_AWS_144 (replication), CKV_AWS_145 (KMS), CKV2_AWS_6/61/62 | s3 | 22 | DevSecOps |
| IV-10 | CKV_AWS_38/39 (public endpoint), CKV_AWS_130 (public-IP subnets), CKV_AWS_58, CKV_AWS_37, CKV_AWS_339 | eks, vpc | 7 | DevSecOps |
| NEW | RDS hardening (CKV_AWS_16/17/118/129/157/161/226/293/353, CKV2_AWS_30/60) | rds | 18 | DevSecOps |
| NEW | VPC security groups (CKV_AWS_23/24/25/260/382, CKV2_AWS_5/12) | vpc | 8 | DevSecOps |
| NEW | VPC flow logging (CKV2_AWS_11) | vpc | 1 | DevSecOps |
| NEW | Misc S3 (lifecycle, replication, etc.) | s3 | 6 | DevSecOps |

**Gate behaviour:** Hard-fail on any failure (Checkov has no severity gradient).

---

## Summary

| Stage | Total findings | Hard-fail count | Routed | Catalogued IDs hit |
|-------|----------------|-----------------|--------|--------------------|
| 1 (Gitleaks) | 21 | 21 | 0 | IV-01, IV-03, IV-04, AV-07, FV-03, CK-09 |
| 2 (SonarQube) | 17 | 3 | 14 | AV-05 (Hotspot), AV-07 |
| 3 (Trivy image) | 9 CRITICAL + 96 HIGH across 3 services | All | 0 | CK-01 |
| 4 part 1 (Trivy K8s) | 16 HIGH | 16 | many (LOW/MEDIUM not in gate) | CK-04, CK-09 (+ adjacent) |
| 4 part 2 (Checkov) | 72 | 72 | 0 | IV-08, IV-09, IV-10 + 33 extras |

**Catalogued findings NOT detected by any scanner:**
- AV-01, AV-02 (SQLi) — SonarCloud free tier lacks commercial taint rules
- AV-04, AV-06 (missing controls) — Not SAST-detectable by any tool
- AV-08 (error leak) — SonarCloud free tier coverage gap
- CK-07 (missing labels) — Requires OPA Gatekeeper, not Trivy

**Detection coverage:** Of the 26 catalogued IDs (8 AV + 7 TV + 6 FV + 10 IV + 9 CK),
the Stages 1–4 pipeline detects approximately 17 (~65%). The remaining 9 are
either inherently not SAST/SCA-detectable (AV-04, AV-06, TV-* runtime exploits)
or require Stage 7 (DAST, OWASP ZAP) or admission-control tooling (Day-7 OPA).

The Day-5 security gate policy will document these coverage limitations
explicitly. The AppSec team's manual code review checklist must address them.
