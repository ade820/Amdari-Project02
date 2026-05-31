# SecureFlow Security Gate Policy

**Owner:** DevSecOps Engineering
**Status:** Active (Week 1, Stage 5)
**Applies to:** All pull requests and pushes to `main` in Amdari-Project02

---

## 1. Purpose

This document defines how the SecureFlow CI/CD security gate (Stage 5)
evaluates findings from the upstream scanners (Stages 1–4) and decides
whether to block or allow a change. It also defines who owns each class of
finding and how findings that are not the pipeline's responsibility are
handed off.

---

## 2. Scanner ownership matrix

| Stage | Scanner | Detects | Owner | Gate stance |
|-------|---------|---------|-------|-------------|
| 1 | Gitleaks | Committed secrets | DevSecOps | Hard-fail on any finding |
| 2 | SonarCloud SAST | Application code vulnerabilities | **AppSec** | Hard-fail on BLOCKER/CRITICAL; route the rest |
| 3 | Trivy (image) | Container CVEs | DevSecOps | Hard-fail on CRITICAL/HIGH |
| 4a | Trivy (config) | K8s misconfigurations | DevSecOps | Hard-fail on CRITICAL/HIGH |
| 4b | Checkov | Terraform/IaC misconfigurations | DevSecOps | Hard-fail on any failed check |

**Ownership definition:**
- **DevSecOps-owned** findings are remediated by the pipeline engineer
  (secret rotation, base-image upgrades, K8s hardening, Terraform fixes).
- **AppSec-owned** findings (application logic: SQLi, IDOR, XSS, broken auth,
  the catalogued AV/TV/FV items) are **detected and routed**, never fixed by
  the DevSecOps engineer. They are handed off to the AppSec team via the
  intake mechanism in Section 5.

---

## 3. Hard-fail vs soft-fail rules

### Hard-fail (merge blocked)
A change is **blocked** if any of the following is true:
1. Gitleaks reports one or more secrets.
2. SonarCloud reports one or more BLOCKER or CRITICAL issues.
3. Trivy image scan reports one or more CRITICAL or HIGH CVEs.
4. Trivy K8s config scan reports one or more CRITICAL or HIGH misconfigurations.
5. Checkov reports one or more failed checks.

### Soft-fail (merge allowed, finding routed)
A finding is **recorded and surfaced but does not block** if:
- It is a SonarCloud MAJOR / MINOR / INFO issue, or a Security Hotspot.
- It is a Trivy K8s LOW / MEDIUM misconfiguration.

Soft-fail findings appear in the gate's PR comment under the AppSec section
with a link to the intake process. They do not prevent merge.

### Rationale for the difference
Secret leaks, container CVEs, and IaC misconfigurations are unambiguous,
high-confidence, and the pipeline engineer's direct responsibility — there is
no business case for merging them, so they hard-fail. Application-code findings
span a confidence spectrum (SAST false-positive rates are non-trivial) and are
owned by a different team, so only the highest-severity, highest-confidence
ones (BLOCKER/CRITICAL) block; the rest route for triage.

---

## 4. Exception process

In rare cases a hard-fail finding must be accepted to unblock an urgent change
(e.g. a finding is a confirmed false positive, or a fix is scheduled but not
yet merged).

### Trigger
A repository maintainer comments on the pull request:
/security-exception <justification>

### Effect (Week 1 implementation)
The gate re-runs and treats the current hard-fail set as accepted for this PR
only, allowing the merge. The exception applies to the whole gate, not a
specific finding.

> **Production refinement (planned):** A mature implementation would scope the
> exception to a specific finding ID (`/security-exception AV-07 <reason>`),
> require approval from a CODEOWNER in a security group, set an expiry, and log
> the exception to an audit trail. The Week-1 implementation is deliberately
> simple to demonstrate the mechanism; Section 7 tracks the hardening backlog.

### Audit
Every exception is recorded in the PR's comment thread (who invoked it, when,
and the justification). The comment history is the audit trail.

---

## 5. AppSec intake (handoff template)

When the gate routes AppSec-owned findings, the PR comment includes an intake
block. The AppSec team triages using this template:
AppSec Intake — SecureFlow PR #<number>
Finding IDSeverityFile:LineScannerTriage status<id><sev><loc><tool>NEW
Triage owner: <assigned>
SLA: CRITICAL 7d / HIGH 30d / MEDIUM 90d

### Scanner coverage caveats (must be read by AppSec)
The automated scanners do **not** detect every application vulnerability.
The following are known coverage gaps requiring manual code review:
- **AV-01, AV-02 (SQL injection):** SonarCloud free tier lacks commercial
  taint-analysis rules. Manual review required on all DB-touching routes.
- **AV-04 (no rate limiting):** Not detectable by SAST (missing-feature
  pattern). Manual review of authentication endpoints required.
- **AV-06 (missing authorization):** Not detectable by SAST (missing-check
  pattern). Manual review of admin routes required.
- **AV-08 (sensitive data in errors):** Free-tier coverage gap.
- **TV-*, FV-* (runtime exploits):** Require DAST (Stage 7, OWASP ZAP).

A green SAST result does **not** imply the absence of these vulnerability
classes. AppSec manual review is mandatory regardless of gate status.

---

## 6. Gate behaviour by trigger context

| Context | Gate runs? | Comment posted? | Blocks? |
|---------|-----------|-----------------|---------|
| Pull request to main | Yes | Yes (PR comment) | Yes |
| Direct push to main | Yes | No (logged to job summary) | Yes (fails the run) |

---

## 7. Hardening backlog (post-Week-1)

- Per-finding exceptions with CODEOWNER approval and expiry.
- Exception audit log persisted outside the PR thread.
- SLA tracking integration (Jira/ServiceNow intake automation).
- Add Stage 7 (DAST) findings to the gate aggregation.
- Add Day-7 OPA Gatekeeper policy results to the gate aggregation.
- Reachability analysis to suppress non-exploitable CVEs (reduce HIGH noise).
