# Day 4 Notes — Trivy and Checkov

## CVE / CVSS / "CRITICAL" — what these terms actually mean

### CVE (Common Vulnerabilities and Exposures)
A CVE is a unique identifier for one publicly disclosed vulnerability.
Format: CVE-YYYY-NNNNN (e.g. CVE-2023-12345). The number is assigned by
a CVE Numbering Authority (CNA) — typically the vendor (Red Hat, GitHub,
Microsoft) or MITRE itself.

A CVE entry contains: a description of the flaw, affected versions, the
type of weakness (CWE — Common Weakness Enumeration), and references to
advisories. CVEs are catalogued in the National Vulnerability Database
(NVD) at https://nvd.nist.gov.

Critical point: A CVE doesn't include a fix. It's just an identifier
and description. The fix (a patch, a config change, an upgrade) comes
from the vendor or maintainer.

### CVSS (Common Vulnerability Scoring System)
A numeric score 0.0–10.0 assigned to each CVE that quantifies severity.
Current version is CVSS 3.1 (CVSS 4.0 exists but adoption is partial).

The score is computed from a vector of attributes:
- Attack Vector (Network / Adjacent / Local / Physical)
- Attack Complexity (Low / High)
- Privileges Required (None / Low / High)
- User Interaction (None / Required)
- Scope (Unchanged / Changed)
- Confidentiality / Integrity / Availability impact (None / Low / High)

CVSS bands → severity labels:
- 0.0      → None
- 0.1–3.9  → Low
- 4.0–6.9  → Medium
- 7.0–8.9  → High
- 9.0–10.0 → CRITICAL

### What "CRITICAL" means in practice
CVSS ≥ 9.0 typically means the vulnerability is:
- Remotely exploitable (no local access needed)
- Requires no privileges
- No user interaction required
- Results in confidentiality + integrity + availability loss

In real terms: "an attacker on the internet can fully compromise the
system without any user action and without prior access." That's why
DevSecOps pipelines hard-fail on CRITICAL — there is no business case
for shipping a CRITICAL CVE to production.

HIGH (7.0–8.9) is "must be remediated, but exploitation needs at least
one mitigating factor — adjacent network, local access, or user
interaction." Most security teams gate on HIGH too, with a short SLA
for exceptions.

CVSS has known limitations: it doesn't account for whether the
vulnerable code path is actually reached in your application
(reachability), or whether you have compensating controls. EPSS
(Exploit Prediction Scoring System) and reachability analysis are
emerging tools that supplement CVSS but don't replace it.

### How this applies to SecureFlow
The CK-01 finding is `python:3.9-slim` shipping with multiple CRITICAL
CVEs in OS packages (glibc, openssl, etc.) inherited from Debian. The
fix is to upgrade the base image to a version where those CVEs have
been patched — which I'll do in Week 2 (Day 7). For Week 1, my job is
just to detect them and document the count.

## Trivy local scan — CK-01 baseline

Scanned: python:3.9-slim
Image digest at time of scan: (capture below)
Trivy version: latest as of $(date +%Y-%m-%d)
Underlying OS: Debian 13.1 (trixie)

Result: **3 CRITICAL CVEs**, all attributable to one underlying issue:

| CVE | Severity | Packages affected | Installed | Fixed in | Status |
|-----|----------|-------------------|-----------|----------|--------|
| CVE-2026-31789 | CRITICAL | libssl3t64, openssl, openssl-provider-legacy | 3.5.1-1+deb13u1 | 3.5.5-1~deb13u2 | Fixed upstream |

Single root cause: OpenSSL heap buffer overflow on 32-bit systems
during X.509 certificate parsing. Counted as 3 findings by Trivy
because three packages in the Debian repository bundle OpenSSL
(the runtime, the dev tools, the legacy-provider).

## Note on the PDF's "47 → 3" success metric

The PDF was authored against an older snapshot of python:3.9-slim
(likely Debian 11 or 12). My scan is against Debian 13.1 (trixie,
released August 2025), where most CRITICAL CVEs the PDF anticipated
have already been backported.

This is a real-world reminder that CVE counts are time-sensitive:
- The same image tag (python:3.9-slim) refers to different actual
  contents depending on when you pull it
- Patched upstream packages flow into base images on the regular
  rebuild cycle (typically weekly for Debian-based images)
- A pipeline that hard-fails on CRITICAL today might be green on
  the same image tomorrow if the maintainer ships a rebuild

The right success metric to use in MY engagement is "3 → 0" — the
same shape, scaled to current reality. Day-7 remediation (Week 2)
will rebuild the service images on a newer base (python:3.13-slim
or python:3.12-slim) that has the OpenSSL fix included.

## How Stage 3 will behave

With --severity CRITICAL,HIGH --exit-code 1:
- 3 CRITICAL findings → hard-fail (correct gate behaviour)
- N HIGH findings (the Python-layer scan showed 3 — jaraco, wheel,
  pip) → also hard-fail on first push, since the gate is OR'd

Stage 3 will stay red on every push until Week 2's image rebuild
removes both the CRITICAL OpenSSL CVEs and the Python-layer HIGHs.

The hard-fail-on-HIGH choice matters: it means a single un-pinned
dependency upgrade gone wrong (like the jaraco path traversal CVE)
blocks the merge. That's the right policy for a security-sensitive
banking application.

## Image digest pinning — evidence anchor

Scanned image: python:3.9-slim
Digest at time of scan: sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b
Full reference: python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b

Pinning to digest (rather than tag) is the only way to guarantee
reproducible scan results. The tag `python:3.9-slim` points at a
different digest each time the maintainer rebuilds the image. Two
scans against the same tag a week apart can produce different CVE
counts because the underlying image content changed.

Day-7 (Week 2) container hardening will pin all service Dockerfiles
to specific digests, not tags — which is also what CK-03 (unpinned
image tags) calls out as a finding.

## Stage 3 CI scan — full results

| Service              | CRITICAL | HIGH |
|---------------------|----------|------|
| auth-service        | 3        | 30   |
| transaction-service | 3        | 33   |
| frontend            | 3        | 33   |

The 3 CRITICALs in every service are identical — the OpenSSL CVE-2026-31789
trio inherited from python:3.9-slim. Same root cause across all images
because every Dockerfile reads `FROM python:3.9-slim`.

The HIGH counts differ per service because each service installs different
pip dependencies on top of the shared base:
- auth-service: Flask, Werkzeug, psycopg2-binary, PyJWT
- transaction-service: Flask, Werkzeug, psycopg2-binary, requests
- frontend: Flask, Werkzeug, requests

Note: the Werkzeug 2.2.2 pin from Day 1 (added to fix the url_quote
import error) almost certainly contributes some of these HIGH findings.
Werkzeug 2.2.2 was released October 2022 and has accumulated CVEs since.
Day-7 remediation will upgrade Flask/Werkzeug as part of the base image
refresh, which will close both the Werkzeug-specific HIGHs and the
OpenSSL CRITICALs in one shot.

## Stage 3 gate behaviour confirmed

- Per-image hard-fail on first CRITICAL/HIGH (correct)
- `if: always()` ensured all three services scanned despite earlier failures
- "Summarise Trivy findings" step ran after all scans, printing counts
- Three trivy-*.json artifacts uploaded for Day-5 gate consumption
- Total run time: 55s (fast — Trivy DB cached after first run)

## Stage 4 part 1 — Trivy K8s manifest scan results

Local scan with --severity CRITICAL,HIGH:
- 5 files scanned, 16 HIGH findings, 0 CRITICAL findings
- Hard-fail gate will trigger on these 16 HIGHs

Full scan (no severity filter) — 19 findings per service file at all
severities. Mapping to VULNERABILITIES.md:

| Catalogued | Trivy Rule(s)     | Severity | Captured? |
|------------|------------------|----------|-----------|
| CK-02      | KSV-0020/21/105  | LOW      | ✅ at LOW |
| CK-04      | KSV-0017 + 0001  | HIGH+MED | ✅ hard-fails |
| CK-05      | KSV-0011/15/16/18| LOW      | ✅ at LOW (routed) |
| CK-06      | KSV-0013         | MEDIUM   | ✅ at MEDIUM (routed) |
| CK-07      | (none)           | —        | ❌ Trivy doesn't check missing labels |
| CK-09      | KSV-0109         | HIGH     | ✅ hard-fails |

Bonus findings (not in VULNERABILITIES.md but caught):
- KSV-0014 (readOnlyRootFilesystem) — HIGH, 5x
- KSV-0118 (default security context) — HIGH, 6x
- KSV-0125 (untrusted registry) — MEDIUM, 3x
- KSV-0030/0104 (seccomp profile) — LOW/MEDIUM

Coverage gap: CK-07 (missing labels) needs OPA Gatekeeper or
Polaris — Trivy doesn't enforce label policy out of the box.
This is a Day-7 (OPA constraints) deliverable, not a Stage 4
deliverable. The Day-5 gate policy doc must note this.

## Stage 4 part 2 — Checkov Terraform scan results

Local scan against infra/terraform/:
- 48 passed, 72 failed, 0 skipped

All three catalogued IV-* findings detected:

| Catalogued | Checkov rule(s)                              | Count |
|------------|---------------------------------------------|-------|
| IV-08      | CKV_AWS_274 (AdministratorAccess) + 9 more | 10    |
| IV-09      | CKV_AWS_53/54/55/56 + 7 more                | 22    |
| IV-10      | CKV_AWS_38/39 + 5 more                      | 7     |

Bonus categories caught (not in VULNERABILITIES.md):

| Category              | Count | Examples                                |
|----------------------|-------|----------------------------------------|
| RDS hardening        | 18    | No encryption (CKV_AWS_16), publicly accessible (CKV_AWS_17), no IAM auth, no deletion protection, no monitoring |
| VPC security groups  | 8     | Wide-open SG on 22/80/3389 (CKV_AWS_24/260/25), no descriptions, default SG unrestricted |
| VPC flow logging     | 1     | CKV2_AWS_11                            |
| Misc S3              | 6     | KMS encryption, versioning, logging, lifecycle, replication, event notifications |

Coverage observation: Checkov caught everything VULNERABILITIES.md
catalogued PLUS ~33 additional findings. The 72 total give a far more
complete picture than the index alone. Week-2 IaC remediation will
need to triage:
- The 10 IV-08 IAM findings (the catalogued ones)
- The 22 IV-09 S3 findings (catalogued + KMS/versioning/logging)
- The 7 IV-10 subnet/EKS findings (catalogued)
- The 18 RDS findings (NEW — these would prevent RDS from being
  production-grade without encryption and IAM auth)
- The 8 VPC SG findings (NEW — at least the wide-open SSH/RDP SGs
  should be tightened; that's a blast-radius issue)

Of the 72 findings, all are HIGH-or-equivalent (Checkov doesn't use
the LOW/MEDIUM/HIGH/CRITICAL bands the way Trivy does — its model
treats every check as a pass/fail). Stage 4's Checkov step will
hard-fail on the entire failure set.

## Stage 4 gate behaviour design

For consistency with the differentiated gate policy:

| Tool   | Hard-fail trigger                          | Soft-fail finding type |
|--------|-------------------------------------------|------------------------|
| Trivy K8s | HIGH or CRITICAL                       | LOW/MEDIUM (route to PR comment) |
| Checkov   | Any failure (no severity gradient)     | (none — Checkov is binary) |

The combined Stage 4 job will hard-fail if either:
- Trivy K8s reports any HIGH/CRITICAL, OR
- Checkov reports any failure

Both scanner JSON outputs upload as artifacts for the Day-5 gate.
