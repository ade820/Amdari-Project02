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
