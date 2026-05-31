# Day 5 Notes — Security Gate (Stage 5)

## The security-gate pattern

A security gate is the decision point in a DevSecOps pipeline that aggregates
the output of all upstream scanners and makes a single, policy-driven
allow/block decision. It's the difference between "we run scanners" and
"we enforce security policy."

Without a gate, each scanner fails independently and developers see a wall
of red checks with no guidance on what's blocking, what's advisory, and who
owns each finding. The gate consolidates this into one verdict plus one
human-readable report.

## Differentiated gate policy — the core concept

Not all findings are equal, and not all findings are the pipeline owner's job
to fix. A differentiated gate distinguishes along two axes:

### Axis 1 — Severity (blocking vs advisory)
- CRITICAL / BLOCKER → hard-fail. Merge blocked. No exceptions without sign-off.
- HIGH → hard-fail for infra/container/secret findings (DevSecOps-owned).
- MEDIUM / LOW / MAJOR / MINOR → soft-fail. Recorded, surfaced, routed. Merge proceeds.

### Axis 2 — Ownership (who fixes it)
- DevSecOps-owned: secrets (Gitleaks), container CVEs (Trivy image),
  K8s misconfig (Trivy config), IaC misconfig (Checkov). The pipeline
  engineer remediates these in Week 2.
- AppSec-owned: application code vulnerabilities (SonarQube SAST findings,
  plus the AV/TV/FV catalogued findings). These are DETECTED and ROUTED to
  the AppSec team, never fixed by the DevSecOps engineer.

The gate's job is to enforce Axis 1 (block or allow) while making Axis 2
visible (who needs to act). A finding can be high-severity AND AppSec-owned —
in which case the gate routes it with urgency but doesn't necessarily block
on it, depending on the policy matrix below.

## Why this matters for SecureFlow

SecureFlow is intentionally vulnerable. If the gate blocked on every finding,
no code would ever merge and the pipeline would be useless. If it blocked on
nothing, it would be theatre. The differentiated approach means:
- The DevSecOps-owned infrastructure problems (committed secrets, unencrypted
  S3, privileged containers) hard-block — because those are MY job to fix and
  there's no reason to ship them.
- The AppSec-owned application problems (SQLi, IDOR, XSS) are detected, logged,
  and handed off via a structured PR comment — because fixing application logic
  is the AppSec/development team's responsibility, not the pipeline engineer's.
