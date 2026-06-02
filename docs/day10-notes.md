# Day 10 Notes - Supply Chain (Stage 6) and DAST (Stage 7)

## Stage 6 - Cosign keyless signing + SPDX SBOM (DevSecOps-owned)
- Builds each service image, pushes to GHCR (ghcr.io/ade820/secureflow-<svc>:<sha>),
  signs keyless via Sigstore/Fulcio (GitHub OIDC), generates SPDX SBOM with Syft,
  attests the SBOM to the signed image, and verifies the signature.
- Job perms: packages: write (GHCR push) + id-token: write (keyless OIDC).
- Artifacts: sboms (~950KB, three SPDX docs). Verified run 26792336356.

## Stage 7 - OWASP ZAP baseline DAST (DevSecOps tooling, AppSec-routed findings)
- Brings up the full app via docker compose (test creds via env), waits for the
  frontend (HTTP 200 on /login), runs ZAP baseline against http://localhost:5000,
  publishes HTML+JSON reports, tears the stack down.
- Findings (8-9 WARN: missing security headers, absent anti-CSRF tokens, CSP, COEP)
  are app-layer -> routed to AppSec, non-blocking (-I informational mode).
- Artifact: zap-dast-report (~28KB). Verified run 26792336356.

## Pipeline trigger fix (Stages 6 and 7 were skipping)
- GitHub propagates Stage 2 (sast) failure transitively down the needs chain, which
  skipped Stages 6/7 even though Stage 5 (security-gate) succeeded.
- Fix: added  if: always() && needs.<dep>.result == success  to both jobs so they
  run when the gate passes, independent of the AppSec-routed Stage 2 failure.

## docker-compose fix (was broken)
- The Day 7 history scrub left literal ***REMOVED*** values in docker-compose.yml,
  which YAML parsed as anchor references -> file would not parse / app would not run.
- Converted to ${VAR:-default} interpolation (DB passwords matched per db/service).
  Unblocks DAST and is the correct pattern; production secrets are Vault-injected in K8s.

## ZAP report-capture fix
- ZAP runs as its own UID and could not write reports to the bind-mounted host dir
  (upload-artifact succeeded but uploaded 0 files). Fix: chmod 777 zap-report before
  the scan, plus if-no-files-found: error on the upload so an empty capture fails loudly.

## Full pipeline status (run 26792336356)
- Stage 1 Gitleaks: success | Stage 3 Trivy image: success | Stage 4 IaC: success
- Stage 5 Gate: success (DevSecOps-clean) | Stage 6 Cosign+SBOM: success | Stage 7 ZAP: success
- Stage 2 SonarQube: failure - CORRECT BY DESIGN (intentional Flask 0.0.0.0/debug app
  vulns; AppSec-owned, detect-and-route, never fixed by DevSecOps). Overall run shows
  failure solely because of this AppSec-routed stage.

## Outstanding (carried forward)
- Digest-pinning: pin K8s manifests to the signed GHCR digests from Stage 6, then flip
  the OPA no-latest-tag constraint from dryrun to enforce. NOT yet done.
- AppSec-BLOCKER gate policy: Stage 5 verdict logic vs table header still contradict on
  whether SonarQube BLOCKERs should hard-fail. Decision deferred.
- Final case-study report (14-20 pp) + presentation deck (12-15 slides). Deferred to a
  dedicated writing session.
- Engagement cleanup: delete pre-rewrite backups (hold old secrets) at the end.
- Vault dev-mode wipes on Docker Desktop restart - re-run Day 6 config before app pods.


## ADDENDUM - gate policy + digest pinning completed (same session)

### Gate policy: route-only (DECISION MADE)
- Decided: AppSec-owned SonarQube BLOCKERs route to AppSec intake, never hard-fail
  the DevSecOps gate. Pipeline can be green when DevSecOps-owned scanners are clean.
- Code aligned: verdict now blocks only on DEVSECOPS_BLOCK (removed the APPSEC_BLOCK
  clause, which was never actually set - the route-only behaviour had been accidental).
  AppSec table header -> "routed to AppSec intake; advisory, non-blocking"; SonarCloud
  BLOCKER row gate column -> "routed". Verdict logic, behaviour, and labels now agree.
- Commit 8113e41.

### Digest pinning + OPA enforce (DONE, enforcement PROVEN)
- Resolved signed GHCR digests (via docker buildx imagetools) for the three services
  built/signed by Stage 6 on commit 8113e41:
    auth-service        sha256:d9ba724f...ad5cb
    transaction-service sha256:77225a8c...6d44f
    frontend            sha256:dc04e1be...01c2b
- Pinned infra/kubernetes/base/{auth,transaction,frontend}.yaml from
  secureflow/<svc>:latest to ghcr.io/ade820/secureflow-<svc>@sha256:<digest>.
- Flipped OPA no-latest-tag constraint enforcementAction dryrun -> deny.
- Enforcement PROVEN: a test Deployment using nginx:latest in secureflow was DENIED
  at admission:  [no-latest-tag] Container c uses :latest tag; pin to a digest (CK-06).
- Note on scope: constraint matches Deployments in secureflow (bare kubectl-run Pods
  are out of match scope by design). The 3 already-running services were admitted under
  dryrun and still run their local images (audit totalViolations=3); enforcement applies
  to NEW admissions. A full redeploy from the pinned manifests (GHCR pull via
  imagePullSecret) would drop the audit count to 0 - deferred (avoids GHCR-auth on the
  local cluster). Honest statement: enforced for new admissions, proven via denial test,
  existing pods grandfathered pending redeploy.
- Commit 3ee4bf5.

## Remaining after this session
- ONLY the final case-study report (14-20 pp) + presentation deck (12-15 slides).
- Plus end-of-engagement cleanup: delete pre-rewrite backups (old secrets).
- Vault re-config runbook still applies if Docker Desktop restarts.
