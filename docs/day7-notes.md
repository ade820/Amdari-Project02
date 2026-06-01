# Day 7 Notes — Container Remediation, History Rewrite & securityContext Hardening

## Summary
Day 7 covered three areas: container-layer remediation (Dockerfiles + CVEs),
the git-history secrets scrub, and the start of Kubernetes securityContext
hardening. Two pipeline stages went green: Stage 1 (Gitleaks) and Stage 3 (Trivy).

---

## 1. Container layer (Chunk A)

### Base image upgrade
- All three Dockerfiles: `python:3.9-slim` → `python:3.12-slim`.
- This eliminated the bulk of the OS-layer CVEs (the "47 → 3" success metric).

### Non-root user (CK-02 / IV-05)
- Each Dockerfile creates a system user at UID 1000:
  `groupadd --system --gid 1000 app && useradd --system --uid 1000 --gid app --create-home app`
- Note: the engagement PDF suggested Alpine syntax (`addgroup -S`); we used the
  Debian-correct form because python:3.12-slim is Debian-based.
- UID 1000 deliberately matches the manifest `runAsUser: 1000` so the image user
  and the K8s-enforced UID are the same identity (avoids file-permission issues).
- Verified live: `kubectl exec ... -- id` returns `uid=1000(app)`, not root.

### HEALTHCHECK
- Added to all three services using Python stdlib (`urllib.request`), since
  python:3.12-slim ships no curl.

### Digest pinning (CK-03)
- postgres pinned from `postgres:14` to
  `postgres@sha256:04a3d3d1475ad37f07d8219d0e5eb46f64ac132bf6e110c772dab45e12e4a919`.
- Service images (auth/transaction/frontend) are NOT digest-pinned yet — they are
  locally built and have no stable registry digest. Per the PDF, service-image
  digest pinning is a Day 8 item (after Cosign signing produces signed digests).

### Dependency fix (build-driven, not app change)
- `psycopg2-binary` 2.9.5 → 2.9.9 in auth-service and transaction-service.
- Reason: 2.9.5 has no prebuilt wheel for Python 3.12, so pip fell back to
  building from source, which needs `pg_config` (absent in slim). 2.9.9 ships a
  cp312 wheel. This is a build-compatibility fix forced by the base-image upgrade,
  NOT an application-logic change. Flask/Werkzeug/PyJWT pins were left untouched.

---

## 2. CVE accepted-risk register (referenced by .trivyignore)

After the 3.12-slim upgrade, each image has exactly 2 residual CRITICAL CVEs,
both in `perl-base`, both with NO fixed version available in Debian 13 as of
the recheck date:

| CVE | Package | Issue | Fix status |
|-----|---------|-------|------------|
| CVE-2026-42496 | perl-base 5.40.1-6 | Archive::Tar symlink extraction | No Debian patch yet (upstream fix in Archive::Tar 3.08) |
| CVE-2026-8376  | perl-base 5.40.1-6 | Perl heap buffer overflow on compile | No Debian patch yet |

**Decision:** These are accepted-risk and listed in `.trivyignore` with a recheck
date (2026-06-14). This is distinct from suppressing upgrade-fixable CVEs — the
base image was already upgraded; only the genuinely-unpatchable residue is
accepted. On the recheck date, remove the entries and rebuild; if Debian has
shipped a fixed perl-base, the CVEs resolve with no code change.

### HIGH CVEs (non-blocking, routed/documented)
- Python deps (Flask, Werkzeug, PyJWT, urllib3) have HIGH CVEs with fixes
  available, but these are application dependencies. Bumping them (esp. PyJWT,
  which ties to AV-03/AV-07 JWT findings) is AppSec-owned. They are reported by
  Trivy, surfaced in the gate, and routed — not fixed here.
- Stage 3 gate realigned: hard-fail on CRITICAL only; HIGH scanned and reported
  (non-blocking), per the documented success metric ("zero CRITICAL; HIGH
  documented and trending downward"). Recorded in docs/security-gate-policy.md.

---

## 3. Git history rewrite (Chunk B)

### What was done
- Created `.gitignore` (was absent); added `.env` and secret-file patterns.
- Untracked `.env` from the working tree (`git rm --cached .env`) — file kept
  locally for the compose stack, removed from git.
- Backed up the repo two ways before any rewrite:
  - Full directory copy: `Amdari-Project02-BACKUP-prerewrite/`
  - Verified git bundle: `Amdari-Project02-prerewrite.bundle`
- Ran `git filter-repo --force --invert-paths --path .env --replace-text replacements.txt`:
  - Removed `.env` from ALL history.
  - Redacted committed secret values to `***REMOVED***` everywhere (docker-compose.yml,
    configmap.yaml history, app.py, etc.).
- Force-pushed the rewritten history (`160f8cb...5a894f6 forced update`).
- Deleted `replacements.txt` (it contained the secret strings).

### Verification
- `.env` absent from all commits.
- No live secret assignments survive in history.
- 64 `***REMOVED***` redaction markers confirm the replacement applied.
- All commit SHAs changed (history genuinely rewritten).

### Backups
- The pre-rewrite backup directory and bundle still contain the OLD history
  (with secrets). They are LOCAL ONLY and must never be pushed. Delete once the
  new history is confirmed healthy and the engagement is complete.

### app.py side effect (scope note)
- The `--replace-text` pass redacted the hardcoded fallback in app.py
  (`os.getenv("JWT_SECRET", "***REMOVED***")`). app.py is normally AppSec-owned,
  but removing a *committed secret value* is DevSecOps scope; the application
  *logic* (the `os.getenv` structure) was not changed — only the literal secret
  was redacted. The underlying AV-07 finding (reliance on a hardcoded fallback)
  remains AppSec's to remediate properly (e.g. fail-closed if the env var is unset).

---

## 4. Gitleaks false-positive handling (Stage 1 green)

After the rewrite, Gitleaks reported 15 findings — all false positives or
documentation, none live secrets:
- docker-compose.yml / configmap.yaml / app.py: values already `***REMOVED***`.
  Cleared via a `.gitleaks.toml` allowlist regex matching the redaction marker.
- .github/workflows/: `curl -u "${SONAR_TOKEN}:"` is a runtime variable
  reference, not a literal. Cleared via a workflows path allowlist.
- infra/terraform/main.tf: `db_password = "postgres"` was a real hardcoded value
  (IV-01). FIXED — changed to `var.db_password` with a `sensitive = true`
  variable declaration. (Broader Terraform hardening — IV-08/09/10 — is Day 8.)

Result: Gitleaks `no leaks found`, exit 0. Stage 1 GREEN.

---

## 5. securityContext hardening (Chunk C) — CK-02 / CK-04

All three service deployments updated:
securityContext:
privileged: false
allowPrivilegeEscalation: false
runAsNonRoot: true
runAsUser: 1000
capabilities:
drop: [ALL]
- Verified live: pods run `2/2 Running`; `id` returns `uid=1000(app)`.
- `runAsNonRoot: true` means K8s would refuse to start a root image — the clean
  start proves the image is genuinely non-root.

---

## Carried forward to Day 8 (documented, not gaps)
- **Stage 5 gate script** still marks Trivy HIGH as BLOCK — inconsistent with the
  Stage 3 CRITICAL-only policy. Align when pursuing full-green.
- **Stage 4** remains red: resource limits (CK-05), required labels (CK-07),
  NetworkPolicy (CK-08), and OPA Gatekeeper are Day 8; Terraform IaC
  (IV-08/09/10) is Day 8.
- **DB password into Vault** — the db-credentials K8s Secret could move to Vault
  injection; deferred. The db-credentials .gitleaks allowlist entry stays until then.
- **Service-image digest pinning** — Day 8, after Cosign signing.

## Pipeline state at end of Day 7
- Stage 1 Gitleaks: GREEN ✅
- Stage 3 Trivy image: GREEN ✅
- Stage 2 SonarQube: red (3 BLOCKER, AppSec-adjacent)
- Stage 4 IaC: red (K8s + Terraform, Day 8)
- Stage 5 gate: BLOCK (on Stage 2 + Stage 4)