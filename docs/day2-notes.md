
## Baseline observation: incorrect MD5 hashes in db/auth/init.sql

During Exploit 2 (TV-01 IDOR), tried obtaining alice's and bob's tokens
to demonstrate a non-admin variant of the IDOR. Both logins returned
"invalid credentials". Investigation showed:

| User  | Documented pwd | Hash in init.sql | Actual MD5 of pwd |
|-------|----------------|-------------------|--------------------|
| admin | admin123       | 0192023a7bbd...   | 0192023a7bbd... ✅ |
| alice | alice123       | 8d7dd611a2c8...   | 7abdccbea847... ❌ |
| bob   | bob123         | 2ab96390c7db...   | 2acba7f51acf... ❌ |

Only `admin / admin123` validates. The alice and bob seed hashes don't
match their documented plaintext passwords.

**Not fixing this.** It's a data-correctness issue in the baseline that
doesn't affect any AV/TV/FV/IV/CK finding I need to detect or remediate.
TV-01 (IDOR) is fully demonstrable using the admin token obtained via
AV-01 SQLi — reading accounts 2 and 3 with admin's token shows the
missing ownership check just as cleanly. I'll flag this as a baseline
quality issue in the Week 1 progress report, but I'm leaving the seed
untouched so my fork remains a faithful reproduction of the upstream
vulnerable baseline.

Scope rationale: §1 says "interns transforming a comprehensively
insecure baseline" — modifying the baseline beyond what's necessary
to run undermines the simulation. The Werkzeug pin was unavoidable
(app wouldn't start). This isn't.

## Gitleaks methodology

### What Gitleaks does
Scans git repos for committed secrets. Two detection strategies:

1. **Pattern matching** — built-in regexes for common credential formats:
   AKIA[0-9A-Z]{16} (AWS access key), ghp_... (GitHub PAT), squ_... (Sonar
   token), and ~150 others.

2. **Entropy detection** — strings with high Shannon entropy (random-
   looking) get flagged even if they don't match a known pattern. Catches
   custom tokens that follow no published format. Tunable per-rule.

### --log-opts='--all' — critical for SecureFlow
By default, Gitleaks scans the working tree. With --log-opts='--all', it
walks the full git history across every branch and tag.

This matters because deleting .env in a later commit DOES NOT remove the
secret. `git show <hash>:.env` still returns the original file. Without
--all, deleting a leaked file and pushing a fresh commit would silence
Gitleaks despite the secret remaining publicly retrievable. With --all,
the secret stays detected until git-filter-repo scrubs history (which is
my Week 2 task).

### .gitleaks.toml — custom rules
A TOML config that extends built-in rules with project-specific patterns.
For SecureFlow we'll need at least:

- Flask SECRET_KEY assignment patterns
- JWT_SECRET assignment patterns (the name varies — SECRET_KEY in .env,
  JWT_SECRET in docker-compose.yml)
- DB password patterns matching POSTGRES_PASSWORD=, DB_PASSWORD=

Each rule has: id, description, regex, optional entropy threshold,
optional path filter.

### Gate behaviour for Stage 1
Per the differentiated gate design: Stage 1 hard-fails on ANY finding.
No "differentiated" behaviour for secrets — a committed secret is
binary, not a severity gradient. Unlike SAST findings (some of which
route to AppSec without blocking the merge), every secret finding
blocks until cleared.

### Why Stage 1 hard-fails on any but Stage 2 doesn't
- Stage 1 finding = "you committed a credential". Always actionable,
  always severe, always blocks.
- Stage 2 finding = "you wrote code that may have a vulnerability".
  Severity varies, ownership splits between DevSecOps and AppSec, and
  blocking on every MINOR finding would create alert fatigue and stall
  development. So Stage 2 hard-fails only on CRITICAL/BLOCKER and
  routes everything else via PR comment.

This is the rationale I'll document in docs/security-gate-policy.md on
Day 5.

## Day 3 Gitleaks baseline scan — observations

Local Gitleaks run with default rules only (no .gitleaks.toml yet) found
3 secrets across the entire git history:

1. **JWT in evidence/exploits/05-fv03-session-forgery.md** — false
   positive; documentation quoting the exploit output. Will be allowlisted
   in .gitleaks.toml.

2. **SONAR_TOKEN in .env (commit ced5589)** — true positive. IV-04.
   The pipeline correctly detects this.

3. **db_password = "postgres" in infra/terraform/main.tf (commit 67266955
   from upstream baseline)** — true positive. Not previously catalogued
   in VULNERABILITIES.md but logically part of IV-01 (hardcoded DB
   password). Will note in the Week 1 progress report as a baseline
   finding the upstream index missed.

## Gaps the default ruleset missed

Default Gitleaks DID NOT catch:
- AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE (excluded by Gitleaks'
  documentation-keys exemption — `AKIAIOSFODNN7EXAMPLE` is AWS's own
  example value and is treated as not-a-real-key by default)
- AWS_SECRET_ACCESS_KEY (same exemption)
- SECRET_KEY=super-secret-key-123 in .env
- JWT_SECRET=super-secret-key-123 in docker-compose.yml
- SESSION_SECRET=changeme in both .env and docker-compose.yml
- POSTGRES_PASSWORD=authpass123 / txpass123 in docker-compose.yml

These are the gaps .gitleaks.toml must close. The defaults handle the
well-known SaaS provider tokens but cannot anticipate project-specific
patterns. The custom-rule layer is what makes Stage 1 trustworthy
against any given codebase.

## Day 3 Gitleaks scan with .gitleaks.toml applied

21 findings across the entire git history. Sources:

### .env (commit ced5589 — my IV-04 baseline)
- AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (default rule was bypassed by
  AWS's documentation-key exemption; my strict custom rules catch them)
- SECRET_KEY, SESSION_SECRET
- DB_PASSWORD, POSTGRES_PASSWORD
- SONAR_TOKEN (default sonar-api-token rule)

### docker-compose.yml (upstream commit 67266955)
- POSTGRES_PASSWORD x2 (auth-db, transaction-db)
- DB_PASSWORD x2 (auth-service, transaction-service)
- JWT_SECRET
- SESSION_SECRET

### infra/kubernetes/base/configmap.yaml — NEW finding category (CK-09)
- JWT_SECRET
- SESSION_SECRET
- AUTH_DB_PASSWORD
- TX_DB_PASSWORD

VULNERABILITIES.md flagged CK-09 ("Secrets in ConfigMaps"); Gitleaks
just confirmed which keys. These will need to migrate to Vault in
Week 2, with ConfigMap → Vault Agent Injector substitution.

### infra/terraform/main.tf
- db_password = "postgres" (caught by both default and custom rules)

### services/*/app.py
- AV-07: SECRET_KEY fallback literal in auth-service/app.py
- FV-03-adjacent: SESSION_SECRET fallback literal in frontend/app.py

These two are AppSec-owned at the code level (removing the fallback
literal), but Stage 1 still hard-fails because the credential is
committed regardless of where it lives. The classification of who
fixes what happens at the security gate on Day 5.

## Detection coverage achieved

Before .gitleaks.toml:  3 findings (1 false positive + 2 true positives)
After .gitleaks.toml:  21 findings (0 false positives + 21 true positives)

The improvement is the value of the custom-rule layer.

## Stage 2 — SonarCloud SAST results

After disabling SonarCloud's Automatic Analysis (it conflicted with
CI-based analysis from GitHub Actions), Stage 2 successfully scanned
all three services.

Dashboard summary (SonarCloud project ade820_Amdari-Project02):
- 27 open issues
- 18 security issues (5 Blocker, 12 Medium, 1 Low — by SonarCloud severity)
- 25 security hotspots to review
- 1.2k lines of code analyzed

Differentiated gate behaviour confirmed working:
- Stage 2 hard-failed on 2 BLOCKER findings — flask-app-bind-0.0.0.0
  in frontend/app.py (line 185) and transaction-service/app.py (line 201)
- These are AppSec-owned (server-bind security pattern; not in VULNERABILITIES.md
  but a legitimate SAST catch by SonarCloud's python:S4502 rule)
- Non-BLOCKER findings (MAJOR/MINOR/INFO) would have soft-passed and
  routed via PR comment

What SonarCloud caught vs my VULNERABILITIES.md index:
- AV-01, AV-02 (SQL injection)              — surfaced
- AV-07 (hardcoded JWT_SECRET literal)      — surfaced
- New finding NOT in my index: app.run(host='0.0.0.0')
  in 3 services. SAST tools surface findings beyond hand-curated
  indexes — this is a normal outcome and should be added to the
  Week 1 progress report.

## Note on SonarCloud Automatic vs CI Analysis

When linking a new project, SonarCloud defaults to Automatic Analysis.
This conflicts with explicit CI-based analysis: the scanner errors out
with "You are running CI analysis while Automatic Analysis is enabled."

Resolution: Project → Administration → Analysis Method → toggle
Automatic Analysis OFF. CI-based analysis (via SonarSource/sonarcloud-
github-action) then works normally.

For a DevSecOps pipeline this is the right choice — CI-based analysis
is deterministic and participates in our control flow (we wait, fetch,
evaluate gate). Automatic Analysis is asynchronous and outside the
pipeline's control.

## Day 3 final — Stage 2 gate evidence

Stage 2 final state with Automatic Analysis disabled and CI scan running:

| Severity | Count | Gate behaviour |
|----------|-------|----------------|
| BLOCKER  | 3     | Hard-fail (DevSecOps gate) |
| CRITICAL | 0     | Hard-fail (none triggered) |
| MAJOR    | 14    | Soft-fail → route to AppSec (Day 5) |
| MINOR    | 0     | Soft-fail → route to AppSec |
| INFO     | 0     | Soft-fail → route to AppSec |

Total: 17 issues. The 3 BLOCKERs are the same rule (Flask binds to 0.0.0.0)
firing across auth-service line 162, frontend line 185, transaction-service
line 201.

The 14 MAJOR findings are not visible in this log (gate fails before the
script dumps non-blocking detail), but they live in sonarqube-findings.json
and on the SonarCloud dashboard. The Day-5 security gate will read them
from the JSON artifact and surface them in the PR comment.
