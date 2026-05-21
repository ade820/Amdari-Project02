
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
