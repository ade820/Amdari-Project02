# Committed Secrets Inventory — SecureFlow Baseline

Source files audited: `.env` (commit ced5589) and `docker-compose.yml`
Mapped findings: IV-03 (secrets in compose env vars), IV-04 (secrets in .env),
                 IV-01 (hardcoded DB password), AV-07 (hardcoded JWT secret),
                 FV-03 (committed session secret)

---

## Secret 1: AWS_ACCESS_KEY_ID

- **Value:** `AKIAIOSFODNN7EXAMPLE`
- **Pattern:** `AKIA[0-9A-Z]{16}` (canonical AWS access key ID)
- **Committed in:** `.env` only
- **Git retrieval:** `git show ced5589:.env`
- **Enables:** Programmatic AWS access under the attached IAM policy. Per
  IV-08 that policy is AdministratorAccess — full account compromise:
  enumerate resources, provision compute, exfiltrate S3, create persistent
  IAM backdoors.
- **Time-to-exploit if public:** Minutes (automated scanners watch GitHub
  for AKIA patterns continuously, per §4.1).
- **Owner:** DevSecOps — rotate, git-filter-repo, move to Vault.

## Secret 2: AWS_SECRET_ACCESS_KEY

- **Value:** `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
- **Committed in:** `.env` only
- **Pairs with:** Secret 1 — together they form a usable credential pair.
- **Owner:** DevSecOps.

## Secret 3: JWT signing secret

- **Value:** `super-secret-key-123`
- **Variable names:** `SECRET_KEY` in `.env`, `JWT_SECRET` in
  `docker-compose.yml` (auth-service block)
- **Committed in:** Both files
- **Enables:** JWT token forgery for any user, including admin (AV-03).
  An attacker mints a token with `{"user_id": 1, "role": "admin"}` and
  signs it with this value — the auth-service accepts it as genuine.
  Also serves as Flask `SECRET_KEY` fallback (AV-07), so Flask session
  cookies are forgeable.
- **Why uniquely bad:** Rotation requires every issued token to expire
  before the change is complete — forced logout for every user.
- **Gitleaks rule implication:** Day-3 custom rule must match BOTH
  `SECRET_KEY=` and `JWT_SECRET=` assignments.
- **Owner:** DevSecOps (move to Vault). AppSec owns the AV-07
  source-code fix (remove hardcoded fallback in auth-service).

## Secret 4: SESSION_SECRET

- **Value:** `changeme`
- **Committed in:** `.env` AND `docker-compose.yml` (frontend block)
- **Enables:** Flask session cookie forgery (FV-03). An attacker who knows
  this value generates a signed session cookie for any user and bypasses
  login entirely.
- **Severity note:** The literal value `changeme` is what every credential
  scanner flags first — it's the most common left-over default in the wild.
- **Owner:** DevSecOps (move to Vault).

## Secret 5: auth-db password

- **Value:** `authpass123`
- **Variable names:** `POSTGRES_PASSWORD` (auth-db service) and
  `DB_PASSWORD` (auth-service block) — both in `docker-compose.yml`
- **Committed in:** `docker-compose.yml` only (NOT in `.env`)
- **Enables:** Direct read/write access to the `authdb` Postgres instance.
  Combined with IV-02 (port 5432 exposed on host), an attacker on the same
  network connects and dumps the users table — every credential hash,
  every email, every role.
- **Owner:** DevSecOps (Week 2: Vault dynamic database credentials).

## Secret 6: transaction-db password

- **Value:** `txpass123`
- **Variable names:** `POSTGRES_PASSWORD` (transaction-db) and
  `DB_PASSWORD` (transaction-service) — both in `docker-compose.yml`
- **Committed in:** `docker-compose.yml` only
- **Enables:** Direct read/write to the `transactiondb` Postgres instance.
  Combined with IV-02 (port 5433 exposed), an attacker dumps every
  account balance, transaction history, and virtual card record.
- **Owner:** DevSecOps.

## Secret 7: SONAR_TOKEN

- **Value:** `squ_a1b2c3d4e5f6789012345678901234567890abcd`
- **Pattern:** `squ_[a-f0-9]{40}` (SonarQube user token format)
- **Committed in:** `.env` only
- **Enables:** Programmatic access to the SonarCloud project. Read every
  source-analysis finding (free vulnerability list), suppress findings
  to hide backdoors, or delete the project entirely.
- **Owner:** DevSecOps (rotate via SonarCloud UI; store new value as a
  GitHub Actions Secret, never in the repo).

---

## Summary Matrix

| # | Secret              | Value                              | In .env | In compose | Findings              |
|---|---------------------|------------------------------------|---------|------------|-----------------------|
| 1 | AWS_ACCESS_KEY_ID   | AKIAIOSFODNN7EXAMPLE               | ✅      | ❌         | IV-04                 |
| 2 | AWS_SECRET_ACCESS_KEY | wJalrXUtnFEMI/K7MDENG/bP...      | ✅      | ❌         | IV-04                 |
| 3 | JWT secret          | super-secret-key-123               | ✅      | ✅         | IV-03, IV-04, AV-07   |
| 4 | SESSION_SECRET      | changeme                           | ✅      | ✅         | IV-03, IV-04, FV-03   |
| 5 | auth-db password    | authpass123                        | ❌      | ✅         | IV-01, IV-03          |
| 6 | transaction-db pwd  | txpass123                          | ❌      | ✅         | IV-01, IV-03          |
| 7 | SONAR_TOKEN         | squ_a1b2c3...                      | ✅      | ❌         | IV-04                 |

**Seven distinct secret values across two committed files.**

The §1 brief says "6 committed secrets reduced to 0" — they're counting JWT
once because the value is identical across `.env` and compose. Either count
(6 logical secrets / 7 distinct file-level occurrences) is defensible; the
remediation work is the same: rotate all seven, move all values to Vault,
rewrite git history.

---

## Implications for later days

- **Day 3 (Gitleaks):** Custom `.gitleaks.toml` rules needed for `SECRET_KEY=`,
  `JWT_SECRET=`, `SESSION_SECRET=`, and DB-password patterns. AWS keys and
  Sonar tokens are caught by Gitleaks' built-in rules.
- **Day 6 (Vault):** Three service-level Vault policies (auth, transaction,
  frontend) each granting access only to that service's secrets. Use
  Vault's dynamic Postgres secrets backend for the DB passwords rather
  than storing them statically.
- **Day 6 (git-filter-repo):** Both `.env` and `docker-compose.yml` need
  history scrubbing. After the rewrite, the values above should be
  ungrep-able anywhere in git history.
