
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
