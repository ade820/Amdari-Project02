# SecureFlow — Vulnerable Banking Platform

> **This is an INTENTIONALLY INSECURE baseline.**
> Do not deploy to a real cloud account. Run only in an isolated lab or local
> Kubernetes cluster (kind, k3s, minikube).

This repository is the "before" state for the SecureFlow DevSecOps case study.
Your job is to build the security pipeline, remediations, policy enforcement,
secrets management, runtime monitoring, and observability described in the
project brief. What you fork is broken on purpose — every vulnerability listed
in [`VULNERABILITIES.md`](./VULNERABILITIES.md) is real and exploitable.

Read the project brief PDF end-to-end before you touch any code.

---

## Architecture

```
                     ┌────────────────────┐
                     │     frontend       │  Flask + Jinja2 on :5000
                     │  (server-rendered) │
                     └──────┬───────┬─────┘
                            │       │
                 calls       │       │  calls
                            ▼       ▼
            ┌─────────────────┐  ┌──────────────────────┐
            │  auth-service   │  │ transaction-service  │
            │   Flask :5001   │  │    Flask :5002       │
            └────────┬────────┘  └──────────┬───────────┘
                     │                      │
                     ▼                      ▼
              ┌────────────┐          ┌────────────────┐
              │  auth-db   │          │ transaction-db │
              │ postgres   │          │   postgres     │
              └────────────┘          └────────────────┘
```

Three Python/Flask services, two independent PostgreSQL instances, microservices
pattern. Each service has its own database so that per-service Vault policies
(Step 14 of the brief) are meaningful — compromising one service does not grant
access to another service's data.

---

## Quick Start — Docker Compose

```bash
docker-compose up --build

# Services are then available at:
#   frontend              http://localhost:5000
#   auth-service API      http://localhost:5001
#   transaction-service   http://localhost:5002
#   auth-db               localhost:5432
#   transaction-db        localhost:5433
```

Seed users (the password hashes are MD5 — weak on purpose, see AV-05):

| Username | Password   | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | alice123  | user  |
| bob      | bob123    | user  |

---

## Quick Start — Kubernetes (base manifests)

```bash
kubectl apply -k infra/kubernetes/base

# Everything will apply because there is no admission controller in the way.
# That is the point. One of your tasks is to install OPA Gatekeeper and watch
# the base manifests get rejected.

kubectl get pods -n secureflow -w
```

---

## Example Exploits

Once the stack is running, these should all succeed against the baseline:

```bash
BASE=http://localhost:5001

# AV-01 — SQL injection auth bypass. Logs in as admin with no password.
curl -s -X POST $BASE/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin'\''--", "password": "anything"}'

# Save the token from the response, then:
TOKEN=<paste token here>

# TV-01 — IDOR. Read admin's balance from alice's account.
curl -s http://localhost:5002/balance/1 \
  -H "Authorization: Bearer $TOKEN"

# TV-03 — Negative transfer. Drains the recipient.
curl -s -X POST http://localhost:5002/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account": 2, "to_account": 3, "amount": -500}'

# FV-01 — Reflected XSS via query string.
# Open in browser after logging in as alice:
#   http://localhost:5000/dashboard?msg=<script>alert(document.cookie)</script>
```

---

## What's In This Repository

```
secureflow/
├── .env                              ← IV-04: committed on purpose, 5 secrets
├── docker-compose.yml                ← IV-01/02/03/06/07 + CK-03
├── .gitignore                        ← deliberately does not exclude .env
├── README.md                         ← this file
├── VULNERABILITIES.md                ← the full index keyed to the PDF
├── services/
│   ├── auth-service/                 ← AV-01..AV-08
│   ├── transaction-service/          ← TV-01..TV-07
│   └── frontend/                     ← FV-01..FV-07 (except FV-04)
├── db/
│   ├── auth/init.sql                 ← users schema + seed
│   └── transaction/init.sql          ← accounts, transactions, cards + seed
└── infra/
    ├── kubernetes/base/              ← CK-02..CK-09
    └── terraform/                    ← IV-08, IV-09, IV-10 + the modules Checkov will scan
```

---

## What's NOT In This Repository

Everything in this list is your job to build, based on the project brief:

- `.github/workflows/*` — the GitHub Actions pipeline
- `.gitleaks.toml` — custom Gitleaks rules for Flask/JWT/DB patterns
- `sonar-project.properties` — SonarQube configuration
- `pipeline/scripts/security-gate.sh` — the aggregation script
- Cosign keys and signing workflow
- OPA Gatekeeper ConstraintTemplates and Constraints
- Falco custom rules
- HashiCorp Vault policies, roles, and Agent Injector annotations
- Kubernetes NetworkPolicies
- Hardened Kustomize overlays (the `base/` here is the broken version)
- Prometheus configuration and Grafana dashboards
- OWASP ZAP scan configuration

If you find yourself adding a file and wondering whether it belongs in the
baseline or the solution — it's in the solution. The baseline is broken; you
are what fixes it.

---

## Success Criteria

See Section 9 of the project brief. At the end of two weeks the expected
artefacts include a green 7-stage pipeline, zero committed secrets, zero
CRITICAL CVEs in any service image, zero CRITICAL Checkov findings, zero OPA
Gatekeeper violations, all application exploits in this README returning
400/403, Vault-injected secrets, Falco alerts triggering on intentional test
events, and signed images with SBOM attestations.

---

## Safety Notes

- Do not `terraform apply` the infrastructure module against a real AWS account.
  The IAM policies use `AdministratorAccess` and the RDS instances are publicly
  accessible. Checkov is supposed to catch that before it reaches AWS.
- The `.env` file contains canonical AWS example keys (`***REMOVED***`).
  They are not live credentials but they will trip every secret scanner you
  point at the repo — which is the exercise.
- When you rotate and remove secrets during remediation, remember that deleting
  a file in a later commit does **not** remove the secret from git history. See
  §4.1 of the brief.
