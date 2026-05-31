# Day 6 Notes — HashiCorp Vault Integration

## Dev mode vs production Vault

Today we run Vault with `server.dev.enabled=true`. Dev mode is designed for
learning and local testing, and is explicitly NOT for production. The
differences matter:

### Storage
- **Dev mode:** all data is in-memory only. When the Vault pod restarts,
  every secret, policy, and auth config is GONE. Nothing persists.
- **Production:** uses a durable storage backend (Integrated Storage / Raft,
  or Consul). Data survives restarts and is replicated across a cluster.

### Sealing / unsealing
- **Dev mode:** Vault starts already unsealed, with a single known root token
  (we set it to "root"). No unseal step.
- **Production:** Vault starts SEALED. The master key is split via Shamir's
  Secret Sharing into N key shares; M of them are required to unseal. This
  means no single operator can unseal Vault alone. Auto-unseal can delegate
  this to a cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) so pods can restart
  without manual intervention.

### Root token
- **Dev mode:** a single, known, all-powerful root token printed at startup.
- **Production:** the initial root token is generated once during
  initialisation, used to bootstrap auth methods and policies, then REVOKED.
  Day-to-day access uses scoped tokens from auth methods (Kubernetes, OIDC,
  AppRole), never the root token.

### TLS
- **Dev mode:** serves plain HTTP on 8200. No TLS.
- **Production:** TLS-only, with proper certs. Secrets never traverse the
  network in plaintext.

### Audit
- **Dev mode:** audit devices are NOT enabled by default (we enable one
  manually today to capture the access log for the deliverable).
- **Production:** at least one audit device is mandatory and typically
  shipped to a SIEM. Every secret access is logged (request + response,
  with sensitive values HMAC'd).

## Why dev mode is acceptable for THIS engagement
SecureFlow's Vault work is demonstrating the *integration pattern* — how
services authenticate to Vault via Kubernetes ServiceAccounts, how per-service
policies enforce least-privilege path access, and how the Agent Injector
mounts secrets as files instead of env vars. That pattern is identical in dev
and production; only the operational hardening (storage, unseal, TLS, audit
shipping) differs. Production hardening is noted as a Week-2-polish / future
item, consistent with the engagement's staged approach.

## The CK-09 connection
The current K8s manifests store secrets in a ConfigMap (base/configmap.yaml) —
this is exactly the CK-09 finding Trivy flagged (KSV-0109). Today's Vault
integration is the REMEDIATION for CK-09: secrets move out of the ConfigMap
into Vault, injected at runtime as files. CK-09 is DevSecOps-owned, so this
fix is in scope.