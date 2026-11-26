# Threat Model & Security Architecture — LIMEN

## Trust Boundaries
- **TB1 — Asymmetric OIDC Token Verification (`src/limen/oidc.py`)**: Enforces `RS256`-only algorithm allowlist, rejects `HS256`/`none` confusion and attacker-controlled `jku`/`x5u` headers, verifies `iss`, `aud`, `exp`, `nbf`, `scope`, and rejects ID tokens presented as API access tokens. Supports automatic JWKS refresh on key rotation (`kid`).
- **TB2 — Backend Policy Enforcement Point (`src/limen/web.py`)**: Default-deny role, tenant, and resource-ownership checks protect `/api/resources/collections`, `/api/resources/research/{record_id}` (prevents horizontal IDOR), and `/api/admin/audit-logs` (prevents vertical privilege escalation).
- **TB3 — Preventive & Detective Governance (`src/limen/governance.py`)**: Direct + inherited entitlement expansion blocks conflicting SoD assignments during Joiner, Mover, and temporary grant workflows. Leaver disables identity, strips roles/grants, and immediately registers the subject in the PEP denylist.

## Local Development vs. Hardened Deployment
- `docker-compose.yml` uses Keycloak `start-dev` bound strictly to `127.0.0.1:8080` for local laboratory verification. Production deployments must run Keycloak `start` behind TLS with external PostgreSQL backups, KMS-managed secrets, and non-default admin credentials.
- Stateless JWTs issued before a Leaver event remain cryptographically valid until `exp` unless checked against a low-latency revocation store/denylist; LIMEN pairs short `300s` access-token lifetimes with PEP subject/JTI denylisting.
