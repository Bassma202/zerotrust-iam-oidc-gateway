# LIMEN — Zero-Trust Identity Security & Access Governance

**Repository:** `https://github.com/Bassma202/zerotrust-iam-oidc-gateway`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
LIMEN is a Zero-Trust Identity & Access Management (IAM) and Identity Governance (IGA) engineering platform built around live Keycloak 26 OIDC/JWKS federation, strict RS256 audience/client-scoped policy enforcement, fail-closed tenant claims, persistent JML revocation integrated directly into PEP runtime decisions, atomic transactional Segregation of Duties (SoD), and explainable Jaccard role mining.

## 2. Implemented Capabilities
- **Live Keycloak 26.0.7 + PostgreSQL 16.6 Stack (`docker-compose.yml`, `config/limen-realm.json`):** Reproducible `limen-heritage` realm with PKCE S256 public SPA client (`limen-web-pkce`), confidential service client (`limen-service-client`), custom `limen-api` audience protocol mapper, `limen-tenant-claim` (`heritage-core`) mapper, and `300s` short-lived access tokens. Zero hardcoded database/admin passwords in Compose.
- **Client-Scoped RS256/JWKS Token Verification & Fail-Closed Tenant Enforcement (`src/limen/oidc.py`):**
  - Validates `RS256` signatures via trusted JWKS with `kid` key-rotation refresh, `iss`, `aud`, `exp`, `nbf`, required `scope`, token-type separation (rejecting ID tokens on APIs), and JTI/subject revocation.
  - Restricts `resource_access` role extraction strictly to `trusted_resource_client` (`limen-api`) plus an explicit `KNOWN_LIMEN_ROLES` realm allowlist—roles on unrelated OAuth clients are ignored.
  - Rejects missing, empty, unknown, or ambiguous multi-valued `tenant` claims fail-closed (`401`).
- **Protected Resource & Governance APIs with Live Persistent JML Enforcement (`src/limen/web.py`, `src/limen/governance.py`):**
  - `/api/governance/summary` requires RS256 Bearer authentication, auditor/admin role, and tenant scoping; public `/` landing page strips directory PII.
  - Research records are keyed by immutable `(owner_sub, tenant)` so colliding usernames across tenants remain isolated (`403`).
  - `require_principal()` checks live persistent SQLite `GovernanceEngine` state on every request so `leaver()` deactivation and `revoke_role()` take effect immediately across restarts and multiple workers.
- **Transactional JML, Temporary Grants & Cumulative SoD (`src/limen/governance.py`):** Wraps Joiner/Mover/Leaver transitions and `grant_temporary_access()` in atomic SQLite `BEGIN IMMEDIATE` transactions evaluating cumulative SoD across permanent roles, direct entitlements, and ALL active temporary grants (`SOD-001` request/approve, `SOD-002` admin/audit, `SOD-003` contractor/vault-write)—preventing concurrent conflicting grant races.
- **Explainable Jaccard Role Mining (`src/limen/role_mining.py`):** Computes user-entitlement Jaccard clusters using core intersection (zero over-assignment), reporting baseline vs. post-mining coverage, redundancy reduction, and an overprivilege review queue requiring human approval.

## 3. Quick Start & Reproduction
```bash
cp .env.example .env   # Set local lab passwords
make setup
make test
make security
make up-idp            # Boots Keycloak 26 + PostgreSQL 16 on 127.0.0.1:8080
make verify-idp        # Executes live RS256 token acquisition & PEP verification
make down-idp          # Clean teardown
make up                # Launches LIMEN governance UI on http://127.0.0.1:8004
```

## 4. Known Limitations
- Local laboratory Compose uses Keycloak `start-dev` over loopback (`127.0.0.1:8080`); TLS termination and production build optimizations are documented separately in `docs/THREAT_MODEL.md`.
- Real-time revocation of stateless access tokens requires either short token lifetimes (`300s`), token introspection, or the persistent governance-backed PEP check implemented here.

## 5. License
MIT License.
