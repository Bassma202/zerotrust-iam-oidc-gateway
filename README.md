# LIMEN — Zero-Trust Identity Security & Access Governance

**Repository:** `https://github.com/Bassma202/zerotrust-iam-oidc-gateway`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
LIMEN is a Zero-Trust Identity & Access Management (IAM) and Identity Governance (IGA) engineering platform built around live Keycloak 26 OIDC/JWKS federation, asymmetric RS256 policy enforcement, Joiner/Mover/Leaver lifecycle controls, time-limited contractor grants, preventive Segregation of Duties (SoD), and explainable Jaccard role mining.

## 2. Implemented Capabilities
- **Live Keycloak 26.0.7 + PostgreSQL 16.6 Stack (`docker-compose.yml`, `config/limen-realm.json`)**: Reproducible `limen-heritage` realm with PKCE S256 public SPA client (`limen-web-pkce`), confidential service client (`limen-service-client`), custom `limen-api` audience protocol mapper, and `300s` short-lived access tokens. Zero hardcoded database/admin passwords in Compose.
- **Asymmetric RS256/JWKS Token Verification (`src/limen/oidc.py`)**: Eliminates hardcoded symmetric secrets; validates `RS256` signatures via trusted JWKS with `kid` key-rotation refresh, `iss`, `aud`, `exp`, `nbf`, required `scope`, token-type separation (rejecting ID tokens on APIs), and JTI/subject revocation.
- **Real Protected Resource APIs (`src/limen/web.py`)**: Enforces default-deny RBAC, multi-tenant collection scoping, resource-level ownership checks (horizontal IDOR prevention), and auditor/admin route separation (vertical escalation prevention).
- **Joiner / Mover / Leaver & Temporary Contractor Grants (`src/limen/governance.py`)**: Joiner provisioning with preventive SoD, Mover stale-entitlement stripping, Leaver immediate access revocation, and TTL-enforced temporary contractor grants.
- **Direct + Inherited SoD Engine (`src/limen/governance.py`)**: Expands role-to-entitlement inheritance to block toxic combinations (`SOD-001` request/approve, `SOD-002` admin/audit, `SOD-003` contractor/vault-write).
- **Explainable Jaccard Role Mining (`src/limen/role_mining.py`)**: Computes user-entitlement Jaccard clusters using core intersection (zero over-assignment), reporting baseline vs. post-mining coverage, redundancy reduction, and an overprivilege review queue requiring human approval.
- **Governance Web UI (`src/limen/web.py`)**: Live directory, SoD status, and role-mining recommendations backed by SQLite (`data/limen.db`).

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
- Real-time revocation of stateless access tokens requires either short token lifetimes (`300s`), token introspection, or the PEP denylist implemented here.

## 5. License
MIT License.
