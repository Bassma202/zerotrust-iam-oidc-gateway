"""LIMEN FastAPI Policy Enforcement Point (PEP), Protected Resource APIs, and Governance UI (LIMEN-03, LIMEN-04)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from limen.governance import GovernanceEngine
from limen.oidc import JWKSKeyStore, OIDCValidator, TokenValidationError, VerifiedPrincipal
from limen.role_mining import mine_candidate_roles

SAMPLE_COLLECTIONS = [
    {"id": "COL-001", "title": "14th-Century Astrolabe Diagrams (Public Archive)", "classification": "INTERNAL", "tenant": "heritage-core"},
    {"id": "COL-002", "title": "Restricted Restoration Blueprints — Vault B", "classification": "RESTRICTED", "tenant": "heritage-core"},
    {"id": "COL-003", "title": "Partner Museum Loan Ledger (Tenant: Partner-Museum)", "classification": "CONFIDENTIAL", "tenant": "partner-museum"},
]

# Object-level ownership keyed strictly by immutable subject ID (`owner_sub`) + `tenant` (LIMEN-03)
SAMPLE_RESEARCH = {
    "RES-101": {"id": "RES-101", "owner_sub": "sub-alice-core", "title": "Multispectral Ink Analysis", "tenant": "heritage-core"},
    "RES-102": {"id": "RES-102", "owner_sub": "sub-bob-core", "title": "Optical Mirror Thermal Calibration", "tenant": "heritage-core"},
    "RES-201": {"id": "RES-201", "owner_sub": "sub-alice-partner", "title": "Partner Museum Provenance Dossier", "tenant": "partner-museum"},
}


def seed_default_identities(gov: GovernanceEngine) -> None:
    if gov.list_identities():
        return
    gov.joiner("sub-alice-core", "alice.researcher", "Scientific Research", "employee", ["ROLE_RESEARCHER"], owner="Research Director", tenant="heritage-core")
    gov.joiner("sub-bob-core", "bob.researcher", "Scientific Research", "employee", ["ROLE_RESEARCHER"], direct_entitlements=["catalog:search"], owner="Research Director", tenant="heritage-core")
    gov.joiner("sub-claire-core", "claire.archivist", "Manuscript Archive", "employee", ["ROLE_ARCHIVIST"], owner="Chief Archivist", tenant="heritage-core")
    gov.joiner("sub-david-core", "david.archivist", "Manuscript Archive", "employee", ["ROLE_ARCHIVIST"], direct_entitlements=["research:read"], owner="Chief Archivist", tenant="heritage-core")
    gov.joiner("sub-elena-core", "elena.restorer", "External Restoration", "contractor", ["ROLE_CONTRACTOR_RESTORER"], owner="Conservation Lead", tenant="heritage-core")
    gov.joiner("sub-farid-core", "farid.auditor", "Internal Audit", "auditor", ["ROLE_SECURITY_AUDITOR"], owner="Audit Committee", tenant="heritage-core")
    gov.joiner("sub-nadia-admin", "nadia.admin", "IAM Operations", "administrator", ["ROLE_ADMIN"], owner="CISO", tenant="heritage-core")
    gov.joiner("sub-alice-partner", "alice.researcher", "Partner Conservation", "employee", ["ROLE_RESEARCHER"], owner="Partner Director", tenant="partner-museum")


def create_app(
    validator: OIDCValidator | None = None,
    db_path: str | Path | None = None,
    seed: bool = True,
) -> FastAPI:
    gov = GovernanceEngine(db_path or os.getenv("LIMEN_DB_PATH", "data/limen.db"))
    if seed:
        seed_default_identities(gov)

    if validator is None:
        issuer = os.getenv("LIMEN_OIDC_ISSUER", "http://127.0.0.1:8080/realms/limen-heritage")
        audience = os.getenv("LIMEN_OIDC_AUDIENCE", "limen-api")
        jwks_url = os.getenv("LIMEN_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
        validator = OIDCValidator(expected_issuer=issuer, expected_audience=audience, key_store=JWKSKeyStore(jwks_url=jwks_url))

    app = FastAPI(title="LIMEN — Zero-Trust Identity Security & Access Governance", version="2.1.0")
    app.state.validator = validator
    app.state.gov = gov

    def require_principal(authorization: str | None = Header(default=None)) -> VerifiedPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer access token.")
        token = authorization.split(" ", 1)[1].strip()
        try:
            principal = validator.validate_access_token(token, required_scope="limen:api")
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=f"{exc.code}: {exc.detail}") from exc

        # LIMEN-04: Persistent SQLite identity lifecycle enforcement across restarts & workers
        persisted = gov.get_identity(principal.subject)
        if persisted is not None:
            if persisted["status"] != "ACTIVE":
                raise HTTPException(status_code=401, detail="IDENTITY_DISABLED: Subject deactivated in persistent governance store.")
            if persisted["tenant"] != principal.tenant:
                raise HTTPException(status_code=403, detail="TENANT_MISMATCH: Token tenant conflicts with authoritative directory membership.")
            # Intersect token roles with currently active persisted governance roles so revocations apply immediately
            effective_roles = principal.roles & set(persisted["roles"])
            principal = VerifiedPrincipal(
                subject=principal.subject,
                username=principal.username,
                roles=effective_roles,
                scopes=principal.scopes,
                tenant=persisted["tenant"],
                jti=principal.jti,
                expires_at=principal.expires_at,
                raw_claims=principal.raw_claims,
            )
        return principal

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "limen-iam", "version": "2.1.0"}

    @app.get("/api/resources/collections")
    def get_collections(principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        allowed_roles = {"ROLE_ARCHIVIST", "ROLE_RESEARCHER", "ROLE_ADMIN", "ROLE_CONTRACTOR_RESTORER"}
        if not (principal.roles & allowed_roles):
            raise HTTPException(status_code=403, detail="Access denied: insufficient role for archive collections.")
        visible = []
        for col in SAMPLE_COLLECTIONS:
            if col["tenant"] != principal.tenant:
                continue
            if col["classification"] == "RESTRICTED" and not (principal.roles & {"ROLE_ARCHIVIST", "ROLE_ADMIN"}):
                continue
            visible.append(col)
        return {"subject": principal.subject, "tenant": principal.tenant, "collections": visible}

    @app.get("/api/resources/research/{record_id}")
    def get_research_record(record_id: str, principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        rec = SAMPLE_RESEARCH.get(record_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Research record not found.")
        if rec["tenant"] != principal.tenant:
            raise HTTPException(status_code=403, detail="Cross-tenant research record access denied.")
        if rec["owner_sub"] != principal.subject and "ROLE_ADMIN" not in principal.roles:
            raise HTTPException(status_code=403, detail="Horizontal access violation: record belongs to another subject.")
        return rec

    @app.get("/api/admin/audit-logs")
    def get_audit_logs(principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        if not (principal.roles & {"ROLE_SECURITY_AUDITOR", "ROLE_ADMIN"}):
            raise HTTPException(status_code=403, detail="Vertical access violation: auditor or admin role required.")
        return {"subject": principal.subject, "tenant": principal.tenant, "events": gov.list_audit(limit=50)}

    @app.get("/api/governance/summary")
    def governance_summary(principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        """LIMEN-03: Governance directory & role-mining summary requires authenticated auditor/admin role & tenant scope."""
        if not (principal.roles & {"ROLE_SECURITY_AUDITOR", "ROLE_ADMIN"}):
            raise HTTPException(status_code=403, detail="Governance summary requires ROLE_SECURITY_AUDITOR or ROLE_ADMIN.")
        idents = gov.list_identities(tenant=principal.tenant)
        ent_map = {i["user_id"]: set(i["effective_entitlements"]) for i in idents if i["status"] == "ACTIVE"}
        mining = mine_candidate_roles(ent_map)
        return {
            "tenant": principal.tenant,
            "identity_count": len(idents),
            "active_identities": sum(1 for i in idents if i["status"] == "ACTIVE"),
            "sod_conflict_total": sum(len(i["sod_conflicts"]) for i in idents),
            "role_mining": mining,
            "identities": idents,
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        # Public landing page exposes ONLY non-sensitive aggregate counts (zero directory/PII exposure without auth)
        idents = gov.list_identities()
        active_count = sum(1 for i in idents if i["status"] == "ACTIVE")
        sod_count = sum(len(i["sod_conflicts"]) for i in idents)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LIMEN — Zero-Trust Identity Security &amp; Access Governance</title>
<style>
  :root {{ --bg:#F3F5F4; --surface:#FFFFFF; --slate:#26323B; --green:#243B35; --ink:#1A2226; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg); color:var(--ink); }}
  header {{ background:var(--slate); color:#EAE5DA; padding:22px 32px; border-bottom:3px solid var(--green); }}
  header h1 {{ font-size:20px; letter-spacing:1.2px; }}
  header p {{ font-size:13px; color:#B8C3CC; margin-top:4px; }}
  main {{ max-width:980px; margin:24px auto; padding:0 24px 40px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:22px; }}
  .card {{ background:var(--surface); border:1px solid #D6DCDC; padding:16px; }}
  .label {{ font-size:11px; text-transform:uppercase; letter-spacing:0.8px; color:#5A666E; }}
  .val {{ font-size:22px; font-weight:700; color:var(--green); margin-top:6px; }}
  section {{ background:var(--surface); border:1px solid #D6DCDC; padding:18px 20px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:0.8px; color:var(--slate); border-bottom:1px solid #E4E9E9; padding-bottom:6px; margin-bottom:12px; }}
  p {{ font-size:13px; line-height:1.6; color:#334155; }}
</style>
</head>
<body>
  <header>
    <h1>LIMEN — Zero-Trust Identity Security &amp; Access Governance</h1>
    <p>RS256 JWKS Policy Enforcement · Verified Tenant Isolation · Persistent JML Revocation · Cumulative SoD</p>
  </header>
  <main>
    <div class="grid">
      <div class="card"><div class="label">Managed Identities</div><div class="val">{len(idents)}</div></div>
      <div class="card"><div class="label">Active Identities</div><div class="val">{active_count}</div></div>
      <div class="card"><div class="label">Active SoD Conflicts</div><div class="val">{sod_count}</div></div>
    </div>
    <section>
      <h2>Protected API Endpoints (RS256 Bearer OIDC Token Required)</h2>
      <p>Directory details, role-mining recommendations, research dossiers, and audit trails are protected behind
      RS256/JWKS authentication, verified tenant membership, and persistent SQLite lifecycle revocation at
      <code>/api/governance/summary</code>, <code>/api/resources/collections</code>,
      <code>/api/resources/research/{{record_id}}</code>, and <code>/api/admin/audit-logs</code>.</p>
    </section>
  </main>
</body>
</html>"""

    return app


app = create_app()
