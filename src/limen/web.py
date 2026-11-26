"""LIMEN FastAPI Policy Enforcement Point (PEP), Protected Resource APIs, and Governance UI."""

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
    {"id": "COL-003", "title": "Partner Museum Loan Ledger (Tenant: Louvre-Partner)", "classification": "CONFIDENTIAL", "tenant": "partner-museum"},
]

SAMPLE_RESEARCH = {
    "RES-101": {"id": "RES-101", "owner": "alice.researcher", "title": "Multispectral Ink Analysis", "tenant": "heritage-core"},
    "RES-102": {"id": "RES-102", "owner": "bob.researcher", "title": "Optical Mirror Thermal Calibration", "tenant": "heritage-core"},
}


def seed_default_identities(gov: GovernanceEngine) -> None:
    if gov.list_identities():
        return
    gov.joiner("alice.researcher", "alice.researcher", "Scientific Research", "employee", ["ROLE_RESEARCHER"], owner="Research Director")
    gov.joiner("bob.researcher", "bob.researcher", "Scientific Research", "employee", ["ROLE_RESEARCHER"], direct_entitlements=["catalog:search"], owner="Research Director")
    gov.joiner("claire.archivist", "claire.archivist", "Manuscript Archive", "employee", ["ROLE_ARCHIVIST"], owner="Chief Archivist")
    gov.joiner("david.archivist", "david.archivist", "Manuscript Archive", "employee", ["ROLE_ARCHIVIST"], direct_entitlements=["research:read"], owner="Chief Archivist")
    gov.joiner("elena.restorer", "elena.restorer", "External Restoration", "contractor", ["ROLE_CONTRACTOR_RESTORER"], owner="Conservation Lead")
    gov.joiner("farid.auditor", "farid.auditor", "Internal Audit", "auditor", ["ROLE_SECURITY_AUDITOR"], owner="Audit Committee")
    gov.joiner("nadia.admin", "nadia.admin", "IAM Operations", "administrator", ["ROLE_ADMIN"], owner="CISO")


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

    app = FastAPI(title="LIMEN — Zero-Trust Identity Security & Access Governance", version="2.0.0")
    app.state.validator = validator
    app.state.gov = gov

    def require_principal(authorization: str | None = Header(default=None)) -> VerifiedPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer access token.")
        token = authorization.split(" ", 1)[1].strip()
        try:
            return validator.validate_access_token(token, required_scope="limen:api")
        except TokenValidationError as exc:
            raise HTTPException(status_code=401, detail=f"{exc.code}: {exc.detail}") from exc

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "limen-iam", "version": "2.0.0"}

    @app.get("/api/resources/collections")
    def get_collections(principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        # Default-deny: must hold a permitted collection role
        allowed_roles = {"ROLE_ARCHIVIST", "ROLE_RESEARCHER", "ROLE_ADMIN", "ROLE_CONTRACTOR_RESTORER"}
        if not (principal.roles & allowed_roles):
            raise HTTPException(status_code=403, detail="Access denied: insufficient role for archive collections.")
        visible = []
        for col in SAMPLE_COLLECTIONS:
            if col["tenant"] != principal.tenant and "ROLE_ADMIN" not in principal.roles:
                continue
            if col["classification"] == "RESTRICTED" and not (principal.roles & {"ROLE_ARCHIVIST", "ROLE_ADMIN"}):
                continue
            visible.append(col)
        return {"principal": principal.username, "tenant": principal.tenant, "collections": visible}

    @app.get("/api/resources/research/{record_id}")
    def get_research_record(record_id: str, principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        rec = SAMPLE_RESEARCH.get(record_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Research record not found.")
        # Resource-level ownership check prevents horizontal privilege escalation (IDOR)
        if rec["owner"] != principal.username and "ROLE_ADMIN" not in principal.roles:
            raise HTTPException(status_code=403, detail="Horizontal access violation: record belongs to another researcher.")
        return rec

    @app.get("/api/admin/audit-logs")
    def get_audit_logs(principal: VerifiedPrincipal = Depends(require_principal)) -> dict[str, Any]:
        if not (principal.roles & {"ROLE_SECURITY_AUDITOR", "ROLE_ADMIN"}):
            raise HTTPException(status_code=403, detail="Vertical access violation: auditor or admin role required.")
        return {"events": gov.list_audit(limit=50)}

    @app.get("/api/governance/summary")
    def governance_summary() -> dict[str, Any]:
        idents = gov.list_identities()
        ent_map = {i["username"]: set(i["effective_entitlements"]) for i in idents if i["status"] == "ACTIVE"}
        mining = mine_candidate_roles(ent_map)
        return {
            "identity_count": len(idents),
            "active_identities": sum(1 for i in idents if i["status"] == "ACTIVE"),
            "sod_conflict_total": sum(len(i["sod_conflicts"]) for i in idents),
            "role_mining": mining,
            "identities": idents,
        }

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        s = governance_summary()
        rm = s["role_mining"]
        id_rows = "".join(
            f"<tr><td><code>{i['username']}</code></td><td>{i['department']}</td><td>{i['identity_type']}</td>"
            f"<td><span class='badge st-{i['status'].lower()}'>{i['status']}</span></td>"
            f"<td>{', '.join(i['roles']) or 'None'}</td><td>{len(i['effective_entitlements'])}</td></tr>"
            for i in s["identities"]
        )
        role_rows = "".join(
            f"<tr><td><code>{r['role_name']}</code></td><td>{', '.join(r['members'])}</td>"
            f"<td>{', '.join(r['core_entitlements'])}</td><td>Pending Approval</td></tr>"
            for r in rm["candidate_roles"]
        ) or "<tr><td colspan='4'>No clusters discovered.</td></tr>"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LIMEN — Zero-Trust Identity Security &amp; Access Governance</title>
<style>
  :root {{ --bg:#F3F5F4; --surface:#FFFFFF; --slate:#26323B; --green:#243B35; --metal:#8B98A4; --ink:#1A2226; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg); color:var(--ink); }}
  header {{ background:var(--slate); color:#EAE5DA; padding:22px 32px; border-bottom:3px solid var(--green); }}
  header h1 {{ font-size:20px; letter-spacing:1.2px; }}
  header p {{ font-size:13px; color:#B8C3CC; margin-top:4px; }}
  main {{ max-width:1160px; margin:24px auto; padding:0 24px 40px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-bottom:22px; }}
  .card {{ background:var(--surface); border:1px solid #D6DCDC; padding:16px; }}
  .label {{ font-size:11px; text-transform:uppercase; letter-spacing:0.8px; color:#5A666E; }}
  .val {{ font-size:22px; font-weight:700; color:var(--green); margin-top:6px; }}
  section {{ background:var(--surface); border:1px solid #D6DCDC; padding:18px 20px; margin-bottom:20px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:0.8px; color:var(--slate); border-bottom:1px solid #E4E9E9; padding-bottom:6px; margin-bottom:12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #ECF0F0; }}
  th {{ font-size:11px; text-transform:uppercase; color:#5A666E; background:#F8FAFA; }}
  .badge {{ padding:2px 7px; font-size:11px; font-weight:600; border-radius:2px; }}
  .st-active {{ background:#E3F0EB; color:var(--green); }}
  .st-disabled {{ background:#F4E5E7; color:#6D2832; }}
</style>
</head>
<body>
  <header>
    <h1>LIMEN — Zero-Trust Identity Security &amp; Access Governance</h1>
    <p>RS256 JWKS Policy Enforcement · Joiner/Mover/Leaver · Preventive SoD · Jaccard Role Mining</p>
  </header>
  <main>
    <div class="grid">
      <div class="card"><div class="label">Managed Identities</div><div class="val">{s['identity_count']}</div></div>
      <div class="card"><div class="label">Active Identities</div><div class="val">{s['active_identities']}</div></div>
      <div class="card"><div class="label">Active SoD Conflicts</div><div class="val">{s['sod_conflict_total']}</div></div>
      <div class="card"><div class="label">Role-Mining Coverage</div><div class="val">{rm['metrics']['entitlement_coverage_pct']}%</div></div>
    </div>
    <section>
      <h2>Identity Directory &amp; Effective Entitlements</h2>
      <table>
        <thead><tr><th>Username</th><th>Department</th><th>Type</th><th>Status</th><th>Roles</th><th>Entitlements</th></tr></thead>
        <tbody>{id_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Jaccard Role-Mining Candidate Recommendations (Human Approval Required)</h2>
      <table>
        <thead><tr><th>Candidate Role</th><th>Cluster Members</th><th>Core Least-Privilege Entitlements</th><th>Status</th></tr></thead>
        <tbody>{role_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""

    return app


app = create_app()
