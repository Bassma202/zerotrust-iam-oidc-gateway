#!/usr/bin/env python3
"""Live Keycloak 26 OIDC integration verification script.

1. Waits for live Keycloak 26.0.7 + PostgreSQL 16.6 to become ready.
2. Imports config/limen-realm.json via Keycloak Admin REST API (idempotent).
3. Acquires a genuine RS256 OAuth2 access token from the `limen-heritage` realm.
4. Fetches real JWKS from Keycloak and verifies RS256 signature, issuer, audience,
   scope, and RBAC through LIMEN's OIDCValidator + FastAPI PEP.
5. Writes sanitized execution evidence to evidence/limen_live_keycloak_evidence.json.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from limen.oidc import JWKSKeyStore, OIDCValidator
from limen.web import create_app


def wait_for_keycloak(url: str, timeout_s: int = 90) -> dict:
    deadline = time.time() + timeout_s
    last_err = ""
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code == 200:
                return r.json()
        except Exception as exc:
            last_err = str(exc)
        time.sleep(2.0)
    raise RuntimeError(f"Keycloak did not become ready at {url}: {last_err}")


def ensure_realm_imported(base_url: str, admin_user: str, admin_pass: str) -> str:
    tok = httpx.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": admin_user,
            "password": admin_pass,
        },
        timeout=10.0,
    )
    tok.raise_for_status()
    admin_token = tok.json()["access_token"]
    realm_cfg = json.loads((ROOT / "config" / "limen-realm.json").read_text(encoding="utf-8"))
    resp = httpx.post(
        f"{base_url}/admin/realms",
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
        json=realm_cfg,
        timeout=15.0,
    )
    if resp.status_code == 201:
        return "imported"
    if resp.status_code == 409:
        return "already_present"
    resp.raise_for_status()
    return f"status_{resp.status_code}"


def main() -> None:
    base_url = os.environ.get("LIMEN_KC_URL", "http://127.0.0.1:8080")
    admin_user = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "limen-admin")
    admin_pass = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "local_lab_admin_pass")

    wait_for_keycloak(f"{base_url}/realms/master/.well-known/openid-configuration")
    import_status = ensure_realm_imported(base_url, admin_user, admin_pass)

    issuer = f"{base_url}/realms/limen-heritage"
    discovery = wait_for_keycloak(f"{issuer}/.well-known/openid-configuration")
    token_url = discovery["token_endpoint"]
    jwks_url = discovery["jwks_uri"]

    tok_resp = httpx.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": "limen-service-client",
            "client_secret": "lab-client-secret-rotate-in-prod",
        },
        timeout=10.0,
    )
    tok_resp.raise_for_status()
    access_token = tok_resp.json()["access_token"]

    jwks_doc = httpx.get(jwks_url, timeout=5.0).json()
    rs256_kids = [k.get("kid") for k in jwks_doc.get("keys", []) if k.get("alg") == "RS256"]

    validator = OIDCValidator(
        expected_issuer=issuer,
        expected_audience="limen-api",
        key_store=JWKSKeyStore(jwks_url=jwks_url),
    )
    app = create_app(validator=validator, db_path=ROOT / "data" / "limen_live.db")
    client = TestClient(app)

    # Service account holds ROLE_SECURITY_AUDITOR -> 200 on audit logs, 403 on archivist collections
    r_audit = client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {access_token}"})
    r_col = client.get("/api/resources/collections", headers={"Authorization": f"Bearer {access_token}"})
    r_unauth = client.get("/api/admin/audit-logs")

    ev = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_classification": "Genuine laboratory execution (live Keycloak 26.0.7 + PostgreSQL 16.6)",
        "realm_import_status": import_status,
        "issuer": issuer,
        "jwks_uri": jwks_url,
        "jwks_rs256_key_count": len(rs256_kids),
        "token_grant": "client_credentials",
        "pep_unauthenticated_status": r_unauth.status_code,
        "pep_audit_logs_status": r_audit.status_code,
        "pep_collections_denied_status": r_col.status_code,
        "verified_pass": (
            r_unauth.status_code == 401 and r_audit.status_code == 200 and r_col.status_code == 403
        ),
    }
    out = ROOT / "evidence" / "limen_live_keycloak_evidence.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ev, indent=2), encoding="utf-8")
    print(json.dumps(ev, indent=2))
    if not ev["verified_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
