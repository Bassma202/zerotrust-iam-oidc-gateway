"""Comprehensive LIMEN security & governance test suite & remediation regressions (LIMEN-01 through LIMEN-06)."""

from __future__ import annotations

import concurrent.futures
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from limen.governance import GovernanceEngine
from limen.oidc import JWKSKeyStore, OIDCValidator
from limen.role_mining import mine_candidate_roles
from limen.web import create_app


def _make_rsa_keypair(kid: str) -> tuple[rsa.RSAPrivateKey, dict]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return priv, jwk


def _issue_token(
    priv: rsa.RSAPrivateKey,
    kid: str,
    sub: str,
    username: str,
    roles: list[str] | None = None,
    resource_access: dict | None = None,
    iss: str = "http://127.0.0.1:8080/realms/limen-heritage",
    aud: str = "limen-api",
    scope: str = "openid limen:api",
    exp_offset: int = 300,
    typ: str = "Bearer",
    tenant: str | list[str] | None = "heritage-core",
    extra_headers: dict | None = None,
) -> str:
    now = int(time.time())
    payload: dict = {
        "iss": iss,
        "sub": sub,
        "preferred_username": username,
        "aud": aud,
        "exp": now + exp_offset,
        "iat": now,
        "nbf": now - 1,
        "typ": typ,
        "scope": scope,
        "jti": f"jti-{sub}-{now}",
    }
    if tenant is not None:
        payload["tenant"] = tenant
    if roles is not None:
        payload["realm_access"] = {"roles": roles}
    if resource_access is not None:
        payload["resource_access"] = resource_access
    headers = {"kid": kid, **(extra_headers or {})}
    return jwt.encode(payload, priv, algorithm="RS256", headers=headers)


def test_limen01_02_03_oidc_role_contract_tenant_fail_closed_and_endpoint_authz(tmp_path: Path) -> None:
    """LIMEN-01, 02, 03: Reject unrelated client roles, fail closed on missing/unknown/ambiguous tenant, enforce subject+tenant authz."""
    priv1, jwk1 = _make_rsa_keypair("key-v1")
    priv2, jwk2 = _make_rsa_keypair("key-v2")
    ks = JWKSKeyStore(static_jwks={"keys": [jwk1]})
    validator = OIDCValidator("http://127.0.0.1:8080/realms/limen-heritage", "limen-api", ks)
    client = TestClient(create_app(validator=validator, db_path=tmp_path / "limen.db"))

    # LIMEN-01: ROLE_ADMIN assigned ONLY on an unrelated OAuth client MUST NOT grant admin access to limen-api
    unrelated_tok = _issue_token(
        priv1, "key-v1", "sub-external-svc", "ext-svc",
        roles=[],
        resource_access={"unrelated-billing-app": {"roles": ["ROLE_ADMIN", "ROLE_SECURITY_AUDITOR"]}},
    )
    assert client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {unrelated_tok}"}).status_code == 403

    # Role assigned on the trusted resource client (`limen-api`) DOES grant access
    trusted_client_tok = _issue_token(
        priv1, "key-v1", "sub-trusted-svc", "svc",
        roles=[],
        resource_access={"limen-api": {"roles": ["ROLE_SECURITY_AUDITOR"]}},
    )
    assert client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {trusted_client_tok}"}).status_code == 200

    # LIMEN-02: Missing, unknown, or ambiguous multi-valued tenant claims MUST fail closed (401)
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice.researcher', ['ROLE_RESEARCHER'], tenant=None)}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice.researcher', ['ROLE_RESEARCHER'], tenant='rogue-tenant')}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice.researcher', ['ROLE_RESEARCHER'], tenant=['heritage-core', 'partner-museum'])}"}).status_code == 401

    # LIMEN-03: /api/governance/summary requires authenticated auditor/admin (anonymous -> 401, researcher -> 403)
    alice_core = _issue_token(priv1, "key-v1", "sub-alice-core", "alice.researcher", ["ROLE_RESEARCHER"], tenant="heritage-core")
    alice_partner = _issue_token(priv1, "key-v1", "sub-alice-partner", "alice.researcher", ["ROLE_RESEARCHER"], tenant="partner-museum")
    assert client.get("/api/governance/summary").status_code == 401
    assert client.get("/api/governance/summary", headers={"Authorization": f"Bearer {alice_core}"}).status_code == 403

    # Same username ("alice.researcher") in DIFFERENT tenants cannot access each other's research records!
    assert client.get("/api/resources/research/RES-101", headers={"Authorization": f"Bearer {alice_core}"}).status_code == 200
    assert client.get("/api/resources/research/RES-101", headers={"Authorization": f"Bearer {alice_partner}"}).status_code == 403
    assert client.get("/api/resources/research/RES-201", headers={"Authorization": f"Bearer {alice_partner}"}).status_code == 200
    assert client.get("/api/resources/research/RES-201", headers={"Authorization": f"Bearer {alice_core}"}).status_code == 403
    assert client.get("/api/resources/research/RES-102", headers={"Authorization": f"Bearer {alice_core}"}).status_code == 403

    # Negative cryptographic checks (expired, bad iss, bad aud, bad scope, ID token, HS256, jku)
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], exp_offset=-60)}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], iss='https://evil.example')}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], aud='other-api')}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], scope='openid')}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], typ='ID')}"}).status_code == 401
    hs_tok = jwt.encode({"sub": "sub-alice-core", "aud": "limen-api", "exp": int(time.time()) + 300}, "weak", algorithm="HS256")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {hs_tok}"}).status_code == 401
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {_issue_token(priv1, 'key-v1', 'sub-alice-core', 'alice', ['ROLE_RESEARCHER'], extra_headers={'jku': 'https://evil.example/j'})}"}).status_code == 401

    # Key rotation + auditor governance summary
    ks.update_static_jwks({"keys": [jwk1, jwk2]})
    aud_tok = _issue_token(priv2, "key-v2", "sub-farid-core", "farid.auditor", ["ROLE_SECURITY_AUDITOR"], tenant="heritage-core")
    r_gov = client.get("/api/governance/summary", headers={"Authorization": f"Bearer {aud_tok}"})
    assert r_gov.status_code == 200
    assert r_gov.json()["tenant"] == "heritage-core"


def test_limen04_and_05_persistent_revocation_across_workers_and_cumulative_sod(tmp_path: Path) -> None:
    """LIMEN-04 & LIMEN-05: Persistent revocation survives restart/workers; cumulative temp grants trigger atomic SoD."""
    priv, jwk = _make_rsa_keypair("k1")
    ks = JWKSKeyStore(static_jwks={"keys": [jwk]})
    db = tmp_path / "limen_shared.db"

    app_worker1 = create_app(validator=OIDCValidator("http://127.0.0.1:8080/realms/limen-heritage", "limen-api", ks), db_path=db, seed=False)
    app_worker2 = create_app(validator=OIDCValidator("http://127.0.0.1:8080/realms/limen-heritage", "limen-api", ks), db_path=db, seed=False)
    gov: GovernanceEngine = app_worker1.state.gov
    c1, c2 = TestClient(app_worker1), TestClient(app_worker2)

    # Preventive SoD on Joiner
    try:
        gov.joiner("sub-bad", "bad.user", "IT", "employee", ["ROLE_ADMIN", "ROLE_SECURITY_AUDITOR"])
        assert False, "Expected SOD-002 block"
    except ValueError as exc:
        assert "SOD-002" in str(exc)

    # LIMEN-05: Two individually acceptable temporary entitlements that conflict cumulatively (SOD-001)
    gov.joiner("sub-worker", "worker.one", "Ops", "employee", ["ROLE_RESEARCHER"])
    gov.grant_temporary_access("sub-worker", "access:request", approved_by="sub-nadia-admin", ttl_seconds=120)
    try:
        gov.grant_temporary_access("sub-worker", "access:approve", approved_by="sub-nadia-admin", ttl_seconds=120)
        assert False, "Expected cumulative SOD-001 block on second temporary entitlement"
    except ValueError as exc:
        assert "SOD-001" in str(exc)

    # Concurrent conflicting temporary grants on fresh identity -> strictly AT MOST ONE succeeds!
    gov.joiner("sub-race", "race.user", "Ops", "employee", ["ROLE_RESEARCHER"])

    def _grant(ent: str) -> str:
        try:
            gov.grant_temporary_access("sub-race", ent, approved_by="sub-nadia-admin", ttl_seconds=120)
            return "GRANTED"
        except ValueError:
            return "BLOCKED_SOD"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        outcomes = list(ex.map(_grant, ["access:request", "access:approve"]))
    assert outcomes.count("GRANTED") == 1 and outcomes.count("BLOCKED_SOD") == 1

    # Mover strips old roles AND revokes old temporary grants
    gov.mover("sub-worker", "Archive", ["ROLE_ARCHIVIST"])
    assert gov.active_temp_entitlements("sub-worker") == []

    # Temp expiry check
    gov.grant_temporary_access("sub-worker", "access:request", approved_by="sub-nadia-admin", ttl_seconds=60)
    assert "access:request" not in gov.active_temp_entitlements("sub-worker", now=datetime.now(timezone.utc) + timedelta(seconds=120))

    # LIMEN-04: Role revocation and Leaver deactivation enforced immediately on WORKER 2 (no shared in-memory set!)
    tok = _issue_token(priv, "k1", "sub-worker", "worker.one", ["ROLE_ARCHIVIST"], tenant="heritage-core")
    assert c2.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    gov.revoke_role("sub-worker", "ROLE_ARCHIVIST")
    assert c2.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 403
    gov.leaver("sub-worker")
    assert c2.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert c1.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_jaccard_role_mining_and_public_landing_hides_pii(tmp_path: Path) -> None:
    matrix = {
        "u1": {"collection:read", "research:read", "research:write_own"},
        "u2": {"collection:read", "research:read", "research:write_own", "catalog:search"},
        "u3": {"collection:read", "collection:annotate", "catalog:search"},
        "u4": {"collection:read", "collection:annotate", "catalog:search", "legacy:temp"},
    }
    res = mine_candidate_roles(matrix, similarity_threshold=0.70, min_cluster_size=2)
    assert len(res["candidate_roles"]) == 2
    assert res["metrics"]["entitlement_coverage_pct"] > 75.0

    client = TestClient(create_app(db_path=tmp_path / "ui.db"))
    html = client.get("/").text
    assert "LIMEN — Zero-Trust Identity Security" in html
    assert "alice.researcher" not in html  # No unauthenticated directory leakage!
