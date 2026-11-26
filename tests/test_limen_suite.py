"""Comprehensive LIMEN security & governance test suite (real RSA-2048 JWKS, rotation, negative JWT checks, horizontal/vertical authz, JML, temp expiry, SoD, Jaccard role mining)."""

from __future__ import annotations

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
    roles: list[str],
    iss: str = "http://127.0.0.1:8080/realms/limen-heritage",
    aud: str = "limen-api",
    scope: str = "openid limen:api",
    exp_offset: int = 300,
    typ: str = "Bearer",
    tenant: str = "heritage-core",
    extra_headers: dict | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": sub,
        "preferred_username": username,
        "aud": aud,
        "exp": now + exp_offset,
        "iat": now,
        "nbf": now - 1,
        "typ": typ,
        "scope": scope,
        "jti": f"jti-{username}-{now}",
        "tenant": tenant,
        "realm_access": {"roles": roles},
    }
    headers = {"kid": kid, **(extra_headers or {})}
    return jwt.encode(payload, priv, algorithm="RS256", headers=headers)


def test_rs256_jwks_validation_and_negative_security_checks(tmp_path: Path) -> None:
    priv1, jwk1 = _make_rsa_keypair("key-v1")
    priv2, jwk2 = _make_rsa_keypair("key-v2")
    ks = JWKSKeyStore(static_jwks={"keys": [jwk1]})
    validator = OIDCValidator("http://127.0.0.1:8080/realms/limen-heritage", "limen-api", ks)
    client = TestClient(create_app(validator=validator, db_path=tmp_path / "limen.db"))

    # 1. Valid RS256 token succeeds
    alice_tok = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"])
    r_ok = client.get("/api/resources/collections", headers={"Authorization": f"Bearer {alice_tok}"})
    assert r_ok.status_code == 200
    assert all(c["classification"] != "RESTRICTED" for c in r_ok.json()["collections"])

    # 2. Expired token rejected
    exp_tok = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], exp_offset=-60)
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {exp_tok}"}).status_code == 401

    # 3. Wrong issuer & wrong audience rejected
    bad_iss = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], iss="https://evil.example/realm")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {bad_iss}"}).status_code == 401
    bad_aud = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], aud="other-service")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {bad_aud}"}).status_code == 401

    # 4. Missing required scope rejected
    no_scope = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], scope="openid profile")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {no_scope}"}).status_code == 401

    # 5. ID token presented as access token rejected
    id_tok = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], typ="ID")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {id_tok}"}).status_code == 401

    # 6. HS256 algorithm confusion rejected
    hs_tok = jwt.encode({"sub": "alice", "aud": "limen-api", "exp": int(time.time()) + 300}, "weak-secret", algorithm="HS256")
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {hs_tok}"}).status_code == 401

    # 7. Attacker jku header rejected
    jku_tok = _issue_token(priv1, "key-v1", "alice.researcher", "alice.researcher", ["ROLE_RESEARCHER"], extra_headers={"jku": "https://evil.example/jwks.json"})
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {jku_tok}"}).status_code == 401

    # 8. Horizontal IDOR & vertical escalation blocked
    assert client.get("/api/resources/research/RES-101", headers={"Authorization": f"Bearer {alice_tok}"}).status_code == 200
    assert client.get("/api/resources/research/RES-102", headers={"Authorization": f"Bearer {alice_tok}"}).status_code == 403
    assert client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {alice_tok}"}).status_code == 403

    # 9. Key rotation: rotating to key-v2 allows tokens signed by key-v2
    ks.update_static_jwks({"keys": [jwk1, jwk2]})
    aud_tok = _issue_token(priv2, "key-v2", "farid.auditor", "farid.auditor", ["ROLE_SECURITY_AUDITOR"])
    assert client.get("/api/admin/audit-logs", headers={"Authorization": f"Bearer {aud_tok}"}).status_code == 200


def test_jml_lifecycle_temp_expiry_and_sod_prevention(tmp_path: Path) -> None:
    priv, jwk = _make_rsa_keypair("k1")
    ks = JWKSKeyStore(static_jwks={"keys": [jwk]})
    validator = OIDCValidator("http://127.0.0.1:8080/realms/limen-heritage", "limen-api", ks)
    app = create_app(validator=validator, db_path=tmp_path / "limen.db", seed=False)
    gov: GovernanceEngine = app.state.gov
    client = TestClient(app)

    # Preventive SoD blocks assigning ADMIN + SECURITY_AUDITOR (inherited entitlements iam:manage + audit:read)
    try:
        gov.joiner("bad.user", "bad.user", "IT", "employee", ["ROLE_ADMIN", "ROLE_SECURITY_AUDITOR"])
        assert False, "Expected preventive SoD ValueError"
    except ValueError as exc:
        assert "SOD-002" in str(exc)

    # Joiner -> Temporary grant -> Expiry check
    gov.joiner("temp.contractor", "temp.contractor", "Conservation", "contractor", ["ROLE_CONTRACTOR_RESTORER"])
    gov.grant_temporary_access("temp.contractor", "catalog:search", approved_by="nadia.admin", ttl_seconds=60)
    assert "catalog:search" in gov.active_temp_entitlements("temp.contractor")
    future = datetime.now(timezone.utc) + timedelta(seconds=120)
    assert "catalog:search" not in gov.active_temp_entitlements("temp.contractor", now=future)

    # Mover strips historical entitlements
    gov.mover("temp.contractor", "Research", ["ROLE_RESEARCHER"])
    moved = gov.get_identity("temp.contractor")
    assert moved["roles"] == ["ROLE_RESEARCHER"]

    # Leaver revokes access immediately on PEP
    tok = _issue_token(priv, "k1", "temp.contractor", "temp.contractor", ["ROLE_RESEARCHER"])
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    gov.leaver("temp.contractor", validator.disabled_subjects)
    assert client.get("/api/resources/collections", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_jaccard_role_mining_baseline_metrics_and_ui(tmp_path: Path) -> None:
    matrix = {
        "u1": {"collection:read", "research:read", "research:write_own"},
        "u2": {"collection:read", "research:read", "research:write_own", "catalog:search"},
        "u3": {"collection:read", "collection:annotate", "catalog:search"},
        "u4": {"collection:read", "collection:annotate", "catalog:search", "legacy:temp"},
    }
    res = mine_candidate_roles(matrix, similarity_threshold=0.70, min_cluster_size=2)
    assert len(res["candidate_roles"]) == 2
    assert res["metrics"]["entitlement_coverage_pct"] > 75.0
    assert res["metrics"]["over_assignment_risk_count"] == 0
    assert len(res["overprivilege_review_queue"]) == 2

    client = TestClient(create_app(db_path=tmp_path / "ui.db"))
    assert "LIMEN — Zero-Trust Identity Security" in client.get("/").text
