"""Asymmetric RS256/JWKS OIDC Token Validator for LIMEN Policy Enforcement Point (Remediated LIMEN-01, LIMEN-02).

Strictly enforces:
- Allowed algorithms = ["RS256"] only (rejects HS256, alg=none, arbitrary algorithms).
- Trusted issuer (`iss`) and intended audience (`aud`).
- Expiration (`exp`) and not-before (`nbf`) with minimal clock skew.
- Token use separation: rejects ID tokens (`typ=ID` or missing API scope) presented as access tokens.
- LIMEN-01: Explicit resource-client role contract — ONLY reads resource_access[trusted_resource_client]
  and explicitly allowlisted realm roles; ignores roles belonging to unrelated OAuth clients.
- LIMEN-02: Fail-closed tenant enforcement — rejects missing, empty, ambiguous, or unknown tenant claims.
- Trusted JWKS key lookup by `kid` with automatic cache refresh on key rotation.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

KNOWN_LIMEN_ROLES = frozenset(
    {
        "ROLE_ARCHIVIST",
        "ROLE_RESEARCHER",
        "ROLE_CONTRACTOR_RESTORER",
        "ROLE_ACCESS_REQUESTER",
        "ROLE_ACCESS_APPROVER",
        "ROLE_SECURITY_AUDITOR",
        "ROLE_ADMIN",
    }
)

DEFAULT_TRUSTED_TENANTS = frozenset({"heritage-core", "partner-museum"})


class TokenValidationError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass
class VerifiedPrincipal:
    subject: str
    username: str
    roles: set[str]
    scopes: set[str]
    tenant: str
    jti: str | None = None
    expires_at: int = 0
    raw_claims: dict[str, Any] = field(default_factory=dict)


class JWKSKeyStore:
    """Trusted JWKS provider supporting either live HTTP JWKS endpoint or static test JWKS."""

    def __init__(self, jwks_url: str | None = None, static_jwks: dict[str, Any] | None = None, ttl_seconds: int = 300) -> None:
        self.jwks_url = jwks_url
        self._static_jwks = static_jwks
        self.ttl_seconds = ttl_seconds
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        if static_jwks:
            self._load_dict(static_jwks)

    def _load_dict(self, jwks_data: dict[str, Any]) -> None:
        loaded: dict[str, Any] = {}
        for jwk in jwks_data.get("keys", []):
            kid = jwk.get("kid")
            if kid and jwk.get("kty") == "RSA":
                loaded[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
        self._keys = loaded
        self._fetched_at = time.monotonic()

    def refresh(self) -> None:
        if self._static_jwks is not None:
            self._load_dict(self._static_jwks)
            return
        if not self.jwks_url:
            raise TokenValidationError("JWKS_UNCONFIGURED", "No trusted JWKS URL or static key set configured.")
        try:
            resp = httpx.get(self.jwks_url, timeout=5.0)
            resp.raise_for_status()
            self._load_dict(resp.json())
        except Exception as exc:
            raise TokenValidationError("JWKS_FETCH_FAILED", f"Unable to retrieve trusted JWKS: {exc}") from exc

    def update_static_jwks(self, jwks_data: dict[str, Any]) -> None:
        self._static_jwks = jwks_data
        self._load_dict(jwks_data)

    def get_key(self, kid: str) -> Any:
        if not self._keys or (time.monotonic() - self._fetched_at > self.ttl_seconds):
            self.refresh()
        if kid in self._keys:
            return self._keys[kid]
        self.refresh()
        if kid in self._keys:
            return self._keys[kid]
        raise TokenValidationError("UNKNOWN_KID", f"Key ID '{kid}' not present in trusted JWKS.")


class OIDCValidator:
    ALLOWED_ALGS = ["RS256"]

    def __init__(
        self,
        expected_issuer: str,
        expected_audience: str,
        key_store: JWKSKeyStore,
        trusted_resource_client: str | None = None,
        trusted_tenants: set[str] | frozenset[str] | None = None,
        accept_realm_roles: bool = True,
        revoked_jtis: set[str] | None = None,
        disabled_subjects: set[str] | None = None,
    ) -> None:
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.trusted_resource_client = trusted_resource_client or expected_audience
        self.trusted_tenants = frozenset(trusted_tenants) if trusted_tenants is not None else DEFAULT_TRUSTED_TENANTS
        self.accept_realm_roles = accept_realm_roles
        self.key_store = key_store
        self.revoked_jtis = revoked_jtis if revoked_jtis is not None else set()
        self.disabled_subjects = disabled_subjects if disabled_subjects is not None else set()

    def validate_access_token(self, token: str, required_scope: str | None = None) -> VerifiedPrincipal:
        if not token or token.count(".") != 2:
            raise TokenValidationError("MALFORMED_TOKEN", "Bearer token must be a 3-segment JWT.")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenValidationError("INVALID_HEADER", str(exc)) from exc

        alg = header.get("alg")
        if alg not in self.ALLOWED_ALGS:
            raise TokenValidationError("DISALLOWED_ALG", f"Algorithm '{alg}' is rejected; only RS256 is permitted.")

        if "jku" in header or "x5u" in header:
            raise TokenValidationError("UNTRUSTED_KEY_HEADER", "Attacker-controlled key URL headers (jku/x5u) are prohibited.")

        kid = header.get("kid")
        if not kid:
            raise TokenValidationError("MISSING_KID", "JWT header must specify a trusted key identifier (kid).")

        pub_key = self.key_store.get_key(kid)

        try:
            claims = jwt.decode(
                token,
                key=pub_key,
                algorithms=self.ALLOWED_ALGS,
                issuer=self.expected_issuer,
                audience=self.expected_audience,
                options={"require": ["exp", "iss", "sub", "aud"]},
                leeway=5,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("TOKEN_EXPIRED", "Access token has expired.") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenValidationError("INVALID_ISSUER", "Token issuer does not match trusted realm.") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenValidationError("INVALID_AUDIENCE", "Token audience does not match protected API.") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenValidationError("TOKEN_NOT_YET_VALID", "Token nbf claim is in the future.") from exc
        except jwt.PyJWTError as exc:
            raise TokenValidationError("SIGNATURE_OR_CLAIMS_INVALID", str(exc)) from exc

        tok_typ = str(claims.get("typ", "")).lower()
        if tok_typ == "id" or ("nonce" in claims and "scope" not in claims):
            raise TokenValidationError("WRONG_TOKEN_TYPE", "ID tokens cannot be used as API access tokens.")

        jti = claims.get("jti")
        if jti and jti in self.revoked_jtis:
            raise TokenValidationError("TOKEN_REVOKED", "Token JTI has been revoked.")

        sub = str(claims["sub"]).strip()
        if not sub:
            raise TokenValidationError("MISSING_SUBJECT", "Token subject claim is empty.")
        if sub in self.disabled_subjects:
            raise TokenValidationError("IDENTITY_DISABLED", "Identity has been disabled via Leaver workflow.")

        # LIMEN-02: Strict fail-closed tenant verification (never silently default!)
        raw_tenant = claims.get("tenant")
        if not isinstance(raw_tenant, str) or not raw_tenant.strip():
            raise TokenValidationError("MISSING_OR_AMBIGUOUS_TENANT", "Verified single string 'tenant' claim is required.")
        tenant = raw_tenant.strip()
        if tenant not in self.trusted_tenants:
            raise TokenValidationError("UNKNOWN_TENANT", f"Tenant '{tenant}' is not registered in trusted tenant directory.")

        # LIMEN-01: Strict trusted role extraction (ONLY trusted resource client + allowlisted realm roles)
        roles: set[str] = set()
        res_access = claims.get("resource_access")
        if isinstance(res_access, dict):
            trusted_client_obj = res_access.get(self.trusted_resource_client)
            if isinstance(trusted_client_obj, dict):
                for r in trusted_client_obj.get("roles") or []:
                    if isinstance(r, str) and r in KNOWN_LIMEN_ROLES:
                        roles.add(r)

        if self.accept_realm_roles:
            realm_access = claims.get("realm_access")
            if isinstance(realm_access, dict):
                for r in realm_access.get("roles") or []:
                    if isinstance(r, str) and r in KNOWN_LIMEN_ROLES:
                        roles.add(r)

        raw_scope = str(claims.get("scope", ""))
        scopes = {s for s in raw_scope.split() if s}
        if required_scope and required_scope not in scopes:
            raise TokenValidationError("INSUFFICIENT_SCOPE", f"Required scope '{required_scope}' not present in token.")

        return VerifiedPrincipal(
            subject=sub,
            username=str(claims.get("preferred_username", sub)),
            roles=roles,
            scopes=scopes,
            tenant=tenant,
            jti=jti,
            expires_at=int(claims["exp"]),
            raw_claims=claims,
        )
