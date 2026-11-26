"""Asymmetric RS256/JWKS OIDC Token Validator for LIMEN Policy Enforcement Point.

Strictly enforces:
- Allowed algorithms = ["RS256"] only (rejects HS256, alg=none, arbitrary algorithms).
- Trusted issuer (`iss`) and intended audience (`aud`).
- Expiration (`exp`) and not-before (`nbf`) with minimal clock skew.
- Token use separation: rejects ID tokens (`typ=ID` or missing API scope) presented as access tokens.
- Trusted JWKS key lookup by `kid` with automatic cache refresh on key rotation.
- Local JTI/subject revocation denylist supporting immediate Leaver termination.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm


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
        # Key rotation support: force single refresh on unknown kid
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
        revoked_jtis: set[str] | None = None,
        disabled_subjects: set[str] | None = None,
    ) -> None:
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
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

        # Reject ID tokens presented as API access tokens
        tok_typ = str(claims.get("typ", "")).lower()
        if tok_typ == "id" or ("nonce" in claims and "scope" not in claims):
            raise TokenValidationError("WRONG_TOKEN_TYPE", "ID tokens cannot be used as API access tokens.")

        jti = claims.get("jti")
        if jti and jti in self.revoked_jtis:
            raise TokenValidationError("TOKEN_REVOKED", "Token JTI has been revoked.")

        sub = str(claims["sub"])
        if sub in self.disabled_subjects:
            raise TokenValidationError("IDENTITY_DISABLED", "Identity has been disabled via Leaver workflow.")

        # Extract Keycloak realm_access + resource_access + flat roles
        roles: set[str] = set(claims.get("roles", []) or [])
        roles.update(claims.get("realm_access", {}).get("roles", []) or [])
        for client_obj in (claims.get("resource_access") or {}).values():
            if isinstance(client_obj, dict):
                roles.update(client_obj.get("roles", []) or [])

        raw_scope = str(claims.get("scope", ""))
        scopes = {s for s in raw_scope.split() if s}
        if required_scope and required_scope not in scopes:
            raise TokenValidationError("INSUFFICIENT_SCOPE", f"Required scope '{required_scope}' not present in token.")

        return VerifiedPrincipal(
            subject=sub,
            username=str(claims.get("preferred_username", sub)),
            roles=roles,
            scopes=scopes,
            tenant=str(claims.get("tenant", "heritage-core")),
            jti=jti,
            expires_at=int(claims["exp"]),
            raw_claims=claims,
        )
