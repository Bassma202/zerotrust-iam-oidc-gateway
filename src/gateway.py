"""
Zero-Trust IAM & OIDC API Gateway
Author: Bassma Alaoui Sossey
Enforces OAuth2 / OpenID Connect Bearer token validation, cryptographic signatures,
claims verification, and Role-Based Access Control (RBAC).
"""

import hmac
import hashlib
import base64
import json
import time
from typing import Dict, List, Optional, Tuple

class JWTValidator:
    def __init__(self, secret_key: str = "SECURE_DEMO_SECRET_KEY_2027", issuer: str = "https://iam.ue.ma/auth/realms/uemf"):
        self.secret_key = secret_key
        self.expected_issuer = issuer

    def _b64_decode(self, val: str) -> bytes:
        rem = len(val) % 4
        if rem > 0:
            val += "=" * (4 - rem)
        return base64.urlsafe_b64decode(val.encode("utf-8"))

    def _b64_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    def generate_token(self, username: str, roles: List[str], expires_in: int = 3600) -> str:
        """Utility to issue test JWT tokens for authentication testing."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": self.expected_issuer,
            "sub": username,
            "roles": roles,
            "iat": int(time.time()),
            "exp": int(time.time()) + expires_in
        }
        
        h_str = self._b64_encode(json.dumps(header).encode("utf-8"))
        p_str = self._b64_encode(json.dumps(payload).encode("utf-8"))
        signing_input = f"{h_str}.{p_str}".encode("utf-8")
        
        signature = hmac.new(self.secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        s_str = self._b64_encode(signature)
        return f"{h_str}.{p_str}.{s_str}"

    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict], str]:
        """
        Validates token signature, expiration (exp), and issuer (iss).
        Returns: (is_valid, payload, error_message)
        """
        parts = token.split(".")
        if len(parts) != 3:
            return False, None, "MALFORMED_TOKEN: Token must contain exactly 3 segments"

        h_str, p_str, s_str = parts
        signing_input = f"{h_str}.{p_str}".encode("utf-8")
        expected_sig = hmac.new(self.secret_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual_sig = self._b64_decode(s_str)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, None, "INVALID_SIGNATURE: Cryptographic signature mismatch"

        try:
            payload = json.loads(self._b64_decode(p_str).decode("utf-8"))
        except Exception:
            return False, None, "INVALID_PAYLOAD: Failed to parse JSON claims"

        # Check issuer
        if payload.get("iss") != self.expected_issuer:
            return False, None, f"INVALID_ISSUER: Expected {self.expected_issuer}, got {payload.get('iss')}"

        # Check expiration
        now = int(time.time())
        if payload.get("exp", 0) < now:
            return False, None, f"TOKEN_EXPIRED: Token expired at {payload.get('exp')}, current time is {now}"

        return True, payload, "OK"

class IAMPolicyEnforcer:
    def __init__(self, validator: JWTValidator):
        self.validator = validator
        # Endpoint RBAC requirements: {endpoint_path: [allowed_roles]}
        self.route_permissions = {
            "/api/v1/patient/records": ["ROLE_DOCTOR", "ROLE_PATHOLOGIST", "ROLE_ADMIN"],
            "/api/v1/audit/logs": ["ROLE_SECURITY_AUDITOR", "ROLE_ADMIN"],
            "/api/v1/admin/users": ["ROLE_ADMIN"],
            "/api/v1/telemetry/read": ["ROLE_USER", "ROLE_DOCTOR", "ROLE_PATHOLOGIST", "ROLE_ADMIN"]
        }

    def evaluate_request(self, auth_header: str, endpoint: str) -> Tuple[int, str]:
        """
        Returns HTTP status code and message.
        401: Unauthorized (missing or invalid token)
        403: Forbidden (valid token but insufficient role permissions)
        200: Allowed
        """
        if not auth_header or not auth_header.startswith("Bearer "):
            return 401, "UNAUTHORIZED: Missing or malformed Authorization Bearer header"

        token = auth_header.split("Bearer ")[1].strip()
        is_valid, payload, err = self.validator.verify_token(token)

        if not is_valid:
            return 401, f"UNAUTHORIZED: {err}"

        user_roles = payload.get("roles", [])
        allowed_roles = self.route_permissions.get(endpoint)

        if allowed_roles is None:
            return 404, "NOT_FOUND: Endpoint route not registered"

        if not any(r in allowed_roles for r in user_roles):
            return 403, f"FORBIDDEN: Insufficient privileges. Required: {allowed_roles}, Assigned: {user_roles}"

        return 200, f"ALLOWED: Access granted to {payload.get('sub')}"
