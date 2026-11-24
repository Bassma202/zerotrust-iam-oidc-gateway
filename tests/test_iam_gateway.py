"""
Unit Tests for Zero-Trust IAM & OIDC Gateway
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gateway import JWTValidator, IAMPolicyEnforcer
from src.sod_auditor import scan_user_for_sod_conflicts

class TestIAMGateway(unittest.TestCase):
    def setUp(self):
        self.validator = JWTValidator()
        self.enforcer = IAMPolicyEnforcer(self.validator)

    def test_valid_token_authorized_access(self):
        # Doctor accessing patient records
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=3600)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/patient/records")
        self.assertEqual(status, 200)
        self.assertIn("ALLOWED", msg)

    def test_valid_token_forbidden_role(self):
        # Standard user attempting to access administrative audit logs
        token = self.validator.generate_token("regular_user", ["ROLE_USER"], expires_in=3600)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/audit/logs")
        self.assertEqual(status, 403)
        self.assertIn("FORBIDDEN", msg)

    def test_expired_token(self):
        # Token expired 10 seconds ago
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=-10)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/patient/records")
        self.assertEqual(status, 401)
        self.assertIn("TOKEN_EXPIRED", msg)

    def test_tampered_token_signature(self):
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=3600)
        # Tamper payload by modifying one character
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}A.{parts[2]}"
        status, msg = self.enforcer.evaluate_request(f"Bearer {tampered_token}", "/api/v1/patient/records")
        self.assertEqual(status, 401)
        self.assertIn("INVALID_SIGNATURE", msg)

    def test_sod_conflict_detected(self):
        # User holds both creator and approver roles (toxic combination)
        conflicts = scan_user_for_sod_conflicts(
            username="bad_actor",
            assigned_roles=["FIN_PAYMENT_CREATOR", "FIN_PAYMENT_APPROVER", "USER"]
        )
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["rule_id"], "SOD-01")
        self.assertEqual(conflicts[0]["severity"], "CRITICAL")

    def test_sod_no_conflict(self):
        clean_user = scan_user_for_sod_conflicts(
            username="good_actor",
            assigned_roles=["FIN_PAYMENT_CREATOR", "USER"]
        )
        self.assertEqual(len(clean_user), 0)

if __name__ == "__main__":
    unittest.main()
