"""
Unit Tests for Zero-Trust IAM & OIDC Gateway, SoD Auditor, and Role Mining
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.gateway import JWTValidator, IAMPolicyEnforcer
from src.sod_auditor import scan_user_for_sod_conflicts
from src.role_mining import RoleMiningEngine, jaccard_similarity

class TestIAMGateway(unittest.TestCase):
    def setUp(self):
        self.validator = JWTValidator()
        self.enforcer = IAMPolicyEnforcer(self.validator)

    def test_valid_token_authorized_access(self):
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=3600)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/patient/records")
        self.assertEqual(status, 200)
        self.assertIn("ALLOWED", msg)

    def test_valid_token_forbidden_role(self):
        token = self.validator.generate_token("regular_user", ["ROLE_USER"], expires_in=3600)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/audit/logs")
        self.assertEqual(status, 403)
        self.assertIn("FORBIDDEN", msg)

    def test_expired_token(self):
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=-10)
        status, msg = self.enforcer.evaluate_request(f"Bearer {token}", "/api/v1/patient/records")
        self.assertEqual(status, 401)
        self.assertIn("TOKEN_EXPIRED", msg)

    def test_tampered_token_signature(self):
        token = self.validator.generate_token("dr_alaoui", ["ROLE_DOCTOR"], expires_in=3600)
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}A.{parts[2]}"
        status, msg = self.enforcer.evaluate_request(f"Bearer {tampered_token}", "/api/v1/patient/records")
        self.assertEqual(status, 401)
        self.assertIn("INVALID_SIGNATURE", msg)

    def test_sod_conflict_detected(self):
        conflicts = scan_user_for_sod_conflicts(
            username="bad_actor",
            assigned_roles=["FIN_PAYMENT_CREATOR", "FIN_PAYMENT_APPROVER", "USER"]
        )
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["rule_id"], "SOD-01")

    def test_jaccard_similarity(self):
        set1 = {"read", "write", "execute"}
        set2 = {"read", "write"}
        sim = jaccard_similarity(set1, set2) # 2 / 3 = 0.6667
        self.assertAlmostEqual(sim, 0.6667, places=3)

    def test_role_mining_clustering(self):
        users = {
            "u1": ["read", "write", "sign"],
            "u2": ["read", "write", "sign"],
            "u3": ["audit", "export"]
        }
        miner = RoleMiningEngine(similarity_threshold=0.8)
        report = miner.mine_candidate_roles(users)
        self.assertEqual(report["candidate_business_roles_found"], 2)

if __name__ == "__main__":
    unittest.main()
