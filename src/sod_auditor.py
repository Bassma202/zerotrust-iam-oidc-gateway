"""
Segregation of Duties (SoD) & Toxic Combination Auditor
Author: Bassma Alaoui Sossey
Scans user entitlement matrices to identify conflicting roles that violate compliance.
"""

from typing import List, Dict, Any

# Standard Enterprise Toxic Combinations (SoD Conflict Rules)
SOD_CONFLICT_RULES = [
    {
        "id": "SOD-01",
        "name": "Payment Creator & Payment Approver",
        "conflicting_roles": ["FIN_PAYMENT_CREATOR", "FIN_PAYMENT_APPROVER"],
        "severity": "CRITICAL",
        "risk": "Risk of internal financial fraud and unreviewed capital transfer."
    },
    {
        "id": "SOD-02",
        "name": "User Access Administrator & Audit Log Deleter",
        "conflicting_roles": ["IAM_USER_ADMIN", "SEC_LOG_ADMIN"],
        "severity": "CRITICAL",
        "risk": "Risk of creating unauthorized backdoor accounts and clearing audit trails."
    },
    {
        "id": "SOD-03",
        "name": "Developer & Production Deployer",
        "conflicting_roles": ["DEV_ENGINEER", "PROD_DEPLOYER"],
        "severity": "HIGH",
        "risk": "Violation of change control policy (ISO 27001 A.8.9); risk of unreviewed code in production."
    },
    {
        "id": "SOD-04",
        "name": "Medical Record Creator & Anonymization Override",
        "conflicting_roles": ["DATA_CREATOR", "PRIVACY_DEANONYMIZER"],
        "severity": "HIGH",
        "risk": "Violation of Moroccan Law 09-08; unauthorized re-identification of medical patients."
    }
]

def scan_user_for_sod_conflicts(username: str, assigned_roles: List[str]) -> List[Dict[str, Any]]:
    violations = []
    assigned_set = set(assigned_roles)
    
    for rule in SOD_CONFLICT_RULES:
        conflicts = set(rule["conflicting_roles"])
        if conflicts.issubset(assigned_set):
            violations.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "risk": rule["risk"],
                "conflicting_roles_held": list(conflicts)
            })
    return violations
