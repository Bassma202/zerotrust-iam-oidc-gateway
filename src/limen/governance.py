"""Identity Lifecycle (Joiner/Mover/Leaver), Time-Limited Grants, and Direct+Inherited SoD Engine."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime | None = None) -> str:
    return (dt or utc_now()).isoformat()


ROLE_ENTITLEMENTS: dict[str, set[str]] = {
    "ROLE_ARCHIVIST": {"collection:read", "collection:annotate", "catalog:search"},
    "ROLE_RESEARCHER": {"collection:read", "research:read", "research:write_own"},
    "ROLE_CONTRACTOR_RESTORER": {"collection:read_scoped", "restoration:log"},
    "ROLE_ACCESS_REQUESTER": {"access:request"},
    "ROLE_ACCESS_APPROVER": {"access:approve"},
    "ROLE_SECURITY_AUDITOR": {"audit:read", "sod:read", "collection:metadata_read"},
    "ROLE_ADMIN": {"iam:manage", "collection:read", "collection:write", "system:configure"},
}

SOD_POLICIES: list[dict[str, Any]] = [
    {
        "policy_id": "SOD-001",
        "name": "Access Request vs. Access Approval",
        "conflicting_pair": ("access:request", "access:approve"),
        "severity": "HIGH",
        "rationale": "Prevents self-approval of elevated privileges.",
    },
    {
        "policy_id": "SOD-002",
        "name": "System Administration vs. Independent Security Audit",
        "conflicting_pair": ("iam:manage", "audit:read"),
        "severity": "CRITICAL",
        "rationale": "Administrators must not independently audit or alter their own activity trails.",
    },
    {
        "policy_id": "SOD-003",
        "name": "External Contractor vs. Core Archive Write",
        "conflicting_pair": ("restoration:log", "collection:write"),
        "severity": "HIGH",
        "rationale": "External restoration specialists must not hold unrestricted production vault write access.",
    },
]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS identities (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    identity_type TEXT NOT NULL,
    status TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    direct_entitlements_json TEXT NOT NULL,
    owner TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS temp_grants (
    grant_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    entitlement TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS iam_audit (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_user TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class GovernanceEngine:
    def __init__(self, db_path: str | Path = "data/limen.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _log(self, actor: str, action: str, target_user: str, outcome: str, detail: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO iam_audit (event_id, timestamp, actor, action, target_user, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"IAM-{uuid.uuid4().hex[:10].upper()}", utc_iso(), actor, action, target_user, outcome, detail),
            )

    def effective_entitlements(self, roles: list[str], direct: list[str], active_temp: list[str] | None = None) -> set[str]:
        eff = set(direct)
        for r in roles:
            eff.update(ROLE_ENTITLEMENTS.get(r, set()))
        if active_temp:
            eff.update(active_temp)
        return eff

    def detect_sod_conflicts(self, roles: list[str], direct: list[str], active_temp: list[str] | None = None) -> list[dict[str, Any]]:
        eff = self.effective_entitlements(roles, direct, active_temp)
        conflicts = []
        for pol in SOD_POLICIES:
            a, b = pol["conflicting_pair"]
            if a in eff and b in eff:
                conflicts.append(
                    {
                        "policy_id": pol["policy_id"],
                        "name": pol["name"],
                        "severity": pol["severity"],
                        "conflicting_entitlements": [a, b],
                        "rationale": pol["rationale"],
                    }
                )
        return conflicts

    def joiner(
        self,
        user_id: str,
        username: str,
        department: str,
        identity_type: str,
        roles: list[str],
        direct_entitlements: list[str] | None = None,
        owner: str = "IAM Governance",
        actor: str = "hr-lifecycle",
        enforce_preventive_sod: bool = True,
    ) -> dict[str, Any]:
        direct = direct_entitlements or []
        conflicts = self.detect_sod_conflicts(roles, direct)
        if enforce_preventive_sod and conflicts:
            self._log(actor, "JOINER_BLOCKED", user_id, "DENIED_SOD", f"{len(conflicts)} SoD conflicts detected.")
            raise ValueError(f"Preventive SoD block: {[c['policy_id'] for c in conflicts]}")
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO identities
                (user_id, username, department, identity_type, status, roles_json, direct_entitlements_json, owner, updated_at)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)""",
                (user_id, username, department, identity_type, json.dumps(sorted(set(roles))), json.dumps(sorted(set(direct))), owner, utc_iso()),
            )
        self._log(actor, "JOINER", user_id, "ALLOWED", f"Provisioned {identity_type} in {department} with roles {roles}.")
        return self.get_identity(user_id)

    def mover(self, user_id: str, new_department: str, new_roles: list[str], actor: str = "hr-lifecycle") -> dict[str, Any]:
        ident = self.get_identity(user_id)
        if not ident:
            raise KeyError(f"Identity {user_id} not found.")
        conflicts = self.detect_sod_conflicts(new_roles, [])
        if conflicts:
            self._log(actor, "MOVER_BLOCKED", user_id, "DENIED_SOD", f"SoD conflict on role change: {[c['policy_id'] for c in conflicts]}")
            raise ValueError(f"Preventive SoD block on mover: {[c['policy_id'] for c in conflicts]}")
        # Mover strips stale historical direct entitlements and old roles
        with self._connect() as conn:
            conn.execute(
                "UPDATE identities SET department=?, roles_json=?, direct_entitlements_json='[]', updated_at=? WHERE user_id=?",
                (new_department, json.dumps(sorted(set(new_roles))), utc_iso(), user_id),
            )
        self._log(actor, "MOVER", user_id, "ALLOWED", f"Moved to {new_department}; stripped historical roles {ident['roles']} -> {new_roles}.")
        return self.get_identity(user_id)

    def leaver(self, user_id: str, disabled_subjects: set[str], actor: str = "hr-lifecycle") -> dict[str, Any]:
        ident = self.get_identity(user_id)
        if not ident:
            raise KeyError(f"Identity {user_id} not found.")
        with self._connect() as conn:
            conn.execute(
                "UPDATE identities SET status='DISABLED', roles_json='[]', direct_entitlements_json='[]', updated_at=? WHERE user_id=?",
                (utc_iso(), user_id),
            )
            conn.execute("UPDATE temp_grants SET revoked=1 WHERE user_id=?", (user_id,))
        disabled_subjects.add(user_id)
        self._log(actor, "LEAVER", user_id, "REVOKED", "Account disabled, roles/grants stripped, subject added to PEP denylist.")
        return self.get_identity(user_id)

    def grant_temporary_access(
        self,
        user_id: str,
        entitlement: str,
        approved_by: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        ident = self.get_identity(user_id)
        if not ident or ident["status"] != "ACTIVE":
            raise ValueError("Cannot grant temporary access to inactive or missing identity.")
        conflicts = self.detect_sod_conflicts(ident["roles"], ident["direct_entitlements"], [entitlement])
        if conflicts:
            self._log(approved_by, "TEMP_GRANT_BLOCKED", user_id, "DENIED_SOD", str(conflicts))
            raise ValueError(f"Temporary grant blocked by SoD: {[c['policy_id'] for c in conflicts]}")
        gid = f"GRT-{uuid.uuid4().hex[:10].upper()}"
        exp = utc_iso(utc_now() + timedelta(seconds=ttl_seconds))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO temp_grants (grant_id, user_id, entitlement, approved_by, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)",
                (gid, user_id, entitlement, approved_by, exp),
            )
        self._log(approved_by, "TEMP_GRANT", user_id, "GRANTED", f"{entitlement} until {exp}")
        return {"grant_id": gid, "user_id": user_id, "entitlement": entitlement, "expires_at": exp}

    def active_temp_entitlements(self, user_id: str, now: datetime | None = None) -> list[str]:
        ref = now or utc_now()
        with self._connect() as conn:
            rows = conn.execute("SELECT entitlement, expires_at FROM temp_grants WHERE user_id=? AND revoked=0", (user_id,)).fetchall()
        active = []
        for r in rows:
            exp_dt = datetime.fromisoformat(r["expires_at"])
            if exp_dt > ref:
                active.append(r["entitlement"])
        return active

    def get_identity(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM identities WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["roles"] = json.loads(d.pop("roles_json"))
        d["direct_entitlements"] = json.loads(d.pop("direct_entitlements_json"))
        d["active_temp_entitlements"] = self.active_temp_entitlements(user_id)
        d["effective_entitlements"] = sorted(
            self.effective_entitlements(d["roles"], d["direct_entitlements"], d["active_temp_entitlements"])
        )
        d["sod_conflicts"] = self.detect_sod_conflicts(d["roles"], d["direct_entitlements"], d["active_temp_entitlements"])
        return d

    def list_identities(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            ids = [r["user_id"] for r in conn.execute("SELECT user_id FROM identities ORDER BY user_id").fetchall()]
        return [self.get_identity(uid) for uid in ids if self.get_identity(uid)]

    def list_audit(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM iam_audit ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]
