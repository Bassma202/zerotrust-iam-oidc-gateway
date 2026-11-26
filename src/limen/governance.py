"""Identity Lifecycle (Joiner/Mover/Leaver), Time-Limited Grants, and Atomic Cumulative SoD Engine (LIMEN-04, LIMEN-05)."""

from __future__ import annotations

import json
import sqlite3
import threading
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
    username TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT 'heritage-core',
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
    """SQLite-backed Identity Governance Engine enforcing atomic cumulative SoD and cross-worker revocation."""

    def __init__(self, db_path: str | Path = "data/limen.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._tx_lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _log_conn(self, conn: sqlite3.Connection, actor: str, action: str, target_user: str, outcome: str, detail: str) -> None:
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

    def _active_temp_in_conn(self, conn: sqlite3.Connection, user_id: str, ref: datetime | None = None) -> list[str]:
        now_ref = ref or utc_now()
        rows = conn.execute("SELECT entitlement, expires_at FROM temp_grants WHERE user_id=? AND revoked=0", (user_id,)).fetchall()
        return [r["entitlement"] for r in rows if datetime.fromisoformat(r["expires_at"]) > now_ref]

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
        tenant: str = "heritage-core",
        enforce_preventive_sod: bool = True,
    ) -> dict[str, Any]:
        direct = direct_entitlements or []
        with self._tx_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active_temp = self._active_temp_in_conn(conn, user_id)
            conflicts = self.detect_sod_conflicts(roles, direct, active_temp)
            if enforce_preventive_sod and conflicts:
                self._log_conn(conn, actor, "JOINER_BLOCKED", user_id, "DENIED_SOD", f"{len(conflicts)} SoD conflicts detected.")
                conn.commit()
                raise ValueError(f"Preventive SoD block: {[c['policy_id'] for c in conflicts]}")
            conn.execute(
                """INSERT OR REPLACE INTO identities
                (user_id, username, tenant, department, identity_type, status, roles_json, direct_entitlements_json, owner, updated_at)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)""",
                (user_id, username, tenant, department, identity_type, json.dumps(sorted(set(roles))), json.dumps(sorted(set(direct))), owner, utc_iso()),
            )
            self._log_conn(conn, actor, "JOINER", user_id, "ALLOWED", f"Provisioned {identity_type} in {department} ({tenant}) with roles {roles}.")
            conn.commit()
        res = self.get_identity(user_id)
        assert res is not None
        return res

    def mover(self, user_id: str, new_department: str, new_roles: list[str], actor: str = "hr-lifecycle") -> dict[str, Any]:
        """Atomically transition department/roles, revoking stale direct and temporary entitlements, enforcing SoD."""
        with self._tx_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                conn.rollback()
                raise KeyError(f"Identity {user_id} not found.")
            if row["status"] != "ACTIVE":
                conn.rollback()
                raise ValueError("Cannot move a disabled identity.")
            conflicts = self.detect_sod_conflicts(new_roles, [], [])
            if conflicts:
                self._log_conn(conn, actor, "MOVER_BLOCKED", user_id, "DENIED_SOD", f"SoD conflict on role change: {[c['policy_id'] for c in conflicts]}")
                conn.commit()
                raise ValueError(f"Preventive SoD block on mover: {[c['policy_id'] for c in conflicts]}")
            old_roles = json.loads(row["roles_json"])
            conn.execute(
                "UPDATE identities SET department=?, roles_json=?, direct_entitlements_json='[]', updated_at=? WHERE user_id=?",
                (new_department, json.dumps(sorted(set(new_roles))), utc_iso(), user_id),
            )
            # Revoke stale temporary grants from previous department role
            conn.execute("UPDATE temp_grants SET revoked=1 WHERE user_id=? AND revoked=0", (user_id,))
            self._log_conn(conn, actor, "MOVER", user_id, "ALLOWED", f"Moved to {new_department}; stripped roles {old_roles} -> {new_roles} and prior temp grants.")
            conn.commit()
        res = self.get_identity(user_id)
        assert res is not None
        return res

    def revoke_role(self, user_id: str, role_to_remove: str, actor: str = "access-review") -> dict[str, Any]:
        """Atomically revoke a specific role from an active identity (enforced immediately across workers)."""
        with self._tx_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT roles_json FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                conn.rollback()
                raise KeyError(f"Identity {user_id} not found.")
            roles = [r for r in json.loads(row["roles_json"]) if r != role_to_remove]
            conn.execute("UPDATE identities SET roles_json=?, updated_at=? WHERE user_id=?", (json.dumps(roles), utc_iso(), user_id))
            self._log_conn(conn, actor, "ROLE_REVOKED", user_id, "REVOKED", f"Removed {role_to_remove}; remaining={roles}")
            conn.commit()
        res = self.get_identity(user_id)
        assert res is not None
        return res

    def leaver(self, user_id: str, disabled_subjects: set[str] | None = None, actor: str = "hr-lifecycle") -> dict[str, Any]:
        """Atomically disable identity in persistent SQLite and revoke all roles/grants (survives restarts & workers)."""
        with self._tx_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT user_id FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                conn.rollback()
                raise KeyError(f"Identity {user_id} not found.")
            conn.execute(
                "UPDATE identities SET status='DISABLED', roles_json='[]', direct_entitlements_json='[]', updated_at=? WHERE user_id=?",
                (utc_iso(), user_id),
            )
            conn.execute("UPDATE temp_grants SET revoked=1 WHERE user_id=?", (user_id,))
            self._log_conn(conn, actor, "LEAVER", user_id, "REVOKED", "Account disabled in persistent governance store; all roles & grants stripped.")
            conn.commit()
        if disabled_subjects is not None:
            disabled_subjects.add(user_id)
        res = self.get_identity(user_id)
        assert res is not None
        return res

    def grant_temporary_access(
        self,
        user_id: str,
        entitlement: str,
        approved_by: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        """Atomically evaluate cumulative SoD across permanent + ALL active temporary entitlements before granting (LIMEN-05)."""
        with self._tx_lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT status, roles_json, direct_entitlements_json FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if not row or row["status"] != "ACTIVE":
                conn.rollback()
                raise ValueError("Cannot grant temporary access to inactive or missing identity.")
            roles = json.loads(row["roles_json"])
            direct = json.loads(row["direct_entitlements_json"])
            existing_temp = self._active_temp_in_conn(conn, user_id)
            cumulative_temp = existing_temp + [entitlement]
            conflicts = self.detect_sod_conflicts(roles, direct, cumulative_temp)
            if conflicts:
                self._log_conn(conn, approved_by, "TEMP_GRANT_BLOCKED", user_id, "DENIED_SOD", f"Cumulative SoD conflict: {[c['policy_id'] for c in conflicts]}")
                conn.commit()
                raise ValueError(f"Temporary grant blocked by cumulative SoD: {[c['policy_id'] for c in conflicts]}")
            gid = f"GRT-{uuid.uuid4().hex[:10].upper()}"
            exp = utc_iso(utc_now() + timedelta(seconds=ttl_seconds))
            conn.execute(
                "INSERT INTO temp_grants (grant_id, user_id, entitlement, approved_by, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)",
                (gid, user_id, entitlement, approved_by, exp),
            )
            self._log_conn(conn, approved_by, "TEMP_GRANT", user_id, "GRANTED", f"{entitlement} until {exp}")
            conn.commit()
        return {"grant_id": gid, "user_id": user_id, "entitlement": entitlement, "expires_at": exp}

    def active_temp_entitlements(self, user_id: str, now: datetime | None = None) -> list[str]:
        with self._connect() as conn:
            return self._active_temp_in_conn(conn, user_id, now)

    def get_identity(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM identities WHERE user_id=?", (user_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["roles"] = json.loads(d.pop("roles_json"))
            d["direct_entitlements"] = json.loads(d.pop("direct_entitlements_json"))
            d["active_temp_entitlements"] = self._active_temp_in_conn(conn, user_id)
        d["effective_entitlements"] = sorted(
            self.effective_entitlements(d["roles"], d["direct_entitlements"], d["active_temp_entitlements"])
        )
        d["sod_conflicts"] = self.detect_sod_conflicts(d["roles"], d["direct_entitlements"], d["active_temp_entitlements"])
        return d

    def list_identities(self, tenant: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if tenant:
                ids = [r["user_id"] for r in conn.execute("SELECT user_id FROM identities WHERE tenant=? ORDER BY user_id", (tenant,)).fetchall()]
            else:
                ids = [r["user_id"] for r in conn.execute("SELECT user_id FROM identities ORDER BY user_id").fetchall()]
        return [ident for uid in ids if (ident := self.get_identity(uid)) is not None]

    def list_audit(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM iam_audit ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]
