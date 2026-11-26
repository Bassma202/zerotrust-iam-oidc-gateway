"""Explainable Jaccard-Similarity Role-Mining Engine with Baseline Comparison Metrics."""

from __future__ import annotations

from typing import Any


def jaccard_similarity(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def mine_candidate_roles(
    user_entitlements: dict[str, set[str]],
    similarity_threshold: float = 0.65,
    min_cluster_size: int = 2,
) -> dict[str, Any]:
    """Discover candidate least-privilege roles via Jaccard similarity clustering.

    Compares candidate role assignments against direct per-user entitlement baseline:
    - Entitlement coverage (%)
    - Permission redundancy reduction (%)
    - Over-assignment / residual outlier entitlements requiring human review
    - Never auto-provisions privileges without explicit governance approval.
    """
    users = sorted(user_entitlements.keys())
    assigned: set[str] = set()
    clusters: list[list[str]] = []

    for u in users:
        if u in assigned:
            continue
        group = [u]
        assigned.add(u)
        for v in users:
            if v in assigned:
                continue
            if jaccard_similarity(user_entitlements[u], user_entitlements[v]) >= similarity_threshold:
                group.append(v)
                assigned.add(v)
        if len(group) >= min_cluster_size:
            clusters.append(group)

    candidate_roles: list[dict[str, Any]] = []
    covered_pairs = 0
    total_pairs = sum(len(ents) for ents in user_entitlements.values())
    overprivilege_outliers: list[dict[str, Any]] = []

    for idx, members in enumerate(clusters, start=1):
        # Core intersection ensures zero over-assignment by default
        core_ents = set.intersection(*(user_entitlements[m] for m in members))
        if not core_ents:
            continue
        role_name = f"CANDIDATE_ROLE_{idx:02d}"
        covered_pairs += len(core_ents) * len(members)
        for m in members:
            extra = sorted(user_entitlements[m] - core_ents)
            if extra:
                overprivilege_outliers.append(
                    {"user": m, "candidate_role": role_name, "unexplained_entitlements": extra}
                )
        candidate_roles.append(
            {
                "role_name": role_name,
                "members": members,
                "core_entitlements": sorted(core_ents),
                "approval_required": True,
                "over_assignment_count": 0,
            }
        )

    unexplained_pairs = total_pairs - covered_pairs
    # Baseline: 1 direct grant per (user, entitlement). With role mining: 1 role-grant per member + 1 definition per core entitlement + remaining exceptions
    baseline_assignments = total_pairs
    mined_assignments = sum(len(r["members"]) + len(r["core_entitlements"]) for r in candidate_roles) + unexplained_pairs
    redundancy_reduction_pct = (
        round((baseline_assignments - mined_assignments) / baseline_assignments * 100.0, 2)
        if baseline_assignments > 0
        else 0.0
    )

    return {
        "similarity_threshold": similarity_threshold,
        "users_analyzed": len(users),
        "candidate_roles": candidate_roles,
        "metrics": {
            "baseline_direct_assignments": baseline_assignments,
            "post_mining_assignments": mined_assignments,
            "entitlement_coverage_pct": round((covered_pairs / total_pairs * 100.0), 2) if total_pairs else 0.0,
            "assignment_redundancy_reduction_pct": redundancy_reduction_pct,
            "unexplained_entitlement_count": unexplained_pairs,
            "over_assignment_risk_count": 0,
        },
        "overprivilege_review_queue": overprivilege_outliers,
        "governance_note": "Recommendations require explicit IAM owner approval before provisioning.",
    }
