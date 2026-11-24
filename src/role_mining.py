"""
Automated Role Mining & Privilege Clustering Engine
Author: Bassma Alaoui Sossey
Analyzes raw enterprise entitlement dumps to discover candidate business roles
using Jaccard similarity and agglomerative clustering, mitigating 'role explosion'.
"""

from typing import List, Dict, Set, Tuple

def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculates Jaccard similarity index between two entitlement sets."""
    if not set_a and not set_b:
        return 1.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return round(intersection / union, 4) if union > 0 else 0.0

class RoleMiningEngine:
    def __init__(self, similarity_threshold: float = 0.70):
        self.similarity_threshold = similarity_threshold

    def mine_candidate_roles(self, user_entitlements: Dict[str, List[str]]) -> Dict[str, Any]:
        """
        user_entitlements: {username: [list of technical permissions]}
        Discovers clusters of users with highly overlapping permissions to propose clean business roles.
        """
        user_sets = {u: set(perms) for u, perms in user_entitlements.items()}
        clusters = []
        visited = set()

        users = list(user_sets.keys())
        for i in range(len(users)):
            u1 = users[i]
            if u1 in visited:
                continue

            current_cluster = {u1}
            visited.add(u1)

            for j in range(i + 1, len(users)):
                u2 = users[j]
                if u2 in visited:
                    continue

                sim = jaccard_similarity(user_sets[u1], user_sets[u2])
                if sim >= self.similarity_threshold:
                    current_cluster.add(u2)
                    visited.add(u2)

            # Common permissions across the cluster
            common_perms = set.intersection(*(user_sets[u] for u in current_cluster))
            clusters.append({
                "cluster_size": len(current_cluster),
                "members": list(current_cluster),
                "core_role_permissions": sorted(list(common_perms)),
                "coverage_score": round(len(common_perms) / max(1, len(user_sets[u1])), 2)
            })

        return {
            "total_users_analyzed": len(user_entitlements),
            "candidate_business_roles_found": len(clusters),
            "clusters": sorted(clusters, key=lambda x: x["cluster_size"], reverse=True)
        }

if __name__ == "__main__":
    # Test dataset representing enterprise hospital staff
    mock_users = {
        "dr_fatima": ["patient:read", "patient:write", "lab:order", "vpn:access"],
        "dr_youssef": ["patient:read", "patient:write", "lab:order", "vpn:access"],
        "dr_mehdi": ["patient:read", "patient:write", "lab:order"],
        "nurse_amina": ["patient:read", "vitals:write"],
        "nurse_sarah": ["patient:read", "vitals:write"],
        "accountant_omar": ["billing:read", "billing:write", "financial:report"]
    }
    miner = RoleMiningEngine(similarity_threshold=0.75)
    report = miner.mine_candidate_roles(mock_users)
    print(f"Discovered {report['candidate_business_roles_found']} optimal candidate roles.")
    for idx, c in enumerate(report["clusters"], 1):
        print(f"Role {idx}: {len(c['members'])} users -> Permissions: {c['core_role_permissions']}")
