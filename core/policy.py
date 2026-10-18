"""
core/policy.py
==============
Central enforcement and investigation policy engine for OmniTrace.
Defines risk thresholds, confidence score formulas, and action rules
(FREEZE, FLAG_VICTIM, MONITOR) so decision criteria are never scattered.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class ThreatPolicy:
    """Rules and confidence scoring for autonomous fraud containment."""

    MIN_FREEZE_CONFIDENCE = 0.80
    SANCTIONS_PATH_CONFIDENCE = 0.95
    CIRCULAR_RING_CONFIDENCE = 0.90
    SYBIL_FARM_CONFIDENCE = 0.85

    @classmethod
    def evaluate_sanctions_path(
        cls,
        path_nodes: List[Dict[str, Any]],
        hop_count: int,
        time_ordered: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluates an OFAC sanctions trail.
        - First node with significant funds outflow and low initial risk is treated as VICTIM.
        - Intermediaries are marked for FREEZE.
        - Sanctioned destination is already blacklisted.
        """
        confidence = cls.SANCTIONS_PATH_CONFIDENCE if time_ordered else (cls.SANCTIONS_PATH_CONFIDENCE - 0.10)

        actions = []
        if not path_nodes:
            return {"confidence": 0.0, "actions": actions}

        victim_id = None
        # If the path starts with an innocent/compromised victim account
        first_node = path_nodes[0]
        first_id = first_node.get("id", "")
        first_risk = first_node.get("properties", {}).get("risk_score", 0)

        if "VICTIM" in first_id.upper() or first_risk < 50:
            victim_id = first_id
            actions.append({
                "account_id": first_id,
                "action": "FLAG_VICTIM",
                "reason": "Probable victim origin of compromised funds. Do not freeze; escalate for human review.",
                "confidence": confidence,
            })

        # Intermediaries along the path
        for node in path_nodes[1:-1]:
            nid = node.get("id", "")
            if nid and not nid.startswith("SANCTION_") and nid != victim_id:
                actions.append({
                    "account_id": nid,
                    "action": "FREEZE",
                    "reason": f"Intermediary money mule on {hop_count}-hop trail to sanctioned entity.",
                    "confidence": confidence,
                })

        return {
            "threat_type": "OFAC_SANCTIONS_EXPOSURE",
            "severity": "CRITICAL",
            "confidence": confidence,
            "victim_account": victim_id,
            "actions": actions,
        }

    @classmethod
    def evaluate_circular_ring(
        cls,
        ring_members: List[str],
        amounts: List[float],
    ) -> Dict[str, Any]:
        """Evaluates a circular structuring ring (A -> B -> C -> A)."""
        confidence = cls.CIRCULAR_RING_CONFIDENCE
        actions = []

        for member in ring_members:
            actions.append({
                "account_id": member,
                "action": "FREEZE",
                "reason": f"Member of circular structuring ring cycling ${amounts[0] if amounts else 0:,.2f}.",
                "confidence": confidence,
            })

        return {
            "threat_type": "CIRCULAR_STRUCTURING_RING",
            "severity": "HIGH",
            "confidence": confidence,
            "actions": actions,
        }

    @classmethod
    def evaluate_sybil_cluster(
        cls,
        cluster_type: str,
        identifier: str,
        member_accounts: List[str],
    ) -> Dict[str, Any]:
        """
        Evaluates a cluster of accounts sharing hardware device fingerprint or IP proxy.
        If 3 or more accounts share an entity, freeze is recommended; otherwise flag for review.
        """
        size = len(member_accounts)
        confidence = cls.SYBIL_FARM_CONFIDENCE if size >= 3 else 0.70
        action_type = "FREEZE" if size >= 3 else "FLAG_REVIEW"

        actions = []
        for acc in member_accounts:
            actions.append({
                "account_id": acc,
                "action": action_type,
                "reason": f"Sybil entity collision: {size} accounts sharing {cluster_type} '{identifier}'.",
                "confidence": confidence,
            })

        return {
            "threat_type": "SYBIL_FINGERPRINT_COLLISION",
            "severity": "HIGH" if size >= 3 else "MEDIUM",
            "confidence": confidence,
            "cluster_type": cluster_type,
            "identifier": identifier,
            "member_count": size,
            "actions": actions,
        }
