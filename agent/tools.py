"""
agent/tools.py
==============
FalkorDB Graph Algorithm Tools for the Autonomous Investigator.
Conforms to standard OpenAI / Anthropic / Gemini MCP Tool Call specs.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.falkor_graph import get_fraud_graph
def tool_list_high_risk_accounts(threshold: int = 50, min_risk: int = None, graph=None) -> List[Dict[str, Any]]:
    """List bank accounts with high risk scores or flagged status to seed investigation."""
    g = graph or get_fraud_graph()
    t = min_risk if min_risk is not None else threshold
    return g.list_high_risk_accounts(t)


def tool_get_account_neighbors(account_id: str, graph=None) -> Dict[str, Any]:
    """Retrieve direct neighbors (incoming/outgoing transfers, devices, IPs) for an account."""
    g = graph or get_fraud_graph()
    return g.get_account_neighbors(account_id)


def tool_find_shortest_path_to_sanctioned(account_id: str, graph=None) -> Dict[str, Any]:
    """Calculate shortest transaction path between an account and any blacklisted entity in FalkorDB."""
    g = graph or get_fraud_graph()
    return g.find_shortest_path_to_sanctioned(account_id)


def tool_detect_circular_money_laundering(max_hops: int = 4, graph=None) -> List[Dict[str, Any]]:
    """Detect circular loops where funds cycle back to origin (structuring / layering)."""
    g = graph or get_fraud_graph()
    return g.detect_circular_money_flows(max_hops)


def tool_detect_device_ip_collisions(graph=None) -> List[Dict[str, Any]]:
    """Find accounts sharing the same hardware device fingerprint or bulletproof IP."""
    g = graph or get_fraud_graph()
    return g.detect_device_ip_sharing()


def tool_calculate_pass_through_mules(graph=None) -> List[Dict[str, Any]]:
    """Identify intermediary accounts with high in/out degree fan-out."""
    g = graph or get_fraud_graph()
    return g.calculate_high_volume_mules()


def tool_freeze_compromised_account(account_id: str, reason: str, graph=None) -> Dict[str, Any]:
    """Execute direct graph intervention: Freeze account and generate enforcement action node."""
    g = graph or get_fraud_graph()
    return g.freeze_account(account_id=account_id, reason=reason)


def tool_propose_freeze(account_id: str, reason: str, evidence: str = "", graph=None) -> Dict[str, Any]:
    """Propose an account freeze for human-in-the-loop review or autonomous approval."""
    return {
        "account_id": account_id,
        "action": "FREEZE_ACCOUNT",
        "status": "PROPOSED",
        "reason": reason,
        "evidence": evidence,
    }


def tool_recall_past_investigations(account_id: str, graph=None) -> List[Dict[str, Any]]:
    """Recall past investigations, uncovered threats, and operator approval/rejection history for an account."""
    g = graph or get_fraud_graph()
    return g.recall_past_investigations(account_id)


def tool_calculate_pagerank_centrality(top_k: int = 10, graph=None) -> List[Dict[str, Any]]:
    """Calculate PageRank centrality over account transactions using FalkorDB GraphBLAS algo.pageRank."""
    g = graph or get_fraud_graph()
    return g.calculate_pagerank(top_k=top_k)


def tool_detect_weakly_connected_components(graph=None) -> List[Dict[str, Any]]:
    """Detect weakly connected components across the graph using FalkorDB GraphBLAS algo.wcc."""
    g = graph or get_fraud_graph()
    return g.detect_wcc()


INVESTIGATION_TOOLS = [
    {
        "name": "list_high_risk_accounts",
        "description": "Discover high-risk or flagged accounts in the graph to prioritize starting points for investigation.",
        "parameters": {
            "type": "object",
            "properties": {
                "min_risk": {"type": "integer", "description": "Minimum risk score threshold (default: 50)"},
                "threshold": {"type": "integer", "description": "Alternative alias for min_risk (default: 50)"},
            },
        },
        "handler": tool_list_high_risk_accounts,
    },
    {
        "name": "get_account_neighbors",
        "description": "Explore direct neighbors of an account: incoming/outgoing money transfers, linked devices, and IPs.",
        "parameters": {
            "type": "object",
            "properties": {"account_id": {"type": "string", "description": "Account ID to inspect neighbors for"}},
            "required": ["account_id"],
        },
        "handler": tool_get_account_neighbors,
    },
    {
        "name": "find_shortest_path_to_sanctioned",
        "description": "Calculate shortest transaction path between an account and blacklisted entities in FalkorDB.",
        "parameters": {
            "type": "object",
            "properties": {"account_id": {"type": "string", "description": "The bank account ID to audit"}},
            "required": ["account_id"],
        },
        "handler": tool_find_shortest_path_to_sanctioned,
    },
    {
        "name": "detect_circular_money_laundering",
        "description": "Detect circular money laundering cycles where funds loop back to the origin.",
        "parameters": {
            "type": "object",
            "properties": {"max_hops": {"type": "integer", "default": 4}},
        },
        "handler": tool_detect_circular_money_laundering,
    },
    {
        "name": "detect_device_ip_collisions",
        "description": "Detect disparate accounts sharing identical device fingerprints or VPN IPs.",
        "parameters": {"type": "object", "properties": {}},
        "handler": tool_detect_device_ip_collisions,
    },
    {
        "name": "calculate_pass_through_mules",
        "description": "Identify high-volume intermediary mule accounts using degree centrality.",
        "parameters": {"type": "object", "properties": {}},
        "handler": tool_calculate_pass_through_mules,
    },
    {
        "name": "propose_freeze",
        "description": "Propose freezing a compromised or mule account with explicit reason and evidence trail for human approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Account ID to propose freezing"},
                "reason": {"type": "string", "description": "Justification for the freeze action"},
                "evidence": {"type": "string", "description": "Concrete evidence trail from graph queries"},
            },
            "required": ["account_id", "reason"],
        },
        "handler": tool_propose_freeze,
    },
    {
        "name": "recall_past_investigations",
        "description": "Recall prior investigations, findings, and operator decisions (approved freezes, rejections) for an account from graph memory.",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "The bank account ID to check prior memory for"},
            },
            "required": ["account_id"],
        },
        "handler": tool_recall_past_investigations,
    },
    {
        "name": "freeze_compromised_account",
        "description": "Directly mutate graph to freeze account and sever active transaction routes (when authorized).",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["account_id", "reason"],
        },
        "handler": tool_freeze_compromised_account,
    },
    {
        "name": "calculate_pagerank_centrality",
        "description": "Compute PageRank transaction centrality over accounts using FalkorDB algo.pageRank to detect critical transit hubs.",
        "parameters": {
            "type": "object",
            "properties": {
                "top_k": {"type": "integer", "description": "Number of top ranked accounts to return (default: 10)"},
            },
        },
        "handler": tool_calculate_pagerank_centrality,
    },
    {
        "name": "detect_weakly_connected_components",
        "description": "Partition graph entities into weakly connected components via FalkorDB algo.wcc to isolate Sybil clusters.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
        "handler": tool_detect_weakly_connected_components,
    },
]
