"""
agent/tools.py
==============
FalkorDB Graph Algorithm Tools for the Autonomous Investigator.
Conforms to standard OpenAI / Anthropic / Gemini MCP Tool Call specs.
"""

from __future__ import annotations

from typing import Any, Dict, List
from core.falkor_graph import get_fraud_graph

graph = get_fraud_graph()


def tool_find_shortest_path_to_sanctioned(account_id: str) -> Dict[str, Any]:
    """Calculate shortest transaction path between an account and any blacklisted entity in FalkorDB."""
    return graph.find_shortest_path_to_sanctioned(account_id)


def tool_detect_circular_money_laundering(max_hops: int = 4) -> List[Dict[str, Any]]:
    """Detect circular loops where funds cycle back to origin (structuring / layering)."""
    return graph.detect_circular_money_flows(max_hops)


def tool_detect_device_ip_collisions() -> List[Dict[str, Any]]:
    """Find accounts sharing the same hardware device fingerprint or bulletproof IP."""
    return graph.detect_device_ip_sharing()


def tool_calculate_pass_through_mules() -> List[Dict[str, Any]]:
    """Identify intermediary accounts with high in/out degree fan-out."""
    return graph.calculate_high_volume_mules()


def tool_freeze_compromised_account(account_id: str, reason: str) -> Dict[str, Any]:
    """Execute direct graph intervention: Freeze account and generate enforcement action node."""
    return graph.freeze_account(account_id=account_id, reason=reason)


INVESTIGATION_TOOLS = [
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
        "name": "freeze_compromised_account",
        "description": "Mutate graph to freeze account and severed active transaction routes.",
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
]
