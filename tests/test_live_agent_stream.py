"""
tests/test_live_agent_stream.py
===============================
Tests for real-time SSE streaming, LLM tool calling, step capping,
canonical ring deduplication, and propose_freeze behavior.
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from agent.investigator import OmniTraceInvestigator
from server import app


class FakeFalkorGraph:
    """Mock graph providing controllable query and algorithm responses."""
    def __init__(self):
        self.host = "localhost"
        self.port = 6379
        self.graph_name = "test_fraud_graph"
        self.graph = MagicMock()
        self.db = MagicMock()

    def get_full_topology(self, node_limit=500, edge_limit=800):
        return {
            "nodes": [
                {"id": "ACC_1", "label": "Account", "color": "#00f0ff"},
                {"id": "ACC_2", "label": "Account", "color": "#00f0ff"},
                {"id": "ACC_3", "label": "Account", "color": "#00f0ff"},
                {"id": "SANCTION_1", "label": "SanctionedEntity", "color": "#ff2d55"},
            ],
            "edges": [
                {"from": "ACC_1", "to": "ACC_2", "amount": 9500},
                {"from": "ACC_2", "to": "ACC_3", "amount": 9400},
                {"from": "ACC_3", "to": "SANCTION_1", "amount": 9300},
            ]
        }

    def list_high_risk_accounts(self, threshold=50):
        return [
            {"id": "ACC_1", "risk_score": 85, "status": "flagged"},
            {"id": "ACC_2", "risk_score": 75, "status": "active"},
        ]

    def get_account_neighbors(self, account_id):
        return {"account_id": account_id, "incoming": [], "outgoing": ["ACC_2"], "devices": ["DEV_1"], "ips": []}

    def find_shortest_path_to_sanctioned(self, account_id):
        if account_id == "ACC_1":
            return {
                "found": True,
                "path_nodes": [
                    {"id": "ACC_1", "properties": {"risk_score": 40}},
                    {"id": "ACC_2", "properties": {"risk_score": 80}},
                    {"id": "SANCTION_1", "properties": {"name": "Blocked Syndicate"}},
                ],
                "hop_count": 2,
                "sanctioned_id": "SANCTION_1",
                "sanctioned_name": "Blocked Syndicate",
                "time_ordered": True,
                "engine_ms": 0.42,
                "roundtrip_ms": 1.25,
            }
        return {"found": False, "engine_ms": 0.1, "roundtrip_ms": 0.5}

    def detect_circular_money_flows(self, max_hops=4):
        # Return a single canonical ring
        return [
            {
                "ring_members": ["ACC_A", "ACC_B", "ACC_C"],
                "transferred_amounts": [5000.0, 4950.0, 4900.0],
                "hop_count": 3,
                "engine_ms": 0.35,
                "roundtrip_ms": 1.1,
            }
        ]

    def detect_device_ip_sharing(self):
        return [
            {
                "cluster_type": "DEVICE",
                "identifier": "FP_MOCK_999",
                "details": "Linux x86_64",
                "member_count": 3,
                "members": ["ACC_X1", "ACC_X2", "ACC_X3"],
                "engine_ms": 0.28,
                "roundtrip_ms": 0.9,
            }
        ]

    def calculate_high_volume_mules(self):
        return [{"account_id": "ACC_2", "in_degree": 4, "out_degree": 4, "pass_through_ratio": 0.95}]

    def freeze_account(self, account_id, reason="Containment", agent_id="omni_sentinel_01"):
        return {
            "success": True,
            "status": "FROZEN",
            "account_id": account_id,
            "blocked_edges_count": 2,
            "audit_hash": "sha256_mock_hash",
        }


def test_streaming_event_sequence_in_rules_mode():
    """Verify stream_investigation yields expected SSE sequence in rules fallback mode."""
    fake_graph = FakeFalkorGraph()
    investigator = OmniTraceInvestigator(provider="rules", graph=fake_graph)

    events = list(investigator.stream_investigation(auto_freeze=False))
    event_types = [e["event"] for e in events]

    assert "thinking" in event_types
    assert "tool_call" in event_types
    assert "tool_result" in event_types
    assert "finding" in event_types
    assert "proposed_action" in event_types
    assert "done" in event_types

    done_event = [e for e in events if e["event"] == "done"][0]
    dossier = done_event["data"]["dossier"]
    assert len(dossier["findings"]) >= 3
    assert len(dossier["proposed_actions"]) >= 1
    assert dossier["graph_metrics"]["status"] == "COMPLETED"


def test_mock_llm_step_cap():
    """Verify tool calling loop halts when max_steps is reached."""
    fake_graph = FakeFalkorGraph()

    # Mock LLM that endlessly calls a tool
    def endless_llm(history, step):
        return {"tool": "list_high_risk_accounts", "args": {"threshold": 50}}

    investigator = OmniTraceInvestigator(
        provider="anthropic",
        max_steps=5,
        mock_llm=endless_llm,
        graph=fake_graph,
    )

    events = list(investigator.stream_investigation(auto_freeze=False))
    tool_calls = [e for e in events if e["event"] == "tool_call"]
    assert len(tool_calls) == 5

    done_event = [e for e in events if e["event"] == "done"][0]
    assert len(done_event["data"]["dossier"]["agent_trace"]) == 5


def test_mock_anthropic_propose_freeze():
    """Verify agent calling propose_freeze generates proposed_action and does not freeze unless auto_freeze=true."""
    fake_graph = FakeFalkorGraph()

    steps = [
        {"tool": "list_high_risk_accounts", "args": {"min_risk": 50}},
        {"tool": "propose_freeze", "args": {"account_id": "ACC_SUSPECT", "reason": "OFAC nexus", "evidence": "Direct hop"}},
        {"type": "finish"},
    ]

    def mock_llm_flow(history, step):
        if step <= len(steps):
            return steps[step - 1]
        return {"type": "finish"}

    # Test with auto_freeze=False
    investigator = OmniTraceInvestigator(
        mock_llm=mock_llm_flow,
        graph=fake_graph,
    )
    events = list(investigator.stream_investigation(auto_freeze=False))
    prop_actions = [e for e in events if e["event"] == "proposed_action"]
    assert any(a["data"]["account_id"] == "ACC_SUSPECT" for a in prop_actions)

    done_event = [e for e in events if e["event"] == "done"][0]
    dossier = done_event["data"]["dossier"]
    assert any(a["account_id"] == "ACC_SUSPECT" for a in dossier["proposed_actions"])
    # Not frozen directly because auto_freeze=False
    assert not any(a.get("account_id") == "ACC_SUSPECT" for a in dossier["enforcement_actions"])


def test_circular_ring_rotation_deduplication():
    """Verify multiple rotations of identical ring produce only one finding."""
    fake_graph = FakeFalkorGraph()
    investigator = OmniTraceInvestigator(graph=fake_graph)

    dossier = {"findings": [], "proposed_actions": [], "enforcement_actions": []}
    # Simulate first rotation: A -> B -> C
    cycle_1 = [{"ring_members": ["ACC_A", "ACC_B", "ACC_C"], "transferred_amounts": [1000]}]
    f1, a1 = investigator._synthesize_finding_from_tool(dossier, "detect_circular_money_laundering", {}, cycle_1, 1.0)

    # Simulate second rotation: B -> C -> A (same physical ring)
    cycle_2 = [{"ring_members": ["ACC_B", "ACC_C", "ACC_A"], "transferred_amounts": [1000]}]
    f2, a2 = investigator._synthesize_finding_from_tool(dossier, "detect_circular_money_laundering", {}, cycle_2, 1.0)

    assert len(dossier["findings"]) == 1
    assert len(f1) == 1
    assert len(f2) == 0  # Deduplicated!


def test_server_sse_stream_endpoint():
    """Verify Flask /api/investigate/stream endpoint returns text/event-stream with no buffering headers."""
    client = app.test_client()
    resp = client.get("/api/investigate/stream?auto_freeze=false")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.content_type
    assert resp.headers.get("Cache-Control") == "no-cache, no-transform"
    assert resp.headers.get("X-Accel-Buffering") == "no"

    # Read part of the stream
    stream_content = resp.data.decode("utf-8")
    assert "event: " in stream_content
    assert "data: " in stream_content
    assert "event: done" in stream_content
