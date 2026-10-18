"""
tests/test_phase1_agent.py
==========================
Unit tests for Phase 1: Real Agent Loop & Dynamic Discovery.
Verifies mock LLM tool calling, zero hardcoded IDs in agent/, and agent_trace recording.
Runs without a live FalkorDB instance using mocks.
"""

import os
import re
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from agent.investigator import OmniTraceInvestigator
from agent.tools import INVESTIGATION_TOOLS


def test_no_hardcoded_account_ids_in_agent():
    """Verify that no specific account IDs remain hardcoded in agent/*.py files."""
    agent_dir = Path(__file__).resolve().parent.parent / "agent"
    assert agent_dir.exists(), f"Directory not found: {agent_dir}"

    forbidden_patterns = [
        r"ACC_MULE_ALPHA",
        r"ACC_MULE_BETA",
        r"ACC_PANAMA_SHELL",
        r"ACC_VICTIM_01",
        r"ACC_RING_A",
        r"ACC_RING_B",
        r"ACC_RING_C",
        r"ACC_FARM_MULE_01",
    ]

    for py_file in agent_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            matches = re.findall(pattern, content)
            assert not matches, f"Found hardcoded pattern '{pattern}' in {py_file.name}"


def test_investigation_tools_registry():
    """Verify that all required tools are defined and have valid schemas and handlers."""
    tool_names = {t["name"] for t in INVESTIGATION_TOOLS}
    expected = {
        "list_high_risk_accounts",
        "get_account_neighbors",
        "find_shortest_path_to_sanctioned",
        "detect_circular_money_laundering",
        "detect_device_ip_collisions",
        "calculate_pass_through_mules",
        "freeze_compromised_account",
    }
    assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"
    for t in INVESTIGATION_TOOLS:
        assert callable(t["handler"]), f"Handler for {t['name']} is not callable"
        assert "description" in t and len(t["description"]) > 10


def test_mock_llm_tool_calling_loop():
    """Verify the agent decides tools dynamically via LLM and records agent_trace."""
    called_steps = []

    def fake_llm(history, step):
        called_steps.append(step)
        if step == 1:
            return {"tool": "list_high_risk_accounts", "args": {"threshold": 45}}
        elif step == 2:
            return {"tool": "detect_circular_money_laundering", "args": {"max_hops": 3}}
        else:
            return {"type": "finish"}

    # Mock the graph layer to avoid requiring a live database
    mock_graph = MagicMock()
    mock_graph.list_high_risk_accounts.return_value = [
        {"id": "ACC_TEST_999", "holder": "Test Subject", "risk_score": 85, "status": "FLAGGED"}
    ]
    mock_graph.detect_circular_money_flows.return_value = [
        {"ring_members": ["ACC_TEST_999", "ACC_B", "ACC_C"], "transferred_amounts": [5000]}
    ]
    mock_graph.get_full_topology.return_value = {"nodes": [1, 2, 3], "edges": [1, 2]}

    with patch("agent.investigator.get_fraud_graph", return_value=mock_graph):
        agent = OmniTraceInvestigator(mock_llm=fake_llm, max_steps=5)
        dossier = agent.run_full_investigation()

    assert dossier["agent_mode"] == "llm"
    assert len(dossier["agent_trace"]) == 2
    assert dossier["agent_trace"][0]["tool"] == "list_high_risk_accounts"
    assert dossier["agent_trace"][0]["arguments"] == {"threshold": 45}
    assert dossier["agent_trace"][1]["tool"] == "detect_circular_money_laundering"
    assert len(dossier["findings"]) >= 1
    assert dossier["graph_metrics"]["total_nodes_audited"] == 3


def test_rules_fallback_mode_discovers_accounts_dynamically():
    """Verify rules fallback runs without hardcoded accounts and sets agent_mode='rules'."""
    mock_graph = MagicMock()
    mock_graph.list_high_risk_accounts.return_value = [
        {"id": "DYNAMIC_ACC_100", "holder": "Discovered Mule", "risk_score": 90, "status": "SUSPICIOUS"}
    ]
    mock_graph.find_shortest_path_to_sanctioned.return_value = {
        "found": True,
        "sanctioned_name": "Test Blacklist",
        "hop_count": 2,
        "path_nodes": [{"id": "DYNAMIC_ACC_100"}, {"id": "SANCTION_TEST"}],
    }
    mock_graph.detect_circular_money_flows.return_value = []
    mock_graph.detect_device_ip_sharing.return_value = []
    mock_graph.calculate_high_volume_mules.return_value = []
    mock_graph.freeze_account.return_value = {"account_id": "DYNAMIC_ACC_100", "success": True, "status": "FROZEN"}
    mock_graph.get_full_topology.return_value = {"nodes": [1, 2], "edges": [1]}

    with patch("agent.investigator.get_fraud_graph", return_value=mock_graph):
        agent = OmniTraceInvestigator()
        with patch.dict(os.environ, {"AGENT_MODE": "rules"}):
            dossier = agent.run_full_investigation()

    assert dossier["agent_mode"] == "rules"
    assert len(dossier["agent_trace"]) >= 4
    # The source account investigated must be the dynamically discovered ID
    assert dossier["findings"][0]["source_account"] == "DYNAMIC_ACC_100"
    assert dossier["enforcement_actions"][0]["account_id"] == "DYNAMIC_ACC_100"
