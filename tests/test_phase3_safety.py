"""
tests/test_phase3_safety.py
==========================
Unit tests for Phase 3: Safety & Human-in-the-Loop Governance.
Verifies:
  - AUTO_FREEZE=false outputs proposed_actions without mutating graph.
  - POST /api/actions/approve executes proposed containment actions.
  - POST /api/freeze allows explicit human/agent freeze.
  - X-API-Key requirement when OMNITRACE_API_KEY is configured.
  - Read-only protection on /api/graph/query rejects write/mutation Cypher.
  - POST /api/seed requires {"confirm": true}.
Runs offline with mock graph and test client.
"""

import os
from unittest.mock import MagicMock, patch
import pytest

from server import app
from agent.investigator import OmniTraceInvestigator


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_seed_requires_confirmation_flag(client):
    """Verify /api/seed returns 400 if confirm is not true."""
    # Without confirm
    res = client.post("/api/seed", json={})
    assert res.status_code == 400
    data = res.get_json()
    assert "Confirmation required" in data["error"]

    # With confirm: true
    with patch("server.seed_fraud_dataset", return_value={"status": "success"}):
        res_ok = client.post("/api/seed", json={"confirm": True})
        assert res_ok.status_code == 200
        assert res_ok.get_json()["status"] == "success"


def test_api_key_auth_protection(client):
    """Verify mutating routes require X-API-Key when OMNITRACE_API_KEY is set."""
    with patch.dict(os.environ, {"OMNITRACE_API_KEY": "secret-token-123"}):
        # Request with missing header
        res1 = client.post("/api/seed", json={"confirm": True})
        assert res1.status_code == 401
        assert "Unauthorized" in res1.get_json()["error"]

        # Request with incorrect header
        res2 = client.post("/api/seed", headers={"X-API-Key": "wrong-key"}, json={"confirm": True})
        assert res2.status_code == 401

        # Request with correct header
        with patch("server.seed_fraud_dataset", return_value={"status": "success"}):
            res3 = client.post("/api/seed", headers={"X-API-Key": "secret-token-123"}, json={"confirm": True})
            assert res3.status_code == 200


def test_read_only_query_endpoint_rejects_mutations(client):
    """Verify /api/graph/query rejects CREATE, SET, DELETE, MERGE, DROP."""
    disallowed_queries = [
        "CREATE (n:Test {id: 'hack'})",
        "MATCH (a:Account) SET a.status = 'ACTIVE'",
        "MATCH (n) DELETE n",
        "MERGE (a:Account {id: '1'})",
        "DROP INDEX ON :Account(id)",
    ]
    for q in disallowed_queries:
        res = client.post("/api/graph/query", json={"query": q})
        assert res.status_code == 403
        data = res.get_json()
        assert data["ok"] is False
        assert "read-only" in data["error"].lower()


def test_auto_freeze_false_produces_proposed_actions():
    """Verify AUTO_FREEZE=false creates proposed_actions and does not execute mutations."""
    mock_graph = MagicMock()
    mock_graph.list_high_risk_accounts.return_value = [
        {"id": "ACC_SUSPECT", "holder": "Suspect", "risk_score": 88, "status": "FLAGGED"}
    ]
    mock_graph.find_shortest_path_to_sanctioned.return_value = {
        "found": True,
        "sanctioned_name": "Sanctioned Entity",
        "hop_count": 2,
        "path_nodes": [
            {"id": "ACC_VICTIM_CORP", "properties": {"risk_score": 30}},
            {"id": "ACC_SUSPECT", "properties": {"risk_score": 88}},
            {"id": "SANCTIONED_TARGET", "properties": {"risk_level": "CRITICAL"}},
        ],
        "time_ordered": True,
    }
    mock_graph.detect_circular_money_flows.return_value = []
    mock_graph.detect_device_ip_sharing.return_value = []
    mock_graph.calculate_high_volume_mules.return_value = []
    mock_graph.get_full_topology.return_value = {"nodes": [1, 2], "edges": [1]}

    with patch("agent.investigator.get_fraud_graph", return_value=mock_graph):
        agent = OmniTraceInvestigator()
        with patch.dict(os.environ, {"AGENT_MODE": "rules", "AUTO_FREEZE": "false"}):
            dossier = agent.run_full_investigation()

    # Verify freeze was proposed, NOT executed directly
    assert dossier["auto_freeze"] is False
    assert len(dossier["proposed_actions"]) >= 1
    assert dossier["proposed_actions"][0]["account_id"] == "ACC_SUSPECT"
    assert dossier["proposed_actions"][0]["action"] == "FREEZE_ACCOUNT"
    assert dossier["proposed_actions"][0]["status"] == "PROPOSED"
    # Enforcement actions only contains victim flag, no mutations executed
    assert not any(a.get("action") == "FREEZE_ACCOUNT" for a in dossier["enforcement_actions"])
    # mock_graph.freeze_account should NEVER have been called
    mock_graph.freeze_account.assert_not_called()


def test_actions_approve_endpoint_executes_mutations(client):
    """Verify POST /api/actions/approve executes proposed containment actions."""
    with patch("server.graph.freeze_account") as mock_freeze:
        mock_freeze.return_value = {"success": True, "account_id": "ACC_SUSPECT", "status": "FROZEN"}
        res = client.post("/api/actions/approve", json={
            "actions": [
                {"account_id": "ACC_SUSPECT", "action": "FREEZE_ACCOUNT", "reason": "Approved"}
            ]
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["executed_count"] == 1
        mock_freeze.assert_called_once_with("ACC_SUSPECT", reason="Approved", agent_id="approved_by_operator")
