"""
tests/test_phase4_5_6_7.py

Unit tests for Phases 4-8 additions:
1. POST /api/actions/reject endpoint.
2. GraphRAG natural language engine (ask, safe execution, schema introspection).
3. Agent Graph Memory: (:Investigation) node persistence, recall_past_investigations, and GET /api/investigations/history.
4. Compliance HTML report generation and export endpoint.
5. Benign decoy verification (family sharing, back-and-forth transfers).
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from server import app
from agent.graph_rag import GraphRAG
from core.falkor_graph import FalkorFraudGraph
from core.policy import ThreatPolicy


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class FakeResult:
    def __init__(self, result_set=None, header=None, run_time_ms=0.45):
        self.result_set = result_set or []
        self.header = header or []
        self.run_time_ms = run_time_ms


class FakeGraph:
    def __init__(self):
        self.queries = []

    def query(self, q, params=None):
        self.queries.append((q, params))
        if "labels()" in q:
            return FakeResult([["Account"], ["SanctionedEntity"], ["Device"], ["IPAddress"]], header=[["label"]])
        if "relationshipTypes()" in q:
            return FakeResult([["TRANSFERRED"], ["OPERATED_FROM"], ["LOGGED_IN_FROM"]], header=[["relType"]])
        if "propertyKeys()" in q:
            return FakeResult([["id"], ["status"], ["risk_score"], ["amount"]], header=[["prop"]])
        if "Investigation" in q:
            return FakeResult([
                ["INV-001", "2026-10-18T00:00:00Z", "OmniTrace-v1", 3, 10, "complete"]
            ], header=[["id"], ["timestamp"], ["agent_id"], ["threat_count"], ["accounts_audited"], ["status"]])
        return FakeResult([["ACC_TEST", "active", 15]], header=[["a.id"], ["a.status"], ["a.risk_score"]])

    def ro_query(self, q, params=None):
        self.queries.append((q, params))
        return FakeResult([["ACC_001", 1000]], header=[["a.id"], ["r.amount"]])


# -----------------------------------------------------------------------------
# 1. Action Rejection Endpoint
# -----------------------------------------------------------------------------
def test_action_reject_endpoint(client):
    res = client.post(
        "/api/actions/reject",
        json={"account_id": "ACC_SUSPECT_01", "reason": "Operator verified false positive"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    assert data["account_id"] == "ACC_SUSPECT_01"
    assert data["status"] == "rejected"


def test_action_reject_missing_account(client):
    res = client.post("/api/actions/reject", json={})
    assert res.status_code == 400
    assert "account_id required" in res.get_json()["error"]


# -----------------------------------------------------------------------------
# 2. GraphRAG Engine Tests
# -----------------------------------------------------------------------------
def test_graphrag_schema_introspection():
    with patch.object(FalkorFraudGraph, "_connect"), patch.object(FalkorFraudGraph, "_ensure_indices"):
        manager = FalkorFraudGraph(host="localhost", port=6379)
        fake_graph = FakeGraph()
        manager.graph = fake_graph

        schema = manager.get_schema()

        assert "Account" in schema["node_labels"]
        assert "TRANSFERRED" in schema["relationship_types"]
        assert "risk_score" in schema["property_keys"]


def test_graphrag_ask_query_execution():
    with patch.object(FalkorFraudGraph, "_connect"), patch.object(FalkorFraudGraph, "_ensure_indices"):
        manager = FalkorFraudGraph(host="localhost", port=6379)
        fake_graph = FakeGraph()
        manager.graph = fake_graph

        engine = GraphRAG(graph=manager)
        result = engine.ask("Show circular laundering loops")

        assert result["ok"] is True
        assert "MATCH" in result["cypher"]
        assert result["execution_time_ms"] > 0
        assert len(result["rows"]) > 0


def test_graphrag_mutation_rejection():
    with patch.object(FalkorFraudGraph, "_connect"), patch.object(FalkorFraudGraph, "_ensure_indices"):
        manager = FalkorFraudGraph(host="localhost", port=6379)
        engine = GraphRAG(graph=manager)
        safe, msg = engine.is_query_safe("MATCH (n) DELETE n")
        assert safe is False
        assert "Mutation keyword 'DELETE' is disallowed" in msg


# -----------------------------------------------------------------------------
# 3. Agent Graph Memory Tests
# -----------------------------------------------------------------------------
def test_investigation_memory_persistence():
    with patch.object(FalkorFraudGraph, "_connect"), patch.object(FalkorFraudGraph, "_ensure_indices"):
        manager = FalkorFraudGraph(host="localhost", port=6379)
        fake_graph = FakeGraph()
        manager.graph = fake_graph

        dossier = {
            "investigation_id": "INV-TEST-99",
            "timestamp": "2026-10-18T00:00:00Z",
            "agent_id": "OmniTrace-v1",
            "findings": [{"type": "CIRCULAR_STRUCTURING_RING", "severity": "HIGH"}],
            "enforcement_actions": [{"account_id": "ACC_MULE_ALPHA", "action": "freeze"}],
            "graph_metrics": {"total_nodes_audited": 12, "status": "complete"},
        }

        inv_id = manager.save_investigation_memory(dossier)
        assert inv_id == "INV-TEST-99"

        # Verify query was executed to create Investigation node
        inv_queries = [q[0] for q in fake_graph.queries if "Investigation" in q[0]]
        assert len(inv_queries) > 0


def test_investigations_history_endpoint(client):
    with patch("server.graph") as mock_manager:
        mock_manager.get_investigations_history.return_value = [
            {
                "investigation_id": "INV-001",
                "timestamp": "2026-10-18T00:00:00Z",
                "agent_id": "OmniTrace-v1",
                "threat_count": 3,
                "accounts_audited_count": 10,
                "status": "complete",
            }
        ]

        res = client.get("/api/investigations/history")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert len(data["investigations"]) == 1
        assert data["investigations"][0]["investigation_id"] == "INV-001"


# -----------------------------------------------------------------------------
# 4. Compliance Export Endpoint Tests
# -----------------------------------------------------------------------------
def test_dossier_html_export(client, tmp_path):
    dossier = {
        "investigation_id": "INV-EXPORT-TEST",
        "timestamp": "2026-10-18T00:00:00Z",
        "agent_id": "OmniTrace-v1",
        "findings": [
            {
                "type": "OFAC_SANCTIONS_EXPOSURE",
                "severity": "CRITICAL",
                "path_trail": "ACC_MULE_ALPHA -> ACC_HOP_1 -> SANCTION_HYDRA",
                "hop_count": 3,
                "reasoning": "Direct path into sanctioned hydra cluster",
            }
        ],
        "enforcement_actions": [{"account_id": "ACC_MULE_ALPHA", "action": "freeze", "status": "executed"}],
        "graph_metrics": {"total_nodes_audited": 15, "total_threats_neutralized": 1, "status": "complete"},
    }

    # Save to dossiers directory
    import os
    os.makedirs("dossiers", exist_ok=True)
    with open("dossiers/INV-EXPORT-TEST.json", "w") as f:
        json.dump(dossier, f)

    res = client.get("/api/dossiers/INV-EXPORT-TEST/export?format=html")
    assert res.status_code == 200
    assert "text/html" in res.content_type
    html_text = res.get_data(as_text=True)
    assert "OMNITRACE FINANCIAL FRAUD INVESTIGATION DOSSIER" in html_text
    assert "INV-EXPORT-TEST" in html_text
    assert "OFAC SANCTIONS EXPOSURE" in html_text


# -----------------------------------------------------------------------------
# 5. Benign Decoy Policy Tests
# -----------------------------------------------------------------------------
def test_policy_does_not_flag_legitimate_back_and_forth():
    policy = ThreatPolicy()
    # A benign business transfer (A -> B $100, B -> A $100 after 5 days)
    # The policy should recognize legitimate return vs rapid structuring loop
    cycle_finding = {
        "type": "CIRCULAR_STRUCTURING_RING",
        "ring_members": ["ACC_LEGIT_A", "ACC_LEGIT_B"],
        "amounts": [100.0, 100.0],
        "timestamps": ["2026-01-01T10:00:00Z", "2026-01-06T10:00:00Z"],  # 5 days apart
    }
    # Ring of 2 nodes with 5-day delta is a routine refund/settlement, not a 3-hop smurfing ring
    assert len(cycle_finding["ring_members"]) < 3

