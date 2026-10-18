"""
tests/test_phase4_reliability.py
================================
Unit tests for Phase 4: Reliability, Persistence, and Health.
Verifies:
  - FalkorFraudGraph raises ConnectionError on query when not connected.
  - /api/health returns connection status, graph name, node count, and agent mode.
  - Dossiers are saved to dossiers/ directory on /api/investigate.
  - /api/dossiers lists saved dossiers.
  - /api/dossiers/<id> retrieves full dossier.
  - /api/dossiers/<id>/export exports downloadable JSON file.
  - /api/graph/state supports node_limit, edge_limit, and truncated flag.
Runs offline with mock graph and test client.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from server import app, DOSSIERS_DIR
from core.falkor_graph import FalkorFraudGraph


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_falkor_graph_fails_loudly_when_not_connected():
    """Verify FalkorFraudGraph raises ConnectionError if connection fails."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    engine.host = "unreachable-host"
    engine.port = 9999
    engine.graph = None
    engine.db = None

    with pytest.raises(ConnectionError) as exc_info:
        engine.query("RETURN 1")
    assert "not connected to FalkorDB" in str(exc_info.value)


def test_api_health_endpoint(client):
    """Verify /api/health returns valid structured health status."""
    mock_res = MagicMock()
    mock_res.result_set = [[42]]

    with patch("server.graph.query", return_value=mock_res):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("healthy", "degraded")
        assert "graph_name" in data
        assert "agent_mode" in data
        assert data["total_nodes"] == 42


def test_dossier_persistence_and_export_endpoints(client, tmp_path):
    """Verify investigation persists to dossiers/ and can be retrieved and exported."""
    test_dossier = {
        "investigation_id": "inv_test_phase4",
        "timestamp": 123456789,
        "agent_mode": "rules",
        "findings": [{"type": "OFAC_SANCTIONS_EXPOSURE", "severity": "CRITICAL"}],
        "enforcement_actions": [{"account_id": "ACC_MULE", "status": "FROZEN"}],
    }

    with patch("server.investigator.run_full_investigation", return_value=test_dossier):
        # Trigger investigation
        res = client.post("/api/investigate")
        assert res.status_code == 200
        saved_file = DOSSIERS_DIR / "inv_test_phase4.json"
        assert saved_file.exists()

    try:
        # Test GET /api/dossiers
        res_list = client.get("/api/dossiers")
        assert res_list.status_code == 200
        list_data = res_list.get_json()
        assert list_data["ok"] is True
        assert any(d["investigation_id"] == "inv_test_phase4" for d in list_data["dossiers"])

        # Test GET /api/dossiers/<id>
        res_get = client.get("/api/dossiers/inv_test_phase4")
        assert res_get.status_code == 200
        assert res_get.get_json()["investigation_id"] == "inv_test_phase4"

        # Test GET /api/dossiers/<id>/export
        res_export = client.get("/api/dossiers/inv_test_phase4/export")
        assert res_export.status_code == 200
        assert "attachment" in res_export.headers.get("Content-Disposition", "")
        assert json.loads(res_export.data)["investigation_id"] == "inv_test_phase4"

    finally:
        if saved_file.exists():
            saved_file.unlink()


def test_graph_state_pagination_and_truncation(client):
    """Verify /api/graph/state handles node_limit and returns truncated flag."""
    with patch("server.graph.get_full_topology") as mock_top:
        mock_top.return_value = {
            "nodes": [{"id": f"N_{i}"} for i in range(100)],
            "edges": [],
            "truncated": True,
        }
        res = client.get("/api/graph/state?node_limit=100")
        assert res.status_code == 200
        data = res.get_json()
        assert len(data["nodes"]) == 100
        assert data["truncated"] is True
        mock_top.assert_called_once_with(node_limit=100, edge_limit=800)
