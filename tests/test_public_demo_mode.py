"""
tests/test_public_demo_mode.py
==============================
Unit and integration tests for PUBLIC_DEMO mode, per-IP rate limiting,
safe auto-freeze defaults, and read-only query protections.
"""

import json
import pytest
from server import app, IP_REQUEST_HISTORY


@pytest.fixture(autouse=True)
def clear_rate_limits():
    """Clear in-memory IP request history between tests."""
    IP_REQUEST_HISTORY.clear()


def test_public_demo_forces_auto_freeze_off(monkeypatch):
    """Verify that when PUBLIC_DEMO=true, auto_freeze is strictly forced to false."""
    monkeypatch.setenv("PUBLIC_DEMO", "true")
    monkeypatch.setenv("AUTO_FREEZE", "true")
    import importlib
    import server
    importlib.reload(server)

    with server.app.test_client() as client:
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["public_demo"] is True
        assert data["auto_freeze"] is False


def test_public_demo_rate_limits_seeding(monkeypatch):
    """Verify per-IP rate limit on /api/seed in public demo mode."""
    monkeypatch.setenv("PUBLIC_DEMO", "true")
    import importlib
    import server
    importlib.reload(server)

    with server.app.test_client() as client:
        # Calls 1 to 4 should be allowed (mocked seed)
        monkeypatch.setattr(server, "seed_fraud_dataset", lambda graph: {"status": "success", "mock": True})
        
        for i in range(4):
            res = client.post("/api/seed", json={"confirm": True})
            assert res.status_code == 200, f"Call {i+1} failed unexpectedly"

        # 5th call from same client should trigger HTTP 429
        res5 = client.post("/api/seed", json={"confirm": True})
        assert res5.status_code == 429
        data = res5.get_json()
        assert data["ok"] is False
        assert "Rate limit reached" in data["error"]


def test_public_demo_rate_limits_investigate(monkeypatch):
    """Verify per-IP rate limit on /api/investigate in public demo mode."""
    monkeypatch.setenv("PUBLIC_DEMO", "true")
    import importlib
    import server
    importlib.reload(server)

    mock_dossier = {"investigation_id": "inv_test", "findings": [], "proposed_actions": []}
    monkeypatch.setattr(server.investigator, "run_full_investigation", lambda goal=None, auto_freeze=None: mock_dossier)

    with server.app.test_client() as client:
        for i in range(10):
            res = client.post("/api/investigate", json={})
            assert res.status_code == 200, f"Investigation {i+1} failed"

        # 11th call should return 429
        res11 = client.post("/api/investigate", json={})
        assert res11.status_code == 429
        data = res11.get_json()
        assert data["ok"] is False
        assert "Rate limit reached" in data["error"]


def test_read_only_query_blocks_mutations():
    """Verify /api/graph/query strictly rejects write/mutation keywords."""
    with app.test_client() as client:
        mutation_queries = [
            "CREATE (n:Test {id: 1})",
            "MATCH (n:Account) SET n.status = 'COMPROMISED'",
            "MERGE (a:Account {id: 'HACKED'})",
            "MATCH (n) DELETE n",
            "MATCH (n) DETACH DELETE n",
        ]
        for q in mutation_queries:
            res = client.post("/api/graph/query", json={"query": q})
            assert res.status_code == 403, f"Query '{q}' was not blocked"
            data = res.get_json()
            assert data["ok"] is False
            assert "Query rejected" in data["error"]
