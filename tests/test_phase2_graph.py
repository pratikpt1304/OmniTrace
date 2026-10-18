"""
tests/test_phase2_graph.py
==========================
Unit tests for Phase 2: True Graph Algorithms & Tamper-Evident Audit Chaining.
Verifies:
  - Canonical cycle deduplication (A-B-C, B-C-A, C-A-B reported exactly once).
  - Route severing on freeze (blocked = true, blocked_edges count).
  - Idempotent freeze (no duplicate EnforcementAction nodes).
  - Freeze returns success=False for unknown account.
  - SHA-256 tamper-evident hash chaining and verification.
  - Victim protection vs intermediary freezing.
  - Restoring risk score and unblocking routes on unfreeze.
Runs offline using mock/fake graph engine without needing live FalkorDB.
"""

import hashlib
import time
from unittest.mock import MagicMock
import pytest

from core.falkor_graph import FalkorFraudGraph
from core.policy import ThreatPolicy
from agent.investigator import OmniTraceInvestigator


class FakeQueryResult:
    def __init__(self, result_set=None, run_time_ms=0.45):
        self.result_set = result_set or []
        self.run_time_ms = run_time_ms


class FakeInMemoryFalkorGraph:
    """
    Lightweight in-memory graph simulator for FalkorFraudGraph tests.
    Faithfully simulates node properties, relationships, and EnforcementAction chaining.
    """

    def __init__(self):
        self.accounts = {
            "ACC_VICTIM_CORP": {"id": "ACC_VICTIM_CORP", "status": "ACTIVE", "risk_score": 40},
            "ACC_MULE_1": {"id": "ACC_MULE_1", "status": "ACTIVE", "risk_score": 75},
            "ACC_MULE_2": {"id": "ACC_MULE_2", "status": "ACTIVE", "risk_score": 80},
        }
        self.transfers = [
            {"from": "ACC_MULE_1", "to": "ACC_MULE_2", "amount": 10000, "blocked": False, "timestamp": 1000},
            {"from": "ACC_MULE_1", "to": "ACC_OTHER", "amount": 5000, "blocked": False, "timestamp": 1001},
        ]
        self.enforcements = []

    def get_latest_audit_hash(self) -> str:
        if self.enforcements:
            return self.enforcements[-1]["content_hash"]
        return "0" * 64

    def query(self, cypher: str, params=None):
        params = params or {}
        # Simulate check query
        if "MATCH (a:Account {id: $account_id}) RETURN a.id, a.status, a.risk_score" in cypher:
            acc_id = params.get("account_id")
            if acc_id in self.accounts:
                acc = self.accounts[acc_id]
                return FakeQueryResult([[acc["id"], acc["status"], acc["risk_score"]]])
            return FakeQueryResult([])

        # Simulate sever query
        if "SET a.previous_risk_score" in cypher and "SET r.blocked = true" in cypher:
            acc_id = params.get("account_id")
            if acc_id in self.accounts:
                acc = self.accounts[acc_id]
                acc["previous_risk_score"] = acc["risk_score"]
                acc["status"] = "FROZEN"
                acc["risk_score"] = 99
                blocked_count = 0
                for t in self.transfers:
                    if t["from"] == acc_id:
                        t["blocked"] = True
                        blocked_count += 1
                return FakeQueryResult([[blocked_count]])
            return FakeQueryResult([[0]])

        # Simulate audit node creation
        if "CREATE (e:EnforcementAction" in cypher:
            action_name = "UNFREEZE_ACCOUNT" if "UNFREEZE_ACCOUNT" in cypher else "FREEZE_ACCOUNT"
            self.enforcements.append({
                "id": params.get("enf_id"),
                "account_id": params.get("account_id"),
                "action": action_name,
                "reason": params.get("reason"),
                "executed_by": params.get("agent_id") or params.get("actor"),
                "timestamp": params.get("ts"),
                "previous_hash": params.get("prev_hash"),
                "content_hash": params.get("content_hash"),
            })
            return FakeQueryResult([[params.get("enf_id"), params.get("content_hash")]])

        # Simulate verify audit chain query
        if "MATCH (a:Account)-[:FLAGGED_BY]->(e:EnforcementAction)" in cypher:
            rows = []
            for e in self.enforcements:
                rows.append([
                    e["account_id"],
                    e["action"],
                    e["reason"],
                    e["timestamp"],
                    e["executed_by"],
                    e["previous_hash"],
                    e["content_hash"],
                    e["id"],
                ])
            return FakeQueryResult(rows)

        # Simulate unfreeze check query
        if "MATCH (a:Account {id: $account_id}) RETURN a.id, a.status, a.previous_risk_score" in cypher:
            acc_id = params.get("account_id")
            if acc_id in self.accounts:
                acc = self.accounts[acc_id]
                return FakeQueryResult([[acc["id"], acc["status"], acc.get("previous_risk_score", 15)]])
            return FakeQueryResult([])

        # Simulate unfreeze set query
        if "SET a.status = 'ACTIVE'" in cypher and "SET r.blocked = false" in cypher:
            acc_id = params.get("account_id")
            if acc_id in self.accounts:
                acc = self.accounts[acc_id]
                acc["status"] = "ACTIVE"
                acc["risk_score"] = params.get("target_risk", 15)
                for t in self.transfers:
                    if t["from"] == acc_id:
                        t["blocked"] = False
                return FakeQueryResult([[acc_id]])
            return FakeQueryResult([])

        return FakeQueryResult([])


def test_freeze_unknown_account_returns_success_false():
    """Verify freeze_account returns success=False when account is not found in graph."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    fake_graph = FakeInMemoryFalkorGraph()
    engine.query = fake_graph.query
    engine.get_latest_audit_hash = fake_graph.get_latest_audit_hash

    res = engine.freeze_account("UNKNOWN_ACC_404", "Suspicious activity")
    assert res["success"] is False
    assert res["status"] == "NOT_FOUND"
    assert res["blocked_edges"] == 0


def test_freeze_severs_outgoing_routes_and_chains_hash():
    """Verify freeze marks outgoing routes as blocked and creates a valid SHA-256 block."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    fake_graph = FakeInMemoryFalkorGraph()
    engine.query = fake_graph.query
    engine.get_latest_audit_hash = fake_graph.get_latest_audit_hash

    res = engine.freeze_account("ACC_MULE_1", "Sanctions trail intermediary", agent_id="sentinel_1")
    assert res["success"] is True
    assert res["status"] == "FROZEN"
    assert res["blocked_edges"] == 2
    assert "content_hash" in res
    assert len(res["content_hash"]) == 64

    # Check that outgoing transfers were blocked
    for t in fake_graph.transfers:
        if t["from"] == "ACC_MULE_1":
            assert t["blocked"] is True

    # Check idempotency: second freeze on same account should not create duplicate action
    res2 = engine.freeze_account("ACC_MULE_1", "Duplicate freeze request")
    assert res2["success"] is True
    assert res2.get("duplicate_skipped") is True
    assert len(fake_graph.enforcements) == 1


def test_tamper_evident_audit_chain_verification():
    """Verify verify_audit_chain detects valid chains and flags tampered blocks."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    fake_graph = FakeInMemoryFalkorGraph()
    engine.query = fake_graph.query
    engine.get_latest_audit_hash = fake_graph.get_latest_audit_hash
    engine.verify_audit_chain = FalkorFraudGraph.verify_audit_chain.__get__(engine, FalkorFraudGraph)

    # Freeze two accounts to form a 2-block chain
    engine.freeze_account("ACC_MULE_1", "Mule 1 caught", agent_id="sentinel_1")
    engine.freeze_account("ACC_MULE_2", "Mule 2 caught", agent_id="sentinel_1")

    # Verify audit chain
    verification = engine.verify_audit_chain()
    assert verification["valid"] is True
    assert verification["verified_count"] == 2
    assert verification["tampered"] is False

    # Simulate tampering with block 0 payload (e.g. attacker modified reason)
    fake_graph.enforcements[0]["reason"] = "Tampered reason by hacker"
    tampered_verification = engine.verify_audit_chain()
    assert tampered_verification["valid"] is False
    assert tampered_verification["tampered"] is True


def test_unfreeze_restores_risk_and_unblocks_routes():
    """Verify unfreeze restores previous risk score, unblocks routes, and logs UNFREEZE_ACCOUNT."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    fake_graph = FakeInMemoryFalkorGraph()
    engine.query = fake_graph.query
    engine.get_latest_audit_hash = fake_graph.get_latest_audit_hash
    engine.unfreeze_account = FalkorFraudGraph.unfreeze_account.__get__(engine, FalkorFraudGraph)

    # First freeze ACC_MULE_1 (original risk was 75)
    engine.freeze_account("ACC_MULE_1", "Investigating mule", agent_id="sentinel_1")
    assert fake_graph.accounts["ACC_MULE_1"]["status"] == "FROZEN"

    # Now unfreeze ACC_MULE_1
    ok = engine.unfreeze_account("ACC_MULE_1", actor="compliance_officer_sarah")
    assert ok is True
    assert fake_graph.accounts["ACC_MULE_1"]["status"] == "ACTIVE"
    assert fake_graph.accounts["ACC_MULE_1"]["risk_score"] == 75

    # Check outgoing transfers are unblocked
    for t in fake_graph.transfers:
        if t["from"] == "ACC_MULE_1":
            assert t["blocked"] is False

    # Check unfreeze audit action was chained
    assert len(fake_graph.enforcements) == 2
    assert fake_graph.enforcements[-1]["action"] == "UNFREEZE_ACCOUNT"
    assert fake_graph.enforcements[-1]["executed_by"] == "compliance_officer_sarah"


def test_circular_ring_rotation_deduplication():
    """Verify that rotations of the same circular ring are reported only once."""
    engine = FalkorFraudGraph.__new__(FalkorFraudGraph)
    engine._extract_engine_ms = FalkorFraudGraph._extract_engine_ms.__get__(engine, FalkorFraudGraph)

    # Simulate query returning 3 rotations of the identical triangle:
    # A -> B -> C -> A, B -> C -> A -> B, and C -> A -> B -> C
    fake_rows = [
        [["ACC_A", "ACC_B", "ACC_C", "ACC_A"], [50000, 49500, 49000]],
        [["ACC_B", "ACC_C", "ACC_A", "ACC_B"], [49500, 49000, 50000]],
        [["ACC_C", "ACC_A", "ACC_B", "ACC_C"], [49000, 50000, 49500]],
    ]
    mock_query = MagicMock(return_value=FakeQueryResult(fake_rows, run_time_ms=0.32))
    engine.query = mock_query
    engine.detect_circular_money_flows = FalkorFraudGraph.detect_circular_money_flows.__get__(engine, FalkorFraudGraph)

    rings = engine.detect_circular_money_flows(max_hops=3)
    # Deduplication must reduce 3 rotations to exactly 1 canonical ring
    assert len(rings) == 1
    assert rings[0]["ring_members"] == ["ACC_A", "ACC_B", "ACC_C"]
    assert rings[0]["engine_ms"] == 0.32
    assert "roundtrip_ms" in rings[0]


def test_threat_policy_protects_victim_account():
    """Verify ThreatPolicy marks victim origin as FLAG_VICTIM and freezes only intermediaries."""
    path_nodes = [
        {"id": "ACC_VICTIM_CORP", "properties": {"risk_score": 40}},
        {"id": "ACC_MULE_ALPHA", "properties": {"risk_score": 75}},
        {"id": "ACC_MULE_BETA", "properties": {"risk_score": 80}},
        {"id": "SANCTION_HYDRA_EXCHANGE", "properties": {"risk_level": "CRITICAL"}},
    ]

    evaluation = ThreatPolicy.evaluate_sanctions_path(path_nodes, hop_count=3, time_ordered=True)
    assert evaluation["threat_type"] == "OFAC_SANCTIONS_EXPOSURE"
    assert evaluation["victim_account"] == "ACC_VICTIM_CORP"

    actions = evaluation["actions"]
    assert len(actions) == 3

    # Victim is flagged for human review, NOT frozen
    victim_act = next(a for a in actions if a["account_id"] == "ACC_VICTIM_CORP")
    assert victim_act["action"] == "FLAG_VICTIM"

    # Mules are frozen
    mule1_act = next(a for a in actions if a["account_id"] == "ACC_MULE_ALPHA")
    assert mule1_act["action"] == "FREEZE"
    mule2_act = next(a for a in actions if a["account_id"] == "ACC_MULE_BETA")
    assert mule2_act["action"] == "FREEZE"
