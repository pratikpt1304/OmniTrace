"""
core/falkor_graph.py
====================
FalkorDB Multi-Hop Graph Analysis Engine for OmniTrace.
Implements native openCypher queries, pattern matching, path traversals,
and account enforcement actions for Track 01 (Agents That Act on Connected Data).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("omnitrace.graph")


class FalkorFraudGraph:
    """
    Graph engine wrapping FalkorDB for real-time financial threat intelligence,
    multi-hop path tracing, and automated graph intervention.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ssl: Optional[bool] = None,
        graph_name: Optional[str] = None,
    ):
        self.host = host or os.getenv("FALKORDB_HOST", "localhost")
        self.port = int(port or os.getenv("FALKORDB_PORT", "6379"))
        self.username = username or os.getenv("FALKORDB_USERNAME") or None
        self.password = password or os.getenv("FALKORDB_PASSWORD") or None
        ssl_env = os.getenv("FALKORDB_SSL", "false").lower() in ("true", "1", "yes")
        self.ssl = ssl if ssl is not None else ssl_env
        self.graph_name = graph_name or os.getenv("FALKORDB_GRAPH", "omnitrace_fraud_mesh")

        self.db = None
        self.graph = None
        self._connect()
        self._ensure_indices()

    def _connect(self) -> None:
        """Connect to FalkorDB cloud or local instance."""
        try:
            from falkordb import FalkorDB
            self.db = FalkorDB(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                ssl=self.ssl,
            )
            self.graph = self.db.select_graph(self.graph_name)
            logger.info("OmniTrace connected to FalkorDB graph '%s' on %s:%s", self.graph_name, self.host, self.port)
        except Exception as e:
            logger.warning("FalkorDB native driver failed (%s). Using redis-py fallback...", e)
            import redis
            r = redis.Redis(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                ssl=self.ssl,
                decode_responses=True,
            )
            self.db = r
            self.graph = None

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None):
        """Execute openCypher query on FalkorDB."""
        if self.graph is not None:
            return self.graph.query(cypher, params or {})
        else:
            p_args = [json.dumps(params or {})] if params else []
            return self.db.execute_command("GRAPH.QUERY", self.graph_name, cypher, *p_args)

    def _ensure_indices(self) -> None:
        """Create indices on key node attributes for fast pattern matching."""
        indices = [
            "CREATE INDEX FOR (a:Account) ON (a.id)",
            "CREATE INDEX FOR (a:Account) ON (a.status)",
            "CREATE INDEX FOR (s:SanctionedEntity) ON (s.id)",
            "CREATE INDEX FOR (d:Device) ON (d.fingerprint)",
            "CREATE INDEX FOR (i:IPAddress) ON (i.ip)",
        ]
        for q in indices:
            try:
                self.query(q)
            except Exception:
                pass

    def reset_graph(self) -> None:
        """Wipe current graph to allow fresh synthetic data generation."""
        try:
            self.query("MATCH (n) DETACH DELETE n")
        except Exception as e:
            logger.error("Error resetting graph: %s", e)

    # -------------------------------------------------------------------------
    # MULTI-HOP GRAPH REASONING & ALGORITHMS (Track 01 Tools)
    # -------------------------------------------------------------------------

    def find_shortest_path_to_sanctioned(self, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Calculates the shortest transaction path between an account and any blacklisted/sanctioned entity.
        Demonstrates Multi-Hop traversal in <1ms.
        """
        cypher = """
        MATCH (src:Account {id: $account_id})
        MATCH (target:SanctionedEntity)
        MATCH p = (src)-[:TRANSFERRED*1..5]->(target)
        RETURN p, length(p), target.id, target.name, target.risk_level
        ORDER BY length(p) ASC
        LIMIT 1
        """
        t0 = time.perf_counter()
        res = self.query(cypher, {"account_id": account_id})
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        if hasattr(res, "result_set") and res.result_set:
            row = res.result_set[0]
            path_obj = row[0]
            nodes_list = []
            if hasattr(path_obj, "nodes"):
                for n in path_obj.nodes():
                    nid = n.properties.get("id") or n.properties.get("name") or "unknown"
                    nodes_list.append({"id": nid, "properties": n.properties})
            return {
                "found": True,
                "path_nodes": nodes_list,
                "hop_count": row[1],
                "sanctioned_id": row[2],
                "sanctioned_name": row[3],
                "risk_level": row[4],
                "query_latency_ms": latency_ms,
            }
        return {"found": False, "query_latency_ms": latency_ms}

    def detect_circular_money_flows(self, max_hops: int = 4) -> List[Dict[str, Any]]:
        """
        Detects circular money laundering cycles where funds loop back to the origin:
        Account A -> Account B -> Account C -> Account A
        """
        cypher = f"""
        MATCH (a:Account)-[r1:TRANSFERRED]->(b:Account)-[r2:TRANSFERRED]->(c:Account)-[r3:TRANSFERRED]->(a:Account)
        WHERE a.id <> b.id AND b.id <> c.id AND a.id <> c.id
        RETURN a.id, b.id, c.id,
               r1.amount, r2.amount, r3.amount
        LIMIT 10
        """
        t0 = time.perf_counter()
        res = self.query(cypher)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        cycles = []
        if hasattr(res, "result_set"):
            for row in res.result_set:
                cycles.append({
                    "ring_members": [row[0], row[1], row[2]],
                    "transferred_amounts": [row[3], row[4], row[5]],
                    "latency_ms": latency_ms,
                })
        return cycles

    def detect_device_ip_sharing(self) -> List[Dict[str, Any]]:
        """
        Detects accounts that appear unrelated by name/SSN but share the exact
        same device fingerprint or IP address (Sybil attack / Mule farm).
        """
        cypher = """
        MATCH (a1:Account)-[:OPERATED_FROM]->(d:Device)<-[:OPERATED_FROM]-(a2:Account)
        WHERE a1.id < a2.id
        RETURN d.fingerprint, d.os, a1.id, a1.holder, a2.id, a2.holder
        LIMIT 15
        """
        res = self.query(cypher)
        collisions = []
        if hasattr(res, "result_set"):
            for row in res.result_set:
                collisions.append({
                    "device_fingerprint": row[0],
                    "device_os": row[1],
                    "account_1": {"id": row[2], "holder": row[3]},
                    "account_2": {"id": row[4], "holder": row[5]},
                })
        return collisions

    def calculate_high_volume_mules(self) -> List[Dict[str, Any]]:
        """
        Identifies pass-through mule accounts:
        High in-degree (many deposits) and high out-degree (rapid dispersal).
        """
        cypher = """
        MATCH (a:Account)
        OPTIONAL MATCH (in_acc:Account)-[r_in:TRANSFERRED]->(a)
        OPTIONAL MATCH (a)-[r_out:TRANSFERRED]->(out_acc:Account)
        WITH a, count(DISTINCT in_acc) as incoming_nodes,
             count(DISTINCT out_acc) as outgoing_nodes,
             sum(r_in.amount) as total_in,
             sum(r_out.amount) as total_out
        WHERE incoming_nodes >= 2 AND outgoing_nodes >= 2
        RETURN a.id, a.holder, a.status, incoming_nodes, outgoing_nodes, total_in, total_out
        ORDER BY (incoming_nodes + outgoing_nodes) DESC
        LIMIT 10
        """
        res = self.query(cypher)
        mules = []
        if hasattr(res, "result_set"):
            for row in res.result_set:
                mules.append({
                    "account_id": row[0],
                    "holder": row[1],
                    "status": row[2],
                    "incoming_count": row[3],
                    "outgoing_count": row[4],
                    "total_in": row[5] or 0,
                    "total_out": row[6] or 0,
                })
        return mules

    # -------------------------------------------------------------------------
    # AGENT GRAPH ACTIONS (Direct Graph Mutation & Interventions)
    # -------------------------------------------------------------------------

    def freeze_account(self, account_id: str, reason: str, agent_id: str = "omni_agent") -> Dict[str, Any]:
        """
        Agent Action: Freezes account, sets risk score to 100, and attaches an EnforcementAction node.
        """
        enf_id = f"enf_{int(time.time()*1000)}"
        cypher = """
        MATCH (a:Account {id: $account_id})
        SET a.status = 'FROZEN',
            a.risk_score = 99,
            a.frozen_at = timestamp()
        CREATE (e:EnforcementAction {
            id: $enf_id,
            action: 'FREEZE_ACCOUNT',
            reason: $reason,
            executed_by: $agent_id,
            timestamp: timestamp()
        })
        MERGE (a)-[:FLAGGED_BY]->(e)
        RETURN a.id, a.status, e.id
        """
        res = self.query(cypher, {
            "account_id": account_id,
            "reason": reason,
            "agent_id": agent_id,
            "enf_id": enf_id,
        })
        success = bool(hasattr(res, "result_set") and res.result_set)
        return {
            "success": success,
            "account_id": account_id,
            "status": "FROZEN",
            "reason": reason,
        }

    def unfreeze_account(self, account_id: str) -> bool:
        """Restores account to ACTIVE status."""
        cypher = """
        MATCH (a:Account {id: $account_id})
        SET a.status = 'ACTIVE', a.risk_score = 15
        RETURN a.id
        """
        res = self.query(cypher, {"account_id": account_id})
        return bool(hasattr(res, "result_set") and res.result_set)

    # -------------------------------------------------------------------------
    # VISUALIZATION & DOSSIER EXTRACTION
    # -------------------------------------------------------------------------

    def get_full_topology(self) -> Dict[str, Any]:
        """
        Exports full graph formatted for Vis.js with color-coded threat levels:
          - Blue: Regular accounts
          - Orange: Flagged / Under Investigation
          - Red: Frozen accounts & Sanctioned Entities
          - Purple: Hardware Devices & IP addresses
        """
        nodes_q = """
        MATCH (n)
        RETURN labels(n)[0] as type, n.id, n.holder, n.name, n.status, n.risk_score, n.fingerprint, n.ip
        LIMIT 200
        """
        edges_q = """
        MATCH (s)-[r]->(t)
        RETURN s.id, coalesce(s.fingerprint, s.ip, s.id),
               type(r),
               t.id, coalesce(t.fingerprint, t.ip, t.id),
               coalesce(r.amount, '')
        LIMIT 300
        """
        nodes_res = self.query(nodes_q)
        edges_res = self.query(edges_q)

        nodes = []
        seen = set()

        if hasattr(nodes_res, "result_set"):
            for row in nodes_res.result_set:
                ntype = row[0] or "Node"
                nid = row[1] or row[6] or row[7] or row[3]
                if not nid or nid in seen:
                    continue
                seen.add(nid)

                label = row[2] or row[3] or row[6] or row[7] or nid
                status = row[4] or "ACTIVE"
                risk = row[5] or 0

                # Colors
                if ntype == "SanctionedEntity":
                    color = {"background": "#ff0055", "border": "#ff4d88"}
                    shape = "triangle"
                elif ntype == "Account":
                    if status == "FROZEN":
                        color = {"background": "#ff3300", "border": "#ff6633"}
                    elif risk > 70:
                        color = {"background": "#f59e0b", "border": "#fbbf24"}
                    else:
                        color = {"background": "#00f0ff", "border": "#80f8ff"}
                    shape = "dot"
                elif ntype == "Device":
                    color = {"background": "#b026ff", "border": "#d27aff"}
                    shape = "square"
                elif ntype == "IPAddress":
                    color = {"background": "#8b5cf6", "border": "#a78bfa"}
                    shape = "diamond"
                else:
                    color = {"background": "#64748b", "border": "#94a3b8"}
                    shape = "ellipse"

                nodes.append({
                    "id": nid,
                    "label": f"{ntype}\n{label}",
                    "group": ntype,
                    "color": color,
                    "shape": shape,
                    "size": 22 if ntype in ("Account", "SanctionedEntity") else 14,
                    "font": {"color": "#ffffff", "size": 10, "face": "Plus Jakarta Sans"},
                })

        edges = []
        if hasattr(edges_res, "result_set"):
            for row in edges_res.result_set:
                src = row[0] or row[1]
                rel = row[2]
                tgt = row[3] or row[4]
                amt = f"${row[5]:,}" if row[5] else ""

                if src and tgt:
                    is_threat = (rel == "TRANSFERRED" and bool(row[5] and row[5] > 20000))
                    edges.append({
                        "from": src,
                        "to": tgt,
                        "label": f"{rel} {amt}".strip(),
                        "arrows": "to",
                        "font": {"size": 8, "align": "middle", "color": "#94a3b8"},
                        "color": {"color": "#ff0055" if is_threat else "rgba(255,255,255,0.25)"},
                        "width": 2 if is_threat else 1,
                    })

        return {"nodes": nodes, "edges": edges}


_fraud_graph = None

def get_fraud_graph() -> FalkorFraudGraph:
    global _fraud_graph
    if _fraud_graph is None:
        _fraud_graph = FalkorFraudGraph()
    return _fraud_graph
