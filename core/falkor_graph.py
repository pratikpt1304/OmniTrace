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
        """Connect to FalkorDB cloud or local instance. Fails loudly if unreachable."""
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
            logger.error("Failed to connect to FalkorDB at %s:%s: %s", self.host, self.port, e)
            self.db = None
            self.graph = None

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None):
        """Execute openCypher query on FalkorDB."""
        if self.graph is not None:
            return self.graph.query(cypher, params or {})
        elif self.db is not None:
            p_args = [json.dumps(params or {})] if params else []
            return self.db.execute_command("GRAPH.QUERY", self.graph_name, cypher, *p_args)
        else:
            raise ConnectionError(f"OmniTrace is not connected to FalkorDB at {self.host}:{self.port}")

    def ro_query(self, cypher: str, params: Optional[Dict[str, Any]] = None, timeout: float = 5.0):
        """
        Execute read-only openCypher query on FalkorDB via GRAPH.RO_QUERY.
        Prevents mutations and guarantees read-only query semantics.
        """
        if self.graph is not None and hasattr(self.graph, "ro_query"):
            return self.graph.ro_query(cypher, params or {})
        elif self.db is not None:
            p_args = [json.dumps(params or {})] if params else []
            return self.db.execute_command("GRAPH.RO_QUERY", self.graph_name, cypher, *p_args)
        else:
            return self.query(cypher, params)

    def _ensure_indices(self) -> None:
        """Create indices on key node attributes for fast pattern matching."""
        if self.graph is None and self.db is None:
            return
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
            except Exception as e:
                err_str = str(e).lower()
                # Ignore clean already-exists notifications
                if "already exists" not in err_str and "already indexed" not in err_str:
                    logger.debug("Index creation notice (%s): %s", q, e)

    def reset_graph(self) -> None:
        """Wipe current graph to allow fresh synthetic data generation."""
        try:
            self.query("MATCH (n) DETACH DELETE n")
        except Exception as e:
            logger.error("Error resetting graph: %s", e)

    # -------------------------------------------------------------------------
    # MULTI-HOP GRAPH REASONING & ALGORITHMS (Track 01 Tools)
    # -------------------------------------------------------------------------

    def _extract_engine_ms(self, res: Any) -> Optional[float]:
        """Extract engine execution time from FalkorDB QueryResult if available."""
        if hasattr(res, "run_time_ms") and res.run_time_ms is not None:
            return round(float(res.run_time_ms), 3)
        return None

    def find_shortest_path_to_sanctioned(self, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Calculates the shortest transaction path between an account and any blacklisted/sanctioned entity
        using openCypher shortestPath(). Returns engine_ms, roundtrip_ms, and time-ordered verification.
        """
        cypher = """
        MATCH (src:Account {id: $account_id}), (target:SanctionedEntity)
        WITH src, target, shortestPath((src)-[:TRANSFERRED*1..6]->(target)) AS p
        WHERE p IS NOT NULL
        RETURN p, length(p), target.id, target.name, target.risk_level
        LIMIT 1
        """
        t0 = time.perf_counter()
        res = self.query(cypher, {"account_id": account_id})
        roundtrip_ms = round((time.perf_counter() - t0) * 1000, 2)
        engine_ms = self._extract_engine_ms(res)

        if hasattr(res, "result_set") and res.result_set:
            row = res.result_set[0]
            path_obj = row[0]
            nodes_list = []
            transfer_times = []

            # Extract nodes & relationships from FalkorDB path object
            if hasattr(path_obj, "nodes"):
                for n in path_obj.nodes():
                    nid = n.properties.get("id") or n.properties.get("name") or "unknown"
                    nodes_list.append({"id": nid, "properties": n.properties})
            if hasattr(path_obj, "relationships"):
                for r in path_obj.relationships():
                    ts = r.properties.get("timestamp")
                    if ts is not None:
                        transfer_times.append(ts)

            # Check if transfers along the path are strictly time-ordered
            is_time_ordered = True
            if len(transfer_times) >= 2:
                for i in range(len(transfer_times) - 1):
                    if transfer_times[i] > transfer_times[i + 1]:
                        is_time_ordered = False
                        break

            return {
                "found": True,
                "path_nodes": nodes_list,
                "hop_count": row[1],
                "sanctioned_id": row[2],
                "sanctioned_name": row[3],
                "risk_level": row[4],
                "time_ordered": is_time_ordered,
                "engine_ms": engine_ms,
                "roundtrip_ms": roundtrip_ms,
                "query_latency_ms": roundtrip_ms,
            }
        return {
            "found": False,
            "engine_ms": engine_ms,
            "roundtrip_ms": roundtrip_ms,
            "query_latency_ms": roundtrip_ms,
        }

    def detect_circular_money_flows(self, max_hops: int = 4) -> List[Dict[str, Any]]:
        """
        Detects circular money laundering cycles of length 3 up to max_hops:
        Account A -> Account B -> Account C -> ... -> Account A.
        Canonical rotation deduplication ensures identical rings (A-B-C, B-C-A, C-A-B)
        are reported exactly once.
        """
        max_h = max(3, min(int(max_hops), 6))
        cypher = f"""
        MATCH p = (a:Account)-[r:TRANSFERRED*{max_h}..{max_h}]->(a)
        RETURN [n IN nodes(p) | n.id] as members,
               [rel IN relationships(p) | rel.amount] as amounts
        LIMIT 25
        """
        t0 = time.perf_counter()
        res = self.query(cypher)
        roundtrip_ms = round((time.perf_counter() - t0) * 1000, 2)
        engine_ms = self._extract_engine_ms(res)

        unique_rings = {}
        if hasattr(res, "result_set") and res.result_set:
            for row in res.result_set:
                raw_members = row[0]
                amounts = row[1]
                if not raw_members:
                    continue

                # Cypher cycles returned as [A, B, C, A]
                distinct_members = raw_members[:-1] if raw_members[0] == raw_members[-1] else raw_members
                if len(distinct_members) < 3 or len(set(distinct_members)) != len(distinct_members):
                    continue

                # Canonical rotation: rotate so lexicographically smallest account is first
                min_m = min(distinct_members)
                min_idx = distinct_members.index(min_m)
                canonical_key = tuple(distinct_members[min_idx:] + distinct_members[:min_idx])

                if canonical_key not in unique_rings:
                    unique_rings[canonical_key] = {
                        "ring_members": list(canonical_key),
                        "transferred_amounts": amounts,
                        "hop_count": len(canonical_key),
                        "engine_ms": engine_ms,
                        "roundtrip_ms": roundtrip_ms,
                        "latency_ms": roundtrip_ms,
                    }

        # Fallback for FalkorDB versions where variable length cycles require explicit path matching
        if not unique_rings:
            explicit_cypher = """
            MATCH (a:Account)-[r1:TRANSFERRED]->(b:Account)-[r2:TRANSFERRED]->(c:Account)-[r3:TRANSFERRED]->(a:Account)
            WHERE a.id < b.id AND a.id < c.id AND b.id <> c.id
            RETURN a.id, b.id, c.id, r1.amount, r2.amount, r3.amount
            LIMIT 10
            """
            res2 = self.query(explicit_cypher)
            if hasattr(res2, "result_set") and res2.result_set:
                for row in res2.result_set:
                    members = [row[0], row[1], row[2]]
                    amounts = [row[3], row[4], row[5]]
                    key = tuple(members)
                    if key not in unique_rings:
                        unique_rings[key] = {
                            "ring_members": members,
                            "transferred_amounts": amounts,
                            "hop_count": 3,
                            "engine_ms": engine_ms,
                            "roundtrip_ms": roundtrip_ms,
                            "latency_ms": roundtrip_ms,
                        }

        return list(unique_rings.values())

    def detect_device_ip_sharing(self) -> List[Dict[str, Any]]:
        """
        Detects Sybil clusters: accounts sharing hardware device fingerprints or IP addresses.
        Returns one cluster per shared entity with all member accounts grouped.
        """
        t0 = time.perf_counter()
        dev_cypher = """
        MATCH (a:Account)-[:OPERATED_FROM]->(d:Device)
        WITH d.fingerprint as identifier, d.os as details, count(a) as member_count, collect(a.id) as members
        WHERE member_count >= 2
        RETURN identifier, details, member_count, members
        LIMIT 10
        """
        ip_cypher = """
        MATCH (a:Account)-[:CONNECTED_VIA]->(ip:IPAddress)
        WITH ip.ip as identifier, ip.isp as details, count(a) as member_count, collect(a.id) as members
        WHERE member_count >= 2
        RETURN identifier, details, member_count, members
        LIMIT 10
        """
        dev_res = self.query(dev_cypher)
        ip_res = self.query(ip_cypher)
        roundtrip_ms = round((time.perf_counter() - t0) * 1000, 2)
        engine_ms = self._extract_engine_ms(dev_res)

        clusters = []
        if hasattr(dev_res, "result_set") and dev_res.result_set:
            for row in dev_res.result_set:
                clusters.append({
                    "cluster_type": "DEVICE",
                    "identifier": row[0],
                    "details": row[1],
                    "member_count": row[2],
                    "members": row[3],
                    "engine_ms": engine_ms,
                    "roundtrip_ms": roundtrip_ms,
                    "latency_ms": roundtrip_ms,
                })

        if hasattr(ip_res, "result_set") and ip_res.result_set:
            for row in ip_res.result_set:
                clusters.append({
                    "cluster_type": "IP",
                    "identifier": row[0],
                    "details": row[1],
                    "member_count": row[2],
                    "members": row[3],
                    "engine_ms": engine_ms,
                    "roundtrip_ms": roundtrip_ms,
                    "latency_ms": roundtrip_ms,
                })

        return clusters

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

    def list_high_risk_accounts(self, threshold: int = 50) -> List[Dict[str, Any]]:
        """List accounts with risk_score >= threshold or flagged/suspicious status."""
        cypher = """
        MATCH (a:Account)
        WHERE a.risk_score >= $threshold OR a.status IN ['FLAGGED', 'SUSPICIOUS']
        RETURN a.id, a.holder, a.balance, a.status, a.risk_score
        ORDER BY a.risk_score DESC
        LIMIT 25
        """
        res = self.query(cypher, {"threshold": threshold})
        accounts = []
        if hasattr(res, "result_set") and res.result_set:
            for row in res.result_set:
                accounts.append({
                    "id": row[0],
                    "holder": row[1],
                    "balance": row[2],
                    "status": row[3],
                    "risk_score": row[4],
                })
        return accounts

    def get_account_neighbors(self, account_id: str) -> Dict[str, Any]:
        """Retrieve incoming/outgoing transfers and shared hardware/IP neighbors for an account."""
        cypher_in = """
        MATCH (in_acc:Account)-[r:TRANSFERRED]->(a:Account {id: $account_id})
        RETURN in_acc.id, r.amount
        """
        cypher_out = """
        MATCH (a:Account {id: $account_id})-[r:TRANSFERRED]->(target)
        RETURN target.id, labels(target)[0], r.amount
        """
        cypher_dev = """
        MATCH (a:Account {id: $account_id})-[:OPERATED_FROM]->(d:Device)
        RETURN d.fingerprint
        """
        cypher_ip = """
        MATCH (a:Account {id: $account_id})-[:CONNECTED_VIA]->(ip:IPAddress)
        RETURN ip.ip
        """
        in_res = self.query(cypher_in, {"account_id": account_id})
        out_res = self.query(cypher_out, {"account_id": account_id})
        dev_res = self.query(cypher_dev, {"account_id": account_id})
        ip_res = self.query(cypher_ip, {"account_id": account_id})

        incoming = [{"id": r[0], "amount": r[1]} for r in (in_res.result_set if hasattr(in_res, "result_set") and in_res.result_set else [])]
        outgoing = [{"id": r[0], "target_type": r[1], "amount": r[2]} for r in (out_res.result_set if hasattr(out_res, "result_set") and out_res.result_set else [])]
        devices = [r[0] for r in (dev_res.result_set if hasattr(dev_res, "result_set") and dev_res.result_set else [])]
        ips = [r[0] for r in (ip_res.result_set if hasattr(ip_res, "result_set") and ip_res.result_set else [])]

        return {
            "account_id": account_id,
            "incoming_transfers": incoming,
            "outgoing_transfers": outgoing,
            "devices": devices,
            "ips": ips,
        }

    def calculate_pagerank(self, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Executes FalkorDB GraphBLAS PageRank algorithm on Account transactions:
        CALL algo.pageRank('Account', 'TRANSFERRED') YIELD node, score
        """
        cypher = """
        CALL algo.pageRank('Account', 'TRANSFERRED') YIELD node, score
        RETURN node.id, score, node.status, node.risk_score
        ORDER BY score DESC
        LIMIT $limit
        """
        try:
            res = self.query(cypher, {"limit": int(top_k)})
            scores = []
            if hasattr(res, "result_set") and res.result_set:
                for row in res.result_set:
                    scores.append({
                        "account_id": row[0],
                        "pagerank_score": round(float(row[1]), 6),
                        "status": row[2] if len(row) > 2 else "ACTIVE",
                        "risk_score": row[3] if len(row) > 3 else 0,
                    })
            return scores
        except Exception as e:
            logger.warning("FalkorDB algo.pageRank execution failed or unsupported: %s", e)
            return []

    def detect_wcc(self) -> List[Dict[str, Any]]:
        """
        Executes FalkorDB GraphBLAS Weakly Connected Components:
        CALL algo.wcc() YIELD node, componentId
        """
        cypher = """
        CALL algo.wcc() YIELD node, componentId
        RETURN node.id, componentId, labels(node)[0] AS node_type
        LIMIT 50
        """
        try:
            res = self.query(cypher)
            components = []
            if hasattr(res, "result_set") and res.result_set:
                for row in res.result_set:
                    components.append({
                        "node_id": row[0],
                        "component_id": row[1],
                        "node_type": row[2] if len(row) > 2 else "Node",
                    })
            return components
        except Exception as e:
            logger.warning("FalkorDB algo.wcc execution failed or unsupported: %s", e)
            return []

    # -------------------------------------------------------------------------
    # AGENT GRAPH ACTIONS & TAMPER-EVIDENT AUDIT TRAIL
    # -------------------------------------------------------------------------

    def get_latest_audit_hash(self) -> str:
        """Returns the content_hash of the latest EnforcementAction node or genesis hash."""
        cypher = """
        MATCH (e:EnforcementAction)
        RETURN e.content_hash
        ORDER BY e.timestamp DESC
        LIMIT 1
        """
        res = self.query(cypher)
        if hasattr(res, "result_set") and res.result_set:
            return res.result_set[0][0] or "0" * 64
        return "0" * 64

    def freeze_account(self, account_id: str, reason: str, agent_id: str = "omni_agent") -> Dict[str, Any]:
        """
        Freezes account, severs outgoing routes (blocked = true, blocked_at),
        saves previous_risk_score, records a tamper-evident SHA-256 EnforcementAction node,
        and ensures idempotency (no duplicate actions if already frozen).
        """
        import hashlib

        # 1. Existence and status check
        check_q = "MATCH (a:Account {id: $account_id}) RETURN a.id, a.status, a.risk_score"
        check_res = self.query(check_q, {"account_id": account_id})
        if not hasattr(check_res, "result_set") or not check_res.result_set:
            return {
                "success": False,
                "account_id": account_id,
                "status": "NOT_FOUND",
                "blocked_edges": 0,
                "reason": "Account not found in graph",
            }

        acc_id, current_status, prev_risk = check_res.result_set[0]
        if current_status == "FROZEN":
            latest_h = self.get_latest_audit_hash()
            return {
                "success": True,
                "account_id": account_id,
                "status": "FROZEN",
                "blocked_edges": 0,
                "duplicate_skipped": True,
                "audit_hash": latest_h,
                "content_hash": latest_h,
                "reason": f"Account already frozen. Skipped duplicate action.",
            }

        # 2. Sever outgoing routes and store previous risk score
        now_ts = int(time.time() * 1000)
        sever_q = """
        MATCH (a:Account {id: $account_id})
        SET a.previous_risk_score = coalesce(a.risk_score, 50),
            a.status = 'FROZEN',
            a.risk_score = 99,
            a.frozen_at = $ts
        WITH a
        OPTIONAL MATCH (a)-[r:TRANSFERRED]->()
        SET r.blocked = true,
            r.blocked_at = $ts
        RETURN count(r)
        """
        sever_res = self.query(sever_q, {"account_id": account_id, "ts": now_ts})
        blocked_count = sever_res.result_set[0][0] if hasattr(sever_res, "result_set") and sever_res.result_set else 0

        # 3. Create tamper-evident EnforcementAction node
        enf_id = f"enf_{now_ts}"
        prev_hash = self.get_latest_audit_hash()
        payload = f"{account_id}|FREEZE_ACCOUNT|{reason}|{now_ts}|{agent_id}|{prev_hash}"
        content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        audit_q = """
        MATCH (a:Account {id: $account_id})
        CREATE (e:EnforcementAction {
            id: $enf_id,
            action: 'FREEZE_ACCOUNT',
            reason: $reason,
            executed_by: $agent_id,
            timestamp: $ts,
            previous_hash: $prev_hash,
            content_hash: $content_hash
        })
        CREATE (a)-[:FLAGGED_BY]->(e)
        RETURN e.id, e.content_hash
        """
        self.query(audit_q, {
            "account_id": account_id,
            "enf_id": enf_id,
            "reason": reason,
            "agent_id": agent_id,
            "ts": now_ts,
            "prev_hash": prev_hash,
            "content_hash": content_hash,
        })

        return {
            "success": True,
            "account_id": account_id,
            "status": "FROZEN",
            "blocked_edges": blocked_count,
            "enforcement_id": enf_id,
            "content_hash": content_hash,
            "audit_hash": content_hash,
            "reason": reason,
        }

    def unfreeze_account(self, account_id: str, actor: str = "human_operator") -> bool:
        """
        Restores account to ACTIVE, restores previous_risk_score, unblocks outgoing routes
        (blocked = false), and records an UNFREEZE_ACCOUNT EnforcementAction node in the audit chain.
        """
        import hashlib

        # Check account
        check_q = "MATCH (a:Account {id: $account_id}) RETURN a.id, a.status, a.previous_risk_score"
        check_res = self.query(check_q, {"account_id": account_id})
        if not hasattr(check_res, "result_set") or not check_res.result_set:
            return False

        acc_id, current_status, prev_risk = check_res.result_set[0]
        target_risk = prev_risk if prev_risk is not None else 15
        now_ts = int(time.time() * 1000)

        # Unfreeze and unblock edges
        unfreeze_q = """
        MATCH (a:Account {id: $account_id})
        SET a.status = 'ACTIVE',
            a.risk_score = $target_risk,
            a.unfrozen_at = $ts
        WITH a
        OPTIONAL MATCH (a)-[r:TRANSFERRED]->()
        SET r.blocked = false,
            r.unblocked_at = $ts
        RETURN a.id
        """
        self.query(unfreeze_q, {"account_id": account_id, "target_risk": target_risk, "ts": now_ts})

        # Record tamper-evident unfreeze action
        enf_id = f"enf_{now_ts}"
        prev_hash = self.get_latest_audit_hash()
        reason = f"Operator unfreeze: restored to active with risk_score={target_risk}."
        payload = f"{account_id}|UNFREEZE_ACCOUNT|{reason}|{now_ts}|{actor}|{prev_hash}"
        content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        audit_q = """
        MATCH (a:Account {id: $account_id})
        CREATE (e:EnforcementAction {
            id: $enf_id,
            action: 'UNFREEZE_ACCOUNT',
            reason: $reason,
            executed_by: $actor,
            timestamp: $ts,
            previous_hash: $prev_hash,
            content_hash: $content_hash
        })
        CREATE (a)-[:FLAGGED_BY]->(e)
        RETURN e.id
        """
        self.query(audit_q, {
            "account_id": account_id,
            "enf_id": enf_id,
            "reason": reason,
            "actor": actor,
            "ts": now_ts,
            "prev_hash": prev_hash,
            "content_hash": content_hash,
        })

        return True

    def verify_audit_chain(self) -> Dict[str, Any]:
        """
        Validates cryptographic integrity of all EnforcementAction nodes.
        Verifies that each block's content_hash equals SHA256(payload)
        and correctly chains to previous_hash.
        """
        import hashlib

        cypher = """
        MATCH (a:Account)-[:FLAGGED_BY]->(e:EnforcementAction)
        RETURN a.id, e.action, e.reason, e.timestamp, e.executed_by, e.previous_hash, e.content_hash, e.id
        ORDER BY e.timestamp ASC
        """
        res = self.query(cypher)
        if not hasattr(res, "result_set") or not res.result_set:
            return {
                "valid": True,
                "verified_count": 0,
                "tampered": False,
                "message": "Audit chain empty. Genesis state intact.",
            }

        expected_prev_hash = "0" * 64
        for idx, row in enumerate(res.result_set):
            acc_id, action, reason, ts, actor, stored_prev_hash, stored_hash, enf_id = row
            if idx > 0 and stored_prev_hash != expected_prev_hash:
                return {
                    "valid": False,
                    "verified_count": idx,
                    "tampered": True,
                    "broken_at_id": enf_id,
                    "error": f"Broken link: expected previous_hash {expected_prev_hash}, got {stored_prev_hash}",
                }

            payload = f"{acc_id}|{action}|{reason}|{ts}|{actor}|{stored_prev_hash}"
            calculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if calculated_hash != stored_hash:
                return {
                    "valid": False,
                    "verified_count": idx,
                    "tampered": True,
                    "broken_at_id": enf_id,
                    "error": f"Hash mismatch on {enf_id}: calculated {calculated_hash}, stored {stored_hash}",
                }
            expected_prev_hash = stored_hash

        return {
            "valid": True,
            "verified_count": len(res.result_set),
            "tampered": False,
            "chain_tip_hash": expected_prev_hash,
            "message": f"Tamper-evident verification passed. Verified {len(res.result_set)} immutable audit actions.",
        }

    # -------------------------------------------------------------------------
    # VISUALIZATION & DOSSIER EXTRACTION
    # -------------------------------------------------------------------------

    def get_full_topology(self, node_limit: int = 500, edge_limit: int = 800) -> Dict[str, Any]:
        """
        Exports full graph formatted for Vis.js with color-coded threat levels:
          - Blue: Regular accounts
          - Orange: Flagged / Under Investigation
          - Red: Frozen accounts & Sanctioned Entities
          - Purple: Hardware Devices & IP addresses
        Supports configurable node and edge limits and sets truncated: true if capped.
        """
        n_lim = max(50, min(int(node_limit), 2000))
        e_lim = max(50, min(int(edge_limit), 3000))

        nodes_q = f"""
        MATCH (n)
        RETURN labels(n)[0] as type, n.id, n.holder, n.name, n.status, n.risk_score, n.fingerprint, n.ip
        LIMIT {n_lim + 1}
        """
        edges_q = f"""
        MATCH (s)-[r]->(t)
        RETURN s.id, coalesce(s.fingerprint, s.ip, s.id),
               type(r),
               t.id, coalesce(t.fingerprint, t.ip, t.id),
               coalesce(r.amount, '')
        LIMIT {e_lim + 1}
        """
        nodes_res = self.query(nodes_q)
        edges_res = self.query(edges_q)

        raw_nodes_list = nodes_res.result_set if hasattr(nodes_res, "result_set") and nodes_res.result_set else []
        raw_edges_list = edges_res.result_set if hasattr(edges_res, "result_set") and edges_res.result_set else []

        truncated = len(raw_nodes_list) > n_lim or len(raw_edges_list) > e_lim

        nodes = []
        seen = set()

        for row in raw_nodes_list[:n_lim]:
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
        for row in raw_edges_list[:e_lim]:
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

        return {"nodes": nodes, "edges": edges, "truncated": truncated}

    # -------------------------------------------------------------------------
    # AGENT GRAPH MEMORY & SCHEMA INTROSPECTION (Track 01 GraphRAG & Memory)
    # -------------------------------------------------------------------------

    def get_schema(self) -> Dict[str, Any]:
        """Introspects current FalkorDB graph schema: node labels, relationship types, and property keys."""
        schema = {"labels": [], "node_labels": [], "relationship_types": [], "property_keys": []}
        try:
            res_labels = self.query("CALL db.labels()")
            if hasattr(res_labels, "result_set") and res_labels.result_set:
                schema["labels"] = [r[0] for r in res_labels.result_set if r]
                schema["node_labels"] = schema["labels"]

            res_rels = self.query("CALL db.relationshipTypes()")
            if hasattr(res_rels, "result_set") and res_rels.result_set:
                schema["relationship_types"] = [r[0] for r in res_rels.result_set if r]

            res_props = self.query("CALL db.propertyKeys()")
            if hasattr(res_props, "result_set") and res_props.result_set:
                schema["property_keys"] = [r[0] for r in res_props.result_set if r]
        except Exception as e:
            logger.warning("Could not fetch graph schema: %s", e)
        return schema

    def save_investigation_memory(self, dossier: Dict[str, Any]) -> Optional[str]:
        """
        Persists investigation graph memory into FalkorDB:
        Creates (:Investigation) node linked to examined (:Account) nodes,
        (:Finding) nodes, and (:EnforcementAction) nodes.
        Idempotent: matches or merges on investigation_id.
        """
        inv_id = dossier.get("investigation_id")
        if not inv_id:
            return None

        raw_ts = dossier.get("timestamp")
        if isinstance(raw_ts, (int, float)):
            ts = int(raw_ts * 1000)
        else:
            ts = int(time.time() * 1000)

        mode = dossier.get("agent_mode", "rules")
        findings = dossier.get("findings", [])
        summary = f"{len(findings)} threats identified across graph"

        try:
            # Create or update Investigation node
            self.query(
                """
                MERGE (inv:Investigation {id: $inv_id})
                ON CREATE SET inv.timestamp = $ts, inv.mode = $mode, inv.summary = $summary
                ON MATCH SET inv.summary = $summary
                """,
                {"inv_id": inv_id, "ts": ts, "mode": mode, "summary": summary},
            )

            # Link examined accounts
            examined_accounts = set()
            for f in findings:
                if f.get("source_account"):
                    examined_accounts.add(f.get("source_account"))
                for m in f.get("ring_members", []):
                    examined_accounts.add(m)
                for m in f.get("accounts_sharing", []):
                    examined_accounts.add(m)
                for m in f.get("path_nodes", []):
                    if not str(m).startswith("SANCTION"):
                        examined_accounts.add(m)

            for acc_id in examined_accounts:
                self.query(
                    """
                    MATCH (inv:Investigation {id: $inv_id})
                    MATCH (acc:Account {id: $acc_id})
                    MERGE (inv)-[:EXAMINED]->(acc)
                    """,
                    {"inv_id": inv_id, "acc_id": acc_id},
                )

            # Store Finding nodes and link to Investigation & Accounts
            for idx, f in enumerate(findings):
                fid = f"{inv_id}_f{idx}"
                ftype = f.get("type", "UNKNOWN")
                fsev = f.get("severity", "MEDIUM")
                fconf = float(f.get("confidence", 0.85))
                fevid = str(f.get("reasoning", ""))

                self.query(
                    """
                    MATCH (inv:Investigation {id: $inv_id})
                    MERGE (fn:Finding {id: $fid})
                    ON CREATE SET fn.type = $ftype, fn.severity = $fsev, fn.confidence = $fconf, fn.evidence = $fevid
                    MERGE (inv)-[:UNCOVERED]->(fn)
                    """,
                    {"inv_id": inv_id, "fid": fid, "ftype": ftype, "fsev": fsev, "fconf": fconf, "fevid": fevid},
                )

                implicated = set()
                if f.get("source_account"):
                    implicated.add(f.get("source_account"))
                for m in f.get("ring_members", []):
                    implicated.add(m)
                for m in f.get("accounts_sharing", []):
                    implicated.add(m)

                for acc_id in implicated:
                    self.query(
                        """
                        MATCH (fn:Finding {id: $fid})
                        MATCH (acc:Account {id: $acc_id})
                        MERGE (fn)-[:IMPLICATES]->(acc)
                        """,
                        {"fid": fid, "acc_id": acc_id},
                    )
        except Exception as e:
            logger.warning("Could not persist investigation memory to FalkorDB: %s", e)
        return inv_id

    def recall_past_investigations(self, account_id: str) -> List[Dict[str, Any]]:
        """
        Recalls past investigations, findings, and operator decisions for a given account.
        Enables agent memory: the agent can cite prior reviews, analyst rejections, or past flags.
        """
        cypher = """
        MATCH (acc:Account {id: $account_id})
        OPTIONAL MATCH (inv:Investigation)-[:EXAMINED]->(acc)
        OPTIONAL MATCH (fn:Finding)-[:IMPLICATES]->(acc)
        OPTIONAL MATCH (acc)-[:FLAGGED_BY]->(act:EnforcementAction)
        RETURN inv.id AS investigation_id,
               inv.timestamp AS inv_timestamp,
               inv.mode AS inv_mode,
               fn.type AS threat_type,
               fn.severity AS severity,
               fn.evidence AS evidence,
               act.action AS prior_action,
               act.reason AS prior_reason
        LIMIT 20
        """
        try:
            res = self.ro_query(cypher, {"account_id": account_id})
            memories = []
            if hasattr(res, "result_set") and res.result_set:
                for row in res.result_set:
                    if any(row):
                        memories.append({
                            "investigation_id": row[0],
                            "investigation_timestamp": row[1],
                            "agent_mode": row[2],
                            "threat_type": row[3],
                            "severity": row[4],
                            "evidence": row[5],
                            "prior_action": row[6],
                            "prior_reason": row[7],
                        })
            return memories
        except Exception as e:
            logger.warning("Could not recall past investigations for %s: %s", account_id, e)
            return []

    def get_investigations_history(self) -> List[Dict[str, Any]]:
        """Returns past investigation memory records from FalkorDB."""
        cypher = """
        MATCH (inv:Investigation)
        OPTIONAL MATCH (inv)-[:UNCOVERED]->(fn:Finding)
        RETURN inv.id AS id,
               inv.timestamp AS timestamp,
               inv.mode AS mode,
               inv.summary AS summary,
               count(fn) AS threat_count
        ORDER BY inv.timestamp DESC
        LIMIT 20
        """
        try:
            res = self.ro_query(cypher)
            history = []
            if hasattr(res, "result_set") and res.result_set:
                for r in res.result_set:
                    history.append({
                        "id": r[0],
                        "investigation_id": r[0],
                        "timestamp": r[1],
                        "mode": r[2],
                        "summary": r[3],
                        "threat_count": r[4],
                    })
            return history
        except Exception as e:
            logger.warning("Could not query investigation history: %s", e)
            return []


_fraud_graph = None

def get_fraud_graph() -> FalkorFraudGraph:
    global _fraud_graph
    if _fraud_graph is None:
        _fraud_graph = FalkorFraudGraph()
    return _fraud_graph
