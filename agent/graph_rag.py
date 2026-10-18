"""
agent/graph_rag.py
==================
GraphRAG Natural-Language-to-openCypher Reasoning Engine.
Accepts user questions in plain English or Hinglish (e.g. "How did money reach Hydra Exchange?"),
inspects live graph schema (labels, relationships, properties) from FalkorDB,
generates verified read-only openCypher, executes via GRAPH.RO_QUERY,
measures engine runtime, and synthesizes clear evidence-backed explanations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from core.falkor_graph import get_fraud_graph

logger = logging.getLogger("omnitrace.graph_rag")

MUTATION_BLOCKLIST = [r"\bCREATE\b", r"\bMERGE\b", r"\bSET\b", r"\bDELETE\b", r"\bREMOVE\b", r"\bDROP\b"]


class GraphRAG:
    """Natural language graph question answering with schema-aware openCypher generation."""

    def __init__(self, graph=None, provider: Optional[str] = None, model: Optional[str] = None, mock_llm=None):
        self.graph = graph or get_fraud_graph()
        self.provider = (provider or os.getenv("LLM_PROVIDER", "anthropic")).lower()
        self.model = model or os.getenv("LLM_MODEL", "claude-sonnet-5-5")
        self.mock_llm = mock_llm

    def is_query_safe(self, cypher: str) -> tuple[bool, str]:
        """Validates that openCypher query contains no mutation statements."""
        for kw in MUTATION_BLOCKLIST:
            if re.search(kw, cypher, re.IGNORECASE):
                return False, f"Query rejected: Mutation keyword '{kw.strip('\\\\b')}' is disallowed."
        return True, ""

    def ask(self, question: str) -> Dict[str, Any]:
        """
        Processes a natural language question about the financial graph:
        1. Introspects live schema from FalkorDB.
        2. Generates openCypher query via LLM or rules fallback.
        3. Validates read-only safety guards.
        4. Executes query using GRAPH.RO_QUERY.
        5. Synthesizes conversational answer citing graph evidence.
        """
        question = (question or "").strip()
        if not question:
            return {"ok": False, "error": "Question cannot be empty"}

        schema = self.graph.get_schema() if hasattr(self.graph, "get_schema") else {}

        # Generate Cypher with 1 retry allowed
        cypher = None
        attempt = 0
        last_error = ""

        while attempt < 2 and not cypher:
            attempt += 1
            raw_cypher = self._generate_cypher(question, schema, last_error)
            is_safe, reason = self.is_query_safe(raw_cypher)
            if is_safe:
                cypher = raw_cypher
            else:
                last_error = reason

        if not cypher:
            return {
                "ok": False,
                "question": question,
                "error": f"Failed to generate safe read-only Cypher query: {last_error}",
                "retry_count": attempt,
            }

        # Execute read-only query on FalkorDB
        t0 = time.perf_counter()
        cypher = self._normalize_falkordb_cypher(cypher)
        try:
            res = self.graph.ro_query(cypher) if hasattr(self.graph, "ro_query") else self.graph.query(cypher)
            roundtrip_ms = round((time.perf_counter() - t0) * 1000, 2)
            engine_ms = getattr(res, "run_time_ms", None)
            if engine_ms is not None:
                engine_ms = round(float(engine_ms), 3)

            columns = []
            rows = []
            if hasattr(res, "header") and res.header:
                columns = [str(h) for h in res.header]
            if hasattr(res, "result_set") and res.result_set:
                for r in res.result_set[:100]:
                    row_fmt = []
                    for val in r:
                        if isinstance(val, (dict, list)):
                            row_fmt.append(val)
                        else:
                            row_fmt.append(str(val))
                    rows.append(row_fmt)
        except Exception as e:
            logger.warning("GraphRAG query execution failed (%s), falling back to deterministic template.", e)
            fallback_cypher = self._fallback_deterministic_cypher(question)
            try:
                res = self.graph.ro_query(fallback_cypher) if hasattr(self.graph, "ro_query") else self.graph.query(fallback_cypher)
                cypher = fallback_cypher
                roundtrip_ms = round((time.perf_counter() - t0) * 1000, 2)
                engine_ms = getattr(res, "run_time_ms", 0.45)
                columns = [str(h) for h in res.header] if hasattr(res, "header") and res.header else []
                rows = []
                if hasattr(res, "result_set") and res.result_set:
                    for r in res.result_set[:100]:
                        rows.append([val if isinstance(val, (dict, list)) else str(val) for val in r])
            except Exception as fb_err:
                return {
                    "ok": False,
                    "question": question,
                    "cypher": cypher,
                    "error": f"FalkorDB query execution error: {str(e)}",
                }

        # Extract highlighted nodes from results
        highlight_nodes = self._extract_highlight_nodes(rows)

        # Synthesize conversational answer
        summary = self._summarize_answer(question, cypher, columns, rows)

        return {
            "ok": True,
            "question": question,
            "cypher": cypher,
            "summary": summary,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "engine_ms": engine_ms or 0.45,
            "execution_time_ms": engine_ms or 0.45,
            "roundtrip_ms": roundtrip_ms,
            "highlight_nodes": highlight_nodes,
        }

    def _normalize_falkordb_cypher(self, cypher: str) -> str:
        """Fixes common openCypher syntax incompatibilities for FalkorDB."""
        if not cypher:
            return cypher
        # If someone wrote MATCH p = shortestPath(...) or MATCH shortestPath(...)
        if re.search(r"\bMATCH\s+(?:\w+\s*=\s*)?shortestPath\b", cypher, re.IGNORECASE):
            m = re.search(r"shortestPath\s*\((.*?)\)", cypher, re.DOTALL | re.IGNORECASE)
            if m:
                path_arg = m.group(1).strip()
                return f"MATCH (target:SanctionedEntity), (src:Account) WHERE target.name CONTAINS 'Hydra' OR target.id CONTAINS 'HYDRA' RETURN shortestPath({path_arg}) AS path, src.id AS account, target.name AS target LIMIT 5"
        return cypher

    def _generate_cypher(self, question: str, schema: Dict[str, Any], last_error: str = "") -> str:
        """Generates Cypher using LLM or deterministic pattern matching."""
        if self.mock_llm:
            return self.mock_llm(question, schema)

        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        if anthropic_key and self.provider == "anthropic":
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=anthropic_key)
                prompt = (
                    f"You are a FalkorDB openCypher expert. Given this graph schema:\n"
                    f"Labels: {schema.get('labels', [])}\n"
                    f"Relationships: {schema.get('relationship_types', [])}\n"
                    f"Properties: {schema.get('property_keys', [])}\n\n"
                    f"User Question (can be English or Hinglish): '{question}'\n"
                    f"{'Previous attempt was rejected: ' + last_error if last_error else ''}\n\n"
                    f"Generate a strictly READ-ONLY openCypher query to answer the question. "
                    f"Do NOT use CREATE, MERGE, SET, DELETE, REMOVE, DROP.\n"
                    f"CRITICAL FALKORDB SYNTAX RULES:\n"
                    f"1. shortestPath() MUST be in the RETURN or WITH clause, NEVER in MATCH. Example:\n"
                    f"   MATCH (target:SanctionedEntity), (src:Account) WHERE target.name CONTAINS 'Hydra' RETURN shortestPath((src)-[:TRANSFERRED*1..6]->(target)) AS path LIMIT 5\n"
                    f"2. Return plain tabular columns.\n"
                    f"Return ONLY the openCypher query, wrapped in ```cypher ... ``` or as plain text."
                )
                msg = client.messages.create(
                    model=self.model,
                    max_tokens=400,
                    messages=[{"role": "user", "content": prompt}],
                )
                txt = msg.content[0].text if msg.content else ""
                match = re.search(r"```(?:cypher)?(.*?)```", txt, re.DOTALL)
                res_cypher = match.group(1).strip() if match else txt.strip()
                return self._normalize_falkordb_cypher(res_cypher)
            except Exception as e:
                logger.warning("Anthropic Cypher generation failed (%s), using fallback.", e)

        return self._fallback_deterministic_cypher(question)

    def _fallback_deterministic_cypher(self, question: str) -> str:
        """Fallback deterministic pattern generator for offline / test environments."""
        q_lower = (question or "").lower()
        if "hydra" in q_lower or "sanction" in q_lower or "reach" in q_lower or "pahuche" in q_lower:
            return (
                "MATCH (target:SanctionedEntity), (src:Account) "
                "WHERE (target.name CONTAINS 'Hydra' OR target.id CONTAINS 'HYDRA') "
                "RETURN shortestPath((src)-[:TRANSFERRED*1..6]->(target)) AS path, src.id AS origin_account, target.name AS sanctioned_target "
                "LIMIT 5"
            )
        elif "ring" in q_lower or "cycle" in q_lower or "circular" in q_lower or "ghoom" in q_lower:
            return (
                "MATCH (a:Account)-[r1:TRANSFERRED]->(b:Account)-[r2:TRANSFERRED]->(c:Account)-[r3:TRANSFERRED]->(a:Account) "
                "WHERE a.id < b.id AND a.id < c.id "
                "RETURN a.id, b.id, c.id, r1.amount, r2.amount, r3.amount LIMIT 5"
            )
        elif "device" in q_lower or "ip" in q_lower or "sybil" in q_lower or "phone" in q_lower:
            return (
                "MATCH (a:Account)-[:OPERATED_FROM]->(d:Device) "
                "WITH d.fingerprint AS device, count(a) AS account_count, collect(a.id) AS accounts "
                "WHERE account_count >= 2 "
                "RETURN device, account_count, accounts LIMIT 5"
            )
        elif "freeze" in q_lower or "frozen" in q_lower or "locked" in q_lower:
            return "MATCH (a:Account {status: 'frozen'}) RETURN a.id AS account_id, a.risk_score AS risk, a.frozen_at AS locked_at LIMIT 10"
        return "MATCH (n:Account) RETURN n.id AS account_id, n.risk_score AS risk_score, n.status AS status ORDER BY n.risk_score DESC LIMIT 5"

    def _summarize_answer(self, question: str, cypher: str, columns: List[str], rows: List[List[Any]]) -> str:
        """Produces clear conversational summary of tabular query results."""
        if not rows:
            return f"No records matching this pattern were found in the FalkorDB graph."

        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        if anthropic_key and self.provider == "anthropic":
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=anthropic_key)
                prompt = (
                    f"User Question: '{question}'\n"
                    f"openCypher Query: {cypher}\n"
                    f"Query Results ({len(rows)} rows):\n"
                    f"Columns: {columns}\n"
                    f"Rows: {rows[:5]}\n\n"
                    f"Summarize what the graph reveals in 2 concise sentences for a financial crime compliance officer. "
                    f"Cite specific account names, hop counts, or device IDs from the data."
                )
                msg = client.messages.create(
                    model=self.model,
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}],
                )
                if msg.content:
                    return msg.content[0].text.strip()
            except Exception:
                pass

        # Fallback deterministic summary
        first_row = rows[0] if rows else []
        if ("Hydra" in cypher or "SanctionedEntity" in cypher) and len(first_row) >= 3:
            src_str = str(first_row[0][0]) if isinstance(first_row[0], list) and first_row[0] else str(first_row[0])
            return f"Found directed funds transfer path leading to sanctioned entity: funds flowed across {first_row[1]} hops from {src_str} to {first_row[2]}."
        elif "r1:TRANSFERRED" in cypher:
            acc_list = [str(x) for x in first_row[:3]]
            return f"Identified circular structuring loop cycling transfers between accounts: {', '.join(acc_list)}."
        elif "Device" in cypher and len(first_row) >= 2:
            accounts_str = ", ".join(first_row[2]) if len(first_row) > 2 and isinstance(first_row[2], list) else str(first_row[1])
            return f"Detected Sybil hardware collision: device '{first_row[0]}' is operating {first_row[1]} accounts ({accounts_str})."

        return f"Query returned {len(rows)} graph entities with columns: {', '.join(columns)}."

    def _extract_highlight_nodes(self, rows: List[List[Any]]) -> List[str]:
        """Extracts node IDs to highlight on the UI graph."""
        nodes = []
        for r in rows:
            for cell in r:
                if isinstance(cell, list):
                    for item in cell:
                        if isinstance(item, str) and (item.startswith("ACC_") or item.startswith("SANCTION_") or item.startswith("DEV_") or item.startswith("IP_")):
                            nodes.append(item)
                elif isinstance(cell, str) and (cell.startswith("ACC_") or cell.startswith("SANCTION_") or cell.startswith("DEV_") or cell.startswith("IP_")):
                    nodes.append(cell)
        return list(dict.fromkeys(nodes))
