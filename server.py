"""
server.py
=========
OmniTrace REST & Dashboard Server (Port 8765).
FalkorDB Multi-Hop Graph Fraud Investigation Engine.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_ROOT / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR))
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("omnitrace.server")

from core.falkor_graph import get_fraud_graph
from data.fraud_generator import seed_fraud_dataset
from agent.investigator import OmniTraceInvestigator

graph = get_fraud_graph()
investigator = OmniTraceInvestigator()


@app.route("/")
def index():
    """Serve the OmniTrace Threat Cockpit UI."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h3>static/index.html not found</h3>", 404


@app.route("/api/graph/state")
def api_graph_state():
    """Return full graph topology for Vis.js visualization."""
    data = graph.get_full_topology()
    return jsonify(data)


@app.route("/api/seed", methods=["POST"])
def api_seed():
    """Seed synthetic financial banking graph."""
    res = seed_fraud_dataset(graph=graph)
    return jsonify(res)


@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    """Trigger the autonomous agent to investigate multi-hop threats."""
    dossier = investigator.run_full_investigation()
    return jsonify(dossier)


@app.route("/api/account/unfreeze", methods=["POST"])
def api_unfreeze():
    """Unfreeze an account in FalkorDB."""
    data = request.get_json(force=True, silent=True) or {}
    acc_id = data.get("account_id")
    if not acc_id:
        return jsonify({"ok": False, "error": "account_id required"}), 400
    ok = graph.unfreeze_account(acc_id)
    return jsonify({"ok": ok})


@app.route("/api/graph/query", methods=["POST"])
def api_graph_query():
    """Execute raw openCypher query directly against FalkorDB."""
    data = request.get_json(force=True, silent=True) or {}
    cypher = data.get("query", "").strip()
    if not cypher:
        return jsonify({"ok": False, "error": "Query string is empty"}), 400
    try:
        import time
        t0 = time.perf_counter()
        res = graph.query(cypher)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        columns = []
        rows = []
        if hasattr(res, "header") and res.header:
            columns = [str(h) for h in res.header]
        if hasattr(res, "result_set") and res.result_set:
            for r in res.result_set:
                row_fmt = []
                for val in r:
                    if isinstance(val, (dict, list)):
                        row_fmt.append(val)
                    else:
                        row_fmt.append(str(val))
                rows.append(row_fmt)

        return jsonify({
            "ok": True,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "execution_time_ms": latency_ms,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def run():
    port = int(os.getenv("PORT", 8765))
    print("=" * 68)
    print("  OMNITRACE :: AUTONOMOUS GRAPH FRAUD INVESTIGATOR (TRACK 01)")
    print(f"  Cockpit UI: http://localhost:{port}")
    print(f"  Graph:      {graph.graph_name} @ {graph.host}")
    print("=" * 68)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run()
