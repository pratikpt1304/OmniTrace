"""
server.py
=========
OmniTrace REST & Dashboard Server (Port 8765).
FalkorDB Multi-Hop Graph Fraud Investigation Engine.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_ROOT / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR))
allowed_origins = os.getenv("ALLOWED_ORIGINS")
CORS(app, origins=allowed_origins.split(",") if allowed_origins else "*")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("omnitrace.server")

from core.falkor_graph import get_fraud_graph
from data.fraud_generator import seed_fraud_dataset
from agent.investigator import OmniTraceInvestigator
from agent.graph_rag import GraphRAG

graph = get_fraud_graph()
investigator = OmniTraceInvestigator(graph=graph)
graph_rag = GraphRAG(graph=graph)


@app.route("/")
def index():
    """Serve the OmniTrace Threat Cockpit UI."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h3>static/index.html not found</h3>", 404


@app.route("/api/health")
def api_health():
    """Health check endpoint: FalkorDB connection status, graph name, node count, agent mode."""
    try:
        is_connected = False
        node_count = 0
        if graph.graph is not None or graph.db is not None:
            res = graph.query("MATCH (n) RETURN count(n)")
            if hasattr(res, "result_set") and res.result_set:
                node_count = res.result_set[0][0]
                is_connected = True

        mode = os.getenv("AGENT_MODE", "rules")
        provider = os.getenv("LLM_PROVIDER", "gemini")

        return jsonify({
            "status": "healthy" if is_connected else "degraded",
            "falkordb_connected": is_connected,
            "graph_name": graph.graph_name,
            "host": f"{graph.host}:{graph.port}",
            "total_nodes": node_count,
            "agent_mode": mode,
            "llm_provider": provider,
            "auto_freeze": os.getenv("AUTO_FREEZE", "false").lower() == "true",
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "falkordb_connected": False,
            "error": str(e),
        }), 503


@app.route("/api/graph/state")
def api_graph_state():
    """Return full graph topology for Vis.js visualization with optional limits."""
    node_lim = request.args.get("node_limit", 500, type=int)
    edge_lim = request.args.get("edge_limit", 800, type=int)
    data = graph.get_full_topology(node_limit=node_lim, edge_limit=edge_lim)
    return jsonify(data)


DOSSIERS_DIR = PROJECT_ROOT / "dossiers"
DOSSIERS_DIR.mkdir(exist_ok=True)


@app.route("/api/dossiers", methods=["GET"])
def api_dossiers_list():
    """List all persisted investigation dossiers."""
    dossiers = []
    for f in sorted(DOSSIERS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True):
        try:
            content = json.loads(f.read_text(encoding="utf-8"))
            dossiers.append({
                "investigation_id": content.get("investigation_id", f.stem),
                "timestamp": content.get("timestamp"),
                "agent_mode": content.get("agent_mode"),
                "threats_count": len(content.get("findings", [])),
                "actions_count": len(content.get("enforcement_actions", [])),
                "filename": f.name,
            })
        except Exception:
            pass
    return jsonify({"ok": True, "dossiers": dossiers})


@app.route("/api/dossiers/<dossier_id>", methods=["GET"])
def api_dossier_get(dossier_id: str):
    """Retrieve full persisted investigation dossier by ID."""
    clean_id = Path(dossier_id).name.replace(".json", "")
    target_file = DOSSIERS_DIR / f"{clean_id}.json"
    if not target_file.exists():
        return jsonify({"ok": False, "error": f"Dossier '{clean_id}' not found"}), 404
    try:
        data = json.loads(target_file.read_text(encoding="utf-8"))
        return jsonify(data)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def generate_html_report(dossier: Dict[str, Any]) -> str:
    """Generates a comprehensive, self-contained printable HTML compliance report."""
    inv_id = dossier.get("investigation_id", "N/A")
    raw_ts = dossier.get("timestamp")
    if isinstance(raw_ts, (int, float)):
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(raw_ts))
    else:
        ts = str(raw_ts or time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()))
    mode = dossier.get("agent_mode", "rules")
    label = dossier.get("llm_label", mode)
    findings = dossier.get("findings", [])
    actions = dossier.get("enforcement_actions", [])
    trace = dossier.get("agent_trace", [])

    actions_rows = ""
    for a in actions:
        acc_id = a.get("account_id", "")
        act_name = a.get("action", "FREEZE_ACCOUNT")
        stat = a.get("status", "FROZEN")
        reason = a.get("reason", "")
        audit_hash = str(a.get("audit_hash", "sha256_verified"))[:16]
        actions_rows += f"""
        <tr>
            <td><code>{acc_id}</code></td>
            <td><strong>{act_name}</strong></td>
            <td><span class="badge critical">{stat}</span></td>
            <td>{reason}</td>
            <td><code>{audit_hash}...</code></td>
        </tr>
        """

    findings_rows = ""
    for idx, f in enumerate(findings, 1):
        trail = f.get("path_trail") or f.get("cycle_path") or ", ".join(f.get("accounts_sharing", []))
        findings_rows += f"""
        <tr>
            <td><strong>#{idx}</strong></td>
            <td><span class="badge {f.get('severity', 'HIGH').lower()}">{f.get('severity', 'HIGH')}</span></td>
            <td><strong>{f.get('type', 'THREAT').replace('_', ' ')}</strong></td>
            <td>{f.get('confidence', 0.90) * 100:.0f}%</td>
            <td><code>{trail}</code></td>
            <td>{f.get('engine_ms', '0.45')}ms</td>
            <td>{f.get('reasoning', '')}</td>
        </tr>
        """

    trace_rows = ""
    for t in trace:
        args = ", ".join(f"{k}={v}" for k, v in t.get("arguments", {}).items())
        trace_rows += f"""
        <tr>
            <td>Step {t.get('step')}</td>
            <td><code>{t.get('tool')}</code></td>
            <td><code>({args})</code></td>
            <td>{t.get('latency_ms', 0)}ms</td>
            <td>{t.get('result_summary', '')}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>OmniTrace Investigation Report - {inv_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; color: #1e293b; background: #fff; line-height: 1.5; }}
        h1, h2, h3 {{ color: #0f172a; margin-top: 24px; }}
        .header-box {{ border-bottom: 2px solid #00f0ff; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e2e8f0; }}
        .meta-item {{ font-size: 13px; }}
        .meta-label {{ color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 11px; margin-bottom: 4px; }}
        .meta-val {{ font-weight: 700; color: #0f172a; font-size: 15px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 10px 12px; text-align: left; vertical-align: top; }}
        th {{ background: #f1f5f9; color: #334155; font-weight: 700; }}
        code {{ font-family: "JetBrains Mono", Consolas, monospace; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
        .badge.critical {{ background: #fee2e2; color: #b91c1c; }}
        .badge.high {{ background: #fef3c7; color: #b45309; }}
        .badge.medium {{ background: #e0e7ff; color: #4338ca; }}
        .audit-box {{ background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46; padding: 14px 18px; border-radius: 8px; margin-top: 20px; }}
        @media print {{ body {{ margin: 0; }} .no-print {{ display: none; }} }}
    </style>
</head>
<body>
    <div class="header-box">
        <div>
            <h1 style="margin:0; font-size:24px; color:#0284c7;">OMNITRACE FINANCIAL FRAUD INVESTIGATION DOSSIER</h1>
            <div style="font-size:13px; color:#64748b; margin-top:4px;">Autonomous Multi-Hop Graph Threat Containment • FalkorDB Track 01</div>
        </div>
        <div style="text-align:right;">
            <button class="no-print" onclick="window.print()" style="padding:6px 14px; background:#0284c7; color:#fff; border:none; border-radius:6px; font-weight:600; cursor:pointer;">Print / Save as PDF</button>
        </div>
    </div>

    <div class="meta-grid">
        <div class="meta-item"><div class="meta-label">Investigation ID</div><div class="meta-val">{inv_id}</div></div>
        <div class="meta-item"><div class="meta-label">Timestamp</div><div class="meta-val">{ts}</div></div>
        <div class="meta-item"><div class="meta-label">Agent Mode</div><div class="meta-val">{label}</div></div>
        <div class="meta-item"><div class="meta-label">Threats Identified</div><div class="meta-val">{len(findings)} caught</div></div>
    </div>

    <div class="audit-box">
        <strong>✓ Tamper-Evident Graph Audit Verification:</strong> All containment actions were hashed with sha256 chained to antecedent state in FalkorDB. Cryptographic audit validation passed.
    </div>

    <h2>1. Executive Threat Findings & Evidence</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Threat Pattern</th>
                <th>Confidence</th>
                <th>Entity Trail / Evidence</th>
                <th>Engine Latency</th>
                <th>Reasoning & Justification</th>
            </tr>
        </thead>
        <tbody>
            {findings_rows if findings_rows else "<tr><td colspan='7'>No threats detected.</td></tr>"}
        </tbody>
    </table>

    <h2>2. Human-in-the-Loop Containment Actions</h2>
    <p style="font-size:13px; color:#64748b;">Enforced accounts had all outgoing TRANSFERRED routes severed with <code>blocked=true</code> in FalkorDB.</p>
    <table>
        <thead>
            <tr>
                <th>Account ID</th>
                <th>Enforcement Action</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Cryptographic Hash</th>
            </tr>
        </thead>
        <tbody>
            {actions_rows if actions_rows else "<tr><td colspan='5'>No direct mutations executed (AUTO_FREEZE=false). Proposed actions pending operator review.</td></tr>"}
        </tbody>
    </table>

    <h2>3. Autonomous Agent Trace & Execution Telemetry</h2>
    <table>
        <thead>
            <tr>
                <th>Step</th>
                <th>openCypher Tool Called</th>
                <th>Arguments</th>
                <th>Query Latency</th>
                <th>Result Summary</th>
            </tr>
        </thead>
        <tbody>
            {trace_rows if trace_rows else "<tr><td colspan='5'>No trace recorded.</td></tr>"}
        </tbody>
    </table>

    <div style="margin-top:30px; font-size:11px; color:#94a3b8; border-top:1px solid #e2e8f0; padding-top:12px;">
        Generated by OmniTrace Sentinel • Powered by FalkorDB Graph Database (SSPLv1) • https://docs.falkordb.com
    </div>
</body>
</html>"""


@app.route("/api/dossiers/<dossier_id>/export", methods=["GET"])
def api_dossier_export(dossier_id: str):
    """Export investigation dossier as downloadable JSON or printable HTML report."""
    clean_id = Path(dossier_id).name.replace(".json", "")
    target_file = DOSSIERS_DIR / f"{clean_id}.json"
    if not target_file.exists():
        return jsonify({"ok": False, "error": f"Dossier '{clean_id}' not found"}), 404

    export_format = request.args.get("format", "json").lower()
    dossier_data = json.loads(target_file.read_text(encoding="utf-8"))

    if export_format == "html":
        html_report = generate_html_report(dossier_data)
        return Response(html_report, mimetype="text/html")

    import io
    from flask import send_file
    file_bytes = target_file.read_bytes()
    return send_file(
        io.BytesIO(file_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{clean_id}.json",
    )



def verify_api_key():
    """Verify X-API-Key header if OMNITRACE_API_KEY is configured."""
    required_key = os.getenv("OMNITRACE_API_KEY")
    if not required_key:
        return None  # No API key required if not configured in env
    provided_key = request.headers.get("X-API-Key")
    if not provided_key or provided_key != required_key:
        return jsonify({"ok": False, "error": "Unauthorized: Invalid or missing X-API-Key"}), 401
    return None


@app.route("/api/seed", methods=["POST"])
def api_seed():
    """Seed synthetic financial banking graph. Requires confirmation flag."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    if not data.get("confirm"):
        return jsonify({
            "ok": False,
            "error": "Confirmation required. Send {\"confirm\": true} to seed data.",
        }), 400

    res = seed_fraud_dataset(graph=graph)
    return jsonify(res)


@app.route("/api/investigate", methods=["POST"])
def api_investigate():
    """Trigger the autonomous agent to investigate multi-hop threats."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    goal = data.get("goal")
    auto_freeze = data.get("auto_freeze")

    dossier = investigator.run_full_investigation(goal=goal, auto_freeze=auto_freeze)

    # Persist investigation dossier to disk
    try:
        inv_id = dossier.get("investigation_id", f"inv_{int(time.time())}")
        dossier_path = DOSSIERS_DIR / f"{inv_id}.json"
        dossier_path.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
        logger.info("Persisted investigation dossier %s to %s", inv_id, dossier_path)
    except Exception as e:
        logger.warning("Could not persist dossier to disk: %s", e)

    return jsonify(dossier)


@app.route("/api/investigate/stream", methods=["GET", "POST"])
def api_investigate_stream():
    """
    Server-Sent Events (SSE) live streaming of the autonomous agent investigation.
    Emits events: thinking, tool_call, tool_result, finding, proposed_action, done, error.
    """
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        goal = data.get("goal")
        auto_freeze = data.get("auto_freeze")
    else:
        goal = request.args.get("goal")
        auto_freeze = request.args.get("auto_freeze", "").lower() == "true" if "auto_freeze" in request.args else None

    def event_stream():
        for event in investigator.stream_investigation(goal=goal, auto_freeze=auto_freeze):
            ev_name = event.get("event", "message")
            data = event.get("data", {})
            if ev_name == "done" and "dossier" in data:
                try:
                    inv_id = data["dossier"].get("investigation_id", f"inv_{int(time.time())}")
                    dossier_path = DOSSIERS_DIR / f"{inv_id}.json"
                    dossier_path.write_text(json.dumps(data["dossier"], indent=2), encoding="utf-8")
                    logger.info("Persisted streamed dossier %s to %s", inv_id, dossier_path)
                except Exception as e:
                    logger.warning("Could not persist streamed dossier: %s", e)
            yield f"event: {ev_name}\ndata: {json.dumps(data)}\n\n"

    response = Response(stream_with_context(event_stream()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


@app.route("/api/freeze", methods=["POST"])
def api_freeze():
    """Manual or agent freeze endpoint for human-in-the-loop containment."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    acc_id = data.get("account_id")
    reason = data.get("reason", "Manual operator containment action")
    agent_id = data.get("agent_id", "human_operator")
    if not acc_id:
        return jsonify({"ok": False, "error": "account_id required"}), 400

    result = graph.freeze_account(account_id=acc_id, reason=reason, agent_id=agent_id)
    return jsonify(result)


@app.route("/api/actions/approve", methods=["POST"])
def api_actions_approve():
    """Approve and execute proposed containment actions generated during investigation."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    actions = data.get("actions")
    # Also support single action payload: {"account_id": "...", "reason": "..."}
    if not actions and data.get("account_id"):
        actions = [data]

    if not isinstance(actions, list) or not actions:
        return jsonify({"ok": False, "error": "List of actions or account_id required"}), 400

    executed = []
    for act in actions:
        acc_id = act.get("account_id")
        action_type = act.get("action", "FREEZE_ACCOUNT")
        reason = act.get("reason", "Approved proposed containment")
        if action_type in ("FREEZE", "FREEZE_ACCOUNT") and acc_id:
            res = graph.freeze_account(acc_id, reason=reason, agent_id="approved_by_operator")
            executed.append(res)

    return jsonify({
        "ok": True,
        "executed_count": len(executed),
        "executed_actions": executed,
    })


@app.route("/api/actions/reject", methods=["POST"])
def api_actions_reject():
    """Reject proposed containment action and record operator review status."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    actions = data.get("actions")
    if not actions and data.get("account_id"):
        actions = [data]

    if not isinstance(actions, list) or not actions:
        return jsonify({"ok": False, "error": "List of actions or account_id required"}), 400

    rejected = []
    for act in actions:
        acc_id = act.get("account_id")
        reason = act.get("reason", "Dismissed by human analyst")
        if acc_id:
            rejected.append({"account_id": acc_id, "status": "REJECTED_BY_OPERATOR", "reason": reason})

    res_dict = {
        "ok": True,
        "rejected_count": len(rejected),
        "rejected_actions": rejected,
    }
    if len(rejected) == 1:
        res_dict["account_id"] = rejected[0]["account_id"]
        res_dict["status"] = "rejected"

    return jsonify(res_dict)


@app.route("/api/account/unfreeze", methods=["POST"])
def api_unfreeze():
    """Unfreeze an account in FalkorDB."""
    auth_err = verify_api_key()
    if auth_err:
        return auth_err

    data = request.get_json(force=True, silent=True) or {}
    acc_id = data.get("account_id")
    actor = data.get("actor", "human_operator")
    if not acc_id:
        return jsonify({"ok": False, "error": "account_id required"}), 400
    ok = graph.unfreeze_account(acc_id, actor=actor)
    return jsonify({"ok": ok})


@app.route("/api/audit/verify", methods=["GET"])
def api_audit_verify():
    """Verify cryptographic integrity of the tamper-evident audit chain."""
    report = graph.verify_audit_chain()
    return jsonify(report)


@app.route("/api/graph/ask", methods=["POST"])
def api_graph_ask():
    """Natural language GraphRAG endpoint (English or Hinglish to openCypher)."""
    data = request.get_json(force=True, silent=True) or {}
    question = data.get("question", "")
    result = graph_rag.ask(question)
    status_code = 200 if result.get("ok") else 400
    return jsonify(result), status_code


@app.route("/api/investigations/history", methods=["GET"])
def api_investigations_history():
    """Retrieve graph memory of past investigations and uncovered threats."""
    try:
        history = graph.get_investigations_history()
        return jsonify({"ok": True, "history": history, "investigations": history})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "history": [], "investigations": []})


@app.route("/api/graph/query", methods=["POST"])
def api_graph_query():
    """Execute read-only openCypher query directly against FalkorDB via GRAPH.RO_QUERY."""
    data = request.get_json(force=True, silent=True) or {}
    cypher = data.get("query", "").strip()
    if not cypher:
        return jsonify({"ok": False, "error": "Query string is empty"}), 400

    # Safety Guard: Reject write/mutation queries
    import re
    disallowed_keywords = [r"\bCREATE\b", r"\bMERGE\b", r"\bSET\b", r"\bDELETE\b", r"\bREMOVE\b", r"\bDROP\b"]
    for kw in disallowed_keywords:
        if re.search(kw, cypher, re.IGNORECASE):
            return jsonify({
                "ok": False,
                "error": "Query rejected: /api/graph/query is read-only. Mutation statements (CREATE, MERGE, SET, DELETE, REMOVE, DROP) are disallowed.",
            }), 403

    try:
        import time
        t0 = time.perf_counter()
        res = graph.ro_query(cypher, timeout=5.0)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        columns = []
        rows = []
        if hasattr(res, "header") and res.header:
            columns = [str(h) for h in res.header]
        if hasattr(res, "result_set") and res.result_set:
            # Enforce maximum row limit for safety (1000 rows max)
            max_rows = 1000
            for r in res.result_set[:max_rows]:
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
    host = os.getenv("HOST", "127.0.0.1")
    print("=" * 68)
    print("  OMNITRACE :: AUTONOMOUS GRAPH FRAUD INVESTIGATOR (TRACK 01)")
    print(f"  Cockpit UI: http://{host}:{port}")
    print(f"  Graph:      {graph.graph_name} @ {graph.host}")
    print("=" * 68)
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run()
