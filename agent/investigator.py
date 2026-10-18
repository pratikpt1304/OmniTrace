"""
agent/investigator.py
=====================
Autonomous Graph Fraud Investigator Agent for Track 01.
Orchestrates multi-hop graph reasoning, executes tool-calling loops with LLM
providers (Gemini or Anthropic) or deterministic rules fallback, records
complete agent_trace telemetry, and enforces containment actions.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional

from agent.tools import INVESTIGATION_TOOLS
from core.falkor_graph import get_fraud_graph

logger = logging.getLogger("omnitrace.investigator")

DEFAULT_GOAL = (
    "Investigate this banking graph for sanctions exposure, laundering rings, "
    "and Sybil clusters. Discover suspicious starting accounts dynamically, trace "
    "multi-hop routes to sanctioned entities, detect circular cycles, check hardware/IP "
    "collisions, and freeze compromised nodes with clear justifications."
)


class OmniTraceInvestigator:
    """
    Autonomous threat investigator agent that leverages FalkorDB openCypher
    graph algorithms via an LLM tool-calling loop (Anthropic Claude, Gemini, or mock)
    or deterministic rules fallback, streaming telemetry and evidence-backed findings.
    """

    def __init__(
        self,
        agent_id: str = "omni_sentinel_01",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        max_steps: int = 12,
        mock_llm: Optional[Callable] = None,
        graph=None,
    ):
        self.agent_id = agent_id
        self.graph = graph or get_fraud_graph()
        self.provider = (provider or os.getenv("LLM_PROVIDER", "anthropic")).lower()
        self.model = model or os.getenv(
            "LLM_MODEL",
            "claude-sonnet-5-5" if self.provider == "anthropic" else "gemini-2.5-flash",
        )
        self.max_steps = max_steps
        self.mock_llm = mock_llm
        self.tool_map = {t["name"]: t["handler"] for t in INVESTIGATION_TOOLS}

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Executes tool by name with arguments and handles exceptions gracefully."""
        if name not in self.tool_map:
            return {"error": f"Tool '{name}' is not registered."}
        try:
            return self.tool_map[name](**args, graph=self.graph)
        except TypeError:
            try:
                return self.tool_map[name](**args)
            except Exception as e:
                logger.warning("Error executing tool %s with args %s: %s", name, args, e)
                return {"error": f"Tool execution failed: {str(e)}"}
        except Exception as e:
            logger.warning("Error executing tool %s with args %s: %s", name, args, e)
            return {"error": f"Tool execution failed: {str(e)}"}

    def run_full_investigation(
        self, goal: Optional[str] = None, auto_freeze: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Runs complete investigation non-streaming and returns the final dossier.
        """
        dossier = None
        for event in self.stream_investigation(goal=goal, auto_freeze=auto_freeze):
            if event.get("event") == "done":
                dossier = event.get("data", {}).get("dossier")

        if dossier is None:
            # Fallback initialization in case generator yielded early error
            dossier = {
                "investigation_id": f"inv_{int(time.time())}",
                "agent_id": self.agent_id,
                "timestamp": time.time(),
                "agent_mode": "rules",
                "goal": goal or DEFAULT_GOAL,
                "findings": [],
                "proposed_actions": [],
                "enforcement_actions": [],
                "graph_metrics": {},
            }
        return dossier

    def stream_investigation(
        self, goal: Optional[str] = None, auto_freeze: Optional[bool] = None
    ):
        """
        Generator yielding real-time SSE events as the agent investigates:
          - thinking: model reasoning tokens or text
          - tool_call: { step, tool, arguments }
          - tool_result: { step, tool, summary, engine_ms, roundtrip_ms }
          - finding: structured finding card
          - proposed_action: containment action proposal
          - done: { dossier }
          - error: { error }
        """
        if auto_freeze is None:
            auto_freeze = os.getenv("AUTO_FREEZE", "false").lower() == "true"

        goal = goal or DEFAULT_GOAL
        mode = os.getenv("AGENT_MODE", "").lower()

        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        gemini_key = os.getenv("GEMINI_API_KEY")

        can_run_llm = bool(
            self.mock_llm
            or (self.provider == "anthropic" and anthropic_key)
            or (self.provider == "gemini" and gemini_key)
        )

        effective_mode = "rules" if mode == "rules" or not can_run_llm else "llm"
        llm_label = (
            f"Claude ({self.model})"
            if effective_mode == "llm" and self.provider == "anthropic"
            else f"Gemini ({self.model})"
            if effective_mode == "llm" and self.provider == "gemini"
            else "Mock LLM"
            if self.mock_llm
            else "Rules Engine (Deterministic)"
        )

        dossier: Dict[str, Any] = {
            "investigation_id": f"inv_{int(time.time())}",
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            "agent_mode": effective_mode,
            "llm_label": llm_label,
            "auto_freeze": auto_freeze,
            "goal": goal,
            "agent_trace": [],
            "findings": [],
            "proposed_actions": [],
            "enforcement_actions": [],
            "graph_metrics": {},
        }
        self._auto_freeze = auto_freeze

        system_prompt = (
            "You are OmniTrace, a specialized senior financial-crime and graph fraud intelligence investigator. "
            "You have direct access to FalkorDB multi-hop openCypher graph tools. "
            "Investigate this banking graph step-by-step for sanctions evasion, circular structuring rings, and Sybil hardware/IP clusters.\n\n"
            "OPERATIONAL PROTOCOL:\n"
            "1. DISCOVERY: Start by calling `list_high_risk_accounts(min_risk=50)` or `calculate_pass_through_mules()` to locate flagged entities dynamically.\n"
            "2. MEMORY CHECK: Call `recall_past_investigations(account_id)` to review prior findings, analyst rejections, or past flags from graph memory.\n"
            "3. MULTI-HOP TRACING: For discovered accounts with elevated risk, call `find_shortest_path_to_sanctioned(account_id)` to audit directed funds flow to blacklists.\n"
            "4. CYCLE DETECTION: Call `detect_circular_money_laundering(max_hops=4)` to catch closed layering loops.\n"
            "5. CLUSTER DETECTION: Call `detect_device_ip_collisions()` to uncover Sybil farms sharing devices or VPN proxies.\n"
            "6. EVIDENCE & ACTION: Propose containment via `propose_freeze(account_id, reason, evidence)`. DO NOT invent accounts that did not appear in tool outputs.\n"
            "7. Explain your reasoning at each step and cite concrete evidence before concluding."
        )

        try:
            if effective_mode == "llm":
                if self.mock_llm:
                    yield from self._stream_mock_llm(dossier, goal, system_prompt)
                elif self.provider == "anthropic":
                    yield from self._stream_anthropic(dossier, goal, system_prompt)
                elif self.provider == "gemini":
                    yield from self._stream_gemini(dossier, goal, system_prompt)
                else:
                    yield from self._stream_rules_fallback(dossier)
            else:
                yield from self._stream_rules_fallback(dossier)
        except Exception as e:
            logger.error("Error during agent investigation stream: %s", e)
            yield {"event": "error", "data": {"error": str(e)}}
            # If LLM failed, fallback to rules
            if effective_mode == "llm":
                dossier["agent_mode"] = "rules_fallback_on_error"
                dossier["llm_label"] = "Fallback: rules mode"
                yield from self._stream_rules_fallback(dossier)

        # Compute summary metrics
        try:
            topology = self.graph.get_full_topology()
            total_nodes = len(topology.get("nodes", []))
            total_edges = len(topology.get("edges", []))
        except Exception:
            total_nodes = 0
            total_edges = 0

        dossier["graph_metrics"] = {
            "total_nodes_audited": total_nodes,
            "total_edges_traversed": total_edges,
            "total_threats_neutralized": len(dossier["enforcement_actions"]),
            "total_actions_proposed": len(dossier["proposed_actions"]),
            "status": "COMPLETED",
        }

        # Persist investigation memory into FalkorDB
        try:
            if hasattr(self.graph, "save_investigation_memory"):
                self.graph.save_investigation_memory(dossier)
        except Exception as e:
            logger.warning("Could not persist investigation memory: %s", e)

        yield {"event": "done", "data": {"dossier": dossier}}

    # -------------------------------------------------------------------------
    # STREAMING LLM RUNNERS (ANTHROPIC, GEMINI, MOCK)
    # -------------------------------------------------------------------------

    def _stream_anthropic(self, dossier: Dict[str, Any], goal: str, system_prompt: str):
        """Streams tool loop via Anthropic SDK with Claude Sonnet."""
        import anthropic

        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        anthropic_tools = [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            }
            for t in INVESTIGATION_TOOLS
        ]

        messages = [{"role": "user", "content": goal}]
        step = 0

        while step < self.max_steps:
            step += 1
            response = client.messages.create(
                model=self.model,
                max_tokens=1500,
                system=system_prompt,
                tools=anthropic_tools,
                messages=messages,
            )

            # Emit thinking text if present
            for block in response.content:
                if getattr(block, "type", None) == "text" and block.text:
                    yield {"event": "thinking", "data": {"text": block.text.strip(), "step": step}}

            if response.stop_reason not in ("tool_use", "end_turn") and not any(getattr(b, "type", "") == "tool_use" for b in response.content):
                break

            tool_results = []
            has_tool = False
            for block in response.content:
                if getattr(block, "type", None) == "tool_use":
                    has_tool = True
                    tool_name = block.name
                    args = block.input or {}

                    yield {
                        "event": "tool_call",
                        "data": {"step": step, "tool": tool_name, "arguments": args},
                    }

                    t0 = time.perf_counter()
                    result = self._execute_tool(tool_name, args)
                    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

                    summary = self._summarize_result(result)
                    engine_ms = self._get_engine_ms(result)

                    yield {
                        "event": "tool_result",
                        "data": {
                            "step": step,
                            "tool": tool_name,
                            "summary": summary,
                            "latency_ms": latency_ms,
                            "engine_ms": engine_ms,
                        },
                    }

                    self._record_trace(dossier, step, tool_name, args, result, latency_ms)
                    new_findings, new_actions = self._synthesize_finding_from_tool(
                        dossier, tool_name, args, result, latency_ms
                    )

                    for f in new_findings:
                        yield {"event": "finding", "data": f}
                    for a in new_actions:
                        yield {"event": "proposed_action", "data": a}

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result),
                    })

            if not has_tool or response.stop_reason == "end_turn":
                break

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

    def _stream_mock_llm(self, dossier: Dict[str, Any], goal: str, system_prompt: str):
        """Simulates step-by-step LLM decisions for testing."""
        history = [{"role": "system", "content": system_prompt}, {"role": "user", "content": goal}]
        for step in range(1, self.max_steps + 1):
            decision = self.mock_llm(history, step)
            if not decision or decision.get("type") == "finish":
                break

            if "thinking" in decision:
                yield {"event": "thinking", "data": {"text": decision["thinking"], "step": step}}

            tool_name = decision.get("tool")
            args = decision.get("args", {})

            yield {
                "event": "tool_call",
                "data": {"step": step, "tool": tool_name, "arguments": args},
            }

            t0 = time.perf_counter()
            result = self._execute_tool(tool_name, args)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            summary = self._summarize_result(result)
            engine_ms = self._get_engine_ms(result)

            yield {
                "event": "tool_result",
                "data": {
                    "step": step,
                    "tool": tool_name,
                    "summary": summary,
                    "latency_ms": latency_ms,
                    "engine_ms": engine_ms,
                },
            }

            self._record_trace(dossier, step, tool_name, args, result, latency_ms)
            new_findings, new_actions = self._synthesize_finding_from_tool(
                dossier, tool_name, args, result, latency_ms
            )

            for f in new_findings:
                yield {"event": "finding", "data": f}
            for a in new_actions:
                yield {"event": "proposed_action", "data": a}

            history.append({
                "role": "assistant",
                "tool_calls": [{"name": tool_name, "args": args}],
            })
            history.append({"role": "tool", "name": tool_name, "result": result})

    def _stream_gemini(self, dossier: Dict[str, Any], goal: str, system_prompt: str):
        """Fallback tool streaming via Google GenAI SDK."""
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
            function_declarations = [
                types.FunctionDeclaration(
                    name=t["name"],
                    description=t["description"],
                    parameters=t.get("parameters"),
                )
                for t in INVESTIGATION_TOOLS
            ]
            gemini_tools = [types.Tool(function_declarations=function_declarations)]
            chat = client.chats.create(
                model=self.model,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    tools=gemini_tools,
                    temperature=0.1,
                ),
            )
            response = chat.send_message(goal)
            step = 0
            while step < self.max_steps:
                step += 1
                if response.text:
                    yield {"event": "thinking", "data": {"text": response.text.strip(), "step": step}}
                if not response.function_calls:
                    break
                tool_responses = []
                for fc in response.function_calls:
                    tool_name = fc.name
                    args = dict(fc.args) if fc.args else {}
                    yield {"event": "tool_call", "data": {"step": step, "tool": tool_name, "arguments": args}}
                    t0 = time.perf_counter()
                    result = self._execute_tool(tool_name, args)
                    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                    summary = self._summarize_result(result)
                    engine_ms = self._get_engine_ms(result)
                    yield {
                        "event": "tool_result",
                        "data": {
                            "step": step,
                            "tool": tool_name,
                            "summary": summary,
                            "latency_ms": latency_ms,
                            "engine_ms": engine_ms,
                        },
                    }
                    self._record_trace(dossier, step, tool_name, args, result, latency_ms)
                    new_findings, new_actions = self._synthesize_finding_from_tool(
                        dossier, tool_name, args, result, latency_ms
                    )
                    for f in new_findings:
                        yield {"event": "finding", "data": f}
                    for a in new_actions:
                        yield {"event": "proposed_action", "data": a}
                    tool_responses.append(types.Part.from_function_response(name=tool_name, response={"result": result}))
                response = chat.send_message(tool_responses)
        except Exception as e:
            logger.error("Gemini streaming error: %s. Falling back to rules.", e)
            yield from self._stream_rules_fallback(dossier)

    def _stream_rules_fallback(self, dossier: Dict[str, Any]):
        """Streams deterministic rules execution without hardcoded account IDs."""
        yield {
            "event": "thinking",
            "data": {
                "text": "Initiating deterministic graph traversal rules. Identifying high-risk starting points...",
                "step": 1,
            },
        }

        # Step 1: list_high_risk_accounts
        yield {"event": "tool_call", "data": {"step": 1, "tool": "list_high_risk_accounts", "arguments": {"threshold": 40}}}
        t0 = time.perf_counter()
        accounts = self._execute_tool("list_high_risk_accounts", {"threshold": 40})
        lat1 = round((time.perf_counter() - t0) * 1000, 2)
        summary1 = f"Discovered {len(accounts)} accounts with risk >= 40." if isinstance(accounts, list) else str(accounts)
        yield {"event": "tool_result", "data": {"step": 1, "tool": "list_high_risk_accounts", "summary": summary1, "latency_ms": lat1}}
        self._record_trace(dossier, 1, "list_high_risk_accounts", {"threshold": 40}, accounts, lat1)

        step = 2
        # Step 2: Trace sanctions paths for discovered accounts
        if isinstance(accounts, list):
            for acc in accounts[:3]:
                acc_id = acc.get("id")
                if not acc_id:
                    continue
                yield {"event": "tool_call", "data": {"step": step, "tool": "find_shortest_path_to_sanctioned", "arguments": {"account_id": acc_id}}}
                t0 = time.perf_counter()
                path_res = self._execute_tool("find_shortest_path_to_sanctioned", {"account_id": acc_id})
                lat2 = round((time.perf_counter() - t0) * 1000, 2)
                summary2 = f"found={path_res.get('found')}, hops={path_res.get('hop_count', 0)}" if isinstance(path_res, dict) else str(path_res)
                yield {"event": "tool_result", "data": {"step": step, "tool": "find_shortest_path_to_sanctioned", "summary": summary2, "latency_ms": lat2, "engine_ms": self._get_engine_ms(path_res)}}
                self._record_trace(dossier, step, "find_shortest_path_to_sanctioned", {"account_id": acc_id}, path_res, lat2)
                new_f, new_a = self._synthesize_finding_from_tool(dossier, "find_shortest_path_to_sanctioned", {"account_id": acc_id}, path_res, lat2)
                for f in new_f:
                    yield {"event": "finding", "data": f}
                for a in new_a:
                    yield {"event": "proposed_action", "data": a}
                step += 1

        # Step 3: detect_circular_money_laundering
        yield {"event": "tool_call", "data": {"step": step, "tool": "detect_circular_money_laundering", "arguments": {"max_hops": 4}}}
        t0 = time.perf_counter()
        cycles = self._execute_tool("detect_circular_money_laundering", {"max_hops": 4})
        lat3 = round((time.perf_counter() - t0) * 1000, 2)
        summary3 = f"Identified {len(cycles)} unique circular structuring rings." if isinstance(cycles, list) else str(cycles)
        yield {"event": "tool_result", "data": {"step": step, "tool": "detect_circular_money_laundering", "summary": summary3, "latency_ms": lat3}}
        self._record_trace(dossier, step, "detect_circular_money_laundering", {"max_hops": 4}, cycles, lat3)
        new_f, new_a = self._synthesize_finding_from_tool(dossier, "detect_circular_money_laundering", {"max_hops": 4}, cycles, lat3)
        for f in new_f:
            yield {"event": "finding", "data": f}
        for a in new_a:
            yield {"event": "proposed_action", "data": a}
        step += 1

        # Step 4: detect_device_ip_collisions
        yield {"event": "tool_call", "data": {"step": step, "tool": "detect_device_ip_collisions", "arguments": {}}}
        t0 = time.perf_counter()
        sybil = self._execute_tool("detect_device_ip_collisions", {})
        lat4 = round((time.perf_counter() - t0) * 1000, 2)
        summary4 = f"Identified {len(sybil)} Sybil device/IP clusters." if isinstance(sybil, list) else str(sybil)
        yield {"event": "tool_result", "data": {"step": step, "tool": "detect_device_ip_collisions", "summary": summary4, "latency_ms": lat4}}
        self._record_trace(dossier, step, "detect_device_ip_collisions", {}, sybil, lat4)
        new_f, new_a = self._synthesize_finding_from_tool(dossier, "detect_device_ip_collisions", {}, sybil, lat4)
        for f in new_f:
            yield {"event": "finding", "data": f}
        for a in new_a:
            yield {"event": "proposed_action", "data": a}

    def _summarize_result(self, result: Any) -> str:
        """Helper to compute brief human-readable summary of tool result."""
        if isinstance(result, list):
            return f"Returned {len(result)} items."
        elif isinstance(result, dict):
            if "found" in result:
                return f"found={result.get('found')}, hops={result.get('hop_count', 0)}, target={result.get('sanctioned_name', 'N/A')}"
            elif "success" in result:
                return f"success={result.get('success')}, status={result.get('status')}"
            return f"Returned keys: {', '.join(list(result.keys())[:4])}"
        return str(result)[:60]

    def _get_engine_ms(self, result: Any) -> Optional[float]:
        if isinstance(result, dict) and "engine_ms" in result:
            return result.get("engine_ms")
        elif isinstance(result, list) and result and isinstance(result[0], dict) and "engine_ms" in result[0]:
            return result[0].get("engine_ms")
        return None

    # -------------------------------------------------------------------------
    # TRACE & DOSSIER SYNTHESIS HELPERS
    # -------------------------------------------------------------------------
    def _record_trace(
        self,
        dossier: Dict[str, Any],
        step: int,
        tool: str,
        args: Dict[str, Any],
        result: Any,
        latency_ms: float,
    ) -> None:
        """Records an execution step into agent_trace."""
        if isinstance(result, list):
            summary = f"Returned {len(result)} items."
        elif isinstance(result, dict):
            if "found" in result:
                summary = f"found={result['found']}, hops={result.get('hop_count', 0)}"
            elif "success" in result:
                summary = f"success={result['success']}, status={result.get('status')}"
            else:
                summary = f"Returned {len(result)} keys."
        else:
            summary = str(result)[:60]

        dossier["agent_trace"].append({
            "step": step,
            "tool": tool,
            "arguments": args,
            "result_summary": summary,
            "latency_ms": latency_ms,
            "timestamp": time.time(),
        })

    def _synthesize_finding_from_tool(
        self,
        dossier: Dict[str, Any],
        tool_name: str,
        args: Dict[str, Any],
        result: Any,
        latency_ms: float,
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extracts structured findings and triggers automated/proposed freezes from tool output using ThreatPolicy."""
        from core.policy import ThreatPolicy

        new_findings: List[Dict[str, Any]] = []
        new_actions: List[Dict[str, Any]] = []

        if tool_name == "find_shortest_path_to_sanctioned" and isinstance(result, dict) and result.get("found"):
            path_nodes = result.get("path_nodes", [])
            hop_nodes = [n.get("id") or n.get("properties", {}).get("name") or "unknown" for n in path_nodes]
            time_ordered = result.get("time_ordered", True)
            hop_count = result.get("hop_count", max(1, len(path_nodes) - 1))
            sanctioned_name = result.get("sanctioned_name")

            # Avoid duplicate findings for same source and sanctioned entity
            if not any(f.get("sanctioned_entity") == sanctioned_name and f.get("source_account") == args.get("account_id") for f in dossier["findings"]):
                engine_ms = result.get("engine_ms")
                roundtrip_ms = result.get("roundtrip_ms", latency_ms)

                timing_note = "Strict chronological transfer sequence confirmed." if time_ordered else "Transfers out of sequence."
                reasoning = (
                    f"Direct {hop_count}-hop graph path connects {args.get('account_id')} to sanctioned entity "
                    f"'{sanctioned_name}'. {timing_note} First account identified as funds source (VICTIM flagged for review)."
                )

                finding = {
                    "type": "OFAC_SANCTIONS_EXPOSURE",
                    "severity": "CRITICAL",
                    "confidence": 0.95 if time_ordered else 0.85,
                    "source_account": args.get("account_id"),
                    "sanctioned_entity": sanctioned_name,
                    "hop_count": hop_count,
                    "path_trail": " -> ".join(hop_nodes),
                    "path_nodes": hop_nodes,
                    "engine_ms": engine_ms,
                    "roundtrip_ms": roundtrip_ms,
                    "latency_ms": roundtrip_ms,
                    "time_ordered": time_ordered,
                    "reasoning": reasoning,
                }
                dossier["findings"].append(finding)
                new_findings.append(finding)

                # Evaluate actions through policy
                eval_res = ThreatPolicy.evaluate_sanctions_path(path_nodes, hop_count, time_ordered=time_ordered)
                for act in eval_res.get("actions", []):
                    acc_id = act.get("account_id")
                    if act.get("action") == "FREEZE" and acc_id:
                        if getattr(self, "_auto_freeze", False):
                            if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                                freeze_res = self._execute_tool(
                                    "freeze_compromised_account",
                                    {"account_id": acc_id, "reason": act.get("reason")},
                                )
                                dossier["enforcement_actions"].append(freeze_res)
                        else:
                            if not any(a.get("account_id") == acc_id for a in dossier["proposed_actions"]):
                                prop = {
                                    "account_id": acc_id,
                                    "action": "FREEZE_ACCOUNT",
                                    "status": "PROPOSED",
                                    "reason": act.get("reason"),
                                    "confidence": act.get("confidence", 0.95),
                                }
                                dossier["proposed_actions"].append(prop)
                                new_actions.append(prop)
                    elif act.get("action") == "FLAG_VICTIM" and acc_id:
                        if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                            flag_act = {
                                "account_id": acc_id,
                                "action": "FLAG_VICTIM",
                                "status": "FLAGGED_FOR_REVIEW",
                                "reason": act.get("reason"),
                                "confidence": act.get("confidence", 0.90),
                            }
                            dossier["enforcement_actions"].append(flag_act)

        elif tool_name == "detect_circular_money_laundering" and isinstance(result, list):
            for cycle in result:
                members = cycle.get("ring_members", [])
                amounts = cycle.get("transferred_amounts", [])
                if members:
                    # canonical cycle path representation for deduplication
                    min_m = min(members)
                    min_idx = members.index(min_m)
                    rot_members = members[min_idx:] + members[:min_idx]
                    cycle_signature = "-".join(sorted(members))

                    if not any(f.get("type") == "CIRCULAR_STRUCTURING_RING" and f.get("cycle_signature") == cycle_signature for f in dossier["findings"]):
                        engine_ms = cycle.get("engine_ms")
                        roundtrip_ms = cycle.get("roundtrip_ms", latency_ms)
                        cycle_path = " -> ".join(rot_members) + f" -> {rot_members[0]}"

                        finding = {
                            "type": "CIRCULAR_STRUCTURING_RING",
                            "severity": "HIGH",
                            "confidence": 0.90,
                            "ring_members": rot_members,
                            "cycle_signature": cycle_signature,
                            "cycle_path": cycle_path,
                            "amounts": amounts,
                            "engine_ms": engine_ms,
                            "roundtrip_ms": roundtrip_ms,
                            "latency_ms": roundtrip_ms,
                            "reasoning": f"Identified circular structuring loop across {len(rot_members)} accounts cycling funds.",
                        }
                        dossier["findings"].append(finding)
                        new_findings.append(finding)

                        eval_res = ThreatPolicy.evaluate_circular_ring(rot_members, amounts)
                        for act in eval_res.get("actions", []):
                            acc_id = act.get("account_id")
                            if getattr(self, "_auto_freeze", False):
                                if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                                    freeze_res = self._execute_tool(
                                        "freeze_compromised_account",
                                        {"account_id": acc_id, "reason": act.get("reason")},
                                    )
                                    dossier["enforcement_actions"].append(freeze_res)
                            else:
                                if not any(a.get("account_id") == acc_id for a in dossier["proposed_actions"]):
                                    prop = {
                                        "account_id": acc_id,
                                        "action": "FREEZE_ACCOUNT",
                                        "status": "PROPOSED",
                                        "reason": act.get("reason"),
                                        "confidence": act.get("confidence", 0.90),
                                    }
                                    dossier["proposed_actions"].append(prop)
                                    new_actions.append(prop)

        elif tool_name == "detect_device_ip_collisions" and isinstance(result, list):
            for cluster in result:
                ctype = cluster.get("cluster_type", "DEVICE")
                ident = cluster.get("identifier", "unknown")
                members = cluster.get("members", [])
                if not members and "account_1" in cluster:
                    members = [cluster["account_1"]["id"], cluster["account_2"]["id"]]
                    ident = cluster.get("device_fingerprint", "unknown")

                if ident and members:
                    if not any(f.get("type") == "SYBIL_DEVICE_FINGERPRINT_COLLISION" and f.get("device_fingerprint") == ident for f in dossier["findings"]):
                        engine_ms = cluster.get("engine_ms")
                        roundtrip_ms = cluster.get("roundtrip_ms", latency_ms)

                        finding = {
                            "type": "SYBIL_DEVICE_FINGERPRINT_COLLISION",
                            "severity": "HIGH" if len(members) >= 3 else "MEDIUM",
                            "confidence": 0.85,
                            "device_fingerprint": ident,
                            "cluster_type": ctype,
                            "accounts_sharing": members,
                            "member_count": len(members),
                            "engine_ms": engine_ms,
                            "roundtrip_ms": roundtrip_ms,
                            "latency_ms": roundtrip_ms,
                            "reasoning": f"{len(members)} accounts share identical {ctype} identifier '{ident}'.",
                        }
                        dossier["findings"].append(finding)
                        new_findings.append(finding)

                        eval_res = ThreatPolicy.evaluate_sybil_cluster(ctype, ident, members)
                        for act in eval_res.get("actions", []):
                            acc_id = act.get("account_id")
                            if act.get("action") == "FREEZE":
                                if getattr(self, "_auto_freeze", False):
                                    if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                                        freeze_res = self._execute_tool(
                                            "freeze_compromised_account",
                                            {"account_id": acc_id, "reason": act.get("reason")},
                                        )
                                        dossier["enforcement_actions"].append(freeze_res)
                                else:
                                    if not any(a.get("account_id") == acc_id for a in dossier["proposed_actions"]):
                                        prop = {
                                            "account_id": acc_id,
                                            "action": "FREEZE_ACCOUNT",
                                            "status": "PROPOSED",
                                            "reason": act.get("reason"),
                                            "confidence": act.get("confidence", 0.85),
                                        }
                                        dossier["proposed_actions"].append(prop)
                                        new_actions.append(prop)
                            elif act.get("action") == "FLAG_REVIEW":
                                if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                                    dossier["enforcement_actions"].append({
                                        "account_id": acc_id,
                                        "action": "FLAG_REVIEW",
                                        "status": "FLAGGED_FOR_REVIEW",
                                        "reason": act.get("reason"),
                                    })

        elif tool_name == "propose_freeze" and isinstance(result, dict):
            acc_id = result.get("account_id")
            reason = result.get("reason", "Suspicious activity detected")
            evidence = result.get("evidence", "")
            if acc_id:
                if getattr(self, "_auto_freeze", False):
                    if not any(a.get("account_id") == acc_id for a in dossier["enforcement_actions"]):
                        freeze_res = self._execute_tool(
                            "freeze_compromised_account",
                            {"account_id": acc_id, "reason": reason},
                        )
                        dossier["enforcement_actions"].append(freeze_res)
                else:
                    if not any(a.get("account_id") == acc_id for a in dossier["proposed_actions"]):
                        prop = {
                            "account_id": acc_id,
                            "action": "FREEZE_ACCOUNT",
                            "status": "PROPOSED",
                            "reason": reason,
                            "evidence": evidence,
                            "confidence": 0.90,
                        }
                        dossier["proposed_actions"].append(prop)
                        new_actions.append(prop)

        elif tool_name == "freeze_compromised_account" and isinstance(result, dict):
            if result.get("success") and not any(a.get("account_id") == args.get("account_id") for a in dossier["enforcement_actions"]):
                dossier["enforcement_actions"].append(result)

        return new_findings, new_actions
