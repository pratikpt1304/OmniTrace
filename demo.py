"""
demo.py
=======
OmniTrace Standalone CLI Demonstration.
Showcases Autonomous Multi-Hop Graph Reasoning & Fraud Enforcement on FalkorDB.
Track 01: Agents That Act on Connected Data.

Usage:
    python demo.py
"""

import sys
import time
from core.falkor_graph import get_fraud_graph
from data.fraud_generator import seed_fraud_dataset
from agent.investigator import OmniTraceInvestigator


def main():
    print("=" * 74)
    print("  OMNITRACE: AUTONOMOUS MULTI-HOP GRAPH FRAUD INVESTIGATOR")
    print("  FalkorDB Graph Hacks (Track 01: Agents That Act on Connected Data)")
    print("=" * 74)

    # 1. Connect
    print("\n[1/5] Connecting to FalkorDB Cloud Instance...")
    graph = get_fraud_graph()
    print(f"      Connected to graph '{graph.graph_name}' on {graph.host}:{graph.port}")

    # 2. Seed Data
    print("\n[2/5] Seeding Synthetic Financial Banking & Threat Graph...")
    seed_res = seed_fraud_dataset(graph=graph)
    for s in seed_res["scenarios_seeded"]:
        print(f"       + Ingested: {s}")

    # 3. Autonomous Agent Launch
    print("\n[3/5] Launching OmniTrace Autonomous Investigator Agent...")
    investigator = OmniTraceInvestigator(agent_id="omni_sentinel_01")
    t0 = time.perf_counter()
    dossier = investigator.run_full_investigation()
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    print(f"      Investigation complete in {elapsed}ms! Processed {len(dossier['findings'])} threats.")

    # 4. Display Findings
    print("\n[4/5] Multi-Hop Threat Analysis Findings:")
    for idx, f in enumerate(dossier["findings"], 1):
        print(f"\n      --- Threat #{idx}: [{f['severity']}] {f['type']} ---")
        print(f"      Explanation: {f['reasoning']}")
        if "path_trail" in f:
            print(f"      Multi-Hop Trail ({f['hop_count']} hops):")
            print(f"       -> {f['path_trail']}")
            print(f"      FalkorDB Traversal Latency: {f.get('latency_ms', 1.0)}ms")
        if "cycle_path" in f:
            print(f"      Circular Laundering Loop:")
            print(f"       -> {f['cycle_path']}")
        if "device_fingerprint" in f:
            print(f"      Shared Hardware Fingerprint Collision: {f['device_fingerprint']}")
            print(f"      Colliding Accounts: {f['accounts_sharing']}")

    # 5. Automated Graph Interventions / Actions
    print("\n[5/5] Automated Graph Enforcement Actions Taken by Agent:")
    for act in dossier["enforcement_actions"]:
        print(f"      [ACTION EXECUTED] Frozen Account: {act['account_id']}")
        print(f"                        Reason: {act['reason'][:75]}...")

    # Summary
    print("\n" + "=" * 74)
    print("  [SUCCESS] All multi-hop threats detected and neutralized on FalkorDB!")
    print(f"  Total Nodes in Graph: {dossier['graph_metrics']['total_nodes_audited']}")
    print(f"  Total Edges in Graph: {dossier['graph_metrics']['total_edges_traversed']}")
    print("  Run 'python server.py' to explore the Visual Threat Radar at http://localhost:8765")
    print("=" * 74)


if __name__ == "__main__":
    main()
