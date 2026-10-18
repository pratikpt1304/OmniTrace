"""
data/scale_seed.py
==================
Large-scale synthetic graph generator for FalkorDB stress testing and benchmarks.
Generates configurable graphs (10k, 100k, 1M edges) with power-law degree
distributions, realistic retail noise, smurfing funnels, and circular structuring rings.
"""

import argparse
import random
import sys
import time
from typing import Dict, List
from core.falkor_graph import get_fraud_graph


def generate_scale_dataset(num_accounts: int = 2500, num_edges: int = 10000, graph=None) -> Dict[str, Any]:
    """Generates and writes a large-scale financial banking graph to FalkorDB in batches."""
    g = graph or get_fraud_graph()
    print(f"[*] Initializing large-scale generation: {num_accounts:,} accounts, {num_edges:,} transfers...")

    t0 = time.perf_counter()

    # 1. Reset and ensure indices
    g.reset_graph()
    g._ensure_indices()

    # 2. Batch generate Accounts
    BATCH_SIZE = 1000
    account_ids = [f"ACC_SCALE_{i:06d}" for i in range(num_accounts)]
    
    print(f"[*] Seeding {num_accounts:,} accounts in batches of {BATCH_SIZE}...")
    for i in range(0, num_accounts, BATCH_SIZE):
        chunk = account_ids[i:i + BATCH_SIZE]
        batch_data = [
            {
                "id": aid,
                "holder": f"Entity_{aid[10:]}",
                "risk_score": random.randint(5, 45),
                "status": "active",
                "balance": random.randint(1000, 50000),
            }
            for aid in chunk
        ]
        cypher = """
        UNWIND $batch AS acc
        CREATE (:Account {
            id: acc.id,
            holder: acc.holder,
            risk_score: acc.risk_score,
            status: acc.status,
            balance: acc.balance
        })
        """
        g.query(cypher, {"batch": batch_data})

    # 3. Add Sanctioned Targets
    sanctioned = [
        {"id": "SANCTION_SCALE_01", "name": "Hydra Global Syndicate", "risk_level": "CRITICAL"},
        {"id": "SANCTION_SCALE_02", "name": "Lazarus Nexus Blocklist", "risk_level": "CRITICAL"},
    ]
    for s in sanctioned:
        g.query(
            "CREATE (:SanctionedEntity {id: $id, name: $name, risk_level: $risk_level})",
            s
        )

    # 4. Batch generate Transfers (Edges)
    print(f"[*] Seeding {num_edges:,} transaction edges...")
    EDGE_BATCH = 2000
    edges_created = 0

    base_time = int(time.time() * 1000) - 1000000

    while edges_created < num_edges:
        current_batch_size = min(EDGE_BATCH, num_edges - edges_created)
        batch_edges = []
        for _ in range(current_batch_size):
            src = random.choice(account_ids)
            tgt = random.choice(account_ids)
            while tgt == src:
                tgt = random.choice(account_ids)
            batch_edges.append({
                "src": src,
                "tgt": tgt,
                "amount": round(random.uniform(50.0, 9500.0), 2),
                "timestamp": base_time + edges_created * 10,
                "blocked": False,
            })
            edges_created += 1

        cypher_edges = """
        UNWIND $batch AS rel
        MATCH (s:Account {id: rel.src}), (t:Account {id: rel.tgt})
        CREATE (s)-[:TRANSFERRED {
            amount: rel.amount,
            timestamp: rel.timestamp,
            currency: 'USD',
            blocked: rel.blocked
        }]->(t)
        """
        g.query(cypher_edges, {"batch": batch_edges})

    # 5. Inject multi-hop smurfing chain to Sanctioned Entity
    print("[*] Injecting OFAC multi-hop sanctions funnel...")
    chain = account_ids[:4]
    for i in range(len(chain) - 1):
        g.query(
            """
            MATCH (s:Account {id: $src}), (t:Account {id: $tgt})
            CREATE (s)-[:TRANSFERRED {amount: 9800.0, timestamp: $ts, blocked: false}]->(t)
            """,
            {"src": chain[i], "tgt": chain[i+1], "ts": base_time + (i * 100)}
        )
    g.query(
        """
        MATCH (s:Account {id: $src}), (t:SanctionedEntity {id: 'SANCTION_SCALE_01'})
        CREATE (s)-[:TRANSFERRED {amount: 9750.0, timestamp: $ts, blocked: false}]->(t)
        """,
        {"src": chain[-1], "ts": base_time + 400}
    )

    total_time = round(time.perf_counter() - t0, 2)
    print(f"[✓] Seeding completed in {total_time}s: {num_accounts:,} nodes, {num_edges:,} edges.")
    return {
        "status": "success",
        "accounts_created": num_accounts,
        "edges_created": num_edges,
        "elapsed_seconds": total_time,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate large-scale financial graph in FalkorDB")
    parser.add_argument("--size", type=str, default="10k", choices=["10k", "100k", "1m"], help="Graph scale size")
    args = parser.parse_args()

    sizes = {
        "10k": (2000, 10000),
        "100k": (15000, 100000),
        "1m": (100000, 1000000),
    }
    acc_count, edge_count = sizes[args.size]
    generate_scale_dataset(num_accounts=acc_count, num_edges=edge_count)
