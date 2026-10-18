"""
data/fraud_generator.py
=======================
Generates a realistic financial transaction graph in FalkorDB.
Seeds:
  1. Background legitimate customer transactions.
  2. Multi-hop smurfing network ending at an OFAC Sanctioned Entity.
  3. Circular money laundering ring (A -> B -> C -> A).
  4. Sybil mule farm sharing device fingerprints and IP proxies.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from core.falkor_graph import get_fraud_graph, FalkorFraudGraph

logger = logging.getLogger("omnitrace.generator")


def seed_fraud_dataset(graph: FalkorFraudGraph = None) -> Dict[str, Any]:
    """Populate FalkorDB with synthetic financial network."""
    if graph is None:
        graph = get_fraud_graph()

    print("[OmniTrace] Resetting graph & seeding financial fraud scenario...")
    graph.reset_graph()

    # 1. Sanctioned Blacklisted Entities (OFAC Specially Designated Nationals)
    cypher_sanctions = """
    CREATE (s1:SanctionedEntity {
        id: 'SANCTION_HYDRA_EXCHANGE',
        name: 'Hydra Darknet Cashout Gateway',
        country: 'Offshore',
        risk_level: 'CRITICAL',
        sanction_list: 'OFAC-SDN-2026'
    })
    CREATE (s2:SanctionedEntity {
        id: 'SANCTION_KAVKAZ_LIMITED',
        name: 'Kavkaz Shadow Holdings Ltd',
        country: 'Cyprus',
        risk_level: 'HIGH',
        sanction_list: 'EU-SANCTION-LIST'
    })
    """
    graph.query(cypher_sanctions)

    # 2. Legitimate Customer Accounts
    cypher_legit = """
    CREATE (u1:Account {id: 'ACC_ALICE_101', holder: 'Alice Smith', balance: 14200, status: 'ACTIVE', risk_score: 5})
    CREATE (u2:Account {id: 'ACC_BOB_102', holder: 'Bob Johnson', balance: 8300, status: 'ACTIVE', risk_score: 8})
    CREATE (u3:Account {id: 'ACC_CHARLIE_103', holder: 'Charlie Davis', balance: 25000, status: 'ACTIVE', risk_score: 12})
    CREATE (u1)-[:TRANSFERRED {amount: 450, timestamp: timestamp()}]->(u2)
    CREATE (u2)-[:TRANSFERRED {amount: 1200, timestamp: timestamp()}]->(u3)
    """
    graph.query(cypher_legit)

    # 3. Threat Scenario A: 4-Hop Smurfing to Sanctioned Entity
    # ACC_VICTIM_01 -> ACC_MULE_ALPHA -> ACC_MULE_BETA -> ACC_PANAMA_SHELL -> SANCTION_HYDRA_EXCHANGE
    cypher_smurfing = """
    CREATE (v:Account {id: 'ACC_VICTIM_CORP', holder: 'Global Logistics Inc (Compromised)', balance: 890000, status: 'ACTIVE', risk_score: 40})
    CREATE (m1:Account {id: 'ACC_MULE_ALPHA', holder: 'Tariq Al-Mansoor', balance: 45000, status: 'ACTIVE', risk_score: 75})
    CREATE (m2:Account {id: 'ACC_MULE_BETA', holder: 'Viktor Kozlov', balance: 22000, status: 'ACTIVE', risk_score: 80})
    CREATE (shell:Account {id: 'ACC_PANAMA_SHELL', holder: 'Aegis Holding Corp Panama', balance: 150000, status: 'ACTIVE', risk_score: 88})

    CREATE (v)-[:TRANSFERRED {amount: 48000, timestamp: timestamp() - 3600000}]->(m1)
    CREATE (m1)-[:TRANSFERRED {amount: 24000, timestamp: timestamp() - 2400000}]->(m2)
    CREATE (m2)-[:TRANSFERRED {amount: 23500, timestamp: timestamp() - 1200000}]->(shell)
    WITH shell
    MATCH (s1:SanctionedEntity {id: 'SANCTION_HYDRA_EXCHANGE'})
    CREATE (shell)-[:TRANSFERRED {amount: 23000, timestamp: timestamp() - 300000}]->(s1)
    """
    graph.query(cypher_smurfing)

    # 4. Threat Scenario B: Circular Laundering Loop (Structuring)
    # RING_A -> RING_B -> RING_C -> RING_A
    cypher_ring = """
    CREATE (ra:Account {id: 'ACC_RING_A', holder: 'Apex Trading Corp', balance: 50000, status: 'ACTIVE', risk_score: 65})
    CREATE (rb:Account {id: 'ACC_RING_B', holder: 'Blue Horizon Consulting', balance: 49500, status: 'ACTIVE', risk_score: 65})
    CREATE (rc:Account {id: 'ACC_RING_C', holder: 'Crimson Import Export', balance: 49000, status: 'ACTIVE', risk_score: 65})

    CREATE (ra)-[:TRANSFERRED {amount: 50000, timestamp: timestamp()}]->(rb)
    CREATE (rb)-[:TRANSFERRED {amount: 49500, timestamp: timestamp()}]->(rc)
    CREATE (rc)-[:TRANSFERRED {amount: 49000, timestamp: timestamp()}]->(ra)
    """
    graph.query(cypher_ring)

    # 5. Threat Scenario C: Sybil Hardware & IP Proxy Mule Farm
    # Multiple accounts sharing the same hardware MAC & IP address
    cypher_devices = """
    CREATE (d1:Device {fingerprint: 'DEV_HWID_8849F0', os: 'Android 14 Rooted', model: 'Pixel 8 Pro'})
    CREATE (ip1:IPAddress {ip: '198.51.100.42', isp: 'Bulletproof VPN Hosting', country: 'Seychelles'})

    CREATE (sf1:Account {id: 'ACC_FARM_MULE_01', holder: 'John Doe 1', balance: 9500, status: 'ACTIVE', risk_score: 60})
    CREATE (sf2:Account {id: 'ACC_FARM_MULE_02', holder: 'John Doe 2', balance: 9800, status: 'ACTIVE', risk_score: 60})
    CREATE (sf3:Account {id: 'ACC_FARM_MULE_03', holder: 'John Doe 3', balance: 9200, status: 'ACTIVE', risk_score: 60})

    CREATE (sf1)-[:OPERATED_FROM]->(d1)
    CREATE (sf2)-[:OPERATED_FROM]->(d1)
    CREATE (sf3)-[:OPERATED_FROM]->(d1)

    CREATE (sf1)-[:CONNECTED_VIA]->(ip1)
    CREATE (sf2)-[:CONNECTED_VIA]->(ip1)
    CREATE (sf3)-[:CONNECTED_VIA]->(ip1)
    """
    graph.query(cypher_devices)

    # 6. Realism & Decoys: Legitimate Corporate Cycle & Shared Family/Office Tablet
    # Decoy 1: Legitimate vendor escrow cycle (low risk, legitimate merchants)
    cypher_decoys = """
    CREATE (v1:Account {id: 'ACC_MERCHANT_CORP', holder: 'Retail Group LLC', balance: 120000, status: 'ACTIVE', risk_score: 5})
    CREATE (v2:Account {id: 'ACC_SUPPLIER_GMBH', holder: 'Precision Parts GmbH', balance: 85000, status: 'ACTIVE', risk_score: 5})
    CREATE (v3:Account {id: 'ACC_ESCROW_SERVICES', holder: 'Global Escrow Trust', balance: 450000, status: 'ACTIVE', risk_score: 2})
    CREATE (v1)-[:TRANSFERRED {amount: 15000, timestamp: timestamp() - 86400000}]->(v2)
    CREATE (v2)-[:TRANSFERRED {amount: 14800, timestamp: timestamp() - 86000000}]->(v3)
    CREATE (v3)-[:TRANSFERRED {amount: 14500, timestamp: timestamp() - 85000000}]->(v1)

    // Decoy 2: Legitimate retail store kiosk / branch tablet (2 verified accounts, low risk)
    CREATE (d_kiosk:Device {fingerprint: 'DEV_KIOSK_BRANCH_07', os: 'iOS 17.5', model: 'iPad Air Kiosk'})
    CREATE (k1:Account {id: 'ACC_RETAIL_CUST_A', holder: 'Emma Wilson', balance: 4200, status: 'ACTIVE', risk_score: 5})
    CREATE (k2:Account {id: 'ACC_RETAIL_CUST_B', holder: 'Liam Martinez', balance: 3100, status: 'ACTIVE', risk_score: 8})
    CREATE (k1)-[:OPERATED_FROM]->(d_kiosk)
    CREATE (k2)-[:OPERATED_FROM]->(d_kiosk)
    """
    graph.query(cypher_decoys)

    # 7. Background Noise Generator: 60 Realistic Banking Accounts & Scatter Transfers
    cypher_noise = """
    UNWIND range(1, 60) AS i
    CREATE (a:Account {
        id: 'ACC_RETAIL_' + i,
        holder: 'Retail Customer ' + i,
        balance: 1000 + (i * 230),
        status: 'ACTIVE',
        risk_score: toInteger(rand() * 25)
    })
    """
    graph.query(cypher_noise)

    cypher_noise_edges = """
    MATCH (a:Account)
    WHERE a.id STARTS WITH 'ACC_RETAIL_' AND toInteger(split(a.id, '_')[2]) < 55
    WITH a, toInteger(split(a.id, '_')[2]) AS i
    MATCH (b:Account {id: 'ACC_RETAIL_' + (i + 1)})
    CREATE (a)-[:TRANSFERRED {
        amount: toInteger(50 + rand() * 950),
        timestamp: timestamp() - toInteger(rand() * 10000000)
    }]->(b)
    """
    graph.query(cypher_noise_edges)

    print("[OmniTrace] Synthetic financial dataset successfully loaded into FalkorDB!")
    return {
        "status": "success",
        "scenarios_seeded": [
            "OFAC Sanctions Multi-Hop Trail (4 hops)",
            "Circular Structuring Loop (3 nodes)",
            "Sybil Hardware Fingerprint Farm (3 mules, 1 device, 1 VPN IP)",
            "Decoy: Legitimate Corporate Settlement Cycle (3 nodes)",
            "Decoy: Legitimate Branch Kiosk Tablet (2 accounts)",
            "60 Background Retail Accounts with Random Inter-Account Transfers",
        ]
    }


if __name__ == "__main__":
    seed_fraud_dataset()
