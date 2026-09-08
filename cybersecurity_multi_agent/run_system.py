"""
run_system.py

Main interactive CLI and live presentation demonstration script for:
Multi-Agent AI-Based Cybersecurity Threat Detection and Response System

Designed to fulfill Review 1 presentation mechanics (10/10 marks):
- Step-by-step collaborative agent execution trace
- Agent 1 ML prediction, confidence, and explainability
- Inter-agent message transmission (loose coupling via JSON)
- Agent 2 knowledge reasoning & dynamic risk scoring
- Genuine side-by-side BFS vs A* algorithmic comparison
- Final optimal mitigation selection
"""

import os
import sys
import json
import time
import argparse
import pandas as pd

# Ensure current directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.intrusion_detection_agent import IntrusionDetectionAgent
from agents.threat_response_agent import ThreatResponseAgent
from evaluation.metrics import format_search_comparison_table, get_academic_accuracy_critique
from search.response_graph import ResponseGraph
from search.bfs import breadth_first_search
from search.astar import astar_search


DEMO_SCENARIOS = [
    {
        "id": "SCENARIO-1",
        "title": "Credential Brute Force Intrusion against Core Database",
        "target_asset": "CORE_DATABASE",
        "features": {
            "network_packet_size": 297,
            "protocol_type": "TCP",
            "login_attempts": 8,
            "session_duration": 1421.4,
            "ip_reputation_score": 0.345,
            "failed_logins": 3,
            "browser_type": "Firefox",
            "unusual_time_access": 1,
            "encryption_used": "AES"
        }
    },
    {
        "id": "SCENARIO-2",
        "title": "Volumetric Denial of Service (DoS) Flood against DMZ Web Server",
        "target_asset": "DMZ_WEB_SERVER",
        "features": {
            "network_packet_size": 804,
            "protocol_type": "UDP",
            "login_attempts": 4,
            "session_duration": 601.2,
            "ip_reputation_score": 0.123,
            "failed_logins": 0,
            "browser_type": "Unknown",
            "unusual_time_access": 0,
            "encryption_used": "DES"
        }
    },
    {
        "id": "SCENARIO-3",
        "title": "Legitimate Authenticated User Session on Workstation",
        "target_asset": "LOW_VALUE_WORKSTATION",
        "features": {
            "network_packet_size": 472,
            "protocol_type": "TCP",
            "login_attempts": 3,
            "session_duration": 1557.9,
            "ip_reputation_score": 0.301,
            "failed_logins": 0,
            "browser_type": "Firefox",
            "unusual_time_access": 0,
            "encryption_used": "DES"
        }
    }
]


def run_pipeline(agent1: IntrusionDetectionAgent, agent2: ThreatResponseAgent, scenario: dict):
    print("\n" + "=" * 76)
    print(f" SCENARIO: {scenario['title']}")
    print(f" Target Asset: {scenario['target_asset']} | Event ID: {scenario['id']}")
    print("=" * 76)

    # 1. Input telemetry
    print("\n[STEP 1: PERCEPTION LAYER] Ingesting Network Sensor Telemetry...")
    features = scenario["features"]
    print(f"  * Packet Payload Size : {features['network_packet_size']} bytes")
    print(f"  * Transport Protocol  : {features['protocol_type']}")
    print(f"  * Login Velocity      : {features['failed_logins']} failed of {features['login_attempts']} attempts")
    print(f"  * Session Duration    : {features['session_duration']} seconds")
    print(f"  * IP Reputation Score : {features['ip_reputation_score']:.3f} (0=Malicious, 1=Reputable)")
    print(f"  * Encryption Cipher   : {features['encryption_used']}")

    time.sleep(0.3)

    # 2. Agent 1 execution
    print("\n[STEP 2: AGENT 1 - INTRUSION DETECTION] Supervised Pattern Classification...")
    msg1 = agent1.process_event(scenario["id"], features)
    status_tag = "[MALICIOUS]" if msg1.prediction == "ATTACK" else "[BENIGN]"
    print(f"  > Agent 1 Decision    : {status_tag} {msg1.prediction}")
    print(f"  > Classifier Confidence: {msg1.confidence * 100:.2f}%")
    print(f"  > Inferred Threat Type : {msg1.attack_type}")
    print("  > Forensic Evidence:")
    for ev in msg1.evidence:
        print(f"     - {ev}")

    time.sleep(0.3)

    # 3. Inter-agent communication handover
    print("\n[STEP 3: INTER-AGENT COMMUNICATION] Emitting Structured JSON Payload...")
    json_wire = msg1.to_json()
    print("  --- BEGIN JSON WIRE PAYLOAD ---")
    for line in json_wire.splitlines()[:10]:
        print(f"  {line}")
    if len(json_wire.splitlines()) > 10:
        print("  ... [Payload truncated for console view] ...")
    print("  --- END JSON WIRE PAYLOAD ---")

    time.sleep(0.3)

    # 4. Agent 2 execution
    print("\n[STEP 4: AGENT 2 - THREAT REASONING & RISK SCORING] Consulting Knowledge Base...")
    response2 = agent2.process_threat(json_wire, target_asset=scenario["target_asset"])
    print(f"  > Threat Category     : {response2.threat_category}")
    print(f"  > Impacted CIA Property: {response2.impacted_property}")
    print(f"  > Evaluated Severity  : {response2.severity}")
    print(f"  > Composite Risk Score: {response2.risk_score} / 100.0")

    time.sleep(0.3)

    # 5. Algorithmic Modeling & Search
    if msg1.prediction == "ATTACK":
        print("\n[STEP 5: ALGORITHMIC SEARCH COMPARISON] Response Graph Optimization...")
        analysis = agent2.analyze_threat(msg1, target_asset=scenario["target_asset"])
        graph = agent2.build_state_space(analysis)
        bfs_res = agent2.plan_response_bfs(graph)
        astar_res = agent2.plan_response_astar(graph)

        print(format_search_comparison_table(bfs_res, astar_res))

        print("\n  > BFS Explored Path  : " + " -> ".join(bfs_res.path))
        print(f"    Total Cost: {bfs_res.total_cost} | Nodes: {bfs_res.nodes_explored} | Strategy: Shallowest path (unit cost)")
        print("\n  > A* Explored Path   : " + " -> ".join(astar_res.path))
        print(f"    Total Cost: {astar_res.total_cost} | Nodes: {astar_res.nodes_explored} | Strategy: Cost-optimal f(n) = g(n) + h(n)")

    # 6. Final Decision
    print("\n" + "-" * 76)
    print(" [FINAL MULTI-AGENT COLLABORATIVE RESPONSE]")
    print("-" * 76)
    print(f"  Dispatched Action  : >>> {response2.selected_response} <<<")
    print(f"  Applied Algorithm  : {response2.selected_algorithm}")
    print(f"  Total Path Cost    : {response2.total_path_cost}")
    print(f"  Technical Reason   : {response2.reason}")
    print("-" * 76)


def run_benchmark(agent2: ThreatResponseAgent, iterations: int = 1000):
    print("\n" + "=" * 76)
    print(f" BENCHMARK EVALUATION: BFS vs A* (N={iterations} Iterations)")
    print("=" * 76)

    graph = ResponseGraph(threat_type="Network Attack", severity="HIGH", target_criticality=1.0)
    
    # BFS
    t0 = time.perf_counter()
    for _ in range(iterations):
        bfs_res = breadth_first_search(graph)
    t_bfs = (time.perf_counter() - t0) * 1000.0

    # A*
    t0 = time.perf_counter()
    for _ in range(iterations):
        astar_res = astar_search(graph)
    t_astar = (time.perf_counter() - t0) * 1000.0

    print(f"BFS Total Time ({iterations} runs) : {t_bfs:.2f} ms (Avg: {t_bfs/iterations:.4f} ms/query)")
    print(f"A* Total Time ({iterations} runs)  : {t_astar:.2f} ms (Avg: {t_astar/iterations:.4f} ms/query)")
    print(f"BFS Optimal Cost Found : {bfs_res.total_cost}")
    print(f"A* Optimal Cost Found  : {astar_res.total_cost} (Provably optimal)")
    print(f"Cost Savings using A*  : {((bfs_res.total_cost - astar_res.total_cost)/bfs_res.total_cost)*100:.1f}%\n")
    print(format_search_comparison_table(bfs_res, astar_res))


def main():
    parser = argparse.ArgumentParser(description="Multi-Agent AI Cybersecurity Threat Detection & Response")
    parser.add_argument("--demo", action="store_true", help="Run full 3-scenario presentation demonstration")
    parser.add_argument("--benchmark", action="store_true", help="Run 1000-iteration BFS vs A* search benchmark")
    args = parser.parse_args()

    print("============================================================================")
    print(" MULTI-AGENT AI-BASED CYBERSECURITY THREAT DETECTION AND RESPONSE SYSTEM")
    print(" Course: 23CSE401 - Foundations of AI | Review 1 Evaluation System")
    print("============================================================================")

    agent1 = IntrusionDetectionAgent()
    agent2 = ThreatResponseAgent()

    if args.benchmark:
        run_benchmark(agent2, iterations=1000)
    else:
        for sc in DEMO_SCENARIOS:
            run_pipeline(agent1, agent2, sc)
            print("\n")


if __name__ == "__main__":
    main()
