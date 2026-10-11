"""
run_system.py

Main interactive CLI and live presentation demonstration script for:
Multi-Agent AI-Based Cybersecurity Threat Detection and Response System

Demonstrates:
  1. Complete 4-Agent Pipeline:
     - Agent 1: Network Intrusion Detection (DETECT)
     - Agent 2: Threat & Security Analysis (ANALYZE)
     - Agent 3: Threat Intelligence & MITRE ATT&CK / CISA KEV (ENRICH)
     - Agent 4: Risk Assessment & Response Planning (ASSESS + PLAN)
  2. Smart Routing: High-confidence benign traffic pruned at Agent 1, saving 3 agent calls.
  3. Dynamic Multi-Agent Dynamics: Backward clarification between Agent 4 and Agent 2.
  4. Real Knowledge Representation: STIX 2.0 graph traversal and CISA KEV lookup.
  5. Search Algorithms: Keyword + Semantic + BFS (Agent 3) and A* Search (Agent 4).
  6. Auditability: Full timestamped communication trace for every incident.
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, Any, List

# Ensure current directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Force UTF-8 stdout encoding for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from agents.intrusion_detection_agent import IntrusionDetectionAgent
from agents.threat_response_agent import ThreatResponseAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.risk_response_agent import RiskResponseAgent
from orchestration.orchestrator import MultiAgentOrchestrator
from evaluation.metrics import format_search_comparison_table
from search.response_graph import ResponseGraph
from search.bfs import breadth_first_search
from search.astar import astar_search


DEMO_INCIDENTS = [
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
        "title": "Weaponized Volumetric DoS Exploit (CISA KEV CVE-2026-88779)",
        "target_asset": "DMZ_WEB_SERVER",
        "features": {
            "network_packet_size": 850,
            "protocol_type": "UDP",
            "login_attempts": 4,
            "session_duration": 601.2,
            "ip_reputation_score": 0.120,
            "failed_logins": 0,
            "browser_type": "Unknown",
            "unusual_time_access": 0,
            "encryption_used": "DES",
            "cve": "CVE-2026-88779"
        }
    },
    {
        "id": "SCENARIO-3",
        "title": "Legitimate Authenticated User Session (Smart Routing Early Exit)",
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
    },
    {
        "id": "SCENARIO-4",
        "title": "Anomalous Intrusion with Missing Asset Context (Backward Clarification)",
        "target_asset": "UNKNOWN",
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
    }
]


def run_orchestrated_scenario(orchestrator: MultiAgentOrchestrator, scenario: Dict[str, Any]):
    print("\n" + "=" * 80)
    print(f" INCIDENT DEMO: {scenario['title']}")
    print(f" Target Asset: {scenario['target_asset']} | Incident ID: {scenario['id']}")
    print("=" * 80)

    features = scenario["features"]
    print("\n[STEP 1: SENSOR PERCEPTION] Ingesting Network Telemetry:")
    print(f"  * Payload Size: {features['network_packet_size']} bytes | Protocol: {features['protocol_type']}")
    print(f"  * Authentication Velocity: {features['failed_logins']} failed of {features['login_attempts']} trials")
    print(f"  * Session Duration: {features['session_duration']}s | IP Reputation Score: {features['ip_reputation_score']}")
    if features.get("cve"):
        print(f"  * Embedded Exploit Signature: {features['cve']}")

    # Execute orchestrator
    state = orchestrator.run_investigation(
        event_id=scenario["id"],
        raw_event=features,
        target_asset=scenario["target_asset"]
    )

    # Display Agent 1 Findings
    a1_res = state.agent_results.get("agent_1", {})
    print("\n[AGENT 1: INTRUSION DETECTION - DETECT]")
    print(f"  * Classification: [{a1_res.get('prediction', 'UNKNOWN')}] (Confidence: {state.confidence.get('agent_1', 0)*100:.1f}%)")
    print(f"  * Inferred Threat Type: {a1_res.get('attack_type', 'None')}")
    for ev in a1_res.get("evidence", []):
        print(f"    - {ev}")

    # Check Smart Routing Early Termination
    if state.status == "CLOSED_BENIGN":
        print("\n>>> SMART ROUTING ACTIVATED: High-confidence Benign Traffic Confirmed! <<<")
        print(f"  * Downstream investigations pruned: Agents 2, 3, and 4 NOT invoked.")
        print(f"  * Unnecessary Agent Invocations Avoided: {state.unnecessary_calls_avoided}")
        print(f"  * Final Incident Status: {state.status}")
        print("-" * 80)
        return

    # Display Agent 2 Findings
    a2_res = state.agent_results.get("agent_2", {})
    print("\n[AGENT 2: THREAT & SECURITY ANALYSIS - ANALYZE]")
    print(f"  * Category: {a2_res.get('threat_category')} | Impacted CIA Property: {a2_res.get('impacted_property')}")
    print(f"  * Evaluated Severity: {a2_res.get('severity')} (Base: {a2_res.get('base_severity')}/10)")
    print(f"  * Indicators Extracted: {len(a2_res.get('indicators', []))}")
    for ind in a2_res.get("indicators", [])[:3]:
        print(f"    - {ind}")

    # Display Agent 3 Findings
    a3_res = state.agent_results.get("agent_3", {})
    print("\n[AGENT 3: THREAT INTELLIGENCE ENGINE - ENRICH]")
    print(f"  * Primary ATT&CK Technique: {a3_res.get('primary_technique_id')} (Confidence: {state.confidence.get('agent_3', 0)*100:.1f}%)")
    tactics = [t.get("name") for t in a3_res.get("tactics", [])]
    if tactics:
        print(f"  * Kill-Chain Tactics: {', '.join(tactics[:2])}")
    vuln = a3_res.get("vulnerability_intel", {})
    if vuln.get("is_known_exploited"):
        print(f"  * CISA KEV Status: [CRITICAL EXPLOITED] {vuln.get('cve_id')} ({vuln.get('product')})")
        print(f"    Mandated Remediation: {vuln.get('required_action', '')[:100]}...")
    groups = [g.get("name") for g in a3_res.get("related_groups", [])]
    if groups:
        print(f"  * Known Threat Groups (BFS depth=2): {', '.join(groups[:3])}")
    print(f"  * Search Algorithms Applied: {', '.join(a3_res.get('search_methods_used', []))}")

    # Display Agent 4 Findings
    a4_res = state.agent_results.get("agent_4", {})
    decision = state.decisions[0] if state.decisions else {}
    print("\n[AGENT 4: RISK ASSESSMENT & RESPONSE PLANNING - ASSESS + PLAN]")
    print(f"  * Deterministic Composite Risk Score: {decision.get('risk_score')}/100 ({decision.get('risk_level')} Priority)")
    factors = a4_res.get("risk_factors", {})
    print(f"    [Severity: {factors.get('threat_severity')} | Exploitability: {factors.get('exploitability')} | Asset: {factors.get('asset_criticality')} | Impact: {factors.get('impact')}]")
    print(f"  * A* Optimal Mitigation Path: {' -> '.join(a4_res.get('astar_metrics', {}).get('path', []))}")
    print(f"  * Path Cost: {a4_res.get('astar_metrics', {}).get('total_cost')} | Dispatched Action: >>> {decision.get('primary_mitigation')} <<<")
    print(f"  * Defense Phasing:")
    for phase in decision.get("response_sequence", [])[:3]:
        print(f"    - [{phase.get('phase')}]: {phase.get('action')} - {phase.get('description')}")

    # Display Communication Trace
    print("\n[MULTI-AGENT DYNAMIC COMMUNICATION TRACE]")
    for idx, msg_rec in enumerate(state.communication_history, 1):
        print(f"  {idx}. {msg_rec['sender']:7s} -> {msg_rec['receiver']:12s} [{msg_rec['message_type']:22s}] Priority: {msg_rec['priority']}")

    print(f"\nFinal Incident State: {state.status} | Total Agent Interactions: {len(state.communication_history)}")
    print("-" * 80)


def run_benchmark(iterations: int = 1000):
    print("\n" + "=" * 80)
    print(f" BENCHMARK EVALUATION: BFS vs A* Search (N={iterations} Iterations)")
    print("=" * 80)
    graph = ResponseGraph(threat_type="Network Attack", severity="HIGH", target_criticality=1.0)
    
    t0 = time.perf_counter()
    for _ in range(iterations):
        bfs_res = breadth_first_search(graph)
    t_bfs = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    for _ in range(iterations):
        astar_res = astar_search(graph)
    t_astar = (time.perf_counter() - t0) * 1000.0

    print(f"BFS Total Runtime : {t_bfs:.2f} ms (Avg: {t_bfs/iterations:.4f} ms/query)")
    print(f"A* Total Runtime  : {t_astar:.2f} ms (Avg: {t_astar/iterations:.4f} ms/query)")
    print(f"BFS Path Cost     : {bfs_res.total_cost} (Blind hop-count minimization)")
    print(f"A* Path Cost      : {astar_res.total_cost} (Cost-optimal admissible f = g + h)")
    print(f"A* Cost Reduction : {((bfs_res.total_cost - astar_res.total_cost)/bfs_res.total_cost)*100:.1f}%\n")
    print(format_search_comparison_table(bfs_res, astar_res))


def main():
    parser = argparse.ArgumentParser(description="Multi-Agent AI Cybersecurity Threat Detection & Response")
    parser.add_argument("--demo", action="store_true", help="Run 4-agent demonstration across realistic incidents")
    parser.add_argument("--benchmark", action="store_true", help="Run 1000-iteration BFS vs A* algorithmic search benchmark")
    args = parser.parse_args()

    print("================================================================================")
    print(" MULTI-AGENT AI-BASED CYBERSECURITY THREAT DETECTION AND RESPONSE SYSTEM")
    print(" Course: 23CSE401 - Foundations of AI | Full 4-Agent Operational Architecture")
    print("================================================================================")

    if args.benchmark:
        run_benchmark(iterations=1000)
    else:
        orchestrator = MultiAgentOrchestrator(benign_confidence_threshold=0.80)
        for sc in DEMO_INCIDENTS:
            run_orchestrated_scenario(orchestrator, sc)


if __name__ == "__main__":
    main()
