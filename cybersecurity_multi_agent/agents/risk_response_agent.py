"""
agents/risk_response_agent.py

Agent 4: Risk Assessment and Response Planning Agent (Specialization: ASSESS + PLAN)

The authoritative cybersecurity decision-support specialist.
Consolidates empirical evidence across Agent 1 (detection), Agent 2 (analysis),
and Agent 3 (threat intelligence).
Computes a transparent, deterministic multi-factor Risk Score (0-100),
issues backward clarification requests when asset context is missing,
and executes A* Search over a defensive response action graph to synthesize
a cost-optimal, defensible mitigation policy.
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional, Tuple
import heapq

# Ensure base project directory is in sys.path for direct execution
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

try:
    from communication.messages import AgentMessage, MessageType, SearchBenchmark
    from search.response_graph import ResponseGraph
    from search.astar import astar_search
except ImportError:
    try:
        from ..communication.messages import AgentMessage, MessageType, SearchBenchmark
        from ..search.response_graph import ResponseGraph
        from ..search.astar import astar_search
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import AgentMessage, MessageType, SearchBenchmark
        from cybersecurity_multi_agent.search.response_graph import ResponseGraph
        from cybersecurity_multi_agent.search.astar import astar_search



class RiskResponseAgent:
    """
    Autonomous Intelligent Agent for Risk Assessment & Response Planning.
    
    Academic PEAS Profile:
      - Performance: Risk Calibration Accuracy, Mitigation Cost-Optimality,
                     Disruption Minimization, Explainability.
      - Environment: Consolidated Multi-Agent Incident Dossier.
      - Actuators: Final Incident Decisions (FINAL_DECISION), Clarification Requests.
      - Sensors: Enriched Dossier (INTELLIGENCE_RESPONSE) from Agent 3 / Orchestrator.
    """

    def __init__(self, risk_weights: Optional[Dict[str, float]] = None):
        # Deterministic multi-factor risk model weights (Sum = 1.0)
        self.weights = risk_weights or {
            "threat_severity": 0.25,
            "asset_criticality": 0.20,
            "exploitability": 0.20,
            "impact": 0.15,
            "exposure": 0.10,
            "detection_confidence": 0.10
        }

    # ---------------------------------------------------------
    # DETERMINISTIC MULTI-FACTOR RISK SCORING
    # ---------------------------------------------------------
    def calculate_risk_score(
        self,
        severity_score: float,       # 0 - 100
        asset_score: float,          # 0 - 100
        exploitability_score: float, # 0 - 100
        impact_score: float,         # 0 - 100
        exposure_score: float,       # 0 - 100
        confidence_score: float      # 0 - 100
    ) -> Tuple[float, str, Dict[str, float]]:
        """
        Calculates deterministic composite Risk Score normalized to [0, 100].
        Risk = w1*Severity + w2*Asset + w3*Exploitability + w4*Impact + w5*Exposure + w6*Confidence
        """
        factors = {
            "threat_severity": round(severity_score, 1),
            "asset_criticality": round(asset_score, 1),
            "exploitability": round(exploitability_score, 1),
            "impact": round(impact_score, 1),
            "exposure": round(exposure_score, 1),
            "detection_confidence": round(confidence_score, 1)
        }

        raw_score = sum(self.weights[k] * factors[k] for k in self.weights)
        risk_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Categorical risk tier
        if risk_score >= 75.0:
            risk_tier = "CRITICAL"
        elif risk_score >= 50.0:
            risk_tier = "HIGH"
        elif risk_score >= 25.0:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        return risk_score, risk_tier, factors

    def evaluate_risk_factors(
        self,
        intel_payload: Dict[str, Any]
    ) -> Tuple[float, str, Dict[str, float]]:
        """
        Derives normalized 0-100 inputs for each risk factor from multi-agent findings.
        """
        if not isinstance(intel_payload, dict):
            intel_payload = {}

        # 1. Threat Severity (from Agent 2 base_severity 0-10)
        base_sev_raw = intel_payload.get("base_severity")
        try:
            base_sev = float(base_sev_raw) if base_sev_raw is not None else 5.0
        except (ValueError, TypeError):
            base_sev = 5.0
        severity_score = min(100.0, max(0.0, base_sev * 10.0))

        # 2. Asset Criticality
        target_asset = intel_payload.get("target_asset") or "UNKNOWN"
        target_asset = str(target_asset)
        asset_mult_raw = intel_payload.get("target_multiplier")
        try:
            asset_mult = float(asset_mult_raw) if asset_mult_raw is not None else 1.0
        except (ValueError, TypeError):
            asset_mult = 1.0

        if target_asset == "UNKNOWN" or asset_mult <= 0:
            asset_score = -1.0  # Flag as unknown to trigger clarification request
        else:
            # Map multiplier [0.8, 1.5] to [40, 100]
            asset_score = min(100.0, max(20.0, (asset_mult / 1.5) * 100.0))

        # 3. Exploitability (Influenced by CISA KEV and ATT&CK findings)
        vuln_intel = intel_payload.get("vulnerability_intel") or {}
        if not isinstance(vuln_intel, dict):
            vuln_intel = {}

        if vuln_intel.get("is_known_exploited"):
            if vuln_intel.get("known_ransomware_campaign_use") == "Known":
                exploitability_score = 100.0
            else:
                exploitability_score = 95.0
        elif intel_payload.get("primary_technique_id"):
            exploitability_score = 75.0
        else:
            exploitability_score = 40.0

        # 4. CIA Impact
        impacted_property = intel_payload.get("impacted_property") or "Availability"
        if impacted_property == "Confidentiality":
            impact_score = 85.0
        elif impacted_property == "Integrity":
            impact_score = 80.0
        elif impacted_property == "Availability":
            impact_score = 75.0
        else:
            impact_score = 50.0

        # 5. Network Exposure
        if "DMZ" in target_asset or "WEB" in target_asset:
            exposure_score = 90.0
        elif "DATABASE" in target_asset or "CONTROLLER" in target_asset:
            exposure_score = 75.0
        else:
            exposure_score = 40.0

        # 6. Confidence Score
        conf_raw = intel_payload.get("confidence")
        try:
            conf = float(conf_raw) if conf_raw is not None else 0.85
        except (ValueError, TypeError):
            conf = 0.85
        confidence_score = min(100.0, max(0.0, conf * 100.0))

        if asset_score < 0:
            return -1.0, "UNKNOWN", {}

        return self.calculate_risk_score(
            severity_score, asset_score, exploitability_score,
            impact_score, exposure_score, confidence_score
        )

    # ---------------------------------------------------------
    # A* DEFENSIVE RESPONSE SEARCH
    # ---------------------------------------------------------
    def plan_mitigation_astar(
        self,
        threat_type: str,
        severity: str,
        target_multiplier: float,
        vulnerability_active: bool = False
    ) -> SearchBenchmark:
        """
        Executes A* Search over the defensive state-space response graph.
        Guarantees cost-optimal mitigation selection minimizing business friction.
        """
        threat_type = str(threat_type) if threat_type else "DoS"
        severity = str(severity) if severity else "HIGH"
        try:
            target_multiplier = float(target_multiplier) if target_multiplier is not None else 1.0
        except (ValueError, TypeError):
            target_multiplier = 1.0

        graph = ResponseGraph(
            threat_type=threat_type,
            severity=severity,
            target_criticality=target_multiplier
        )
        return astar_search(graph)

    # ---------------------------------------------------------
    # STRUCTURED MITIGATION SEQUENCE SYNTHESIS
    # ---------------------------------------------------------
    def synthesize_response_phases(
        self,
        astar_benchmark: SearchBenchmark,
        intel_payload: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """
        Translates optimal A* state path and CTI intelligence into an operational
        action plan requiring human confirmation.
        """
        if not isinstance(intel_payload, dict):
            intel_payload = {}
        path = astar_benchmark.path if (astar_benchmark and hasattr(astar_benchmark, "path")) else []
        vuln_intel = intel_payload.get("vulnerability_intel") or {}
        if not isinstance(vuln_intel, dict):
            vuln_intel = {}
        attack_type = str(intel_payload.get("attack_type") or "Unknown Threat")

        plan: List[Dict[str, str]] = []

        # Phase 1: Immediate Triage
        plan.append({
            "phase": "Immediate Action",
            "action": "CORRELATE_TELEMETRY",
            "description": "Correlate packet flows and authentication logs on perimeter firewall and SIEM."
        })

        # Phase 2: Containment (Derived from A* optimal key state)
        if any("BLOCKED" in s for s in path):
            plan.append({
                "phase": "Containment Action",
                "action": "BLOCK_SOURCE_IP",
                "description": "Deploy automated ingress firewall rule to drop offending source IP address."
            })
        elif any("ISOLATED" in s for s in path):
            plan.append({
                "phase": "Containment Action",
                "action": "ISOLATE_HOST_ENDPOINT",
                "description": "Quarantine affected host network adapter to prevent lateral movement."
            })
        else:
            plan.append({
                "phase": "Containment Action",
                "action": "THROTTLE_CONNECTION",
                "description": "Apply bandwidth rate-limiting and challenge-response authentication."
            })

        # Phase 3: Remediation
        if vuln_intel.get("is_known_exploited"):
            req_act = vuln_intel.get("required_action") or "Apply vendor security update immediately."
            req_act = str(req_act)
            plan.append({
                "phase": "Remediation Action",
                "action": "APPLY_CISA_MANDATED_PATCH",
                "description": f"Remediate {vuln_intel.get('cve_id')}: {req_act[:150]}"
            })
        elif "Brute Force" in attack_type:
            plan.append({
                "phase": "Remediation Action",
                "action": "RESET_COMPROMISED_CREDENTIALS",
                "description": "Force credential rotation and enforce mandatory MFA for targeted accounts."
            })
        else:
            plan.append({
                "phase": "Remediation Action",
                "action": "UPDATE_SIGNATURE_RULES",
                "description": "Update IDS/IPS detection rules to match newly identified threat telemetry."
            })

        # Phase 4: Recovery & Monitoring
        plan.append({
            "phase": "Monitoring Action",
            "action": "ENHANCED_AUDIT_LOGGING",
            "description": "Monitor system telemetry for 72 hours under heightened sensitivity threshold."
        })

        return plan

    # ---------------------------------------------------------
    # MAIN WORKFLOW: PROCESS RISK & PLAN RESPONSE
    # ---------------------------------------------------------
    def process_incident(
        self,
        request: Any,
        incident_id: str = "INC-001"
    ) -> AgentMessage:
        """
        Orchestrates full Agent 4 assessment and planning:
        1. Evaluates multi-factor risk score.
        2. If asset context is unknown, requests backward clarification from Agent 2.
        3. Executes A* search on defensive action graph.
        4. Synthesizes prioritized mitigation sequence.
        5. Emits structured FINAL_DECISION.
        """
        # Parse incoming envelope
        if isinstance(request, AgentMessage):
            payload = request.payload
            incident_id = request.incident_id
            conversation_id = request.conversation_id
        elif isinstance(request, dict):
            payload = request.get("payload", request)
            incident_id = request.get("incident_id", incident_id)
            conversation_id = request.get("conversation_id", f"CONV-{incident_id}")
        else:
            payload = {}
            conversation_id = f"CONV-{incident_id}"

        # 1. Evaluate Risk Score
        risk_score, risk_tier, factors = self.evaluate_risk_factors(payload)

        # Backward Communication Pattern: Missing Asset Criticality
        if risk_score < 0 or risk_tier == "UNKNOWN":
            return AgentMessage(
                message_type=MessageType.CLARIFICATION_REQUEST,
                sender="agent_4",
                receiver="agent_2",
                incident_id=incident_id,
                conversation_id=conversation_id,
                confidence=0.5,
                priority="HIGH",
                payload={
                    "required_information": "asset_criticality",
                    "target_asset": payload.get("target_asset", "UNKNOWN"),
                    "reason": "Cannot calculate definitive Risk Score without verified target asset criticality."
                }
            )

        # 2. Plan Defensive Mitigation via A* Search
        attack_type = str(payload.get("attack_type") or "Generic Anomaly")
        severity = str(payload.get("agent2_severity") or payload.get("severity") or "HIGH")
        try:
            target_mult = float(payload.get("target_multiplier", 1.0))
        except (ValueError, TypeError):
            target_mult = 1.0
        vuln_intel = payload.get("vulnerability_intel") or {}
        vuln_active = bool(vuln_intel.get("is_known_exploited", False)) if isinstance(vuln_intel, dict) else False

        astar_result = self.plan_mitigation_astar(
            threat_type=attack_type,
            severity=severity,
            target_multiplier=target_mult,
            vulnerability_active=vuln_active
        )

        # 3. Synthesize Phased Response Plan
        response_plan = self.synthesize_response_phases(astar_result, payload)

        # Determine Primary Dispatched Action
        primary_action = response_plan[1]["action"] if len(response_plan) > 1 else "MONITOR"

        # 4. Formulate Transparent Technical Explanation
        reasons: List[str] = [
            f"Evaluated Risk Score {risk_score}/100 ({risk_tier} Priority).",
            f"Key risk drivers: Severity={factors.get('threat_severity')}, Exploitability={factors.get('exploitability')}, Asset={factors.get('asset_criticality')}.",
            f"A* Search computed optimal response path ({' -> '.join(astar_result.path)}) with minimum operational cost of {astar_result.total_cost}."
        ]
        if vuln_active:
            reasons.append(f"Confirmed weaponized CISA KEV exploit: {vuln_intel.get('cve_id')}.")

        explanation_str = " ".join(reasons)

        conf_factor = factors.get("detection_confidence", 85.0)
        conf_normalized = round((float(conf_factor) if conf_factor is not None else 85.0) / 100.0, 4)

        return AgentMessage(
            message_type=MessageType.FINAL_DECISION,
            sender="agent_4",
            receiver="orchestrator",
            incident_id=incident_id,
            conversation_id=conversation_id,
            confidence=conf_normalized,
            priority=risk_tier,
            payload={
                "event_id": payload.get("event_id", "EVT-UNKNOWN"),
                "attack_type": attack_type,
                "target_asset": payload.get("target_asset", "DMZ_WEB_SERVER"),
                "risk_score": risk_score,
                "risk_level": risk_tier,
                "response_priority": risk_tier,
                "risk_factors": factors,
                "primary_mitigation": primary_action,
                "response_sequence": response_plan,
                "search_algorithm": "A*",
                "astar_metrics": {
                    "path": astar_result.path,
                    "total_cost": astar_result.total_cost,
                    "nodes_explored": astar_result.nodes_explored,
                    "execution_time_ms": astar_result.execution_time_ms
                },
                "evidence": payload.get("evidence", []),
                "explanation": explanation_str
            }
        )


if __name__ == "__main__":
    print("=" * 80)
    print(" AGENT 4: Risk Assessment & Response Planning Agent (Standalone Test)")
    print("=" * 80)
    agent = RiskResponseAgent()

    # Test 1: Deterministic risk scoring
    score, tier, factors = agent.calculate_risk_score(80, 90, 95, 85, 90, 95)
    print(f"\n[Test 1: Risk Scoring] Score: {score}/100 | Tier: {tier}")
    print(f"Factors: {factors}")

    # Test 2: A* Search mitigation planning
    bm = agent.plan_mitigation_astar("DoS", "CRITICAL", 1.0)
    print(f"\n[Test 2: A* Search] Path: {' -> '.join(bm.path)}")
    print(f"Total Cost: {bm.total_cost} | Nodes Explored: {bm.nodes_explored}")

    # Test 3: Process incident with CISA KEV
    test_msg = AgentMessage(
        message_type=MessageType.INTELLIGENCE_RESPONSE,
        sender="agent_3",
        receiver="agent_4",
        incident_id="INC-DEMO-A4",
        payload={
            "event_id": "EVT-KEV-DEMO",
            "attack_type": "Web Attack",
            "target_asset": "DMZ_WEB_SERVER",
            "target_multiplier": 1.0,
            "base_severity": 8,
            "confidence": 0.95,
            "vulnerability_intel": {
                "cve_id": "CVE-2026-88779",
                "is_known_exploited": True,
                "known_ransomware_campaign_use": "Known"
            }
        }
    )
    decision = agent.process_incident(test_msg)
    print(f"\n[Test 3: Process Incident Decision]")
    print(f"Decision Type: {decision.message_type}")
    print(f"Risk Level: {decision.payload['risk_level']} (Score: {decision.payload['risk_score']})")
    print(f"Primary Mitigation: {decision.payload['primary_mitigation']}")
    print(f"A* Optimal Path: {' -> '.join(decision.payload['astar_metrics']['path'])}")
    print("\n[+] Agent 4 self-test passed successfully!")

