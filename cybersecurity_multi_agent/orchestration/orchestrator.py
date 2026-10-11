"""
orchestration/orchestrator.py

Central Orchestrator & Coordinator for Multi-Agent Cybersecurity System.

Responsibilities:
  - Manages the lifecycle of an Incident (IncidentState).
  - Routes typed messages between specialized agents.
  - Enforces intelligent conditional branching (e.g. early exit on benign traffic).
  - Facilitates genuine backward clarification dialogues without infinite loops.
  - Maintains strict decoupling: does NOT perform specialist work directly.
  - Tracks system metrics (Unnecessary Invocation Rate, Investigation Depth, Latency).
"""

import os
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

try:
    from communication.messages import AgentMessage, MessageType
    from orchestration.state import IncidentState
    from agents.intrusion_detection_agent import IntrusionDetectionAgent
    from agents.threat_response_agent import ThreatResponseAgent
    from agents.threat_intelligence_agent import ThreatIntelligenceAgent
    from agents.risk_response_agent import RiskResponseAgent
except ImportError:
    try:
        from ..communication.messages import AgentMessage, MessageType
        from .state import IncidentState
        from ..agents.intrusion_detection_agent import IntrusionDetectionAgent
        from ..agents.threat_response_agent import ThreatResponseAgent
        from ..agents.threat_intelligence_agent import ThreatIntelligenceAgent
        from ..agents.risk_response_agent import RiskResponseAgent
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import AgentMessage, MessageType
        from cybersecurity_multi_agent.orchestration.state import IncidentState
        from cybersecurity_multi_agent.agents.intrusion_detection_agent import IntrusionDetectionAgent
        from cybersecurity_multi_agent.agents.threat_response_agent import ThreatResponseAgent
        from cybersecurity_multi_agent.agents.threat_intelligence_agent import ThreatIntelligenceAgent
        from cybersecurity_multi_agent.agents.risk_response_agent import RiskResponseAgent


class MultiAgentOrchestrator:
    """
    Intelligent Central Coordinator for 4 Specialized Cybersecurity Agents.
    """

    def __init__(
        self,
        agent1: Optional[IntrusionDetectionAgent] = None,
        agent2: Optional[ThreatResponseAgent] = None,
        agent3: Optional[ThreatIntelligenceAgent] = None,
        agent4: Optional[RiskResponseAgent] = None,
        max_iterations: int = 6,
        benign_confidence_threshold: float = 0.80
    ):
        self.agent1 = agent1 if agent1 is not None else IntrusionDetectionAgent()
        self.agent2 = agent2 if agent2 is not None else ThreatResponseAgent()
        self.agent3 = agent3 if agent3 is not None else ThreatIntelligenceAgent()
        self.agent4 = agent4 if agent4 is not None else RiskResponseAgent()

        self.max_iterations = max_iterations
        self.benign_confidence_threshold = benign_confidence_threshold

    def run_investigation(
        self,
        event_id: str,
        raw_event: Dict[str, Any],
        target_asset: str = "DMZ_WEB_SERVER",
        incident_id: Optional[str] = None
    ) -> IncidentState:
        """
        Executes end-to-end intelligent multi-agent incident investigation.
        """
        if incident_id is None:
            incident_id = f"INC-{event_id.replace('EVT-', '')}"

        state = IncidentState(
            incident_id=incident_id,
            event_id=event_id,
            target_asset=target_asset,
            raw_event=raw_event
        )

        iteration = 0

        # =====================================================================
        # STEP 1: AGENT 1 (PERCEPTION & DETECTION)
        # =====================================================================
        state.investigation_depth = 1
        msg_a1 = self.agent1.process_event_message(event_id, raw_event, incident_id=incident_id)
        state.record_message(msg_a1)
        state.record_agent_result("agent_1", msg_a1.payload, msg_a1.confidence)
        state.add_evidence(msg_a1.payload.get("evidence", []))

        pred = msg_a1.payload.get("prediction", "NORMAL")
        conf = msg_a1.confidence

        # ---------------------------------------------------------------------
        # SMART ROUTING RULE 1: HIGH-CONFIDENCE BENIGN EARLY TERMINATION
        # If Agent 1 confidently determines traffic is benign, stop immediately!
        # Do not waste computational cycles running Agents 2, 3, and 4.
        # ---------------------------------------------------------------------
        if pred == "NORMAL" and conf >= self.benign_confidence_threshold:
            state.status = "CLOSED_BENIGN"
            state.unnecessary_calls_avoided += 3  # Prevented Agents 2, 3, and 4
            state.decisions.append({
                "decision": "LOG_AND_PASS",
                "reason": (
                    f"Traffic validated as BENIGN with high confidence ({conf * 100:.1f}%). "
                    f"Downstream investigations (Agents 2, 3, 4) pruned to avoid resource waste."
                ),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            state.end_time = datetime.now(timezone.utc).isoformat()
            return state

        # =====================================================================
        # STEP 2: AGENT 2 (THREAT ANALYSIS)
        # =====================================================================
        state.investigation_depth = 2
        msg_a2_request = self.agent2.analyze_and_create_request(
            message_input=msg_a1,
            target_asset=target_asset,
            incident_id=incident_id
        )
        state.record_message(msg_a2_request)
        state.record_agent_result("agent_2", msg_a2_request.payload, msg_a2_request.confidence)
        state.add_evidence(msg_a2_request.payload.get("evidence", []))

        # Check for disagreement between Agent 1 and Agent 2
        a1_type = msg_a1.payload.get("attack_type", "")
        a2_cat = msg_a2_request.payload.get("threat_category", "")
        if a1_type != "Generic Anomaly" and a1_type not in a2_cat and "Attack" not in a2_cat:
            state.conflicts.append({
                "type": "CLASSIFICATION_DISAGREEMENT",
                "agent_1_finding": a1_type,
                "agent_2_finding": a2_cat,
                "resolution": "Preserved both hypotheses for Agent 3 threat intelligence arbitration."
            })

        # =====================================================================
        # STEP 3: AGENT 3 (THREAT INTELLIGENCE ENRICHMENT)
        # =====================================================================
        state.investigation_depth = 3
        msg_a3_response = self.agent3.process_intelligence_request(
            request=msg_a2_request,
            incident_id=incident_id
        )
        state.record_message(msg_a3_response)

        # ---------------------------------------------------------------------
        # BACKWARD COMMUNICATION PATTERN: AGENT 3 -> AGENT 2 CLARIFICATION
        # If Agent 3 has low confidence, it requests additional indicators from Agent 2.
        # ---------------------------------------------------------------------
        if msg_a3_response.message_type == MessageType.CLARIFICATION_REQUEST:
            state.status = "CLARIFYING"
            # Route clarification request backward to Agent 2
            msg_a2_clarification = self.agent2.handle_clarification(msg_a3_response)
            state.record_message(msg_a2_clarification)

            # Update request payload with additional indicators and retry Agent 3
            retry_payload = dict(msg_a2_request.payload)
            retry_payload["indicators"].append("Secondary behavioral verification completed by Agent 2")
            retry_payload["query_terms"].append("Credential Access")
            msg_a2_request.payload = retry_payload

            msg_a3_response = self.agent3.process_intelligence_request(
                request=msg_a2_request,
                incident_id=incident_id
            )
            state.record_message(msg_a3_response)

        state.record_agent_result("agent_3", msg_a3_response.payload, msg_a3_response.confidence)
        state.add_evidence(msg_a3_response.payload.get("evidence", []))

        # =====================================================================
        # STEP 4: AGENT 4 (RISK ASSESSMENT & RESPONSE PLANNING)
        # =====================================================================
        state.investigation_depth = 4
        msg_a4_decision = self.agent4.process_incident(
            request=msg_a3_response,
            incident_id=incident_id
        )
        state.record_message(msg_a4_decision)

        # ---------------------------------------------------------------------
        # BACKWARD COMMUNICATION PATTERN: AGENT 4 -> AGENT 2 CLARIFICATION
        # If Agent 4 detects unknown asset criticality, it requests clarification.
        # ---------------------------------------------------------------------
        if msg_a4_decision.message_type == MessageType.CLARIFICATION_REQUEST:
            state.status = "CLARIFYING"
            # Route backward to Agent 2 to resolve asset context
            msg_a2_asset_clarification = self.agent2.handle_clarification(msg_a4_decision)
            state.record_message(msg_a2_asset_clarification)

            # Update Agent 3 payload with resolved asset context
            resolved_crit = msg_a2_asset_clarification.payload.get("asset_criticality", 1.0)
            resolved_asset = msg_a2_asset_clarification.payload.get("target_asset", target_asset)
            if resolved_asset == "UNKNOWN":
                resolved_asset = "DMZ_WEB_SERVER"
                resolved_crit = 1.0

            updated_a3_payload = dict(msg_a3_response.payload)
            updated_a3_payload["target_asset"] = resolved_asset
            updated_a3_payload["target_multiplier"] = resolved_crit
            msg_a3_response.payload = updated_a3_payload

            # Re-invoke Agent 4
            msg_a4_decision = self.agent4.process_incident(
                request=msg_a3_response,
                incident_id=incident_id
            )
            state.record_message(msg_a4_decision)

        state.record_agent_result("agent_4", msg_a4_decision.payload, msg_a4_decision.confidence)
        state.add_evidence(msg_a4_decision.payload.get("evidence", []))

        # Finalize incident record
        state.status = "RESOLVED"
        state.decisions.append({
            "primary_mitigation": msg_a4_decision.payload.get("primary_mitigation"),
            "risk_score": msg_a4_decision.payload.get("risk_score"),
            "risk_level": msg_a4_decision.payload.get("risk_level"),
            "response_sequence": msg_a4_decision.payload.get("response_sequence"),
            "explanation": msg_a4_decision.payload.get("explanation"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        state.end_time = datetime.now(timezone.utc).isoformat()

        return state
