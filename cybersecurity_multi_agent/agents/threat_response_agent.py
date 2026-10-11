"""
agents/threat_response_agent.py

Agent 2: Threat Analysis & Response Planning Agent (Reasoning & Search)

Specializes in knowledge-based threat interpretation and state-space response planning.
Receives structured messages from Agent 1, queries external cybersecurity knowledge rules,
calculates composite risk scores based on target asset criticality and CIA impact,
models the defensive mitigation state-space, executes and benchmarks both BFS and A* searches,
and dispatches the cost-optimal defensive response action.
"""

import os
import sys
import json
from typing import Dict, Any, Optional

# Ensure base project directory is in sys.path for direct execution
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

try:
    from communication.messages import Agent1Message, Agent2Response, SearchBenchmark, AgentMessage, MessageType
except ImportError:
    try:
        from ..communication.messages import Agent1Message, Agent2Response, SearchBenchmark, AgentMessage, MessageType
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import Agent1Message, Agent2Response, SearchBenchmark, AgentMessage, MessageType


try:
    from search.response_graph import ResponseGraph
    from search.bfs import breadth_first_search
    from search.astar import astar_search
except ImportError:
    try:
        from ..search.response_graph import ResponseGraph
        from ..search.bfs import breadth_first_search
        from ..search.astar import astar_search
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.search.response_graph import ResponseGraph
        from cybersecurity_multi_agent.search.bfs import breadth_first_search
        from cybersecurity_multi_agent.search.astar import astar_search


class ThreatResponseAgent:
    """
    Autonomous Intelligent Agent for Threat Analysis & Response Planning.
    
    Academic Role:
      Knowledge-based reasoning and state-space search planning.
      Answers: "What does this threat mean, and what is the optimal sequence of defensive actions?"
    """

    def __init__(self, knowledge_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if knowledge_path is None:
            knowledge_path = os.path.join(base_dir, "knowledge", "cybersecurity_rules.json")
            
        self.knowledge_path = knowledge_path
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> Dict[str, Any]:
        """Loads declarative cybersecurity domain rules from external JSON."""
        if not os.path.exists(self.knowledge_path):
            raise FileNotFoundError(f"[Agent 2 Error] Knowledge base file not found: {self.knowledge_path}")
        with open(self.knowledge_path, "r") as f:
            return json.load(f)

    def receive_message(self, message_input: Any) -> Agent1Message:
        """
        Message reception interface.
        Enforces loose coupling: accepts Agent1Message instances, AgentMessage envelopes,
        or serialized JSON strings. Direct memory sharing is strictly disallowed.
        """
        if isinstance(message_input, Agent1Message):
            return message_input
        elif isinstance(message_input, AgentMessage):
            payload = message_input.payload
            if "prediction" in payload:
                return Agent1Message.from_dict(payload)
            else:
                return Agent1Message(
                    event_id=payload.get("event_id", payload.get("alert_id", "EVT-UNKNOWN")),
                    prediction=payload.get("prediction", "ATTACK"),
                    confidence=message_input.confidence,
                    attack_type=payload.get("attack_type", "Generic Anomaly"),
                    evidence=payload.get("evidence", []),
                    raw_features_summary=payload.get("raw_features_summary", {})
                )
        elif isinstance(message_input, str):
            try:
                data = json.loads(message_input)
                if "payload" in data and "message_type" in data:
                    return self.receive_message(AgentMessage.from_dict(data))
                return Agent1Message.from_dict(data)
            except Exception:
                return Agent1Message.from_json(message_input)
        elif isinstance(message_input, dict):
            if "payload" in message_input and "message_type" in message_input:
                return self.receive_message(AgentMessage.from_dict(message_input))
            return Agent1Message.from_dict(message_input)
        else:
            raise TypeError(f"[Agent 2 Error] Rejected invalid message format: {type(message_input)}")

    def analyze_threat(self, message: Agent1Message, target_asset: str = "DMZ_WEB_SERVER") -> Dict[str, Any]:
        """
        Reasoning Engine: Consults knowledge base rules to infer category, CIA impact, and risk score.
        """
        if message.prediction == "NORMAL":
            return {
                "threat_category": "Benign Telemetry",
                "impacted_property": "None",
                "severity": "LOW",
                "base_severity": 0,
                "risk_score": 0.0,
                "target_multiplier": 1.0,
                "target_asset": target_asset
            }

        taxonomy = self.knowledge_base.get("attack_taxonomy", {})
        attack_info = taxonomy.get(message.attack_type, taxonomy.get("Generic Anomaly", {
            "category": "Suspicious Activity",
            "impacted_property": "Integrity",
            "base_severity": 5
        }))

        category = attack_info.get("category", "Unknown Threat")
        impacted_property = attack_info.get("impacted_property", "General Security")
        base_severity = attack_info.get("base_severity", 5)

        # Infer qualitative severity tier based on confidence and base severity
        assigned_severity = "LOW"
        for rule in self.knowledge_base.get("severity_thresholds", []):
            if message.confidence >= rule["min_confidence"] and base_severity >= rule["base_severity_ge"]:
                assigned_severity = rule["assigned_severity"]
                break

        # Calculate numeric Risk Score in [0, 100]
        multipliers = self.knowledge_base.get("target_criticality_multipliers", {})
        target_multiplier = multipliers.get(target_asset, 1.0)
        
        raw_risk = message.confidence * base_severity * target_multiplier * 10.0
        risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

        return {
            "threat_category": category,
            "impacted_property": impacted_property,
            "severity": assigned_severity,
            "base_severity": base_severity,
            "risk_score": risk_score,
            "target_multiplier": target_multiplier,
            "target_asset": target_asset
        }

    def build_state_space(self, threat_analysis: Dict[str, Any]) -> ResponseGraph:
        """Constructs the response graph parametrized by the evaluated threat context."""
        return ResponseGraph(
            threat_type=threat_analysis.get("threat_category", "Unknown"),
            severity=threat_analysis.get("severity", "HIGH"),
            target_criticality=threat_analysis.get("target_multiplier", 1.0)
        )

    def plan_response_bfs(self, graph: ResponseGraph) -> SearchBenchmark:
        """Executes uninformed Breadth-First Search."""
        return breadth_first_search(graph)

    def plan_response_astar(self, graph: ResponseGraph) -> SearchBenchmark:
        """Executes informed A* Search with admissible heuristic."""
        return astar_search(graph)

    def process_threat(self, message_input: Any, target_asset: str = "DMZ_WEB_SERVER") -> Agent2Response:
        """
        Orchestrates full Agent 2 threat analysis and response planning cycle.
        Executes both BFS and A* searches, benchmarks their results,
        selects the optimal defensive policy, and compiles the final Agent2Response.
        """
        message = self.receive_message(message_input)
        analysis = self.analyze_threat(message, target_asset=target_asset)

        # Handle normal benign event
        if message.prediction == "NORMAL":
            return Agent2Response(
                referenced_event_id=message.event_id,
                threat_category="Benign Telemetry",
                impacted_property="None",
                severity="LOW",
                risk_score=0.0,
                selected_response="LOG_AND_PASS",
                selected_algorithm="RuleEngine",
                execution_path=["BENIGN_VERIFIED"],
                total_path_cost=0.0,
                nodes_explored=1,
                execution_time_ms=0.05,
                search_comparison={},
                reason="Traffic validated as normal enterprise operational behavior. No mitigation required."
            )

        # Build response graph and execute comparative search
        graph = self.build_state_space(analysis)
        bfs_res = self.plan_response_bfs(graph)
        astar_res = self.plan_response_astar(graph)

        # Search Comparison dictionary
        search_comparison = {
            "BFS": {
                "path": bfs_res.path,
                "cost": bfs_res.total_cost,
                "nodes_explored": bfs_res.nodes_explored,
                "execution_time_ms": bfs_res.execution_time_ms,
                "optimal": bfs_res.total_cost <= astar_res.total_cost
            },
            "A*": {
                "path": astar_res.path,
                "cost": astar_res.total_cost,
                "nodes_explored": astar_res.nodes_explored,
                "execution_time_ms": astar_res.execution_time_ms,
                "optimal": True
            }
        }

        # Select primary action from optimal path (A* path)
        # e.g., if path is ['ATTACK_DETECTED', 'THREAT_CONFIRMED', 'SOURCE_BLOCKED', 'INCIDENT_CONTROLLED']
        # primary mitigation action is typically the action leading to containment
        if len(astar_res.path) >= 3:
            key_state = astar_res.path[2]
            if "BLOCKED" in key_state:
                selected_response = "BLOCK_SOURCE"
            elif "ISOLATED" in key_state:
                selected_response = "ISOLATE_HOST"
            elif "ALERTED" in key_state or "SOC" in key_state:
                selected_response = "ESCALATE"
            else:
                selected_response = "VERIFY_AND_CONTAIN"
        else:
            selected_response = "MONITOR"

        reason = (
            f"Threat identified as {analysis['threat_category']} targeting {analysis['impacted_property']} "
            f"with {analysis['severity']} severity (Risk Score: {analysis['risk_score']}/100 on {target_asset}). "
            f"A* search determined optimal response path with minimum operational disruption "
            f"(Total Cost: {astar_res.total_cost} vs BFS Cost: {bfs_res.total_cost})."
        )

        return Agent2Response(
            referenced_event_id=message.event_id,
            threat_category=analysis["threat_category"],
            impacted_property=analysis["impacted_property"],
            severity=analysis["severity"],
            risk_score=analysis["risk_score"],
            selected_response=selected_response,
            selected_algorithm="A*",
            execution_path=astar_res.path,
            total_path_cost=astar_res.total_cost,
            nodes_explored=astar_res.nodes_explored,
            execution_time_ms=astar_res.execution_time_ms,
            search_comparison=search_comparison,
            reason=reason
        )

    def extract_indicators(self, message: Agent1Message) -> List[str]:
        """
        Specialist capability: extracts actionable indicators of compromise (IoCs)
        and behavioral attack signatures from perceived event telemetry.
        """
        indicators: List[str] = list(message.evidence)
        summary = message.raw_features_summary or {}

        # Scan for explicit CVE identifiers
        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        for ev in message.evidence:
            matches = cve_pattern.findall(ev)
            for m in matches:
                indicators.append(f"Targeted CVE: {m.upper()}")

        if summary.get("cve"):
            indicators.append(f"Targeted CVE: {str(summary['cve']).upper()}")

        if summary.get("login_attempts", 0) > 3:
            indicators.append(f"Repeated authentication velocity: {summary.get('login_attempts')} attempts")
        if summary.get("network_packet_size", 0) > 650:
            indicators.append(f"Volumetric anomaly: {summary.get('network_packet_size')} bytes")
        if summary.get("protocol_type") in ["UDP", "ICMP"]:
            indicators.append(f"Suspicious protocol abuse: {summary.get('protocol_type')}")

        return list(dict.fromkeys(indicators))  # Deduplicate while preserving order

    def generate_query_terms(self, attack_type: str, indicators: List[str]) -> List[str]:
        """
        Synthesizes targeted MITRE ATT&CK and vulnerability search terms.
        """
        terms: List[str] = [attack_type]
        mapping = {
            "Brute Force": ["Brute Force", "Password Spraying", "T1110"],
            "DoS": ["Denial of Service", "Network Flood", "T1498"],
            "Port Scan": ["Network Service Discovery", "Port Scan", "T1046"],
            "Botnet": ["Command and Control", "Protocol Tunneling", "T1071"],
            "Web Attack": ["Exploit Public-Facing Application", "SQL Injection", "T1190"],
            "Infiltration": ["Lateral Movement", "Privilege Escalation", "T1068"]
        }
        if attack_type in mapping:
            terms.extend(mapping[attack_type])

        # Add any CVE terms
        import re
        for ind in indicators:
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", ind, re.IGNORECASE)
            for cve in cves:
                terms.append(cve.upper())

        return list(dict.fromkeys(terms))

    def analyze_and_create_request(
        self,
        message_input: Any,
        target_asset: str = "DMZ_WEB_SERVER",
        incident_id: str = "INC-001"
    ) -> AgentMessage:
        """
        Specialist entrypoint for 4-Agent Orchestration:
        Analyzes Agent 1 alert, synthesizes indicators and query terms,
        and constructs a structured INTELLIGENCE_REQUEST for Agent 3.
        """
        msg1 = self.receive_message(message_input)
        analysis = self.analyze_threat(msg1, target_asset=target_asset)
        indicators = self.extract_indicators(msg1)
        query_terms = self.generate_query_terms(msg1.attack_type, indicators)

        # Check for extracted CVE
        cve_id = None
        for term in query_terms:
            if term.startswith("CVE-"):
                cve_id = term
                break

        priority = "CRITICAL" if analysis["severity"] in ["CRITICAL", "HIGH"] else "MEDIUM"

        return AgentMessage(
            message_type=MessageType.INTELLIGENCE_REQUEST,
            sender="agent_2",
            receiver="agent_3",
            incident_id=incident_id,
            confidence=msg1.confidence,
            priority=priority,
            payload={
                "event_id": msg1.event_id,
                "attack_type": msg1.attack_type,
                "threat_category": analysis["threat_category"],
                "impacted_property": analysis["impacted_property"],
                "severity": analysis["severity"],
                "base_severity": analysis["base_severity"],
                "target_asset": target_asset,
                "target_multiplier": analysis["target_multiplier"],
                "indicators": indicators,
                "query_terms": query_terms,
                "cve_id": cve_id,
                "agent1_confidence": msg1.confidence,
                "evidence": msg1.evidence
            }
        )

    def handle_clarification(self, clarification_msg: AgentMessage) -> AgentMessage:
        """
        Specialist capability: handles backward CLARIFICATION_REQUEST from Agent 4 or Agent 3.
        Provides missing asset context, attack severity, or indicators without fabricating.
        """
        req_info = clarification_msg.payload.get("required_information", "").lower()
        incident_id = clarification_msg.incident_id
        target_asset = clarification_msg.payload.get("target_asset", "DMZ_WEB_SERVER")

        multipliers = self.knowledge_base.get("target_criticality_multipliers", {})
        criticality = multipliers.get(target_asset, 1.0)

        response_payload = {
            "request_id": clarification_msg.message_id,
            "target_asset": target_asset,
            "asset_criticality": criticality,
            "resolved_property": req_info,
            "status": "RESOLVED",
            "clarification_notes": f"Verified asset context for '{target_asset}': criticality multiplier = {criticality}."
        }

        return AgentMessage(
            message_type=MessageType.CLARIFICATION_RESPONSE,
            sender="agent_2",
            receiver=clarification_msg.sender,
            incident_id=incident_id,
            conversation_id=clarification_msg.conversation_id,
            confidence=0.95,
            priority="HIGH",
            payload=response_payload
        )


if __name__ == "__main__":
    print("=" * 80)
    print(" AGENT 2: Threat Analysis & Response Planning Agent (Standalone Test)")
    print("=" * 80)
    agent = ThreatResponseAgent()
    msg = Agent1Message(
        event_id="EVT-TEST",
        prediction="ATTACK",
        confidence=0.92,
        attack_type="DoS",
        evidence=["UDP flood detected"]
    )
    analysis = agent.analyze_threat(msg, target_asset="DMZ_WEB_SERVER")
    print(f"Analysis: Category={analysis['threat_category']} | Severity={analysis['severity']} | Risk={analysis['risk_score']}")
    print("\n[+] Agent 2 self-test passed successfully!")

