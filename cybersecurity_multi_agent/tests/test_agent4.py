"""
tests/test_agent4.py

Unit tests for Agent 4 (RiskResponseAgent).
Validates multi-factor deterministic Risk Scoring, A* Search optimization,
backward CLARIFICATION_REQUEST generation for unknown asset contexts,
CISA KEV exploit prioritization, and structured FINAL_DECISION emission.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.risk_response_agent import RiskResponseAgent
from communication.messages import AgentMessage, MessageType


class TestRiskResponseAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = RiskResponseAgent()

    def test_deterministic_risk_calculation_tiers(self):
        # 1. LOW Risk scenario
        low_score, low_tier, _ = self.agent.calculate_risk_score(20, 20, 20, 20, 20, 20)
        self.assertEqual(low_score, 20.0)
        self.assertEqual(low_tier, "LOW")

        # 2. MEDIUM Risk scenario
        med_score, med_tier, _ = self.agent.calculate_risk_score(40, 40, 40, 40, 40, 40)
        self.assertEqual(med_score, 40.0)
        self.assertEqual(med_tier, "MEDIUM")

        # 3. HIGH Risk scenario
        high_score, high_tier, _ = self.agent.calculate_risk_score(65, 65, 65, 65, 65, 65)
        self.assertEqual(high_score, 65.0)
        self.assertEqual(high_tier, "HIGH")

        # 4. CRITICAL Risk scenario
        crit_score, crit_tier, _ = self.agent.calculate_risk_score(90, 95, 100, 85, 90, 95)
        self.assertTrue(crit_score >= 75.0)
        self.assertEqual(crit_tier, "CRITICAL")

    def test_astar_search_mitigation_planning(self):
        benchmark = self.agent.plan_mitigation_astar(
            threat_type="DoS",
            severity="CRITICAL",
            target_multiplier=1.0
        )
        self.assertEqual(benchmark.algorithm, "A*")
        self.assertTrue(benchmark.goal_found)
        self.assertEqual(benchmark.path[0], "ATTACK_DETECTED")
        self.assertEqual(benchmark.path[-1], "INCIDENT_CONTROLLED")
        self.assertEqual(benchmark.total_cost, 10.0)  # Optimal path cost

    def test_unknown_asset_criticality_triggers_clarification(self):
        req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id="INC-UNIT-4",
            payload={
                "event_id": "EVT-UNKNOWN-ASSET",
                "attack_type": "Brute Force",
                "target_asset": "UNKNOWN",
                "target_multiplier": 0.0,
                "base_severity": 7
            }
        )
        res = self.agent.process_incident(req)
        self.assertEqual(res.message_type, MessageType.CLARIFICATION_REQUEST)
        self.assertEqual(res.receiver, "agent_2")
        self.assertEqual(res.payload.get("required_information"), "asset_criticality")

    def test_cisa_kev_weaponized_exploit_elevates_risk(self):
        req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id="INC-UNIT-4",
            payload={
                "event_id": "EVT-EXPLOIT",
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
        decision = self.agent.process_incident(req)
        self.assertEqual(decision.message_type, MessageType.FINAL_DECISION)
        self.assertEqual(decision.payload["risk_level"], "CRITICAL")
        self.assertTrue(decision.payload["risk_score"] >= 75.0)
        self.assertEqual(decision.payload["risk_factors"]["exploitability"], 100.0)

    def test_process_incident_full_decision_structure(self):
        req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id="INC-UNIT-4",
            payload={
                "event_id": "EVT-VALID",
                "attack_type": "Brute Force",
                "target_asset": "CORE_DATABASE",
                "target_multiplier": 1.3,
                "base_severity": 7,
                "agent2_severity": "CRITICAL",
                "confidence": 0.95,
                "primary_technique_id": "T1110",
                "vulnerability_intel": {"is_known_exploited": False},
                "evidence": ["Excessive failed logins"]
            }
        )
        decision = self.agent.process_incident(req)
        self.assertEqual(decision.message_type, MessageType.FINAL_DECISION)
        self.assertIn("risk_score", decision.payload)
        self.assertIn("risk_factors", decision.payload)
        self.assertIn("response_sequence", decision.payload)
        self.assertIn("astar_metrics", decision.payload)
        self.assertIn("explanation", decision.payload)
        self.assertTrue(len(decision.payload["response_sequence"]) >= 3)

    def test_direct_package_import(self):
        """Verifies Agent 4 can be directly imported from the top-level agents package."""
        from agents import RiskResponseAgent as ExportedAgent
        self.assertIs(ExportedAgent, RiskResponseAgent)

    def test_robustness_against_none_and_missing_payload_values(self):
        """Verifies Agent 4 gracefully handles None and missing values without crashing."""
        malformed_req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id="INC-UNIT-NULL",
            payload={
                "event_id": "EVT-NULLS",
                "attack_type": None,
                "target_asset": None,
                "target_multiplier": None,
                "base_severity": None,
                "confidence": None,
                "vulnerability_intel": None,
                "impacted_property": None
            }
        )
        # Should gracefully trigger clarification request due to target_asset=None / target_multiplier=None
        res = self.agent.process_incident(malformed_req)
        self.assertEqual(res.message_type, MessageType.CLARIFICATION_REQUEST)
        self.assertEqual(res.receiver, "agent_2")

    def test_robustness_valid_values_with_none_vulnerability(self):
        """Verifies Agent 4 produces FINAL_DECISION when vulnerability_intel is None but asset is valid."""
        req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id="INC-UNIT-NONE-VULN",
            payload={
                "event_id": "EVT-NO-VULN",
                "attack_type": "Generic Anomaly",
                "target_asset": "DMZ_WEB_SERVER",
                "target_multiplier": 1.0,
                "base_severity": 6,
                "confidence": 0.85,
                "vulnerability_intel": None
            }
        )
        decision = self.agent.process_incident(req)
        self.assertEqual(decision.message_type, MessageType.FINAL_DECISION)
        self.assertGreater(decision.payload["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()

