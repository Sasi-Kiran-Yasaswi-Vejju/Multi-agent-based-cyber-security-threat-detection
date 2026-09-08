"""
tests/test_agent2.py

Unit tests for Agent 2 (ThreatResponseAgent).
Validates message reception, knowledge-base rule lookup, CIA Triad impact mapping,
risk score calculation, and response plan formulation.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.threat_response_agent import ThreatResponseAgent
from communication.messages import Agent1Message, Agent2Response


class TestThreatResponseAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = ThreatResponseAgent()

    def test_benign_message_handling(self):
        msg = Agent1Message(
            event_id="EVT-BENIGN",
            prediction="NORMAL",
            confidence=0.95,
            attack_type="None",
            evidence=["Traffic within baseline"]
        )
        resp = self.agent.process_threat(msg)
        self.assertIsInstance(resp, Agent2Response)
        self.assertEqual(resp.selected_response, "LOG_AND_PASS")
        self.assertEqual(resp.risk_score, 0.0)
        self.assertEqual(resp.severity, "LOW")

    def test_dos_threat_reasoning(self):
        msg = Agent1Message(
            event_id="EVT-DOS",
            prediction="ATTACK",
            confidence=0.92,
            attack_type="DoS",
            evidence=["UDP flood detected", "Packet size 850 bytes"]
        )
        analysis = self.agent.analyze_threat(msg, target_asset="DMZ_WEB_SERVER")
        self.assertEqual(analysis["threat_category"], "Network Attack")
        self.assertEqual(analysis["impacted_property"], "Availability")
        self.assertEqual(analysis["severity"], "CRITICAL")
        self.assertGreaterEqual(analysis["risk_score"], 70.0)

    def test_brute_force_threat_reasoning(self):
        msg = Agent1Message(
            event_id="EVT-BF",
            prediction="ATTACK",
            confidence=0.88,
            attack_type="Brute Force",
            evidence=["5 failed logins"]
        )
        analysis = self.agent.analyze_threat(msg, target_asset="CORE_DATABASE")
        self.assertEqual(analysis["threat_category"], "Credential Attack")
        self.assertEqual(analysis["impacted_property"], "Confidentiality")
        # Target multiplier for CORE_DATABASE is 1.3
        self.assertGreaterEqual(analysis["risk_score"], 75.0)

    def test_rejects_direct_invalid_input(self):
        with self.assertRaises(Exception):
            self.agent.process_threat(12345)


if __name__ == "__main__":
    unittest.main()
