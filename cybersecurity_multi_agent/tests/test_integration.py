"""
tests/test_integration.py

End-to-End Integration Test for Multi-Agent Cybersecurity System.
Tests the complete collaborative workflow across both agents:
Raw Sensor Data -> Agent 1 Perception -> JSON Message -> Agent 2 Reasoning -> State Space Search -> Optimal Response.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.intrusion_detection_agent import IntrusionDetectionAgent
from agents.threat_response_agent import ThreatResponseAgent
from communication.messages import Agent1Message, Agent2Response


class TestMultiAgentIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent1 = IntrusionDetectionAgent()
        cls.agent2 = ThreatResponseAgent()

    def test_end_to_end_attack_containment_pipeline(self):
        # 1. Incoming malicious network event (matches dataset attack profile)
        raw_event = {
            "network_packet_size": 599,
            "protocol_type": "TCP",
            "login_attempts": 4,
            "session_duration": 492.98,
            "ip_reputation_score": 0.6068,
            "failed_logins": 1,
            "browser_type": "Edge",
            "unusual_time_access": 0,
            "encryption_used": "DES"
        }

        # 2. Agent 1 executes perception, preprocessing, ML classification, and evidence generation
        msg_agent1 = self.agent1.process_event("EVT-INT-001", raw_event)
        self.assertIsInstance(msg_agent1, Agent1Message)
        self.assertEqual(msg_agent1.prediction, "ATTACK")

        # 3. Simulate inter-agent network wire transmission via JSON string
        serialized_msg = msg_agent1.to_json()
        self.assertIsInstance(serialized_msg, str)

        # 4. Agent 2 receives message via network boundary, performs symbolic reasoning, and plans response
        response = self.agent2.process_threat(serialized_msg, target_asset="DMZ_WEB_SERVER")
        self.assertIsInstance(response, Agent2Response)
        self.assertEqual(response.referenced_event_id, "EVT-INT-001")
        self.assertIn(response.selected_response, ["BLOCK_SOURCE", "ISOLATE_HOST", "ESCALATE", "VERIFY_AND_CONTAIN"])
        self.assertEqual(response.selected_algorithm, "A*")
        self.assertIn("INCIDENT_CONTROLLED", response.execution_path)

        # 5. Verify search comparison metrics are populated
        self.assertIn("BFS", response.search_comparison)
        self.assertIn("A*", response.search_comparison)
        self.assertLessEqual(
            response.search_comparison["A*"]["cost"],
            response.search_comparison["BFS"]["cost"]
        )

    def test_end_to_end_normal_benign_pipeline(self):
        # Incoming benign user connection (matches dataset normal profile)
        raw_event = {
            "network_packet_size": 472,
            "protocol_type": "TCP",
            "login_attempts": 3,
            "session_duration": 1557.99,
            "ip_reputation_score": 0.3015,
            "failed_logins": 0,
            "browser_type": "Firefox",
            "unusual_time_access": 0,
            "encryption_used": "DES"
        }

        msg = self.agent1.process_event("EVT-BENIGN-002", raw_event)
        self.assertEqual(msg.prediction, "NORMAL")

        response = self.agent2.process_threat(msg.to_json())
        self.assertEqual(response.selected_response, "LOG_AND_PASS")
        self.assertEqual(response.risk_score, 0.0)


if __name__ == "__main__":
    unittest.main()
