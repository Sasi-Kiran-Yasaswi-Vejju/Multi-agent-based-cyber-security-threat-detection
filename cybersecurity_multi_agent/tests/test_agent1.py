"""
tests/test_agent1.py

Unit tests for Agent 1 (IntrusionDetectionAgent).
Validates perception, preprocessing, classification, confidence calculation,
evidence extraction, and structured message generation.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.intrusion_detection_agent import IntrusionDetectionAgent
from communication.messages import Agent1Message


class TestIntrusionDetectionAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = IntrusionDetectionAgent()

    def test_perceive_valid_event(self):
        raw_event = {
            "network_packet_size": 450,
            "protocol_type": "TCP",
            "login_attempts": 2,
            "session_duration": 400.0,
            "ip_reputation_score": 0.85,
            "failed_logins": 0,
            "browser_type": "Chrome",
            "unusual_time_access": 0
        }
        perceived = self.agent.perceive(raw_event)
        self.assertEqual(perceived["encryption_used"], "None")
        self.assertEqual(perceived["network_packet_size"], 450)

    def test_perceive_missing_required_feature_raises_error(self):
        malformed = {
            "network_packet_size": 450,
            # Missing protocol_type, failed_logins, etc.
        }
        with self.assertRaises(ValueError):
            self.agent.perceive(malformed)

    def test_process_event_returns_valid_agent1_message(self):
        sample_event = {
            "network_packet_size": 850,
            "protocol_type": "UDP",
            "login_attempts": 5,
            "session_duration": 12.0,
            "ip_reputation_score": 0.15,
            "failed_logins": 4,
            "browser_type": "Unknown",
            "unusual_time_access": 1,
            "encryption_used": "None"
        }
        msg = self.agent.process_event("EVT-TEST-001", sample_event)
        self.assertIsInstance(msg, Agent1Message)
        self.assertEqual(msg.event_id, "EVT-TEST-001")
        self.assertIn(msg.prediction, ["ATTACK", "NORMAL"])
        self.assertGreaterEqual(msg.confidence, 0.0)
        self.assertLessEqual(msg.confidence, 1.0)
        self.assertTrue(len(msg.evidence) > 0)
        self.assertEqual(msg.sender, "IntrusionDetectionAgent")

    def test_message_json_serialization(self):
        sample_event = {
            "network_packet_size": 350,
            "protocol_type": "TCP",
            "login_attempts": 1,
            "session_duration": 500.0,
            "ip_reputation_score": 0.90,
            "failed_logins": 0,
            "browser_type": "Firefox",
            "unusual_time_access": 0
        }
        msg = self.agent.process_event("EVT-SERIALIZE", sample_event)
        json_payload = msg.to_json()
        self.assertIn("EVT-SERIALIZE", json_payload)
        reconstructed = Agent1Message.from_json(json_payload)
        self.assertEqual(reconstructed.event_id, msg.event_id)
        self.assertEqual(reconstructed.confidence, msg.confidence)


if __name__ == "__main__":
    unittest.main()
