"""
tests/test_end_to_end.py

Comprehensive End-to-End Test Suite for Multi-Agent Cybersecurity System.
Validates all 12 required incident scenarios:
  1. Benign normal enterprise telemetry
  2. Credential Brute Force attack
  3. Port Scan reconnaissance probe
  4. Volumetric Denial of Service (DoS)
  5. Web Application Exploit (SQL Injection)
  6. Command & Control Botnet activity
  7. Generic Anomaly / Unknown attack
  8. Confirmed Weaponized CISA KEV Vulnerability
  9. Conflicting evidence / Cross-agent disagreement
  10. Missing asset information (backward clarification)
  11. Low-confidence detection triggering secondary investigation
  12. High-confidence critical enterprise attack
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from orchestration.orchestrator import MultiAgentOrchestrator
from communication.messages import MessageType


class TestEndToEndIncidents(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.orch = MultiAgentOrchestrator(benign_confidence_threshold=0.80)

    # 1. Benign Traffic
    def test_scenario_01_benign_traffic(self):
        event = {
            "network_packet_size": 472, "protocol_type": "TCP", "login_attempts": 3,
            "session_duration": 1557.9, "ip_reputation_score": 0.301, "failed_logins": 0,
            "browser_type": "Firefox", "unusual_time_access": 0, "encryption_used": "DES"
        }
        state = self.orch.run_investigation("SCENARIO-01", event, "LOW_VALUE_WORKSTATION")
        self.assertEqual(state.status, "CLOSED_BENIGN")
        self.assertEqual(state.unnecessary_calls_avoided, 3)

    # 2. Brute Force
    def test_scenario_02_brute_force(self):
        event = {
            "network_packet_size": 297, "protocol_type": "TCP", "login_attempts": 8,
            "session_duration": 1421.4, "ip_reputation_score": 0.345, "failed_logins": 3,
            "browser_type": "Firefox", "unusual_time_access": 1, "encryption_used": "AES"
        }
        state = self.orch.run_investigation("SCENARIO-02", event, "CORE_DATABASE")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.agent_results["agent_1"]["attack_type"], "Brute Force")
        self.assertEqual(state.agent_results["agent_3"]["primary_technique_id"], "T1110")

    # 3. Port Scan
    def test_scenario_03_port_scan(self):
        event = {
            "network_packet_size": 250, "protocol_type": "TCP", "login_attempts": 4,
            "session_duration": 30.0, "ip_reputation_score": 0.150, "failed_logins": 0,
            "browser_type": "Unknown", "unusual_time_access": 0, "encryption_used": "DES"
        }
        state = self.orch.run_investigation("SCENARIO-03", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.status, "RESOLVED")
        self.assertIn(state.agent_results["agent_1"]["attack_type"], ["Port Scan", "Generic Anomaly"])
        self.assertIn(state.decisions[0]["primary_mitigation"], ["BLOCK_SOURCE_IP", "THROTTLE_CONNECTION", "ISOLATE_HOST_ENDPOINT"])

    # 4. Volumetric DoS
    def test_scenario_04_dos_flood(self):
        event = {
            "network_packet_size": 850, "protocol_type": "UDP", "login_attempts": 4,
            "session_duration": 601.2, "ip_reputation_score": 0.120, "failed_logins": 0,
            "browser_type": "Unknown", "unusual_time_access": 0, "encryption_used": "DES"
        }
        state = self.orch.run_investigation("SCENARIO-04", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.agent_results["agent_1"]["attack_type"], "DoS")
        self.assertTrue(len(state.agent_results["agent_3"]["matched_techniques"]) > 0)

    # 5. Web Attack (SQL Injection)
    def test_scenario_05_web_attack(self):
        event = {
            "network_packet_size": 600, "protocol_type": "TCP", "login_attempts": 2,
            "session_duration": 120.0, "ip_reputation_score": 0.150, "failed_logins": 1,
            "browser_type": "Chrome", "unusual_time_access": 1, "encryption_used": "AES",
            "attack_hint": "Web Attack"
        }
        state = self.orch.run_investigation("SCENARIO-05", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.agent_results["agent_1"]["attack_type"], "Web Attack")
        self.assertTrue(len(state.agent_results["agent_3"]["matched_techniques"]) > 0)

    # 6. Botnet Command and Control
    def test_scenario_06_botnet(self):
        event = {
            "network_packet_size": 320, "protocol_type": "TCP", "login_attempts": 4,
            "session_duration": 2800.0, "ip_reputation_score": 0.080, "failed_logins": 0,
            "browser_type": "Unknown", "unusual_time_access": 1, "encryption_used": "None",
            "is_bot": 1
        }
        state = self.orch.run_investigation("SCENARIO-06", event, "INTERNAL_HOST")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.agent_results["agent_1"]["attack_type"], "Botnet")

    # 7. Generic Anomaly / Unknown Attack
    def test_scenario_07_unknown_anomaly(self):
        event = {
            "network_packet_size": 500, "protocol_type": "TCP", "login_attempts": 4,
            "session_duration": 300.0, "ip_reputation_score": 0.150, "failed_logins": 0,
            "browser_type": "Unknown", "unusual_time_access": 1, "encryption_used": "None"
        }
        state = self.orch.run_investigation("SCENARIO-07", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.agent_results["agent_1"]["attack_type"], "Generic Anomaly")

    # 8. Known Exploited Vulnerability (CISA KEV)
    def test_scenario_08_cisa_kev_exploit(self):
        event = {
            "network_packet_size": 950, "protocol_type": "TCP", "login_attempts": 1,
            "session_duration": 18.0, "ip_reputation_score": 0.020, "failed_logins": 0,
            "browser_type": "Unknown", "unusual_time_access": 1, "encryption_used": "None",
            "cve": "CVE-2026-88779"
        }
        state = self.orch.run_investigation("SCENARIO-08", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.status, "RESOLVED")
        vuln = state.agent_results["agent_3"]["vulnerability_intel"]
        self.assertTrue(vuln["is_known_exploited"])
        self.assertEqual(state.decisions[0]["risk_level"], "CRITICAL")

    # 9. Conflicting Evidence / Disagreement
    def test_scenario_09_conflicting_evidence(self):
        event = {
            "network_packet_size": 610, "protocol_type": "TCP", "login_attempts": 1,
            "session_duration": 400.0, "ip_reputation_score": 0.200, "failed_logins": 0,
            "browser_type": "Chrome", "unusual_time_access": 1, "encryption_used": "None"
        }
        state = self.orch.run_investigation("SCENARIO-09", event, "CORE_DATABASE")
        self.assertEqual(state.status, "RESOLVED")
        self.assertIn("agent_4", state.agent_results)
        self.assertTrue(len(state.evidence) > 0)

    # 10. Missing Asset Criticality (Backward Clarification)
    def test_scenario_10_missing_asset_clarification(self):
        event = {
            "network_packet_size": 297, "protocol_type": "TCP", "login_attempts": 8,
            "session_duration": 1421.4, "ip_reputation_score": 0.345, "failed_logins": 3,
            "browser_type": "Firefox", "unusual_time_access": 1, "encryption_used": "AES"
        }
        state = self.orch.run_investigation("SCENARIO-10", event, "UNKNOWN")
        self.assertEqual(state.status, "RESOLVED")
        # Check backward clarification messages
        msg_types = [m["message_type"] for m in state.communication_history]
        self.assertIn(MessageType.CLARIFICATION_REQUEST, msg_types)
        self.assertIn(MessageType.CLARIFICATION_RESPONSE, msg_types)

    # 11. Low Confidence Detection Triggering Full Pipeline
    def test_scenario_11_low_confidence_investigation(self):
        event = {
            "network_packet_size": 520, "protocol_type": "TCP", "login_attempts": 2,
            "session_duration": 310.0, "ip_reputation_score": 0.450, "failed_logins": 0,
            "browser_type": "Chrome", "unusual_time_access": 0, "encryption_used": "DES"
        }
        # Force low threshold so borderline cases get investigated
        orch_strict = MultiAgentOrchestrator(benign_confidence_threshold=0.99)
        state = orch_strict.run_investigation("SCENARIO-11", event, "DMZ_WEB_SERVER")
        self.assertEqual(state.investigation_depth, 4)

    # 12. High-Confidence Critical Attack
    def test_scenario_12_critical_high_confidence_attack(self):
        event = {
            "network_packet_size": 1100, "protocol_type": "UDP", "login_attempts": 10,
            "session_duration": 4800.0, "ip_reputation_score": 0.010, "failed_logins": 5,
            "browser_type": "Unknown", "unusual_time_access": 1, "encryption_used": "None"
        }
        state = self.orch.run_investigation("SCENARIO-12", event, "DOMAIN_CONTROLLER")
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.decisions[0]["risk_level"], "CRITICAL")
        self.assertTrue(state.decisions[0]["risk_score"] >= 75.0)


if __name__ == "__main__":
    unittest.main()
