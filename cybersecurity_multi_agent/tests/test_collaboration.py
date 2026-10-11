"""
tests/test_collaboration.py

Multi-Agent Collaboration, Dynamic Interaction, and Communication Tests.
Validates:
  1. Full 4-Agent collaborative lifecycle: A1 -> A2 -> A3 -> A4 -> Orchestrator.
  2. Smart routing pruning: Benign telemetry exits early, saving 3 agent calls.
  3. Backward communication loop: Agent 4 queries Agent 2 for missing asset criticality.
  4. CISA KEV weaponized exploit elevation to CRITICAL priority.
  5. Multi-agent communication trace integrity and auditability.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from orchestration.orchestrator import MultiAgentOrchestrator
from communication.messages import MessageType


class TestMultiAgentCollaboration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.orchestrator = MultiAgentOrchestrator(benign_confidence_threshold=0.80)

    def test_full_four_agent_malicious_workflow(self):
        """Scenario: Credential Brute Force against Core Database triggers all 4 agents."""
        raw_event = {
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
        state = self.orchestrator.run_investigation(
            event_id="EVT-COLLAB-01",
            raw_event=raw_event,
            target_asset="CORE_DATABASE"
        )
        self.assertEqual(state.status, "RESOLVED")
        self.assertEqual(state.investigation_depth, 4)
        self.assertEqual(state.unnecessary_calls_avoided, 0)
        self.assertTrue(state.total_agent_calls >= 4)

        # Verify all 4 agents produced results
        self.assertIn("agent_1", state.agent_results)
        self.assertIn("agent_2", state.agent_results)
        self.assertIn("agent_3", state.agent_results)
        self.assertIn("agent_4", state.agent_results)

        # Check Agent 1 detection
        self.assertEqual(state.agent_results["agent_1"]["prediction"], "ATTACK")
        # Check Agent 3 ATT&CK technique
        self.assertEqual(state.agent_results["agent_3"]["primary_technique_id"], "T1110")
        # Check Agent 4 decision
        self.assertEqual(state.decisions[0]["primary_mitigation"], "BLOCK_SOURCE_IP")
        self.assertTrue(state.decisions[0]["risk_score"] > 60.0)

    def test_smart_routing_benign_early_exit(self):
        """Scenario: High-confidence Benign session stops at Agent 1, avoiding Agents 2-4."""
        raw_event = {
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
        state = self.orchestrator.run_investigation(
            event_id="EVT-BENIGN-01",
            raw_event=raw_event,
            target_asset="LOW_VALUE_WORKSTATION"
        )
        self.assertEqual(state.status, "CLOSED_BENIGN")
        self.assertEqual(state.investigation_depth, 1)
        self.assertEqual(state.unnecessary_calls_avoided, 3)
        self.assertEqual(state.total_agent_calls, 1)
        # Verify Agents 2, 3, and 4 were NOT invoked
        self.assertEqual(state.agent_results["agent_2"], {})
        self.assertEqual(state.agent_results["agent_3"], {})
        self.assertEqual(state.agent_results["agent_4"], {})

    def test_backward_communication_asset_clarification(self):
        """Scenario: Missing asset context triggers Agent 4 -> Agent 2 -> Agent 4 backward resolution."""
        raw_event = {
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
        state = self.orchestrator.run_investigation(
            event_id="EVT-UNKNOWN-ASSET-01",
            raw_event=raw_event,
            target_asset="UNKNOWN"
        )
        self.assertEqual(state.status, "RESOLVED")
        # Check that communication trace contains the backward clarification messages
        msg_types = [m["message_type"] for m in state.communication_history]
        self.assertIn(MessageType.CLARIFICATION_REQUEST, msg_types)
        self.assertIn(MessageType.CLARIFICATION_RESPONSE, msg_types)

        # Check sender & receiver pairs for the clarification
        clarification_pairs = [
            (m["sender"], m["receiver"])
            for m in state.communication_history
            if m["message_type"] in [MessageType.CLARIFICATION_REQUEST, MessageType.CLARIFICATION_RESPONSE]
        ]
        self.assertIn(("agent_4", "agent_2"), clarification_pairs)
        self.assertIn(("agent_2", "agent_4"), clarification_pairs)

    def test_cisa_kev_weaponized_exploit_elevation(self):
        """Scenario: Event targeting CVE-2026-88779 triggers CISA KEV priority elevation."""
        raw_event = {
            "network_packet_size": 1200,
            "protocol_type": "TCP",
            "login_attempts": 2,
            "session_duration": 34.0,
            "ip_reputation_score": 0.05,
            "failed_logins": 0,
            "browser_type": "Unknown",
            "unusual_time_access": 1,
            "encryption_used": "None",
            "cve": "CVE-2026-88779"
        }
        state = self.orchestrator.run_investigation(
            event_id="EVT-KEV-01",
            raw_event=raw_event,
            target_asset="DMZ_WEB_SERVER"
        )
        self.assertEqual(state.status, "RESOLVED")
        # Agent 3 must have flagged CISA KEV
        vuln_intel = state.agent_results["agent_3"]["vulnerability_intel"]
        self.assertTrue(vuln_intel["is_known_exploited"])
        self.assertEqual(vuln_intel["cve_id"], "CVE-2026-88779")
        # Agent 4 must have elevated to CRITICAL
        self.assertEqual(state.decisions[0]["risk_level"], "CRITICAL")
        self.assertTrue(state.decisions[0]["risk_score"] >= 75.0)

    def test_communication_trace_auditability(self):
        """Scenario: Verifies strictly typed, timestamped, traceable message log."""
        raw_event = {
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
        state = self.orchestrator.run_investigation(
            event_id="EVT-TRACE-01",
            raw_event=raw_event,
            target_asset="CORE_DATABASE"
        )
        self.assertTrue(len(state.communication_history) >= 4)
        for msg_record in state.communication_history:
            self.assertIsNotNone(msg_record["sender"])
            self.assertIsNotNone(msg_record["receiver"])
            self.assertIsNotNone(msg_record["message_type"])
            self.assertIsNotNone(msg_record["timestamp"])


if __name__ == "__main__":
    unittest.main()
