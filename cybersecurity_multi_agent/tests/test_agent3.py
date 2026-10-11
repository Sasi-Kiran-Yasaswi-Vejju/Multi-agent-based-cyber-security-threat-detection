"""
tests/test_agent3.py

Unit tests for Agent 3 (ThreatIntelligenceAgent).
Validates Keyword Search, Semantic Search, BFS Graph Expansion,
CISA KEV catalog lookup, confidence estimation, and structured message output.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from communication.messages import AgentMessage, MessageType


class TestThreatIntelligenceAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = ThreatIntelligenceAgent()

    def test_keyword_search_known_technique(self):
        matches = self.agent.search_keyword(["T1110", "Brute Force"], limit=3)
        self.assertTrue(len(matches) > 0)
        top_id, score = matches[0]
        self.assertEqual(top_id, "T1110")
        self.assertAlmostEqual(score, 1.0, places=2)

    def test_semantic_search_description(self):
        matches = self.agent.search_semantic("repeated failed password authentication trials", limit=5)
        self.assertTrue(len(matches) > 0)
        top_id, score = matches[0]
        self.assertTrue(score > 0.20)
        # Verify retrieved top technique is an authentic ATT&CK technique dealing with authentication/credentials
        tech_meta = self.agent.attack_kb.get_technique(top_id)
        self.assertIsNotNone(tech_meta)
        tactics = tech_meta.get("tactics", [])
        name = tech_meta.get("name", "").lower()
        self.assertTrue(
            "credential-access" in tactics
            or "defense-evasion" in tactics
            or "authentication" in name
            or "password" in name
        )

    def test_bfs_graph_expansion(self):
        bfs_res = self.agent.search_bfs_relationships("T1110", depth=1)
        self.assertTrue(bfs_res["found"])
        self.assertEqual(bfs_res["start_node"], "T1110")
        self.assertTrue(bfs_res["total_nodes_visited"] > 5)
        self.assertTrue(len(bfs_res["mitigations"]) > 0)
        # Check password policies or account management mitigation
        mit_names = [m["name"].lower() for m in bfs_res["mitigations"]]
        self.assertTrue(any("password" in m or "account" in m or "multi-factor" in m for m in mit_names))

    def test_cisa_kev_known_exploited_cve(self):
        # CVE-2026-88779 is in the workspace CISA KEV catalog
        intel = self.agent.check_vulnerability_intelligence("CVE-2026-88779", [])
        self.assertTrue(intel["is_known_exploited"])
        self.assertEqual(intel["cve_id"], "CVE-2026-88779")
        self.assertEqual(intel["product"], "NetScaler")

    def test_cisa_kev_unlisted_cve(self):
        intel = self.agent.check_vulnerability_intelligence("CVE-1990-00001", [])
        self.assertFalse(intel["is_known_exploited"])
        self.assertEqual(intel["cve_id"], "CVE-1990-00001")

    def test_process_intelligence_request_emission(self):
        req = AgentMessage(
            message_type=MessageType.INTELLIGENCE_REQUEST,
            sender="agent_2",
            receiver="agent_3",
            incident_id="INC-UNIT-3",
            payload={
                "event_id": "EVT-003",
                "attack_type": "Brute Force",
                "indicators": ["Multiple failed login trials", "Insecure cipher"],
                "query_terms": ["Brute Force", "T1110"],
                "cve_id": None,
                "severity": "CRITICAL",
                "base_severity": 7,
                "target_asset": "CORE_DATABASE",
                "target_multiplier": 1.3
            }
        )
        response = self.agent.process_intelligence_request(req)
        self.assertEqual(response.message_type, MessageType.INTELLIGENCE_RESPONSE)
        self.assertEqual(response.sender, "agent_3")
        self.assertEqual(response.receiver, "agent_4")
        self.assertTrue(response.confidence > 0.5)
        self.assertEqual(response.payload["primary_technique_id"], "T1110")
        self.assertTrue(len(response.payload["tactics"]) > 0)
        self.assertTrue(len(response.payload["evidence"]) > 0)


if __name__ == "__main__":
    unittest.main()
