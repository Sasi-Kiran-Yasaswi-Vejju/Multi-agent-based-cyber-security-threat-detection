"""
search/response_graph.py

Formulates the cybersecurity response planning state-space graph.
Represents states, action transitions, edge operational costs,
and admissible/consistent heuristic risk estimates.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class Edge:
    """Directed edge in the response state space."""
    target_state: str
    action_name: str
    operational_cost: float
    description: str


class ResponseGraph:
    """
    Formal state-space response graph G = (V, E).
    
    States (V):
      - ATTACK_DETECTED (Initial state)
      - PASSIVE_TRACKING
      - THREAT_CONFIRMED
      - SOURCE_BLOCKED
      - HOST_ISOLATED
      - SOC_ALERTED
      - INCIDENT_CONTROLLED (Goal state)
      
    Edge Costs c(u, v):
      Reflects real-world operational disruption, service friction,
      and engineering labor.
      
    Heuristic h(n):
      Under-estimates the remaining cost to reach INCIDENT_CONTROLLED,
      satisfying the admissibility condition h(n) <= h*(n).
    """

    START_STATE = "ATTACK_DETECTED"
    GOAL_STATE = "INCIDENT_CONTROLLED"

    def __init__(self, threat_type: str = "DoS", severity: str = "HIGH", target_criticality: float = 1.0):
        self.threat_type = threat_type
        self.severity = severity
        self.target_criticality = target_criticality
        self.adj_list: Dict[str, List[Edge]] = {}
        self.heuristics: Dict[str, float] = {}
        self._build_graph()

    def _build_graph(self):
        """Constructs the canonical response graph with contextual cost weighting."""
        
        # Base operational costs for defensive actions:
        # MONITOR: 1 (zero user impact, passive logging)
        # VERIFY_MITIGATION: 2 (automated health-check probe)
        # VERIFY: 3 (low user friction, challenge-response / MFA)
        # MANUAL_OVERRIDE: 4 (SOC analyst triage time)
        # BLOCK_SOURCE: 5 (moderate impact, potential shared IP proxy collateral)
        # ESCALATE: 8 (high cost, paging senior incident responders)
        # ISOLATE_HOST: 10 (highest impact, immediate service downtime)
        
        c_monitor = 1.0
        c_verify_mitigation = 2.0
        c_verify = 3.0
        c_override = 4.0
        c_block = 5.0
        c_escalate = 8.0
        c_isolate = 10.0

        # Adjust cost if the target is mission critical (e.g. host isolation costs more on critical DB)
        if self.target_criticality > 1.2:
            c_isolate = 14.0

        self.adj_list = {
            "ATTACK_DETECTED": [
                Edge("PASSIVE_TRACKING", "MONITOR", c_monitor, "Deploy passive telemetry and packet captures"),
                Edge("THREAT_CONFIRMED", "VERIFY", c_verify, "Trigger identity challenge or packet inspection"),
                Edge("SOC_ALERTED", "ESCALATE", c_escalate, "Directly page Tier-3 SOC on-call incident response"),
            ],
            "PASSIVE_TRACKING": [
                Edge("SOC_ALERTED", "ESCALATE", c_escalate, "Escalate unresolved anomalous flow to Tier-3 SOC"),
            ],
            "THREAT_CONFIRMED": [
                Edge("SOURCE_BLOCKED", "BLOCK_SOURCE", c_block, "Inject firewall drop rule for offending IP address"),
                Edge("HOST_ISOLATED", "ISOLATE_HOST", c_isolate, "Quarantine compromised internal host endpoint"),
            ],
            "SOURCE_BLOCKED": [
                Edge("INCIDENT_CONTROLLED", "VERIFY_MITIGATION", c_verify_mitigation, "Automated probe confirms malicious traffic dropped"),
            ],
            "HOST_ISOLATED": [
                Edge("INCIDENT_CONTROLLED", "VERIFY_MITIGATION", c_verify_mitigation, "Confirm lateral network movement severed"),
            ],
            "SOC_ALERTED": [
                Edge("INCIDENT_CONTROLLED", "MANUAL_OVERRIDE", c_override, "Human analyst manually patches and resolves incident"),
            ],
            "INCIDENT_CONTROLLED": []
        }

        # Context-dependent dynamic link: For low-severity threats, passive tracking can directly self-resolve
        if self.severity == "LOW":
            self.adj_list["PASSIVE_TRACKING"].append(
                Edge("INCIDENT_CONTROLLED", "CLOSE_BENIGN", 1.0, "Auto-close after timeout with no further anomalies")
            )

        # Admissible heuristics h(n) <= h*(n):
        # True minimum costs h*(n) from each state:
        # ATTACK_DETECTED: min(VERIFY (3) + BLOCK (5) + VERIFY_MIT (2) = 10; ESCALATE (8) + MANUAL (4) = 12) = 10
        # THREAT_CONFIRMED: BLOCK (5) + VERIFY_MIT (2) = 7
        # SOURCE_BLOCKED: VERIFY_MIT (2) = 2
        # HOST_ISOLATED: VERIFY_MIT (2) = 2
        # SOC_ALERTED: MANUAL (4) = 4
        # PASSIVE_TRACKING: ESCALATE (8) + MANUAL (4) = 12 (or 1 if LOW)
        # INCIDENT_CONTROLLED: 0
        
        self.heuristics = {
            "ATTACK_DETECTED": 8.0,
            "THREAT_CONFIRMED": 7.0,
            "PASSIVE_TRACKING": 1.0 if self.severity == "LOW" else 10.0,
            "SOURCE_BLOCKED": 2.0,
            "HOST_ISOLATED": 2.0,
            "SOC_ALERTED": 4.0,
            "INCIDENT_CONTROLLED": 0.0
        }

    def get_neighbors(self, state: str) -> List[Edge]:
        """Returns outward transition edges from a state."""
        return self.adj_list.get(state, [])

    def get_heuristic(self, state: str) -> float:
        """Returns the admissible heuristic risk estimate for a given state."""
        return self.heuristics.get(state, 0.0)

    def is_goal(self, state: str) -> bool:
        """Determines if the state is the goal state."""
        return state == self.GOAL_STATE
