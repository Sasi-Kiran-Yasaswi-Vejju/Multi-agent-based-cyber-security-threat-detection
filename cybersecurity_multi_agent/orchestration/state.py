"""
orchestration/state.py

Shared Incident State for Multi-Agent Cybersecurity Threat Detection & Response.
Maintains global context, evidentiary history, inter-agent communication logs,
and metric tracking across all specialized agents.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import json
import uuid
from datetime import datetime, timezone


@dataclass
class IncidentState:
    """
    Central shared state object for an active cybersecurity incident.
    Enforces accountability, auditability, and structured state transitions.
    """
    incident_id: str
    status: str = "UNDER_INVESTIGATION"  # UNDER_INVESTIGATION, CLARIFYING, CLOSED_BENIGN, RESOLVED, ERROR
    event_id: str = "EVT-UNKNOWN"
    target_asset: str = "DMZ_WEB_SERVER"
    raw_event: Dict[str, Any] = field(default_factory=dict)
    
    agent_results: Dict[str, Any] = field(default_factory=lambda: {
        "agent_1": {},
        "agent_2": {},
        "agent_3": {},
        "agent_4": {}
    })
    
    confidence: Dict[str, float] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    pending_requests: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    communication_history: List[Dict[str, Any]] = field(default_factory=list)

    # Multi-Agent Performance Metrics
    total_agent_calls: int = 0
    unnecessary_calls_avoided: int = 0
    investigation_depth: int = 0
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None

    def record_message(self, message: Any):
        """Appends a transmitted message to the audit log."""
        if hasattr(message, "to_dict"):
            m_dict = message.to_dict()
        elif isinstance(message, dict):
            m_dict = message
        else:
            m_dict = {"raw": str(message)}

        self.communication_history.append({
            "message_id": m_dict.get("message_id"),
            "sender": m_dict.get("sender"),
            "receiver": m_dict.get("receiver"),
            "message_type": m_dict.get("message_type"),
            "priority": m_dict.get("priority"),
            "timestamp": m_dict.get("timestamp"),
            "summary": f"{m_dict.get('sender')} -> {m_dict.get('receiver')} [{m_dict.get('message_type')}]"
        })

    def add_evidence(self, items: List[str]):
        """Deduplicates and registers evidentiary findings."""
        for item in items:
            if item not in self.evidence:
                self.evidence.append(item)

    def record_agent_result(self, agent_id: str, result: Dict[str, Any], conf: float):
        """Stores structured output from a specialist agent."""
        self.agent_results[agent_id] = result
        self.confidence[agent_id] = round(conf, 4)
        self.total_agent_calls += 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)
