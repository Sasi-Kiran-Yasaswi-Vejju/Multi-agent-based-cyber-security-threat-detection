"""
communication/messages.py

Defines structured, strongly-typed message models exchanged between agents.
Direct memory sharing between agents is strictly disallowed; all inter-agent
communication must use these validated serialized structures.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json
import uuid
from datetime import datetime, timezone


@dataclass
class Agent1Message:
    """
    Message emitted by Agent 1 (IntrusionDetectionAgent) and delivered to Agent 2.
    Represents the output of data-driven perception and supervised classification.
    """
    event_id: str
    prediction: str  # "ATTACK" or "NORMAL"
    confidence: float  # [0.0, 1.0]
    attack_type: str  # "DoS", "Brute Force", "Port Scan", "Generic Anomaly", or "None"
    evidence: List[str] = field(default_factory=list)
    raw_features_summary: Dict[str, Any] = field(default_factory=dict)
    sender: str = "IntrusionDetectionAgent"
    receiver: str = "ThreatAnalysisResponseAgent"
    message_id: str = field(default_factory=lambda: f"MSG-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        """Serializes the message into an exchangeable JSON string."""
        return json.dumps(asdict(self), indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """Converts message into a Python dictionary."""
        return asdict(self)

    @classmethod
    def from_json(cls, json_str: str) -> "Agent1Message":
        """Deserializes a JSON string into an Agent1Message instance."""
        data = json.loads(json_str)
        return cls(**data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Agent1Message":
        """Constructs an Agent1Message from a dictionary."""
        return cls(**data)


@dataclass
class SearchBenchmark:
    """Performance metrics recorded for a search algorithm execution."""
    algorithm: str
    path: List[str]
    total_cost: float
    nodes_explored: int
    execution_time_ms: float
    goal_found: bool


@dataclass
class Agent2Response:
    """
    Structured mitigation decision produced by Agent 2 (ThreatAnalysisResponseAgent).
    Contains threat classification, CIA Triad mapping, risk score, search evaluation,
    and the selected operational response action.
    """
    referenced_event_id: str
    threat_category: str
    impacted_property: str  # "Confidentiality", "Integrity", "Availability", or "None"
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: float  # [0.0, 100.0]
    selected_response: str  # e.g., "BLOCK_SOURCE", "ISOLATE_HOST", "MONITOR"
    selected_algorithm: str  # "A*" or "BFS"
    execution_path: List[str]
    total_path_cost: float
    nodes_explored: int
    execution_time_ms: float
    search_comparison: Dict[str, Any]
    reason: str
    sender: str = "ThreatAnalysisResponseAgent"
    response_id: str = field(default_factory=lambda: f"RES-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        """Serializes the response into a JSON string."""
        return json.dumps(asdict(self), indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """Converts response into a Python dictionary."""
        return asdict(self)

    @classmethod
    def from_json(cls, json_str: str) -> "Agent2Response":
        """Deserializes JSON string into an Agent2Response instance."""
        data = json.loads(json_str)
        return cls(**data)
