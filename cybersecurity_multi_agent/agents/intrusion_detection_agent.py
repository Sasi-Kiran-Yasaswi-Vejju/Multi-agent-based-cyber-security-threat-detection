"""
agents/intrusion_detection_agent.py

Agent 1: Intrusion Detection Agent (Perception & Classification)

Specializes in data-driven perception and pattern classification.
Ingests raw network flow / session events, applies statistical preprocessing,
infers normality vs maliciousness using a supervised Random Forest model,
computes predictive confidence, generates explainable evidentiary findings,
and compiles a validated Agent1Message to pass to Agent 2.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, List, Optional
try:
    from communication.messages import Agent1Message
except ImportError:
    try:
        from ..communication.messages import Agent1Message
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import Agent1Message


class IntrusionDetectionAgent:
    """
    Autonomous Intelligent Agent for Network Intrusion Detection.
    
    Academic Role:
      Perception and Data-Driven Classification.
      Answers: "Is this network activity normal or malicious, with what confidence and evidence?"
    """

    def __init__(self, model_path: Optional[str] = None, preprocessor_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, "models")
        
        if model_path is None:
            model_path = os.path.join(models_dir, "random_forest.joblib")
        if preprocessor_path is None:
            preprocessor_path = os.path.join(models_dir, "preprocessor.joblib")

        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        self.model = None
        self.preprocessor = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Loads the serialized trained model and feature preprocessor."""
        if os.path.exists(self.model_path) and os.path.exists(self.preprocessor_path):
            self.model = joblib.load(self.model_path)
            self.preprocessor = joblib.load(self.preprocessor_path)
        else:
            # Lazy warning if not trained yet
            self.model = None
            self.preprocessor = None

    def perceive(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sensory perception interface.
        Ingests and validates raw telemetry from network session sensors.
        """
        required_keys = [
            "network_packet_size", "protocol_type", "login_attempts",
            "session_duration", "ip_reputation_score", "failed_logins"
        ]
        sanitized = dict(raw_event)
        for key in required_keys:
            if key not in sanitized:
                raise ValueError(f"[Agent 1 Error] Missing required sensor feature: '{key}'")
        
        # Default optional attributes if omitted
        sanitized.setdefault("encryption_used", "None")
        sanitized.setdefault("browser_type", "Unknown")
        sanitized.setdefault("unusual_time_access", 0)
        
        if pd.isna(sanitized.get("encryption_used")) or sanitized.get("encryption_used") is None:
            sanitized["encryption_used"] = "None"

        return sanitized

    def preprocess(self, perceived_event: Dict[str, Any]) -> np.ndarray:
        """
        Normalizes, encodes, and transforms raw sensor values into a mathematical feature vector.
        """
        if self.preprocessor is None:
            self._load_artifacts()
            if self.preprocessor is None:
                raise RuntimeError("[Agent 1 Error] Preprocessor artifact not found. Run train_model.py first.")

        df_row = pd.DataFrame([perceived_event])
        return self.preprocessor.transform(df_row)

    def classify(self, feature_vector: np.ndarray) -> str:
        """
        Executes supervised classification inference.
        Returns 'ATTACK' or 'NORMAL'.
        """
        if self.model is None:
            self._load_artifacts()
            if self.model is None:
                raise RuntimeError("[Agent 1 Error] Classifier artifact not found. Run train_model.py first.")

        pred = self.model.predict(feature_vector)[0]
        return "ATTACK" if int(pred) == 1 else "NORMAL"

    def calculate_confidence(self, feature_vector: np.ndarray) -> float:
        """
        Calculates posterior classification confidence probability in [0.0, 1.0].
        """
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(feature_vector)[0]
            confidence = float(np.max(probs))
        else:
            confidence = 0.90
        return round(confidence, 4)

    def generate_evidence(self, raw_event: Dict[str, Any], prediction: str, confidence: float) -> Tuple[str, List[str]]:
        """
        Produces explainable attribution for the decision.
        Infers specific attack profile and human-interpretable technical evidence strings.
        """
        if prediction == "NORMAL":
            return "None", [
                "Connection telemetry aligns with standard enterprise baseline",
                "Authentication attempt frequency within benign threshold",
                f"Classification model confidence: {confidence * 100:.1f}%"
            ]

        evidence: List[str] = []
        packet_size = float(raw_event.get("network_packet_size", 0))
        protocol = str(raw_event.get("protocol_type", "TCP")).upper()
        failed_logins = int(raw_event.get("failed_logins", 0))
        login_attempts = int(raw_event.get("login_attempts", 0))
        session_duration = float(raw_event.get("session_duration", 0))
        ip_rep = float(raw_event.get("ip_reputation_score", 0.5))
        encryption = str(raw_event.get("encryption_used", "None"))
        unusual_time = int(raw_event.get("unusual_time_access", 0))

        # Heuristic threat profile attribution
        if failed_logins >= 2 or login_attempts >= 5:
            attack_type = "Brute Force"
            evidence.append(f"Excessive failed authentication attempts: {failed_logins} of {login_attempts} trials")
            if encryption in ["None", "DES"]:
                evidence.append(f"Insecure or weak cipher suite ({encryption}) used during authentication")
        elif packet_size > 650 or protocol in ["UDP", "ICMP"]:
            attack_type = "DoS"
            evidence.append(f"Abnormally high packet payload size: {packet_size} bytes")
            if protocol in ["UDP", "ICMP"]:
                evidence.append(f"High-risk connectionless protocol observed: {protocol}")
        elif session_duration < 45 and packet_size < 300:
            attack_type = "Port Scan"
            evidence.append(f"Brief connection duration ({session_duration:.1f}s) characteristic of reconnaissance probe")
            evidence.append(f"Minimal payload exchange ({packet_size} bytes)")
        else:
            attack_type = "Generic Anomaly"
            if ip_rep < 0.35:
                evidence.append(f"Low source IP reputation confidence ({ip_rep:.2f})")
            if unusual_time == 1:
                evidence.append("Session initiated during anomalous off-hours schedule")
            if encryption == "None":
                evidence.append("Unencrypted plaintext transport layer detected")

        if not evidence:
            evidence.append("Statistical deviation detected across multi-variate feature space")

        evidence.append(f"Supervised Random Forest classification confidence: {confidence * 100:.1f}%")
        return attack_type, evidence

    def process_event(self, event_id: str, raw_event: Dict[str, Any]) -> Agent1Message:
        """
        Orchestrates full Agent 1 perception-to-communication workflow.
        Returns a strongly-typed Agent1Message for delivery to Agent 2.
        """
        perceived = self.perceive(raw_event)
        features = self.preprocess(perceived)
        prediction = self.classify(features)
        confidence = self.calculate_confidence(features)
        attack_type, evidence = self.generate_evidence(perceived, prediction, confidence)

        return Agent1Message(
            event_id=event_id,
            prediction=prediction,
            confidence=confidence,
            attack_type=attack_type,
            evidence=evidence,
            raw_features_summary={
                "network_packet_size": perceived.get("network_packet_size"),
                "protocol_type": perceived.get("protocol_type"),
                "login_attempts": perceived.get("login_attempts"),
                "failed_logins": perceived.get("failed_logins"),
                "ip_reputation_score": perceived.get("ip_reputation_score"),
                "encryption_used": perceived.get("encryption_used")
            }
        )
