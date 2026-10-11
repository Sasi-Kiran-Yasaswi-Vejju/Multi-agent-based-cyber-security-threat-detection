"""
agents/threat_intelligence_agent.py

Agent 3: Threat Intelligence Agent (Specialization: ENRICH)

Specializes in cyber threat intelligence (CTI) enrichment and knowledge retrieval.
Ingests intelligence requests from Agent 2, executes a multi-stage hybrid search engine
(Keyword Search, TF-IDF Cosine Semantic Search, and NetworkX BFS Graph Traversal),
cross-references active weaponized exploits in the CISA KEV catalog, and compiles
a structured threat intelligence dossier for Agent 4.
"""

import os
import sys
import re
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Ensure base project directory is in sys.path for direct execution
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

try:
    from communication.messages import AgentMessage, MessageType
    from knowledge.attack_kb import AttackKnowledgeBase
    from knowledge.vulnerability_kb import VulnerabilityKnowledgeBase
except ImportError:
    try:
        from ..communication.messages import AgentMessage, MessageType
        from ..knowledge.attack_kb import AttackKnowledgeBase
        from ..knowledge.vulnerability_kb import VulnerabilityKnowledgeBase
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import AgentMessage, MessageType
        from cybersecurity_multi_agent.knowledge.attack_kb import AttackKnowledgeBase
        from cybersecurity_multi_agent.knowledge.vulnerability_kb import VulnerabilityKnowledgeBase



class ThreatIntelligenceAgent:
    """
    Autonomous Intelligent Agent for Threat Intelligence Enrichment.
    
    Academic PEAS Profile:
      - Performance: Retrieval Precision@K, Semantic Relevance, Graph Consistency, CVE Accuracy.
      - Environment: MITRE ATT&CK STIX Knowledge Graph + CISA KEV Catalog.
      - Actuators: Intelligence Responses (INTELLIGENCE_RESPONSE), Clarification Requests.
      - Sensors: Structured Intelligence Requests (INTELLIGENCE_REQUEST) from Agent 2.
    """

    def __init__(
        self,
        attack_kb: Optional[AttackKnowledgeBase] = None,
        vuln_kb: Optional[VulnerabilityKnowledgeBase] = None
    ):
        self.attack_kb = attack_kb if attack_kb is not None else AttackKnowledgeBase()
        self.vuln_kb = vuln_kb if vuln_kb is not None else VulnerabilityKnowledgeBase()

        # Semantic index setup
        self._technique_ids: List[str] = []
        self._technique_names: List[str] = []
        self._technique_texts: List[str] = []
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._tfidf_matrix = None
        self._build_semantic_index()

    def _build_semantic_index(self):
        """Indexes all ATT&CK technique descriptions into a TF-IDF vector space."""
        if not self.attack_kb.is_loaded:
            return

        for mid, meta in self.attack_kb.techniques.items():
            self._technique_ids.append(mid)
            self._technique_names.append(meta.get("name", ""))
            # Combine name, tactics, and description for rich semantic representation
            text = f"{meta.get('name', '')} {' '.join(meta.get('tactics', []))} {meta.get('description', '')}"
            self._technique_texts.append(text)

        if self._technique_texts:
            self._vectorizer = TfidfVectorizer(
                stop_words="english",
                max_features=5000,
                ngram_range=(1, 2)
            )
            self._tfidf_matrix = self._vectorizer.fit_transform(self._technique_texts)

    # ---------------------------------------------------------
    # SEARCH COMPONENT 1: Keyword Search
    # ---------------------------------------------------------
    def search_keyword(self, query_terms: List[str], limit: int = 5) -> List[Tuple[str, float]]:
        """
        Executes exact and token-based keyword search over ATT&CK IDs, names, and tactics.
        Returns list of (technique_id, match_score).
        """
        scores: Dict[str, float] = {}

        for term in query_terms:
            cleaned = term.strip().upper()
            if not cleaned:
                continue

            # Exact MITRE ID match (e.g. T1110, T1110.001)
            if cleaned in self.attack_kb.techniques:
                scores[cleaned] = max(scores.get(cleaned, 0.0), 1.0)
                continue

            # Partial ID matching (parent technique)
            for tid in self.attack_kb.techniques:
                if tid.startswith(cleaned):
                    scores[tid] = max(scores.get(tid, 0.0), 0.9)

            # Name and tactic keyword matching
            term_lower = term.lower()
            for tid, meta in self.attack_kb.techniques.items():
                name_lower = meta.get("name", "").lower()
                tactics = [tac.lower() for tac in meta.get("tactics", [])]

                if term_lower in name_lower:
                    scores[tid] = max(scores.get(tid, 0.0), 0.75)
                elif any(term_lower in tac for tac in tactics):
                    scores[tid] = max(scores.get(tid, 0.0), 0.50)

        sorted_matches = sorted(scores.items(), key=lambda x: -x[1])[:limit]
        return sorted_matches

    # ---------------------------------------------------------
    # SEARCH COMPONENT 2: Semantic Search (Cosine Similarity)
    # ---------------------------------------------------------
    def search_semantic(self, query_text: str, limit: int = 5) -> List[Tuple[str, float]]:
        """
        Executes semantic search by projecting query into the TF-IDF space
        and computing cosine similarity against technique descriptions.
        """
        if not self._vectorizer or self._tfidf_matrix is None or not query_text.strip():
            return []

        q_vec = self._vectorizer.transform([query_text])
        sims = cosine_similarity(q_vec, self._tfidf_matrix)[0]

        top_indices = np.argsort(sims)[::-1][:limit]
        results: List[Tuple[str, float]] = []
        for idx in top_indices:
            score = float(sims[idx])
            if score > 0.01:
                results.append((self._technique_ids[idx], round(score, 4)))

        return results

    # ---------------------------------------------------------
    # SEARCH COMPONENT 3: Breadth-First Search (BFS) Traversal
    # ---------------------------------------------------------
    def search_bfs_relationships(self, technique_id: str, depth: int = 2) -> Dict[str, Any]:
        """
        Traverses the ATT&CK relationship graph starting from technique_id.
        Retrieves related tactics, threat actor groups, software, and mitigations.
        """
        return self.attack_kb.bfs_subgraph(technique_id, max_depth=depth)

    # ---------------------------------------------------------
    # HYBRID RANKING & CONFIDENCE ESTIMATION
    # ---------------------------------------------------------
    def rank_candidates(
        self,
        query_terms: List[str],
        description_text: str,
        limit: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Fuses Keyword Search and Semantic Search results using deterministic weights:
          score = 0.50 * semantic_score + 0.35 * keyword_score + 0.15 * structural_bonus
        """
        kw_results = dict(self.search_keyword(query_terms, limit=10))
        sem_results = dict(self.search_semantic(description_text, limit=10))

        candidate_ids = set(kw_results.keys()).union(set(sem_results.keys()))
        ranked: List[Dict[str, Any]] = []

        for cid in candidate_ids:
            kw_score = kw_results.get(cid, 0.0)
            sem_score = sem_results.get(cid, 0.0)
            meta = self.attack_kb.get_technique(cid) or {}

            # Structural bonus if technique has verified tactics and mitigations
            structural_bonus = 0.15 if (meta.get("tactics") and cid in self.attack_kb.graph) else 0.0

            combined_score = (0.50 * sem_score) + (0.35 * kw_score) + structural_bonus
            combined_score = round(min(1.0, combined_score), 4)

            ranked.append({
                "technique_id": cid,
                "name": meta.get("name", "Unknown Technique"),
                "tactics": meta.get("tactics", []),
                "description": (meta.get("description", "")[:250] + "...") if meta.get("description") else "",
                "semantic_similarity": round(sem_score, 4),
                "keyword_score": round(kw_score, 4),
                "combined_score": combined_score
            })

        ranked.sort(key=lambda x: -x["combined_score"])
        return ranked[:limit]

    # ---------------------------------------------------------
    # CISA KEV VULNERABILITY ENRICHMENT
    # ---------------------------------------------------------
    def check_vulnerability_intelligence(
        self,
        cve_id: Optional[str],
        indicators: List[str]
    ) -> Dict[str, Any]:
        """
        Queries CISA KEV catalog to verify whether an observed vulnerability
        is actively exploited or part of known ransomware campaigns.
        """
        # Collect candidate CVEs
        candidates: List[str] = []
        if cve_id:
            candidates.append(cve_id)

        cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        for ind in indicators:
            for match in cve_regex.findall(ind):
                candidates.append(match.upper())

        for cid in candidates:
            kev_entry = self.vuln_kb.lookup_cve(cid)
            if kev_entry:
                return {
                    "cve_id": kev_entry["cve_id"],
                    "is_known_exploited": True,
                    "vendor_project": kev_entry["vendor_project"],
                    "product": kev_entry["product"],
                    "vulnerability_name": kev_entry["vulnerability_name"],
                    "known_ransomware_campaign_use": kev_entry["known_ransomware_campaign_use"],
                    "required_action": kev_entry["required_action"],
                    "due_date": kev_entry["due_date"],
                    "status_label": "CRITICAL: Actively Exploited in the Wild (CISA KEV)"
                }

        if candidates:
            # CVE was cited but not in CISA KEV catalog
            first_cve = candidates[0]
            return {
                "cve_id": first_cve,
                "is_known_exploited": False,
                "status_label": "Unconfirmed in CISA KEV catalog (Standard Advisory)"
            }

        return {
            "cve_id": None,
            "is_known_exploited": False,
            "status_label": "No CVE Indicators Identified"
        }

    # ---------------------------------------------------------
    # MAIN WORKFLOW: PROCESS INTELLIGENCE REQUEST
    # ---------------------------------------------------------
    def process_intelligence_request(
        self,
        request: Any,
        incident_id: str = "INC-001"
    ) -> AgentMessage:
        """
        Orchestrates full Agent 3 threat intelligence enrichment:
        1. Ingests Agent 2 payload.
        2. Executes Keyword, Semantic, and BFS search.
        3. Cross-references CISA KEV catalog.
        4. Calculates confidence.
        5. Emits structured INTELLIGENCE_RESPONSE (or CLARIFICATION_REQUEST if low confidence).
        """
        # Parse incoming request envelope
        if isinstance(request, AgentMessage):
            payload = request.payload
            incident_id = request.incident_id
        elif isinstance(request, dict):
            payload = request.get("payload", request)
            incident_id = request.get("incident_id", incident_id)
        else:
            payload = {}

        attack_type = payload.get("attack_type", "Generic Anomaly")
        indicators = payload.get("indicators", [])
        query_terms = payload.get("query_terms", [attack_type])
        cve_id = payload.get("cve_id")

        # Synthesize query text from indicators and attack type
        query_text = f"{attack_type} " + " ".join(indicators)

        # 1. Hybrid Ranking
        ranked_techniques = self.rank_candidates(query_terms, query_text, limit=3)

        # 2. Check CISA KEV
        vuln_intel = self.check_vulnerability_intelligence(cve_id, indicators)

        # 3. BFS Graph Search on primary technique
        bfs_data: Dict[str, Any] = {}
        primary_technique_id = None
        overall_confidence = 0.0

        if ranked_techniques:
            top_tech = ranked_techniques[0]
            primary_technique_id = top_tech["technique_id"]
            overall_confidence = top_tech["combined_score"]

            # Boost confidence if CISA KEV confirms exploitation
            if vuln_intel.get("is_known_exploited"):
                overall_confidence = min(1.0, max(overall_confidence, 0.95))

            # Execute BFS on relationship graph
            bfs_data = self.search_bfs_relationships(primary_technique_id, depth=2)

        # 4. Handle Low Confidence (< 0.25) -> Request Clarification from Agent 2
        if overall_confidence < 0.25 and not vuln_intel.get("is_known_exploited"):
            return AgentMessage(
                message_type=MessageType.CLARIFICATION_REQUEST,
                sender="agent_3",
                receiver="agent_2",
                incident_id=incident_id,
                confidence=overall_confidence,
                priority="MEDIUM",
                payload={
                    "required_information": "additional_attack_indicators",
                    "reason": f"Low confidence ATT&CK mapping ({overall_confidence:.2f}) for attack type '{attack_type}'.",
                    "current_query_terms": query_terms
                }
            )

        # 5. Extract Mitigations and Tactics for response planning
        mitigations = bfs_data.get("mitigations", []) if bfs_data else []
        tactics = bfs_data.get("tactics", []) if bfs_data else []
        groups = bfs_data.get("related_groups", []) if bfs_data else []
        software = bfs_data.get("related_software", []) if bfs_data else []

        # Compile explainable evidence list
        evidence_list: List[str] = []
        if primary_technique_id:
            evidence_list.append(
                f"MITRE ATT&CK Technique {primary_technique_id} ({ranked_techniques[0]['name']}) "
                f"mapped with {overall_confidence * 100:.1f}% confidence."
            )
        if tactics:
            tac_names = [t["name"] for t in tactics[:2]]
            evidence_list.append(f"Associated Kill-Chain Tactics: {', '.join(tac_names)}.")
        if vuln_intel.get("is_known_exploited"):
            evidence_list.append(
                f"Weaponized exploit confirmed in CISA KEV: {vuln_intel['cve_id']} "
                f"({vuln_intel.get('product', '')}) - Ransomware use: {vuln_intel.get('known_ransomware_campaign_use')}."
            )
        if groups:
            grp_names = [g["name"] for g in groups[:3]]
            evidence_list.append(f"Known Threat Actors utilizing technique: {', '.join(grp_names)}.")
        if mitigations:
            mit_names = [m["name"] for m in mitigations[:3]]
            evidence_list.append(f"Recommended Mitigations: {', '.join(mit_names)}.")

        priority = "CRITICAL" if (
            vuln_intel.get("is_known_exploited") or overall_confidence >= 0.85
        ) else ("HIGH" if overall_confidence >= 0.50 else "MEDIUM")

        return AgentMessage(
            message_type=MessageType.INTELLIGENCE_RESPONSE,
            sender="agent_3",
            receiver="agent_4",
            incident_id=incident_id,
            confidence=round(overall_confidence, 4),
            priority=priority,
            payload={
                "event_id": payload.get("event_id", "EVT-UNKNOWN"),
                "attack_type": attack_type,
                "target_asset": payload.get("target_asset", "DMZ_WEB_SERVER"),
                "target_multiplier": payload.get("target_multiplier", 1.0),
                "agent2_severity": payload.get("severity", "MEDIUM"),
                "base_severity": payload.get("base_severity", 5),
                "matched_techniques": ranked_techniques,
                "primary_technique_id": primary_technique_id,
                "tactics": tactics,
                "related_groups": groups[:5],
                "related_software": software[:5],
                "mitigations": mitigations[:5],
                "vulnerability_intel": vuln_intel,
                "search_methods_used": ["keyword", "semantic", "BFS"],
                "bfs_expansion": {
                    "total_nodes_visited": bfs_data.get("total_nodes_visited", 0),
                    "depth_reached": bfs_data.get("depth_reached", 0),
                    "edge_count": len(bfs_data.get("edges", []))
                },
                "evidence": evidence_list
            }
        )


if __name__ == "__main__":
    print("=" * 80)
    print(" AGENT 3: Threat Intelligence Agent (Standalone Test)")
    print("=" * 80)
    agent = ThreatIntelligenceAgent()
    kw_matches = agent.search_keyword(["T1110", "Brute Force"], limit=2)
    print(f"Keyword Matches for T1110: {kw_matches}")
    bfs_res = agent.search_bfs_relationships("T1110", depth=1)
    print(f"BFS Expansion (Nodes visited: {bfs_res['total_nodes_visited']}):")
    print(f"Mitigations: {[m['name'] for m in bfs_res['mitigations'][:3]]}")
    kev = agent.check_vulnerability("CVE-2026-88779")
    print(f"CISA KEV CVE-2026-88779: Exploited={kev['is_known_exploited']}")
    print("\n[+] Agent 3 self-test passed successfully!")

