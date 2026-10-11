"""
knowledge/attack_kb.py

Formal Knowledge Representation of MITRE ATT&CK Enterprise Matrix.
Parses STIX 2.0/2.1 JSON ('enterprise-attack.json') and constructs an in-memory
NetworkX DiGraph modeling techniques, sub-techniques, tactics, threat groups,
software/tools/malware, mitigations, and all semantic relationships.
"""

import os
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import deque
import networkx as nx


class AttackKnowledgeBase:
    """
    Formal Knowledge Graph representation for MITRE ATT&CK.
    Uses NetworkX DiGraph G = (V, E) where:
      V: Techniques, Tactics, Groups (Intrusion Sets), Software (Tools/Malware), Mitigations
      E: uses, mitigates, subtechnique-of, reverse edges
    """

    def __init__(self, json_path: Optional[str] = None):
        if json_path is None:
            # Check parent directory then current directory
            candidates = [
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "enterprise-attack.json"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "enterprise-attack.json"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw", "enterprise-attack.json"),
                "enterprise-attack.json"
            ]
            for c in candidates:
                if os.path.exists(c):
                    json_path = c
                    break

        self.json_path = json_path
        self.graph: nx.DiGraph = nx.DiGraph()
        self.techniques: Dict[str, Dict[str, Any]] = {}  # mitre_id -> metadata
        self.tactics: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.software: Dict[str, Dict[str, Any]] = {}
        self.mitigations: Dict[str, Dict[str, Any]] = {}
        self._stix_to_mitre_id: Dict[str, str] = {}
        self._loaded: bool = False

        if self.json_path and os.path.exists(self.json_path):
            self._load_and_build_graph()

    def _load_and_build_graph(self):
        """Parses STIX objects and constructs the NetworkX graph."""
        with open(self.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])

        # Phase 1: Ingest entities
        for obj in objects:
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            obj_type = obj.get("type")
            stix_id = obj.get("id")
            name = obj.get("name", "")
            desc = obj.get("description", "")

            # Extract MITRE external ID (e.g. T1110, G0010, M1036)
            mitre_id = None
            for ref in obj.get("external_references", []):
                src = ref.get("source_name", "")
                if src in ["mitre-attack", "mitre-enterprise-attack"]:
                    mitre_id = ref.get("external_id")
                    break

            node_id = mitre_id if mitre_id else stix_id
            self._stix_to_mitre_id[stix_id] = node_id

            if obj_type == "attack-pattern":
                tactics = [
                    kc.get("phase_name")
                    for kc in obj.get("kill_chain_phases", [])
                    if kc.get("kill_chain_name") in ["mitre-attack", "mitre-enterprise-attack"]
                ]
                metadata = {
                    "node_id": node_id,
                    "mitre_id": node_id,
                    "type": "technique",
                    "name": name,
                    "description": desc,
                    "tactics": tactics,
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
                }
                self.techniques[node_id] = metadata
                self.graph.add_node(node_id, **metadata)

            elif obj_type == "x-mitre-tactic":
                tactic_short = obj.get("x_mitre_shortname", name.lower().replace(" ", "-"))
                metadata = {
                    "node_id": node_id,
                    "mitre_id": node_id,
                    "type": "tactic",
                    "short_name": tactic_short,
                    "name": name,
                    "description": desc
                }
                self.tactics[node_id] = metadata
                self.graph.add_node(node_id, **metadata)

            elif obj_type == "intrusion-set":
                metadata = {
                    "node_id": node_id,
                    "mitre_id": node_id,
                    "type": "group",
                    "name": name,
                    "aliases": obj.get("aliases", []),
                    "description": desc
                }
                self.groups[node_id] = metadata
                self.graph.add_node(node_id, **metadata)

            elif obj_type in ["malware", "tool"]:
                metadata = {
                    "node_id": node_id,
                    "mitre_id": node_id,
                    "type": "software",
                    "software_kind": obj_type,
                    "name": name,
                    "description": desc
                }
                self.software[node_id] = metadata
                self.graph.add_node(node_id, **metadata)

            elif obj_type == "course-of-action":
                metadata = {
                    "node_id": node_id,
                    "mitre_id": node_id,
                    "type": "mitigation",
                    "name": name,
                    "description": desc
                }
                self.mitigations[node_id] = metadata
                self.graph.add_node(node_id, **metadata)

        # Phase 2: Ingest relationships
        for obj in objects:
            if obj.get("type") == "relationship" and not obj.get("revoked"):
                s_ref = obj.get("source_ref")
                t_ref = obj.get("target_ref")
                rel = obj.get("relationship_type")

                if s_ref in self._stix_to_mitre_id and t_ref in self._stix_to_mitre_id:
                    u = self._stix_to_mitre_id[s_ref]
                    v = self._stix_to_mitre_id[t_ref]
                    self.graph.add_edge(u, v, relationship=rel)
                    self.graph.add_edge(v, u, relationship=f"reverse_{rel}")

        # Connect techniques to their tactic nodes
        for t_id, t_meta in self.techniques.items():
            for phase in t_meta.get("tactics", []):
                # Find matching tactic node
                for tac_id, tac_meta in self.tactics.items():
                    if tac_meta.get("short_name") == phase:
                        self.graph.add_edge(t_id, tac_id, relationship="belongs_to")
                        self.graph.add_edge(tac_id, t_id, relationship="reverse_belongs_to")

        self._loaded = True

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Lookup technique by ID (e.g. 'T1110' or 'T1110.001')."""
        return self.techniques.get(technique_id.upper())

    def get_mitigation(self, mitigation_id: str) -> Optional[Dict[str, Any]]:
        """Lookup mitigation by ID (e.g. 'M1036')."""
        return self.mitigations.get(mitigation_id.upper())

    def bfs_subgraph(
        self,
        start_node_id: str,
        max_depth: int = 2
    ) -> Dict[str, Any]:
        """
        Executes Breadth-First Search (BFS) graph traversal starting from start_node_id.
        Explores related tactics, threat actor groups, malware/software, and mitigations.
        
        Returns:
          Structured dictionary of nodes explored, edge paths, depth, and categorized entities.
        """
        start_node_id = start_node_id.upper()
        if start_node_id not in self.graph:
            return {
                "start_node": start_node_id,
                "found": False,
                "depth_reached": 0,
                "nodes_visited": [],
                "tactics": [],
                "related_groups": [],
                "related_software": [],
                "mitigations": [],
                "edges": []
            }

        visited: Set[str] = {start_node_id}
        queue = deque([(start_node_id, 0)])
        
        categorized: Dict[str, List[Dict[str, Any]]] = {
            "tactics": [],
            "related_groups": [],
            "related_software": [],
            "mitigations": []
        }
        collected_edges: List[Dict[str, str]] = []
        visited_nodes_order: List[str] = [start_node_id]

        max_depth_reached = 0

        while queue:
            curr_id, curr_depth = queue.popleft()
            max_depth_reached = max(max_depth_reached, curr_depth)

            if curr_depth >= max_depth:
                continue

            for neighbor in self.graph.neighbors(curr_id):
                edge_data = self.graph.get_edge_data(curr_id, neighbor) or {}
                rel = edge_data.get("relationship", "connected_to")

                if neighbor not in visited:
                    visited.add(neighbor)
                    visited_nodes_order.append(neighbor)
                    queue.append((neighbor, curr_depth + 1))

                    collected_edges.append({
                        "source": curr_id,
                        "target": neighbor,
                        "relationship": rel
                    })

                    node_data = self.graph.nodes.get(neighbor, {})
                    ntype = node_data.get("type")
                    entry = {
                        "id": neighbor,
                        "name": node_data.get("name", ""),
                        "type": ntype,
                        "relationship": rel,
                        "depth": curr_depth + 1
                    }

                    if ntype == "tactic":
                        categorized["tactics"].append(entry)
                    elif ntype == "group":
                        categorized["related_groups"].append(entry)
                    elif ntype == "software":
                        categorized["related_software"].append(entry)
                    elif ntype == "mitigation":
                        categorized["mitigations"].append(entry)

        return {
            "start_node": start_node_id,
            "found": True,
            "depth_reached": max_depth_reached,
            "total_nodes_visited": len(visited_nodes_order),
            "nodes_visited": visited_nodes_order,
            "tactics": categorized["tactics"],
            "related_groups": categorized["related_groups"],
            "related_software": categorized["related_software"],
            "mitigations": categorized["mitigations"],
            "edges": collected_edges
        }
