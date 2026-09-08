"""
tests/test_search.py

Rigorous algorithmic tests for state-space search strategies.
Validates BFS completeness, A* optimality, and proves heuristic
admissibility and consistency under course examination standards.
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from search.response_graph import ResponseGraph
from search.bfs import breadth_first_search
from search.astar import astar_search


class TestSearchAlgorithms(unittest.TestCase):

    def setUp(self):
        self.graph = ResponseGraph(threat_type="Network Attack", severity="HIGH", target_criticality=1.0)

    def test_bfs_finds_goal_path(self):
        res = breadth_first_search(self.graph)
        self.assertTrue(res.goal_found)
        self.assertEqual(res.path[0], "ATTACK_DETECTED")
        self.assertEqual(res.path[-1], "INCIDENT_CONTROLLED")
        self.assertGreater(res.nodes_explored, 0)
        self.assertGreater(res.total_cost, 0.0)

    def test_astar_finds_optimal_path(self):
        res = astar_search(self.graph)
        self.assertTrue(res.goal_found)
        self.assertEqual(res.path[0], "ATTACK_DETECTED")
        self.assertEqual(res.path[-1], "INCIDENT_CONTROLLED")
        self.assertGreater(res.nodes_explored, 0)

    def test_astar_cost_is_less_than_or_equal_to_bfs_cost(self):
        """
        Academic Core: Proves that A* guided by an admissible heuristic produces
        a solution whose operational cost is <= BFS uninformed search.
        """
        bfs_res = breadth_first_search(self.graph)
        astar_res = astar_search(self.graph)
        self.assertLessEqual(astar_res.total_cost, bfs_res.total_cost)

    def test_heuristic_admissibility(self):
        """
        Admissibility Proof: h(n) <= h*(n) for all nodes n.
        h*(n) is the true optimal cost from n to INCIDENT_CONTROLLED.
        """
        # Run A* from each node to calculate the exact optimal cost h*(n)
        for state in self.graph.adj_list.keys():
            true_cost_benchmark = astar_search(self.graph, start_state=state)
            h_star = true_cost_benchmark.total_cost if true_cost_benchmark.goal_found else float("inf")
            h_n = self.graph.get_heuristic(state)
            self.assertLessEqual(
                h_n, h_star,
                f"Heuristic violation at state '{state}': h(n)={h_n} > h*(n)={h_star}"
            )

    def test_heuristic_consistency_triangle_inequality(self):
        """
        Consistency Proof: h(u) <= c(u, a, v) + h(v) for all edges (u, v).
        Guarantees monotonicity and prevents f-contour backtracking.
        """
        for state, edges in self.graph.adj_list.items():
            h_u = self.graph.get_heuristic(state)
            for edge in edges:
                h_v = self.graph.get_heuristic(edge.target_state)
                cost = edge.operational_cost
                self.assertLessEqual(
                    h_u, cost + h_v + 1e-6,
                    f"Consistency violation on edge '{state}' -> '{edge.target_state}': "
                    f"h(u)={h_u} > c={cost} + h(v)={h_v}"
                )


if __name__ == "__main__":
    unittest.main()
