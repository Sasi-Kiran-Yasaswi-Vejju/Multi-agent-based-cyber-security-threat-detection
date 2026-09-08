"""
search/astar.py

A* Search implementation for cybersecurity response planning.
Represents an informed (heuristic-guided) search strategy.
Expands states using the evaluation function f(n) = g(n) + h(n),
guaranteeing cost-optimal mitigation when h(n) is admissible.
"""

import heapq
import time
from typing import Optional, List, Tuple, Dict
try:
    from search.response_graph import ResponseGraph
except ImportError:
    try:
        from .response_graph import ResponseGraph
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.search.response_graph import ResponseGraph

try:
    from communication.messages import SearchBenchmark
except ImportError:
    try:
        from ..communication.messages import SearchBenchmark
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import SearchBenchmark


def astar_search(graph: ResponseGraph, start_state: Optional[str] = None) -> SearchBenchmark:
    """
    Executes A* Search from start_state to INCIDENT_CONTROLLED.
    
    Mathematical Formulation:
      f(n) = g(n) + h(n)
        - g(n): Incurred operational disruption cost from start_state to node n.
        - h(n): Estimated remaining risk cost from node n to INCIDENT_CONTROLLED.
        - f(n): Total estimated cost of solution passing through node n.
        
    Academic Characteristics:
      - Search Type: Informed (Heuristic).
      - Data Structure: Priority Queue (heapq).
      - Admissibility: Guaranteed because h(n) <= h*(n) for all states n.
      - Consistency (Monotonicity): h(n) <= c(n, a, n') + h(n').
      - Optimality: Provably cost-optimal.
      
    Returns:
      SearchBenchmark recording the optimal path, minimum total cost,
      nodes explored, and execution time in milliseconds.
    """
    if start_state is None:
        start_state = graph.START_STATE

    start_time = time.perf_counter()
    
    # Priority queue entries: (f_score, tie_breaker_id, current_state, path, actions, g_score)
    tie_breaker = 0
    start_h = graph.get_heuristic(start_state)
    start_f = 0.0 + start_h
    
    pq = [(start_f, tie_breaker, start_state, [start_state], [], 0.0)]
    best_g: Dict[str, float] = {start_state: 0.0}
    nodes_explored = 0

    while pq:
        f_score, _, current_state, path, actions, g_score = heapq.heappop(pq)
        nodes_explored += 1

        # Check if goal state is reached
        if graph.is_goal(current_state):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return SearchBenchmark(
                algorithm="A*",
                path=path,
                total_cost=g_score,
                nodes_explored=nodes_explored,
                execution_time_ms=round(elapsed_ms, 3),
                goal_found=True
            )

        # Prune redundant paths if a strictly cheaper path to current_state was already found
        if g_score > best_g.get(current_state, float("inf")):
            continue

        for edge in graph.get_neighbors(current_state):
            neighbor = edge.target_state
            tentative_g = g_score + edge.operational_cost

            if tentative_g < best_g.get(neighbor, float("inf")):
                best_g[neighbor] = tentative_g
                h_score = graph.get_heuristic(neighbor)
                f_score_new = tentative_g + h_score
                tie_breaker += 1
                heapq.heappush(pq, (
                    f_score_new,
                    tie_breaker,
                    neighbor,
                    path + [neighbor],
                    actions + [edge.action_name],
                    tentative_g
                ))

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return SearchBenchmark(
        algorithm="A*",
        path=[],
        total_cost=float("inf"),
        nodes_explored=nodes_explored,
        execution_time_ms=round(elapsed_ms, 3),
        goal_found=False
    )
