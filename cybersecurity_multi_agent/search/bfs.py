"""
search/bfs.py

Breadth-First Search (BFS) implementation for cybersecurity response planning.
Represents an uninformed (blind) search strategy used as an academic baseline.
Explores the state space layer-by-layer using a FIFO queue.
"""

import os
import sys
from collections import deque
import time
from typing import Optional, List, Tuple

# Ensure base project directory is in sys.path for direct execution
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

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



def breadth_first_search(graph: ResponseGraph, start_state: Optional[str] = None) -> SearchBenchmark:
    """
    Executes Breadth-First Search from start_state to INCIDENT_CONTROLLED.
    
    Academic Characteristics:
      - Search Type: Uninformed (Blind).
      - Strategy: Explores shallowest unexpanded nodes first.
      - Data Structure: FIFO Queue (collections.deque).
      - Completeness: Complete (guaranteed to find goal if finite branching factor).
      - Optimality: Optimal ONLY for unit-cost step environments. With non-uniform
        operational costs, BFS finds the minimum-hop path, NOT the minimum-cost path.
        
    Returns:
      SearchBenchmark recording path, total operational cost, nodes explored,
      and execution time in milliseconds.
    """
    if start_state is None:
        start_state = graph.START_STATE

    start_time = time.perf_counter()
    queue = deque([(start_state, [start_state], [], 0.0)])
    visited = set()
    nodes_explored = 0

    while queue:
        current_state, path, actions, current_cost = queue.popleft()
        nodes_explored += 1

        if graph.is_goal(current_state):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return SearchBenchmark(
                algorithm="BFS",
                path=path,
                total_cost=current_cost,
                nodes_explored=nodes_explored,
                execution_time_ms=round(elapsed_ms, 3),
                goal_found=True
            )

        if current_state in visited:
            continue
        visited.add(current_state)

        for edge in graph.get_neighbors(current_state):
            if edge.target_state not in visited:
                queue.append((
                    edge.target_state,
                    path + [edge.target_state],
                    actions + [edge.action_name],
                    current_cost + edge.operational_cost
                ))

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
    return SearchBenchmark(
        algorithm="BFS",
        path=[],
        total_cost=float("inf"),
        nodes_explored=nodes_explored,
        execution_time_ms=round(elapsed_ms, 3),
        goal_found=False
    )
