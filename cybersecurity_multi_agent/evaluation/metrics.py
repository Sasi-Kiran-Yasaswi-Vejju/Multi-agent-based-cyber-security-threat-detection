"""
evaluation/metrics.py

Comprehensive evaluation utilities for both:
1. Supervised machine learning intrusion classification (Agent 1)
2. State-space search performance (Agent 2)
"""

from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
try:
    from communication.messages import SearchBenchmark
except ImportError:
    try:
        from ..communication.messages import SearchBenchmark
    except (ImportError, ValueError):
        from cybersecurity_multi_agent.communication.messages import SearchBenchmark


def evaluate_classifier(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    """
    Computes complete classification metrics for intrusion detection.
    
    Academic focus:
      - Accuracy alone is vulnerable to the Base Rate Fallacy in security.
      - False Positive Rate (FPR) directly quantifies SOC alert fatigue.
      - Recall directly measures defense against breaches (1 - FN rate).
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    # cm structure: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "classification_report": classification_report(y_true, y_pred, target_names=["NORMAL", "ATTACK"], digits=4)
    }


def format_search_comparison_table(bfs_res: SearchBenchmark, astar_res: SearchBenchmark) -> str:
    """Generates a clean ASCII comparative analysis table for Review 1 presentations."""
    lines = [
        "+----------------------+----------------------+----------------------+",
        "| Metric               | BFS (Uninformed)     | A* (Informed)        |",
        "+----------------------+----------------------+----------------------+",
        f"| Search Strategy      | Layer-by-layer Queue | Priority Queue f=g+h |",
        f"| Uses Heuristic       | No                   | Yes (Admissible h)   |",
        f"| Path Hop Length      | {len(bfs_res.path) - 1:<20} | {len(astar_res.path) - 1:<20} |",
        f"| Total Path Cost      | {bfs_res.total_cost:<20.1f} | {astar_res.total_cost:<20.1f} |",
        f"| Nodes Explored       | {bfs_res.nodes_explored:<20} | {astar_res.nodes_explored:<20} |",
        f"| Execution Time (ms)  | {bfs_res.execution_time_ms:<20.3f} | {astar_res.execution_time_ms:<20.3f} |",
        f"| Optimal Cost Found   | {'Sub-optimal/Blind' if bfs_res.total_cost > astar_res.total_cost else 'Yes':<20} | {'Yes (Provably)' if astar_res.goal_found else 'No':<20} |",
        "+----------------------+----------------------+----------------------+"
    ]
    return "\n".join(lines)


def get_academic_accuracy_critique() -> str:
    """Returns academic defense on why accuracy alone is insufficient in cybersecurity."""
    return (
        "Academic Rationale: Why Accuracy Alone is Insufficient in Cybersecurity:\n"
        "1. Extreme Class Imbalance (Base Rate Fallacy): In enterprise networks, attacks may constitute < 1% "
        "of billions of packets. A trivial classifier predicting 'NORMAL' achieves 99% accuracy while allowing "
        "every breach through.\n"
        "2. Asymmetric Cost of Errors: False Negatives (FN) permit exfiltration and ransomware deployment. "
        "False Positives (FP) waste analyst triage hours. Thus, Recall and Precision (harmonized via F1) "
        "and False Positive Rate (FPR) provide true operational security validity."
    )
