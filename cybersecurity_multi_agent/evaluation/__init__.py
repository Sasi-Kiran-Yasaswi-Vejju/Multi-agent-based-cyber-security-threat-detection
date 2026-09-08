"""Evaluation package for classifier and search benchmark metrics."""
from .metrics import evaluate_classifier, format_search_comparison_table, get_academic_accuracy_critique

__all__ = ["evaluate_classifier", "format_search_comparison_table", "get_academic_accuracy_critique"]
