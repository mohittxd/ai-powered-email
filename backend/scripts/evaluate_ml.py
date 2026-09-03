#!/usr/bin/env python3
"""
Phase 19 — Standalone ML Model Evaluation Script.

Usage:
    python scripts/evaluate_ml.py
    or
    python -m scripts.evaluate_ml

Evaluates the defensive classifier against the safe synthetic benchmark dataset,
printing Accuracy, Per-Class Precision/Recall/F1, 5x5 Confusion Matrix, and legal disclaimers.
"""
import sys
import os
import json

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.evaluator import MLEvaluator


def main():
    evaluator = MLEvaluator()
    results = evaluator.evaluate()
    report_text = MLEvaluator.format_report_text(results)

    print("\n" + report_text + "\n")

    # Optionally save evaluation report to JSON artifact for tracking
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../artifacts"))
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "ml_evaluation_results.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Evaluation summary saved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
