"""
Tests for Phase 19: Safe Synthetic ML Evaluation Dataset & Metrics Pipeline.
"""
import os
import json
import pytest
from ml.synthetic_dataset import SYNTHETIC_EVALUATION_DATASET
from ml.evaluator import MLEvaluator, CATEGORIES


def test_synthetic_dataset_safety_and_structure():
    assert len(SYNTHETIC_EVALUATION_DATASET) >= 50, "Dataset must contain at least 50 synthetic evaluation samples."

    category_counts = {cat: 0 for cat in CATEGORIES}

    for sample in SYNTHETIC_EVALUATION_DATASET:
        gt = sample["ground_truth"]
        assert gt in CATEGORIES, f"Invalid ground truth category: {gt}"
        category_counts[gt] += 1

        # Check safe indicators (example.com, example.org, test-domain.invalid, RFC 5737 IPs)
        parsed = sample["parsed_email"]
        from_addr = parsed.get("from_address", "")
        reply_to = parsed.get("reply_to", "")
        
        # Verify no real malicious domain is used
        for domain in sample["iocs"].get("domains", []):
            assert "example" in domain or "invalid" in domain, f"Non-synthetic domain found: {domain}"

        # Verify no operational IP is used (documentation IP ranges: 192.0.2.x, 198.51.100.x, 203.0.113.x)
        for ip in sample["iocs"].get("ips", []):
            assert ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113."), f"Non-documentation IP found: {ip}"

    for cat in CATEGORIES:
        assert category_counts[cat] >= 10, f"Category '{cat}' must have at least 10 samples."

    print("✅ Synthetic dataset safety and multi-class distribution verified.")


def test_ml_evaluator_metrics_computation():
    evaluator = MLEvaluator()
    results = evaluator.evaluate()

    assert results["total_samples"] == len(SYNTHETIC_EVALUATION_DATASET)
    assert 0.0 <= results["accuracy"] <= 1.0

    # Verify all 5 categories are in per-class metrics & confusion matrix
    for cat in CATEGORIES:
        assert cat in results["per_class"]
        assert cat in results["confusion_matrix"]
        m = results["per_class"][cat]
        assert 0.0 <= m["precision"] <= 1.0
        assert 0.0 <= m["recall"] <= 1.0
        assert 0.0 <= m["f1_score"] <= 1.0
        assert m["support"] >= 10

    assert "disclaimer" in results
    assert "production-ready" in results["disclaimer"].lower() or "production-readiness" in results["disclaimer"].lower()

    # Format report check
    report_text = MLEvaluator.format_report_text(results)
    assert "CONFUSION MATRIX" in report_text
    assert "DEFENSIVE ML EMAIL CLASSIFIER EVALUATION REPORT" in report_text

    print("✅ ML Evaluation metrics, confusion matrix, and disclaimer verified.")
