"""
Phase 19 — Machine Learning Evaluation Engine for Defensive Classifier.

Computes:
- Overall Accuracy
- Per-Class Precision, Recall, F1-Score, Support
- Macro & Weighted Averages
- 5x5 Confusion Matrix (LEGITIMATE, SUSPICIOUS, IMPERSONATION, PHISHING, BEC_FRAUD)
- Synthetic Benchmark Evaluation Disclaimer
"""

from typing import Dict, List, Any, Tuple
from services.ai_classifier import run_ai_classification
from ml.synthetic_dataset import SYNTHETIC_EVALUATION_DATASET

CATEGORIES = ["LEGITIMATE", "SUSPICIOUS", "IMPERSONATION", "PHISHING", "BEC_FRAUD"]


class MLEvaluator:
    """Evaluates the defensive AI/ML email classifier against benchmark datasets."""

    def __init__(self, dataset: List[Dict[str, Any]] = None):
        self.dataset = dataset or SYNTHETIC_EVALUATION_DATASET

    def evaluate(self) -> Dict[str, Any]:


        y_true = []
        y_pred = []
        sample_results = []

        # Run classification on each dataset sample
        for sample in self.dataset:
            gt = sample["ground_truth"].upper()

            res = run_ai_classification(
                parsed=sample["parsed_email"],
                auth_result=sample["auth_result"],
                forensics=sample["forensics"],
                iocs=sample["iocs"],
                threat_intel=sample["threat_intel"],
                rule_based_result=sample["rule_based_result"],
            )

            pred = res.get("classification", "LEGITIMATE").upper()
            # Map legacy aliases if any
            if "BEC" in pred:
                pred = "BEC_FRAUD"

            y_true.append(gt)
            y_pred.append(pred)

            sample_results.append({
                "id": sample["id"],
                "ground_truth": gt,
                "predicted": pred,
                "risk_score": res["final_risk_score"],
                "rule_score": res["rule_based_score"],
                "ml_score": res.get("ml_score"),
                "correct": gt == pred
            })

        # Calculate Confusion Matrix
        cm = {gt: {p: 0 for p in CATEGORIES} for gt in CATEGORIES}
        for true_lbl, pred_lbl in zip(y_true, y_pred):
            if true_lbl in cm and pred_lbl in cm[true_lbl]:
                cm[true_lbl][pred_lbl] += 1

        # Calculate Per-Class Precision, Recall, F1
        per_class_metrics = {}
        total_samples = len(y_true)
        correct_total = sum(1 for t, p in zip(y_true, y_pred) if t == p)
        accuracy = round(correct_total / total_samples, 4) if total_samples > 0 else 0.0

        macro_precision_sum = 0.0
        macro_recall_sum = 0.0
        macro_f1_sum = 0.0

        for cat in CATEGORIES:
            tp = cm[cat][cat]
            fp = sum(cm[other][cat] for other in CATEGORIES if other != cat)
            fn = sum(cm[cat][other] for other in CATEGORIES if other != cat)
            support = sum(cm[cat].values())

            precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
            recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
            if precision + recall > 0:
                f1 = round(2 * (precision * recall) / (precision + recall), 4)
            else:
                f1 = 0.0

            per_class_metrics[cat] = {
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "support": support,
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
            }

            macro_precision_sum += precision
            macro_recall_sum += recall
            macro_f1_sum += f1

        num_cats = len(CATEGORIES)
        macro_avg = {
            "precision": round(macro_precision_sum / num_cats, 4),
            "recall": round(macro_recall_sum / num_cats, 4),
            "f1_score": round(macro_f1_sum / num_cats, 4),
        }

        # Weighted Averages
        weighted_p = sum(per_class_metrics[c]["precision"] * per_class_metrics[c]["support"] for c in CATEGORIES) / total_samples
        weighted_r = sum(per_class_metrics[c]["recall"] * per_class_metrics[c]["support"] for c in CATEGORIES) / total_samples
        weighted_f1 = sum(per_class_metrics[c]["f1_score"] * per_class_metrics[c]["support"] for c in CATEGORIES) / total_samples

        weighted_avg = {
            "precision": round(weighted_p, 4),
            "recall": round(weighted_r, 4),
            "f1_score": round(weighted_f1, 4),
        }

        disclaimer = (
            "DISCLAIMER: The evaluation results are derived from a safe synthetic benchmark dataset designed for defensive model testing. "
            "Performance on this benchmark indicates heuristic signal efficacy but does NOT guarantee production-readiness or real-world zero-day generalization."
        )

        return {
            "total_samples": total_samples,
            "accuracy": accuracy,
            "per_class": per_class_metrics,
            "macro_avg": macro_avg,
            "weighted_avg": weighted_avg,
            "confusion_matrix": cm,
            "sample_results": sample_results,
            "disclaimer": disclaimer,
        }

    @staticmethod
    def format_report_text(eval_results: Dict[str, Any]) -> str:
        """Formats evaluation results as a clean, terminal-readable ASCII report."""
        lines = []
        lines.append("=" * 80)
        lines.append("           DEFENSIVE ML EMAIL CLASSIFIER EVALUATION REPORT")
        lines.append("=" * 80)
        lines.append(f"Total Samples Evaluated : {eval_results['total_samples']}")
        lines.append(f"Overall Model Accuracy  : {eval_results['accuracy'] * 100:.2f}%")
        lines.append("-" * 80)

        lines.append(f"{'CATEGORY':<16} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'SUPPORT':<8}")
        lines.append("-" * 80)

        for cat, m in eval_results["per_class"].items():
            lines.append(
                f"{cat:<16} | {m['precision']*100:>8.2f}% | {m['recall']*100:>8.2f}% | {m['f1_score']*100:>8.2f}% | {m['support']:>7}"
            )

        lines.append("-" * 80)
        m_avg = eval_results["macro_avg"]
        w_avg = eval_results["weighted_avg"]
        lines.append(f"{'Macro Average':<16} | {m_avg['precision']*100:>8.2f}% | {m_avg['recall']*100:>8.2f}% | {m_avg['f1_score']*100:>8.2f}% | {eval_results['total_samples']:>7}")
        lines.append(f"{'Weighted Average':<16} | {w_avg['precision']*100:>8.2f}% | {w_avg['recall']*100:>8.2f}% | {w_avg['f1_score']*100:>8.2f}% | {eval_results['total_samples']:>7}")
        lines.append("=" * 80)

        lines.append("\n5x5 CONFUSION MATRIX (Rows: Ground Truth, Columns: Predicted):")
        header = f"{'True \\ Pred':<16} | " + " | ".join(f"{c[:8]:<8}" for c in CATEGORIES)
        lines.append("-" * len(header))
        lines.append(header)
        lines.append("-" * len(header))

        cm = eval_results["confusion_matrix"]
        for gt in CATEGORIES:
            row_str = f"{gt:<16} | " + " | ".join(f"{cm[gt][p]:>8}" for p in CATEGORIES)
            lines.append(row_str)
        lines.append("-" * len(header))

        lines.append("\n⚠️  BENCHMARK LIMITATION DISCLAIMER:")
        lines.append(eval_results["disclaimer"])
        lines.append("=" * 80)

        return "\n".join(lines)
