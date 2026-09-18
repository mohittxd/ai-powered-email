"""
evaluate.py — Full Evaluation, Ranking Analysis, and Visualization

Generates:
- Confusion matrices
- ROC curves
- Precision-Recall curves
- Score distributions
- Ranking reports
- Model comparison
"""

import json
import os
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, roc_curve, precision_recall_curve,
    average_precision_score, roc_auc_score,
)

# Import PlattScaler so joblib can unpickle calibrated models
sys.path.insert(0, str(Path(__file__).resolve().parent))
from platt_scaler import PlattScaler  # noqa: F401

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
ARTIFACT_DIR = MODELS_DIR / "email_risk_model"


def load_all():
    """Load models, data, and metadata."""
    model_primary = joblib.load(ARTIFACT_DIR / "xgb_model_calibrated.joblib")
    model_domain = joblib.load(ARTIFACT_DIR / "xgb_model_domain_calibrated.joblib")

    X_test_primary = pd.read_csv(ARTIFACT_DIR / "X_test_primary.csv")
    X_test_domain = pd.read_csv(ARTIFACT_DIR / "X_test_domain.csv")
    y_test = np.load(ARTIFACT_DIR / "labels_test.npy")
    email_meta = pd.read_csv(ARTIFACT_DIR / "email_metadata.csv")
    test_indices = np.load(ARTIFACT_DIR / "test_idx.npy")

    with open(ARTIFACT_DIR / "model_metadata.json") as f:
        metadata = json.load(f)

    return {
        "model_primary": model_primary,
        "model_domain": model_domain,
        "X_test_primary": X_test_primary,
        "X_test_domain": X_test_domain,
        "y_test": y_test,
        "email_meta": email_meta,
        "test_indices": test_indices,
        "metadata": metadata,
    }


def plot_confusion_matrix(y_true, y_pred, title, save_path):
    """Plot and save confusion matrix."""
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Ham (0)", "Spam (1)"],
                yticklabels=["Ham (0)", "Spam (1)"])
    plt.title(title)
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved: {save_path}")


def plot_roc_curve(y_true, y_prob, title, save_path):
    """Plot and save ROC curve."""
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    auc = roc_auc_score(y_true, y_prob)
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, linewidth=2, label=f"ROC (AUC = {auc:.4f})")
    plt.plot([0, 1], [0, 1], "k--", linewidth=1, alpha=0.5)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(title)
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved: {save_path}")


def plot_pr_curve(y_true, y_prob, title, save_path):
    """Plot and save Precision-Recall curve."""
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    ap = average_precision_score(y_true, y_prob)
    plt.figure(figsize=(7, 5))
    plt.plot(recall, precision, linewidth=2, label=f"PR (AP = {ap:.4f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title(title)
    plt.legend(loc="upper right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved: {save_path}")


def plot_score_distribution(y_true, y_prob, title, save_path):
    """Plot score distribution for ham vs spam."""
    plt.figure(figsize=(8, 5))
    plt.hist(y_prob[y_true == 0], bins=50, alpha=0.6, label="Ham (0)", color="steelblue", density=True)
    plt.hist(y_prob[y_true == 1], bins=50, alpha=0.6, label="Spam (1)", color="crimson", density=True)
    plt.xlabel("Risk Score")
    plt.ylabel("Density")
    plt.title(title)
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved: {save_path}")


def plot_model_comparison(results):
    """Plot side-by-side comparison of primary vs domain model metrics."""
    metrics = ["roc_auc", "pr_auc", "precision", "recall", "f1"]
    primary_vals = [results["primary"][m] for m in metrics]
    domain_vals = [results["domain"][m] for m in metrics]

    x = np.arange(len(metrics))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    bars1 = ax.bar(x - width / 2, primary_vals, width, label="Primary (no domain)", color="steelblue")
    bars2 = ax.bar(x + width / 2, domain_vals, width, label="Domain (leakage)", color="crimson")
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — Primary vs Domain-Feature Model")
    ax.set_xticks(x)
    ax.set_xticklabels([m.upper() for m in metrics])
    ax.legend()
    ax.set_ylim(0.5, 1.05)
    ax.grid(True, alpha=0.3, axis="y")

    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 0.005,
                f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 0.005,
                f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    save_path = REPORTS_DIR / "model_comparison.png"
    plt.savefig(save_path, dpi=150)
    plt.close()
    print(f"  Saved: {save_path}")


def generate_ranking_details(y_prob, y_true, email_meta, test_indices, top_k_values=(10, 50, 100)):
    """Generate detailed ranking report with email summaries."""
    sorted_indices = np.argsort(-y_prob)
    report = []

    max_k = max(top_k_values)
    for rank_pos in range(min(max_k, len(sorted_indices))):
        idx = sorted_indices[rank_pos]
        orig_idx = test_indices[idx]
        meta = email_meta.iloc[orig_idx]
        report.append({
            "rank": rank_pos + 1,
            "email_index": int(orig_idx),
            "sender_domain": str(meta.get("sender_domain", "unknown")),
            "subject_summary": str(meta.get("subject_summary", ""))[:80],
            "true_label": int(y_true[idx]),
            "true_label_str": "spam" if y_true[idx] == 1 else "ham",
            "risk_score": round(float(y_prob[idx]), 4),
        })

    return report


def evaluate_all():
    """Run full evaluation."""
    data = load_all()

    os.makedirs(REPORTS_DIR, exist_ok=True)

    # --- Primary model ---
    print("=" * 70)
    print("EVALUATING PRIMARY MODEL (no domain features)")
    print("=" * 70)

    prob_primary = data["model_primary"].predict_proba(data["X_test_primary"])[:, 1]
    pred_primary = (prob_primary >= 0.5).astype(int)
    y = data["y_test"]

    print(f"  Test size: {len(y)}")
    print(f"  Spam in test: {y.sum()} ({100 * y.sum() / len(y):.1f}%)")
    print(f"  Predicted spam: {pred_primary.sum()}")

    # Confusion matrix
    cm = confusion_matrix(y, pred_primary)
    print(f"  Confusion matrix:\n    {cm}")
    plot_confusion_matrix(y, pred_primary, "Primary Model — Confusion Matrix",
                          REPORTS_DIR / "confusion_matrix_primary.png")

    # ROC
    plot_roc_curve(y, prob_primary, "Primary Model — ROC Curve",
                   REPORTS_DIR / "roc_curve_primary.png")

    # PR
    plot_pr_curve(y, prob_primary, "Primary Model — Precision-Recall Curve",
                  REPORTS_DIR / "pr_curve_primary.png")

    # Score distribution
    plot_score_distribution(y, prob_primary, "Primary Model — Risk Score Distribution",
                            REPORTS_DIR / "score_distribution_primary.png")

    # --- Domain model ---
    print("\n" + "=" * 70)
    print("EVALUATING DOMAIN-FEATURE MODEL (leakage demo)")
    print("=" * 70)

    prob_domain = data["model_domain"].predict_proba(data["X_test_domain"])[:, 1]
    pred_domain = (prob_domain >= 0.5).astype(int)

    cm_domain = confusion_matrix(y, pred_domain)
    print(f"  Confusion matrix:\n    {cm_domain}")
    plot_confusion_matrix(y, pred_domain, "Domain Model — Confusion Matrix",
                          REPORTS_DIR / "confusion_matrix_domain.png")
    plot_roc_curve(y, prob_domain, "Domain Model — ROC Curve",
                   REPORTS_DIR / "roc_curve_domain.png")
    plot_pr_curve(y, prob_domain, "Domain Model — Precision-Recall Curve",
                  REPORTS_DIR / "pr_curve_domain.png")
    plot_score_distribution(y, prob_domain, "Domain Model — Risk Score Distribution",
                            REPORTS_DIR / "score_distribution_domain.png")

    # --- Model comparison ---
    primary_metrics = {
        "roc_auc": float(roc_auc_score(y, prob_primary)),
        "pr_auc": float(average_precision_score(y, prob_primary)),
        "precision": float((pred_primary[y == 1].sum() + (pred_primary[y == 0] == 0).sum()) / len(y)),
        "recall": float(pred_primary[y == 1].sum() / y.sum()),
        "f1": 0.0,
    }
    from sklearn.metrics import f1_score, precision_score, recall_score
    primary_metrics["precision"] = float(precision_score(y, pred_primary, zero_division=0))
    primary_metrics["recall"] = float(recall_score(y, pred_primary, zero_division=0))
    primary_metrics["f1"] = float(f1_score(y, pred_primary, zero_division=0))

    domain_metrics = {
        "roc_auc": float(roc_auc_score(y, prob_domain)),
        "pr_auc": float(average_precision_score(y, prob_domain)),
        "precision": float(precision_score(y, pred_domain, zero_division=0)),
        "recall": float(recall_score(y, pred_domain, zero_division=0)),
        "f1": float(f1_score(y, pred_domain, zero_division=0)),
    }

    plot_model_comparison({"primary": primary_metrics, "domain": domain_metrics})

    # --- Ranking details ---
    print("\n--- Primary Model: Ranking Details ---")
    ranking_details = generate_ranking_details(
        prob_primary, y, data["email_meta"], data["test_indices"]
    )

    for k in [10, 50, 100]:
        top_k = ranking_details[:k]
        n_spam = sum(1 for e in top_k if e["true_label"] == 1)
        n_ham = sum(1 for e in top_k if e["true_label"] == 0)
        print(f"\n  Top {k}: {n_spam} spam, {n_ham} ham")
        for e in top_k[:5]:
            print(f"    #{e['rank']:>3d} | score={e['risk_score']:.4f} | "
                  f"true={e['true_label_str']:>4s} | {e['sender_domain']:<30s} | "
                  f"{e['subject_summary'][:50]}")
        if k > 5:
            print(f"    ... ({k - 5} more)")

    # Save ranking report
    with open(REPORTS_DIR / "ranking_details.json", "w") as f:
        json.dump(ranking_details, f, indent=2)

    # --- Feature importance (primary model) ---
    print("\n--- Feature Importance (Primary Model) ---")
    raw_model = joblib.load(ARTIFACT_DIR / "xgb_model_raw.joblib")
    importances = raw_model.feature_importances_
    feature_names = list(data["X_test_primary"].columns)
    imp_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances,
    }).sort_values("importance", ascending=False)
    print(imp_df.head(20).to_string(index=False))

    imp_df.to_csv(REPORTS_DIR / "feature_importance_primary.csv", index=False)

    plt.figure(figsize=(10, 8))
    top_features = imp_df.head(20)
    plt.barh(range(len(top_features)), top_features["importance"].values, color="steelblue")
    plt.yticks(range(len(top_features)), top_features["feature"].values)
    plt.xlabel("Importance")
    plt.title("Primary Model — Top 20 Feature Importances")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "feature_importance_primary.png", dpi=150)
    plt.close()
    print(f"  Saved: {REPORTS_DIR / 'feature_importance_primary.png'}")

    # --- Save complete evaluation report ---
    eval_report = {
        "primary_model": {
            "test_size": len(y),
            "spam_count": int(y.sum()),
            "confusion_matrix": cm.tolist(),
            "roc_auc": float(roc_auc_score(y, prob_primary)),
            "pr_auc": float(average_precision_score(y, prob_primary)),
        },
        "domain_model": {
            "confusion_matrix": cm_domain.tolist(),
            "roc_auc": float(roc_auc_score(y, prob_domain)),
            "pr_auc": float(average_precision_score(y, prob_domain)),
        },
        "ranking_samples": {
            "top_10": ranking_details[:10],
            "top_50_summary": {
                "total": 50,
                "spam": sum(1 for e in ranking_details[:50] if e["true_label"] == 1),
                "ham": sum(1 for e in ranking_details[:50] if e["true_label"] == 0),
            },
            "top_100_summary": {
                "total": 100,
                "spam": sum(1 for e in ranking_details[:100] if e["true_label"] == 1),
                "ham": sum(1 for e in ranking_details[:100] if e["true_label"] == 0),
            },
        },
    }
    with open(REPORTS_DIR / "evaluation_report.json", "w") as f:
        json.dump(eval_report, f, indent=2, default=str)

    print(f"\n--- All evaluation artifacts saved to {REPORTS_DIR} ---")
    return eval_report


if __name__ == "__main__":
    evaluate_all()
    print("\nEvaluation complete.")
