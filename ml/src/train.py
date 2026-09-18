"""
train.py — XGBoost Training for Email Risk Ranking

Trains two model variants:
  A. Primary model (no domain features) — candidate for production
  B. Domain-feature model — for leakage quantification only

Both use predict_proba()[:, 1] as the risk score.
Calibration via Platt scaling on validation set.
"""

import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, average_precision_score, confusion_matrix,
)
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

RANDOM_SEED = 42
N_ESTIMATORS = 300
MAX_DEPTH = 6
LEARNING_RATE = 0.1


def load_preprocessed_data():
    """Load the preprocessed data from artifacts."""
    artifact_dir = MODELS_DIR / "email_risk_model"

    # Load from CSV (reliable, preserves column names)
    X_train_primary = pd.read_csv(artifact_dir / "X_train_primary.csv")
    X_val_primary = pd.read_csv(artifact_dir / "X_val_primary.csv")
    X_test_primary = pd.read_csv(artifact_dir / "X_test_primary.csv")

    X_train_domain = pd.read_csv(artifact_dir / "X_train_domain.csv")
    X_val_domain = pd.read_csv(artifact_dir / "X_val_domain.csv")
    X_test_domain = pd.read_csv(artifact_dir / "X_test_domain.csv")

    y_train = np.load(artifact_dir / "labels_train.npy")
    y_val = np.load(artifact_dir / "labels_val.npy")
    y_test = np.load(artifact_dir / "labels_test.npy")

    with open(artifact_dir / "feature_config.json") as f:
        metadata = json.load(f)

    return {
        "X_train_primary": X_train_primary,
        "X_val_primary": X_val_primary,
        "X_test_primary": X_test_primary,
        "X_train_domain": X_train_domain,
        "X_val_domain": X_val_domain,
        "X_test_domain": X_test_domain,
        "y_train": y_train,
        "y_val": y_val,
        "y_test": y_test,
        "metadata": metadata,
    }


def train_xgboost(X_train, y_train, X_val, y_val, label="primary"):
    """Train XGBoost with early stopping on validation set."""
    print(f"\n--- Training XGBoost ({label} model) ---")
    print(f"  Train: {X_train.shape}, Val: {X_val.shape}")
    print(f"  Class dist train: {dict(zip(*np.unique(y_train, return_counts=True)))}")

    n_pos = y_train.sum()
    n_neg = len(y_train) - n_pos
    scale_pos = n_neg / max(n_pos, 1)

    model = XGBClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        learning_rate=LEARNING_RATE,
        scale_pos_weight=scale_pos,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        min_child_weight=3,
        random_state=RANDOM_SEED,
        eval_metric="aucpr",
        early_stopping_rounds=30,
        use_label_encoder=False,
        n_jobs=2,
        tree_method="hist",
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    print(f"  Best iteration: {model.best_iteration}")
    print(f"  Best score: {model.best_score:.4f}")

    return model


from platt_scaler import PlattScaler  # noqa: F401 — needed for pickle unpickling


def calibrate_model(model, X_val, y_val):
    """Apply Platt scaling calibration on validation set."""
    print("  Calibrating with Platt scaling on validation set...")
    scaler = PlattScaler(model)
    scaler.fit(X_val, y_val)
    return scaler


def evaluate_model(model, X, y, label="test"):
    """Compute all metrics for a model on a dataset split."""
    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y, y_pred)),
        "precision": float(precision_score(y, y_pred, zero_division=0)),
        "recall": float(recall_score(y, y_pred, zero_division=0)),
        "f1": float(f1_score(y, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, y_prob)),
        "pr_auc": float(average_precision_score(y, y_prob)),
        "confusion_matrix": confusion_matrix(y, y_pred).tolist(),
    }

    # Ranking metrics
    sorted_indices = np.argsort(-y_prob)
    sorted_labels = y[sorted_indices]
    n_total = len(y)
    n_positive = y.sum()

    for k_name, k_val in [("5%", 0.05), ("10%", 0.10)]:
        top_k = max(1, int(n_total * k_val))
        top_labels = sorted_labels[:top_k]
        precision_k = float(top_labels.sum() / top_k)
        recall_k = float(top_labels.sum() / n_positive) if n_positive > 0 else 0.0
        metrics[f"precision@{k_name}"] = precision_k
        metrics[f"recall@{k_name}"] = recall_k

    for k_val in [50, 100]:
        top_k = min(k_val, n_total)
        top_labels = sorted_labels[:top_k]
        precision_k = float(top_labels.sum() / top_k)
        recall_k = float(top_labels.sum() / n_positive) if n_positive > 0 else 0.0
        metrics[f"precision@{k_val}"] = precision_k
        metrics[f"recall@{k_val}"] = recall_k

    return metrics, y_prob


def get_ranking_report(y_prob, y, email_meta, indices, top_k_values=(10, 50, 100)):
    """Generate ranking report for top-K emails."""
    sorted_indices = np.argsort(-y_prob)
    report = {"total_emails": len(y), "total_spam": int(y.sum())}

    for k in top_k_values:
        top_k_indices = sorted_indices[:k]
        top_entries = []
        for rank, idx in enumerate(top_k_indices):
            orig_idx = indices[idx]
            meta = email_meta.iloc[orig_idx]
            top_entries.append({
                "rank": rank + 1,
                "email_index": int(orig_idx),
                "sender_domain": str(meta.get("sender_domain", "unknown")),
                "subject_summary": str(meta.get("subject_summary", ""))[:80],
                "true_label": int(y[idx]),
                "risk_score": float(y_prob[idx]),
            })
        report[f"top_{k}"] = top_entries

    return report


def train_all():
    """Full training pipeline for both model variants."""
    data = load_preprocessed_data()

    results = {}

    # === PRIMARY MODEL (no domain features) ===
    model_primary = train_xgboost(
        data["X_train_primary"], data["y_train"],
        data["X_val_primary"], data["y_val"],
        label="PRIMARY (no domain)"
    )

    # Raw validation metrics
    val_metrics_raw, val_prob_raw = evaluate_model(
        model_primary, data["X_val_primary"], data["y_val"], label="val-raw"
    )
    print(f"\n  Primary raw val ROC-AUC: {val_metrics_raw['roc_auc']:.4f}")
    print(f"  Primary raw val PR-AUC:  {val_metrics_raw['pr_auc']:.4f}")

    # Calibrate
    model_primary_cal = calibrate_model(model_primary, data["X_val_primary"], data["y_val"])

    # Calibrated validation metrics
    val_metrics_cal, val_prob_cal = evaluate_model(
        model_primary_cal, data["X_val_primary"], data["y_val"], label="val-cal"
    )
    print(f"  Primary calibrated val ROC-AUC: {val_metrics_cal['roc_auc']:.4f}")
    print(f"  Primary calibrated val PR-AUC:  {val_metrics_cal['pr_auc']:.4f}")

    # Test metrics
    test_metrics_raw, test_prob_raw = evaluate_model(
        model_primary, data["X_test_primary"], data["y_test"], label="test-raw"
    )
    test_metrics_cal, test_prob_cal = evaluate_model(
        model_primary_cal, data["X_test_primary"], data["y_test"], label="test-cal"
    )

    print(f"\n  Primary RAW test ROC-AUC:    {test_metrics_raw['roc_auc']:.4f}")
    print(f"  Primary RAW test PR-AUC:     {test_metrics_raw['pr_auc']:.4f}")
    print(f"  Primary CALIBRATED test ROC-AUC: {test_metrics_cal['roc_auc']:.4f}")
    print(f"  Primary CALIBRATED test PR-AUC:  {test_metrics_cal['pr_auc']:.4f}")

    # Load email metadata for ranking report
    email_meta = pd.read_csv(MODELS_DIR / "email_risk_model" / "email_metadata.csv")
    test_indices = np.load(MODELS_DIR / "email_risk_model" / "test_idx.npy")

    ranking_report = get_ranking_report(test_prob_cal, data["y_test"], email_meta, test_indices)

    # Save primary model
    artifact_dir = MODELS_DIR / "email_risk_model"
    joblib.dump(model_primary, artifact_dir / "xgb_model_raw.joblib")
    joblib.dump(model_primary_cal, artifact_dir / "xgb_model_calibrated.joblib")

    results["primary"] = {
        "val_raw": val_metrics_raw,
        "val_cal": val_metrics_cal,
        "test_raw": test_metrics_raw,
        "test_cal": test_metrics_cal,
        "ranking": ranking_report,
    }

    # === DOMAIN MODEL (with domain features) ===
    model_domain = train_xgboost(
        data["X_train_domain"], data["y_train"],
        data["X_val_domain"], data["y_val"],
        label="DOMAIN (leakage demo)"
    )

    val_metrics_domain, _ = evaluate_model(
        model_domain, data["X_val_domain"], data["y_val"], label="domain-val"
    )
    model_domain_cal = calibrate_model(model_domain, data["X_val_domain"], data["y_val"])
    test_metrics_domain, test_prob_domain = evaluate_model(
        model_domain_cal, data["X_test_domain"], data["y_test"], label="domain-test"
    )

    print(f"\n  Domain CALIBRATED test ROC-AUC: {test_metrics_domain['roc_auc']:.4f}")
    print(f"  Domain CALIBRATED test PR-AUC:  {test_metrics_domain['pr_auc']:.4f}")

    joblib.dump(model_domain, artifact_dir / "xgb_model_domain_raw.joblib")
    joblib.dump(model_domain_cal, artifact_dir / "xgb_model_domain_calibrated.joblib")

    domain_ranking = get_ranking_report(test_prob_domain, data["y_test"], email_meta, test_indices)

    results["domain"] = {
        "val_raw": val_metrics_domain,
        "test_cal": test_metrics_domain,
        "ranking": domain_ranking,
    }

    # === COMPARISON ===
    print("\n" + "=" * 70)
    print("MODEL COMPARISON (Test Set, Calibrated)")
    print("=" * 70)
    print(f"{'Metric':<25} {'Primary (no domain)':<25} {'Domain (leakage)':<25}")
    print("-" * 70)
    for key in ["roc_auc", "pr_auc", "precision", "recall", "f1", "accuracy"]:
        v1 = results["primary"]["test_cal"].get(key, 0)
        v2 = results["domain"]["test_cal"].get(key, 0)
        print(f"  {key:<23} {v1:<25.4f} {v2:<25.4f}")

    for k_name in ["5%", "10%"]:
        p1 = results["primary"]["test_cal"].get(f"precision@{k_name}", 0)
        r1 = results["primary"]["test_cal"].get(f"recall@{k_name}", 0)
        p2 = results["domain"]["test_cal"].get(f"precision@{k_name}", 0)
        r2 = results["domain"]["test_cal"].get(f"recall@{k_name}", 0)
        print(f"  precision@{k_name:<17} {p1:<25.4f} {p2:<25.4f}")
        print(f"  recall@{k_name:<18} {r1:<25.4f} {r2:<25.4f}")

    for kv in [50, 100]:
        p1 = results["primary"]["test_cal"].get(f"precision@{kv}", 0)
        r1 = results["primary"]["test_cal"].get(f"recall@{kv}", 0)
        p2 = results["domain"]["test_cal"].get(f"precision@{kv}", 0)
        r2 = results["domain"]["test_cal"].get(f"recall@{kv}", 0)
        print(f"  precision@{kv:<17} {p1:<25.4f} {p2:<25.4f}")
        print(f"  recall@{kv:<18} {r1:<25.4f} {r2:<25.4f}")

    print()
    print("WARNING: Domain-feature model performance is inflated by")
    print("sender/receiver domain-label correlations specific to CEAS_08.")
    print("It is NOT suitable for production use.")

    # === Save all results ===
    os.makedirs(REPORTS_DIR, exist_ok=True)

    with open(REPORTS_DIR / "training_report.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    with open(REPORTS_DIR / "ranking_report.json", "w") as f:
        json.dump({
            "primary_ranking": ranking_report,
            "domain_ranking": domain_ranking,
        }, f, indent=2, default=str)

    # Save model metadata
    metadata = {
        "model_type": "XGBoost",
        "transformer": "all-MiniLM-L6-v2",
        "pca_components": 64,
        "n_estimators": N_ESTIMATORS,
        "max_depth": MAX_DEPTH,
        "learning_rate": LEARNING_RATE,
        "calibration": "Platt scaling (sigmoid)",
        "random_seed": RANDOM_SEED,
        "training_date": pd.Timestamp.now().isoformat(),
        "dataset": "CEAS_08.csv.zip",
        "features_primary": list(data["X_train_primary"].columns),
        "features_domain": list(data["X_train_domain"].columns),
        "label_mapping": {"0": "ham (legitimate)", "1": "spam/phishing"},
        "primary_test_metrics": results["primary"]["test_cal"],
        "domain_test_metrics": results["domain"]["test_cal"],
        "model_version": "1.0.0",
    }
    with open(artifact_dir / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2, default=str)

    print(f"\n--- All artifacts saved ---")
    print(f"Models: {artifact_dir}")
    print(f"Reports: {REPORTS_DIR}")

    return results


if __name__ == "__main__":
    results = train_all()
    print("\nTraining complete.")
