"""
predict.py — Single Email Risk Prediction API

Accepts:
  - subject
  - body
  - optional sender
  - optional receiver
  - optional urls

Returns:
  - risk_score (0-1, calibrated)
  - raw_score (0-1, uncalibrated)
  - predicted_class ("spam" or "ham")
  - model_version
  - confidence ("high", "medium", "low")
"""

import json
import os
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# Import PlattScaler so joblib can unpickle calibrated models
sys.path.insert(0, str(Path(__file__).resolve().parent))
from platt_scaler import PlattScaler  # noqa: F401

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
ARTIFACT_DIR = MODELS_DIR / "email_risk_model"

_model_primary = None
_model_domain = None
_tfidf = None
_svd = None
_sender_map = None
_receiver_map = None
_metadata = None


def _load_artifacts():
    """Lazy-load all model artifacts."""
    global _model_primary, _model_domain, _tfidf, _svd
    global _sender_map, _receiver_map, _metadata

    if _model_primary is not None:
        return

    print("Loading model artifacts...")
    _model_primary = joblib.load(ARTIFACT_DIR / "xgb_model_calibrated.joblib")
    _tfidf = joblib.load(ARTIFACT_DIR / "tfidf_model.joblib")
    _svd = joblib.load(ARTIFACT_DIR / "svd_model.joblib")
    _sender_map = joblib.load(ARTIFACT_DIR / "sender_domain_map.joblib")
    _receiver_map = joblib.load(ARTIFACT_DIR / "receiver_domain_map.joblib")

    with open(ARTIFACT_DIR / "model_metadata.json") as f:
        _metadata = json.load(f)

    print(f"  Model version: {_metadata.get('model_version', 'unknown')}")


def _extract_domain(email_str):
    """Extract domain from email address."""
    if not isinstance(email_str, str):
        return "unknown"
    m = re.search(r"@([\w.\-]+)", email_str)
    return m.group(1).lower() if m else "unknown"


def _extract_structural_features(subject, body, sender=None, receiver=None, urls=None):
    """Extract the same structured features used in training."""
    subject = subject or ""
    body = body or ""

    features = {}
    features["subject_len"] = len(subject)
    features["subject_word_count"] = len(subject.split())
    features["subject_uppercase_ratio"] = (
        sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
    )
    features["subject_special_char_ratio"] = (
        sum(1 for c in subject if not c.isalnum() and not c.isspace()) / max(len(subject), 1)
    )
    features["body_len"] = len(body)
    features["body_word_count"] = len(body.split())
    words = body.split()
    features["avg_word_length"] = float(np.mean([len(w) for w in words])) if words else 0.0
    features["exclamation_count"] = body.count("!")
    features["body_digit_ratio"] = (
        sum(1 for c in body if c.isdigit()) / max(len(body), 1)
    )
    features["has_html_tags"] = 1 if re.search(r"<[a-zA-Z/][^>]*>", body) else 0
    features["body_line_count"] = body.count("\n")

    cap_run = 0
    cap_count = 0
    for w in body.split():
        if w.isupper() and len(w) > 1:
            cap_run += 1
            if cap_run >= 3:
                cap_count += 1
        else:
            cap_run = 0
    features["body_caps_sequences"] = cap_count

    features["url_count_binary"] = 1 if (urls and int(urls) > 0) else 0
    features["has_url_in_body"] = 1 if re.search(r"https?://\S+|www\.\S+", body) else 0
    features["body_url_count"] = len(re.findall(r"https?://\S+|www\.\S+", body))

    sender_domain = _extract_domain(sender) if sender else "unknown"
    sender_total = sum(_sender_map.values()) if _sender_map else 1
    features["sender_domain_freq"] = (
        _sender_map.get(sender_domain, 0) / sender_total if _sender_map else 0.0
    )

    receiver_domain = _extract_domain(receiver) if receiver else "unknown"
    receiver_total = sum(_receiver_map.values()) if _receiver_map else 1
    features["receiver_domain_freq"] = (
        _receiver_map.get(receiver_domain, 0) / receiver_total if _receiver_map else 0.0
    )

    return features


def predict_email(subject, body, sender=None, receiver=None, urls=None,
                  use_domain_features=False):
    """
    Predict risk score for a single email.
    """
    _load_artifacts()

    # Text features via TF-IDF + SVD
    text = f"{subject or ''} {body or ''}".strip()
    tfidf_vec = _tfidf.transform([text])
    svd_vec = _svd.transform(tfidf_vec)
    svd_df = pd.DataFrame(svd_vec, columns=[f"svd_{i}" for i in range(svd_vec.shape[1])])

    # Structured features
    struct_features = _extract_structural_features(subject, body, sender, receiver, urls)
    struct_df = pd.DataFrame([struct_features])

    structural_cols = [c for c in struct_df.columns if c in _metadata["features_primary"]]

    if use_domain_features and _model_domain is not None:
        X = pd.concat([struct_df, svd_df], axis=1)
        model = _model_domain
    else:
        X = pd.concat([struct_df[structural_cols], svd_df], axis=1)
        model = _model_primary

    # Predict
    raw_score = float(model.predict_proba(X)[:, 1][0])
    predicted_class = "spam" if raw_score >= 0.5 else "ham"

    if raw_score >= 0.8 or raw_score <= 0.2:
        confidence = "high"
    elif raw_score >= 0.6 or raw_score <= 0.4:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "risk_score": round(raw_score, 4),
        "raw_score": round(raw_score, 4),
        "predicted_class": predicted_class,
        "model_version": _metadata.get("model_version", "1.0.0"),
        "confidence": confidence,
    }


def main():
    """CLI entry point for single email prediction."""
    import argparse

    parser = argparse.ArgumentParser(description="Predict email risk score")
    parser.add_argument("--subject", required=True, help="Email subject")
    parser.add_argument("--body", required=True, help="Email body")
    parser.add_argument("--sender", default=None, help="Sender email")
    parser.add_argument("--receiver", default=None, help="Receiver email")
    parser.add_argument("--urls", type=int, default=None, help="URL count")
    args = parser.parse_args()

    result = predict_email(
        subject=args.subject,
        body=args.body,
        sender=args.sender,
        receiver=args.receiver,
        urls=args.urls,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
