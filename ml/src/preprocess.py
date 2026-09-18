"""
preprocess.py — CEAS_08 Dataset Loading, Feature Engineering, and Splitting

Loads the CEAS_08.csv.zip dataset, extracts structured features, generates
text representations via TF-IDF + TruncatedSVD (CPU-friendly), and performs
stratified train/validation/test splitting with NO data leakage.

All fitting (SVD, frequency encoders, TF-IDF) occurs ONLY on the training split.
"""

import csv
import io
import json
import os
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "datasets" / "CEAS_08.csv.zip"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

RANDOM_SEED = 42
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15
TEXT_DIM = 64
TFIDF_MAX_FEATURES = 10000

csv.field_size_limit(sys.maxsize)


def load_ceas_dataset():
    """Load CEAS_08.csv.zip into a DataFrame."""
    print(f"Loading dataset from {DATASET_PATH}...")
    with zipfile.ZipFile(DATASET_PATH, "r") as z:
        fname = z.namelist()[0]
        with z.open(fname) as f:
            text = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
            df = pd.read_csv(text, low_memory=False)
    print(f"  Loaded {len(df)} rows, columns: {list(df.columns)}")
    return df


def extract_sender_domain(sender):
    """Extract domain from sender email, return lowercase or 'unknown'."""
    if not isinstance(sender, str):
        return "unknown"
    m = re.search(r"@([\w.\-]+)", sender)
    return m.group(1).lower() if m else "unknown"


def extract_receiver_domain(receiver):
    """Extract domain from receiver email, return lowercase or 'unknown'."""
    if not isinstance(receiver, str):
        return "unknown"
    m = re.search(r"@([\w.\-]+)", receiver)
    return m.group(1).lower() if m else "unknown"


def count_urls_in_text(text):
    """Count occurrences of http/https/www URLs in text."""
    if not isinstance(text, str):
        return 0
    return len(re.findall(r"https?://\S+|www\.\S+", text))


def count_caps_sequences(text, min_len=3):
    """Count runs of min_len or more consecutive uppercase words."""
    if not isinstance(text, str):
        return 0
    words = text.split()
    count = 0
    run = 0
    for w in words:
        if w.isupper() and len(w) > 1:
            run += 1
            if run >= min_len:
                count += 1
        else:
            run = 0
    return count


def has_html_tags(text):
    """Check if text contains HTML-like tags."""
    if not isinstance(text, str):
        return 0
    return 1 if re.search(r"<[a-zA-Z/][^>]*>", text) else 0


def build_structured_features(df, sender_domain_map=None, receiver_domain_map=None,
                              fit_encoder=False):
    """
    Build structured feature matrix from the DataFrame.
    """
    features = pd.DataFrame()

    features["subject_len"] = df["subject"].fillna("").str.len()
    features["subject_word_count"] = df["subject"].fillna("").str.split().str.len()
    features["subject_uppercase_ratio"] = df["subject"].fillna("").apply(
        lambda x: sum(1 for c in x if c.isupper()) / max(len(x), 1)
    )
    features["subject_special_char_ratio"] = df["subject"].fillna("").apply(
        lambda x: sum(1 for c in x if not c.isalnum() and not c.isspace()) / max(len(x), 1)
    )

    features["body_len"] = df["body"].fillna("").str.len()
    features["body_word_count"] = df["body"].fillna("").str.split().str.len()
    features["avg_word_length"] = df["body"].fillna("").apply(
        lambda x: np.mean([len(w) for w in x.split()]) if x.split() else 0
    )
    features["exclamation_count"] = df["body"].fillna("").str.count("!")
    features["body_digit_ratio"] = df["body"].fillna("").apply(
        lambda x: sum(1 for c in x if c.isdigit()) / max(len(x), 1)
    )
    features["has_html_tags"] = df["body"].fillna("").apply(has_html_tags)
    features["body_line_count"] = df["body"].fillna("").str.count("\n")
    features["body_caps_sequences"] = df["body"].fillna("").apply(
        lambda x: count_caps_sequences(x)
    )

    features["url_count_binary"] = df["urls"].fillna("0").astype(str).apply(
        lambda x: 1 if x.strip() == "1" else 0
    )
    features["has_url_in_body"] = df["body"].fillna("").apply(
        lambda x: 1 if re.search(r"https?://\S+|www\.\S+", x) else 0
    )
    features["body_url_count"] = df["body"].fillna("").apply(count_urls_in_text)

    sender_domains = df["sender"].fillna("unknown").apply(extract_sender_domain)
    if fit_encoder:
        sender_domain_map = dict(Counter(sender_domains))
        total = len(sender_domains)
        sender_domain_map = {k: v / total for k, v in sender_domain_map.items()}
    features["sender_domain_freq"] = sender_domains.map(
        lambda d: sender_domain_map.get(d, 0.0) if sender_domain_map else 0.0
    )

    receiver_domains = df["receiver"].fillna("unknown").apply(extract_receiver_domain)
    if fit_encoder:
        receiver_domain_map = dict(Counter(receiver_domains))
        total = len(receiver_domains)
        receiver_domain_map = {k: v / total for k, v in receiver_domain_map.items()}
    features["receiver_domain_freq"] = receiver_domains.map(
        lambda d: receiver_domain_map.get(d, 0.0) if receiver_domain_map else 0.0
    )

    return features, sender_domain_map, receiver_domain_map


PRIMARY_STRUCTURAL_FEATURES = [
    "subject_len", "subject_word_count", "subject_uppercase_ratio",
    "subject_special_char_ratio",
    "body_len", "body_word_count", "avg_word_length",
    "exclamation_count", "body_digit_ratio", "has_html_tags",
    "body_line_count", "body_caps_sequences",
    "url_count_binary", "has_url_in_body", "body_url_count",
]

DOMAIN_FEATURES = ["sender_domain_freq", "receiver_domain_freq"]


def prepare_dataset():
    """
    Full preprocessing pipeline:
    1. Load dataset
    2. Build structured features
    3. Train/val/test split (stratified)
    4. TF-IDF + TruncatedSVD for text (fit on train only)
    5. Transform all splits
    6. Assemble final feature matrices
    7. Save all artifacts
    """
    # --- 1. Load ---
    df = load_ceas_dataset()
    labels = df["label"].astype(int).values
    print(f"\n  Label distribution: {dict(Counter(labels))}")

    # --- 2. Split (before any fitting) ---
    indices = np.arange(len(df))
    train_idx, temp_idx, train_labels, temp_labels = train_test_split(
        indices, labels, test_size=(1 - TRAIN_RATIO),
        stratify=labels, random_state=RANDOM_SEED
    )
    val_relative_ratio = VAL_RATIO / (VAL_RATIO + TEST_RATIO)
    val_idx, test_idx, val_labels, test_labels = train_test_split(
        temp_idx, temp_labels, test_size=(1 - val_relative_ratio),
        stratify=temp_labels, random_state=RANDOM_SEED
    )

    print(f"\n  Split sizes:")
    print(f"    Train: {len(train_idx)} ({100*len(train_idx)/len(df):.1f}%)")
    print(f"    Val:   {len(val_idx)} ({100*len(val_idx)/len(df):.1f}%)")
    print(f"    Test:  {len(test_idx)} ({100*len(test_idx)/len(df):.1f}%)")
    print(f"    Train label dist: {dict(Counter(train_labels))}")
    print(f"    Val label dist:   {dict(Counter(val_labels))}")
    print(f"    Test label dist:  {dict(Counter(test_labels))}")

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_val = df.iloc[val_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    # --- 3. Structured features (fit encoder on train only) ---
    features_train, sender_map, receiver_map = build_structured_features(
        df_train, fit_encoder=True
    )
    features_val, _, _ = build_structured_features(
        df_val, sender_domain_map=sender_map, receiver_domain_map=receiver_map,
        fit_encoder=False
    )
    features_test, _, _ = build_structured_features(
        df_test, sender_domain_map=sender_map, receiver_domain_map=receiver_map,
        fit_encoder=False
    )

    # --- 4. TF-IDF + TruncatedSVD (fit on train only) ---
    print("\n--- Text Representation: TF-IDF + TruncatedSVD ---")

    texts_train = (df_train["subject"].fillna("") + " " + df_train["body"].fillna("")).tolist()
    texts_val = (df_val["subject"].fillna("") + " " + df_val["body"].fillna("")).tolist()
    texts_test = (df_test["subject"].fillna("") + " " + df_test["body"].fillna("")).tolist()

    print(f"  Fitting TF-IDF on {len(texts_train)} training texts...")
    tfidf = TfidfVectorizer(
        max_features=TFIDF_MAX_FEATURES,
        stop_words="english",
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
    )
    tfidf_train = tfidf.fit_transform(texts_train)
    print(f"  TF-IDF vocabulary size: {len(tfidf.vocabulary_)}")
    print(f"  Training TF-IDF matrix: {tfidf_train.shape}")

    print(f"  Fitting TruncatedSVD ({TEXT_DIM} components)...")
    svd = TruncatedSVD(n_components=TEXT_DIM, random_state=RANDOM_SEED)
    svd_train = svd.fit_transform(tfidf_train)
    explained = svd.explained_variance_ratio_.sum()
    print(f"  Explained variance: {explained:.2%}")

    tfidf_val = tfidf.transform(texts_val)
    svd_val = svd.transform(tfidf_val)

    tfidf_test = tfidf.transform(texts_test)
    svd_test = svd.transform(tfidf_test)

    print(f"  Train text features: {svd_train.shape}")
    print(f"  Val text features:   {svd_val.shape}")
    print(f"  Test text features:  {svd_test.shape}")

    # --- 5. Assemble final features ---
    svd_train_df = pd.DataFrame(svd_train, columns=[f"svd_{i}" for i in range(TEXT_DIM)])
    svd_val_df = pd.DataFrame(svd_val, columns=[f"svd_{i}" for i in range(TEXT_DIM)])
    svd_test_df = pd.DataFrame(svd_test, columns=svd_train_df.columns)

    # PRIMARY MODEL: structural + SVD (NO domain features)
    X_train_primary = pd.concat([features_train.reset_index(drop=True), svd_train_df], axis=1)[PRIMARY_STRUCTURAL_FEATURES + list(svd_train_df.columns)]
    X_val_primary = pd.concat([features_val.reset_index(drop=True), svd_val_df], axis=1)[PRIMARY_STRUCTURAL_FEATURES + list(svd_val_df.columns)]
    X_test_primary = pd.concat([features_test.reset_index(drop=True), svd_test_df], axis=1)[PRIMARY_STRUCTURAL_FEATURES + list(svd_test_df.columns)]

    # DOMAIN MODEL: structural + SVD + domain features
    domain_cols = PRIMARY_STRUCTURAL_FEATURES + DOMAIN_FEATURES + list(svd_train_df.columns)
    X_train_domain = pd.concat([features_train.reset_index(drop=True), svd_train_df], axis=1)[domain_cols]
    X_val_domain = pd.concat([features_val.reset_index(drop=True), svd_val_df], axis=1)[domain_cols]
    X_test_domain = pd.concat([features_test.reset_index(drop=True), svd_test_df], axis=1)[domain_cols]

    print(f"\n  Primary feature matrix shape: {X_train_primary.shape}")
    print(f"  Domain feature matrix shape:   {X_train_domain.shape}")

    # --- 6. Save artifacts ---
    import joblib
    artifact_dir = MODELS_DIR / "email_risk_model"
    os.makedirs(artifact_dir, exist_ok=True)

    np.save(artifact_dir / "train_idx.npy", train_idx)
    np.save(artifact_dir / "val_idx.npy", val_idx)
    np.save(artifact_dir / "test_idx.npy", test_idx)

    np.save(artifact_dir / "labels_all.npy", labels)
    np.save(artifact_dir / "labels_train.npy", train_labels)
    np.save(artifact_dir / "labels_val.npy", val_labels)
    np.save(artifact_dir / "labels_test.npy", test_labels)

    joblib.dump(tfidf, artifact_dir / "tfidf_model.joblib")
    joblib.dump(svd, artifact_dir / "svd_model.joblib")
    joblib.dump(sender_map, artifact_dir / "sender_domain_map.joblib")
    joblib.dump(receiver_map, artifact_dir / "receiver_domain_map.joblib")

    metadata = {
        "text_representation": "TF-IDF + TruncatedSVD",
        "tfidf_max_features": TFIDF_MAX_FEATURES,
        "svd_components": TEXT_DIM,
        "svd_explained_variance": float(explained),
        "primary_features": PRIMARY_STRUCTURAL_FEATURES,
        "domain_features": DOMAIN_FEATURES,
        "train_size": len(train_idx),
        "val_size": len(val_idx),
        "test_size": len(test_idx),
        "random_seed": RANDOM_SEED,
        "label_mapping": {"0": "ham (legitimate)", "1": "spam/phishing"},
    }
    with open(artifact_dir / "feature_config.json", "w") as f:
        json.dump(metadata, f, indent=2)

    X_train_primary.to_csv(artifact_dir / "X_train_primary.csv", index=False)
    X_val_primary.to_csv(artifact_dir / "X_val_primary.csv", index=False)
    X_test_primary.to_csv(artifact_dir / "X_test_primary.csv", index=False)
    X_train_domain.to_csv(artifact_dir / "X_train_domain.csv", index=False)
    X_val_domain.to_csv(artifact_dir / "X_val_domain.csv", index=False)
    X_test_domain.to_csv(artifact_dir / "X_test_domain.csv", index=False)

    email_meta = df[["sender", "subject", "date"]].copy()
    email_meta["sender_domain"] = email_meta["sender"].fillna("unknown").apply(extract_sender_domain)
    email_meta["subject_summary"] = email_meta["subject"].fillna("").str[:80]
    email_meta.to_csv(artifact_dir / "email_metadata.csv", index=False)

    print(f"\n--- Artifacts saved to {artifact_dir} ---")

    return {
        "X_train_primary": X_train_primary,
        "X_val_primary": X_val_primary,
        "X_test_primary": X_test_primary,
        "X_train_domain": X_train_domain,
        "X_val_domain": X_val_domain,
        "X_test_domain": X_test_domain,
        "y_train": train_labels,
        "y_val": val_labels,
        "y_test": test_labels,
        "train_idx": train_idx,
        "val_idx": val_idx,
        "test_idx": test_idx,
        "labels_all": labels,
        "df": df,
        "tfidf": tfidf,
        "svd": svd,
        "sender_map": sender_map,
        "receiver_map": receiver_map,
        "metadata": metadata,
    }


if __name__ == "__main__":
    data = prepare_dataset()
    print("\nPreprocessing complete.")
    print(f"Primary features: {list(data['X_train_primary'].columns)}")
    print(f"Domain features:  {list(data['X_train_domain'].columns)}")
