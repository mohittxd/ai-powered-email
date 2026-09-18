# Email Risk Ranking ML System

XGBoost-based email risk scoring and ranking system trained on CEAS_08 (2008 CEAS Anti-Spam Challenge dataset).

Produces a continuous `risk_score` (0–1) for ranking emails by threat likelihood.

## Quick Start

```bash
cd "ml/"

# 1. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run full pipeline (preprocess + train + evaluate)
python src/run_pipeline.py

# 4. Single email prediction
python src/predict.py \
  --subject "Urgent: verify your account" \
  --body "Click here to verify: http://phish.com" \
  --sender "security@phish.com"

# 5. Batch ranking (demo)
python src/batch_rank.py --demo

# 6. Batch ranking (from file)
python src/batch_rank.py --input emails.json --output rankings.csv
```

## Project Structure

```
ml/
├── datasets/
│   └── CEAS_08.csv.zip          # Source dataset
├── src/
│   ├── run_pipeline.py           # Full pipeline orchestrator
│   ├── preprocess.py             # Dataset loading, feature engineering, splits
│   ├── train.py                  # XGBoost training + Platt calibration
│   ├── evaluate.py               # Metrics, plots, ranking analysis
│   ├── predict.py                # Single email prediction API
│   ├── batch_rank.py             # Batch ranking script
│   └── platt_scaler.py           # Standalone Platt scaling module
├── models/
│   └── email_risk_model/         # All trained model artifacts
│       ├── xgb_model_raw.joblib          # Uncalibrated XGBoost
│       ├── xgb_model_calibrated.joblib   # Calibrated XGBoost (primary)
│       ├── xgb_model_domain_raw.joblib       # Domain-leakage variant (raw)
│       ├── xgb_model_domain_calibrated.joblib # Domain-leakage variant (calibrated)
│       ├── tfidf_model.joblib            # TF-IDF vectorizer (fitted on train)
│       ├── svd_model.joblib              # TruncatedSVD (fitted on train)
│       ├── pca_model.joblib              # PCA (legacy, not used)
│       ├── sender_domain_map.joblib      # Sender domain frequencies (train)
│       ├── receiver_domain_map.joblib    # Receiver domain frequencies (train)
│       ├── feature_config.json           # Feature names, splits, metadata
│       ├── model_metadata.json           # Full model metadata + metrics
│       ├── email_metadata.csv            # Sender/subject for ranking reports
│       ├── X_train_primary.csv           # Training features (primary)
│       ├── X_val_primary.csv             # Validation features (primary)
│       ├── X_test_primary.csv            # Test features (primary)
│       ├── X_train_domain.csv            # Training features (domain variant)
│       ├── X_val_domain.csv              # Validation features (domain variant)
│       ├── X_test_domain.csv             # Test features (domain variant)
│       ├── labels_*.npy                  # Labels arrays
│       └── *_idx.npy                     # Split indices
├── reports/                      # Generated reports and plots
│   ├── training_report.json
│   ├── evaluation_report.json
│   ├── ranking_report.json
│   ├── ranking_details.json
│   ├── feature_importance_primary.csv
│   ├── confusion_matrix_primary.png
│   ├── confusion_matrix_domain.png
│   ├── roc_curve_primary.png
│   ├── roc_curve_domain.png
│   ├── pr_curve_primary.png
│   ├── pr_curve_domain.png
│   ├── score_distribution_primary.png
│   ├── score_distribution_domain.png
│   ├── model_comparison.png
│   └── feature_importance_primary.png
├── requirements.txt
├── README.md
└── .venv/                        # Virtual environment
```

## Dataset

**CEAS_08.csv.zip** — 2008 Challenge on Email Anti-Spam

| Property | Value |
|---|---|
| Total rows | 39,154 |
| Label=1 (spam) | 21,842 (55.8%) |
| Label=0 (ham) | 17,312 (44.2%) |
| Columns | sender, receiver, date, subject, body, label, urls |
| Duplicates | 0 |

### Label Mapping
- `0` = ham (legitimate email)
- `1` = spam / phishing

## Model Architecture

### Text Representation
**TF-IDF (10K features, 1-2 grams) → TruncatedSVD (64 components)**

- Fits TF-IDF vocabulary and SVD projection on training data only
- Transforms validation/test splits using the training-fit objects
- ~32% variance explained (sufficient for classification)

**Note:** The original plan used sentence-transformers (all-MiniLM-L6-v2) but this hardware (AMD A8-6410, CPU-only) could not complete inference in reasonable time (~9+ hours). TF-IDF+SVD runs in seconds and provides effective text features for spam classification.

### Structured Features (15, primary model)
- `subject_len`, `subject_word_count`, `subject_uppercase_ratio`, `subject_special_char_ratio`
- `body_len`, `body_word_count`, `avg_word_length`, `exclamation_count`, `body_digit_ratio`
- `has_html_tags`, `body_line_count`, `body_caps_sequences`
- `url_count_binary`, `has_url_in_body`, `body_url_count`

### Domain Features (experimental model only, NOT for production)
- `sender_domain_freq` — frequency of sender domain in training data
- `receiver_domain_freq` — frequency of receiver domain in training data

### Classifier
**XGBoost** with early stopping on validation set, class-weight balancing via `scale_pos_weight`.

## Data Leakage Prevention

- **Stratified 70/15/10 split** with fixed random seed (42)
- **PCA/SVD fitted on training split only** — validation/test are transformed, never fit
- **Frequency encoders fitted on training split only** — unseen domains get frequency 0
- **Platt calibration fitted on validation split only** — test set never used for calibration
- **Test set held out completely** — used only for final evaluation

### Known Leakage Vectors (CEAS_08)
Sender and receiver domains are extreme leakage vectors:
- 244 sender domains (≥10 emails) are 100% ham (e.g., `issues.apache.org`, `python.org`)
- 63 sender domains (≥10 emails) are 100% spam
- Receiver `gvc.ceas-challenge.cc` is 91.5% spam and contains 60.8% of all data

**This is why the PRIMARY model excludes domain features entirely.**

## Training Metrics

### Primary Model (no domain features)
| Metric | Validation (Raw) | Validation (Calibrated) | Test (Raw) | Test (Calibrated) |
|---|---|---|---|---|
| ROC-AUC | 0.9998 | 0.9998 | 0.9999 | 0.9999 |
| PR-AUC | 0.9999 | 0.9999 | 1.0000 | 1.0000 |
| Precision | — | — | 0.9979 | 0.9979 |
| Recall | — | — | 0.9969 | 0.9969 |
| F1 | — | — | 0.9974 | 0.9974 |
| Accuracy | — | — | 0.9971 | 0.9971 |

### Domain-Feature Model (leakage demo)
| Metric | Test (Calibrated) |
|---|---|
| ROC-AUC | 1.0000 |
| PR-AUC | 1.0000 |
| Precision | 0.9991 |
| Recall | 0.9982 |
| F1 | 0.9986 |
| Accuracy | 0.9985 |

### Ranking Metrics (Primary Model, Test Set)
| Metric | Value |
|---|---|
| Precision@5% | 1.0000 |
| Recall@5% | 0.0894 |
| Precision@10% | 1.0000 |
| Recall@10% | 0.1791 |
| Precision@50 | 1.0000 |
| Recall@50 | 0.0153 |
| Precision@100 | 1.0000 |
| Recall@100 | 0.0305 |

### Top Ranked Emails (Test Set)
- **Top 10:** 10/10 spam, 0/10 ham
- **Top 50:** 50/50 spam, 0/50 ham
- **Top 100:** 100/100 spam, 0/100 ham

### Confusion Matrix (Primary, Test)
```
            Predicted
            Ham     Spam
Actual Ham  [2590      7]
       Spam [  10   3267]
```

### Feature Importance (Top 10)
1. `svd_2` — 31.9%
2. `svd_9` — 9.1%
3. `body_len` — 8.9%
4. `svd_3` — 5.7%
5. `body_line_count` — 5.1%
6. `svd_4` — 3.2%
7. `subject_special_char_ratio` — 2.7%
8. `svd_1` — 2.7%
9. `svd_8` — 2.5%
10. `svd_11` — 1.7%

## Calibration

- **Method:** Platt scaling (sigmoid) fitted on validation set
- **Primary model params:** A=0.976, B=0.339
- **Domain model params:** A=1.044, B=-0.099
- Raw and calibrated scores are very close (A≈1, B≈0 means minimal correction needed)
- Both `risk_score` and `raw_score` are returned by predict.py

## Limitations & Warnings

1. **Dataset-specific performance:** CEAS_08 is a well-separated spam dataset. Real-world email threat detection would require additional features (authentication headers, reputation data, etc.)
2. **Domain features leak:** The domain-frequency model achieves near-perfect scores because of extreme sender/receiver domain-label correlations in CEAS_08. This model is NOT generalizable.
3. **No header forensic features:** This model does NOT use SPF, DKIM, DMARC, IP geolocation, ASN, WHOIS, or Received-chain data. These would need to be added separately in the Forensic AI backend integration.
4. **Text representation:** TF-IDF+SVD is used instead of sentence-transformers due to hardware constraints (AMD A8-6410, CPU-only). Upgrading to a GPU system would allow using the full transformer pipeline.
5. **Not integrated with FastAPI yet:** The prediction API is standalone Python. Integration with the Forensic AI backend is a future step.

## Files Created
- `ml/src/preprocess.py`
- `ml/src/train.py`
- `ml/src/evaluate.py`
- `ml/src/predict.py`
- `ml/src/batch_rank.py`
- `ml/src/platt_scaler.py`
- `ml/src/run_pipeline.py`
- `ml/src/__init__.py`
- `ml/requirements.txt`
- `ml/README.md`
- `ml/models/email_risk_model/*` (all artifacts)
- `ml/reports/*` (all reports and plots)

## Files Modified
- None. No existing files in the Forensic AI project were modified.

## Version
- Model version: 1.0.0
- Dataset: CEAS_08.csv.zip
- Training date: 2026-09-18
