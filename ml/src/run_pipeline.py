"""
run_pipeline.py — Full ML Pipeline Orchestration

Runs the complete pipeline:
1. Preprocessing (dataset loading, feature engineering, splits)
2. Training (both model variants)
3. Evaluation (metrics, plots, ranking)
4. Verification

Usage:
    python ml/src/run_pipeline.py
"""

import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def main():
    start = time.time()

    print("=" * 70)
    print("EMAIL RISK RANKING — FULL ML PIPELINE")
    print("=" * 70)

    # Step 1: Preprocess
    print("\n\n" + "=" * 70)
    print("STEP 1: PREPROCESSING")
    print("=" * 70)
    from preprocess import prepare_dataset
    data = prepare_dataset()

    # Step 2: Train
    print("\n\n" + "=" * 70)
    print("STEP 2: TRAINING")
    print("=" * 70)
    from train import train_all
    results = train_all()

    # Step 3: Evaluate
    print("\n\n" + "=" * 70)
    print("STEP 3: EVALUATION")
    print("=" * 70)
    from evaluate import evaluate_all
    eval_report = evaluate_all()

    elapsed = time.time() - start
    print(f"\n\n{'=' * 70}")
    print(f"PIPELINE COMPLETE — Total time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
