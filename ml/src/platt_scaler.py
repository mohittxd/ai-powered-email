"""
platt_scaler.py — Platt Scaling for Probability Calibration

Standalone module so joblib can unpickle calibrated models
regardless of which script loads them.
"""

import numpy as np
from scipy.special import expit
from scipy.optimize import minimize


class PlattScaler:
    """Manual Platt scaling: fit sigmoid on validation predictions."""

    def __init__(self, base_model):
        self.base_model = base_model
        self.A = None
        self.B = None

    def fit(self, X_val, y_val):
        raw_probs = self.base_model.predict_proba(X_val)[:, 1]
        raw_probs = np.clip(raw_probs, 1e-7, 1 - 1e-7)

        def neg_log_likelihood(params):
            A, B = params
            p_cal = expit(A * np.log(raw_probs / (1 - raw_probs)) + B)
            p_cal = np.clip(p_cal, 1e-7, 1 - 1e-7)
            return -np.sum(y_val * np.log(p_cal) + (1 - y_val) * np.log(1 - p_cal))

        result = minimize(neg_log_likelihood, [1.0, 0.0], method="Nelder-Mead")
        self.A, self.B = result.x
        print(f"  Platt params: A={self.A:.4f}, B={self.B:.4f}")
        return self

    def predict_proba(self, X):
        raw_probs = self.base_model.predict_proba(X)[:, 1]
        raw_probs = np.clip(raw_probs, 1e-7, 1 - 1e-7)
        cal_probs = expit(self.A * np.log(raw_probs / (1 - raw_probs)) + self.B)
        cal_probs = np.clip(cal_probs, 1e-7, 1 - 1e-7)
        return np.column_stack([1 - cal_probs, cal_probs])
