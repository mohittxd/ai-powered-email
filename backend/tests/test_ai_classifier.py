"""
Unit & Integration tests for Phase 14: AI-assisted email classification.
"""
import pytest
from services.ai_classifier import (
    NLPPreprocessor,
    TransformerClassifier,
    XGBoostRiskClassifier,
    run_ai_classification,
)


def test_nlp_preprocessor():
    parsed = {
        "subject": "URGENT: Password Reset Required Now!",
        "body_text": "Please click here to verify your bank account credentials immediately.",
        "body_html": "<p>Urgent invoice transfer required.</p>",
    }
    nlp_data = NLPPreprocessor.preprocess(parsed)
    assert "Password Reset" in nlp_data["subject"]
    assert nlp_data["urgency_tokens"] >= 2
    assert nlp_data["credential_tokens"] >= 2
    assert nlp_data["word_count"] > 5


def test_transformer_classifier():
    tf = TransformerClassifier()
    nlp_data = {
        "full_text": "Subject: Urgent Bank Transfer\n\nVerify password immediately.",
        "urgency_tokens": 2,
        "credential_tokens": 2,
        "financial_tokens": 1,
        "executive_tokens": 0,
    }
    res = tf.predict_nlp_features(nlp_data)
    assert "nlp_urgency_score" in res
    assert "nlp_phishing_intent_score" in res
    assert res["nlp_phishing_intent_score"] > 0.0


def test_xgboost_classifier():
    xgb_engine = XGBoostRiskClassifier()
    nlp_features = {
        "nlp_urgency_score": 0.8,
        "nlp_phishing_intent_score": 0.9,
        "nlp_credential_harvest_score": 0.7,
        "nlp_social_eng_score": 0.6,
        "nlp_transformer_risk_raw": 0.75,
    }
    forensic_features = ["reply_to_mismatch", "suspicious_url", "url_shortener"]
    nlp_data = {"word_count": 120}
    auth_result = {"spf": {"status": "FAIL"}, "dkim": {"status": "FAIL"}, "dmarc": {"status": "FAIL"}}
    iocs = {"urls": [{"severity": "critical"}]}
    threat_intel = {"status": "success", "reputation": "malicious"}

    ml_score, importances = xgb_engine.predict_score(
        nlp_features, forensic_features, nlp_data, auth_result, iocs, threat_intel
    )
    assert 0 <= ml_score <= 100
    assert len(importances) > 0
    assert any(imp["feature"] == "dmarc_fail" or imp["feature"] == "nlp_phishing_intent_score" for imp in importances)


def test_ai_classification_full_pipeline_and_safeguards():
    parsed = {
        "subject": "Urgent PayPal Verification",
        "body_text": "Reset password at http://bit.ly/fake",
        "body_html": "",
        "embedded_urls": ["http://bit.ly/fake"],
    }
    auth_result = {
        "spf": {"status": "FAIL"},
        "dkim": {"status": "FAIL"},
        "dmarc": {"status": "FAIL"},
    }
    forensics = {"anomalies": [{"type": "reply_to_mismatch"}]}
    iocs = {"urls": [{"severity": "critical", "tags": ["url_shortener"]}]}
    threat_intel = {"status": "success", "reputation": "malicious"}
    rule_result = {
        "risk_score": 75,
        "features": ["reply_to_mismatch", "suspicious_url", "url_shortener"],
        "reasons": ["Reply-To mismatch detected"],
    }

    res = run_ai_classification(parsed, auth_result, forensics, iocs, threat_intel, rule_result)

    # 1. Distinguish rule_based_score, ml_score, final_risk_score
    assert "rule_based_score" in res
    assert "ml_score" in res
    assert "final_risk_score" in res
    assert res["rule_based_score"] == 75

    # 2. Authentication threat floor safeguard (DMARC fail floor = 60, reply-to mismatch floor = 50)
    assert res["final_risk_score"] >= 60

    # 3. Calibration note present
    assert "calibration_note" in res
    assert "not a statistically validated probability" in res["calibration_note"]

    # 4. Feature importances present
    assert "feature_importance" in res
    assert len(res["feature_importance"]) > 0


def test_ai_classification_fallback_when_pipeline_errors(monkeypatch):
    """If ML model pipeline encounters an error, fall back to rule-based score."""
    parsed = {"subject": "Normal Meeting", "body_text": "See you at 3pm."}
    auth_result = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    forensics = {"anomalies": []}
    iocs = {"urls": []}
    threat_intel = {"status": "unavailable"}
    rule_result = {"risk_score": 10, "features": [], "reasons": []}

    # Simulate exception during preprocessing/model step
    def broken_preprocess(*args, **kwargs):
        raise RuntimeError("Model loading offline")

    monkeypatch.setattr(NLPPreprocessor, "preprocess", broken_preprocess)

    res = run_ai_classification(parsed, auth_result, forensics, iocs, threat_intel, rule_result)

    assert res["rule_based_score"] == 10
    assert res["final_risk_score"] == 10
    assert res["ml_available"] is False
