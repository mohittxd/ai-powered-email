"""
Unit tests — Phase 7: Explainable Risk Engine.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.risk_engine import (
    calculate_risk_score, _detect_body_features,
    CL_LEGITIMATE, CL_SUSPICIOUS, CL_IMPERSONATION, CL_PHISHING, CL_CRITICAL
)

class TestBodyFeatures:
    def test_urgency(self):
        features = _detect_body_features("Please do this immediately!", "")
        assert any(f[2] == "urgency_indicators" for f in features)

    def test_credential(self):
        features = _detect_body_features("Click to reset password", "")
        assert any(f[2] == "credential_request" for f in features)

    def test_financial(self):
        features = _detect_body_features("Please wire funds to this account", "")
        assert any(f[2] == "financial_indicators" for f in features)

    def test_exec_impersonation(self):
        features = _detect_body_features("are you at your desk? need a favor", "")
        assert any(f[2] == "exec_impersonation" for f in features)

    def test_clean_body(self):
        features = _detect_body_features("Hello, checking in.", "<html></html>")
        assert len(features) == 0


class TestCalculateRiskScore:
    def _defaults(self):
        return {
            "parsed": {},
            "auth_result": {},
            "forensics": {},
            "iocs": {},
            "threat_intel": {},
        }

    def test_perfectly_clean_is_legit(self):
        data = self._defaults()
        res = calculate_risk_score(**data)
        assert res["risk_score"] == 0
        assert res["classification"] == CL_LEGITIMATE
        assert len(res["reasons"]) == 0

    def test_auth_failures(self):
        data = self._defaults()
        data["auth_result"] = {
            "spf": {"status": "FAIL"},
            "dkim": {"status": "FAIL"},
            "dmarc": {"status": "FAIL"},
        }
        res = calculate_risk_score(**data)
        assert res["risk_score"] == 45
        assert "spf_failure" in res["features"]
        assert "dkim_failure" in res["features"]
        assert "dmarc_failure" in res["features"]

    def test_auth_none_does_not_add_points(self):
        data = self._defaults()
        data["auth_result"] = {
            "spf": {"status": "NONE"},
            "dkim": {"status": "UNAVAILABLE"},
            "dmarc": {"status": "UNKNOWN"},
        }
        res = calculate_risk_score(**data)
        assert res["risk_score"] == 0

    def test_header_anomalies(self):
        data = self._defaults()
        data["forensics"] = {
            "anomalies": [
                {"type": "reply_to_mismatch"},
                {"type": "from_sender_mismatch"},
                {"type": "timestamp_regression"},
            ]
        }
        res = calculate_risk_score(**data)
        assert res["risk_score"] == 23
        assert "reply_to_mismatch" in res["features"]

    def test_ioc_anomalies(self):
        data = self._defaults()
        data["iocs"] = {
            "urls": [
                {"severity": "high", "tags": ["suspicious_tld"]},
                {"severity": "critical", "tags": ["url_shortener"]},
            ],
            "attachments": [
                {"severity": "high"}
            ]
        }
        res = calculate_risk_score(**data)
        # high_url=10, shortener=5, high_attachment=10 -> 25
        assert res["risk_score"] == 25

    def test_threat_intel_malicious(self):
        data = self._defaults()
        data["threat_intel"] = {"status": "success", "reputation": "malicious"}
        res = calculate_risk_score(**data)
        assert "malicious_ip" in res["features"]
        assert res["risk_score"] == 20

    def test_score_capped_at_100_and_classifications(self):
        data = self._defaults()
        data["auth_result"] = {"spf": {"status": "FAIL"}, "dkim": {"status": "FAIL"}, "dmarc": {"status": "FAIL"}} # 45
        data["forensics"] = {"anomalies": [{"type": "reply_to_mismatch"}, {"type": "from_sender_mismatch"}]} # 18
        data["iocs"] = {"urls": [{"severity": "high", "tags": ["url_shortener"]}], "attachments": [{"severity": "high"}]} # 25
        data["parsed"] = {"body_text": "urgent reset password wire funds need a favor"} # 5+10+8+10 = 33
        data["threat_intel"] = {"status": "success", "reputation": "malicious"} # 20
        # Total would be 141
        res = calculate_risk_score(**data)
        assert res["risk_score"] == 100
        assert res["classification"] == CL_CRITICAL
        
    def test_confidence_scoring(self):
        # Low confidence
        data = self._defaults()
        data["auth_result"] = {"dmarc": {"status": "UNKNOWN"}}
        data["threat_intel"] = {"status": "unavailable"}
        res = calculate_risk_score(**data)
        assert res["confidence"] == "low"
        
        # High confidence
        data["auth_result"] = {"dmarc": {"status": "PASS"}}
        data["threat_intel"] = {"status": "success"}
        res = calculate_risk_score(**data)
        assert res["confidence"] == "high"
