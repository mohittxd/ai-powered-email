import requests
import json
import os
import sys

BASE_URL = "http://localhost:8000"
EML_PATH = "test_e2e_phishing.eml"

def run_tests():
    print("🚀 Starting End-to-End API Audit...")

    # 1. Test Ingestion and Analysis
    print("\n1. Uploading and analyzing EML...")
    with open(EML_PATH, 'rb') as f:
        files = {'file': ('test_e2e_phishing.eml', f, 'message/rfc822')}
        resp = requests.post(f"{BASE_URL}/api/v1/analyze-email", files=files)
    
    if resp.status_code != 200:
        print(f"❌ Analysis failed: {resp.status_code} - {resp.text}")
        sys.exit(1)
        
    data = resp.json()
    email_id = data.get("email_id")
    print(f"✅ Email ingested successfully. ID: {email_id}")
    
    # Verify core fields
    assert data["email"]["subject"] == "URGENT: Your PayPal Account Has Been Suspended!", "Subject parsing failed"
    assert data["authentication"]["spf"]["mta_reported"] == "FAIL", "SPF parsing failed"
    assert data["authentication"]["dkim"]["mta_reported"] == "FAIL", "DKIM parsing failed"
    assert data["authentication"]["dmarc"]["mta_reported"] == "FAIL", "DMARC parsing failed"
    print("✅ Header Auth correctly parsed (SPF, DKIM, DMARC FAIL).")

    # Verify Risk Engine & Phase 14 AI Score
    risk = data.get("risk_analysis", {})
    assert "ml_score" in risk, "Phase 14 ML Score missing"
    assert "rule_based_score" in risk, "Rule-based score missing"
    assert "final_risk_score" in risk, "Final risk score missing"
    assert "calibration_note" in risk, "Calibration note missing"
    
    # Assert auth safeguard (DMARC fail -> should have high floor)
    assert risk["final_risk_score"] >= 60, f"Auth threat floor failed! Score is {risk['final_risk_score']}"
    print(f"✅ Risk engine validated. Final Score: {risk['final_risk_score']} (Rule: {risk['rule_based_score']}, ML: {risk['ml_score']})")

    # Verify IOC extraction
    urls = [ioc["value"] for ioc in data.get("iocs", {}).get("urls", [])]
    assert "http://bit.ly/3xyz789" in urls, "URL IOC extraction failed"
    print("✅ IOC Extraction validated (URL found).")

    # 2. Test JSON Report Export
    print("\n2. Fetching JSON Report...")
    resp = requests.get(f"{BASE_URL}/api/v1/emails/{email_id}/report.json")
    if resp.status_code != 200:
        print(f"❌ Report fetch failed: {resp.status_code}")
        sys.exit(1)
        
    report = resp.json()
    assert report["analysis"]["final_risk_score"] == risk["final_risk_score"], "Report score mismatch"
    assert "calibration_note" in report["analysis"], "Report missing calibration note"
    print("✅ JSON Report exported successfully.")

    # 3. Test Audit Log
    print("\n3. Verifying Audit Logs...")
    resp = requests.get(f"{BASE_URL}/api/v1/audit")
    if resp.status_code == 200:
        logs = resp.json()
        assert len(logs) > 0, "No audit logs found"
        found = any(log["action"] == "ingest_email" and log["resource_id"] == email_id for log in logs)
        assert found, "Ingest action not found in audit logs"
        print("✅ Audit logs recorded successfully.")
    else:
        print(f"❌ Audit log fetch failed: {resp.status_code}")

    print("\n🎉 All End-to-End API tests passed!")

if __name__ == "__main__":
    run_tests()
