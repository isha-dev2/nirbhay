"""
Integration and Unit Tests for Nirbhay Platform
Tests endpoints: /api/health, /api/predict, /api/evaluation, /api/evaluate-live, /
"""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["models_ready"] is True
    print("[PASS] Health check verified.")

def test_predict_hindi_scam():
    payload = {
        "text": "प्रिय एसबीआई ग्राहक, आपका बैंक खाता और योनो ऐप आज रात 9 बजे तक बंद कर दिया जाएगा। तुरंत केवाईसी पूरा करें: http://sbi-kyc-quickupdate.xyz/login",
        "url": "http://sbi-kyc-quickupdate.xyz/login"
    }
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["threat_level"] in ["HIGH_RISK_PHISHING", "SUSPICIOUS"]
    assert data["risk_score"] > 60.0
    assert data["language"]["code"] == "hi"
    assert len(data["explainability"]["actionable_guidance"]) > 0
    print(f"[PASS] Hindi scam prediction verified: {data['threat_level']}, Score: {data['risk_score']}%, Lang: {data['language']['name']}")

def test_predict_gujarati_scam():
    payload = {
        "text": "પ્રિય ગ્રાહક, તમારા પાછલા મહિનાનું વીજળી બિલ અપડેટ ન હોવાથી આજે રાત્રે 9:30 વાગ્યે વીજ કનેક્શન કાપી નાખવામાં આવશે: http://mgvcl-online-bill-update.xyz",
        "url": "http://mgvcl-online-bill-update.xyz"
    }
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["threat_level"] in ["HIGH_RISK_PHISHING", "SUSPICIOUS"]
    assert data["risk_score"] > 60.0
    assert data["language"]["code"] == "gu"
    assert len(data["explainability"]["actionable_guidance"]) > 0
    print(f"[PASS] Gujarati scam prediction verified: {data['threat_level']}, Score: {data['risk_score']}%, Lang: {data['language']['name']}")

def test_predict_legitimate_english():
    payload = {
        "text": "Dear Customer, INR 1,500.00 debited from A/C **4589 on 01-Nov-26 at ATM VADODARA. Avl Bal: INR 34,250.75. Not you? Visit https://onlinesbi.sbi",
        "url": "https://onlinesbi.sbi"
    }
    res = client.post("/api/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["threat_level"] == "SAFE"
    assert data["risk_score"] < 35.0
    print(f"[PASS] Legitimate alert verified: {data['threat_level']}, Score: {data['risk_score']}%")

def test_evaluation_report():
    res = client.get("/api/evaluation")
    assert res.status_code == 200
    data = res.json()
    assert "ablation_study" in data
    assert "language_breakdown" in data
    assert "text_only" in data["ablation_study"]
    assert "url_only" in data["ablation_study"]
    assert "multi_evidence_fusion" in data["ablation_study"]
    print(f"[PASS] Evaluation report verified. Total test records: {data['dataset_summary']['test_records']}")

def test_evaluate_live_batch():
    batch = {
        "samples": [
            {
                "text": "SBI account blocked. Verify: http://sbi-kyc-verify-portal.top",
                "url": "http://sbi-kyc-verify-portal.top",
                "label": 1,
                "language": "en"
            },
            {
                "text": "Your Amazon order is out for delivery. Track at https://amazon.in/orders",
                "url": "https://amazon.in/orders",
                "label": 0,
                "language": "en"
            }
        ]
    }
    res = client.post("/api/evaluate-live", json=batch)
    assert res.status_code == 200
    data = res.json()
    assert data["total_evaluated"] == 2
    assert "fusion_metrics" in data
    assert data["fusion_metrics"]["accuracy"] >= 0.5
    print(f"[PASS] Live batch evaluation verified: {data['total_evaluated']} samples, Acc: {data['fusion_metrics']['accuracy']*100}%")

def test_html_ui():
    res = client.get("/")
    assert res.status_code == 200
    assert "Nirbhay" in res.text
    print("[PASS] Static UI HTML serving verified.")

if __name__ == "__main__":
    test_health()
    test_predict_hindi_scam()
    test_predict_gujarati_scam()
    test_predict_legitimate_english()
    test_evaluation_report()
    test_evaluate_live_batch()
    test_html_ui()
    print("\nALL 6 SYSTEM INTEGRATION TESTS PASSED PERFECTLY!")

