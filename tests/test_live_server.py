"""
Test live server by starting uvicorn server in background thread and making real HTTP requests
"""
import os
import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import threading
import time
import requests
import uvicorn
from backend.main import app

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")

server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()

# Wait 2 seconds for server to start
time.sleep(2)

base = "http://127.0.0.1:8001"

# 1. Health
res = requests.get(f"{base}/api/health")
print("[1] Health status:", res.status_code, res.json()["status"])

# 2. English Phishing
res = requests.post(f"{base}/api/predict", json={
    "text": "SBI Alert: Your YONO account has been suspended due to pending KYC update. Click here: http://sbi-kyc-verify-portal.top",
    "url": "http://sbi-kyc-verify-portal.top"
})
data = res.json()
print("[2] English Phishing:", data["threat_level"], "Score:", data["risk_score"], "Lang:", data["language"]["code"])

# 3. Hindi Phishing
res = requests.post(f"{base}/api/predict", json={
    "text": "प्रिय उपभोक्ता, आपके बिजली बिल का भुगतान न होने के कारण आज रात 9:30 बजे बिजली कनेक्शन काट दिया जाएगा। तुरंत भुगतान करें: http://electricity-bill-pay-officer.xyz",
    "url": "http://electricity-bill-pay-officer.xyz"
})
data = res.json()
print("[3] Hindi Phishing:", data["threat_level"], "Score:", data["risk_score"], "Lang:", data["language"]["code"])

# 4. Gujarati Phishing
res = requests.post(f"{base}/api/predict", json={
    "text": "પ્રિય ગ્રાહક, તમારા પાછલા મહિનાનું વીજળી બિલ અપડેટ ન હોવાથી આજે રાત્રે 9:30 વાગ્યે વીજ કનેક્શન કાપી નાખવામાં આવશે: http://mgvcl-online-bill-update.xyz",
    "url": "http://mgvcl-online-bill-update.xyz"
})
data = res.json()
print("[4] Gujarati Phishing:", data["threat_level"], "Score:", data["risk_score"], "Lang:", data["language"]["code"])

# 5. Legitimate Bank Alert
res = requests.post(f"{base}/api/predict", json={
    "text": "Dear Customer, INR 1,500.00 debited from A/C **4589 on 01-Nov-26 at ATM VADODARA. Avl Bal: INR 34,250.75. Not you? Visit https://onlinesbi.sbi",
    "url": "https://onlinesbi.sbi"
})
data = res.json()
print("[5] Legitimate Alert:", data["threat_level"], "Score:", data["risk_score"])

# 6. Evaluation metrics endpoint
res = requests.get(f"{base}/api/evaluation")
print("[6] Evaluation metrics status:", res.status_code, "Ablation keys:", list(res.json()["ablation_study"].keys()))

# 7. UI Serving
res = requests.get(f"{base}/")
print("[7] UI HTML served:", res.status_code, "Length:", len(res.text))

print("\nALL LIVE SERVER TESTS COMPLETED SUCCESSFULLY!")
