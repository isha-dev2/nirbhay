"""
Nirbhay — AI-Powered Digital Safety & Response Platform
FastAPI Application Server
Integrates Multilingual Text Classification, Structural URL Analysis, Evidence Fusion,
Explainable AI in English/Hindi/Gujarati, and Live Data Evaluation Dashboard.

Presented by: Isha Rajput, Parisha Parmar, Priya Bhatt
Guide: Prof. Ujwala Patigara | Navrachana University, Vadodara
"""
import os
import sys
from typing import List, Optional

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Starlette 1.x compatibility shim for FastAPI
import starlette.routing
_orig_router_init = starlette.routing.Router.__init__
def _compat_router_init(self, *args, **kwargs):
    kwargs.pop("on_startup", None)
    kwargs.pop("on_shutdown", None)
    return _orig_router_init(self, *args, **kwargs)
starlette.routing.Router.__init__ = _compat_router_init

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.ml_engine.predictor import nirbhay_engine

app = FastAPI(
    title="Nirbhay — AI Digital Safety & Multilingual Scam Detection Platform",
    description="End-semester Major Project DS-ML Demonstration API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# PYDANTIC DATA CONTRACTS
# -------------------------------------------------------------
class PredictRequest(BaseModel):
    text: Optional[str] = Field(default="", description="Suspicious SMS or message text in EN, HI, or GU")
    url: Optional[str] = Field(default="", description="Target URL if present")
    lang_override: Optional[str] = Field(default=None, description="Optional forced language ('en', 'hi', 'gu')")

class LiveSampleItem(BaseModel):
    text: str = Field(default="")
    url: Optional[str] = Field(default="")
    label: int = Field(default=1, description="1 for Phishing/Scam, 0 for Legitimate")
    language: Optional[str] = Field(default=None)

class EvaluateLiveBatchRequest(BaseModel):
    samples: List[LiveSampleItem]

# -------------------------------------------------------------
# API ROUTES
# -------------------------------------------------------------
@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "platform": "Nirbhay Digital Safety Platform",
        "models_ready": bool(nirbhay_engine.text_model and nirbhay_engine.url_model and nirbhay_engine.fusion_model),
        "institution": "Navrachana University, Vadodara, Gujarat",
        "guide": "Prof. Ujwala Patigara",
        "presenters": ["Isha Rajput", "Parisha Parmar", "Priya Bhatt"]
    }

@app.post("/api/predict")
def predict_threat(payload: PredictRequest):
    """
    Live Running of Model:
    Analyzes message text and URL across English, Hindi, and Gujarati.
    Returns Fused Risk Score, Modality Breakdown, and Plain-Language Explanation.
    """
    if not payload.text and not payload.url:
        raise HTTPException(status_code=400, detail="Please provide either message text, a URL, or both.")

    try:
        result = nirbhay_engine.predict(
            text=payload.text,
            url=payload.url,
            lang_override=payload.lang_override
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

@app.get("/api/evaluation")
def get_evaluation_metrics():
    """
    Returns the comprehensive DS-ML evaluation report:
    - Ablation Study: Text-Only vs URL-Only vs Multi-Evidence Fusion
    - Per-Language Metrics & False Positive Rate (FPR) for EN, HI, and GU
    - Feature Importances
    """
    if nirbhay_engine.eval_report:
        return nirbhay_engine.eval_report
    raise HTTPException(status_code=404, detail="Evaluation report not available yet. Run retraining first.")

@app.post("/api/evaluate-live")
def evaluate_live_batch(payload: EvaluateLiveBatchRequest):
    """
    Evaluating Model with Live Data:
    Runs immediate evaluation on custom test samples provided live by professor or presenters.
    Computes Precision, Recall, F1-Score, False Positive Rate (FPR), and sample breakdown.
    """
    if not payload.samples:
        raise HTTPException(status_code=400, detail="Sample list cannot be empty.")

    sample_dicts = [s.model_dump() for s in payload.samples]
    res = nirbhay_engine.evaluate_live_batch(sample_dicts)
    return res

@app.post("/api/retrain")
def retrain_models():
    """
    Triggers the end-to-end training pipeline and updates evaluation metrics
    """
    try:
        report = nirbhay_engine.retrain()
        return {
            "message": "Models retrained successfully!",
            "report": report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retraining error: {str(e)}")

@app.get("/api/sample-cases")
def get_sample_cases():
    """
    Preloaded authentic real-world scenarios for instant 1-click live demonstration
    """
    return [
        {
            "id": "case-1",
            "title": "SBI YONO KYC Suspension (Hindi Scam)",
            "language": "hi",
            "lang_name": "हिन्दी (Hindi)",
            "type": "phishing",
            "expected_label": 1,
            "text": "प्रिय एसबीआई ग्राहक, आपका बैंक खाता और योनो ऐप आज रात 9 बजे तक बंद कर दिया जाएगा क्योंकि आपका पैन कार्ड और केवाईसी अपडेट नहीं है। तुरंत लिंक पर क्लिक करके केवाईसी पूरा करें: http://sbi-kyc-quickupdate.xyz/login",
            "url": "http://sbi-kyc-quickupdate.xyz/login",
            "description": "Devanagari text with high urgency threat + suspicious .xyz brand spoofing URL"
        },
        {
            "id": "case-2",
            "title": "MGVCL Electricity Power Cut (Gujarati Scam)",
            "language": "gu",
            "lang_name": "ગુજરાતી (Gujarati)",
            "type": "phishing",
            "expected_label": 1,
            "text": "પ્રિય ગ્રાહક, તમારા પાછલા મહિનાનું વીજળી બિલ અપડેટ ન હોવાથી આજે રાત્રે 9:30 વાગ્યે તમારું વીજ કનેક્શન કાપી નાખવામાં આવશે. તાત્કાલિક અમારા અધિકારીનો સંપર્ક કરો અથવા લિંક દ્વારા બિલ ભરો: http://mgvcl-online-bill-update.xyz",
            "url": "http://mgvcl-online-bill-update.xyz",
            "description": "Gujarati regional utility threat targeting Gujarat electricity consumers with deceptive link"
        },
        {
            "id": "case-3",
            "title": "India Post Parcel Delivery Fee (English Scam)",
            "language": "en",
            "lang_name": "English",
            "type": "phishing",
            "expected_label": 1,
            "text": "India Post: Your package cannot be delivered due to an incorrect delivery address. Please update your address and pay Rs. 25 redelivery fee within 12 hours: http://indiapost-parcel-address-update.xyz/tracking",
            "url": "http://indiapost-parcel-address-update.xyz/tracking",
            "description": "Courier parcel bait asking for Rs 25 redelivery fee to harvest credit/debit card details"
        },
        {
            "id": "case-4",
            "title": "KBC 25 Lakh Lottery (English/Hindi Hybrid Scam)",
            "language": "en",
            "lang_name": "English",
            "type": "phishing",
            "expected_label": 1,
            "text": "Congratulations! You won Rs. 25,00,000 in KBC All India Lucky Draw 2026. Claim your lottery prize immediately: http://kbc-lucky-winner-claim.top",
            "url": "http://kbc-lucky-winner-claim.top",
            "description": "Unrealistic lottery reward with suspicious .top TLD"
        },
        {
            "id": "case-5",
            "title": "Electricity Disconnection via Call (No URL Phishing)",
            "language": "gu",
            "lang_name": "ગુજરાતી (Gujarati)",
            "type": "phishing",
            "expected_label": 1,
            "text": "તાત્કાલિક નોટિસ: તમારા મીટરનું વીજ કનેક્શન આજે કાપવામાં આવશે. બિલ ક્લિયર કરવા માટે આ નંબર 9723019284 પર સંપર્ક કરો.",
            "url": "",
            "description": "Scam with NO URL! Demonstrates that Text NLP model detects what URL model cannot."
        },
        {
            "id": "case-6",
            "title": "Stealth Phishing (Polite Text, Malicious IP Host)",
            "language": "en",
            "lang_name": "English",
            "type": "phishing",
            "expected_label": 1,
            "text": "Good morning, your requested bank account statement is ready for download.",
            "url": "http://192.168.4.15:8080/kyc-update",
            "description": "Neutral polite text, but malicious IP-based URL. Demonstrates URL model catching stealth phishing!"
        },
        {
            "id": "case-7",
            "title": "Legitimate SBI Transaction Alert (English)",
            "language": "en",
            "lang_name": "English",
            "type": "legitimate",
            "expected_label": 0,
            "text": "Dear Customer, INR 1,500.00 debited from A/C **4589 on 01-Nov-26 at ATM VADODARA. Avl Bal: INR 34,250.75. Not you? Visit https://onlinesbi.sbi",
            "url": "https://onlinesbi.sbi",
            "description": "Authentic bank transactional SMS with certified official domain onlinesbi.sbi"
        },
        {
            "id": "case-8",
            "title": "Legitimate Bank OTP Notice (Hindi)",
            "language": "hi",
            "lang_name": "हिन्दी (Hindi)",
            "type": "legitimate",
            "expected_label": 0,
            "text": "एसबीआई नेटबैंकिंग लॉगिन के लिए आपका ओटीपी 749201 है। यह 5 मिनट के लिए मान्य है। किसी के साथ शेयर न करें। आधिकारिक पोर्टल: https://onlinesbi.sbi",
            "url": "https://onlinesbi.sbi",
            "description": "Authentic Hindi OTP message emphasizing security and privacy"
        },
        {
            "id": "case-9",
            "title": "Legitimate MGVCL Bill Reminder (Gujarati)",
            "language": "gu",
            "lang_name": "ગુજરાતી (Gujarati)",
            "type": "legitimate",
            "expected_label": 0,
            "text": "પ્રિય ગ્રાહક, તમારા વીજળી જોડાણનું બિલ રૂ. 1,150 છે. છેલ્લી તારીખ 12-નવેમ્બર છે. ઓનલાઇન બિલ ભરવા માટે મુલાકાત લો: https://www.mgvcl.com",
            "url": "https://www.mgvcl.com",
            "description": "Legitimate Gujarati utility reminder linking to official mgvcl.com portal"
        }
    ]

@app.get("/api/system-info")
def get_system_info():
    return {
        "project": "Nirbhay — AI-Powered Digital Safety & Response Platform",
        "department": "Department of Data Science & Machine Learning",
        "institution": "Navrachana University, Vadodara, Gujarat",
        "academic_session": "Major Project 2026-27",
        "guide": "Prof. Ujwala Patigara",
        "team_members": [
            {"name": "Isha Rajput", "role": "ML & Dataset Pipeline"},
            {"name": "Parisha Parmar", "role": "Multilingual NLP & Explainability"},
            {"name": "Priya Bhatt", "role": "URL Analysis & System Integration"}
        ],
        "research_contributions": [
            "Multilingual Text Classification using Word & Character N-Grams for English, Hindi (Devanagari), and Gujarati",
            "Structural URL Analysis with 25+ Lexical, Host, Domain, and Shannon Entropy Features (inspired by QsecR IEEE Access 2023)",
            "Multi-Evidence Late Fusion combining semantic text signals and URL architecture",
            "Empirical evaluation reporting Accuracy, Precision, Recall, F1, and False Positive Rate (FPR) across EN, HI, and GU",
            "Actionable plain-language explanations in regional Indic languages for non-technical users"
        ]
    }

# -------------------------------------------------------------
# STATIC FILES & WEB DASHBOARD UI
# -------------------------------------------------------------
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_ui():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Nirbhay API is running. UI index.html not found in static folder."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
