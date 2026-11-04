#!/usr/bin/env python3
"""
backend/routes.py
API endpoints for Nirbhay Multi-Modal Safety Engine:
  - /check/url: Inspect standalone web URLs.
  - /check/qr: Decode & inspect QR code images (UPI fraud / malicious links).
  - /check/full: Unified multi-modal endpoint (text + links + QR payloads).
"""

import io
from typing import Optional, Dict, Any
from fastapi import APIRouter, File, UploadFile, Form, HTTPException
from pydantic import BaseModel

from backend.url_service import URLClassifierService
from backend.qr_detector import QRDetector
from backend.text_service import TextClassifierService

router = APIRouter(prefix="/v2", tags=["Safety Verification v2"])

url_service = URLClassifierService()
qr_detector = QRDetector()
text_service = TextClassifierService()

class URLCheckRequest(BaseModel):
    url: str

class TextCheckRequest(BaseModel):
    text: str
    language: Optional[str] = "auto"

@router.get("/status")
def service_status():
    return {
        "status": "online",
        "classifier_1_text": "MuRIL / TF-IDF Indic Engine active",
        "classifier_2_url": "RandomForest URL Inspector active",
        "classifier_2_qr": "OpenCV QR & UPI Detector active"
    }

@router.post("/check/message")
def check_message_endpoint(request: TextCheckRequest):
    """Inspects text messages across English, Hindi, and Gujarati, integrating embedded URL analysis."""
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty.")
    return text_service.inspect_message(request.text)

@router.post("/check/image-text")
async def check_image_text_endpoint(file: UploadFile = File(...)):
    """Extracts text from an uploaded screenshot/image using OCR and runs scam analysis."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    import shutil
    if not shutil.which("tesseract"):
        return {
            "ocr_success": False,
            "risk_level": "unknown",
            "message": "Backend native tesseract binary not installed. The Web UI uses client-side WASM OCR (Tesseract.js) in the browser.",
            "extracted_text": ""
        }

    try:
        from PIL import Image
        import pytesseract
        img = Image.open(io.BytesIO(contents))
        extracted = pytesseract.image_to_string(img)
        if not extracted.strip():
            return {
                "ocr_success": False,
                "risk_level": "unknown",
                "message": "No readable text could be recognized from the image.",
                "extracted_text": ""
            }
        result = text_service.inspect_message(extracted.strip())
        result["ocr_success"] = True
        result["extracted_text"] = extracted.strip()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR processing failed: {str(e)}")

@router.post("/check/url")
def check_url_endpoint(request: URLCheckRequest):
    """Inspects a web URL for phishing, typosquatting, APK downloads, and malicious TLDs."""
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return url_service.inspect_url(request.url)

@router.post("/check/qr")
async def check_qr_endpoint(file: UploadFile = File(...)):
    """Uploads an image containing a QR code, decodes the payload, and assesses risk."""
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        
    payload = qr_detector.decode_image_bytes(contents)
    if not payload:
        return {
            "qr_detected": False,
            "risk_level": "unknown",
            "message": "No QR code could be decoded from this image. Please provide a clear, glare-free picture."
        }
        
    analysis = qr_detector.analyze_payload(payload)
    
    # If the QR code contains a Web URL, run Classifier 2 URL inspection
    if analysis.get("is_url"):
        url_verdict = url_service.inspect_url(analysis["url"])
        analysis["url_analysis"] = url_verdict
        analysis["risk_level"] = url_verdict["risk_level"]
        analysis["explanation"] = url_verdict["explanation_en"]
        analysis["explanation_hi"] = url_verdict["explanation_hi"]
        analysis["explanation_gu"] = url_verdict["explanation_gu"]
        
    analysis["qr_detected"] = True
    return analysis

class ComplaintRequest(BaseModel):
    incident_type: str = "financial"  # financial, phishing, apk, sim
    suspect_identifier: Optional[str] = "Unknown / Phone / Link"
    amount_lost: Optional[float] = 0.0
    bank_and_txnid: Optional[str] = "Not Specified"
    complainant_name: Optional[str] = "[Name]"
    complainant_phone: Optional[str] = "[Mobile]"

@router.get("/cure/guidelines")
def get_cure_guidelines():
    """Returns statutory incident recovery guidelines grounded in Indian legal and regulatory bodies."""
    return {
        "authorities": [
            {
                "name": "Ministry of Home Affairs (MHA) - I4C",
                "helpline": "1930",
                "portal": "https://cybercrime.gov.in",
                "framework": "Citizen Financial Cyber Fraud Reporting & Management System (CFCFRMS)",
                "golden_hour_rule": "Report within 2 hours to freeze fraudster mule account before cash withdrawal."
            },
            {
                "name": "Reserve Bank of India (RBI)",
                "citation": "Circular DBR.No.Leg.BC.78/09.07.005/2017-18",
                "rule": "Zero Customer Liability if notified within 3 working days. Bank must credit shadow reversal within 10 days.",
                "ombudsman_portal": "https://cms.rbi.org.in"
            },
            {
                "name": "Information Technology Act, 2000 & BNS 2023",
                "sections": [
                    "IT Act Sec 66C (Identity Theft & Credential Hacking)",
                    "IT Act Sec 66D (Cheating by personation using computer resource / phishing)",
                    "BNS Sec 318(4) (Cheating and dishonestly inducing delivery of property)"
                ]
            },
            {
                "name": "Department of Telecommunications (DoT)",
                "portals": {
                    "Chakshu": "https://sancharsaathi.gov.in/sfc (Report fraudulent calls/SMS/APKs)",
                    "TAFCOP": "https://tafcop.sancharsaathi.gov.in (Check unauthorized SIMs issued on Aadhaar)",
                    "CEIR": "https://ceir.sancharsaathi.gov.in (Block device IMEI across Indian networks)"
                }
            }
        ],
        "bank_fraud_helplines": {
            "State Bank of India": {"phone": "1800 1234 / 1800 2100", "sms_block": "SMS BLOCK to 567676"},
            "HDFC Bank": {"phone": "1800 1600 / 1800 266 4060", "sms_block": "SMS BLOCK to 5676712"},
            "ICICI Bank": {"phone": "1800 1080 / 1800 120 7777", "sms_block": "SMS BLOCK <Card> to 9215676766"},
            "Bank of Baroda": {"phone": "1800 5700 / 1800 5000", "sms_block": "SMS BLOCK to 8422009988"},
            "Punjab National Bank": {"phone": "1800 180 2222", "sms_block": "SMS HOTLIST to 5607040"},
            "Axis Bank": {"phone": "1800 419 5959", "sms_block": "SMS BLOCK to 5676782"}
        }
    }

@router.post("/cure/generate-complaint")
def generate_complaint_endpoint(req: ComplaintRequest):
    """Generates a formal legal cybercrime police complaint draft citing IT Act and BNS."""
    from datetime import datetime
    now_str = datetime.now().strftime("%d-%b-%Y %I:%M %p")

    scenario_titles = {
        "financial": "Financial Cyber Fraud & Unauthorized Debit",
        "phishing": "Cyber Phishing & Credential Theft",
        "apk": "Malicious Software / Android Trojan Injection",
        "sim": "SIM Swap Identity Theft & Account Hijacking"
    }
    title = scenario_titles.get(req.incident_type, "Cyber Financial Fraud")

    complaint_body = f"""To:
The Station House Officer / Cyber Crime Police Station,
National Cybercrime Reporting Portal (cybercrime.gov.in)
Citizen Financial Cyber Fraud Reporting and Management System (CFCFRMS - 1930)

Subject: Formal Complaint under Section 66C & 66D of Information Technology Act, 2000 and Section 318(4) of Bharatiya Nyaya Sanhita (BNS, 2023) regarding {title}.

Respected Sir/Madam,

I am lodging this formal complaint regarding a cyber fraud incident perpetrated against me:

1. INCIDENT DETAILS:
   - Nature of Offense: {title}
   - Date and Time: {now_str}
   - Disputed Financial Amount: Rs. {req.amount_lost:,.2f}
   - Bank Account / Transaction UTR / Ref: {req.bank_and_txnid}
   - Perpetrator Identifier (Phone/UPI/Link): {req.suspect_identifier}

2. BRIEF SUMMARY OF FACTS:
   The cyber perpetrator contacted/lured me through electronic communication, falsely impersonating legitimate authorities/banking services. By deceptive means and intimidation/urgency, they attempted/executed unauthorized financial extraction and credential compromise.

3. RELEVANT STATUTORY PROVISIONS & LEGAL CITATIONS:
   - Section 66C, Information Technology Act, 2000: Punishment for identity theft.
   - Section 66D, Information Technology Act, 2000: Punishment for cheating by personation by using computer resource.
   - Section 318(4), Bharatiya Nyaya Sanhita, 2023: Cheating and dishonestly inducing delivery of property.
   - Reserve Bank of India Circular DBR.No.Leg.BC.78/09.07.005/2017-18: Customer Protection - Limiting Liability in Unauthorised Electronic Banking Transactions.

4. PRAYER / RELIEF SOUGHT:
   I kindly request the Cyber Crime Investigation Cell and Bank Nodal Officers to:
   a) Immediately register this complaint and issue an acknowledgment / FIR number.
   b) Trigger lien / freeze request on the beneficiary's mule account under the CFCFRMS framework.
   c) Direct the concerned intermediary/telecom provider to preserve CDR and IP logs.

Complainant Details:
Name: {req.complainant_name}
Mobile Number: {req.complainant_phone}
"""
    return {
        "status": "success",
        "complaint_draft": complaint_body,
        "filing_url": "https://cybercrime.gov.in",
        "emergency_helpline": "1930"
    }

