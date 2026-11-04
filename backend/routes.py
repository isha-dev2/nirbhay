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

