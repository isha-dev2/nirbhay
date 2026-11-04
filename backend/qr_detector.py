#!/usr/bin/env python3
"""
backend/qr_detector.py
QR Code & UPI Payload Detector for Nirbhay (Classifier 2).
Decodes QR images (using OpenCV) and inspects:
  - UPI Payment requests (upi://pay) to catch UPI Reverse-Payment scams.
  - Web links (http/https/shorteners) sent for URL Phishing analysis.
  - Plain text / phone payloads.
"""

import io
import re
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
import cv2
import numpy as np
from PIL import Image

class QRDetector:
    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def decode_image_bytes(self, image_bytes: bytes) -> Optional[str]:
        """Decode a QR code from raw image bytes."""
        try:
            image = Image.open(io.BytesIO(image_bytes))
            # Convert PIL Image to OpenCV BGR format
            img_np = np.array(image.convert("RGB"))
            img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            return self.decode_cv_image(img_cv)
        except Exception as e:
            return None

    def decode_file(self, file_path: str) -> Optional[str]:
        """Decode a QR code from a file path."""
        try:
            img = cv2.imread(file_path)
            if img is None:
                return None
            return self.decode_cv_image(img)
        except Exception:
            return None

    def decode_cv_image(self, img: np.ndarray) -> Optional[str]:
        """Decodes QR code with multiple image enhancement fallbacks."""
        # 1. Direct pass
        val, _, _ = self.detector.detectAndDecode(img)
        if val and val.strip():
            return val.strip()

        # 2. Grayscale pass
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        val, _, _ = self.detector.detectAndDecode(gray)
        if val and val.strip():
            return val.strip()

        # 3. Contrast adjustment (helpful for photo captures)
        enhanced = cv2.equalizeHist(gray)
        val, _, _ = self.detector.detectAndDecode(enhanced)
        if val and val.strip():
            return val.strip()

        # 4. Otsu Thresholding pass
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        val, _, _ = self.detector.detectAndDecode(thresh)
        if val and val.strip():
            return val.strip()

        return None

    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """
        Analyzes the decoded QR payload string:
          - UPI payment URIs (upi://pay?...)
          - Web URLs (http/https/shorteners)
          - Generic text
        """
        p = str(payload).strip()
        
        # 1. UPI Payment URIs
        if p.lower().startswith("upi://pay"):
            return self._analyze_upi(p)
            
        # 2. Web URLs
        url_match = re.match(r'^(?:https?://|www\.)[^\s]+', p, re.IGNORECASE)
        if url_match or any(p.lower().startswith(s) for s in ['bit.ly/', 'tinyurl.com/', 't.co/']):
            return {
                "payload_type": "url",
                "raw_payload": p,
                "url": p,
                "is_upi": False,
                "is_url": True,
                "message": "QR Code contains a web URL."
            }
            
        # 3. Other Plain Text / Phone Number
        return {
            "payload_type": "text",
            "raw_payload": p,
            "is_upi": False,
            "is_url": False,
            "message": "QR Code contains plain text or contact data."
        }

    def _analyze_upi(self, upi_uri: str) -> Dict[str, Any]:
        """
        Inspects UPI payment strings for reverse payment fraud:
        e.g., 'upi://pay?pa=scammer@upi&pn=LuckyDraw&am=5000&cu=INR'
        """
        parsed = urlparse(upi_uri)
        qs = parse_qs(parsed.query)
        
        pa = qs.get("pa", [""])[0]  # Payee Address
        pn = qs.get("pn", [""])[0]  # Payee Name
        am = qs.get("am", [""])[0]  # Amount
        cu = qs.get("cu", ["INR"])[0]
        tn = qs.get("tn", [""])[0]  # Transaction note
        
        amount_num = float(am) if am and am.replace(".", "", 1).isdigit() else 0.0
        
        # High Risk: Asking victim to scan to 'receive' money
        is_scam = True
        risk_level = "scam" if amount_num > 0 else "suspicious"
        
        explanation_en = (
            f"CRITICAL WARNING: This QR code is a UPI PAYMENT REQUEST. "
            f"Scanning this will DEDUCT {cu} {amount_num if amount_num > 0 else '[custom amount]'} "
            f"from YOUR bank account to '{pn or pa}'. "
            f"Golden Rule: You NEVER need to scan a QR code or enter your UPI PIN to receive money!"
        )
        
        explanation_hi = (
            f"गंभीर चेतावनी: यह क्यूआर कोड एक यूपीआई भुगतान अनुरोध (Payment Request) है। "
            f"इसे स्कैन करने पर आपके बैंक खाते से {cu} {amount_num if amount_num > 0 else 'राशि'} "
            f"कटकर '{pn or pa}' को चले जाएंगे। "
            f"नियम: पैसे प्राप्त करने के लिए कभी भी क्यूआर स्कैन या यूपीआई पिन दर्ज न करें।"
        )
        
        explanation_gu = (
            f"ગંભીર ચેતવણી: આ QR કોડ એક UPI પેમેન્ટ વિનંતી છે. "
            f"આ સ્કેન કરવાથી તમારા બેંક ખાતામાંથી {cu} {amount_num if amount_num > 0 else 'રકમ'} "
            f"કપાશે અને '{pn or pa}' ને મળશે. "
            f"નિયમ: પૈસા મેળવવા માટે ક્યારેય QR સ્કેન કે UPI પિન દાખલ કરવાની જરૂર નથી."
        )
        
        return {
            "payload_type": "upi",
            "raw_payload": upi_uri,
            "is_upi": True,
            "is_url": False,
            "payee_vpa": pa,
            "payee_name": pn,
            "amount": amount_num,
            "currency": cu,
            "note": tn,
            "risk_level": risk_level,
            "is_scam": is_scam,
            "explanation": explanation_en,
            "explanation_hi": explanation_hi,
            "explanation_gu": explanation_gu
        }

