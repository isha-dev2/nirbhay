#!/usr/bin/env python3
"""
backend/text_service.py
Service layer for Classifier 1: Multilingual Scam Message Detector (En, Hi, Gu).
Combines Text NLP analysis with embedded URL payload extraction.
"""

import os
import re
import unicodedata
import joblib
from typing import Dict, Any, List
from backend.url_service import URLClassifierService

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEXT_MODEL_PATH = os.path.join(BASE_DIR, "models", "text_classifier.joblib")
MURIL_MODEL_DIR = os.path.join(BASE_DIR, "..", "muril_scam_model")

URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>\"\'\)]+|'
    r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|bit\.do|shorturl\.at|tiny\.cc|rb\.gy|cutt\.ly)/[^\s<>\"\'\)]+',
    re.IGNORECASE
)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PHONE_REGEX = re.compile(
    r'(?:(?:\+|00)?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|'
    r'1800[\s-]?\d{3}[\s-]?\d{3,4}\b|'
    r'\b0\d{2,4}[\s-]?\d{6,8}\b|'
    r'\b(?:\+?\d{1,3}[\s-]?)?\(?\d{3,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
)
DIGIT_RUNS_REGEX = re.compile(r'\b\d{4,}\b')
ZERO_WIDTH_REGEX = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff]')

URGENCY_WORDS = [
    r'\burgent\b', r'\bimmediately\b', r'\bimmediate\b', r'\bexpires?\b', r'\bexpiring\b',
    r'\bblocked?\b', r'\bsuspended?\b', r'\bhurry\b', r'\blast chance\b', r'\bwarning\b',
    'तुरंत', 'तत्काल', 'जल्द', 'अंतिम तिथि', 'समाप्त', 'बंद', 'सावधान', 'चेतावनी', 'ब्लॉक',
    'તાત્કાલિક', 'તરત', 'જલ્દી', 'છેલ્લી તારીખ', 'સમાપ્ત', 'બંધ', 'સાવધાન', 'ચેતવણી', 'બ્લોક'
]

AUTHORITY_WORDS = [
    r'\brbi\b', r'\bsbi\b', r'\bkyc\b', r'\bpolice\b', r'\btrai\b', r'\bbank\b',
    r'\bincome tax\b', r'\bcbi\b', r'\bcyber\b', r'\bcustoms\b', r'\baadhaar\b',
    r'\bpgvcl\b', r'\bugvcl\b', r'\bmgvcl\b', r'\bdgvcl\b', r'\btatapower\b',
    'आरबीआई', 'एसबीआई', 'केवाईसी', 'पुलिस', 'बैंक', 'बिजली',
    'આરબીઆઈ', 'એસબીઆઈ', 'કેવાયસી', 'પોલીસ', 'બેંક', 'વીજળી'
]

CREDENTIAL_WORDS = [
    r'\botp\b', r'\bpin\b', r'\bcvv\b', r'\bpasswords?\b', r'\bpasscode\b',
    'पासवर्ड', 'पिन', 'ओटीपी', 'પાસવર્ડ', 'પીન', 'ઓટીપી'
]

class TextClassifierService:
    def __init__(self):
        self.pipeline = None
        self.url_service = URLClassifierService()
        self._load_model()

    def _load_model(self):
        if os.path.exists(TEXT_MODEL_PATH):
            self.pipeline = joblib.load(TEXT_MODEL_PATH)

    def clean_text(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        t = unicodedata.normalize('NFC', text)
        t = ZERO_WIDTH_REGEX.sub('', t)
        t = URL_REGEX.sub('<LINK>', t)
        t = EMAIL_REGEX.sub('<EMAIL>', t)
        def phone_repl(m):
            raw = m.group(0)
            digits = re.sub(r'\D', '', raw)
            return '<PHONE>' if len(digits) >= 10 else raw
        t = PHONE_REGEX.sub(phone_repl, t)
        t = DIGIT_RUNS_REGEX.sub('<NUM>', t)
        t = re.sub(r'\s+', ' ', t).strip()
        return t

    def detect_language(self, text: str) -> str:
        dev_count = sum(1 for c in text if 'DEVANAGARI' in unicodedata.name(c, ''))
        gu_count = sum(1 for c in text if 'GUJARATI' in unicodedata.name(c, ''))
        latin_count = sum(1 for c in text if 'LATIN' in unicodedata.name(c, ''))
        
        if gu_count > latin_count and gu_count >= dev_count:
            return "gu"
        elif dev_count > latin_count and dev_count >= gu_count:
            return "hi"
        return "en"

    def find_matched_keywords(self, text: str, patterns: list) -> list:
        t_low = text.lower()
        found = []
        for p in patterns:
            if p.startswith(r'\b'):
                m = re.findall(p, t_low, re.IGNORECASE)
                if m:
                    found.extend(list(set(m)))
            else:
                if p.lower() in t_low:
                    found.append(p)
        return sorted(list(set(found)))

    def inspect_message(self, raw_text: str) -> Dict[str, Any]:
        if not self.pipeline:
            self._load_model()

        text_clean = self.clean_text(raw_text)
        detected_lang = self.detect_language(raw_text)
        
        # 1. NLP Text Classification
        if self.pipeline:
            prob_scam = float(self.pipeline.predict_proba([text_clean])[0, 1])
        else:
            prob_scam = 0.5

        # 2. Extract keywords
        urgency_matches = self.find_matched_keywords(raw_text, URGENCY_WORDS)
        authority_matches = self.find_matched_keywords(raw_text, AUTHORITY_WORDS)
        credential_matches = self.find_matched_keywords(raw_text, CREDENTIAL_WORDS)

        # 3. Embedded URL Analysis (Classifier 2 integration)
        embedded_urls = URL_REGEX.findall(raw_text)
        url_analyses = []
        highest_url_prob = 0.0

        for u in embedded_urls:
            u_res = self.url_service.inspect_url(u)
            url_analyses.append(u_res)
            highest_url_prob = max(highest_url_prob, u_res.get("scam_probability", 0.0))

        # 4. Multi-Modal Decision Fusion
        combined_prob = max(prob_scam, highest_url_prob)
        if credential_matches and (urgency_matches or authority_matches):
            combined_prob = max(combined_prob, 0.85)

        if combined_prob >= 0.65:
            risk_level = "scam"
        elif combined_prob >= 0.40 or len(urgency_matches) >= 2 or highest_url_prob >= 0.40:
            risk_level = "suspicious"
        else:
            risk_level = "safe"

        # 5. Multilingual explanations
        red_flags = []
        if urgency_matches:
            red_flags.append(f"Urgency wording: {', '.join(urgency_matches[:3])}")
        if authority_matches:
            red_flags.append(f"Impersonation signals: {', '.join(authority_matches[:3])}")
        if credential_matches:
            red_flags.append(f"Credential harvesting: {', '.join(credential_matches[:2])}")
        if highest_url_prob >= 0.60:
            red_flags.append("Contains high-risk link/download payload")

        flags_str = "; ".join(red_flags) if red_flags else "No aggressive red flags detected."

        if risk_level == "scam":
            exp_en = f"HIGH RISK (Scam): This message exhibits classic social engineering tactics. {flags_str}"
            exp_hi = f"अत्यधिक संदिग्ध (Scam): यह संदेश धोखाधड़ी या जालसाजी का प्रयास प्रतीत होता है। {flags_str}"
            exp_gu = f"અત્યંત જોખમી (Scam): આ સંદેશ છેતરપિંડી દર્શાવે છે. {flags_str}"
        elif risk_level == "suspicious":
            exp_en = f"SUSPICIOUS: Exercise caution. {flags_str}"
            exp_hi = f"सावधान: यह संदेश संदिग्ध हो सकता है। कोई भी ओटीपी या व्यक्तिगत जानकारी साझा न करें।"
            exp_gu = f"સાવધાન: આ સંદેશ શંકાસ્પદ હોઈ શકે છે. કોઈ પણ ઓટીપી કે અંગત વિગતો આપશો નહીં."
        else:
            exp_en = "SAFE: Normal routine communication patterns detected."
            exp_hi = "सुरक्षित: कोई प्रत्यक्ष खतरा या धोखाधड़ी का संकेत नहीं मिला।"
            exp_gu = "સુરક્ષિત: કોઈ પ્રત્યક્ષ જોખમ કે છેતરપિંડી જોવા મળી નથી."

        return {
            "text": raw_text,
            "language": detected_lang,
            "risk_level": risk_level,
            "scam_probability": round(combined_prob, 4),
            "text_scam_probability": round(prob_scam, 4),
            "red_flags": red_flags,
            "urgency_keywords": urgency_matches,
            "authority_keywords": authority_matches,
            "credential_keywords": credential_matches,
            "embedded_urls": url_analyses,
            "explanation_en": exp_en,
            "explanation_hi": exp_hi,
            "explanation_gu": exp_gu
        }

