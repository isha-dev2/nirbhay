#!/usr/bin/env python3
"""
backend/url_service.py
Service layer for Classifier 2: URL Phishing & Scam Inspection.
Loads backend/models/url_classifier.joblib and generates multilingual risk verdicts.
"""

import os
import re
import joblib
import pandas as pd
from urllib.parse import urlparse
from typing import Dict, Any, List

MODEL_PATH = "backend/models/url_classifier.joblib"

class URLClassifierService:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.model_bundle = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            self.model_bundle = joblib.load(self.model_path)
            self.model = self.model_bundle["model"]
            self.feature_columns = self.model_bundle["feature_columns"]
            self.trusted_domains = self.model_bundle["trusted_domains"]
            self.suspicious_tlds = self.model_bundle["suspicious_tlds"]
            self.target_brands = self.model_bundle["target_brands"]
            self.shorteners = self.model_bundle["shorteners"]
        else:
            self.model = None

    def extract_features(self, url: str) -> dict:
        url_clean = str(url).strip()
        if not url_clean.startswith(('http://', 'https://')):
            url_clean = 'http://' + url_clean
            
        try:
            parsed = urlparse(url_clean)
            hostname = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            query = (parsed.query or "").lower()
        except Exception:
            hostname, path, query = "", "", ""
            
        url_len = len(url_clean)
        host_len = len(hostname)
        
        num_dots = url_clean.count(".")
        num_hyphens = url_clean.count("-")
        num_digits = sum(1 for c in url_clean if c.isdigit())
        digit_ratio = num_digits / url_len if url_len > 0 else 0.0
        has_at_symbol = 1 if "@" in url_clean else 0
        path_depth = len([p for p in path.split("/") if p])
        
        ipv4_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$')
        has_ip = 1 if ipv4_regex.match(hostname) else 0
        is_https = 1 if url_clean.lower().startswith("https://") else 0
        
        is_shortener = 1 if any(hostname == s or hostname.endswith("." + s) for s in self.shorteners) else 0
        
        host_parts = hostname.split(".")
        tld = host_parts[-1] if len(host_parts) >= 2 else ""
        suspicious_tld = 1 if tld in self.suspicious_tlds else 0
        subdomain_count = max(0, len(host_parts) - 2)
        
        suspicious_keywords = [
            "kyc", "otp", "login", "verify", "verification", "update", "claim", "reward",
            "bonus", "free", "lottery", "prize", "cashback", "apk", "download", "wallet",
            "deactivated", "blocked", "suspend", "bill-payment"
        ]
        path_and_query = path + "?" + query
        suspicious_keyword_count = sum(1 for kw in suspicious_keywords if kw in path_and_query)
        
        is_trusted = any(hostname == d or hostname.endswith("." + d) for d in self.trusted_domains)
        brand_impersonation = 0
        matched_brand = ""
        if not is_trusted:
            for b in self.target_brands:
                if b in hostname:
                    brand_impersonation = 1
                    matched_brand = b
                    break
                    
        has_apk = 1 if path.endswith(".apk") or ".apk" in path_and_query else 0
        
        return {
            "url_length": url_len,
            "host_length": host_len,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_digits": num_digits,
            "digit_ratio": digit_ratio,
            "has_at_symbol": has_at_symbol,
            "path_depth": path_depth,
            "has_ip": has_ip,
            "is_https": is_https,
            "is_shortener": is_shortener,
            "suspicious_tld": suspicious_tld,
            "subdomain_count": subdomain_count,
            "suspicious_keyword_count": suspicious_keyword_count,
            "brand_impersonation": brand_impersonation,
            "matched_brand": matched_brand,
            "has_apk": has_apk,
            "is_trusted_domain": 1 if is_trusted else 0,
            "hostname": hostname,
            "tld": tld
        }

    def inspect_url(self, url: str) -> Dict[str, Any]:
        """Inspects a single URL and returns risk level, probability, and multilingual explanation."""
        if not self.model_bundle:
            self._load_model()
            
        feats = self.extract_features(url)
        
        # 1. Whitelist override for official Indian institutions
        if feats["is_trusted_domain"]:
            return {
                "url": url,
                "domain": feats["hostname"],
                "risk_level": "safe",
                "scam_probability": 0.01,
                "reasons": ["Official verified domain."],
                "explanation_en": f"Verified authentic domain for an Indian institution ({feats['hostname']}).",
                "explanation_hi": f"प्रमाणित आधिकारिक वेबसाइट ({feats['hostname']})।",
                "explanation_gu": f"ચકાસાયેલ અધિકૃત વેબસાઇટ ({feats['hostname']})."
            }
            
        # 2. Extract ML feature vector
        X_vec = pd.DataFrame([{col: feats[col] for col in self.feature_columns}])
        prob_scam = float(self.model.predict_proba(X_vec)[0, 1])
        
        # 3. Generate explicit evidence points
        reasons = []
        if feats["has_ip"]:
            reasons.append("URL uses a raw IP address instead of a domain name (common in evasion).")
        if feats["suspicious_tld"]:
            reasons.append(f"Uses high-risk top-level domain (.{feats['tld']}) frequently abused by scammers.")
        if feats["brand_impersonation"]:
            reasons.append(f"Impersonates official brand '{feats['matched_brand']}' on an untrusted domain.")
        if feats["has_apk"]:
            reasons.append("Forces an unverified direct Android package (.apk) download file.")
        if feats["is_shortener"]:
            reasons.append("Uses a URL shortener to hide the true destination link.")
        if not feats["is_https"]:
            reasons.append("Unencrypted connection (HTTP instead of HTTPS).")
            
        # 4. Final Verdict Determination
        if prob_scam >= 0.65 or feats["has_apk"] or (feats["suspicious_tld"] and feats["brand_impersonation"]):
            risk_level = "scam"
        elif prob_scam >= 0.40 or feats["is_shortener"] or feats["brand_impersonation"]:
            risk_level = "suspicious"
        else:
            risk_level = "safe"
            
        # 5. Multilingual explanations
        if risk_level == "scam":
            exp_en = f"HIGH RISK: This link exhibits strong phishing patterns. {'; '.join(reasons)}"
            exp_hi = f"अत्यधिक संदिग्ध (Scam): यह लिंक फ़िशिंग या धोखाधड़ी जैसा दिखता है। {'; '.join(reasons)}"
            exp_gu = f"અત્યંત જોખમી (Scam): આ લિંક ફિશિંગ અથવા છેતરપિંડી દર્શાવે છે. {'; '.join(reasons)}"
        elif risk_level == "suspicious":
            exp_en = f"CAUTION: Unverified destination. {'; '.join(reasons) if reasons else 'Proceed with care.'}"
            exp_hi = f"सावधान: अपुष्ट वेबसाइट। कोई भी व्यक्तिगत जानकारी या ओटीपी साझा न करें।"
            exp_gu = f"સાવધાન: અપ્રમાણિત વેબસાઇટ. કોઈપણ અંગત વિગતો કે ઓટીપી શેર કરશો નહીં."
        else:
            exp_en = "Low risk detected on this URL."
            exp_hi = "इस लिंक में कोई प्रत्यक्ष खतरा नहीं मिला।"
            exp_gu = "આ લિંક પર કોઈ પ્રત્યક્ષ જોખમ મળ્યું નથી."
            
        return {
            "url": url,
            "domain": feats["hostname"],
            "risk_level": risk_level,
            "scam_probability": round(prob_scam, 4),
            "reasons": reasons,
            "explanation_en": exp_en,
            "explanation_hi": exp_hi,
            "explanation_gu": exp_gu
        }

