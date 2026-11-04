"""
Unified Predictor and Inference Engine for Nirbhay Platform
Coordinates:
- Multilingual Text Model (English, Hindi, Gujarati)
- Structural URL Lexical Model
- Multi-Evidence Fusion Model
- Plain-Language Explainability Generation (EN, HI, GU)
- Live Data Evaluation Sandbox
"""
import json
import os
import sys

# Ensure root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np
import pandas as pd

from ml.feature_extractor import (
    FEATURE_COLUMNS,
    detect_language,
    extract_text_indicators,
    extract_url_indicators,
    extract_url_features,
    extract_url_from_text,
    calculate_shannon_entropy
)
from ml.train import calculate_metrics, train_and_evaluate

MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

class NirbhayEngine:
    def __init__(self):
        self.text_model = None
        self.url_model = None
        self.fusion_model = None
        self.eval_report = {}
        self.load_models()

    def load_models(self):
        text_path = os.path.join(MODELS_DIR, "text_model.joblib")
        url_path = os.path.join(MODELS_DIR, "url_model.joblib")
        fusion_path = os.path.join(MODELS_DIR, "fusion_model.joblib")
        report_path = os.path.join(MODELS_DIR, "evaluation_report.json")

        if os.path.exists(text_path) and os.path.exists(url_path) and os.path.exists(fusion_path):
            self.text_model = joblib.load(text_path)
            self.url_model = joblib.load(url_path)
            self.fusion_model = joblib.load(fusion_path)
            print("Sanket (TRINETRA) models loaded successfully from disk.")
        else:
            print("Models not found on disk. Training initial models...")
            self.eval_report = train_and_evaluate()
            self.text_model = joblib.load(text_path)
            self.url_model = joblib.load(url_path)
            self.fusion_model = joblib.load(fusion_path)

        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                self.eval_report = json.load(f)

    def predict(self, text: str, url: str = None, lang_override: str = None) -> dict:
        """
        Full inference pipeline combining Text NLP, Structural URL analysis, and Evidence Fusion
        """
        text = text.strip() if text else ""
        
        # If url is not passed, attempt extracting it from text
        extracted_url = extract_url_from_text(text) if not url else url.strip()
        final_url = extracted_url if extracted_url else ""

        # Language identification
        detected_lang = detect_language(text) if not lang_override else lang_override
        if detected_lang not in ["en", "hi", "gu"]:
            detected_lang = "en"

        # 1. Text Model Inference
        if text:
            try:
                p_text = float(self.text_model.predict_proba([text])[0, 1])
            except Exception as e:
                p_text = 0.5
        else:
            p_text = 0.5

        # 2. URL Model Inference
        has_url = 1 if final_url else 0
        if has_url:
            url_features_dict = extract_url_features(final_url)
            feat_vector = pd.DataFrame([url_features_dict])[FEATURE_COLUMNS].values
            try:
                p_url = float(self.url_model.predict_proba(feat_vector)[0, 1])
            except Exception as e:
                p_url = 0.5
        else:
            url_features_dict = extract_url_features("")
            p_url = 0.0

        # 3. Evidence Fusion Inference
        if not text and final_url:
            p_fusion = p_url
        elif text and not final_url:
            if self.fusion_model:
                try:
                    fusion_feats = np.array([[p_text, 0.0, 0, 0.0]])
                    p_fusion = float(self.fusion_model.predict_proba(fusion_feats)[0, 1])
                except Exception:
                    p_fusion = p_text
            else:
                p_fusion = p_text
        elif self.fusion_model and text and final_url:
            fusion_feats = np.array([[p_text, p_url, 1, p_text * p_url]])
            try:
                p_fusion = float(self.fusion_model.predict_proba(fusion_feats)[0, 1])
            except Exception:
                p_fusion = (p_text * 0.6 + p_url * 0.4)
        else:
            p_fusion = p_text if text else p_url

        # 4. Domain Whitelist & Structural Heuristics Safety Net
        if final_url:
            from urllib.parse import urlparse
            try:
                domain = urlparse(final_url if final_url.startswith("http") else "http://" + final_url).netloc.lower()
            except Exception:
                domain = final_url.lower()

            legit_suffixes = [".gov.in", ".nic.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "bankofbaroda.in", "mgvcl.com", "uppcl.org", "nuv.ac.in"]
            if any(domain.endswith(sfx) for sfx in legit_suffixes) and not url_features_dict["is_ip"]:
                # High trust authentic domain
                p_fusion = min(p_fusion, 0.15)
                p_url = min(p_url, 0.15)
            elif url_features_dict["is_ip"] or (url_features_dict["has_brand_spoof"] and url_features_dict["has_suspicious_tld"]):
                # Confirmed malicious lexical structure
                p_fusion = max(p_fusion, 0.88)
                p_url = max(p_url, 0.90)

        # Calculate final risk score percentage
        risk_score = round(p_fusion * 100, 1)

        # Categorize threat level
        if risk_score >= 65.0:
            threat_level = "HIGH_RISK_PHISHING"
            badge_color = "red"
        elif risk_score >= 35.0:
            threat_level = "SUSPICIOUS"
            badge_color = "amber"
        else:
            threat_level = "SAFE"
            badge_color = "emerald"

        # 5. Explainability & Guidance Generation
        text_flags = extract_text_indicators(text, detected_lang)
        url_flags = extract_url_indicators(final_url, detected_lang) if final_url else []

        explanation_package = self._generate_plain_explanation(
            threat_level=threat_level,
            risk_score=risk_score,
            lang=detected_lang,
            text_flags=text_flags,
            url_flags=url_flags,
            final_url=final_url
        )

        # WhatsApp share text for family protection
        share_texts = {
            "en": f"⚠️ CYBER FRAUD ALERT: I verified this on Nirbhay AI Threat Platform. It is flagged as {threat_level.replace('_', ' ')} ({risk_score}% Risk). Please DO NOT click any links, DO NOT share your OTP or bank details! National Cybercrime Helpline: 1930.",
            "hi": f"⚠️ साइबर फ्रॉड चेतावनी: मैंने निर्भय (Nirbhay) सुरक्षा प्लेटफॉर्म पर इसकी जांच की है। यह अत्यधिक संदिग्ध/फिशिंग फ्रॉड ({risk_score}% जोखिम) पाया गया है। कृपया किसी भी लिंक पर क्लिक न करें, ओटीपी न दें और पैसे न भेजें! राष्ट्रीय साइबर हेल्पलाइन: 1930.",
            "gu": f"⚠️ સાયબર છેતરપિંડી સાવચેતી: મેં નિર્ભય (Nirbhay) સુરક્ષા પ્લેટફોર્મ પર આ તપાસ્યું છે. આ બનાવટી ફિશિંગ ફ્રોડ ({risk_score}% જોખમ) જણાયું છે. કોઈ લિંક પર ક્લિક ન કરશો કે OTP કોઈને આપશો નહીં! રાષ્ટ્રીય સાયબર હેલ્પલાઇન: 1930."
        }

        return {
            "threat_level": threat_level,
            "risk_score": risk_score,
            "badge_color": badge_color,
            "language": {
                "code": detected_lang,
                "name": {"en": "English", "hi": "हिन्दी (Hindi)", "gu": "ગુજરાતી (Gujarati)"}.get(detected_lang, "English")
            },
            "input_analysis": {
                "has_text": bool(text),
                "has_url": bool(final_url),
                "extracted_url": final_url,
                "text_char_count": len(text)
            },
            "modality_scores": {
                "text_only_risk": round(p_text * 100, 1) if text else None,
                "url_only_risk": round(p_url * 100, 1) if has_url else None,
                "fused_risk": risk_score
            },
            "explainability": {
                "summary": explanation_package["summary"],
                "actionable_guidance": explanation_package["guidance"],
                "text_indicators": text_flags,
                "url_indicators": url_flags,
                "url_features": url_features_dict if has_url else None
            },
            "share_warning_text": share_texts[detected_lang],
            "cyber_helpline": {
                "national_helpline": "1930",
                "portal_url": "https://cybercrime.gov.in",
                "organization": "Indian Cyber Crime Coordination Centre (I4C), MHA"
            }
        }

    def _generate_plain_explanation(self, threat_level, risk_score, lang, text_flags, url_flags, final_url):
        """Generates plain language explanation and safety advice in EN, HI, or GU"""
        lang = lang if lang in ["en", "hi", "gu"] else "en"

        guidance_dict = {
            "en": {
                "HIGH_RISK_PHISHING": [
                    "DO NOT CLICK the link or enter your bank account details, PIN, or OTP.",
                    "Banks and utility companies (like SBI or MGVCL) NEVER threaten disconnection or account block via SMS links.",
                    "If you received this via WhatsApp or SMS, report and block the sender immediately.",
                    "If you already shared financial details, call National Cybercrime Helpline 1930 immediately."
                ],
                "SUSPICIOUS": [
                    "Proceed with extreme caution. This message exhibits high urgency or suspicious URL patterns.",
                    "Verify directly by calling the official customer care number from your passbook or monthly bill.",
                    "Never enter login credentials on non-official websites."
                ],
                "SAFE": [
                    "This message appears to be a standard notification or legitimate transaction alert.",
                    "Always ensure you are visiting the official verified portal before making payments.",
                    "Remember: Never share confidential OTPs with anyone over phone calls."
                ]
            },
            "hi": {
                "HIGH_RISK_PHISHING": [
                    "इस लिंक पर कतई क्लिक न करें और अपना बैंक विवरण, पिन (PIN) या ओटीपी (OTP) साझा न करें।",
                    "कोई भी बैंक (SBI आदि) या बिजली विभाग (MGVCL) एसएमएस लिंक से खाता बंद करने की धमकी नहीं देता।",
                    "संदिग्ध भेजने वाले नंबर को तुरंत ब्लॉक करें और रिपोर्ट करें।",
                    "यदि आपने कोई जानकारी साझा कर दी है, तो तुरंत साइबर हेल्पलाइन 1930 पर संपर्क करें।"
                ],
                "SUSPICIOUS": [
                    "सतर्क रहें! इस संदेश में जल्दबाजी कराने या संदिग्ध लिंक के संकेत मिले हैं।",
                    "अपनी बैंक पासबुक या बिजली बिल पर दिए गए आधिकारिक नंबर पर फोन करके ही पुष्टि करें।",
                    "किसी भी अनधिकृत वेबसाइट पर लॉगिन या भुगतान न करें।"
                ],
                "SAFE": [
                    "यह संदेश सामान्य और वैध बैंकिंग या सेवा सूचना प्रतीत होता है।",
                    "भुगतान करने से पहले हमेशा आधिकारिक पोर्टल या ऐप की जांच अवश्य करें।",
                    "सुरक्षा नियम: अपना गोपनीय ओटीपी किसी के साथ साझा न करें।"
                ]
            },
            "gu": {
                "HIGH_RISK_PHISHING": [
                    "આ લિંક પર ક્લિક કરશો નહીં તેમજ તમારો બેંક પાસવર્ડ, PIN કે OTP કોઈને આપશો નહીં.",
                    "કોઈપણ બેંક (SBI) કે વીજળી કંપની (MGVCL) SMS લિંક દ્વારા એકાઉન્ટ બ્લોક કરવાની ધમકી આપતી નથી.",
                    "આ મેસેજ મોકલનાર શંકાસ્પદ નંબરને તરત જ બ્લોક અને રિપોર્ટ કરો.",
                    "જો ભૂલથી માહિતી અપાઈ ગઈ હોય તો તરત જ સાયબર ક્રાઈમ હેલ્પલાઈન 1930 પર કોલ કરો."
                ],
                "SUSPICIOUS": [
                    "સાવચેત રહો! આ મેસેજમાં તાત્કાલિક દબાણ અથવા અસામાન્ય લિંકના સંકેતો મળ્યા છે.",
                    "તમારી બેંક પાસબુક અથવા વીજળી બિલ પર આપેલા સત્તાવાર ગ્રાહક સેવા નંબર પર જ તપાસ કરો.",
                    "બિનસત્તાવાર પોર્ટલ પર નેટબેંકિંગ લોગિન કે પેમેન્ટ કરશો નહીં."
                ],
                "SAFE": [
                    "આ મેસેજ સામાન્ય અને સુરક્ષિત વ્યવહારિક સૂચના જણાય છે.",
                    "કોઈપણ ચુકવણી કરતી વખતે હંમેશા સત્તાવાર વેબસાઇટ કે એપ્લિકેશનની ખાતરી કરો.",
                    "ધ્યાન રાખો: કોઈપણ વ્યક્તિ સાથે ફોન પર ગુપ્ત OTP શેર કરશો નહીં."
                ]
            }
        }

        # Summaries
        if threat_level == "HIGH_RISK_PHISHING":
            summaries = {
                "en": f"CRITICAL THREAT DETECTED ({risk_score}% Phishing Probability). Multiple high-confidence fraud indicators matched across message content and URL architecture.",
                "hi": f"गंभीर धोखाधड़ी का खतरा ({risk_score}% फिशिंग संभावना)। संदेश की भाषा और लिंक की संरचना में स्पष्ट साइबर अपराध के संकेत मिले हैं।",
                "gu": f"ગંભીર છેતરપિંડીનો ખતરો ({risk_score}% ફિશિંગ જોખમ). મેસેજ અને લિંકમાં નકલી વેબસાઇટ અને છેતરપિંડીના સ્પષ્ટ પુરાવા મળ્યા છે."
            }
        elif threat_level == "SUSPICIOUS":
            summaries = {
                "en": f"CAUTION ADVISED ({risk_score}% Risk Score). The message contains psychological urgency or unverified web routing.",
                "hi": f"सावधानी बरतें ({risk_score}% जोखिम स्कोर)। संदेश में जल्दबाजी का दबाव या असत्यापित लिंक पैटर्न पाया गया है।",
                "gu": f"સાવધાની જરૂરી ({risk_score}% જોખમ સ્કોર). મેસેજમાં ભ્રામક શબ્દો અથવા શંકાસ્પદ વેબ લિંકના લક્ષણો જણાયા છે."
            }
        else:
            summaries = {
                "en": f"LOW RISK DETECTED ({risk_score}% Threat Score). Verified authentic communication patterns without phishing anomalies.",
                "hi": f"सुरक्षित संदेश ({risk_score}% जोखिम स्कोर)। सामान्य और प्रामाणिक सूचना पैटर्न, कोई साइबर धोखाधड़ी संकेत नहीं मिला।",
                "gu": f"સુરક્ષિત મેસેજ ({risk_score}% જોખમ સ્કોર). પ્રમાણિત વ્યવહારિક સંકેત, કોઈ ફ્રોડ કે છેતરપિંડીના લક્ષણ મળ્યા નથી."
            }

        return {
            "summary": summaries[lang],
            "guidance": guidance_dict[lang][threat_level]
        }

    def evaluate_live_batch(self, samples: list) -> dict:
        """
        Evaluates model on custom live data provided during demonstration
        samples format: [{"text": "...", "url": "...", "label": 1 or 0, "language": "en"}]
        """
        if not samples:
            return {"error": "No samples provided for evaluation"}

        y_true = []
        y_pred_fusion = []
        y_pred_text = []
        y_pred_url = []
        detailed_results = []

        for idx, item in enumerate(samples):
            txt = str(item.get("text", "")).strip()
            raw_url = str(item.get("url", "")).strip()
            lbl = int(item.get("label", 1))
            lang = item.get("language") or detect_language(txt)

            pred_res = self.predict(text=txt, url=raw_url, lang_override=lang)
            p_fused = pred_res["risk_score"] / 100.0
            p_text = pred_res["modality_scores"]["text_only_risk"] / 100.0
            p_url = (pred_res["modality_scores"]["url_only_risk"] or 0.0) / 100.0

            binary_fusion = 1 if p_fused >= 0.5 else 0
            binary_text = 1 if p_text >= 0.5 else 0
            binary_url = 1 if p_url >= 0.5 else 0

            y_true.append(lbl)
            y_pred_fusion.append(binary_fusion)
            y_pred_text.append(binary_text)
            y_pred_url.append(binary_url)

            is_correct = (binary_fusion == lbl)
            detailed_results.append({
                "sample_index": idx + 1,
                "text": txt[:80] + ("..." if len(txt) > 80 else ""),
                "url": raw_url,
                "language": lang,
                "true_label": lbl,
                "true_label_text": "Phishing/Scam" if lbl == 1 else "Legitimate/Safe",
                "predicted_label": binary_fusion,
                "predicted_label_text": "Phishing/Scam" if binary_fusion == 1 else "Legitimate/Safe",
                "risk_score": pred_res["risk_score"],
                "threat_level": pred_res["threat_level"],
                "is_correct": is_correct
            })

        # Calculate metrics for fusion, text, and url
        metrics_fusion = calculate_metrics(np.array(y_true), np.array(y_pred_fusion))
        metrics_text = calculate_metrics(np.array(y_true), np.array(y_pred_text))
        metrics_url = calculate_metrics(np.array(y_true), np.array(y_pred_url))

        return {
            "total_evaluated": len(samples),
            "fusion_metrics": metrics_fusion,
            "text_metrics": metrics_text,
            "url_metrics": metrics_url,
            "detailed_samples": detailed_results
        }

    def retrain(self) -> dict:
        """Triggers pipeline retrain and reloads models"""
        report = train_and_evaluate()
        self.load_models()
        return report

# Global Singleton Instance
nirbhay_engine = NirbhayEngine()
