"""
Feature Extraction Engine for Nirbhay Platform
Implements:
1. Indic & Multilingual text preprocessing and Language Identification (EN, HI, GU)
2. 25+ Lexical, Host, Domain, and Entropy URL features (QsecR inspired)
3. Explainability token extractors for both Text and URL
"""
import math
import re
from urllib.parse import urlparse

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "club", "live", "buzz", "work", "site", 
    "support", "cfd", "online", "tk", "ml", "ga", "cf", "gq", "icu"
}

FEATURE_COLUMNS = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_questionmarks", "num_equal", "num_at",
    "num_ampersand", "num_percent", "num_digits", "digit_ratio", "is_https",
    "is_ip", "num_subdomains", "domain_entropy", "has_suspicious_tld",
    "num_sensitive_words", "has_brand_spoof", "brand_spoof_count",
    "is_shortened", "has_port", "url_entropy"
]

# Known Indian brand keywords targeted by scammers
TARGET_BRANDS = [
    "sbi", "yono", "hdfc", "icici", "pnb", "bob", "axis", "kotak",
    "mgvcl", "ugvcl", "pgvcl", "dgycl", "uppcl", "bescom", "tneb",
    "phonepe", "paytm", "gpay", "googlepay", "bhim", "amazon", "flipkart",
    "indiapost", "kbc", "pmkisan", "incometax", "aadhaar", "uidai"
]

# Sensitive / Action keywords in URL
URL_SENSITIVE_WORDS = [
    "login", "verify", "update", "kyc", "pan", "otp", "bill", "pay", 
    "secure", "banking", "account", "confirm", "free", "reward", 
    "cashback", "winner", "prize", "claim", "urgent", "blocked", "redelivery"
]

# Text Red-Flag Dictionaries per language (including Romanized Hinglish/Gujlish)
EXPLAINABILITY_KEYWORDS = {
    "en": {
        "urgency": [
            "urgent", "immediately", "24 hours", "tonight", "blocked", "suspended", 
            "disconnected", "lapse", "last chance", "aaj raat", "turant", "tatkal", 
            "aaje ratre", "tatkalik", "bandh ho", "kat diya", "kapi nakhva"
        ],
        "financial_kyc": [
            "kyc", "pan card", "bank account", "netbanking", "yono", "debit", 
            "credit card", "wallet", "aadhaar", "khata", "bijli", "bill", "paisa", "rupaye"
        ],
        "fraud_incentive": [
            "lottery", "cash prize", "kbc", "won", "reward", "scratch card", 
            "cashback", "part time job", "earn daily", "refund", "inaam", "kamao", "jeeto"
        ],
        "credential_theft": [
            "otp", "pin", "password", "click here", "link", "verify", 
            "update address", "redelivery fee", "click karein", "link par", "shulk"
        ],
    },
    "hi": {
        "urgency": ["तुरंत", "तत्काल", "आज रात", "24 घंटे", "बंद कर दिया", "काट दिया", "निष्क्रिय", "ब्लॉक", "अति आवश्यक", "चेतावनी"],
        "financial_kyc": ["केवाईसी", "पैन कार्ड", "बैंक खाता", "योनो", "नेट बैंकिंग", "आधार कार्ड", "वॉलेट", "रुपये", "खाता संख्या"],
        "fraud_incentive": ["लॉटरी", "इनाम", "केबीसी", "बधाई", "कैशबैक", "स्क्रैच कार्ड", "रिवॉर्ड", "पार्ट टाइम", "घर बैठे", "कमाएं", "रिफंड"],
        "credential_theft": ["ओटीपी", "पिन", "पासवर्ड", "क्लिक करें", "सत्यापित", "लिंक खोलें", "शुल्क भरें"],
    },
    "gu": {
        "urgency": ["તાત્કાલિક", "હમણાં જ", "આજે રાત્રે", "24 કલાક", "સ્થગિત", "કાપી નાખવામાં", "બ્લોક", "બંધ થશે", "ખાસ સૂચના", "ચેતવણી"],
        "financial_kyc": ["કેવાયસી", "પાન કાર્ડ", "બેંક એકાઉન્ટ", "નેટ બેંકિંગ", "ખાતું", "આધાર", "વૉલેટ", "રૂપિયા", "વીજળી"],
        "fraud_incentive": ["લકી ડ્રો", "ઈનામ", "રોકડ", "અભિનંદન", "કેશબેક", "સ્ક્રેચ કાર્ડ", "રિવોર્ડ", "પાર્ટ-ટાઈમ", "ઘરે બેઠા", "કમાઓ", "સહાય", "રિફંડ"],
        "credential_theft": ["ઓટીપી", "પિન", "પાસવર્ડ", "ક્લિક કરો", "વેરિફાઈ", "ચકાસણી", "લિંક પર"],
    }
}

def detect_language(text: str) -> str:
    """
    Detects whether text is English ('en'), Hindi ('hi'), or Gujarati ('gu').
    Uses Unicode script code point ranges:
    - Devanagari (Hindi): U+0900 to U+097F
    - Gujarati: U+0A80 to U+0AFF
    - Latin (English): U+0020 to U+007E
    """
    if not text or not isinstance(text, str):
        return "en"
    
    devanagari_count = 0
    gujarati_count = 0
    latin_count = 0

    for ch in text:
        cp = ord(ch)
        if 0x0900 <= cp <= 0x097F:
            devanagari_count += 1
        elif 0x0A80 <= cp <= 0x0AFF:
            gujarati_count += 1
        elif 0x0041 <= cp <= 0x005A or 0x0061 <= cp <= 0x007A:
            latin_count += 1

    if gujarati_count >= 5 or (gujarati_count > 0 and gujarati_count >= devanagari_count and gujarati_count >= latin_count * 0.4):
        return "gu"
    if devanagari_count >= 5 or (devanagari_count > 0 and devanagari_count > gujarati_count and devanagari_count >= latin_count * 0.4):
        return "hi"
    return "en"

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to spot algorithmically generated / random domains"""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_url_from_text(text: str) -> str:
    """Extracts first HTTP/HTTPS or domain URL from text if present"""
    if not text:
        return ""
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.(?:com|org|in|net|xyz|top|click|club|live|buzz|gov|edu|ac\.in|sbi)[^\s]*)'
    match = re.search(url_pattern, text)
    if match:
        url = match.group(0).rstrip('.,;:!?)')
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        return url
    return ""

def extract_url_features(url: str) -> dict:
    """
    Extracts 25+ lexical, host, and domain features from a URL
    Inspired by QsecR framework (IEEE Access 2023)
    """
    features = {
        "url_length": 0,
        "domain_length": 0,
        "path_length": 0,
        "num_dots": 0,
        "num_hyphens": 0,
        "num_underscores": 0,
        "num_slashes": 0,
        "num_questionmarks": 0,
        "num_equal": 0,
        "num_at": 0,
        "num_ampersand": 0,
        "num_percent": 0,
        "num_digits": 0,
        "digit_ratio": 0.0,
        "is_https": 0,
        "is_ip": 0,
        "num_subdomains": 0,
        "domain_entropy": 0.0,
        "has_suspicious_tld": 0,
        "num_sensitive_words": 0,
        "has_brand_spoof": 0,
        "brand_spoof_count": 0,
        "is_shortened": 0,
        "has_port": 0,
        "url_entropy": 0.0
    }

    if not url or not isinstance(url, str) or len(url.strip()) == 0:
        return features

    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception:
        netloc = url.split("/")[0].lower()
        path = ""
        query = ""

    # Basic lengths
    features["url_length"] = len(url)
    features["domain_length"] = len(netloc)
    features["path_length"] = len(path)

    # Character counts
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_questionmarks"] = url.count("?")
    features["num_equal"] = url.count("=")
    features["num_at"] = url.count("@")
    features["num_ampersand"] = url.count("&")
    features["num_percent"] = url.count("%")
    digits = sum(c.isdigit() for c in url)
    features["num_digits"] = digits
    features["digit_ratio"] = round(digits / len(url), 4) if len(url) > 0 else 0.0

    # Protocol & Host
    features["is_https"] = 1 if url.lower().startswith("https://") else 0
    
    # Check IP host
    domain_part = netloc.split(":")[0]
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features["is_ip"] = 1 if re.match(ip_pattern, domain_part) else 0

    # Port check
    features["has_port"] = 1 if ":" in netloc and not netloc.startswith("http") else 0

    # Subdomains
    parts = domain_part.split(".")
    features["num_subdomains"] = max(0, len(parts) - 2)

    # TLD
    tld = parts[-1] if parts else ""
    features["has_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

    # Entropies
    features["domain_entropy"] = calculate_shannon_entropy(domain_part)
    features["url_entropy"] = calculate_shannon_entropy(url)

    # Sensitive words
    url_lower = url.lower()
    sens_count = sum(1 for word in URL_SENSITIVE_WORDS if word in url_lower)
    features["num_sensitive_words"] = sens_count

    # Brand spoofing check
    brand_hits = sum(1 for brand in TARGET_BRANDS if brand in url_lower)
    # Check if brand is in domain but it is not an official domain
    is_spoof = 0
    if brand_hits > 0:
        # Legitimate domain whitelist check
        is_legit_domain = any(domain_part.endswith(suffix) for suffix in [
            "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", 
            "bankofbaroda.in", "mgvcl.com", "uppcl.org", "phonepe.com",
            "paytm.com", "amazon.in", "flipkart.com", "indiapost.gov.in",
            "gov.in", "nic.in", "nuv.ac.in", "irctc.co.in", "licindia.in"
        ])
        if not is_legit_domain:
            is_spoof = 1
    features["has_brand_spoof"] = is_spoof
    features["brand_spoof_count"] = brand_hits

    # Shorteners
    shorteners = ["bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy"]
    features["is_shortened"] = 1 if any(s in domain_part for s in shorteners) else 0

    return features

def extract_text_indicators(text: str, lang: str = "en") -> list:
    """
    Finds exact flagged keywords and patterns in message text for explainable AI
    """
    if not text:
        return []
    
    lang = lang if lang in EXPLAINABILITY_KEYWORDS else "en"
    text_lower = text.lower()
    flags = []

    categories = EXPLAINABILITY_KEYWORDS[lang]
    category_labels = {
        "en": {
            "urgency": "High-Pressure Urgency Trigger",
            "financial_kyc": "Financial / KYC Impersonation",
            "fraud_incentive": "Unrealistic Reward / Lottery Bait",
            "credential_theft": "Credential / OTP Theft Signal"
        },
        "hi": {
            "urgency": "अत्यधिक तात्कालिकता / धमकी (Urgency Pressure)",
            "financial_kyc": "बैंक / केवाईसी धोखाधड़ी संकेत",
            "fraud_incentive": "अवास्तविक लॉटरी / इनाम का लालच",
            "credential_theft": "ओटीपी / पासवर्ड चोरी का खतरा"
        },
        "gu": {
            "urgency": "તાત્કાલિક દબાણ / ધમકીભર્યો સંદેશ",
            "financial_kyc": "બેંક / KYC સંબંધી છેતરપિંડી સૂચક",
            "fraud_incentive": "બિનવાસ્તવિક ઈનામ / લકી ડ્રો લાલચ",
            "credential_theft": "OTP / પાસવર્ડ ચોરી સંકેત"
        }
    }

    for cat_key, words in categories.items():
        found = [w for w in words if w in text_lower]
        if found:
            flags.append({
                "category": cat_key,
                "label": category_labels[lang][cat_key],
                "matches": found[:4]
            })

    # Also detect suspicious phone call triggers
    phone_pattern = r'\b[6-9]\d{9}\b'
    if re.search(phone_pattern, text):
        phone_label = {
            "en": "Suspicious Mobile Number Direct Call Request",
            "hi": "संदिग्ध मोबाइल नंबर पर सीधे कॉल करने का दबाव",
            "gu": "શંકાસ્પદ મોબાઇલ નંબર પર સીધો સંપર્ક કરવાની સૂચના"
        }
        flags.append({
            "category": "direct_call",
            "label": phone_label[lang],
            "matches": re.findall(phone_pattern, text)
        })

    return flags

def extract_url_indicators(url: str, lang: str = "en") -> list:
    """
    Extracts human-understandable structural URL red flags
    """
    if not url:
        return []
    
    feats = extract_url_features(url)
    indicators = []

    text_map = {
        "en": {
            "ip_host": "URL uses a raw IP address instead of a legitimate registered domain name",
            "suspicious_tld": "Uses an unusual, high-risk top-level domain often associated with scams",
            "brand_spoof": "Impersonates a known trusted Indian bank, utility, or financial service",
            "excessive_hyphens": "Excessive hyphens and subdomains designed to deceive mobile users",
            "no_https": "Insecure HTTP connection without valid security certificate",
            "high_entropy": "Domain characters appear randomly generated or obfuscated",
            "sensitive_words": "Contains sensitive banking keywords in unauthorized web path"
        },
        "hi": {
            "ip_host": "यूआरएल में पंजीकृत डोमेन के बजाय सीधे आईपी एड्रेस का उपयोग किया गया है",
            "suspicious_tld": "धोखाधड़ी में अक्सर उपयोग होने वाले संदिग्ध एक्सटेंशन (.xyz, .top आदि) का उपयोग",
            "brand_spoof": "प्रतिष्ठित भारतीय बैंक या संस्थान (SBI, HDFC, MGVCL) का नकली प्रतिरूपण",
            "excessive_hyphens": "यूआरएल में अत्यधिक हाइफन और भ्रामक सबडोमेन जोड़े गए हैं",
            "no_https": "असुरक्षित कनेक्शन (HTTP) - इसमें कोई सुरक्षा प्रमाणपत्र नहीं है",
            "high_entropy": "डोमेन का नाम संदिग्ध रूप से रैंडम अक्षरों से बना हुआ प्रतीत होता है",
            "sensitive_words": "अनधिकृत लिंक में संवेदनशील बैंक/केवाईसी कीवर्ड्स शामिल हैं"
        },
        "gu": {
            "ip_host": "લિંકમાં માન્ય ડોમેનને બદલે સીધા IP એડ્રેસનો ઉપયોગ થયેલ છે",
            "suspicious_tld": "સાયબર ફ્રોડમાં વપરાતા શંકાસ્પદ એક્સટેન્શન (.xyz, .top વગેરે) છે",
            "brand_spoof": "વિશ્વાસપાત્ર બેંક અથવા સરકારી સંસ્થા (SBI, MGVCL વગેરે) ની નકલ",
            "excessive_hyphens": "લિંકમાં અસામાન્ય હાઇફન (-) અને ભ્રામક સબડોમેન ઉમેરેલા છે",
            "no_https": "અસુરક્ષિત કનેક્શન (HTTP) - સિક્યોરિટી સર્ટિફિકેટનો અભાવ છે",
            "high_entropy": "ડોમેન નામ શંકાસ્પદ રીતે રેન્ડમ શબ્દોથી બનેલું જણાય છે",
            "sensitive_words": "અનધિકૃત લિંકમાં બેંકિંગ અથવા KYC સંબંધિત શબ્દો છે"
        }
    }

    t = text_map.get(lang, text_map["en"])

    if feats["is_ip"]:
        indicators.append({"type": "ip_host", "severity": "CRITICAL", "description": t["ip_host"]})
    if feats["has_brand_spoof"]:
        indicators.append({"type": "brand_spoof", "severity": "HIGH", "description": t["brand_spoof"]})
    if feats["has_suspicious_tld"]:
        indicators.append({"type": "suspicious_tld", "severity": "HIGH", "description": t["suspicious_tld"]})
    if feats["num_hyphens"] >= 3 or feats["num_subdomains"] >= 2:
        indicators.append({"type": "excessive_hyphens", "severity": "MEDIUM", "description": t["excessive_hyphens"]})
    if not feats["is_https"]:
        indicators.append({"type": "no_https", "severity": "MEDIUM", "description": t["no_https"]})
    if feats["domain_entropy"] > 3.6:
        indicators.append({"type": "high_entropy", "severity": "MEDIUM", "description": t["high_entropy"]})
    if feats["num_sensitive_words"] >= 2:
        indicators.append({"type": "sensitive_words", "severity": "MEDIUM", "description": t["sensitive_words"]})

    return indicators
