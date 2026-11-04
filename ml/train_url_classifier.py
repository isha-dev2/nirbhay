#!/usr/bin/env python3
"""
ml/train_url_classifier.py
Trains a dedicated URL Phishing Classifier for Nirbhay (Classifier 2).
Uses:
  - Lexical, structural, domain, and brand impersonation features.
  - Curated legitimate Indian domains and verified phishing / scam URL patterns.
  - RandomForestClassifier + Rule Engine.
Outputs:
  - backend/models/url_classifier.joblib
  - ml/reports/url_classifier_report.txt
"""

import os
import re
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

MODELS_DIR = "backend/models"
REPORTS_DIR = "ml/reports"
MODEL_PATH = os.path.join(MODELS_DIR, "url_classifier.joblib")
REPORT_PATH = os.path.join(REPORTS_DIR, "url_classifier_report.txt")

# ---------------------------------------------------------------------------
# High-Value Target Brands & Trusted Whitelist (India Focus)
# ---------------------------------------------------------------------------
TRUSTED_INDIAN_DOMAINS = {
    # Banking
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "pnbindia.in", "bankofbaroda.in", "canarabank.com", "kotak.com", "rbi.org.in",
    # Government & Law Enforcement
    "cybercrime.gov.in", "incometax.gov.in", "uidai.gov.in", "passportindia.gov.in",
    "echallan.parivahan.gov.in", "parivahan.gov.in", "trai.gov.in", "india.gov.in",
    # Utilities & Telecom (Gujarat / National)
    "pgvcl.com", "ugvcl.com", "mgvcl.com", "dgvcl.com", "tatapower.com", "torrentpower.com",
    "jio.com", "airtel.in", "myvi.in", "bsnl.co.in",
    # Tech & E-commerce
    "amazon.in", "amazon.com", "flipkart.com", "paytm.com", "phonepe.com", "google.com"
}

TARGET_BRAND_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "pnb", "bob", "kotak", "rbi",
    "pgvcl", "ugvcl", "mgvcl", "dgvcl", "tatapower", "electricity", "bill",
    "trai", "challan", "parivahan", "police", "cybercrime", "incometax", "aadhaar",
    "jio", "airtel", "paytm", "phonepe", "gpay", "amazon", "flipkart", "lottery", "kbc"
]

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'site', 'click', 'info', 'club', 'work', 'online', 'vip',
    'live', 'loan', 'link', 'stream', 'gq', 'cf', 'ml', 'ga', 'tk', 'biz',
    'download', 'racing', 'win', 'bid', 'party', 'trade', 'review', 'space',
    'monster', 'buzz', 'rest', 'fit', 'icu', 'cam', 'quest'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'shorturl.at', 'tiny.cc', 'rb.gy', 'cutt.ly', 'qr.ae',
    'v.gd', 'trib.al', 'rebrand.ly'
}

SUSPICIOUS_PATH_KEYWORDS = [
    "kyc", "otp", "login", "verify", "verification", "update", "claim", "reward",
    "bonus", "free", "lottery", "prize", "cashback", "apk", "download", "wallet",
    "deactivated", "blocked", "suspend", "suspend-account", "bill-payment"
]

IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$')

# ---------------------------------------------------------------------------
# Feature Extraction Function
# ---------------------------------------------------------------------------
def extract_url_features(url: str) -> dict:
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
    
    # 1. Structural features
    num_dots = url_clean.count(".")
    num_hyphens = url_clean.count("-")
    num_digits = sum(1 for c in url_clean if c.isdigit())
    digit_ratio = num_digits / url_len if url_len > 0 else 0.0
    has_at_symbol = 1 if "@" in url_clean else 0
    path_depth = len([p for p in path.split("/") if p])
    
    # 2. Host & Protocol
    has_ip = 1 if IPV4_REGEX.match(hostname) else 0
    is_https = 1 if url_clean.lower().startswith("https://") else 0
    
    is_shortener = 1 if any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS) else 0
    
    # TLD
    host_parts = hostname.split(".")
    tld = host_parts[-1] if len(host_parts) >= 2 else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    subdomain_count = max(0, len(host_parts) - 2)
    
    # 3. Path keywords
    path_and_query = path + "?" + query
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path_and_query)
    
    # 4. Brand Impersonation (Brand string inside untrusted domain)
    is_trusted = any(hostname == d or hostname.endswith("." + d) for d in TRUSTED_INDIAN_DOMAINS)
    brand_impersonation = 0
    if not is_trusted:
        for b in TARGET_BRAND_KEYWORDS:
            if b in hostname:
                brand_impersonation = 1
                break
                
    # 5. Dangerous extension (.apk download)
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
        "has_apk": has_apk,
        "is_trusted_domain": 1 if is_trusted else 0
    }

FEATURE_COLUMNS = [
    "url_length", "host_length", "num_dots", "num_hyphens", "num_digits",
    "digit_ratio", "has_at_symbol", "path_depth", "has_ip", "is_https",
    "is_shortener", "suspicious_tld", "subdomain_count",
    "suspicious_keyword_count", "brand_impersonation", "has_apk"
]

# ---------------------------------------------------------------------------
# Training Data Generation (Representative Phishing vs Legitimate Distribution)
# ---------------------------------------------------------------------------
def build_dataset() -> pd.DataFrame:
    """Builds a rich, balanced training dataset of phishing vs legitimate URLs."""
    records = []
    
    # 1. Known Legitimate Indian & Global Domains (Safe = 0)
    legit_templates = [
        "https://www.onlinesbi.sbi/portal/login.htm",
        "https://retail.onlinesbi.sbi/retail/userlogin.htm",
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://www.icicibank.com/personal-banking/insta-banking/internet-banking",
        "https://www.axisbank.com/retail/accounts",
        "https://www.bankofbaroda.in/personal-banking/digital-products",
        "https://cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx",
        "https://incometax.gov.in/iec/foportal/",
        "https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html",
        "https://echallan.parivahan.gov.in/index/accused-challan",
        "https://parivahan.gov.in/parivahan/en/content/driving-licence-0",
        "https://pgvcl.com/consumer/bill-payment.php",
        "https://ugvcl.com/quickpay/",
        "https://www.tatapower.com/customer/mumbai/pay-bill.aspx",
        "https://www.jio.com/selfcare/recharge/mobility/",
        "https://www.airtel.in/prepaid-recharge/",
        "https://paytm.com/recharge",
        "https://www.amazon.in/gp/css/order-history",
        "https://www.flipkart.com/account/orders",
        "https://github.com/google/muril",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://policies.google.com/privacy",
        "https://support.google.com/accounts/answer/185839",
        "https://www.irctc.co.in/nget/train-search",
        "https://www.cowin.gov.in/vaccination-certificate",
        "https://sandesh.com/gujarat/news",
        "https://amarujala.com/technology",
        "https://timesofindia.indiatimes.com/city/ahmedabad"
    ]
    
    for url in legit_templates:
        records.append({"url": url, "label": 0})
        # Add slight path variants
        records.append({"url": url + "?ref=nav_header", "label": 0})
        records.append({"url": url.replace("https://", "https://m."), "label": 0})
        
    # 2. Real-World Phishing & Scam Templates (Scam = 1)
    phishing_templates = [
        # Electricity bill scams (Gujarat/National)
        "http://pgvcl-billupdate.top/pay.apk",
        "http://ugvcl-electricity.site/quickpay.html",
        "https://pgvcl-consumer-bill.click/verify?u=982341",
        "http://192.168.1.104/bill-payment/pgvcl.apk",
        "http://bijli-vibhag-bill.xyz/connection-blocked",
        "https://ugvcl-bill.online/payment-service",
        # Bank & KYC impersonation
        "http://sbi-kyc-verification.top/login.php",
        "https://sbi-reward-points.click/redeem-cash",
        "http://hdfc-netbanking-update.xyz/login/customer.html",
        "http://icici-pan-update.site/verify-account",
        "https://pnb-kyc-alert.vip/verification.htm",
        "http://142.250.190.46/onlinesbi/login.html",
        "https://sbi-customer-support.loan/update-kyc",
        # Traffic challan APK scams
        "https://echallan-parivahan.top/challan_payment.apk",
        "http://traffic-police-challan.click/download/fine.apk",
        "https://parivahan-sewa.site/vahan-challan-details.apk",
        # Lottery & Work-from-Home Telegram scams
        "http://kbc-lottery-winner.xyz/claim-25-lakhs",
        "https://t.me/part_time_task_earning_daily",
        "http://telegram-earn-daily.online/vip-register",
        "https://bit.ly/free-recharge-jio-5g-offer",
        "https://tinyurl.com/sbi-blocked-account-fix",
        "http://jio-free-recharge.site/claim-offer",
        "http://free-5g-data-jio.top/register.php?phone=987654",
        # Digital arrest / Police impersonation
        "http://cyber-crime-notice.xyz/court-summons.pdf.exe",
        "https://cbi-arrest-warrant.top/case-details.html",
        # URL shortener phishing
        "http://rb.gy/sbi-urgent-kyc",
        "https://cutt.ly/rbi-bonus-credit",
        "http://bit.do/pan-link-aadhaar-fine"
    ]
    
    for url in phishing_templates:
        records.append({"url": url, "label": 1})
        # Add query variants
        records.append({"url": url + "?ref=sms&token=8941", "label": 1})
        records.append({"url": url.replace("http://", "http://www."), "label": 1})

    df = pd.DataFrame(records).drop_duplicates(subset=["url"]).reset_index(drop=True)
    return df

# ---------------------------------------------------------------------------
# Training & Cross-Validation
# ---------------------------------------------------------------------------
def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    print("=" * 60)
    print("TRAINING CLASSIFIER 2: URL PHISHING & SCAM DETECTOR")
    print("=" * 60)
    
    df = build_dataset()
    print(f"Total training URLs: {len(df)} (Safe: {(df['label']==0).sum()}, Scam: {(df['label']==1).sum()})")
    
    # Feature extraction
    feat_dicts = [extract_url_features(u) for u in df["url"]]
    X = pd.DataFrame(feat_dicts)[FEATURE_COLUMNS]
    y = df["label"].values
    
    # 5-fold cross validation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    oof_preds = np.zeros(len(df))
    oof_probas = np.zeros(len(df))
    
    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        clf_fold = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
        clf_fold.fit(X.iloc[train_idx], y[train_idx])
        oof_probas[test_idx] = clf_fold.predict_proba(X.iloc[test_idx])[:, 1]
        oof_preds[test_idx] = (oof_probas[test_idx] >= 0.5).astype(int)
        
    print("\nCross-Validation Performance:")
    cr = classification_report(y, oof_preds, target_names=["Safe URL", "Scam URL"], digits=4)
    cm = confusion_matrix(y, oof_preds)
    roc = roc_auc_score(y, oof_probas)
    
    print(cr)
    print("Confusion Matrix:")
    print(cm)
    print(f"ROC-AUC Score: {roc:.4f}")
    
    # Train final model on full dataset
    final_model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    final_model.fit(X, y)
    
    # Feature importances
    fi = pd.DataFrame({
        "feature": FEATURE_COLUMNS,
        "importance": final_model.feature_importances_
    }).sort_values("importance", ascending=False)
    
    print("\nTop 8 Feature Importances:")
    print(fi.head(8).to_string(index=False))
    
    # Save model bundle
    bundle = {
        "model": final_model,
        "feature_columns": FEATURE_COLUMNS,
        "trusted_domains": TRUSTED_INDIAN_DOMAINS,
        "suspicious_tlds": SUSPICIOUS_TLDS,
        "target_brands": TARGET_BRAND_KEYWORDS,
        "shorteners": SHORTENERS
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"\nSaved model bundle to {MODEL_PATH}")
    
    # Write report
    report_text = f"""============================================================
NIRBHAY CLASSIFIER 2: URL DETECTOR PERFORMANCE REPORT
============================================================
Total Samples: {len(df)}
Safe URLs: {(df['label']==0).sum()}
Scam URLs: {(df['label']==1).sum()}

Cross-Validation Metrics:
{cr}
Confusion Matrix:
[[TN={cm[0,0]}, FP={cm[0,1]}],
 [FN={cm[1,0]}, TP={cm[1,1]}]]

ROC-AUC: {roc:.4f}

Feature Importances:
{fi.to_string(index=False)}
============================================================
"""
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"Report written to {REPORT_PATH}")

if __name__ == "__main__":
    main()

