#!/usr/bin/env python3
"""
ml/preprocess_features.py
Preprocesses master_v2.csv and engineers tabular features (Stages 2 & 3).
Produces:
  - ml/data/processed/train_ready.csv
"""

import re
import hashlib
import unicodedata
from urllib.parse import urlparse
import pandas as pd
import numpy as np

INPUT_PATH = "ml/data/processed/master_v2.csv"
OUTPUT_PATH = "ml/data/processed/train_ready.csv"

# -------------------------------------------------------------
# Regex Patterns & Vocabulary Constants
# -------------------------------------------------------------
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>\"\'\)]+|'
    r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|bit\.do|shorturl\.at|tiny\.cc|rb\.gy|cutt\.ly)/[^\s<>\"\'\)]+',
    re.IGNORECASE
)
IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$')

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'site', 'click', 'info', 'club', 'work', 'online', 'vip',
    'live', 'loan', 'link', 'stream', 'gq', 'cf', 'ml', 'ga', 'tk', 'biz',
    'download', 'racing', 'win', 'bid', 'party', 'trade', 'review', 'space',
    'monster', 'buzz', 'rest', 'fit', 'cc'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'shorturl.at', 'tiny.cc', 'rb.gy', 'cutt.ly', 'qr.ae',
    'v.gd', 'trib.al', 'rebrand.ly'
}

EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
PHONE_REGEX = re.compile(
    r'(?:(?:\+|00)?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|'
    r'1800[\s-]?\d{3}[\s-]?\d{3,4}\b|'
    r'\b0\d{2,4}[\s-]?\d{6,8}\b|'
    r'\b(?:\+?\d{1,3}[\s-]?)?\(?\d{3,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
)
DIGIT_RUNS_REGEX = re.compile(r'\b\d{4,}\b')
ZERO_WIDTH_REGEX = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff]')

CURRENCY_REGEX = re.compile(r'(?:₹|\brs\b|\brs\.|\binr\b|रु|રૂ|£|[\$€])', re.IGNORECASE)
AMOUNT_REGEX = re.compile(
    r'(?:(?:₹|\brs\b|\brs\.|\binr\b|रु|રૂ|£|[\$€])\s*\d+[\d,.]*|\d+[\d,.]*\s*(?:₹|\brs\b|\brs\.|\binr\b|रु|રૂ|£|[\$€]|/-|/=))',
    re.IGNORECASE
)

URGENCY_KEYWORDS = [
    # English
    r'\burgent\b', r'\bimmediately\b', r'\bimmediate\b', r'\bexpires?\b', r'\bexpiring\b',
    r'\bblocked?\b', r'\bsuspended?\b', r'\bhurry\b', r'\blast day\b', r'\blast chance\b',
    r'\blimited time\b', r'\btoday only\b', r'\bfinal notice\b', r'\bdeadline\b', r'\balert\b', r'\bwarning\b',
    # Hindi
    'तुरंत', 'तत्काल', 'जल्द', 'अंतिम तिथि', 'समाप्त', 'बंद', 'सावधान', 'चेतावनी', 'अभी', 'शीघ्र', 'रुकावट', 'ब्लॉक',
    # Gujarati
    'તાત્કાલિક', 'તરત', 'જલ્દી', 'છેલ્લી તારીખ', 'સમાપ્ત', 'બંધ', 'સાવધાન', 'ચેતવણી', 'અત્યારે', 'બ્લોક'
]

AUTHORITY_KEYWORDS = [
    # English
    r'\brbi\b', r'\bsbi\b', r'\bkyc\b', r'\bpolice\b', r'\btrai\b', r'\bbank(?:ing)?\b',
    r'\bcourt\b', r'\bincome tax\b', r'\bcbi\b', r'\bcyber\b', r'\bcustoms\b', r'\baadhaar\b',
    r'\bpan card\b', r'\bgov(?:ernment)?\b', r'\belectricity board\b', r'\bpgvcl\b', r'\bugvcl\b',
    r'\bmgvcl\b', r'\bdgvcl\b', r'\btatapower\b',
    # Hindi
    'आरबीआई', 'एसबीआई', 'केवाईसी', 'पुलिस', 'बैंक', 'अदालत', 'आयकर', 'सीबीआई', 'साइबर', 'सरकार', 'आधार', 'पैन कार्ड', 'बिजली विभाग',
    # Gujarati
    'આરબીઆઈ', 'એસબીઆઈ', 'કેવાયસી', 'પોલીસ', 'બેંક', 'અદાલત', 'આવકવેરા', 'સીબીઆઈ', 'સાયબર', 'સરકાર', 'આધાર', 'પાન કાર્ડ', 'વીજળી બોર્ડ'
]

CREDENTIAL_KEYWORDS = [
    r'\botp\b', r'\bpin\b', r'\bcvv\b', r'\bpasswords?\b', r'\bpasscode\b', r'\bsecret code\b',
    r'\bcredentials?\b', r'\blogin\b', r'\buser\s*id\b',
    'पासवर्ड', 'पिन', 'ओटीपी', 'પાસવર્ડ', 'પીન', 'ઓટીપી'
]

ACTION_VERB_KEYWORDS = [
    # English
    r'\bclicks?\b', r'\bcalls?\b', r'\bdownloads?\b', r'\binstall(?:ed|ing)?\b', r'\bupdates?\b',
    r'\bclaims?\b', r'\bverif(?:y|ied|ication)\b', r'\brepl(?:y|ied)\b', r'\bsend\b', r'\bdial\b',
    r'\bvisits?\b', r'\bopen\b', r'\bcontact\b',
    # Hindi
    'क्लिक', 'कॉल', 'डाउनलोड', 'अपडेट', 'सत्यापित', 'जवाब', 'भेजें', 'संपर्क', 'जाएं', 'दावा',
    # Gujarati
    'ક્લિક', 'કૉલ', 'કોલ', 'ડાઉનલોડ', 'અપડેટ', 'ચકાસો', 'જવાબ', 'મોકલો', 'સંપર્ક', 'જાઓ', 'દાવો'
]

# -------------------------------------------------------------
# Stage 2 Preprocessing Helpers
# -------------------------------------------------------------
def clean_text(text: str) -> str:
    """
    Unicode NFC, strip zero-width characters, collapse whitespace,
    links -> <LINK>, phones -> <PHONE>, emails -> <EMAIL>, long digit runs -> <NUM>.
    Keep case. Keep Indic scripts untouched.
    """
    if not isinstance(text, str):
        return ""
    # Unicode NFC
    t = unicodedata.normalize('NFC', text)
    # Strip zero-width chars
    t = ZERO_WIDTH_REGEX.sub('', t)
    # URLs -> <LINK>
    t = URL_REGEX.sub('<LINK>', t)
    # Emails -> <EMAIL>
    t = EMAIL_REGEX.sub('<EMAIL>', t)
    # Phones -> <PHONE>
    def phone_repl(m):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) >= 10:
            return '<PHONE>'
        return raw
    t = PHONE_REGEX.sub(phone_repl, t)
    # Long digit runs (4+ digits) -> <NUM>
    t = DIGIT_RUNS_REGEX.sub('<NUM>', t)
    # Collapse whitespace
    t = re.sub(r'\s+', ' ', t).strip()
    return t

def make_template_key(text: str) -> str:
    t = str(text).lower()
    t = re.sub(r'https?://\S+|www\.\S+', '<link>', t)
    t = re.sub(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', '<phone>', t)
    t = re.sub(r'\d+', '', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t[:60]

def count_emojis(text: str) -> int:
    count = 0
    for ch in text:
        cp = ord(ch)
        if (0x1F600 <= cp <= 0x1F64F or
            0x1F300 <= cp <= 0x1F5FF or
            0x1F680 <= cp <= 0x1F6FF or
            0x1F700 <= cp <= 0x1F77F or
            0x1F780 <= cp <= 0x1F7FF or
            0x1F800 <= cp <= 0x1F8FF or
            0x1F900 <= cp <= 0x1F9FF or
            0x1FA00 <= cp <= 0x1FA6F or
            0x1FA70 <= cp <= 0x1FAFF or
            0x2600 <= cp <= 0x26FF or
            0x2700 <= cp <= 0x27BF):
            count += 1
    return count

def count_keyword_matches(text: str, patterns) -> int:
    text_lower = text.lower()
    cnt = 0
    for p in patterns:
        if p.startswith(r'\b'):
            cnt += len(re.findall(p, text_lower, re.IGNORECASE))
        else:
            cnt += text_lower.count(p.lower())
    return cnt

# -------------------------------------------------------------
# Stage 3 Feature Extraction
# -------------------------------------------------------------
def compute_features(text: str) -> dict:
    t = str(text) if isinstance(text, str) else ""
    t_len = len(t)
    
    # 1. URL features
    urls = URL_REGEX.findall(t)
    n_urls = len(urls)
    has_url = 1 if n_urls > 0 else 0
    url_is_ip = 0
    url_suspicious_tld = 0
    url_is_shortener = 0
    url_https = 0
    max_url_len = 0
    
    for u in urls:
        max_url_len = max(max_url_len, len(u))
        if u.lower().startswith("https://"):
            url_https = 1
        parsed = urlparse(u if "://" in u else "http://" + u)
        netloc = (parsed.netloc or "").split(":")[0].lower()
        if IPV4_REGEX.match(netloc):
            url_is_ip = 1
        if any(netloc == s or netloc.endswith("." + s) for s in SHORTENERS):
            url_is_shortener = 1
        parts = netloc.split(".")
        if len(parts) >= 2 and parts[-1] in SUSPICIOUS_TLDS:
            url_suspicious_tld = 1
            
    # 2. Digit ratio
    digits_count = sum(1 for c in t if c.isdigit())
    digit_ratio = (digits_count / t_len) if t_len > 0 else 0.0
    
    # 3. Has phone
    has_phone = 1 if ("<PHONE>" in t or PHONE_REGEX.search(t)) else 0
    
    # 4. Has currency & amount
    has_currency = 1 if bool(CURRENCY_REGEX.search(t)) else 0
    has_amount = 1 if bool(AMOUNT_REGEX.search(t)) else 0
    
    # 5. Domain keyword counts
    urgency_count = count_keyword_matches(t, URGENCY_KEYWORDS)
    authority_count = count_keyword_matches(t, AUTHORITY_KEYWORDS)
    credential_count = count_keyword_matches(t, CREDENTIAL_KEYWORDS)
    action_verbs_count = count_keyword_matches(t, ACTION_VERB_KEYWORDS)
    
    # 6. Punctuation & casing
    exclamation_count = t.count("!")
    latin_letters = [c for c in t if 'LATIN' in unicodedata.name(c, '')]
    n_latin = len(latin_letters)
    upper_latin = sum(1 for c in latin_letters if c.isupper())
    uppercase_ratio = (upper_latin / n_latin) if n_latin > 0 else 0.0
    
    # 7. Emoji count & length
    emoji_cnt = count_emojis(t)
    
    # 8. Script ratios
    dev_count = sum(1 for c in t if 'DEVANAGARI' in unicodedata.name(c, ''))
    gu_count = sum(1 for c in t if 'GUJARATI' in unicodedata.name(c, ''))
    
    latin_ratio = (n_latin / t_len) if t_len > 0 else 0.0
    dev_ratio = (dev_count / t_len) if t_len > 0 else 0.0
    gu_ratio = (gu_count / t_len) if t_len > 0 else 0.0
    
    return {
        "feat_has_url": has_url,
        "feat_n_urls": n_urls,
        "feat_url_is_ip": url_is_ip,
        "feat_url_suspicious_tld": url_suspicious_tld,
        "feat_url_is_shortener": url_is_shortener,
        "feat_url_https": url_https,
        "feat_url_length": max_url_len,
        "feat_digit_ratio": digit_ratio,
        "feat_has_phone": has_phone,
        "feat_has_currency": has_currency,
        "feat_has_amount": has_amount,
        "feat_urgency_count": urgency_count,
        "feat_authority_count": authority_count,
        "feat_credential_count": credential_count,
        "feat_action_verbs_count": action_verbs_count,
        "feat_exclamation_count": exclamation_count,
        "feat_uppercase_ratio": uppercase_ratio,
        "feat_emoji_count": emoji_cnt,
        "feat_length": t_len,
        "feat_latin_ratio": latin_ratio,
        "feat_devanagari_ratio": dev_ratio,
        "feat_gujarati_ratio": gu_ratio,
    }

def main():
    print("=" * 60)
    print("STAGE 2 & 3 - PREPROCESSING & FEATURE ENGINEERING")
    print("=" * 60)
    
    print(f"Reading master dataset from {INPUT_PATH}...")
    df = pd.read_csv(INPUT_PATH)
    print(f"Loaded {len(df)} rows.")
    
    # Stage 2: Preprocess text
    print("Cleaning text (Unicode NFC, whitespace, masking to tokens <LINK>, <PHONE>, <EMAIL>, <NUM>)...")
    df['text_clean'] = df['text'].apply(clean_text)
    
    # Target label y (scam=1, safe=0)
    df['y'] = (df['label'] == 'scam').astype(int)
    
    # is_real: True if collected_by != 'synthetic'
    df['is_real'] = df['collected_by'] != 'synthetic'
    
    # group_id: template key hash
    print("Generating template keys and group_id for grouped cross-validation...")
    template_keys = df['text'].apply(make_template_key)
    # Using integer factorize for clean group IDs
    df['group_id'] = pd.factorize(template_keys)[0]
    n_groups = df['group_id'].nunique()
    print(f"Total unique message groups (group_id): {n_groups}")
    
    # Stage 3: Feature Engineering from ORIGINAL text before stage 2 masking
    print("Computing tabular features from original text...")
    feat_records = [compute_features(t) for t in df['text']]
    df_feat = pd.DataFrame(feat_records)
    
    # Combine metadata + stage 2 cols + stage 3 features
    meta_cols = [
        'id', 'text', 'text_clean', 'language', 'label', 'y',
        'is_real', 'group_id', 'source', 'collected_by', 'notes'
    ]
    df_out = pd.concat([df[meta_cols], df_feat], axis=1)
    
    # Save train_ready.csv
    print(f"Saving train-ready dataset to {OUTPUT_PATH}...")
    df_out.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
    print(f"Saved {len(df_out)} rows with {df_out.shape[1]} columns to {OUTPUT_PATH}.")
    
    # Print short summary
    print("\n" + "=" * 60)
    print("STAGE 2 & 3 SUMMARY COUNTS (language x label x collected_by):")
    print("=" * 60)
    summary_table = df_out.groupby(['language', 'label', 'collected_by']).size().reset_index(name='count')
    print(summary_table.to_string(index=False))
    
    print("\nReal vs Synthetic breakdown:")
    print(pd.crosstab(df_out['is_real'], df_out['label'], margins=True))
    
    print("\nTop Feature Means by Label:")
    feat_cols = [c for c in df_out.columns if c.startswith('feat_')]
    means = df_out.groupby('label')[feat_cols[:10]].mean().T
    print(means.to_string())
    print("=" * 60)

if __name__ == "__main__":
    main()

