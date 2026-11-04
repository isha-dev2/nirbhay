#!/usr/bin/env python3
"""
ml/ingest_extra_sources.py
Ingestion script for extra sources into Nirbhay dataset (Stage 1).
Produces:
  - ml/data/raw/hf_hi_gu_extract.csv
  - ml/data/processed/master_v2.csv
  - ml/data/processed/needs_manual_review.csv
  - ml/data/processed/ingest_report.txt
"""

import os
import re
import unicodedata

# Set HF to use local cache if offline BEFORE importing datasets
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"

import pandas as pd
import datasets

MASTER_V1_PATH = "ml/data/processed/master_dataset.csv"
PARI_PATH = "ml/data/raw/multilingual_phishing_dataset_pari.csv"
PRIYA_PATH = "ml/data/raw/sms_spam_cleaned_priya.xlsx"

HF_EXTRACT_PATH = "ml/data/raw/hf_hi_gu_extract.csv"
MASTER_V2_PATH = "ml/data/processed/master_v2.csv"
REVIEW_QUEUE_PATH = "ml/data/processed/needs_manual_review.csv"
REPORT_PATH = "ml/data/processed/ingest_report.txt"

COLS = ["id", "text", "language", "label", "channel", "source", "collected_by", "notes"]

GENERIC_SALUTATIONS = {
    'customer', 'user', 'member', 'cardholder', 'patron', 'all', 'there',
    'sir', 'madam', 'team', 'candidate', 'consumer', 'resident', 'citizen',
    'investor', 'subscriber', 'applicant', 'student', 'parent', 'doctor',
    'merchant', 'partner', 'friend', 'colleague', 'folks'
}

def mask_pii(text: str) -> str:
    """
    Mask personal data BEFORE writing any output:
      - phone numbers -> <PHONE>
      - emails -> <EMAIL>
      - card/account fragments and OTP/PIN codes -> <NUM>
      - person names in greetings like 'Dear Priya,' -> <NAME>
    Preserves URLs so stage 3 URL feature engineering can parse domains/TLDs/IPs.
    """
    if not isinstance(text, str):
        return ""
    
    # 1. Protect URLs temporarily
    urls = []
    def save_url(m):
        urls.append(m.group(0))
        return f"__URL_TOKEN_{len(urls)-1}__"
    
    url_pattern = r'(?:https?://|www\.)[^\s<>\"\'\)]+'
    text = re.sub(url_pattern, save_url, text)
    
    # 2. Mask emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    text = re.sub(email_pattern, '<EMAIL>', text)
    
    # 3. Person names in greetings
    def greeting_replacer(m):
        salutation = m.group(1)
        name = m.group(2)
        punct = m.group(3) or ''
        first_word = name.split()[0].lower()
        if first_word in GENERIC_SALUTATIONS:
            return m.group(0)
        return f"{salutation} <NAME>{punct}"
    
    greeting_pattern = r'\b(Dear|Hi|Hello|Namaste|Namaskar)\s+([A-Za-z]+(?:\s+[A-Za-z]+)?)([,.!:]?)'
    text = re.sub(greeting_pattern, greeting_replacer, text, flags=re.IGNORECASE)
    
    # 4. OTP and PIN codes
    otp_pattern = r'(?i)\b(?:otp|one[-\s]time[-\s]password|pin|code|secret\s+code|passcode|verification\s+code)\s*(?:is|for|of|:|-|=|\.|\b)*\s*([0-9]{4,8})\b'
    text = re.sub(otp_pattern, lambda m: m.group(0).replace(m.group(1), '<NUM>'), text)
    
    rev_otp_pattern = r'\b(\d{4,8})\s+(is\s+(?:your\s+)?(?:otp|pin|secret\s+code|verification\s+code))\b'
    text = re.sub(rev_otp_pattern, r'<NUM> \2', text, flags=re.IGNORECASE)
    
    # 5. Account and card fragments
    acct_pattern = r'(?i)\b(?:a/c|acct|acc|account|card)\s*(?:no\.?|number)?\s*(?:ending\s+(?:with|in)?|is)?\s*[:.-]?\s*([xX*.]*\d{3,6})\b'
    text = re.sub(acct_pattern, lambda m: m.group(0).replace(m.group(1), '<NUM>'), text)
    text = re.sub(r'\b[xX*]{2,}\d{2,6}\b', '<NUM>', text)
    
    # 6. Phone numbers (Indian mobile, international +91, landline, toll-free 1800, UK Kaggle formats)
    phone_pattern = r'(?:(?:\+|00)?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|1800[\s-]?\d{3}[\s-]?\d{3,4}\b|\b0\d{2,4}[\s-]?\d{6,8}\b|\b(?:\+?\d{1,3}[\s-]?)?\(?\d{3,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
    def phone_replacer(m):
        raw = m.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) >= 10:
            return '<PHONE>'
        return raw
    text = re.sub(phone_pattern, phone_replacer, text)
    
    # 7. Restore protected URLs
    for idx, u in enumerate(urls):
        text = text.replace(f"__URL_TOKEN_{idx}__", u)
        
    return text

def count_scripts(text: str):
    """Count Gujarati, Latin, and Devanagari alphabetic characters."""
    g = sum(1 for c in text if 'GUJARATI' in unicodedata.name(c, ''))
    l = sum(1 for c in text if 'LATIN' in unicodedata.name(c, ''))
    d = sum(1 for c in text if 'DEVANAGARI' in unicodedata.name(c, ''))
    return g, l, d

def devanagari_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    dev = [c for c in letters if 'DEVANAGARI' in unicodedata.name(c, '')]
    return len(dev) / len(letters)

def make_template_key(text: str) -> str:
    """Template key: lowercase, digits removed, links/phones masked, first 60 characters."""
    t = str(text).lower()
    t = re.sub(r'https?://\S+|www\.\S+', '<link>', t)
    t = re.sub(r'(\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}', '<phone>', t)
    t = re.sub(r'\d+', '', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t[:60]

def main():
    report_lines = []
    def log(msg: str):
        print(msg)
        report_lines.append(msg)
    
    log("=" * 60)
    log("STAGE 1 - INGESTION OF EXTRA SOURCES REPORT")
    log("=" * 60)
    
    # -------------------------------------------------------------
    # 1. Existing Master Dataset
    # -------------------------------------------------------------
    log(f"\n[1] Loading existing master dataset from {MASTER_V1_PATH}...")
    df_master = pd.read_csv(MASTER_V1_PATH)
    log(f"    Master v1 loaded: {len(df_master)} rows")
    master_texts = set(df_master['text'].dropna())
    
    # -------------------------------------------------------------
    # 2. Source (c): Hugging Face Multilingual Dataset
    # -------------------------------------------------------------
    log("\n[2] Ingesting source (c): Hugging Face dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset...")
    ds = datasets.load_dataset('dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset', split='train')
    log(f"    Total rows in HF dataset: {len(ds)}")
    
    # Check Gujarati presence
    cols = ds.column_names
    log(f"    Available text columns in HF dataset: {[c for c in cols if c.startswith('text')]}")
    log("    Gujarati language check: No 'text_gu' or Gujarati column exists in this dataset.")
    
    hf_extracted_rows = []
    for row in ds:
        t_hi = row.get('text_hi')
        if t_hi and devanagari_ratio(t_hi) >= 0.5:
            label = "safe" if row['labels'] == 'ham' else "scam"
            hf_extracted_rows.append({
                "text": t_hi,
                "language": "hi",
                "label": label,
                "channel": "sms",
                "source": "HF dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset",
                "collected_by": "synthetic",
                "notes": "machine-translated; UK-style SMS content"
            })
    
    df_hf = pd.DataFrame(hf_extracted_rows)
    log(f"    Extracted Hindi rows with >=50% Devanagari script: {len(df_hf)}")
    log(f"    HF label breakdown:\n{df_hf['label'].value_counts().to_string()}")
    
    # Save raw extract to ml/data/raw/hf_hi_gu_extract.csv
    df_hf_to_save = df_hf.copy()
    df_hf_to_save.insert(0, "id", range(1, len(df_hf_to_save) + 1))
    df_hf_to_save.to_csv(HF_EXTRACT_PATH, index=False, encoding="utf-8-sig")
    log(f"    Saved raw HF extract to {HF_EXTRACT_PATH}")
    
    # -------------------------------------------------------------
    # 3. Source (a): Pari Multilingual Phishing Dataset
    # -------------------------------------------------------------
    log(f"\n[3] Ingesting source (a): Pari dataset from {PARI_PATH}...")
    df_pari = pd.read_csv(PARI_PATH)
    log(f"    Pari dataset loaded: {len(df_pari)} rows")
    # Columns: id, text, url, language, label, category
    # Drop url
    df_pari = df_pari.drop(columns=['url'], errors='ignore')
    # Map label 1->scam, 0->safe
    df_pari['label'] = df_pari['label'].map({1: 'scam', 0: 'safe'})
    df_pari['channel'] = 'sms'
    df_pari['source'] = 'Pari multilingual phishing dataset (template-generated)'
    df_pari['collected_by'] = 'synthetic'
    df_pari['notes'] = df_pari['category'].fillna('')
    df_pari = df_pari[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']]
    log(f"    Pari processed: {len(df_pari)} rows (en: {(df_pari['language']=='en').sum()}, gu: {(df_pari['language']=='gu').sum()}, hi: {(df_pari['language']=='hi').sum()})")
    
    # -------------------------------------------------------------
    # 4. Source (b): Priya SMS Spam Cleaned Dataset
    # -------------------------------------------------------------
    log(f"\n[4] Ingesting source (b): Priya dataset from {PRIYA_PATH}...")
    df_priya = pd.read_excel(PRIYA_PATH, sheet_name="sms_spam_cleaned.csv")
    log(f"    Priya raw rows loaded: {len(df_priya)}")
    
    # Drop blank row
    df_priya = df_priya.dropna(subset=['text'])
    df_priya = df_priya[df_priya['text'].astype(str).str.strip() != '']
    log(f"    Rows after dropping blank rows: {len(df_priya)}")
    
    # Drop UCI Kaggle 800 rows (already represented in master)
    kaggle_mask = df_priya['source'] == "UCI SMS Spam Collection (Kaggle)"
    df_priya = df_priya[~kaggle_mask]
    log(f"    Rows after dropping Kaggle 800 rows: {len(df_priya)} (phone SMS remaining)")
    
    # Drop rows whose text already exists in master
    master_dup_mask = df_priya['text'].isin(master_texts)
    dropped_master_dups = master_dup_mask.sum()
    df_priya = df_priya[~master_dup_mask]
    log(f"    Rows after dropping texts already present in master: {len(df_priya)} (dropped {dropped_master_dups})")
    
    # Mask personal data on real phone SMS
    log("    Applying PII masking (<PHONE>, <EMAIL>, <NUM>, <NAME>) to phone SMS...")
    df_priya['text'] = df_priya['text'].apply(mask_pii)
    
    # Normalize language: gu-en/hi-en
    norm_langs = []
    norm_notes = []
    for _, r in df_priya.iterrows():
        l_code = r['language']
        note_str = str(r['notes']) if pd.notna(r['notes']) else ""
        g, l, d = count_scripts(str(r['text']))
        
        if l_code == 'gu-en':
            if g > l:
                l_code = 'gu'
            else:
                l_code = 'gu-en'
                note_str = (note_str + "; romanized-check").strip("; ")
        elif l_code == 'hi-en':
            if d > l:
                l_code = 'hi'
            else:
                l_code = 'hi-en'
                note_str = (note_str + "; romanized-check").strip("; ")
                
        norm_langs.append(l_code)
        norm_notes.append(note_str)
        
    df_priya['language'] = norm_langs
    df_priya['notes'] = norm_notes
    log(f"    Normalized language distribution in phone SMS:\n{df_priya['language'].value_counts().to_string()}")
    
    # Separate auto-SCAM into needs_manual_review.csv
    scam_mask = df_priya['label'] == 'scam'
    df_review = df_priya[scam_mask].copy()
    df_safe = df_priya[~scam_mask].copy()
    
    log(f"    Auto-SCAM rows isolated for manual review: {len(df_review)}")
    log(f"    Auto-SAFE rows candidate for ingestion: {len(df_safe)}")
    
    # Save review queue
    df_review_out = df_review[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']].copy()
    df_review_out.insert(0, "id", range(1, len(df_review_out) + 1))
    df_review_out.to_csv(REVIEW_QUEUE_PATH, index=False, encoding="utf-8-sig")
    log(f"    Saved {len(df_review_out)} rows to review queue: {REVIEW_QUEUE_PATH}")
    
    # Format auto-SAFE notes
    df_safe['notes'] = df_safe['notes'].apply(
        lambda n: "auto-label, unverified; romanized-check" if "romanized-check" in n else "auto-label, unverified"
    )
    
    # Real phone SMS template deduplication (keep at most 5 per template)
    df_safe['template_key'] = df_safe['text'].apply(make_template_key)
    unique_safe_templates = df_safe['template_key'].nunique()
    df_safe_capped = df_safe.groupby('template_key', group_keys=False).apply(lambda g: g.head(5)).copy()
    log(f"    Unique safe templates: {unique_safe_templates}. Kept at most 5 per template: {len(df_safe_capped)} rows (from {len(df_safe)})")
    
    # -------------------------------------------------------------
    # 5. Combine and Deduplicate Across Everything
    # -------------------------------------------------------------
    log("\n[5] Combining all sources and performing global deduplication...")
    
    df_master_clean = df_master[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']].copy()
    df_safe_capped_clean = df_safe_capped[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']].copy()
    df_pari_clean = df_pari[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']].copy()
    df_hf_clean = df_hf[['text', 'language', 'label', 'channel', 'source', 'collected_by', 'notes']].copy()
    
    all_combined = pd.concat([
        df_master_clean,
        df_safe_capped_clean,
        df_pari_clean,
        df_hf_clean
    ], ignore_index=True)
    
    log(f"    Total rows combined before global deduplication: {len(all_combined)}")
    
    # Priority sorting: Real + Hand-labelled (4) > Real + Auto-labelled (3) > Dataset + Hand-labelled (2) > Synthetic (1)
    def dedupe_priority(row):
        cb = str(row['collected_by'])
        if cb in ['isha', 'scraper']:
            return 4
        elif cb == 'user_consented_device':
            return 3
        elif cb == 'dataset':
            return 2
        else:
            return 1
            
    all_combined['priority'] = all_combined.apply(dedupe_priority, axis=1)
    all_combined = all_combined.sort_values(by='priority', ascending=False)
    
    before_dedupe = len(all_combined)
    df_final = all_combined.drop_duplicates(subset=['text'], keep='first').copy()
    log(f"    Exact-duplicate texts dropped: {before_dedupe - len(df_final)}")
    log(f"    Final master_v2 total rows: {len(df_final)}")
    
    # Assign sequential IDs
    df_final = df_final.sort_index().reset_index(drop=True)
    df_final.insert(0, "id", range(1, len(df_final) + 1))
    df_final = df_final[COLS]
    
    # Write master_v2.csv
    df_final.to_csv(MASTER_V2_PATH, index=False, encoding="utf-8-sig")
    log(f"    Written final master dataset to {MASTER_V2_PATH}")
    
    # -------------------------------------------------------------
    # 6. Summary Breakdown Report
    # -------------------------------------------------------------
    log("\n" + "=" * 60)
    log("STAGE 1 SUMMARY COUNTS (language x label x collected_by):")
    log("=" * 60)
    summary_table = df_final.groupby(['language', 'label', 'collected_by']).size().reset_index(name='count')
    log(summary_table.to_string(index=False))
    
    log("\nLanguage totals:")
    log(df_final['language'].value_counts().to_string())
    
    log("\nLabel totals:")
    log(df_final['label'].value_counts().to_string())
    
    log("\nCollected_by totals:")
    log(df_final['collected_by'].value_counts().to_string())
    log("=" * 60)
    
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")
    log(f"\nReport written to {REPORT_PATH}")

if __name__ == "__main__":
    main()
