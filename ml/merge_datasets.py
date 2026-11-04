import os
import pandas as pd

# Run from the project root (nirbhay/):   python3 ml/merge_datasets.py

SOURCES = [
    "ml/data/processed/sms_spam_cleaned.csv",        # English, Kaggle (scam + safe)
    "ml/scam_dataset.csv",                            # Hindi/Gujarati scams, scraped
    "ml/data/processed/whatsapp_safe_cleaned.csv",    # Hindi/Gujarati safe, family WhatsApp
]
OUTPUT_FILE = "ml/data/processed/master_dataset.csv"
COLS = ["text", "language", "label", "channel", "source", "collected_by", "notes"]

# The scraper writes channel="news_article_example" as a placeholder.
# Real channel, keyed by (language, scam type as written in the notes column):
CHANNEL_FIX = {
    ("gu", "Gujarat Electricity Bill Scam (PGVCL/UGVCL Impersonation)"): "sms",
    ("gu", "Fake KYC / Bank Account Block Scam"): "sms",
    ("gu", "Lottery / Prize Scam (KBC Fraud)"): "whatsapp",
    ("gu", "Digital Arrest / Law Enforcement Impersonation"): "video_call",
    ("gu", "Fake Job / Task Scam (YouTube Like)"): "telegram",
    ("gu", "TRAI / SIM Card Disconnection Scam"): "call",
    ("gu", "Fake Stock Trading / Investment Scam"): "app",
    ("hi", "Electricity Bill Scam"): "sms",
    ("hi", "Fake KYC / Bank Account Block Scam"): "sms",
    ("hi", "Lottery / Prize Scam (KBC Fraud)"): "whatsapp",
    ("hi", "Digital Arrest / Law Enforcement Impersonation"): "video_call",
    ("hi", "Fake Job / Task Scam (YouTube Like)"): "sms",
    ("hi", "WhatsApp Bank Debit Scam (Reply NO Attack)"): "whatsapp",
    ("hi", "Credit Card Reward Points Scam"): "sms",
    ("hi", "Malicious APK / Fake Traffic Challan Scam"): "whatsapp",
}
PLACEHOLDER = "news_article_example"

# ---- LOAD ----
frames = []
for path in SOURCES:
    if not os.path.exists(path):
        print(f"WARNING: {path} not found, skipping")
        continue
    d = pd.read_csv(path, encoding="utf-8-sig")
    frames.append(d[COLS].copy())
    print(f"Loaded {len(d):>5} rows from {path}")

df = pd.concat(frames, ignore_index=True)
df["notes"] = df["notes"].fillna("")

# ---- FIX PLACEHOLDER CHANNELS ----
m = df["channel"] == PLACEHOLDER
df.loc[m, "channel"] = [
    CHANNEL_FIX.get((lang, note), PLACEHOLDER)
    for lang, note in zip(df.loc[m, "language"], df.loc[m, "notes"])
]
left = (df["channel"] == PLACEHOLDER).sum()
if left:
    print(f"WARNING: {left} rows still have channel='{PLACEHOLDER}'. Add their scam type to CHANNEL_FIX.")

# ---- DEDUPE + CHECKS ----
before = len(df)
df = df.drop_duplicates(subset="text", keep="first").reset_index(drop=True)
if before != len(df):
    print(f"Removed {before - len(df)} duplicate texts")
bad = ~df["label"].isin(["scam", "safe"])
if bad.any():
    print(f"WARNING: {bad.sum()} rows have a label other than scam/safe")
if (df["language"] == "CHECK").any():
    print(f"WARNING: {(df['language'] == 'CHECK').sum()} rows have language=CHECK (fix by hand)")

# ---- SAVE ----
df.insert(0, "id", range(1, len(df) + 1))
df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")

print(f"\nMaster dataset written to {OUTPUT_FILE}: {len(df)} rows")
print("\nLanguage x label:")
print(pd.crosstab(df["language"], df["label"]).to_string())
print("\nChannel x label:")
print(pd.crosstab(df["channel"], df["label"]).to_string())