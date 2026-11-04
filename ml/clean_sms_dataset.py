import pandas as pd
import random

# ---- CONFIG ----
INPUT_FILE = "data/raw/spam.csv"
OUTPUT_FILE = "data/processed/sms_spam_cleaned.csv"
SAMPLE_SIZE_PER_LABEL = 400       # set to None to keep everything instead of sampling
RANDOM_SEED = 42

# ---- LOAD ----
df = pd.read_csv(INPUT_FILE, encoding="latin-1")
df = df[["v1", "v2"]].rename(columns={"v1": "label", "v2": "text"})
df = df.dropna(subset=["text"])
df = df[df["text"].str.strip() != ""]
df = df.drop_duplicates(subset="text")
df["label"] = df["label"].map({"spam": "scam", "ham": "safe"})

# ---- OPTIONAL SAMPLING ----
if SAMPLE_SIZE_PER_LABEL:
    random.seed(RANDOM_SEED)
    parts = []
    for lbl in ["scam", "safe"]:
        subset = df[df["label"] == lbl]
        n = min(SAMPLE_SIZE_PER_LABEL, len(subset))
        parts.append(subset.sample(n=n, random_state=RANDOM_SEED))
    df = pd.concat(parts, ignore_index=True)

# ---- ADD REQUIRED COLUMNS ----
df["language"] = "en"
df["channel"] = "sms"
df["source"] = "UCI SMS Spam Collection (Kaggle)"
df["collected_by"] = "dataset"
df["notes"] = ""
df.insert(0, "id", range(1, len(df) + 1))
df = df[["id", "text", "language", "label", "channel", "source", "collected_by", "notes"]]

# ---- SAVE ----
df.to_csv(OUTPUT_FILE, index=False)
print(f"Done. {len(df)} rows written to {OUTPUT_FILE}")
print(df["label"].value_counts())
