"""
Fine-tune MuRIL for scam vs safe on train_ready.csv (English + Hindi + Gujarati).

* 5-fold StratifiedGroupKFold, grouped by group_id (near-duplicate templates never straddle a split).
* Trains on real + synthetic rows, but REPORTS ONLY on real rows (is_real == True), per language,
  as raw counts (TP/FN/FP/TN) with a 95% interval on scam recall. With only a handful of real
  Hindi/Gujarati scam messages, F1 alone is misleading.
* The 5,000+ machine-translated Hindi rows from Hugging Face are EXCLUDED by default: they are
  translations of the English Kaggle messages (so they leak across languages) and would make up
  two thirds of the data. Use --hf-cap N to include a balanced sample of N of them.

Colab: Runtime > Change runtime type > T4 GPU, upload this file + train_ready.csv, then
    !pip -q install transformers scikit-learn
    !python train_muril.py --dry-run                 # shows the folds only
    !python train_muril.py                           # main run
    !python train_muril.py --real-only               # ablation: do synthetic rows help?
    !python train_muril.py --no-synth-en             # ablation: drop synthetic English
    !python train_muril.py --hf-cap 800              # include 800 translated Hindi rows
    !python train_muril.py --final                   # also train on everything and save ./muril_scam_model
"""
import argparse
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

ap = argparse.ArgumentParser()
ap.add_argument("--data", default="train_ready.csv")
ap.add_argument("--model", default="google/muril-base-cased")   # alternative: xlm-roberta-base
ap.add_argument("--epochs", type=int, default=4)
ap.add_argument("--hf-cap", type=int, default=0, help="max machine-translated HF Hindi rows to keep (default 0 = none)")
ap.add_argument("--no-synth-en", action="store_true", help="drop synthetic English rows")
ap.add_argument("--real-only", action="store_true", help="drop ALL synthetic rows (ablation)")
ap.add_argument("--dry-run", action="store_true")
ap.add_argument("--final", action="store_true")
args = ap.parse_args()

MAX_LEN, BATCH, LR, FOLDS, SEED = 128, 16, 3e-5, 5, 42

# ---------- data ----------
df = pd.read_csv(args.data, encoding="utf-8-sig")
df = df[df["language"].isin(["en", "hi", "gu"]) & df["label"].isin(["scam", "safe"])].copy()
df["is_real"] = df["is_real"].astype(str).str.lower().isin(["1", "true", "1.0"])
df["y"] = (df["label"] == "scam").astype(int)
df["text_clean"] = df["text_clean"].fillna(df["text"]).astype(str)
is_hf = df["source"].astype(str).str.startswith("HF")

drop = pd.Series(False, index=df.index)
if args.real_only:
    drop |= ~df["is_real"]
if args.no_synth_en:
    drop |= (df["language"] == "en") & ~df["is_real"]
# machine-translated Hindi: none by default, or a label-balanced sample of N
hf_idx = df.index[is_hf & ~drop]
keep_hf = []
if args.hf_cap > 0 and not args.real_only:
    for lab in (0, 1):
        pool = df.loc[hf_idx][df.loc[hf_idx, "y"] == lab].index
        keep_hf += list(pd.Series(pool).sample(min(len(pool), args.hf_cap // 2), random_state=SEED))
drop |= is_hf & ~df.index.isin(keep_hf)
df = df[~drop].reset_index(drop=True)

groups = df["group_id"].astype(str).astype("category").cat.codes
strata = df["language"] + "_" + df["label"] + "_" + np.where(df["is_real"], "real", "synth")
splits = list(StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED).split(df, strata, groups))

print(f"{len(df)} rows used | real={int(df['is_real'].sum())} synthetic={int((~df['is_real']).sum())}")
print("rows by language x label x real:\n" + df.groupby(["language", "label", "is_real"]).size().to_string())
for i, (tr, te) in enumerate(splits, 1):
    te_real = df.iloc[te][df.iloc[te]["is_real"]]
    print(f"fold {i}: train={len(tr)} test={len(te)} | REAL test rows by language_label: "
          f"{(te_real['language'] + '_' + te_real['label']).value_counts().to_dict()}")
if args.dry_run:
    sys.exit(0)

# ---------- model code (heavy imports only after the dry-run check) ----------
import random
import torch
from torch.utils.data import DataLoader, TensorDataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup

device = "cuda" if torch.cuda.is_available() else "cpu"
if device == "cpu":
    print("WARNING: no GPU found. Training will be very slow. In Colab: Runtime > Change runtime type > T4 GPU")
tok = AutoTokenizer.from_pretrained(args.model)


def seed_all(s):
    random.seed(s); np.random.seed(s); torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)


def loader(texts, labels, shuffle):
    enc = tok(list(texts), truncation=True, padding=True, max_length=MAX_LEN, return_tensors="pt")
    ds = TensorDataset(enc["input_ids"], enc["attention_mask"], torch.tensor(list(labels)))
    return DataLoader(ds, batch_size=BATCH, shuffle=shuffle)


def train(texts, labels):
    seed_all(SEED)
    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2).to(device)
    dl = loader(texts, labels, shuffle=True)
    opt = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total = args.epochs * len(dl)
    sched = get_linear_schedule_with_warmup(opt, int(0.1 * total), total)
    model.train()
    for ep in range(args.epochs):
        running = 0.0
        for ids, mask, y in dl:
            out = model(input_ids=ids.to(device), attention_mask=mask.to(device), labels=y.to(device))
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad()
            running += out.loss.item()
        print(f"   epoch {ep + 1}/{args.epochs} loss {running / len(dl):.4f}")
    return model


@torch.no_grad()
def predict(model, texts):
    model.eval()
    preds = []
    for ids, mask, _ in loader(texts, [0] * len(texts), shuffle=False):
        logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
        preds += logits.argmax(-1).cpu().tolist()
    return preds


# ---------- cross-validation ----------
df["pred"] = -1
for i, (tr, te) in enumerate(splits, 1):
    print(f"\n--- fold {i}/{FOLDS} ---")
    model = train(df.loc[tr, "text_clean"], df.loc[tr, "y"])
    df.loc[te, "pred"] = predict(model, df.loc[te, "text_clean"])
    del model
    if device == "cuda":
        torch.cuda.empty_cache()


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (c - h) / d, (c + h) / d


def summarize(sub, name):
    y, p = sub["y"].values, sub["pred"].values
    tp = int(((y == 1) & (p == 1)).sum()); fn = int(((y == 1) & (p == 0)).sum())
    fp = int(((y == 0) & (p == 1)).sum()); tn = int(((y == 0) & (p == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec == prec and rec == rec and prec + rec > 0) else float("nan")
    lo, hi = wilson(tp, tp + fn)
    print(f"{name:<9} rows={len(sub):>5} scam={tp + fn:>4} | TP={tp:>4} FN={fn:>4} FP={fp:>4} TN={tn:>4} | "
          f"scam precision={prec:.3f}  recall={rec:.3f} (95% CI {lo:.2f}-{hi:.2f})  F1={f1:.3f}")


real = df[df["is_real"]]
print("\n=== REAL messages only, out-of-fold ===")
print(f"settings: hf_cap={args.hf_cap} no_synth_en={args.no_synth_en} real_only={args.real_only} model={args.model}")
for lang in ["en", "hi", "gu"]:
    summarize(real[real["language"] == lang], lang)
summarize(real, "ALL real")
print("\nHow to read this: 'scam' is the number of real scam messages in that language. If it is under ~30, the "
      "F1 and the recall move a lot with one message; use the confidence interval, not the headline number. "
      "The English figure is partly easy: its safe messages are Indian phone SMS while its scams are UK Kaggle SMS.")
print("\n=== SYNTHETIC messages (sanity check only, not evidence of real-world accuracy) ===")
syn = df[~df["is_real"]]
for lang in ["en", "hi", "gu"]:
    if (syn["language"] == lang).any():
        summarize(syn[syn["language"] == lang], lang)

df[["id", "text", "language", "label", "is_real", "pred"]].assign(pred=df["pred"].map({0: "safe", 1: "scam"})).to_csv(
    "oof_predictions.csv", index=False, encoding="utf-8-sig")
print("\nWrote oof_predictions.csv. Open the wrong REAL rows and look at what the model misses.")

# ---------- optional: final model on all used rows ----------
if args.final:
    print("\n--- training final model on all used rows ---")
    model = train(df["text_clean"], df["y"])
    model.save_pretrained("muril_scam_model")
    tok.save_pretrained("muril_scam_model")
    print("Saved ./muril_scam_model  (zip it and download it, or copy it to Google Drive)")