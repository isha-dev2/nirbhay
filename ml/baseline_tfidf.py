#!/usr/bin/env python3
"""
ml/baseline_tfidf.py
Stage 4 Baseline Training & Evaluation (scikit-learn only).
Evaluates:
  - Model A: TF-IDF char n-grams (2-5, sublinear tf) + LogisticRegression(class_weight="balanced")
  - Model B: Model A + all scaled feat_ columns (signal fusion)
  - Model B (No URL): Model A + scaled feat_ columns excluding url features
  - Ablation: Training restricted to real rows only vs training on all rows (real + synthetic)
Using StratifiedGroupKFold(5, shuffle=True, random_state=42).
Produces:
  - ml/reports/oof_baseline.csv
  - ml/reports/metrics_summary.csv
  - ml/reports/baseline_report.txt
"""

import os
import time
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

INPUT_PATH = "ml/data/processed/train_ready.csv"
REPORTS_DIR = "ml/reports"
OOF_PATH = os.path.join(REPORTS_DIR, "oof_baseline.csv")
METRICS_CSV_PATH = os.path.join(REPORTS_DIR, "metrics_summary.csv")
REPORT_TXT_PATH = os.path.join(REPORTS_DIR, "baseline_report.txt")

def calculate_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    prec = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1_scam = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    return {
        "n_samples": len(y_true),
        "n_scam": int(np.sum(y_true == 1)),
        "n_safe": int(np.sum(y_true == 0)),
        "precision_scam": prec,
        "recall_scam": rec,
        "f1_scam": f1_scam,
        "macro_f1": macro_f1,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "cm": f"[[{tn},{fp}],[{fn},{tp}]]"
    }

def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_lines = []
    def log(msg: str):
        print(msg)
        report_lines.append(msg)
        
    log("=" * 80)
    log("STAGE 4 - BASELINE TF-IDF & FEATURE FUSION EVALUATION")
    log("=" * 80)
    
    log(f"Loading train-ready dataset from {INPUT_PATH}...")
    df = pd.read_csv(INPUT_PATH)
    log(f"Total rows: {len(df)}")
    
    # Feature columns
    all_feat_cols = [c for c in df.columns if c.startswith("feat_")]
    url_cols = [
        'feat_has_url', 'feat_n_urls', 'feat_url_is_ip', 'feat_url_suspicious_tld',
        'feat_url_is_shortener', 'feat_url_https', 'feat_url_length'
    ]
    non_url_feat_cols = [c for c in all_feat_cols if c not in url_cols]
    
    log(f"Total tabular features: {len(all_feat_cols)}")
    log(f"URL feature subset: {url_cols}")
    log(f"Non-URL feature subset count: {len(non_url_feat_cols)}")
    
    # Setup StratifiedGroupKFold
    # Normalize language for stratification to ensure enough samples per bin
    strat_lang = df['language'].replace({'gu-en': 'gu', 'hi-en': 'hi'})
    strat_key = strat_lang + "_" + df['label']
    groups = df['group_id']
    
    n_splits = 5
    sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
    
    # Placeholders for Out-Of-Fold predictions
    oof_pred_A = np.zeros(len(df), dtype=int)
    oof_proba_A = np.zeros(len(df), dtype=float)
    
    oof_pred_B = np.zeros(len(df), dtype=int)
    oof_proba_B = np.zeros(len(df), dtype=float)
    
    oof_pred_B_nourl = np.zeros(len(df), dtype=int)
    oof_proba_B_nourl = np.zeros(len(df), dtype=float)
    
    # Real-only ablation placeholders
    oof_pred_A_realonly = np.zeros(len(df), dtype=int)
    oof_proba_A_realonly = np.zeros(len(df), dtype=float)
    
    oof_pred_B_realonly = np.zeros(len(df), dtype=int)
    oof_proba_B_realonly = np.zeros(len(df), dtype=float)
    
    oof_pred_B_nourl_realonly = np.zeros(len(df), dtype=int)
    oof_proba_B_nourl_realonly = np.zeros(len(df), dtype=float)
    
    fold_assignments = np.zeros(len(df), dtype=int)
    
    log(f"\nStarting {n_splits}-fold StratifiedGroupKFold cross-validation...")
    start_time = time.time()
    
    for fold, (train_idx, test_idx) in enumerate(sgkf.split(df, strat_key, groups=groups)):
        fold_assignments[test_idx] = fold
        log(f"\n--- Fold {fold + 1}/{n_splits} ---")
        
        train_df = df.iloc[train_idx]
        test_df = df.iloc[test_idx]
        
        real_train_mask = train_df['is_real'].values
        real_train_idx = train_idx[real_train_mask]
        
        log(f"  Train samples: {len(train_idx)} (Real: {len(real_train_idx)}, Synthetic: {len(train_idx) - len(real_train_idx)})")
        log(f"  Test samples:  {len(test_idx)} (Real: {test_df['is_real'].sum()}, Synthetic: {(~test_df['is_real']).sum()})")
        
        # 1. Fit TF-IDF Vectorizer on train fold text_clean
        vec = TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            sublinear_tf=True,
            min_df=2
        )
        X_train_tfidf = vec.fit_transform(train_df['text_clean'])
        X_test_tfidf = vec.transform(test_df['text_clean'])
        
        # TF-IDF for real-only training
        vec_real = TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            sublinear_tf=True,
            min_df=2
        )
        X_train_tfidf_real = vec_real.fit_transform(df.iloc[real_train_idx]['text_clean'])
        X_test_tfidf_real = vec_real.transform(test_df['text_clean'])
        
        # 2. Scale tabular features
        scaler_all = StandardScaler()
        X_train_feat_all = scaler_all.fit_transform(train_df[all_feat_cols])
        X_test_feat_all = scaler_all.transform(test_df[all_feat_cols])
        
        scaler_nourl = StandardScaler()
        X_train_feat_nourl = scaler_nourl.fit_transform(train_df[non_url_feat_cols])
        X_test_feat_nourl = scaler_nourl.transform(test_df[non_url_feat_cols])
        
        # Scalers for real-only training
        scaler_all_real = StandardScaler()
        X_train_feat_all_real = scaler_all_real.fit_transform(df.iloc[real_train_idx][all_feat_cols])
        X_test_feat_all_real = scaler_all_real.transform(test_df[all_feat_cols])
        
        scaler_nourl_real = StandardScaler()
        X_train_feat_nourl_real = scaler_nourl_real.fit_transform(df.iloc[real_train_idx][non_url_feat_cols])
        X_test_feat_nourl_real = scaler_nourl_real.transform(test_df[non_url_feat_cols])
        
        # Combine matrices
        X_train_B = hstack([X_train_tfidf, csr_matrix(X_train_feat_all)])
        X_test_B = hstack([X_test_tfidf, csr_matrix(X_test_feat_all)])
        
        X_train_B_nourl = hstack([X_train_tfidf, csr_matrix(X_train_feat_nourl)])
        X_test_B_nourl = hstack([X_test_tfidf, csr_matrix(X_test_feat_nourl)])
        
        X_train_B_real = hstack([X_train_tfidf_real, csr_matrix(X_train_feat_all_real)])
        X_test_B_real = hstack([X_test_tfidf_real, csr_matrix(X_test_feat_all_real)])
        
        X_train_B_nourl_real = hstack([X_train_tfidf_real, csr_matrix(X_train_feat_nourl_real)])
        X_test_B_nourl_real = hstack([X_test_tfidf_real, csr_matrix(X_test_feat_nourl_real)])
        
        y_train = train_df['y'].values
        y_train_real = df.iloc[real_train_idx]['y'].values
        
        # Model A: TF-IDF only (All train data)
        clf_A = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_A.fit(X_train_tfidf, y_train)
        oof_proba_A[test_idx] = clf_A.predict_proba(X_test_tfidf)[:, 1]
        oof_pred_A[test_idx] = (oof_proba_A[test_idx] >= 0.5).astype(int)
        
        # Model B: Signal Fusion (All train data, all features)
        clf_B = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_B.fit(X_train_B, y_train)
        oof_proba_B[test_idx] = clf_B.predict_proba(X_test_B)[:, 1]
        oof_pred_B[test_idx] = (oof_proba_B[test_idx] >= 0.5).astype(int)
        
        # Model B (No URL): Signal Fusion without URL features (All train data)
        clf_B_nourl = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_B_nourl.fit(X_train_B_nourl, y_train)
        oof_proba_B_nourl[test_idx] = clf_B_nourl.predict_proba(X_test_B_nourl)[:, 1]
        oof_pred_B_nourl[test_idx] = (oof_proba_B_nourl[test_idx] >= 0.5).astype(int)
        
        # Ablation: Train restricted to REAL rows only
        # Model A (Real Only)
        clf_A_real = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_A_real.fit(X_train_tfidf_real, y_train_real)
        oof_proba_A_realonly[test_idx] = clf_A_real.predict_proba(X_test_tfidf_real)[:, 1]
        oof_pred_A_realonly[test_idx] = (oof_proba_A_realonly[test_idx] >= 0.5).astype(int)
        
        # Model B (Real Only)
        clf_B_real = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_B_real.fit(X_train_B_real, y_train_real)
        oof_proba_B_realonly[test_idx] = clf_B_real.predict_proba(X_test_B_real)[:, 1]
        oof_pred_B_realonly[test_idx] = (oof_proba_B_realonly[test_idx] >= 0.5).astype(int)
        
        # Model B (No URL, Real Only)
        clf_B_nourl_real = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        clf_B_nourl_real.fit(X_train_B_nourl_real, y_train_real)
        oof_proba_B_nourl_realonly[test_idx] = clf_B_nourl_real.predict_proba(X_test_B_nourl_real)[:, 1]
        oof_pred_B_nourl_realonly[test_idx] = (oof_proba_B_nourl_realonly[test_idx] >= 0.5).astype(int)
        
    elapsed = time.time() - start_time
    log(f"\nCross-validation complete in {elapsed:.2f}s.")
    
    # Save Out-Of-Fold predictions
    log(f"\nSaving Out-Of-Fold predictions to {OOF_PATH}...")
    df_oof = df[['id', 'text', 'language', 'label', 'y', 'is_real', 'group_id', 'source', 'collected_by']].copy()
    df_oof['fold'] = fold_assignments
    
    # Model predictions
    df_oof['pred_A'] = oof_pred_A
    df_oof['proba_A'] = np.round(oof_proba_A, 4)
    df_oof['pred_B'] = oof_pred_B
    df_oof['proba_B'] = np.round(oof_proba_B, 4)
    df_oof['pred_B_no_url'] = oof_pred_B_nourl
    df_oof['proba_B_no_url'] = np.round(oof_proba_B_nourl, 4)
    
    # Real-only ablation predictions
    df_oof['pred_A_real_only'] = oof_pred_A_realonly
    df_oof['proba_A_real_only'] = np.round(oof_proba_A_realonly, 4)
    df_oof['pred_B_real_only'] = oof_pred_B_realonly
    df_oof['proba_B_real_only'] = np.round(oof_proba_B_realonly, 4)
    df_oof['pred_B_no_url_real_only'] = oof_pred_B_nourl_realonly
    df_oof['proba_B_no_url_real_only'] = np.round(oof_proba_B_nourl_realonly, 4)
    
    df_oof.to_csv(OOF_PATH, index=False, encoding="utf-8-sig")
    log(f"Saved {len(df_oof)} rows to {OOF_PATH}.")
    
    # -------------------------------------------------------------
    # Evaluate & Report Metrics
    # -------------------------------------------------------------
    models = {
        "Model A (TF-IDF char 2-5) [Train: All]": ("pred_A", "proba_A"),
        "Model B (TF-IDF + All Feat) [Train: All]": ("pred_B", "proba_B"),
        "Model B (TF-IDF + Feat No-URL) [Train: All]": ("pred_B_no_url", "proba_B_no_url"),
        "Ablation: Model A [Train: Real Only]": ("pred_A_real_only", "proba_A_real_only"),
        "Ablation: Model B [Train: Real Only]": ("pred_B_real_only", "proba_B_real_only"),
        "Ablation: Model B (No-URL) [Train: Real Only]": ("pred_B_no_url_real_only", "proba_B_no_url_real_only"),
    }
    
    # Evaluation subsets
    # Map gu-en -> gu, hi-en -> hi for language reporting
    eval_lang = df_oof['language'].replace({'gu-en': 'gu', 'hi-en': 'hi'})
    
    slices = [
        ("Real - Overall", df_oof['is_real']),
        ("Real - English (en)", df_oof['is_real'] & (eval_lang == 'en')),
        ("Real - Gujarati (gu)", df_oof['is_real'] & (eval_lang == 'gu')),
        ("Real - Hindi (hi)", df_oof['is_real'] & (eval_lang == 'hi')),
        ("Synthetic - Overall", ~df_oof['is_real']),
        ("Synthetic - English (en)", (~df_oof['is_real']) & (eval_lang == 'en')),
        ("Synthetic - Gujarati (gu)", (~df_oof['is_real']) & (eval_lang == 'gu')),
        ("Synthetic - Hindi (hi)", (~df_oof['is_real']) & (eval_lang == 'hi')),
    ]
    
    metrics_records = []
    
    for model_name, (pred_col, proba_col) in models.items():
        log("\n" + "=" * 80)
        log(f"EVALUATION: {model_name}")
        log("=" * 80)
        
        for slice_name, mask in slices:
            sub = df_oof[mask]
            if len(sub) == 0:
                continue
            m = calculate_metrics(sub['y'].values, sub[pred_col].values)
            m["model"] = model_name
            m["slice"] = slice_name
            metrics_records.append(m)
            
            # Print row
            log(f"{slice_name:<28} | N={m['n_samples']:<4} (Scam={m['n_scam']:<3}, Safe={m['n_safe']:<4}) | "
                f"Prec={m['precision_scam']:.4f} | Rec={m['recall_scam']:.4f} | "
                f"F1={m['f1_scam']:.4f} | MacroF1={m['macro_f1']:.4f} | CM={m['cm']}")
                
    df_metrics = pd.DataFrame(metrics_records)
    
    # Reorder columns
    m_cols = [
        "model", "slice", "n_samples", "n_scam", "n_safe",
        "precision_scam", "recall_scam", "f1_scam", "macro_f1", "tn", "fp", "fn", "tp", "cm"
    ]
    df_metrics = df_metrics[m_cols]
    df_metrics.to_csv(METRICS_CSV_PATH, index=False)
    log(f"\nMetrics table saved to {METRICS_CSV_PATH}")
    
    # -------------------------------------------------------------
    # Detailed Comparison Tables
    # -------------------------------------------------------------
    log("\n" + "=" * 80)
    log("SUMMARY COMPARISON ON REAL TEST ROWS (is_real == True)")
    log("=" * 80)
    
    real_summary = df_metrics[df_metrics['slice'].str.startswith("Real")].copy()
    piv_f1 = real_summary.pivot(index="model", columns="slice", values="f1_scam")
    piv_macro = real_summary.pivot(index="model", columns="slice", values="macro_f1")
    
    log("\n[Scam F1 Score on Real Data]:")
    log(piv_f1.to_string())
    
    log("\n[Macro F1 Score on Real Data]:")
    log(piv_macro.to_string())
    
    log("\n" + "=" * 80)
    log("SUMMARY COMPARISON ON SYNTHETIC TEST ROWS (is_real == False)")
    log("=" * 80)
    synth_summary = df_metrics[df_metrics['slice'].str.startswith("Synthetic")].copy()
    piv_synth_f1 = synth_summary.pivot(index="model", columns="slice", values="f1_scam")
    log(piv_synth_f1.to_string())
    
    # Write full report to file
    with open(REPORT_TXT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines) + "\n")
    log(f"\nFull report written to {REPORT_TXT_PATH}")

if __name__ == "__main__":
    main()

