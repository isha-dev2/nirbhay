"""
Model Training and Rigorous Multilingual Evaluation Pipeline for Nirbhay
Addresses:
1. Multilingual Classifier (English, Hindi, Gujarati) with Character & Word N-Grams
2. Structural URL Analysis (25+ Lexical & Domain Features)
3. Multi-Evidence Integration & Late Fusion Layer
4. Per-Language Evaluation (Precision, Recall, F1, False Positive Rate - FPR)
5. Ablation Study: Text-Only vs URL-Only vs Multi-Evidence Fusion
"""
import json
import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from ml.feature_extractor import extract_url_features

FEATURE_COLUMNS = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_questionmarks", "num_equal", "num_at",
    "num_ampersand", "num_percent", "num_digits", "digit_ratio", "is_https",
    "is_ip", "num_subdomains", "domain_entropy", "has_suspicious_tld",
    "num_sensitive_words", "has_brand_spoof", "brand_spoof_count",
    "is_shortened", "has_port", "url_entropy"
]

def calculate_metrics(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "sample_count": len(y_true)
    }

def train_and_evaluate(data_path="data/multilingual_phishing_dataset.csv", output_dir="models"):
    print("=" * 70)
    print("NIRBHAY ML PIPELINE: TRAINING & RIGOROUS EVALUATION")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_csv(data_path)
    print(f"Loaded dataset from {data_path} with {len(df)} records.")

    # Stratify by language and label
    df["strat_key"] = df["language"] + "_" + df["label"].astype(str)
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["strat_key"]
    )
    print(f"Train split: {len(train_df)} samples | Test split: {len(test_df)} samples.")

    # -------------------------------------------------------------
    # 1. TEXT NLP MODEL: WORD + CHAR N-GRAM FEATURE UNION
    # -------------------------------------------------------------
    print("\n--- 1. Training Multilingual Text Classifier (Word + Char N-Grams) ---")
    word_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        analyzer='word',
        max_features=6000,
        sublinear_tf=True
    )
    char_vectorizer = TfidfVectorizer(
        ngram_range=(3, 5),
        analyzer='char',
        max_features=6000,
        sublinear_tf=True
    )
    text_features = FeatureUnion([
        ("word_ngram", word_vectorizer),
        ("char_ngram", char_vectorizer)
    ])

    base_svc = LinearSVC(class_weight='balanced', random_state=42, C=1.0)
    calibrated_svc = CalibratedClassifierCV(estimator=base_svc, cv=3)

    text_pipeline = Pipeline([
        ("features", text_features),
        ("classifier", calibrated_svc)
    ])

    X_train_text = train_df["text"].fillna("")
    y_train = train_df["label"].values
    text_pipeline.fit(X_train_text, y_train)

    # -------------------------------------------------------------
    # 2. URL ENGINE: 25+ STRUCTURAL & LEXICAL FEATURES + RANDOM FOREST
    # -------------------------------------------------------------
    print("\n--- 2. Training Structural URL Classifier (Random Forest) ---")
    def build_url_feature_matrix(url_series):
        rows = [extract_url_features(str(u)) for u in url_series]
        return pd.DataFrame(rows)[FEATURE_COLUMNS].values

    X_train_url = build_url_feature_matrix(train_df["url"].fillna(""))
    
    url_rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    url_rf.fit(X_train_url, y_train)

    # -------------------------------------------------------------
    # 3. MULTI-EVIDENCE FUSION LAYER (STACKING / PROBABILITY COMBINER)
    # -------------------------------------------------------------
    print("\n--- 3. Training Multi-Evidence Fusion Layer ---")
    # Generate out-of-fold or training probability predictions
    p_text_train = text_pipeline.predict_proba(X_train_text)[:, 1]
    p_url_train = url_rf.predict_proba(X_train_url)[:, 1]
    has_url_train = (train_df["url"].fillna("").str.strip() != "").astype(int).values

    # Fusion feature vector: [p_text, p_url, has_url, p_text * p_url]
    X_train_fusion = np.column_stack([
        p_text_train,
        p_url_train,
        has_url_train,
        p_text_train * p_url_train
    ])

    fusion_classifier = LogisticRegression(class_weight="balanced", random_state=42)
    fusion_classifier.fit(X_train_fusion, y_train)

    # -------------------------------------------------------------
    # 4. RIGOROUS EVALUATION SUITE
    # -------------------------------------------------------------
    print("\n--- 4. Running Comprehensive Evaluation on Test Set ---")
    X_test_text = test_df["text"].fillna("")
    X_test_url = build_url_feature_matrix(test_df["url"].fillna(""))
    y_test = test_df["label"].values

    p_text_test = text_pipeline.predict_proba(X_test_text)[:, 1]
    p_url_test = url_rf.predict_proba(X_test_url)[:, 1]
    has_url_test = (test_df["url"].fillna("").str.strip() != "").astype(int).values

    X_test_fusion = np.column_stack([
        p_text_test,
        p_url_test,
        has_url_test,
        p_text_test * p_url_test
    ])

    p_fusion_test = fusion_classifier.predict_proba(X_test_fusion)[:, 1]

    # Binary predictions (threshold = 0.5)
    pred_text = (p_text_test >= 0.5).astype(int)
    pred_url = (p_url_test >= 0.5).astype(int)
    pred_fusion = (p_fusion_test >= 0.5).astype(int)

    # 4A. Ablation Study: Compare Text-Only, URL-Only, and Multi-Evidence Fusion
    ablation_metrics = {
        "text_only": calculate_metrics(y_test, pred_text),
        "url_only": calculate_metrics(y_test, pred_url),
        "multi_evidence_fusion": calculate_metrics(y_test, pred_fusion)
    }

    # 4B. Per-Language Evaluation for Multi-Evidence Fusion
    languages = ["en", "hi", "gu"]
    language_names = {"en": "English", "hi": "Hindi (Devanagari)", "gu": "Gujarati"}
    language_metrics = {}

    for lang in languages:
        mask = (test_df["language"] == lang).values
        if np.sum(mask) > 0:
            y_lang_true = y_test[mask]
            pred_lang_fusion = pred_fusion[mask]
            pred_lang_text = pred_text[mask]
            pred_lang_url = pred_url[mask]

            language_metrics[lang] = {
                "name": language_names[lang],
                "fusion": calculate_metrics(y_lang_true, pred_lang_fusion),
                "text_only": calculate_metrics(y_lang_true, pred_lang_text),
                "url_only": calculate_metrics(y_lang_true, pred_lang_url)
            }

    # Print summary results to console
    print("\n" + "=" * 70)
    print("ABLATION STUDY: DOES COMBINING TEXT + URL IMPROVE SCAM DETECTION?")
    print("=" * 70)
    for model_name, m in ablation_metrics.items():
        print(f"[{model_name.upper():<22}] Accuracy: {m['accuracy']*100:.2f}% | Precision: {m['precision']*100:.2f}% | Recall: {m['recall']*100:.2f}% | F1: {m['f1_score']*100:.2f}% | FPR: {m['false_positive_rate']*100:.2f}%")

    print("\n" + "=" * 70)
    print("PER-LANGUAGE EVALUATION: FALSE POSITIVE RATE (FPR) & F1-SCORE")
    print("=" * 70)
    for lang, data in language_metrics.items():
        m = data["fusion"]
        print(f"[{data['name']:<22}] Acc: {m['accuracy']*100:.2f}% | Prec: {m['precision']*100:.2f}% | Rec: {m['recall']*100:.2f}% | F1: {m['f1_score']*100:.2f}% | FPR: {m['false_positive_rate']*100:.2f}%")

    # -------------------------------------------------------------
    # 5. SAVE ARTIFACTS AND EVALUATION REPORT
    # -------------------------------------------------------------
    joblib.dump(text_pipeline, os.path.join(output_dir, "text_model.joblib"))
    joblib.dump(url_rf, os.path.join(output_dir, "url_model.joblib"))
    joblib.dump(fusion_classifier, os.path.join(output_dir, "fusion_model.joblib"))

    # Feature importances for URL model
    url_feat_importance = dict(sorted(
        zip(FEATURE_COLUMNS, [round(float(x), 4) for x in url_rf.feature_importances_]),
        key=lambda item: item[1],
        reverse=True
    ))

    report = {
        "dataset_summary": {
            "total_records": len(df),
            "train_records": len(train_df),
            "test_records": len(test_df),
            "language_counts": df["language"].value_counts().to_dict(),
            "label_counts": {
                "phishing": int((df["label"] == 1).sum()),
                "legitimate": int((df["label"] == 0).sum())
            }
        },
        "ablation_study": ablation_metrics,
        "language_breakdown": language_metrics,
        "url_feature_importance": url_feat_importance,
        "feature_columns": FEATURE_COLUMNS,
        "project_metadata": {
            "title": "Nirbhay — AI-Powered Digital Safety & Response Platform",
            "guide": "Prof. Ujwala Patigara",
            "team": ["Isha Rajput", "Parisha Parmar", "Priya Bhatt"],
            "academic_year": "2026-27",
            "institution": "Navrachana University, Vadodara, Gujarat",
            "course": "Major Project (DS-ML)"
        }
    }

    report_path = os.path.join(output_dir, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nEvaluation report successfully saved to {report_path}")

    # Also save test samples for quick live demonstration
    test_samples = test_df.head(25)[["id", "text", "url", "language", "label", "category"]].to_dict(orient="records")
    with open(os.path.join(output_dir, "test_demo_samples.json"), "w", encoding="utf-8") as f:
        json.dump(test_samples, f, indent=2, ensure_ascii=False)

    print("All ML artifacts saved successfully!")
    return report

if __name__ == "__main__":
    train_and_evaluate()
