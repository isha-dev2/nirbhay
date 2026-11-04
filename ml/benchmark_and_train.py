"""
TRINETRA Machine Learning Training, Model Comparison & Rigorous Benchmark Pipeline
Department of Data Science & Machine Learning | Navrachana University, Vadodara
Guide: Prof. Ujwala Patigara | Team: Isha Rajput, Parisha Parmar, Priya Bhatt

Benchmarks:
1. Model Comparison: Naive Bayes, Logistic Regression, LinearSVC, SGDClassifier, Random Forest
2. Multi-Evidence Integration: Text NLP + Structural URL Analysis + Late Fusion Stacking
3. Rigorous Evaluation: Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), Confusion Matrices
4. Per-Language Slices: English, Hindi (Devanagari), Gujarati
5. Ablation Study: Text-Only vs URL-Only vs Multi-Evidence Fusion
"""
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from ml.feature_extractor import FEATURE_COLUMNS, extract_url_features

DATA_PATH = os.path.join(BASE_DIR, "data", "multilingual_phishing_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def compute_metrics(y_true, y_pred):
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

def build_url_feature_matrix(url_series):
    rows = [extract_url_features(str(u)) for u in url_series]
    return pd.DataFrame(rows)[FEATURE_COLUMNS].values

def run_pipeline():
    print("=" * 80)
    print("TRINETRA (SANKET) MULTILINGUAL AI MODEL TRAINING & BENCHMARKING")
    print("Datasets: IEEE Hindi SMS + IndiF Telecom Fraud + LDC-IL + Samanantar + UCI")
    print("=" * 80)

    # 1. Load Master Dataset
    df = pd.read_csv(DATA_PATH)
    print(f"\n[1] Loaded Master Dataset: {len(df)} samples across {df['language'].nunique()} languages.")
    print("Distribution by Language & Class:")
    print(df.groupby(["language", "label"]).size())
    print("\nDistribution by Institutional Research Source:")
    print(df.groupby(["source", "label"]).size())

    # 2. Train-Test Split (Strict Stratified Partitioning)
    df["strat_key"] = df["language"] + "_" + df["label"].astype(str)
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["strat_key"]
    )
    print(f"\n[2] Stratified Split: Train={len(train_df)} (80%) | Test={len(test_df)} (20%)")

    # 3. Text Featurization: Subword Character N-Grams + Word N-Grams
    word_vec = TfidfVectorizer(
        ngram_range=(1, 2),
        analyzer='word',
        max_features=8000,
        sublinear_tf=True,
        min_df=2
    )
    char_vec = TfidfVectorizer(
        ngram_range=(3, 5),
        analyzer='char',
        max_features=12000,
        sublinear_tf=True,
        min_df=3
    )
    text_features = FeatureUnion([
        ("word", word_vec),
        ("char", char_vec)
    ])

    X_train_raw = train_df["text"].fillna("")
    y_train = train_df["label"].values

    print("\n[3] Fitting Text Featurizer on Training Data only (Strict No-Leakage)...")
    X_train_text_vec = text_features.fit_transform(X_train_raw)
    print(f"Total Combined Text Feature Dimensions: {X_train_text_vec.shape[1]}")

    # 4. Model Comparison Suite (5-Fold Stratified Cross-Validation on Training Set)
    print("\n" + "=" * 65)
    print("--- 4. CLASSIFIER COMPARISON (5-Fold Stratified Cross-Validation) ---")
    print("=" * 65)
    
    candidate_models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression (L2)": LogisticRegression(C=2.0, max_iter=1000, class_weight='balanced', random_state=42),
        "SGDClassifier (Modified Huber)": SGDClassifier(loss='modified_huber', penalty='l2', alpha=1e-4, max_iter=1000, random_state=42),
        "Random Forest (100 Trees)": RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, class_weight='balanced'),
        "LinearSVC (Calibrated Margin)": CalibratedClassifierCV(
            estimator=LinearSVC(C=1.0, class_weight='balanced', random_state=42), cv=3
        )
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    comparison_results = {}

    for name, clf in candidate_models.items():
        acc_scores = cross_val_score(clf, X_train_text_vec, y_train, cv=cv, scoring='accuracy')
        f1_scores = cross_val_score(clf, X_train_text_vec, y_train, cv=cv, scoring='f1')
        prec_scores = cross_val_score(clf, X_train_text_vec, y_train, cv=cv, scoring='precision')
        rec_scores = cross_val_score(clf, X_train_text_vec, y_train, cv=cv, scoring='recall')

        comparison_results[name] = {
            "cv_accuracy_mean": round(float(np.mean(acc_scores)), 4),
            "cv_accuracy_std": round(float(np.std(acc_scores)), 4),
            "cv_f1_mean": round(float(np.mean(f1_scores)), 4),
            "cv_f1_std": round(float(np.std(f1_scores)), 4),
            "cv_precision_mean": round(float(np.mean(prec_scores)), 4),
            "cv_recall_mean": round(float(np.mean(rec_scores)), 4)
        }
        print(f"{name:<32} | Acc: {np.mean(acc_scores)*100:5.2f}% (+/- {np.std(acc_scores)*100:4.2f}%) | F1: {np.mean(f1_scores):.4f} | Prec: {np.mean(prec_scores):.4f} | Rec: {np.mean(rec_scores):.4f}")

    # 5. Train Selected Production Text Classifier
    print("\n[5] Training Production Text Pipeline (LinearSVC + Calibrated Probability)...")
    chosen_text_clf = CalibratedClassifierCV(
        estimator=LinearSVC(C=1.0, class_weight='balanced', random_state=42), cv=3
    )
    text_pipeline = Pipeline([
        ("features", text_features),
        ("classifier", chosen_text_clf)
    ])
    text_pipeline.fit(X_train_raw, y_train)

    # 6. Train Structural URL Classifier (Random Forest with 25+ Features)
    print("\n[6] Training Structural URL Classifier (Random Forest with Lexical & Entropy Features)...")
    X_train_url = build_url_feature_matrix(train_df["url"].fillna(""))
    url_rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        random_state=42,
        class_weight="balanced"
    )
    url_rf.fit(X_train_url, y_train)

    # 7. Train Multi-Evidence Late Fusion Model (Stacking)
    print("\n[7] Training Multi-Evidence Fusion Layer (Stacking Classifier)...")
    p_text_train = text_pipeline.predict_proba(X_train_raw)[:, 1]
    p_url_train = url_rf.predict_proba(X_train_url)[:, 1]
    has_url_train = (train_df["url"].fillna("").str.strip() != "").astype(int).values

    X_train_fusion = np.column_stack([
        p_text_train,
        p_url_train,
        has_url_train,
        p_text_train * p_url_train
    ])

    fusion_clf = LogisticRegression(class_weight="balanced", random_state=42)
    fusion_clf.fit(X_train_fusion, y_train)

    # 8. Rigorous Test Set Evaluation
    print("\n[8] Running Comprehensive Evaluation on Held-Out Test Set (Unseen Data)...")
    X_test_raw = test_df["text"].fillna("")
    X_test_url = build_url_feature_matrix(test_df["url"].fillna(""))
    y_test = test_df["label"].values

    p_text_test = text_pipeline.predict_proba(X_test_raw)[:, 1]
    p_url_test = url_rf.predict_proba(X_test_url)[:, 1]
    has_url_test = (test_df["url"].fillna("").str.strip() != "").astype(int).values

    X_test_fusion = np.column_stack([
        p_text_test,
        p_url_test,
        has_url_test,
        p_text_test * p_url_test
    ])
    p_fusion_test = fusion_clf.predict_proba(X_test_fusion)[:, 1]

    pred_text = (p_text_test >= 0.5).astype(int)
    pred_url = (p_url_test >= 0.5).astype(int)
    pred_fusion = (p_fusion_test >= 0.5).astype(int)

    # 8A. Ablation Study
    ablation_study = {
        "text_only": compute_metrics(y_test, pred_text),
        "url_only": compute_metrics(y_test, pred_url),
        "multi_evidence_fusion": compute_metrics(y_test, pred_fusion)
    }

    print("\n" + "=" * 65)
    print("--- ABLATION STUDY: MODALITY PERFORMANCE ON TEST SET ---")
    print("=" * 65)
    for mod, m in ablation_study.items():
        print(f"{mod:<22} | Acc: {m['accuracy']*100:5.2f}% | Prec: {m['precision']*100:5.2f}% | Rec: {m['recall']*100:5.2f}% | F1: {m['f1_score']:.4f} | FPR: {m['false_positive_rate']*100:5.2f}%")

    # 8B. Per-Language Benchmark
    languages = ["en", "hi", "gu"]
    language_names = {"en": "English", "hi": "Hindi (Devanagari)", "gu": "Gujarati"}
    language_breakdown = {}

    print("\n" + "=" * 65)
    print("--- PER-LANGUAGE EVALUATION (FPR & F1 BREAKDOWN) ---")
    print("=" * 65)
    for lang in languages:
        mask = (test_df["language"] == lang).values
        if np.sum(mask) > 0:
            y_sub = y_test[mask]
            pred_sub_fusion = pred_fusion[mask]
            pred_sub_text = pred_text[mask]
            pred_sub_url = pred_url[mask]

            m_fusion = compute_metrics(y_sub, pred_sub_fusion)
            m_text = compute_metrics(y_sub, pred_sub_text)
            m_url = compute_metrics(y_sub, pred_sub_url)

            language_breakdown[lang] = {
                "name": language_names[lang],
                "sample_count": int(np.sum(mask)),
                "fusion": m_fusion,
                "text_only": m_text,
                "url_only": m_url
            }
            print(f"{language_names[lang]:<20} | Acc: {m_fusion['accuracy']*100:5.2f}% | F1: {m_fusion['f1_score']:.4f} | Prec: {m_fusion['precision']*100:5.2f}% | Rec: {m_fusion['recall']*100:5.2f}% | FPR: {m_fusion['false_positive_rate']*100:5.2f}%")

    # 8C. Disjoint Template Generalization Evaluation (Zero Template Leakage)
    print("\n" + "=" * 65)
    print("--- 8C. DISJOINT TEMPLATE GENERALIZATION STUDY (STRICT 0% LEAKAGE) ---")
    print("=" * 65)
    import re
    from sklearn.model_selection import GroupShuffleSplit
    
    def extract_template_signature(text):
        t = re.sub(r'http\S+', '', str(text))
        t = re.sub(r'\d+', '', t)
        t = re.sub(r'[*]+', '', t)
        t = re.sub(r'\s+', ' ', t)
        return t.strip()[:35]

    df_full = df.copy()
    df_full['template_group'] = df_full['text'].apply(extract_template_signature)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    disjoint_train_idx, disjoint_test_idx = next(gss.split(df_full, groups=df_full['template_group']))

    d_train_df = df_full.iloc[disjoint_train_idx]
    d_test_df = df_full.iloc[disjoint_test_idx]

    # Fit a dedicated validation model on disjoint templates
    d_vec = FeatureUnion([
        ('word', TfidfVectorizer(ngram_range=(1,2), analyzer='word', max_features=8000, sublinear_tf=True)),
        ('char', TfidfVectorizer(ngram_range=(3,5), analyzer='char', max_features=12000, sublinear_tf=True))
    ])
    d_clf = CalibratedClassifierCV(LinearSVC(class_weight='balanced', random_state=42), cv=3)
    d_pipe = Pipeline([('vec', d_vec), ('clf', d_clf)])
    d_pipe.fit(d_train_df['text'].fillna(''), d_train_df['label'].values)

    d_y_true = d_test_df['label'].values
    d_y_pred = d_pipe.predict(d_test_df['text'].fillna(''))
    d_overall_metrics = compute_metrics(d_y_true, d_y_pred)

    d_lang_breakdown = {}
    for lang in languages:
        l_mask = (d_test_df['language'] == lang).values
        if np.sum(l_mask) > 0:
            d_lang_breakdown[lang] = compute_metrics(d_y_true[l_mask], d_y_pred[l_mask])

    print(f"Disjoint Test Samples: {len(d_test_df)} across {d_test_df['template_group'].nunique()} completely novel templates.")
    print(f"Generalization Accuracy: {d_overall_metrics['accuracy']*100:.2f}% | F1: {d_overall_metrics['f1_score']:.4f} | FPR: {d_overall_metrics['false_positive_rate']*100:.2f}%")
    for lang in languages:
        if lang in d_lang_breakdown:
            print(f"  - {language_names[lang]}: Acc: {d_lang_breakdown[lang]['accuracy']*100:.2f}% | F1: {d_lang_breakdown[lang]['f1_score']:.4f} | FPR: {d_lang_breakdown[lang]['false_positive_rate']*100:.2f}%")

    # 9. Save Models & Evaluation Report
    print("\n[9] Serializing Artifacts to models/ ...")
    joblib.dump(text_pipeline, os.path.join(MODELS_DIR, "text_model.joblib"))
    joblib.dump(url_rf, os.path.join(MODELS_DIR, "url_model.joblib"))
    joblib.dump(fusion_clf, os.path.join(MODELS_DIR, "fusion_model.joblib"))

    final_report = {
        "platform": "Sanket (TRINETRA) Multilingual AI Safety",
        "institution": "Navrachana University, Vadodara, Gujarat",
        "academic_session": "Major Project 2026-27",
        "guide": "Prof. Ujwala Patigara",
        "team": ["Isha Rajput", "Parisha Parmar", "Priya Bhatt"],
        "datasets_used": [
            "IEEE Hindi Spam SMS Dataset (Ramanujam et al. / NIT Silchar / IEEE DataPort 2024)",
            "IndiF / INDICA Telecom Fraud Benchmark (Vikram et al., 2026)",
            "LDC-IL Gujarati Corpus (Linguistic Data Consortium for Indian Languages, GoI)",
            "AI4Bharat Samanantar (Parallel Indic Corpus)",
            "UCI SMS Spam Collection & Indian Banking Formats",
            "Curated Gujarati Cyber Fraud Corpus"
        ],
        "dataset_statistics": {
            "total_samples": len(df),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "per_language_counts": df["language"].value_counts().to_dict(),
            "per_source_counts": df["source"].value_counts().to_dict()
        },
        "model_comparison": comparison_results,
        "selected_architecture": {
            "text_classifier": "LinearSVC (calibrated with 3-fold Platt scaling) on (1,2) word + (3,5) char TF-IDF n-grams",
            "url_classifier": "Random Forest (150 estimators, 25+ structural & lexical features)",
            "fusion_layer": "Logistic Regression Late-Fusion Stacker"
        },
        "ablation_study": ablation_study,
        "language_breakdown": language_breakdown,
        "disjoint_generalization_study": {
            "methodology": "GroupShuffleSplit on semantic message signatures with strict 0% template overlap between train and test",
            "train_samples_count": len(d_train_df),
            "test_samples_count": len(d_test_df),
            "novel_templates_tested": d_test_df['template_group'].nunique(),
            "overall_metrics": d_overall_metrics,
            "per_language_metrics": d_lang_breakdown
        }
    }

    with open(os.path.join(MODELS_DIR, "evaluation_report.json"), "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2, ensure_ascii=False)

    # 10. Generate Live Demonstration Samples (for Faculty Pointer 2 Review)
    demo_samples = []
    # Pick balanced representative samples from test_df
    for _, row in test_df.sample(n=min(30, len(test_df)), random_state=42).iterrows():
        demo_samples.append({
            "id": row["id"],
            "text": row["text"],
            "url": row["url"] if pd.notna(row["url"]) else "",
            "label": int(row["label"]),
            "language": row["language"],
            "source": row["source"],
            "category": row["category"]
        })

    with open(os.path.join(MODELS_DIR, "test_demo_samples.json"), "w", encoding="utf-8") as f:
        json.dump(demo_samples, f, indent=2, ensure_ascii=False)

    print(f"\nAll artifacts successfully saved to {MODELS_DIR}/:")
    print("  - text_model.joblib")
    print("  - url_model.joblib")
    print("  - fusion_model.joblib")
    print("  - evaluation_report.json")
    print("  - test_demo_samples.json")
    print("=" * 80)
    print("PIPELINE TRAINING & BENCHMARKING COMPLETE!")
    print("=" * 80)

if __name__ == "__main__":
    run_pipeline()

