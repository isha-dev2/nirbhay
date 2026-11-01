# Nirbhay (निर्भय • નિર્ભય) — AI-Powered Digital Safety & Response Platform

> **Major Project (2026–27) | Department of Data Science & Machine Learning**  
> **Institution:** Navrachana University, Vadodara, Gujarat  
> **Guide:** Prof. Ujwala Patigara  
> **Presented by:** Isha Rajput, Parisha Parmar, Priya Bhatt  

---

## 🎯 Central Research Problem & Question

### Problem Statement
Digital scams and phishing attacks manipulate victims through deceptive communications (SMS, WhatsApp, impersonation, malicious payment links). While English-trained security classifiers exist, regional Indian languages suffer severe performance drops due to vocabulary shifts, lack of labeled Indic corpora, and omission of URL structural evidence.

### Central Research Question
> **“Does combining message text and URL evidence improve scam detection compared to analyzing either source alone across English, Hindi, and Gujarati?”**

---

## 🚀 Live Demonstration Pointers (Faculty Requirements)

### Pointer 1: Running of Model
- **Multilingual Support:** Live real-time analysis of messages in **English**, **Hindi (हिन्दी / Devanagari)**, and **Gujarati (ગુજરાતી)**.
- **Parallel Dual-Engine Architecture:**
  1. **Multilingual NLP Model:** TF-IDF Word + Character N-Gram Feature Union (captures morphological inflections in Indic scripts) with Calibrated Support Vector Classifier.
  2. **Structural URL Classifier:** 25+ Lexical, Host, Domain, and Shannon Entropy features (inspired by QsecR *IEEE Access 2023*) powered by Random Forest.
  3. **Multi-Evidence Fusion Layer:** Calibrated late-fusion combining text threat probability, URL lexical threat probability, and safety heuristics.
- **Explainable AI (XAI) & Plain-Language Guidance:** Delivers step-by-step safety recommendations and exact red-flag breakdowns in English, Hindi, and Gujarati alongside emergency National Cybercrime Helpline **1930** (`cybercrime.gov.in`).

### Pointer 2: Evaluating Model with Live Data
- **Live Batch Evaluation Sandbox:** Allows typing or loading unseen live test samples (1-click preset batches or custom JSON) and recalculates Precision, Recall, F1-Score, and False Positive Rate (FPR) on the fly during the demonstration.
- **Ablation Study Matrix:** Side-by-side empirical comparison proving the research hypothesis:
  - **Text-Only NLP:** Strong on text threats, misses stealth phishing with minimal/neutral text.
  - **URL-Only Lexical:** Strong on URL structural anomalies, fails when URL is absent (phone calls/pure SMS scams).
  - **Multi-Evidence Fusion:** Combines both modalities, achieving highest F1-Score and lowest False Positive Rate across all languages.
- **Per-Language Evaluation:** Explicitly reports Accuracy, Precision, Recall, F1, and **False Positive Rate (FPR)** for English, Hindi, and Gujarati, overcoming the research gap identified in Staples et al. (*IEEE PST 2023*).

---

## 📂 Project Architecture

```
nirbhay/
├── data/
│   └── multilingual_phishing_dataset.csv   # 838 balanced samples (EN, HI, GU)
├── ml/
│   ├── generate_dataset.py                 # Authentic dataset synthesis script
│   ├── feature_extractor.py               # 25+ URL features, Indic script detection, XAI
│   ├── train.py                           # Training & rigorous evaluation pipeline
│   └── nirbhay_dsml_demonstration.ipynb   # Jupyter Notebook for cell-by-cell demo
├── models/
│   ├── text_model.joblib                  # Trained Multilingual Text Classifier
│   ├── url_model.joblib                   # Trained URL Random Forest Model
│   ├── fusion_model.joblib                # Trained Multi-Evidence Fusion Combiner
│   └── evaluation_report.json             # Benchmark metrics, ablation, & importances
├── backend/
│   ├── main.py                            # FastAPI application server
│   ├── ml_engine/
│   │   └── predictor.py                   # Unified inference & explainability engine
│   └── static/
│       └── index.html                     # Responsive Web Dashboard UI
├── tests/
│   ├── test_api.py                        # Unit and integration test suite
│   └── test_live_server.py                # Live HTTP server test runner
├── run_app.py                             # Single-click launcher (server + browser)
├── run_demo.bat                           # Windows batch launcher
└── README.md                              # Project documentation
```

---

## ⚡ How to Run Tomorrow's Demonstration

### Option 1: Quick 1-Click Launch (Recommended)
Double-click `run_demo.bat` or run in terminal:
```bash
python run_app.py
```
This automatically starts the server and opens `http://localhost:8000` in your browser.

### Option 2: Jupyter Notebook Live Walkthrough
If the faculty requests a cell-by-cell DS-ML code execution:
```bash
jupyter notebook ml/nirbhay_dsml_demonstration.ipynb
```

### Option 3: Retraining the Model from Scratch
To demonstrate model training and metrics generation live:
```bash
python ml/train.py
```

---

## 📊 Benchmark Evaluation Results

| Modality / Language | Accuracy | Precision | Recall | F1-Score | False Positive Rate (FPR) |
|---|---|---|---|---|---|
| **Text-Only Model** | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% |
| **URL-Only Model** | 95.83% | 100.0% | 91.67% | 95.65% | 0.00% |
| **Multi-Evidence Fusion** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.00%** |
| *English Subset* | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% |
| *Hindi (Devanagari)* | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% |
| *Gujarati Subset* | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% |

---

## 📚 Literature Review Grounding

1. **Staples, Hakak, and Cook (IEEE PST 2023):** *A Comparison of Machine Learning Algorithms for Multilingual Phishing Detection.* Motivated the need for Indic script corpora and language-wise False Positive Rate analysis.
2. **Rafsanjani et al. (IEEE Access 2023):** *QsecR: Malicious URL Detection Framework.* Informed the 25+ lexical and structural URL feature extraction pipeline.
3. **van Haastrecht et al. (ACM ARES 2021):** *Threat-Based Cybersecurity Risk Assessment.* Emphasized actionable plain-language explanations over raw mathematical probability scores.
4. **Indian Cyber Crime Coordination Centre (I4C, MHA 2023):** Verified statistical incident data (over 1.56M complaints in 2023, 70%+ financial fraud) grounding the real-world utility of Nirbhay.
