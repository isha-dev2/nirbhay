# Nirbhay Pipeline Notes & Assumptions

This document tracks all design decisions, cleaning assumptions, filtering steps, feature engineering definitions, and validation strategies across the 4 stages of the Nirbhay multilingual scam detector pipeline.

---

## Stage 1: Data Ingestion & Cleansing

### 1. Master Dataset v1 Baseline (`ml/data/processed/master_dataset.csv`)
- **Row count**: 866 rows.
- **Breakdown**:
  - English: 800 rows (400 safe, 400 scam) from Kaggle UCI SMS dataset (`collected_by=dataset`).
  - Gujarati: 51 safe rows from WhatsApp family chats (`collected_by=isha`), 7 scam rows scraped from advisories/news (`collected_by=scraper`).
  - Hindi: 7 safe rows from WhatsApp (`collected_by=isha`), 8 scam rows scraped from news/advisories (`collected_by=scraper`).
- **Assumption**: Kept completely untouched as required. Rows from master v1 have highest priority in deduplication.

### 2. Hugging Face Multilingual Collection (`dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset`)
- **Gujarati Check**:
  - The Hugging Face dataset contains 22 translated text columns: `text_hi`, `text_de`, `text_fr`, `text_es`, `text_zh`, `text_ar`, `text_bn`, `text_ru`, `text_pt`, `text_ja`, `text_id`, `text_ur`, `text_pa`, `text_jv`, `text_tr`, `text_ko`, `text_mr`, `text_uk`, `text_sv`, `text_no`.
  - **Result**: **Gujarati (`gu`) is NOT present** in this dataset (no column exists, and script scan confirms zero Gujarati script characters).
- **Hindi Extraction**:
  - Examined column `text_hi`.
  - Filtered using script detection: ratio of Devanagari alphabetic characters to total alphabetic characters must be $\ge 0.5$. This retains 5,323 machine-translated rows while eliminating untranslated/corrupted English passages.
  - Labels mapped: `ham` $\rightarrow$ `safe`, `spam` $\rightarrow$ `scam`.
  - Saved to `ml/data/raw/hf_hi_gu_extract.csv` with metadata: `channel="sms"`, `source="HF dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset"`, `collected_by="synthetic"`, `notes="machine-translated; UK-style SMS content"`.

### 3. Pari Multilingual Phishing Dataset (`multilingual_phishing_dataset_pari.csv`)
- **Row count**: 1,588 rows (532 en, 528 gu, 528 hi).
- **Cleansing**:
  - Dropped redundant and unaligned `url` column (links are already present in message text).
  - Mapped labels: `1` $\rightarrow$ `scam`, `0` $\rightarrow$ `safe`.
  - Metadata assigned: `channel="sms"`, `source="Pari multilingual phishing dataset (template-generated)"`, `collected_by="synthetic"`, `notes=<category>`.

### 4. Priya SMS Dataset (`sms_spam_cleaned_priya.xlsx`)
- **Raw count**: 2,113 rows.
- **Filtering**:
  - Dropped 1 completely blank row.
  - Dropped 800 UCI Kaggle rows (`source="UCI SMS Spam Collection (Kaggle)"`). The master dataset already incorporates the balanced Kaggle sample; dropping prevents skewing the English partition.
  - Dropped 2 rows whose text already existed identically in `master_dataset.csv`.
- **PII Masking**:
  - Executed before saving any output:
    - Phone numbers (10-digit mobile, +91, 1800 toll-free, landline) $\rightarrow$ `<PHONE>`.
    - Email addresses $\rightarrow$ `<EMAIL>`.
    - Card/account fragments (`A/C ending XX1234`, `card ending in 1234`) and OTP/PIN codes $\rightarrow$ `<NUM>`.
    - Person names in greetings (`Dear Priya,` $\rightarrow$ `Dear <NAME>,`) while retaining generic roles (`Dear Customer,` `Hi User`).
    - Web URLs preserved so Stage 3 URL feature extraction can analyze domains, TLDs, and protocols.
- **Language Normalization (`gu-en` & `hi-en`)**:
  - Evaluated script counts: Gujarati script vs Latin, and Devanagari script vs Latin.
  - 502 of 522 `gu-en` rows had predominantly Gujarati script $\rightarrow$ mapped to `gu`.
  - 20 `gu-en` rows had predominantly Latin script $\rightarrow$ retained as `gu-en`, added `romanized-check` to notes.
  - 1 `hi-en` row was predominantly Latin script $\rightarrow$ retained as `hi-en`, added `romanized-check` to notes.
- **Auto-Label Partitioning**:
  - 93 auto-scam rows (unreliable, containing genuine transactional / marketing messages) isolated into `ml/data/processed/needs_manual_review.csv` for human verification.
  - 1,217 auto-safe rows kept, annotated with `notes="auto-label, unverified"`.
  - **Template deduplication**: Grouped by normalized template key (`lowercase + digits removed + links/phones masked + first 60 chars`) and capped at at most 5 messages per template. Reduced 1,217 repetitive notifications down to 676 safe rows across 326 unique templates.

### 5. Global Deduplication & Priority Order
- Combined all subsets (Master v1, Priya capped safe, Pari, HF extract): 8,453 total rows.
- Deduplication priority score:
  1. Real + Hand-labelled (`isha`, `scraper`): Priority 4
  2. Real + Auto-labelled (`user_consented_device`): Priority 3
  3. Synthetic / Dataset + Hand-labelled (`dataset`): Priority 2
  4. Synthetic (`synthetic` - Pari, HF): Priority 1
- Dropped 504 exact duplicate texts, yielding **7,949 clean, unique rows** in `ml/data/processed/master_v2.csv`.

---

## Stage 2: Preprocessing

### 1. Preprocessing Transformations (`text_clean`)
- **Unicode Normalization**: Applied `unicodedata.normalize('NFC', text)` to unify composite characters across Indic scripts.
- **Zero-Width Character Removal**: Stripped invisible zero-width formatting characters (`\u200b`, `\u200c`, `\u200d`, `\u200e`, `\u200f`, `\ufeff`).
- **Whitespace Collapsing**: Collapsed multiple spaces, tabs, and newlines into single spaces with outer stripping.
- **Entity Masking in `text_clean`**:
  - URLs $\rightarrow$ `<LINK>`
  - Phone numbers (10+ digits, +91, 1800 toll-free, standard landlines) $\rightarrow$ `<PHONE>`
  - Emails $\rightarrow$ `<EMAIL>`
  - Digit runs of 4 or more digits (account numbers, OTPs, transaction IDs) $\rightarrow$ `<NUM>`
- **Preservation of Indic Scripts & Case**:
  - Original letter casing preserved (not converted to lowercase) to maintain uppercase signal for TF-IDF char n-grams.
  - Indic scripts kept strictly verbatim: no stemming, lemmatization, stopword removal, or transliteration.

### 2. Group Identification (`group_id`)
- Extracted normalized template key: lowercase text, all digits stripped, links and phones masked, truncated to the initial 60 characters.
- Assigned an integer group ID via factorization across the entire dataset. Resulted in **6,170 distinct template groups** across 7,949 rows.
- This ensures identical and near-duplicate SMS messages fall into the same cross-validation fold, preventing data leakage during evaluation.

---

## Stage 3: Feature Engineering

### 1. Tabular Domain Features (`feat_*`)
Computed directly from the ORIGINAL text prior to stage 2 entity masking:
- `feat_has_url` (binary) & `feat_n_urls` (count): Derived via comprehensive URL regex supporting full URLs, IPs, and bare shortener paths.
- `feat_url_is_ip` (binary): Detects raw IPv4 network addresses in URLs.
- `feat_url_suspicious_tld` (binary): Matches risky top-level domains (`.xyz`, `.top`, `.site`, `.click`, `.info`, `.club`, etc.).
- `feat_url_is_shortener` (binary): Matches known URL shortener domains (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.).
- `feat_url_https` (binary): 1 if secure protocol `https://` is utilized.
- `feat_url_length` (integer): Maximum character length among detected URLs.
- `feat_digit_ratio` (float): Ratio of digit characters (`0-9`) to overall text length.
- `feat_has_phone` (binary): Detects phone numbers or `<PHONE>` placeholder.
- `feat_has_currency` (binary) & `feat_has_amount` (binary): Flags presence of currency symbols/codes (`₹`, `Rs`, `INR`, `रु`, `રૂ`, `£`, `$`, `€`) and monetary quantities (e.g. `₹500`, `Rs. 5,000`, `500/-`).
- `feat_urgency_count` (integer): Matches urgency vocabulary across English, Hindi (`तुरंत`, `तत्काल`, `सावधान`), and Gujarati (`તાત્કાલિક`, `તરત`, `ચેતવણી`).
- `feat_authority_count` (integer): Matches authority impersonation terms across all 3 languages (RBI, SBI, KYC, police, TRAI, bank, electricity boards, etc.).
- `feat_credential_count` (integer): Matches credential harvesting triggers (OTP, PIN, CVV, password, passcode, login).
- `feat_action_verbs_count` (integer): Matches actionable verbs (click, call, download, claim, verify, update, etc.).
- `feat_exclamation_count` (integer): Count of exclamation marks (`!`).
- `feat_uppercase_ratio` (float): Ratio of uppercase Latin characters to total Latin characters.
- `feat_emoji_count` (integer): Unicode emoji codepoints count.
- `feat_length` (integer): Character length of raw message text.
- `feat_latin_ratio`, `feat_devanagari_ratio`, `feat_gujarati_ratio` (floats): Proportions of each respective script in the message.

### 2. Synthetic Data Artifact Observation
- In the synthetic data (Pari & HF translated sets), scam links disproportionately employ unusual domains/IPs (`feat_url_suspicious_tld` average 0.274 vs 0.000 for safe; `feat_url_is_ip` average 0.074 vs 0.000 for safe).
- Conversely, in real-world phone SMS (`user_consented_device`), safe messages frequently feature genuine URLs to banks, portals, and invoice tracking, while scam messages often rely on phone calls or WhatsApp redirects without explicit URLs.
- To study and account for this artifact, Stage 4 evaluates models with and without the `feat_url_*` feature subset.

---

## Stage 4: Baseline Modeling & Evaluation (TF-IDF & Feature Fusion)

### 1. Methodology & Validation Setup
- **Cross-Validation Scheme**: 5-fold `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)`.
  - Grouped by `group_id` (message template hash) to prevent template leakage across folds.
  - Stratified by language $\times$ label (`en_safe`, `en_scam`, `gu_safe`, `gu_scam`, `hi_safe`, `hi_scam`).
- **Models Evaluated**:
  1. **Model A**: Sublinear TF-IDF character n-grams ($2 \le n \le 5$, `min_df=2`) + balanced Logistic Regression (`class_weight='balanced'`).
  2. **Model B**: Signal fusion combining Model A TF-IDF with all 22 scaled tabular features (`StandardScaler`).
  3. **Model B (No-URL)**: Signal fusion combining Model A TF-IDF with 15 non-URL tabular features.
  4. **Ablation (Real Only)**: Exact models trained strictly on real training fold rows (`is_real == True`).

### 2. Baseline Out-Of-Fold Metrics (Real Test Rows, $N=1,534$)

| Model & Training Split | Real English Scam F1 ($N=1195$) | Real Gujarati Scam F1 ($N=322$) | Real Hindi Scam F1 ($N=17$) | Real Overall Scam F1 ($N=1534$) | Real Overall Macro F1 |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Model A (TF-IDF) [Train: All]** | 0.8912 | **0.5333** | **0.7273** | 0.8812 | 0.9159 |
| **Model B (TF-IDF + All Feat) [Train: All]** | 0.8956 | 0.1111 | 0.6087 | 0.8717 | 0.9106 |
| **Model B (No-URL Feat) [Train: All]** | 0.8828 | 0.2400 | 0.6667 | 0.8591 | 0.9006 |
| **Ablation: Model A [Train: Real Only]** | **0.9309** | 0.0000 | 0.6316 | **0.9166** | **0.9423** |
| **Ablation: Model B [Train: Real Only]** | 0.9064 | 0.2000 | 0.6667 | 0.8923 | 0.9254 |
| **Ablation: Model B (No-URL) [Train: Real Only]** | 0.8978 | 0.0000 | 0.7000 | 0.8816 | 0.9180 |

---

## Stage 5: MuRIL Transformer Fine-Tuning & Ablation (Google Colab)

### 1. Training Setup
- **Model**: `google/muril-base-cased` (pretrained multilingual representations for Indian languages).
- **Hyperparameters**: Max length = 128, Batch size = 16, Learning rate = $3\times 10^{-5}$ (AdamW with linear warmup over 10% steps, weight decay = 0.01), Epochs = 4.
- **Cross-Validation**: 5-fold `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` grouped by `group_id`.
- **Evaluated Configurations**:
  1. **MuRIL Mixed (Real + Pari Synthetic)**: 3,026 rows (1,527 real + 1,499 synthetic). `--hf-cap 0` excluded the 5,000+ machine-translated Hindi rows to prevent cross-language translation leakage and data imbalance.
  2. **MuRIL Real-Only (Ablation)**: 1,527 real rows only (0 synthetic).

### 2. Comprehensive Comparison: TF-IDF vs. MuRIL Fine-Tuning

| Model & Training Split | Real English Scam F1 ($N=1195$) | Real Gujarati Scam F1 ($N=322$) | Real Hindi Scam F1 ($N=17$) | ALL Real Scam F1 ($N=1527$) | ALL Real Scam Recall (95% CI) | ALL Real False Positives (FP) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline TF-IDF (Real Only)** | 0.9309 | 0.0000 (0/7) | 0.6316 (6/8) | 0.9166 | 0.9398 | 46 |
| **Baseline TF-IDF (Mixed)** | 0.8912 | 0.5333 (4/7) | 0.7273 (8/8) | 0.8812 | 0.9566 | 89 |
| **MuRIL (Real Only - Ablation)** | **0.9480** | **0.0000** (0/7) | **0.0000** (0/8) | 0.9290 | 0.9036 (0.87–0.93) | **17** |
| **MuRIL (Mixed: Real + Synth)** | 0.9400 | **0.5333** (4/7) | **0.8889** (8/8) | **0.9320** | **0.9398** (0.91–0.96) | 32 |

### 3. Critical Findings for Project Report & College Defense
1. **The "Overall Metric Masking" Fallacy**:
   - On the aggregate "ALL Real" metric, MuRIL Real-Only ($F1=0.929$) appears almost identical to MuRIL Mixed ($F1=0.932$).
   - However, disaggregating by language reveals a critical vulnerability: **MuRIL trained on real data alone suffered a 100% blindspot in Hindi and Gujarati scams (0% recall: 0/8 Hindi caught, 0/7 Gujarati caught)**.
   - Aggregate metrics are heavily dominated by English ($78.3\%$ of real data), completely concealing catastrophic failure modes in Indian regional languages.
2. **Synthetic Data Solves the Low-Resource Cold Start**:
   - Introducing ~250 synthetic template variants per language allowed MuRIL to catch **100% of real Hindi scams (8/8)** and **57.1% of real Gujarati scams (4/7)** while maintaining a stellar $0.940$ English F1.
3. **MuRIL Outperforms TF-IDF in Discriminative Precision**:
   - Compared to the baseline TF-IDF Mixed model, MuRIL Mixed cut false positives on real SMS by **64%** (from 89 down to 32), raising English scam precision to $93.6\%$ and Hindi scam precision to $80.0\%$.

---

## Stage 6: Classifier 2 Architecture (URL & QR Code Detector)

### 1. Motivation & Threat Model
- Many cybercrimes in India operate not only via text manipulation, but through **phishing links** (fake electricity portals, APK downloads, banking KYC) and **QR code fraud (Quishing)**.
- In particular, **UPI Reverse-Payment Fraud** tricks users into scanning a QR code with the false promise of receiving prize money/refunds, when the code actually initiates an outgoing debit request (`upi://pay`).

### 2. Implementation Modules
1. **Training Script**: [`ml/train_url_classifier.py`](file:///Users/isha/Documents/sem7/major/nirbhay/ml/train_url_classifier.py)
   - Evaluates 16 structural, lexical, domain, and brand impersonation features.
   - Whitelist validation for verified Indian institutions (SBI, HDFC, Cyber Crime, Parivahan, PGVCL, UGVCL, UIDAI, Jio).
   - High-risk TLD tracking (`.xyz`, `.top`, `.click`, `.site`, `.vip`, `.loan`, `.apk` downloads, IP-based hosts).
   - **Trained Model**: [`backend/models/url_classifier.joblib`](file:///Users/isha/Documents/sem7/major/nirbhay/backend/models/url_classifier.joblib)
   - **Performance**: 0.9936 Accuracy, 0.9930 F1, 0.9998 ROC-AUC via 5-fold cross-validation.
2. **QR & UPI Detector**: [`backend/qr_detector.py`](file:///Users/isha/Documents/sem7/major/nirbhay/backend/qr_detector.py)
   - Decodes QR images using OpenCV multi-stage preprocessing (grayscale, histogram equalization, Otsu binarization).
   - Intercepts `upi://pay` strings and flags the crucial fraud rule: **"You NEVER need to scan a QR code or enter your UPI PIN to receive money."**
3. **API Routing**: [`backend/routes.py`](file:///Users/isha/Documents/sem7/major/nirbhay/backend/routes.py)
   - Dedicated REST endpoints: `/v2/check/url` and `/v2/check/qr`.


