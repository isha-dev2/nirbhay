# Sanket (સંકેત / संकेत) — Presentation Day Quick Demonstration Cheatsheet
> **Keep this tab or printed page open during your presentation with Prof. Ujwala Patigara!**

---

## ⚡ 10-Second Quick Start
To launch the app for the panel:
```bash
python run_app.py
```
*(Or double-click `run_demo.bat` on the Desktop/folder. It opens `http://localhost:8000` automatically).*

---

## 🎯 Live Demonstration Flow (Guaranteed A+ Presentation)

### Step 1: Real-World Consumer App (Live Running of Model - Pointer 1)
1. **Show the Clean Google Stitch / Material 3 UI:**
   - Mention: *"Sir/Ma'am, we designed Sanket (સંકેત / संकेत — meaning 'Early Warning Signal') as an accessible, multi-modal cyber threat indicator tailored for citizens across Gujarat and India on both mobile phones and laptops."*
2. **Switch Regional Language:**
   - Use the top language dropdown to switch to **हिन्दी** or **ગુજરાતી**.
   - Show how the entire UI, explanations, and advice adapt dynamically into the regional language.
3. **1-Tap Demo Scenarios:**
   - Click **"SBI YONO KYC Suspension (Hindi Scam)"** ➔ Click **"Check Message Safety"**.
   - Point out:
     - 🔴 **Threat Level & Risk Score:** 88% Phishing Scam.
     - 💡 **Plain-Language Explanation in Hindi:** Explaining why the message and fake `.xyz` domain are fraudulent.
     - 🔊 **Voice Audio Button:** Click **"Listen Audio Alert"** to play the spoken warning aloud!
     - 👨‍👩‍👧 **"Copy WhatsApp Alert":** Show how a user can copy a pre-formatted fraud warning in 1 click to protect their parents and family groups.
4. **Try a Legitimate Message:**
   - Click **"Legitimate SBI Transaction Alert"** ➔ Click **"Check Message Safety"**.
   - Show how the model accurately identifies verified `.sbi` domains and transactional SMS, returning 🟢 **SAFE** without false alarms!
5. **Screenshot OCR Demonstration (New Feature):**
   - Click the **"OCR Photo"** tab.
   - Click **"Test MGVCL Power Cutoff (ગુજરાતી)"** or **"SBI KYC Blocked SMS"** (or upload any real screenshot from phone/laptop).
   - Show the real-time OCR progress bar extracting text from the image, detecting URLs, and analyzing threat with Sanket AI!
6. **QR Code Quishing Scanner (Direct link to Paper 2 - QsecR):**
   - Click the **"QR Code"** tab.
   - Click **"Test UPI QR Code Payment Scam Demo"** ➔ It decodes the hidden payload and evaluates the URL threat!

---

## 🔬 Live Evaluation with Unseen Data (Pointer 2)

When the faculty asks: *"How does the model evaluate on live data?"*

1. Click the top-right button: **`Faculty Demo (Pointer 2)`**.
2. A slide-out console appears showing:
   - **Ablation Study Matrix:**
     - Text-Only Model vs. URL-Only Model vs. Multi-Evidence Fusion.
     - Proving that **Multi-Evidence Fusion** achieves the highest F1-Score and lowest False Positive Rate (FPR).
   - **Per-Language FPR:** English (0.0%), Hindi (0.0%), Gujarati (0.0%), directly addressing the gap in *Staples et al. (IEEE PST 2023)*.
3. **Run Live Test:**
   - Click **"Load 10 Samples"**.
   - Click **"Run Live Test"**.
   - Show the live evaluation table updating on the spot with real-time Precision, Recall, and PASS/FAIL marks!

---

## 💬 Answers to Expected Viva / Defense Questions

| Question | Your Answer |
|---|---|
| **Why is the project named Sanket?** | *Sanket (સંકેત / संकेत)* means "Early Indicator / Signal" in Gujarati and Hindi. It functions as an early-warning signal for vulnerable citizens against sophisticated phishing and smishing before monetary loss occurs. |
| **Why did you choose this classifier architecture (LinearSVC + Random Forest + Stacking Fusion)?** | Text classification in high-dimensional n-gram spaces (12,000+ dimensions) is linearly separable; `LinearSVC` with Platt calibration optimizes the maximum margin without overfitting. For URLs, `Random Forest` natively handles heterogeneous non-linear features (entropy, digit counts, TLDs) without feature scaling. Late fusion via Stacking Logistic Regression allows independent evaluation when messages have no URL (`has_url = 0`), which early fusion cannot do cleanly. |
| **Why not use deep learning (e.g. IndicBERT / MuRIL)?** | IndicBERT/MuRIL require 500MB–1.2GB RAM and 300–800ms inference latency, making them unviable for serverless (Vercel 250MB limit) or edge mobile execution. Our calibrated pipeline executes in under 5ms with a lightweight 760KB model footprint while maintaining 100% test recall on fraud benchmarks. |
| **Why did you use Character N-grams for text?** | Indic languages (Hindi, Gujarati) are morphologically rich and agglutinative, and Indian smishing heavily uses phonetic Hinglish and deliberate misspellings to bypass filters. Subword Character N-grams (3–5 chars) capture semantic roots and phonetics without suffering from Out-Of-Vocabulary (OOV) tokenization failure. |
| **What is the difference between Spam and Scam?** | A promotional marketing SMS (Spam) is unwanted but non-fraudulent (no deception or credential theft). A Scam actively attempts unauthorized fund transfer, credential harvesting (phishing), or extortion. Our dataset implements a 3-way taxonomy (0: Ham, 1: Spam, 2: Scam) with binary objective `is_scam = 1`. |
| **Isn't the dataset augmented? How do you know the accuracy isn't inflated by template memorization?** | Excellent question! In low-resource Indic languages (especially Gujarati SMS), authentic public scam corpora are scarce, so slot augmentation is necessary to expose subword models to regional entities and morphological inflections. However, if evaluated with standard random splitting, template leakage artificially inflates accuracy to 100%. To prevent this and verify true generalization, we performed a **Strict Disjoint Group-Stratified Validation (GroupShuffleSplit)** where **0% of the training templates appear in the test set**. Even on completely novel, unseen templates, TRINETRA achieves **98.41% accuracy and 0.9854 F1-score with 100% recall**, proving that the (3,5) character n-gram feature union learns true morphological and psychological invariants rather than memorizing template syntax! |
| **How did you address the Gujarati dataset gap and select authentic sources?** | Rather than relying on unverified community uploads, we grounded TRINETRA in peer-reviewed and institutional resources: (1) **IEEE Hindi Spam SMS** (3,894 research-backed messages from Ramanujam et al., IEEE DataPort 2024), (2) **IndiF / INDICA Benchmark** (Vikram et al., 2026) for Hindi & Gujarati telecom fraud covering 6 major crime categories (Banking, Customer Impersonation, Investment, Phishing, Lottery, Identity Theft), (3) **LDC-IL Gujarati Corpus** (Govt of India, 2.86M authentic words) and **AI4Bharat Samanantar** for linguistic grounding and low False Positive Rates, and (4) Curated authentic Gujarati DISCOM (MGVCL/UGVCL) and banking smishing messages to address the documented literature gap. |
| **How does the Screenshot OCR work?** | In real life, users receive scam messages on WhatsApp or take screenshots of notices. Sanket uses `Tesseract.js` client-side WebAssembly OCR in the browser, enabling instant image text extraction and URL detection on both phones and laptops without server latency. |
| **What is Quishing?** | QR code phishing. Attackers embed deceptive payment or login links inside QR codes (often on WhatsApp or fake electricity bills) to evade email text scanners. Sanket decodes QR codes before URL execution, as recommended by *QsecR (IEEE Access 2023)*. |
| **Why is False Positive Rate (FPR) critical?** | If a safety app flags legitimate bank alerts or OTPs as scams, users lose trust and ignore real warnings. Sanket explicitly minimizes FPR to near zero using legitimate domain whitelisting and fusion calibration. |

---
**Team Members:** Isha Rajput, Parisha Parmar, Priya Bhatt  
**Navrachana University, Vadodara • DS-ML Major Project 2026-27**
